package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractTablesFromOpenAPI(t *testing.T) {
	openapi := &openAPIDef{
		Paths: map[string]map[string]interface{}{
			"/":         map[string]interface{}{},
			"/rpc/func": map[string]interface{}{},
			"/profiles": map[string]interface{}{},
			"/products": map[string]interface{}{},
			"/orders":   map[string]interface{}{},
		},
	}
	t.Logf("openapi.Paths len=%d, nil=%v", len(openapi.Paths), openapi.Paths == nil)
	tables := extractTables(openapi)
	if len(tables) != 3 {
		t.Fatalf("expected 3 tables, got %d: %#v", len(tables), tables)
	}
	expected := map[string]bool{"profiles": true, "products": true, "orders": true}
	for _, table := range tables {
		if !expected[table] {
			t.Fatalf("unexpected table: %q", table)
		}
	}
}

func TestRestAccessFindings(t *testing.T) {
	access := []TableAccess{
		{Table: "profiles", Writable: true},
		{Table: "products", Readable: true},
		{Table: "orders"},
	}
	findings := RestAccessFindings(access, "https://test.supabase.co")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity for writable table, got %s", findings[0].Severity)
	}
	if findings[1].Severity != "high" {
		t.Fatalf("expected high severity for readable table, got %s", findings[1].Severity)
	}
}

func TestProbeRestTablesIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"paths":{"/profiles":{"get":{},"post":{}},"/products":{"get":{}}},"definitions":{"profiles":{"required":["id"],"properties":{"id":{"type":"integer"},"bio":{"type":"string"}}}}}`))
			return
		}
		if r.URL.Path == "/rest/v1/profiles" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.URL.Path == "/rest/v1/profiles" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/rest/v1/products" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	access, err := ProbeRestTables(context.Background(), server.URL+"/", RestCheckOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(access) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(access))
	}
	for _, ta := range access {
		if ta.Table == "profiles" {
			if !ta.Readable {
				t.Fatal("profiles should be readable")
			}
			if !ta.Writable {
				t.Fatal("profiles should be writable")
			}
		}
		if ta.Table == "products" {
			if ta.Readable {
				t.Fatal("products should not be readable (403)")
			}
		}
	}
}

func TestProbeTableWriteUsesRealColumns(t *testing.T) {
	var gotBody []byte
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	def := &openAPIDef{Definitions: map[string]tableDefinition{
		"widgets": {Required: []string{"id"}, Properties: map[string]any{"id": nil, "name": nil}},
	}}
	res := probeTableWrite(context.Background(), server.URL+"/", "widgets", def.probeColumns("widgets"), "", writeProbeOpts{})
	if res != writeAllowed {
		t.Fatalf("probeTableWrite = %v, want writeAllowed", res)
	}
	if gotPath != "/rest/v1/widgets" {
		t.Fatalf("probed path = %q, want /rest/v1/widgets", gotPath)
	}
	var payload map[string]any
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatal(err)
	}
	// Real nullable column used, required pk omitted; no fake probe column.
	if _, ok := payload["name"]; !ok {
		t.Fatalf("expected real column 'name' in payload, got %v", payload)
	}
	if _, ok := payload["supascope_probe"]; ok {
		t.Fatalf("fake probe column must not be sent, got %v", payload)
	}
	if _, ok := payload["id"]; ok {
		t.Fatalf("required column 'id' should be omitted from the null probe, got %v", payload)
	}
}

func TestProbeTableWriteDenials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	if res := probeTableWrite(context.Background(), server.URL+"/", "t", []string{"a"}, "", writeProbeOpts{}); res != writeDenied {
		t.Fatalf("probeTableWrite = %v, want writeDenied", res)
	}
	// No probe columns (unknown schema) is inconclusive, never a false positive.
	if res := probeTableWrite(context.Background(), server.URL+"/", "t", nil, "", writeProbeOpts{}); res != writeInconclusive {
		t.Fatalf("probeTableWrite = %v, want writeInconclusive", res)
	}
}

func TestProbeRestTablesNamedWithoutOpenAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No /rest/v1/ OpenAPI route at all: spec unavailable.
		if r.URL.Path == "/rest/v1/widgets" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	access, err := ProbeRestTablesNamed(context.Background(), server.URL+"/", []string{"widgets", "ghost"}, RestCheckOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(access) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(access))
	}
	for _, ta := range access {
		switch ta.Table {
		case "widgets":
			if !ta.Readable {
				t.Fatal("widgets should be readable")
			}
			if ta.Writable {
				t.Fatal("widgets write should be inconclusive without column definitions")
			}
		case "ghost":
			if ta.Readable || ta.Writable {
				t.Fatal("ghost should not be readable/writable (404)")
			}
		}
	}
}

func TestRestOpenAPIWarning(t *testing.T) {
	w := RestOpenAPIWarning("https://x.supabase.co", 0)
	if w.ID != "SUPA-REST-WARN-001" {
		t.Fatalf("warning ID = %q", w.ID)
	}
	w = RestOpenAPIWarning("https://x.supabase.co", 3)
	if w.ID != "SUPA-REST-WARN-001" {
		t.Fatalf("fallback warning ID = %q", w.ID)
	}
}
