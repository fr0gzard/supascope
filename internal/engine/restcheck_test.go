package engine

import (
	"context"
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
			_, _ = w.Write([]byte(`{"paths":{"/profiles":{"get":{},"post":{}},"/products":{"get":{}}}}`))
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
