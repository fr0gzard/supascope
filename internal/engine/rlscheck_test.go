package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRLSFindingsAnonWriteCritical(t *testing.T) {
	results := []RLSTableResult{
		{Table: "profiles", Access: map[string]TableAccess{
			"anon":   {Writable: true, Readable: true},
			"user_1": {Readable: true},
		}},
	}
	findings := RLSFindings(results, "https://test.supabase.co")
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	hasCrit := false
	for _, f := range findings {
		if f.ID == "SUPA-RLS-CRIT-001" && f.Severity == "critical" {
			hasCrit = true
		}
	}
	if !hasCrit {
		t.Fatal("expected critical anon write finding")
	}
}

func TestRLSFindingsCrossUserLeak(t *testing.T) {
	results := []RLSTableResult{
		{Table: "messages", Access: map[string]TableAccess{
			"anon":   {},
			"user_1": {Readable: true},
			"user_2": {Readable: true},
		}, CrossUser: &CrossUserResult{
			UserA:    "user_1",
			UserB:    "user_2",
			Overlap:  5,
			TotalA:   10,
			TotalB:   10,
			Isolated: false,
		}},
	}
	findings := RLSFindings(results, "https://test.supabase.co")
	found := false
	for _, f := range findings {
		if f.ID == "SUPA-RLS-CRIT-002" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected cross-user leak finding")
	}
}

func TestRLSFindingsIsolationVerified(t *testing.T) {
	results := []RLSTableResult{
		{Table: "messages", Access: map[string]TableAccess{
			"anon":   {},
			"user_1": {Readable: true},
			"user_2": {Readable: true},
		}, CrossUser: &CrossUserResult{
			UserA:    "user_1",
			UserB:    "user_2",
			Overlap:  0,
			TotalA:   5,
			TotalB:   3,
			Isolated: true,
		}},
	}
	findings := RLSFindings(results, "https://test.supabase.co")
	found := false
	for _, f := range findings {
		if f.ID == "SUPA-RLS-INFO-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected isolation verified finding")
	}
}

func TestRLSFindingsAuthWriteMedium(t *testing.T) {
	results := []RLSTableResult{
		{Table: "posts", Access: map[string]TableAccess{
			"anon":   {},
			"user_1": {Readable: true, Writable: true},
		}},
	}
	findings := RLSFindings(results, "https://test.supabase.co")
	found := false
	for _, f := range findings {
		if f.ID == "SUPA-RLS-MED-001" && f.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected medium auth write finding")
	}
}

func TestProbeRLSIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"paths":{"/profiles":{"get":{},"post":{}}}}`))
			return
		}
		if r.URL.Path == "/rest/v1/profiles" {
			token := r.Header.Get("Authorization")
			switch {
			case token == "":
				w.WriteHeader(http.StatusUnauthorized)
			case token == "Bearer tokenA":
				if r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`[{"id":1},{"id":2}]`))
				} else {
					w.WriteHeader(http.StatusCreated)
				}
			case token == "Bearer tokenB":
				if r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`[{"id":3},{"id":4}]`))
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
			default:
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	results, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		AnonKey: "anon-key",
		Tokens: []Identity{
			{Name: "user_a", Token: "tokenA"},
			{Name: "user_b", Token: "tokenB"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 table, got %d", len(results))
	}
	r := results[0]
	if r.Table != "profiles" {
		t.Fatalf("expected profiles, got %s", r.Table)
	}
	if r.Access["anon"].Readable {
		t.Fatal("anon should not be readable")
	}
	if !r.Access["user_a"].Readable {
		t.Fatal("user_a should be readable")
	}
	if !r.Access["user_a"].Writable {
		t.Fatal("user_a should be writable")
	}
	if r.Access["user_b"].Writable {
		t.Fatal("user_b should not be writable")
	}
	if r.CrossUser == nil {
		t.Fatal("expected cross-user result")
	}
	if !r.CrossUser.Isolated {
		t.Fatal("expected isolation (disjoint ID sets)")
	}
}

func TestProbeRLSNoTokensSkipsCrossUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			_, _ = w.Write([]byte(`{"paths":{"/items":{"get":{}}}}`))
			return
		}
		if r.URL.Path == "/rest/v1/items" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	results, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		AnonKey: "anon-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 table, got %d", len(results))
	}
	if results[0].CrossUser != nil {
		t.Fatal("cross-user should be nil without 2 tokens")
	}
}

func TestFetchRowIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"id": 42, "name": "test"},
			{"id": 99, "name": "other"},
		})
	}))
	defer server.Close()

	ids, total := fetchRowIDs(context.Background(), server.URL+"/", "test", Identity{Name: "u", Token: "tok"}, RLSCheckOptions{})
	if total != 2 {
		t.Fatalf("expected 2 rows, got %d", total)
	}
	if len(ids) != 2 || ids[0] != "42" || ids[1] != "99" {
		t.Fatalf("unexpected ids: %#v", ids)
	}
}