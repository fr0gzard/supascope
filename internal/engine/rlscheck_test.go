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
	findings := RLSFindings(&RLSReport{Results: results}, "https://test.supabase.co")
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
	findings := RLSFindings(&RLSReport{Results: results}, "https://test.supabase.co")
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
	findings := RLSFindings(&RLSReport{Results: results}, "https://test.supabase.co")
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
	findings := RLSFindings(&RLSReport{Results: results}, "https://test.supabase.co")
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
			_, _ = w.Write([]byte(`{"paths":{"/profiles":{"get":{},"post":{}}},"definitions":{"profiles":{"required":["id"],"properties":{"id":{"type":"integer"},"bio":{"type":"string"}}}}}`))
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

	report, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		AnonKey: "anon-key",
		Tokens: []Identity{
			{Name: "user_a", Token: "tokenA"},
			{Name: "user_b", Token: "tokenB"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("expected 1 table, got %d", len(report.Results))
	}
	r := report.Results[0]
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

	report, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		AnonKey: "anon-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("expected 1 table, got %d", len(report.Results))
	}
	if report.Results[0].CrossUser != nil {
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
func TestRLSFindingsNoFalseIsolationVerified(t *testing.T) {
	// Regression: INFO-001 used to gate on TotalA/TotalB > 0, so a table with
	// no id column (zero rows actually compared) got "isolation verified".
	results := []RLSTableResult{
		{Table: "events", Access: map[string]TableAccess{
			"anon":   {},
			"user_1": {Readable: true},
			"user_2": {Readable: true},
		}, CrossUser: &CrossUserResult{
			UserA:    "user_1",
			UserB:    "user_2",
			Overlap:  0,
			TotalA:   5,
			TotalB:   3,
			Isolated: false, // no ids extracted (no id column)
		}},
	}
	findings := RLSFindings(&RLSReport{Results: results}, "https://test.supabase.co")
	for _, f := range findings {
		if f.ID == "SUPA-RLS-INFO-001" {
			t.Fatal("must not report isolation verified when no rows were compared")
		}
	}
}

func TestProbeRLSSkipsDuplicateTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			_, _ = w.Write([]byte(`{"paths":{"/items":{"get":{}}}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	defer server.Close()

	report, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		Tokens: []Identity{
			{Name: "user_a", Token: "same-token"},
			{Name: "user_b", Token: "same-token"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].CrossUser != nil {
		t.Fatalf("cross-user check should be skipped for identical tokens: %#v", report.Results)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("expected a warning about identical tokens")
	}
	findings := RLSFindings(report, "https://test.supabase.co")
	found := false
	for _, f := range findings {
		if f.ID == "SUPA-RLS-CRIT-002" {
			t.Fatal("must not report a cross-user leak for a single identity")
		}
		if f.ID == "SUPA-RLS-WARN-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a coverage-gap warning finding")
	}
}

func TestProbeRLSFlagsRejectedTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			if r.Header.Get("Authorization") == "Bearer dead-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"paths":{"/items":{"get":{}}}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	report, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		Tokens: []Identity{
			{Name: "user_a", Token: "dead-token"},
			{Name: "user_b", Token: "live-token"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("expected a warning for the rejected token")
	}
	if _, ok := report.Results[0].Access["user_a"]; ok {
		t.Fatal("rejected identity should not be probed")
	}
	if _, ok := report.Results[0].Access["user_b"]; !ok {
		t.Fatal("accepted identity should be probed")
	}
	// Only one live token left: no cross-user comparison possible.
	if report.Results[0].CrossUser != nil {
		t.Fatal("cross-user should be nil with only one live token")
	}
}

func TestProbeRLSUnionsTablesAcrossIdentities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			// PostgREST scopes OpenAPI per role: anon sees less.
			if r.Header.Get("Authorization") == "Bearer authed-token" {
				_, _ = w.Write([]byte(`{"paths":{"/public_stuff":{"get":{}},"/private_stuff":{"get":{}}}}`))
			} else {
				_, _ = w.Write([]byte(`{"paths":{"/public_stuff":{"get":{}}}}`))
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	report, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		Tokens: []Identity{{Name: "user_a", Token: "authed-token"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected union of anon+authed tables, got %d: %#v", len(report.Results), report.Results)
	}
}

func TestProbeRLSFallsBackToNamedTables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OpenAPI disabled: every identity gets 404.
		if r.URL.Path == "/rest/v1/" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/rest/v1/widgets" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	report, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{
		FallbackTables: []string{"widgets"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.UsedFallbackTables {
		t.Fatal("expected UsedFallbackTables")
	}
	if len(report.Results) != 1 || report.Results[0].Table != "widgets" {
		t.Fatalf("unexpected results: %#v", report.Results)
	}
	if !report.Results[0].Access["anon"].Readable {
		t.Fatal("widgets should be readable by anon")
	}

	findings := RLSFindings(report, server.URL+"/")
	found := false
	for _, f := range findings {
		if f.ID == "SUPA-RLS-WARN-002" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected SUPA-RLS-WARN-002 fallback warning, got %v", findings)
	}
}

func TestProbeRLSErrorsWithoutTablesOrFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	if _, err := ProbeRLS(context.Background(), server.URL+"/", RLSCheckOptions{}); err == nil {
		t.Fatal("expected error when OpenAPI is unavailable and no fallback tables exist")
	}
}
