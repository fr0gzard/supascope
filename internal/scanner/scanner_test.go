package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"supascope/internal/model"
)

func TestLocalScanEmptyHasNoFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hello');"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := New().Scan(context.Background(), model.Options{
		Target: model.Target{Type: model.TargetLocalPath, Value: dir},
		Yes:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", result.Findings)
	}
}

func TestURLScanRecursesIntoChunksAndSanitizesSecrets(t *testing.T) {
	secret := strings.Join([]string{"sb", "secret", "abcdefghijklmnopqrstuvwxyz"}, "_")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("content-type", "text/html")
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			w.Header().Set("content-type", "application/javascript")
			_, _ = w.Write([]byte(`const chunk = "/assets/chunk.js";`))
		case "/assets/chunk.js":
			w.Header().Set("content-type", "application/javascript")
			_, _ = w.Write([]byte(`fetch('https://abcxyz.supabase.co/rest/v1/products?select=id'); const key = '` + secret + `';`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := New().Scan(context.Background(), model.Options{
		Target: model.Target{Type: model.TargetURL, Value: server.URL + "/"},
		Yes:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("report JSON contains raw secret")
	}
	if result.Services.REST != model.ServiceObserved {
		t.Fatalf("REST status = %q, want observed", result.Services.REST)
	}
	if !hasFinding(result.Findings, "SUPA-KEY-CRIT-001") {
		t.Fatal("expected critical secret key finding")
	}
	if !hasCategory(result.Findings, "service_detection") {
		t.Fatal("expected service detection finding")
	}
}

func TestActiveChecksGenerateServiceStatusFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/v1/":
			w.WriteHeader(http.StatusUnauthorized)
		case "/auth/v1/settings":
			w.WriteHeader(http.StatusOK)
		case "/storage/v1/":
			w.WriteHeader(http.StatusForbidden)
		case "/realtime/v1/":
			w.WriteHeader(http.StatusNotFound)
		case "/functions/v1/":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/graphql/v1":
			if r.Method != http.MethodPost {
				t.Fatalf("GraphQL method = %q, want POST", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := New().Scan(context.Background(), model.Options{
		Target:       model.Target{Type: model.TargetSupabaseProject, Value: server.URL},
		Yes:          true,
		ActiveChecks: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Services.REST != model.ServiceUnauthorized {
		t.Fatalf("REST status = %q, want unauthorized", result.Services.REST)
	}
	if result.Services.GraphQL != model.ServiceReachable {
		t.Fatalf("GraphQL status = %q, want reachable", result.Services.GraphQL)
	}
	if !hasFinding(result.Findings, "SUPA-ACTIVE-REST-INFO-002") {
		t.Fatal("expected REST authorization active finding")
	}
	if !hasFinding(result.Findings, "SUPA-ACTIVE-AUTH-INFO-001") {
		t.Fatal("expected Auth reachable active finding")
	}
	if !hasFinding(result.Findings, "SUPA-ACTIVE-GRAPHQL-INFO-001") {
		t.Fatal("expected GraphQL reachable active finding")
	}
	if hasFinding(result.Findings, "SUPA-ACTIVE-REALTIME-INFO-001") {
		t.Fatal("did not expect not_found realtime active finding")
	}
}

func hasFinding(findings []model.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func hasCategory(findings []model.Finding, category string) bool {
	for _, finding := range findings {
		if finding.Category == category {
			return true
		}
	}
	return false
}
