package scanner

import (
	"context"
	"encoding/base64"
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

func TestShowSecretsReportsRawValues(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Join([]string{"sb", "secret", "abcdefghijklmnopqrstuvwxyz"}, "_")
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("const key = '"+secret+"';"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := New().Scan(context.Background(), model.Options{
		Target:      model.Target{Type: model.TargetLocalPath, Value: dir},
		Yes:         true,
		ShowSecrets: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), secret) {
		t.Fatal("report JSON does not contain raw secret with ShowSecrets enabled")
	}

	for _, finding := range result.Findings {
		if finding.ID == "SUPA-KEY-CRIT-001" && finding.Evidence.MaskedValue == secret {
			return
		}
	}
	t.Fatal("expected finding evidence value to contain raw secret")
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

func TestGraphQLIntrospectionWritesSchemaAndFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql/v1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"profiles"}]}}}`))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "schema.txt")
	result, err := New().Scan(context.Background(), model.Options{
		Target:               model.Target{Type: model.TargetSupabaseProject, Value: server.URL},
		Yes:                  true,
		GraphQLIntrospection: true,
		GraphQLSchemaOutput:  output,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(result.Findings, "SUPA-GRAPHQL-MED-001") {
		t.Fatal("expected GraphQL introspection finding")
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "profiles") {
		t.Fatalf("schema output = %q, want type name", string(written))
	}
}

func TestGraphQLIntrospectionWritesErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql/v1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "schema.txt")
	result, err := New().Scan(context.Background(), model.Options{
		Target:               model.Target{Type: model.TargetSupabaseProject, Value: server.URL},
		Yes:                  true,
		GraphQLIntrospection: true,
		GraphQLSchemaOutput:  output,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(result.Findings, "SUPA-GRAPHQL-MED-001") {
		t.Fatal("did not expect GraphQL introspection finding for error response")
	}
	var detail string
	for _, finding := range result.Findings {
		if finding.ID == "SUPA-GRAPHQL-INFO-002" {
			detail = finding.Evidence.Detail
			break
		}
	}
	if !strings.Contains(detail, "GraphQL introspection is not allowed") {
		t.Fatalf("detail = %q, want GraphQL error message", detail)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "GraphQL introspection is not allowed") {
		t.Fatalf("schema output = %q, want error response", string(written))
	}
}

func TestWAFDiscoveryGeneratesCoverageFinding(t *testing.T) {
	findings := discoveriesToFindings([]model.Discovery{{
		Type:   "waf_block",
		Value:  "possible WAF/CDN block: status=403 fingerprints=cloudflare",
		Source: "static_fetch",
		Evidence: &model.Evidence{
			Source: "static_fetch",
			URL:    "https://example.com/assets/app.js",
			Detail: "possible WAF/CDN block: status=403 fingerprints=cloudflare",
		},
	}}, false)
	if !hasFinding(findings, "SUPA-WAF-INFO-001") {
		t.Fatal("expected WAF coverage finding")
	}
}

func TestJWTFindingIncludesSafeMetadata(t *testing.T) {
	dir := t.TempDir()
	jwt := scannerTestJWT(map[string]any{
		"role": "service_role",
		"iss":  "https://abcxyz.supabase.co/auth/v1",
		"exp":  float64(1893456000),
	})
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("const key = '"+jwt+"';"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := New().Scan(context.Background(), model.Options{
		Target: model.Target{Type: model.TargetLocalPath, Value: dir},
		Yes:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	var detail string
	for _, finding := range result.Findings {
		if finding.ID == "SUPA-KEY-CRIT-002" {
			detail = finding.Evidence.Detail
			break
		}
	}
	for _, want := range []string{"role: service_role", "project_ref: abcxyz", "expiry: 2030-01-01T00:00:00Z"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail = %q, want to contain %q", detail, want)
		}
	}
	if strings.Contains(detail, jwt) {
		t.Fatal("finding detail contains raw JWT")
	}
}

func TestConcreteDatabaseURLInDummyContextStaysCritical(t *testing.T) {
	discoveries := []model.Discovery{{
		Type:   "key",
		Value:  "postgresql://app:secret@db.internal.net:5432/app",
		Source: "static",
		Evidence: &model.Evidence{
			Source:  "static",
			URL:     "https://example.com/assets/dummyPods.js",
			Snippet: "const dummyConnection = 'postgresql://app:secret@db.internal.net:5432/app'",
		},
	}}

	findings := discoveriesToFindings(discoveries, false)
	if !hasFinding(findings, "SUPA-DB-CRIT-001") {
		t.Fatalf("expected critical DB URL finding, got %#v", findings)
	}
}

func scannerTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
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
