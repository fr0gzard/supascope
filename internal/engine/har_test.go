package engine

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"supascope/internal/model"
)

func TestScanHARDetectsRequestAndResponseArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network.har")
	secret := strings.Join([]string{"sb", "secret", "abcdefghijklmnopqrstuvwxyz"}, "_")
	response := base64.StdEncoding.EncodeToString([]byte(`{"project":"https://respabc.supabase.co"}`))
	content := `{
  "log": {
    "entries": [
      {
        "request": {
          "method": "POST",
          "url": "https://abcxyz.supabase.co/rest/v1/products?select=id",
          "headers": [{"name":"apikey","value":"` + secret + `"}],
          "postData": {"text":"{\"url\":\"https://bodyabc.supabase.co\"}"}
        },
        "response": {"content": {"text":"` + response + `", "encoding":"base64"}}
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	discoveries, err := ScanHAR(path)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiscovery(discoveries, "endpoint", "https://abcxyz.supabase.co/rest/v1/products?select=id") {
		t.Fatalf("expected endpoint discovery, got %#v", discoveries)
	}
	if !hasDiscovery(discoveries, "key", secret) {
		t.Fatalf("expected key discovery, got %#v", discoveries)
	}
	if !hasDiscovery(discoveries, "supabase_url", "https://bodyabc.supabase.co") {
		t.Fatalf("expected request body discovery, got %#v", discoveries)
	}
	if !hasDiscovery(discoveries, "supabase_url", "https://respabc.supabase.co") {
		t.Fatalf("expected response discovery, got %#v", discoveries)
	}
	for _, discovery := range discoveries {
		if discovery.Evidence == nil || discovery.Evidence.Source != "har" || discovery.Evidence.File != path {
			t.Fatalf("unexpected evidence: %#v", discovery)
		}
	}
}

func hasDiscovery(discoveries []model.Discovery, discoveryType string, value string) bool {
	for _, discovery := range discoveries {
		if discovery.Type == discoveryType && discovery.Value == value {
			return true
		}
	}
	return false
}
