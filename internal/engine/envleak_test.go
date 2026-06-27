package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"supascope/internal/model"
)

func TestProbeEnvLeaksDetectsExposedConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" || r.URL.Path == "/env.js" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	discoveries := ProbeEnvLeaks(context.Background(), server.URL, EnvLeakOptions{})
	if len(discoveries) != 2 {
		t.Fatalf("expected 2 discoveries, got %d: %#v", len(discoveries), discoveries)
	}
	for _, d := range discoveries {
		if d.Type != "config_file" {
			t.Fatalf("expected config_file type, got %q", d.Type)
		}
		if d.Source != "env_probe" {
			t.Fatalf("expected env_probe source, got %q", d.Source)
		}
	}
}

func TestProbeEnvLeaksReturnsEmptyForNoConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	discoveries := ProbeEnvLeaks(context.Background(), server.URL, EnvLeakOptions{})
	if len(discoveries) != 0 {
		t.Fatalf("expected 0 discoveries, got %d", len(discoveries))
	}
}

func TestEnvLeakFindingsGeneratesForConfigFiles(t *testing.T) {
	discoveries := []model.Discovery{
		{Type: "config_file", Value: "https://test.com/.env", Source: "env_probe"},
		{Type: "supabase_url", Value: "https://test.supabase.co", Source: "static"},
	}
	findings := EnvLeakFindings(discoveries)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPA-ENV-INFO-001" {
		t.Fatalf("expected SUPA-ENV-INFO-001, got %s", findings[0].ID)
	}
}