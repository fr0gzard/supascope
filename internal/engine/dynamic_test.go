package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkObservationsToDiscoveries(t *testing.T) {
	secret := "sb_publishable_abcdefghijklmnopqrstuvwxyz"
	discoveries := networkObservationsToDiscoveries([]networkObservation{
		{Source: "dynamic_network", URL: "https://example.com", Detail: "GET https://example.com", Text: "https://abcxyz.supabase.co/rest/v1/products?select=id"},
		{Source: "dynamic_network", URL: "https://example.com", Detail: "headers", Text: "apikey: " + secret},
	})

	if !hasDiscovery(discoveries, "endpoint", "https://abcxyz.supabase.co/rest/v1/products?select=id") {
		t.Fatalf("expected endpoint discovery, got %#v", discoveries)
	}
	if !hasDiscovery(discoveries, "key", secret) {
		t.Fatalf("expected key discovery, got %#v", discoveries)
	}
	for _, discovery := range discoveries {
		if discovery.Evidence == nil || discovery.Evidence.Source != "dynamic_network" {
			t.Fatalf("unexpected evidence: %#v", discovery)
		}
	}
}

func TestScanDynamicCapturesBrowserNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script>fetch('https://abcxyz.supabase.co/rest/v1/products?select=id', {headers: {'apikey': 'sb_publishable_abcdefghijklmnopqrstuvwxyz'}}).catch(() => {})</script>`))
	}))
	defer server.Close()

	discoveries, err := ScanDynamic(context.Background(), server.URL, DynamicOptions{})
	if err != nil {
		if chromeUnavailable(err) {
			t.Skipf("chromedp browser unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if !hasDiscovery(discoveries, "endpoint", "https://abcxyz.supabase.co/rest/v1/products?select=id") {
		t.Fatalf("expected dynamic endpoint discovery, got %#v", discoveries)
	}
}

func chromeUnavailable(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "executable file not found") || strings.Contains(message, "could not find") || strings.Contains(message, "chrome") && strings.Contains(message, "not found")
}
