package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
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

func TestNetworkObservationsToDiscoveriesWebSocket(t *testing.T) {
	secret := "sb_publishable_abcdefghijklmnopqrstuvwxyz"
	wsURL := "wss://abcxyz.supabase.co/realtime/v1/websocket?apikey=" + secret
	discoveries := networkObservationsToDiscoveries([]networkObservation{
		{Source: "dynamic_network", URL: wsURL, Detail: "websocket created: " + wsURL, Text: wsURL},
		{Source: "dynamic_network", URL: wsURL, Detail: "websocket handshake request", Text: "apikey: " + secret},
		{Source: "dynamic_network", URL: wsURL, Detail: "websocket frame received", Text: `{"table":"profiles","type":"SELECT"}`},
	})

	if !hasDiscovery(discoveries, "supabase_url", "wss://abcxyz.supabase.co") {
		t.Fatalf("expected supabase_url discovery from websocket URL, got %#v", discoveries)
	}
	if !hasDiscovery(discoveries, "endpoint", wsURL) {
		t.Fatalf("expected endpoint discovery for websocket URL, got %#v", discoveries)
	}
	if !hasDiscovery(discoveries, "key", secret) {
		t.Fatalf("expected key discovery from websocket headers, got %#v", discoveries)
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

func TestNetworkCaptureHandlesRequestEvent(t *testing.T) {
	cap := newNetworkCapture(false)
	ev := &network.EventRequestWillBeSent{
		RequestID: "1",
		Request: &network.Request{
			URL:    "https://abcxyz.supabase.co/rest/v1/profiles?select=id",
			Method: "GET",
		},
	}
	cap.handle(context.Background(), ev)

	if got := cap.observationCount(); got == 0 {
		t.Fatal("expected observations from synthetic request event")
	}
	discoveries := networkObservationsToDiscoveries(cap.snapshot())
	if !hasDiscovery(discoveries, "endpoint", "https://abcxyz.supabase.co/rest/v1/profiles?select=id") {
		t.Fatalf("expected endpoint discovery, got %#v", discoveries)
	}
}

func TestNetworkCaptureDropsEmptyText(t *testing.T) {
	cap := newNetworkCapture(false)
	cap.addObservation(networkObservation{Source: "dynamic_network", Text: "   "})
	if got := cap.observationCount(); got != 0 {
		t.Fatalf("expected empty-text observation to be dropped, got %d", got)
	}
}

func TestTextualMime(t *testing.T) {
	textual := []string{"", "text/html", "text/html; charset=utf-8", "application/json", "application/ld+json", "application/javascript", "text/css", "image/svg+xml", "application/xml"}
	for _, m := range textual {
		if !textualMime(m) {
			t.Fatalf("expected textual for %q", m)
		}
	}
	binary := []string{"image/png", "image/jpeg", "font/woff2", "video/mp4", "application/octet-stream", "application/pdf", "audio/mpeg"}
	for _, m := range binary {
		if textualMime(m) {
			t.Fatalf("expected binary for %q", m)
		}
	}
}

func TestNetworkCaptureSkipsBinaryBodies(t *testing.T) {
	cap := newNetworkCapture(false)
	// Record an image response, then finish loading: no CDP body fetch should
	// be attempted (no browser in unit tests) and no observation recorded.
	cap.handle(context.Background(), &network.EventResponseReceived{
		RequestID: "img1",
		Response:  &network.Response{URL: "https://example.com/x.png", MimeType: "image/png", Status: 200},
	})
	before := cap.observationCount()
	cap.handle(context.Background(), &network.EventLoadingFinished{RequestID: "img1"})
	// The waitgroup was already Done() synchronously for skipped bodies.
	if done := cap.waitForBodies(time.Second); !done {
		t.Fatal("waitgroup should be released for skipped binary bodies")
	}
	if got := cap.observationCount(); got != before {
		t.Fatalf("binary body should not add observations, got %d want %d", got, before)
	}
}
