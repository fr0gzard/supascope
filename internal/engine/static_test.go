package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestDiscoverAssetURLs(t *testing.T) {
	content := []byte(`
		<script src="/assets/app.js"></script>
		<link href="https://example.com/assets/app.css" rel="stylesheet">
		<script src="https://cdn.example.net/remote.js"></script>
	`)

	got := DiscoverAssetURLs("https://example.com", string(content))
	want := []string{
		"https://example.com/assets/app.js",
		"https://example.com/assets/app.css",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiscoverAssetURLs() = %#v, want %#v", got, want)
	}
}

func TestScanURLUsesConfiguredUserAgent(t *testing.T) {
	const userAgent = "SupaScope-Test/1.0"

	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, err := NewStatic(userAgent, nil, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != userAgent {
		t.Fatalf("User-Agent = %q, want %q", got, userAgent)
	}
}

func TestScanURLUsesConfiguredHeaders(t *testing.T) {
	headers := map[string]string{"Accept-Language": "en-US,en;q=0.9,id;q=0.8"}

	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Accept-Language")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, err := NewStatic("", headers, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != headers["Accept-Language"] {
		t.Fatalf("Accept-Language = %q, want %q", got, headers["Accept-Language"])
	}
}

func TestDiscoverAssetURLsFromBundles(t *testing.T) {
	content := `
		const viteChunk = "/assets/vendor-a1b2c3.js";
		const nextChunk = "/_next/static/chunks/app/page-123.js";
		const webpackChunk = "/static/js/451.abcd.js";
		import("/assets/lazy.mjs");
		//# sourceMappingURL=app.js.map
	`

	got := DiscoverAssetURLs("https://example.com/assets/app.js", content)
	want := []string{
		"https://example.com/assets/vendor-a1b2c3.js",
		"https://example.com/_next/static/chunks/app/page-123.js",
		"https://example.com/static/js/451.abcd.js",
		"https://example.com/assets/lazy.mjs",
		"https://example.com/assets/app.js.map",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiscoverAssetURLs() = %#v, want %#v", got, want)
	}
}
