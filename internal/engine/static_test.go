package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

func TestScanURLScansSourceMapSourcesContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			_, _ = w.Write([]byte(`console.log("app");
//# sourceMappingURL=app.js.map`))
		case "/assets/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3,"sources":["webpack://app/src/lib/supabase.ts"],"sourcesContent":["export const supabaseUrl = 'https://abcxyz.supabase.co';"],"mappings":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	discoveries, err := NewStatic("", nil, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range discoveries {
		if discovery.Type != "supabase_url" || discovery.Evidence == nil {
			continue
		}
		if discovery.Evidence.Source == "source_map" && strings.Contains(discovery.Evidence.File, "supabase.ts") {
			return
		}
	}
	t.Fatalf("expected source map discovery, got %#v", discoveries)
}

func TestScanSourceMapStopsAfterDiscoveryLimit(t *testing.T) {
	sources := make([]string, maxSourceMapDiscoveries+5)
	sourcesContent := make([]string, maxSourceMapDiscoveries+5)
	for i := range sources {
		sources[i] = "src/file.js"
		sourcesContent[i] = "export const url = 'https://abcxyz.supabase.co';"
	}
	encoded, err := json.Marshal(sourceMap{Sources: sources, SourcesContent: sourcesContent})
	if err != nil {
		t.Fatal(err)
	}

	discoveries := scanSourceMap("https://example.com/assets/app.js.map", string(encoded))
	if len(discoveries) != maxSourceMapDiscoveries {
		t.Fatalf("discoveries = %d, want %d", len(discoveries), maxSourceMapDiscoveries)
	}
}

func TestScanSourceMapStopsAfterSourceLimit(t *testing.T) {
	sources := make([]string, maxSourceMapSources+1)
	sourcesContent := make([]string, maxSourceMapSources+1)
	for i := range sources {
		sources[i] = "src/empty.js"
		sourcesContent[i] = "console.log('empty');"
	}
	sources[maxSourceMapSources] = "src/late.js"
	sourcesContent[maxSourceMapSources] = "export const url = 'https://late.supabase.co';"
	encoded, err := json.Marshal(sourceMap{Sources: sources, SourcesContent: sourcesContent})
	if err != nil {
		t.Fatal(err)
	}

	discoveries := scanSourceMap("https://example.com/assets/app.js.map", string(encoded))
	if len(discoveries) != 0 {
		t.Fatalf("discoveries = %#v, want none after source limit", discoveries)
	}
}
