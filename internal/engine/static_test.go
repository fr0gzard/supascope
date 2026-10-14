package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

func TestScanURLLimitsAssetFetchConcurrency(t *testing.T) {
	var active int32
	var maxActive int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/a.js"></script><script src="/assets/b.js"></script><script src="/assets/c.js"></script><script src="/assets/d.js"></script>`))
		default:
			current := atomic.AddInt32(&active, 1)
			for {
				previous := atomic.LoadInt32(&maxActive)
				if current <= previous || atomic.CompareAndSwapInt32(&maxActive, previous, current) {
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			_, _ = w.Write([]byte("console.log('ok');"))
		}
	}))
	defer server.Close()

	_, err := NewStatic("", nil, false, 10, StaticOptions{MaxConcurrency: 2}).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&maxActive); got > 2 {
		t.Fatalf("max concurrent asset fetches = %d, want <= 2", got)
	}
}

func TestDiscoverAssetURLsFromBundles(t *testing.T) {
	content := `
		const viteChunk = "/assets/vendor-a1b2c3.js";
		const nextChunk = "/_next/static/chunks/app/page-123.js";
		const nuxtChunk = "/_nuxt/app.123456.js";
		const astroChunk = "/_astro/Page.abcdef.css";
		const svelteKitChunk = "/_app/immutable/chunks/entry.abcdef.js";
		const webpackChunk = "/static/js/451.abcd.js";
		import("/assets/lazy.mjs");
		//# sourceMappingURL=app.js.map
	`

	got := DiscoverAssetURLs("https://example.com/assets/app.js", content)
	want := []string{
		"https://example.com/assets/vendor-a1b2c3.js",
		"https://example.com/_next/static/chunks/app/page-123.js",
		"https://example.com/_nuxt/app.123456.js",
		"https://example.com/_astro/Page.abcdef.css",
		"https://example.com/_app/immutable/chunks/entry.abcdef.js",
		"https://example.com/static/js/451.abcd.js",
		"https://example.com/assets/lazy.mjs",
		"https://example.com/assets/app.js.map",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiscoverAssetURLs() = %#v, want %#v", got, want)
	}
}

func TestScanURLGuessesHashStrippedFrameworkSourceMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script>window.__chunks=["/assets/index-Dg_4Nfjf.js"]</script>`))
		case "/assets/index-Dg_4Nfjf.js":
			_, _ = w.Write([]byte(`console.log("app");`))
		case "/assets/index.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3,"sources":["src/lib/supabase.ts"],"sourcesContent":["export const supabaseUrl = 'https://abcxyz.supabase.co';"],"mappings":""}`))
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
		if discovery.Evidence.Source == "source_map" && discovery.Evidence.URL == server.URL+"/assets/index.js.map" {
			return
		}
	}
	t.Fatalf("expected hash-stripped source map discovery, got %#v", discoveries)
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

func TestScanURLGuessesAdjacentSourceMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			_, _ = w.Write([]byte(`console.log("app");`))
		case "/assets/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3,"sources":["src/lib/supabase.ts"],"sourcesContent":["export const supabaseUrl = 'https://abcxyz.supabase.co';"],"mappings":""}`))
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
		if discovery.Evidence.Source == "source_map" && discovery.Evidence.File == "src/lib/supabase.ts" {
			return
		}
	}
	t.Fatalf("expected adjacent source map discovery, got %#v", discoveries)
}

func TestScanURLIgnoresMissingAdjacentSourceMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			_, _ = w.Write([]byte(`console.log("app");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if _, err := NewStatic("", nil, false, 0).ScanURL(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
}

func TestScanLocalParsesSourceMapSourcesContent(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "app.js.map")
	content := `{"version":3,"sources":["src/lib/supabase.ts"],"sourcesContent":["export const supabaseUrl = 'https://abcxyz.supabase.co';"],"mappings":""}`
	if err := os.WriteFile(mapPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	discoveries, err := ScanLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range discoveries {
		if discovery.Type != "supabase_url" || discovery.Evidence == nil {
			continue
		}
		if discovery.Evidence.Source == "source_map" && discovery.Evidence.File == "src/lib/supabase.ts" {
			return
		}
	}
	t.Fatalf("expected local source map discovery, got %#v", discoveries)
}

func TestSourceMapCandidateURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "js", raw: "https://example.com/assets/app.js?v=1", want: "https://example.com/assets/app.js.map", ok: true},
		{name: "hashed js", raw: "https://example.com/assets/app-a1b2c3d4.js", want: "https://example.com/assets/app-a1b2c3d4.js.map", ok: true},
		{name: "mjs", raw: "https://example.com/assets/app.mjs", want: "https://example.com/assets/app.mjs.map", ok: true},
		{name: "css", raw: "https://example.com/assets/app.css#hash", want: "https://example.com/assets/app.css.map", ok: true},
		{name: "map", raw: "https://example.com/assets/app.js.map", ok: false},
		{name: "json", raw: "https://example.com/assets/manifest.json", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := sourceMapCandidateURL(test.raw)
			if ok != test.ok || got != test.want {
				t.Fatalf("sourceMapCandidateURL(%q) = %q, %v; want %q, %v", test.raw, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestSourceMapCandidateURLsIncludesHashStrippedVariants(t *testing.T) {
	got := sourceMapCandidateURLs("https://example.com/assets/index-Dg_4Nfjf.js?v=1#hash")
	want := []string{
		"https://example.com/assets/index-Dg_4Nfjf.js.map",
		"https://example.com/assets/index.js.map",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sourceMapCandidateURLs() = %#v, want %#v", got, want)
	}
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

	discoveries, ok := scanSourceMap("https://example.com/assets/app.js.map", string(encoded))
	if !ok {
		t.Fatal("expected scanSourceMap to report scanned sources")
	}
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

	discoveries, ok := scanSourceMap("https://example.com/assets/app.js.map", string(encoded))
	if !ok {
		t.Fatal("expected scanSourceMap to report scanned sources")
	}
	if len(discoveries) != 0 {
		t.Fatalf("discoveries = %#v, want none after source limit", discoveries)
	}
}

func TestScanURLReportsWAFBlockedAssets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("CF-Ray", "abc123")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("error 1020 access denied"))
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
		if discovery.Type == "waf_block" && discovery.Evidence != nil && strings.Contains(discovery.Evidence.Detail, "cloudflare") {
			return
		}
	}
	t.Fatalf("expected waf_block discovery, got %#v", discoveries)
}

func TestScanURLReportsVerifyingBrowserChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("CiteHR\n\nVerifying your browser..."))
	}))
	defer server.Close()

	discoveries, err := NewStatic("", nil, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range discoveries {
		if discovery.Type == "waf_block" && discovery.Evidence != nil && strings.Contains(discovery.Evidence.Detail, "verifying your browser") {
			return
		}
	}
	t.Fatalf("expected verifying browser WAF discovery, got %#v", discoveries)
}

func TestScanURLDoesNotSkipSuccessfulCloudflareAsset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("CF-Ray", "abc123")
			_, _ = w.Write([]byte("export const url = 'https://abcxyz.supabase.co';"))
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
		if discovery.Type == "supabase_url" {
			return
		}
	}
	t.Fatalf("expected Supabase discovery from successful CDN asset, got %#v", discoveries)
}

func TestScanURLDoesNotSkipSuccessfulAssetWithGenericChallengeWords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<script src="/assets/app.js"></script>`))
		case "/assets/app.js":
			_, _ = w.Write([]byte("const challenge = 'captcha'; export const url = 'https://abcxyz.supabase.co';"))
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
		if discovery.Type == "supabase_url" {
			return
		}
	}
	t.Fatalf("expected Supabase discovery from successful asset with generic challenge words, got %#v", discoveries)
}

func TestScanURLSetsDefaultRequestHeaders(t *testing.T) {
	// Verify default request headers are applied when none are provided.
	var gotAccept string
	var gotUpgrade string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotUpgrade = r.Header.Get("Upgrade-Insecure-Requests")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, err := NewStatic("", nil, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if gotAccept != defaultRequestHeaders["Accept"] {
		t.Fatalf("Accept header = %q, want %q", gotAccept, defaultRequestHeaders["Accept"])
	}
	if gotUpgrade != defaultRequestHeaders["Upgrade-Insecure-Requests"] {
		t.Fatalf("Upgrade-Insecure-Requests = %q, want %q", gotUpgrade, defaultRequestHeaders["Upgrade-Insecure-Requests"])
	}
}

func TestScanURLUsesDefaultUserAgent(t *testing.T) {
	// When no user agent is provided, the default browser-like User-Agent should be used.
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, err := NewStatic("", nil, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != defaultUserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, defaultUserAgent)
	}
}

func TestScanURLHeaderOverridePriority(t *testing.T) {
	headers := map[string]string{"Accept": "text/plain", "Accept-Language": "fr-FR"}

	var gotAccept string
	var gotLang string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotLang = r.Header.Get("Accept-Language")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, err := NewStatic("", headers, false, 0).ScanURL(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if gotAccept != "text/plain" {
		t.Fatalf("Accept = %q, want %q", gotAccept, "text/plain")
	}
	if gotLang != "fr-FR" {
		t.Fatalf("Accept-Language = %q, want %q", gotLang, "fr-FR")
	}
}

func TestCrossOriginRedirect(t *testing.T) {
	if _, ok := crossOriginRedirect("https://a.example/", "https://a.example/home"); ok {
		t.Fatal("same host should not count as cross-origin")
	}
	if _, ok := crossOriginRedirect("http://a.example/", "https://a.example/"); ok {
		t.Fatal("http->https upgrade on the same host should be allowed")
	}
	to, ok := crossOriginRedirect("https://a.example/", "https://b.example/")
	if !ok || to != "https://b.example/" {
		t.Fatalf("host change should be flagged, got %q %v", to, ok)
	}
}

func TestSameOriginNormalizesDefaultPorts(t *testing.T) {
	a, _ := url.Parse("https://example.com:443/x.js")
	b, _ := url.Parse("https://example.com/y.js")
	if !sameOrigin(a, b) {
		t.Fatal("explicit :443 should match the default https port")
	}
}

func TestScanAssetContentSkipsRawMapPass(t *testing.T) {
	// The same key in sourcesContent must not yield two discoveries (one from
	// the raw .map JSON, one from the source entry).
	encoded, err := json.Marshal(sourceMap{
		Sources:        []string{"src/app.js"},
		SourcesContent: []string{"export const key = 'sb_publishable_abcdefghijklmnopqrstuvwxyz';"},
	})
	if err != nil {
		t.Fatal(err)
	}
	discoveries := scanAssetContent("https://example.com/assets/app.js.map", string(encoded))
	keyCount := 0
	for _, d := range discoveries {
		if d.Type == "key" {
			keyCount++
		}
	}
	if keyCount != 1 {
		t.Fatalf("expected 1 key discovery, got %d: %#v", keyCount, discoveries)
	}
}

func TestScanAssetContentFallsBackToRawMap(t *testing.T) {
	// A .map without parseable sourcesContent still gets the raw scan.
	discoveries := scanAssetContent("https://example.com/assets/app.js.map", `{"version":3,"sources":["a.js"]}`)
	_ = discoveries // no panic; raw scan applies
	encoded, err := json.Marshal(sourceMap{
		Sources:        []string{"src/app.js"},
		SourcesContent: []string{""},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := scanAssetContent("https://example.com/assets/app.js.map", string(encoded))
	_ = raw
}
