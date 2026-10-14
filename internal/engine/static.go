package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"supascope/internal/detect"
	"supascope/internal/model"
)

const (
	defaultMaxAssets          = 50
	maxDepth                  = 3
	defaultUserAgent          = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SupaScope/0.1"
	minHashSegmentLength      = 6
	maxSourceMapSources       = 250
	maxSourceMapBytesScanned  = 2 * 1024 * 1024
	maxSourceMapDiscoveries   = 25
	maxSourceContentScanBytes = 256 * 1024
	maxWAFBodySampleBytes     = 4096
)

var assetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:src|href)=["']([^"']+\.(?:js|mjs|css|map|json)(?:\?[^"']*)?)["']`),
	regexp.MustCompile(`["']([^"']*(?:/_next/static/|/_nuxt/|/_astro/|/_app/immutable/|/assets/|/static/js/|/static/css/|/build/assets/|/build/|/dist/|/packs/|/js/|/css/)[^"']+\.(?:js|mjs|css|map|json)(?:\?[^"']*)?)["']`),
	regexp.MustCompile(`sourceMappingURL=([^\s*]+)`),
	regexp.MustCompile(`(?i)import\(\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']\s*\)`),
	regexp.MustCompile(`(?i)url\(\s*["']?([^"')]+\.(?:css|map|json)(?:\?[^"')]+)?)["']?\s*\)`),
}

var defaultRequestHeaders = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,text/css,application/json;q=0.8,*/*;q=0.7",
	"Accept-Language":           "en-US,en;q=0.9",
	"Cache-Control":             "no-cache",
	"Pragma":                    "no-cache",
	"Upgrade-Insecure-Requests": "1",
}

type Static struct {
	client         *http.Client
	userAgent      string
	headers        map[string]string
	debug          bool
	maxAssets      int
	delay          time.Duration
	maxConcurrency int
}

type StaticOptions struct {
	Delay          time.Duration
	MaxConcurrency int
}

func NewStatic(userAgent string, headers map[string]string, debug bool, maxAssets int, options ...StaticOptions) Static {
	if strings.TrimSpace(userAgent) == "" {
		userAgent = defaultUserAgent
	}
	if maxAssets <= 0 {
		maxAssets = defaultMaxAssets
	}
	staticOptions := StaticOptions{MaxConcurrency: 1}
	if len(options) > 0 {
		staticOptions = options[0]
	}
	if staticOptions.MaxConcurrency <= 0 {
		staticOptions.MaxConcurrency = 1
	}
	return Static{client: &http.Client{Timeout: 15 * time.Second}, userAgent: userAgent, headers: headers, debug: debug, maxAssets: maxAssets, delay: staticOptions.Delay, maxConcurrency: staticOptions.MaxConcurrency}
}

func (s Static) ScanURL(ctx context.Context, target string) ([]model.Discovery, error) {
	root, err := s.fetch(ctx, target)
	if err != nil {
		return nil, err
	}
	if redirectTo, ok := crossOriginRedirect(target, root.finalURL); ok {
		return nil, fmt.Errorf("target redirected cross-origin to %s: re-run the scan against that URL (with --yes) if it is in scope", redirectTo)
	}
	s.debugf("root: target=%s final=%s bytes=%d", target, root.finalURL, len(root.body))

	var discoveries []model.Discovery
	discoveries = append(discoveries, wafDiscovery(root)...)
	discoveries = append(discoveries, scanAssetContent(root.finalURL, root.body)...)

	queue := make([]queuedAsset, 0)
	queued := map[string]bool{}
	enqueueAssets(&queue, queued, nil, s.maxAssets, sourceMapCandidateURLs(root.finalURL), 1)
	for _, asset := range s.discoverAssetURLs(root.finalURL, root.body) {
		enqueueAsset(&queue, queued, nil, s.maxAssets, asset, 1)
	}
	enqueueAssets(&queue, queued, nil, s.maxAssets, frameworkSourceMapCandidateURLs(root.finalURL, root.body), 1)
	s.debugf("root assets: queued=%d", len(queue))

	visited := map[string]bool{}
	for len(queue) > 0 && len(visited) < s.maxAssets {
		batch := make([]queuedAsset, 0, s.maxConcurrency)
		for len(queue) > 0 && len(visited) < s.maxAssets && len(batch) < s.maxConcurrency {
			next := queue[0]
			queue = queue[1:]
			if visited[next.url] || next.depth > maxDepth {
				continue
			}
			visited[next.url] = true
			batch = append(batch, next)
		}
		if len(batch) == 0 {
			continue
		}

		for _, result := range s.fetchAssets(ctx, batch) {
			next := result.asset
			if result.err != nil {
				s.debugf("fetch skipped: url=%s err=%v", next.url, result.err)
				continue
			}
			fetched := result.fetched
			discoveries = append(discoveries, wafDiscovery(fetched)...)
			if fetched.blocked {
				s.debugf("fetch blocked: url=%s detail=%s", fetched.finalURL, fetched.wafDetail)
				continue
			}
			discoveries = append(discoveries, scanAssetContent(fetched.finalURL, fetched.body)...)

			enqueueAssets(&queue, queued, visited, s.maxAssets, sourceMapCandidateURLs(fetched.finalURL), next.depth+1)
			for _, child := range s.discoverAssetURLs(fetched.finalURL, fetched.body) {
				enqueueAsset(&queue, queued, visited, s.maxAssets, child, next.depth+1)
			}
			enqueueAssets(&queue, queued, visited, s.maxAssets, frameworkSourceMapCandidateURLs(fetched.finalURL, fetched.body), next.depth+1)
		}
	}
	s.debugf("done: visited_assets=%d queued_remaining=%d max_assets=%d discoveries=%d", len(visited), len(queue), s.maxAssets, len(discoveries))

	return discoveries, nil
}

type assetFetchResult struct {
	asset   queuedAsset
	fetched fetchResult
	err     error
}

func (s Static) fetchAssets(ctx context.Context, batch []queuedAsset) []assetFetchResult {
	results := make(chan assetFetchResult, len(batch))
	launched := 0
fetchLoop:
	for i, asset := range batch {
		select {
		case <-ctx.Done():
			break fetchLoop
		default:
		}
		launched++
		go func(asset queuedAsset) {
			fetched, err := s.fetch(ctx, asset.url)
			results <- assetFetchResult{asset: asset, fetched: fetched, err: err}
		}(asset)

		if s.delay > 0 && i < len(batch)-1 {
			select {
			case <-ctx.Done():
				break fetchLoop
			case <-time.After(s.delay):
			}
		}
	}

	out := make([]assetFetchResult, 0, launched)
	for i := 0; i < launched; i++ {
		out = append(out, <-results)
	}
	return out
}

type fetchResult struct {
	body      string
	finalURL  string
	blocked   bool
	wafDetail string
	wafSample string
}

func wafDiscovery(result fetchResult) []model.Discovery {
	if !result.blocked {
		return nil
	}
	evidence := model.Evidence{Source: "static_fetch", URL: result.finalURL, Detail: result.wafDetail, Snippet: result.wafSample}
	return []model.Discovery{{Type: "waf_block", Value: result.wafDetail, Source: "static_fetch", Evidence: &evidence}}
}

func scanAssetContent(fetchedURL string, content string) []model.Discovery {
	evidence := model.Evidence{Source: "static", URL: fetchedURL}
	discoveries := detect.Artifacts(content, evidence)
	if !isSourceMapURL(fetchedURL) {
		return discoveries
	}
	return append(discoveries, scanSourceMap(fetchedURL, content)...)
}

type sourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

func scanSourceMap(mapURL string, content string) []model.Discovery {
	var parsed sourceMap
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}
	var discoveries []model.Discovery
	scannedBytes := 0
	for index, sourceContent := range parsed.SourcesContent {
		if sourceContent == "" {
			continue
		}
		if index >= maxSourceMapSources || scannedBytes >= maxSourceMapBytesScanned || len(discoveries) >= maxSourceMapDiscoveries {
			break
		}
		if len(sourceContent) > maxSourceContentScanBytes {
			sourceContent = sourceContent[:maxSourceContentScanBytes]
		}
		scannedBytes += len(sourceContent)
		sourceName := fmt.Sprintf("sourcesContent[%d]", index)
		if index < len(parsed.Sources) && strings.TrimSpace(parsed.Sources[index]) != "" {
			sourceName = parsed.Sources[index]
		}
		evidence := model.Evidence{Source: "source_map", URL: mapURL, File: sourceName, Detail: "source map source: " + sourceName}
		discoveries = append(discoveries, detect.Artifacts(sourceContent, evidence)...)
	}
	return discoveries
}

func isSourceMapURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return strings.HasSuffix(strings.ToLower(rawURL), ".map")
	}
	return strings.HasSuffix(strings.ToLower(parsed.Path), ".map")
}

func sourceMapCandidateURL(rawURL string) (string, bool) {
	candidates := sourceMapCandidateURLs(rawURL)
	if len(candidates) == 0 {
		return "", false
	}
	return candidates[0], true
}

func sourceMapCandidateURLs(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	path := strings.ToLower(parsed.Path)
	if !(strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") || strings.HasSuffix(path, ".css")) {
		return nil
	}

	adjacent := *parsed
	adjacent.Path += ".map"
	adjacent.RawQuery = ""
	adjacent.Fragment = ""
	candidates := []string{adjacent.String()}

	if hashStripped, ok := hashStrippedSourceMapCandidateURL(parsed); ok && hashStripped != candidates[0] {
		candidates = append(candidates, hashStripped)
	}
	return candidates
}

func hashStrippedSourceMapCandidateURL(parsed *url.URL) (string, bool) {
	basePath := parsed.Path
	lastSlash := strings.LastIndex(basePath, "/")
	dir := ""
	file := basePath
	if lastSlash >= 0 {
		dir = basePath[:lastSlash+1]
		file = basePath[lastSlash+1:]
	}

	ext := ""
	for _, candidateExt := range []string{".mjs", ".js", ".css"} {
		if strings.HasSuffix(strings.ToLower(file), candidateExt) {
			ext = file[len(file)-len(candidateExt):]
			file = file[:len(file)-len(candidateExt)]
			break
		}
	}
	if ext == "" {
		return "", false
	}

	separator := strings.LastIndexAny(file, "-.")
	if separator <= 0 || separator == len(file)-1 {
		return "", false
	}
	if !looksLikeAssetHash(file[separator+1:]) {
		return "", false
	}

	candidate := *parsed
	candidate.Path = dir + file[:separator] + ext + ".map"
	candidate.RawQuery = ""
	candidate.Fragment = ""
	return candidate.String(), true
}

func looksLikeAssetHash(value string) bool {
	if len(value) < minHashSegmentLength {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func frameworkSourceMapCandidateURLs(base string, content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, asset := range DiscoverAssetURLs(base, content) {
		for _, candidate := range sourceMapCandidateURLs(asset) {
			if !seen[candidate] {
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	return out
}

func enqueueAssets(queue *[]queuedAsset, queued map[string]bool, visited map[string]bool, maxAssets int, urls []string, depth int) {
	for _, rawURL := range urls {
		enqueueAsset(queue, queued, visited, maxAssets, rawURL, depth)
	}
}

func enqueueAsset(queue *[]queuedAsset, queued map[string]bool, visited map[string]bool, maxAssets int, rawURL string, depth int) {
	if rawURL == "" || queued[rawURL] || visited[rawURL] || len(*queue)+len(visited) >= maxAssets {
		return
	}
	queued[rawURL] = true
	*queue = append(*queue, queuedAsset{url: rawURL, depth: depth})
}

func DiscoverAssetURLs(base string, content string) []string {
	return discoverAssetURLs(base, content, nil)
}

func (s Static) discoverAssetURLs(base string, content string) []string {
	return discoverAssetURLs(base, content, s.debugf)
}

func discoverAssetURLs(base string, content string, debugf func(string, ...any)) []string {
	seen := map[string]bool{}
	var out []string

	for _, pattern := range assetPatterns {
		for _, match := range pattern.FindAllStringSubmatch(content, -1) {
			if len(match) < 2 {
				continue
			}
			resolved, ok := sameOriginURL(base, match[1])
			if !ok {
				if debugf != nil {
					debugf("asset rejected: base=%s candidate=%s", base, match[1])
				}
				continue
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			out = append(out, resolved)
		}
	}
	if debugf != nil {
		debugf("assets discovered: base=%s count=%d", base, len(out))
	}

	return out
}

func (s Static) fetch(ctx context.Context, target string) (fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fetchResult{}, err
	}
	applyRequestHeaders(req, s.userAgent, s.headers)

	resp, err := s.client.Do(req)
	if err != nil {
		return fetchResult{}, err
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return fetchResult{}, err
	}
	finalURL := resp.Request.URL.String()
	if target == resp.Request.URL.String() {
		s.debugf("response: url=%s status=%s content-type=%s content-encoding=%s", target, resp.Status, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))
	} else {
		s.debugf("response: requested=%s final=%s status=%s content-type=%s content-encoding=%s", target, finalURL, resp.Status, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))
	}
	blocked, detail := detectWAF(resp.StatusCode, resp.Header, string(bytes))
	result := fetchResult{body: string(bytes), finalURL: finalURL, blocked: blocked, wafDetail: detail, wafSample: wafBodySample(string(bytes))}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if blocked {
			return result, nil
		}
		return fetchResult{}, fmt.Errorf("request failed for %s: %s", target, resp.Status)
	}
	return result, nil
}

func applyRequestHeaders(req *http.Request, userAgent string, headers map[string]string) {
	for name, value := range defaultRequestHeaders {
		req.Header.Set(name, value)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = defaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
}

func detectWAF(statusCode int, headers http.Header, body string) (bool, string) {
	lowerBody := strings.ToLower(body)
	var matches []string
	add := func(value string) {
		if value != "" {
			matches = append(matches, value)
		}
	}

	blockingStatus := statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable || statusCode >= 500
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") || headers.Get("Cf-Ray") != "" || headers.Get("Cf-Cache-Status") != "" || headers.Get("Cf-Mitigated") != "" {
		add("cloudflare")
	}
	if headers.Get("X-Sucuri-ID") != "" || headers.Get("X-Sucuri-Block") != "" {
		add("sucuri")
	}
	if headers.Get("X-Iinfo") != "" || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "incap_ses") || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "visid_incap") {
		add("imperva/incapsula")
	}
	if strings.Contains(server, "akamai") || headers.Get("Akamai-Origin-Hop") != "" || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "ak_bmsc") {
		add("akamai")
	}
	if strings.Contains(server, "fastly") || headers.Get("Fastly-Restarts") != "" || headers.Get("X-Served-By") != "" && strings.Contains(strings.ToLower(headers.Get("X-Served-By")), "cache-") {
		add("fastly")
	}
	if headers.Get("X-Vercel-ID") != "" && (statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests) {
		add("vercel edge block")
	}
	for _, marker := range []string{"error 1020", "checking your browser", "verifying your browser", "attention required"} {
		if strings.Contains(lowerBody, marker) {
			add(marker)
		}
	}
	if blockingStatus {
		for _, marker := range []string{"captcha", "challenge", "bot detection"} {
			if strings.Contains(lowerBody, marker) {
				add(marker)
			}
		}
	}
	if blockingStatus && strings.Contains(lowerBody, "access denied") {
		add("access denied")
	}

	if len(matches) == 0 {
		return false, ""
	}
	if !blockingStatus {
		for _, match := range matches {
			switch match {
			case "error 1020", "checking your browser", "verifying your browser", "attention required", "vercel edge block":
				return true, fmt.Sprintf("possible WAF/CDN block: status=%d fingerprints=%s", statusCode, strings.Join(matches, ", "))
			}
		}
		return false, ""
	}
	return true, fmt.Sprintf("possible WAF/CDN block: status=%d fingerprints=%s", statusCode, strings.Join(matches, ", "))
}

func wafBodySample(body string) string {
	body = strings.TrimSpace(body)
	if len(body) > maxWAFBodySampleBytes {
		body = body[:maxWAFBodySampleBytes]
	}
	return body
}

func (s Static) debugf(format string, args ...any) {
	if s.debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}

func sameOriginURL(base string, candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || strings.HasPrefix(candidate, "data:") || strings.HasPrefix(candidate, "blob:") {
		return "", false
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	resolved, err := baseURL.Parse(candidate)
	if err != nil {
		return "", false
	}
	if !sameOrigin(baseURL, resolved) {
		return "", false
	}
	resolved.Fragment = ""
	return resolved.String(), true
}

// sameOrigin compares scheme, hostname, and effective port, so
// https://example.com and https://example.com:443 count as the same origin.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// crossOriginRedirect reports whether following redirects landed on a
// different host than the requested target. Scanning would otherwise
// silently drift onto a host the user didn't authorize. Scheme upgrades
// (http -> https) on the same host are allowed.
func crossOriginRedirect(target, final string) (string, bool) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	finalURL, err := url.Parse(final)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(targetURL.Hostname(), finalURL.Hostname()) {
		return final, true
	}
	return "", false
}

type queuedAsset struct {
	url   string
	depth int
}
