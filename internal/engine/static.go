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
	defaultUserAgent          = "SupaScope/0.1"
	maxSourceMapSources       = 250
	maxSourceMapBytesScanned  = 2 * 1024 * 1024
	maxSourceMapDiscoveries   = 25
	maxSourceContentScanBytes = 256 * 1024
	maxWAFBodySampleBytes     = 4096
)

var assetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:src|href)=["']([^"']+\.(?:js|mjs|css|map|json)(?:\?[^"']*)?)["']`),
	regexp.MustCompile(`["']([^"']*(?:/_next/static/|/assets/|/static/js/|/static/css/|/build/assets/)[^"']+\.(?:js|mjs|css|map|json)(?:\?[^"']*)?)["']`),
	regexp.MustCompile(`sourceMappingURL=([^\s*]+)`),
	regexp.MustCompile(`(?i)import\(\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']\s*\)`),
	regexp.MustCompile(`(?i)url\(\s*["']?([^"')]+\.(?:css|map|json)(?:\?[^"')]+)?)["']?\s*\)`),
}

type Static struct {
	client    *http.Client
	userAgent string
	headers   map[string]string
	debug     bool
	maxAssets int
}

func NewStatic(userAgent string, headers map[string]string, debug bool, maxAssets int) Static {
	if strings.TrimSpace(userAgent) == "" {
		userAgent = defaultUserAgent
	}
	if maxAssets <= 0 {
		maxAssets = defaultMaxAssets
	}
	return Static{client: &http.Client{Timeout: 15 * time.Second}, userAgent: userAgent, headers: headers, debug: debug, maxAssets: maxAssets}
}

func (s Static) ScanURL(ctx context.Context, target string) ([]model.Discovery, error) {
	root, err := s.fetch(ctx, target)
	if err != nil {
		return nil, err
	}
	s.debugf("root: target=%s final=%s bytes=%d", target, root.finalURL, len(root.body))

	var discoveries []model.Discovery
	discoveries = append(discoveries, wafDiscovery(root)...)
	discoveries = append(discoveries, scanAssetContent(root.finalURL, root.body)...)

	queue := make([]queuedAsset, 0)
	for _, asset := range s.discoverAssetURLs(root.finalURL, root.body) {
		queue = append(queue, queuedAsset{url: asset, depth: 1})
	}
	s.debugf("root assets: queued=%d", len(queue))

	visited := map[string]bool{}
	for len(queue) > 0 && len(visited) < s.maxAssets {
		next := queue[0]
		queue = queue[1:]
		if visited[next.url] || next.depth > maxDepth {
			continue
		}
		visited[next.url] = true

		fetched, err := s.fetch(ctx, next.url)
		if err != nil {
			s.debugf("fetch skipped: url=%s err=%v", next.url, err)
			continue
		}
		discoveries = append(discoveries, wafDiscovery(fetched)...)
		if fetched.blocked {
			s.debugf("fetch blocked: url=%s detail=%s", fetched.finalURL, fetched.wafDetail)
			continue
		}
		discoveries = append(discoveries, scanAssetContent(fetched.finalURL, fetched.body)...)

		for _, child := range s.discoverAssetURLs(fetched.finalURL, fetched.body) {
			if !visited[child] && len(queue)+len(visited) < s.maxAssets {
				queue = append(queue, queuedAsset{url: child, depth: next.depth + 1})
			}
		}
	}
	s.debugf("done: visited_assets=%d queued_remaining=%d max_assets=%d discoveries=%d", len(visited), len(queue), s.maxAssets, len(discoveries))

	return discoveries, nil
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
	for name, value := range s.headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("User-Agent", s.userAgent)

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
	for _, marker := range []string{"error 1020", "captcha", "challenge", "bot detection", "checking your browser", "attention required"} {
		if strings.Contains(lowerBody, marker) {
			add(marker)
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
			case "error 1020", "captcha", "challenge", "bot detection", "checking your browser", "attention required", "vercel edge block":
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
	if resolved.Scheme != baseURL.Scheme || resolved.Host != baseURL.Host {
		return "", false
	}
	resolved.Fragment = ""
	return resolved.String(), true
}

type queuedAsset struct {
	url   string
	depth int
}
