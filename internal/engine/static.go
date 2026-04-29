package engine

import (
	"context"
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
	defaultMaxAssets = 50
	maxDepth         = 3
	defaultUserAgent = "SupaScope/0.1"
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
	body, finalURL, err := s.fetch(ctx, target)
	if err != nil {
		return nil, err
	}
	s.debugf("root: target=%s final=%s bytes=%d", target, finalURL, len(body))

	var discoveries []model.Discovery
	discoveries = append(discoveries, detect.Artifacts(body, model.Evidence{Source: "static", URL: finalURL})...)

	queue := make([]queuedAsset, 0)
	for _, asset := range s.discoverAssetURLs(finalURL, body) {
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

		content, fetchedURL, err := s.fetch(ctx, next.url)
		if err != nil {
			s.debugf("fetch skipped: url=%s err=%v", next.url, err)
			continue
		}
		discoveries = append(discoveries, detect.Artifacts(content, model.Evidence{Source: "static", URL: fetchedURL})...)

		for _, child := range s.discoverAssetURLs(fetchedURL, content) {
			if !visited[child] && len(queue)+len(visited) < s.maxAssets {
				queue = append(queue, queuedAsset{url: child, depth: next.depth + 1})
			}
		}
	}
	s.debugf("done: visited_assets=%d queued_remaining=%d max_assets=%d discoveries=%d", len(visited), len(queue), s.maxAssets, len(discoveries))

	return discoveries, nil
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

func (s Static) fetch(ctx context.Context, target string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", err
	}
	for name, value := range s.headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if target == resp.Request.URL.String() {
		s.debugf("response: url=%s status=%s content-type=%s content-encoding=%s", target, resp.Status, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))
	} else {
		s.debugf("response: requested=%s final=%s status=%s content-type=%s content-encoding=%s", target, resp.Request.URL.String(), resp.Status, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", resp.Request.URL.String(), fmt.Errorf("request failed for %s: %s", target, resp.Status)
	}
	bytes, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return "", resp.Request.URL.String(), err
	}
	return string(bytes), resp.Request.URL.String(), nil
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
