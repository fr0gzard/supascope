package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"supascope/internal/model"
)

type ActiveOptions struct {
	UserAgent          string
	Headers            map[string]string
	Key                string
	Debug              bool
	ActiveStorageTests bool
}

func ProbeProjectServices(ctx context.Context, projectURL string, opts ActiveOptions) (model.ServiceMap, error) {
	base, err := url.Parse(projectURL)
	if err != nil {
		return model.ServiceMap{}, err
	}
	if base.Scheme == "" || base.Host == "" {
		return model.ServiceMap{}, fmt.Errorf("invalid Supabase project URL: %s", projectURL)
	}
	base.Path = ""
	base.RawQuery = ""
	base.Fragment = ""

	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	client := &http.Client{Timeout: 15 * time.Second}
	probe := func(method, path string, body []byte) model.ServiceStatus {
		target := base.ResolveReference(&url.URL{Path: path}).String()
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			debugActive(opts.Debug, "active request build failed: url=%s err=%v", target, err)
			return model.ServiceUnknown
		}
		for name, value := range opts.Headers {
			req.Header.Set(name, value)
		}
		req.Header.Set("User-Agent", userAgent)
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		if opts.Key != "" {
			req.Header.Set("apikey", opts.Key)
			req.Header.Set("Authorization", "Bearer "+opts.Key)
		}

		resp, err := client.Do(req)
		if err != nil {
			debugActive(opts.Debug, "active fetch failed: url=%s err=%v", target, err)
			return model.ServiceUnknown
		}
		defer resp.Body.Close()
		debugActive(opts.Debug, "active response: method=%s url=%s status=%s", method, target, resp.Status)
		return statusFromHTTP(resp.StatusCode)
	}

	services := model.ServiceMap{
		REST:      probe(http.MethodGet, "/rest/v1/", nil),
		Auth:      probe(http.MethodGet, "/auth/v1/settings", nil),
		Storage:   probe(http.MethodGet, storageProbePath(opts.ActiveStorageTests), nil),
		Realtime:  probe(http.MethodGet, "/realtime/v1/", nil),
		Functions: probe(http.MethodGet, "/functions/v1/", nil),
		GraphQL:   probe(http.MethodPost, "/graphql/v1", []byte(`{"query":"query SupaScopeProbe { __typename }"}`)),
	}
	return services, nil
}

func storageProbePath(activeStorageTests bool) string {
	if activeStorageTests {
		return "/storage/v1/bucket"
	}
	return "/storage/v1/"
}

func statusFromHTTP(code int) model.ServiceStatus {
	switch {
	case code >= 200 && code < 300:
		return model.ServiceReachable
	case code == http.StatusUnauthorized:
		return model.ServiceUnauthorized
	case code == http.StatusForbidden:
		return model.ServiceForbidden
	case code == http.StatusNotFound:
		return model.ServiceNotFound
	case code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable:
		return model.ServiceBlocked
	default:
		return model.ServiceUnknown
	}
}

func debugActive(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
