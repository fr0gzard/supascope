package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

type GraphQLIntrospectionResult struct {
	ProjectURL string
	Status     model.ServiceStatus
	Enabled    bool
	Response   string
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

	client := &http.Client{Timeout: 15 * time.Second}
	probe := func(method, path string, body []byte) model.ServiceStatus {
		target := base.ResolveReference(&url.URL{Path: path}).String()
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			debugActive(opts.Debug, "active request build failed: url=%s err=%v", target, err)
			return model.ServiceUnknown
		}
		applyRequestHeaders(req, opts.UserAgent, opts.Headers)
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

func ProbeGraphQLIntrospection(ctx context.Context, projectURL string, opts ActiveOptions) (GraphQLIntrospectionResult, error) {
	base, err := url.Parse(projectURL)
	if err != nil {
		return GraphQLIntrospectionResult{}, err
	}
	if base.Scheme == "" || base.Host == "" {
		return GraphQLIntrospectionResult{}, fmt.Errorf("invalid Supabase project URL: %s", projectURL)
	}
	base.Path = ""
	base.RawQuery = ""
	base.Fragment = ""

	target := base.ResolveReference(&url.URL{Path: "/graphql/v1"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader([]byte(graphQLIntrospectionBody)))
	if err != nil {
		return GraphQLIntrospectionResult{}, err
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Content-Type", "application/json")
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		debugActive(opts.Debug, "graphql introspection failed: url=%s err=%v", target, err)
		return GraphQLIntrospectionResult{ProjectURL: projectURL, Status: model.ServiceUnknown}, nil
	}
	defer resp.Body.Close()
	debugActive(opts.Debug, "graphql introspection response: url=%s status=%s", target, resp.Status)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return GraphQLIntrospectionResult{}, err
	}
	response := formatJSON(body)
	return GraphQLIntrospectionResult{
		ProjectURL: projectURL,
		Status:     statusFromHTTP(resp.StatusCode),
		Enabled:    resp.StatusCode >= 200 && resp.StatusCode < 300 && hasGraphQLSchema(body),
		Response:   response,
	}, nil
}

const graphQLIntrospectionBody = `{"query":"query SupaScopeIntrospection { __schema { queryType { name } mutationType { name } subscriptionType { name } directives { name } types { kind name } } }"}`

func hasGraphQLSchema(body []byte) bool {
	var decoded struct {
		Data struct {
			Schema any `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return false
	}
	return decoded.Data.Schema != nil
}

func formatJSON(body []byte) string {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return string(body)
	}
	formatted, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return string(body)
	}
	return string(formatted) + "\n"
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
