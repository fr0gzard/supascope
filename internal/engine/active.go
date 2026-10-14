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
	"sort"
	"time"

	"supascope/internal/model"
)

type ActiveOptions struct {
	UserAgent          string
	Headers            map[string]string
	Key                string
	Debug              bool
	ActiveStorageTests bool
	// Pacing controls for active probes
	Delay          time.Duration
	MaxConcurrency int
}

type GraphQLIntrospectionResult struct {
	ProjectURL string
	Status     model.ServiceStatus
	Enabled    bool
	Response   string
}

type AuthSettings struct {
	SignupDisabled         bool
	ExternalProviders      []string
	MailerAutoconfirm      bool
	SMSAutoconfirm         bool
	ExternalAnonymousUsers bool
	ProjectURL             string
}

func ProbeProjectServices(ctx context.Context, projectURL string, opts ActiveOptions) (model.ServiceMap, []model.Discovery, error) {
	base, err := url.Parse(projectURL)
	if err != nil {
		return model.ServiceMap{}, nil, err
	}
	if base.Scheme == "" || base.Host == "" {
		return model.ServiceMap{}, nil, fmt.Errorf("invalid Supabase project URL: %s", projectURL)
	}
	base.Path = ""
	base.RawQuery = ""
	base.Fragment = ""

	client := &http.Client{Timeout: 15 * time.Second}

	type probeSpec struct {
		name   string
		method string
		path   string
		body   []byte
	}

	probes := []probeSpec{
		{name: "REST", method: http.MethodGet, path: "/rest/v1/"},
		{name: "Auth", method: http.MethodGet, path: "/auth/v1/settings"},
		{name: "Storage", method: http.MethodGet, path: storageProbePath(opts.ActiveStorageTests)},
		{name: "Realtime", method: http.MethodGet, path: "/realtime/v1/"},
		{name: "Functions", method: http.MethodGet, path: "/functions/v1/"},
		{name: "GraphQL", method: http.MethodPost, path: "/graphql/v1", body: []byte(`{"query":"query SupaScopeProbe { __typename }"}`)},
	}

	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 1
	}
	sem := make(chan struct{}, opts.MaxConcurrency)

	type probeResult struct {
		name   string
		status model.ServiceStatus
		disc   *model.Discovery
	}
	results := make(chan probeResult, len(probes))

	launched := 0
probeLoop:
	for i, p := range probes {
		select {
		case <-ctx.Done():
			break probeLoop
		case sem <- struct{}{}:
		}
		launched++
		go func(p probeSpec) {
			defer func() { <-sem }()
			target := base.ResolveReference(&url.URL{Path: p.path}).String()
			req, err := http.NewRequestWithContext(ctx, p.method, target, bytes.NewReader(p.body))
			if err != nil {
				debugActive(opts.Debug, "active request build failed: url=%s err=%v", target, err)
				results <- probeResult{p.name, model.ServiceUnknown, nil}
				return
			}
			applyRequestHeaders(req, opts.UserAgent, opts.Headers)
			if len(p.body) > 0 {
				req.Header.Set("Content-Type", "application/json")
			}
			if opts.Key != "" {
				req.Header.Set("apikey", opts.Key)
				req.Header.Set("Authorization", "Bearer "+opts.Key)
			}

			resp, err := client.Do(req)
			if err != nil {
				debugActive(opts.Debug, "active fetch failed: url=%s err=%v", target, err)
				results <- probeResult{p.name, model.ServiceUnknown, nil}
				return
			}
			defer resp.Body.Close()
			debugActive(opts.Debug, "active response: method=%s url=%s status=%s", p.method, target, resp.Status)

			bodySampleBytes, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxWAFBodySampleBytes)))
			bodySample := string(bodySampleBytes)
			blocked, detail := detectWAF(resp.StatusCode, resp.Header, bodySample)
			var disc *model.Discovery
			if blocked {
				ev := model.Evidence{Source: "active_fetch", URL: target, Detail: detail, Snippet: wafBodySample(bodySample)}
				disc = &model.Discovery{Type: "waf_block", Value: detail, Source: "active_fetch", Evidence: &ev}
			}
			results <- probeResult{p.name, statusFromHTTP(resp.StatusCode), disc}
		}(p)

		if opts.Delay > 0 && i < len(probes)-1 {
			select {
			case <-ctx.Done():
				break probeLoop
			case <-time.After(opts.Delay):
			}
		}
	}

	services := model.ServiceMap{REST: model.ServiceNotObserved, Auth: model.ServiceNotObserved, Storage: model.ServiceNotObserved, Realtime: model.ServiceNotObserved, Functions: model.ServiceNotObserved, GraphQL: model.ServiceNotObserved}
	var discoveries []model.Discovery
	for i := 0; i < launched; i++ {
		res := <-results
		switch res.name {
		case "REST":
			services.REST = res.status
		case "Auth":
			services.Auth = res.status
		case "Storage":
			services.Storage = res.status
		case "Realtime":
			services.Realtime = res.status
		case "Functions":
			services.Functions = res.status
		case "GraphQL":
			services.GraphQL = res.status
		}
		if res.disc != nil {
			discoveries = append(discoveries, *res.disc)
		}
	}
	return services, discoveries, nil
}

func ProbeAuthSettings(ctx context.Context, projectURL string, opts ActiveOptions) (*AuthSettings, error) {
	base, err := url.Parse(projectURL)
	if err != nil {
		return nil, err
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid Supabase project URL: %s", projectURL)
	}
	base.Path = "/auth/v1/settings"
	base.RawQuery = ""
	base.Fragment = ""

	target := base.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		debugActive(opts.Debug, "auth settings fetch failed: url=%s err=%v", target, err)
		return nil, err
	}
	defer resp.Body.Close()
	debugActive(opts.Debug, "auth settings response: url=%s status=%s", target, resp.Status)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	return parseAuthSettings(projectURL, body), nil
}

func parseAuthSettings(projectURL string, body []byte) *AuthSettings {
	settings := &AuthSettings{ProjectURL: projectURL}
	var decoded struct {
		DisableSignup          *bool           `json:"disable_signup"`
		External               map[string]bool `json:"external"`
		MailerAutoconfirm      bool            `json:"mailer_autoconfirm"`
		SMSAutoconfirm         bool            `json:"sms_autoconfirm"`
		ExternalAnonymousUsers *bool           `json:"external_anonymous_users"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return settings
	}
	if decoded.DisableSignup != nil {
		settings.SignupDisabled = *decoded.DisableSignup
	}
	settings.MailerAutoconfirm = decoded.MailerAutoconfirm
	settings.SMSAutoconfirm = decoded.SMSAutoconfirm
	if decoded.ExternalAnonymousUsers != nil {
		settings.ExternalAnonymousUsers = *decoded.ExternalAnonymousUsers
	}
	for name, enabled := range decoded.External {
		if enabled {
			settings.ExternalProviders = append(settings.ExternalProviders, name)
		}
	}
	sort.Strings(settings.ExternalProviders)
	return settings
}

func AuthSettingsFindings(settings *AuthSettings) []model.Finding {
	if settings == nil {
		return nil
	}
	var findings []model.Finding
	ev := model.Evidence{Source: "active_check", URL: settings.ProjectURL + "/auth/v1/settings"}

	if settings.ExternalAnonymousUsers {
		findings = append(findings, model.Finding{
			ID:             "SUPA-AUTH-MED-001",
			Title:          "Anonymous sign-in is enabled",
			Severity:       "medium",
			Category:       "auth_configuration",
			Evidence:       ev,
			Impact:         "Anonymous users can create accounts without credentials, which may enable unauthorized access depending on RLS policies.",
			Recommendation: "Review anonymous user RLS policies and disable anonymous sign-in if not required.",
			Confidence:     "high",
		})
	}

	if !settings.SignupDisabled {
		findings = append(findings, model.Finding{
			ID:             "SUPA-AUTH-INFO-001",
			Title:          "Public signup is enabled",
			Severity:       "info",
			Category:       "auth_configuration",
			Evidence:       ev,
			Impact:         "Anyone with the project URL and anon key can create accounts.",
			Recommendation: "Disable signup if user registration is not required, or ensure RLS policies properly scope new users.",
			Confidence:     "high",
		})
	}

	if len(settings.ExternalProviders) > 0 {
		ev := ev
		ev.Detail = "enabled OAuth providers: " + joinStrings(settings.ExternalProviders, ", ")
		findings = append(findings, model.Finding{
			ID:             "SUPA-AUTH-INFO-002",
			Title:          "Social/OAuth providers are enabled",
			Severity:       "info",
			Category:       "auth_configuration",
			Evidence:       ev,
			Impact:         "External authentication providers were detected. This is expected if social login is intended.",
			Recommendation: "Review OAuth provider configurations and redirect URLs to prevent misuse.",
			Confidence:     "high",
		})
	}

	if !settings.MailerAutoconfirm {
		findings = append(findings, model.Finding{
			ID:             "SUPA-AUTH-INFO-003",
			Title:          "Email auto-confirmation is disabled",
			Severity:       "info",
			Category:       "auth_configuration",
			Evidence:       ev,
			Impact:         "Users can sign up without verifying their email address.",
			Recommendation: "Enable email confirmation in the Supabase dashboard if email validation is required for your use case.",
			Confidence:     "high",
		})
	}

	return findings
}

func joinStrings(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return values[0]
	}
	result := values[0]
	for _, v := range values[1:] {
		result += separator + v
	}
	return result
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

const graphQLIntrospectionBody = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields(includeDeprecated: true) { name description args { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } isDeprecated deprecationReason } inputFields { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } interfaces { kind name ofType { kind name ofType { kind name ofType { kind name } } } } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } directives { name description args { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } } } }"}`

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
