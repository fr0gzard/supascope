package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"supascope/internal/model"
)

func TestProbeProjectServicesClassifiesReadOnlyChecks(t *testing.T) {
	var gotAPIKey string
	var gotGraphQLMethod string
	var gotGraphQLContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("apikey")
		switch r.URL.Path {
		case "/rest/v1/":
			w.WriteHeader(http.StatusOK)
		case "/auth/v1/settings":
			w.WriteHeader(http.StatusUnauthorized)
		case "/storage/v1/bucket":
			w.WriteHeader(http.StatusForbidden)
		case "/realtime/v1/":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/functions/v1/":
			w.WriteHeader(http.StatusNotFound)
		case "/graphql/v1":
			gotGraphQLMethod = r.Method
			gotGraphQLContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	services, disc, err := ProbeProjectServices(context.Background(), server.URL, ActiveOptions{
		Key:                "test-key",
		ActiveStorageTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotAPIKey != "test-key" {
		t.Fatalf("apikey header = %q, want test-key", gotAPIKey)
	}
	if gotGraphQLMethod != http.MethodPost {
		t.Fatalf("GraphQL method = %q, want POST", gotGraphQLMethod)
	}
	if gotGraphQLContentType != "application/json" {
		t.Fatalf("GraphQL content type = %q, want application/json", gotGraphQLContentType)
	}
	if services.REST != model.ServiceReachable {
		t.Fatalf("REST = %q, want reachable", services.REST)
	}
	if services.Auth != model.ServiceUnauthorized {
		t.Fatalf("Auth = %q, want unauthorized", services.Auth)
	}
	if services.Storage != model.ServiceForbidden {
		t.Fatalf("Storage = %q, want forbidden", services.Storage)
	}
	if services.Realtime != model.ServiceBlocked {
		t.Fatalf("Realtime = %q, want blocked", services.Realtime)
	}
	if services.Functions != model.ServiceNotFound {
		t.Fatalf("Functions = %q, want not_found", services.Functions)
	}
	if services.GraphQL != model.ServiceReachable {
		t.Fatalf("GraphQL = %q, want reachable", services.GraphQL)
	}
	if len(disc) > 0 {
		// ensure any active discoveries are well-formed
		for _, d := range disc {
			if d.Type == "waf_block" && d.Evidence != nil {
				if d.Evidence.Source != "active_fetch" {
					t.Fatalf("unexpected evidence source: %s", d.Evidence.Source)
				}
			}
		}
	}
}

func TestProbeGraphQLIntrospectionDetectsEnabledSchema(t *testing.T) {
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql/v1" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"users"}]}}}`))
	}))
	defer server.Close()

	result, err := ProbeGraphQLIntrospection(context.Background(), server.URL, ActiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.ServiceReachable {
		t.Fatalf("Status = %q, want reachable", result.Status)
	}
	if !result.Enabled {
		t.Fatal("expected introspection enabled")
	}
	if !strings.Contains(gotBody, "__schema") {
		t.Fatalf("request body = %q, want introspection query", gotBody)
	}
	if !strings.Contains(result.Response, "\"__schema\"") {
		t.Fatalf("response = %q, want schema JSON", result.Response)
	}
}

func TestParseAuthSettingsSignupEnabled(t *testing.T) {
	settings := parseAuthSettings("https://test.supabase.co", []byte(`{
		"disable_signup": false,
		"external": {"google": true, "github": false},
		"mailer_autoconfirm": false,
		"sms_autoconfirm": false,
		"external_anonymous_users": null
	}`))
	if settings.SignupDisabled {
		t.Fatal("expected signup enabled")
	}
	if len(settings.ExternalProviders) != 1 || settings.ExternalProviders[0] != "google" {
		t.Fatalf("ExternalProviders = %#v, want [google]", settings.ExternalProviders)
	}
	if settings.MailerAutoconfirm {
		t.Fatal("expected mailer auto-confirm disabled")
	}
	if settings.ExternalAnonymousUsers {
		t.Fatal("expected anonymous users disabled")
	}
}

func TestParseAuthSettingsAnonymousEnabled(t *testing.T) {
	settings := parseAuthSettings("https://test.supabase.co", []byte(`{
		"disable_signup": true,
		"external": {},
		"mailer_autoconfirm": true,
		"sms_autoconfirm": true,
		"external_anonymous_users": true
	}`))
	if !settings.SignupDisabled {
		t.Fatal("expected signup disabled")
	}
	if len(settings.ExternalProviders) != 0 {
		t.Fatalf("ExternalProviders = %#v, want empty", settings.ExternalProviders)
	}
	if !settings.MailerAutoconfirm {
		t.Fatal("expected mailer auto-confirm enabled")
	}
	if !settings.ExternalAnonymousUsers {
		t.Fatal("expected anonymous users enabled")
	}
}

func TestAuthSettingsFindingsGeneratesForEnabledFeatures(t *testing.T) {
	settings := &AuthSettings{
		ProjectURL:             "https://test.supabase.co",
		SignupDisabled:         false,
		ExternalProviders:      []string{"google", "github"},
		ExternalAnonymousUsers: true,
	}
	findings := AuthSettingsFindings(settings)
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d", len(findings))
	}
	hasSignup := false
	hasProviders := false
	hasAnon := false
	for _, f := range findings {
		switch f.ID {
		case "SUPA-AUTH-INFO-001":
			hasSignup = true
		case "SUPA-AUTH-INFO-002":
			hasProviders = true
		case "SUPA-AUTH-MED-001":
			hasAnon = true
		}
	}
	if !hasSignup || !hasProviders || !hasAnon {
		t.Fatalf("missing expected findings: signup=%v providers=%v anon=%v", hasSignup, hasProviders, hasAnon)
	}
}

func TestAuthSettingsFindingsEmptyForDisabledFeatures(t *testing.T) {
	settings := &AuthSettings{
		ProjectURL:        "https://test.supabase.co",
		SignupDisabled:    true,
		MailerAutoconfirm: true,
	}
	findings := AuthSettingsFindings(settings)
	for _, f := range findings {
		if f.ID == "SUPA-AUTH-INFO-001" || f.ID == "SUPA-AUTH-INFO-003" {
			t.Fatalf("unexpected finding ID %s for disabled features", f.ID)
		}
	}
}

func TestProbeAuthSettingsReturnsAuthSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/v1/settings" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"disable_signup":false,"external":{"google":true},"mailer_autoconfirm":true}`))
	}))
	defer server.Close()

	settings, err := ProbeAuthSettings(context.Background(), server.URL, ActiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.SignupDisabled {
		t.Fatal("expected signup enabled")
	}
	if len(settings.ExternalProviders) != 1 || settings.ExternalProviders[0] != "google" {
		t.Fatalf("ExternalProviders = %#v", settings.ExternalProviders)
	}
}
