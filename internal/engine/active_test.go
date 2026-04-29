package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	services, err := ProbeProjectServices(context.Background(), server.URL, ActiveOptions{
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
}
