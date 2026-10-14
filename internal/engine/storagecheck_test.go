package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStorageBucketFindings(t *testing.T) {
	buckets := []BucketInfo{
		{Name: "avatars", Public: true, Info: "public_listable"},
		{Name: "documents", Public: false},
		{Name: "images", Public: true, Info: "public_forbidden"},
	}
	findings := StorageBucketFindings(buckets, "https://test.supabase.co")
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	if findings[0].Severity != "medium" {
		t.Fatalf("expected medium severity for listable public bucket, got %s", findings[0].Severity)
	}
	if findings[1].Severity != "info" || findings[1].ID != "SUPA-STOR-INFO-002" {
		t.Fatalf("expected info for private bucket, got %s %s", findings[1].Severity, findings[1].ID)
	}
	if findings[2].Severity != "info" {
		t.Fatalf("expected info for non-listable public bucket, got %s", findings[2].Severity)
	}
}

func TestProbeStorageBucketsIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/bucket" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"avatars","public":true,"owner":""},{"name":"docs","public":false,"owner":""}]`))
			return
		}
		if r.URL.Path == "/storage/v1/object/list/avatars" {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST for list probe, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"file.txt"}]`))
			return
		}
		if r.URL.Path == "/storage/v1/object/list/docs" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	buckets, err := ProbeStorageBuckets(context.Background(), server.URL+"/", StorageCheckOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(buckets))
	}
	if buckets[0].Name != "avatars" || buckets[0].Info != "public_listable" {
		t.Fatalf("unexpected bucket[0]: %#v", buckets[0])
	}
	if buckets[1].Name != "docs" || buckets[1].Info != "public_forbidden" {
		t.Fatalf("unexpected bucket[1]: %#v", buckets[1])
	}
}
func TestProbeBucketMetaUsesListEndpoint(t *testing.T) {
	var method, path, contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, contentType = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"file.txt"}]`))
	}))
	defer server.Close()

	got := probeBucketMeta(context.Background(), server.URL+"/", "avatars", StorageCheckOptions{})
	if got != "public_listable" {
		t.Fatalf("probeBucketMeta = %q, want public_listable", got)
	}
	if method != http.MethodPost || path != "/storage/v1/object/list/avatars" {
		t.Fatalf("probe used %s %s, want POST /storage/v1/object/list/avatars", method, path)
	}
	if contentType != "application/json" {
		t.Fatalf("content-type = %q, want application/json", contentType)
	}
}

func TestProbeBucketMetaForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	if got := probeBucketMeta(context.Background(), server.URL+"/", "avatars", StorageCheckOptions{}); got != "public_forbidden" {
		t.Fatalf("probeBucketMeta = %q, want public_forbidden", got)
	}
}
