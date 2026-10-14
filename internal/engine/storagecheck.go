package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"supascope/internal/model"
)

type StorageCheckOptions struct {
	UserAgent string
	Headers   map[string]string
	Key       string
	Debug     bool
	Delay     time.Duration
}

type BucketInfo struct {
	Name   string `json:"name"`
	Public bool   `json:"public"`
	Owner  string `json:"owner"`
	Info   string `json:"-"`
}

func ProbeStorageBuckets(ctx context.Context, projectURL string, opts StorageCheckOptions) ([]BucketInfo, error) {
	if !strings.HasSuffix(projectURL, "/") {
		projectURL += "/"
	}
	bucketURL := projectURL + "storage/v1/bucket"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bucketURL, nil)
	if err != nil {
		return nil, err
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage bucket endpoint returned %d", resp.StatusCode)
	}

	var buckets []BucketInfo
	if err := json.NewDecoder(resp.Body).Decode(&buckets); err != nil {
		return nil, err
	}

	var results []BucketInfo
	for i, b := range buckets {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		b.Info = probeBucketMeta(ctx, projectURL, b.Name, opts)
		debugStorageCheck(opts.Debug, "bucket %s: public=%v info=%s", b.Name, b.Public, b.Info)
		results = append(results, b)

		if opts.Delay > 0 && i < len(buckets)-1 {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}
	return results, nil
}

// probeBucketMeta checks whether a bucket's objects can be enumerated.
// It uses the real list endpoint (POST /object/list/{bucket}); the previous
// GET on /object/public/{bucket}/ could never return 2xx on real Supabase
// Storage, which made the public_listable finding unreachable.
func probeBucketMeta(ctx context.Context, projectURL, bucket string, opts StorageCheckOptions) string {
	url := fmt.Sprintf("%sstorage/v1/object/list/%s", projectURL, url.PathEscape(bucket))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(`{"prefix":"","limit":1}`))
	if err != nil {
		return ""
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Content-Type", "application/json")
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "public_listable"
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return "public_forbidden"
	}
	if resp.StatusCode == http.StatusNotFound {
		return "empty_or_unlisted"
	}
	return fmt.Sprintf("status_%d", resp.StatusCode)
}

func StorageBucketFindings(buckets []BucketInfo, projectURL string) []model.Finding {
	var findings []model.Finding
	for _, b := range buckets {
		if b.Public {
			ev := model.Evidence{
				Source: "storage_check",
				URL:    projectURL + "/storage/v1/bucket/" + b.Name,
				Detail: fmt.Sprintf("bucket %q is publicly accessible", b.Name),
			}
			severity := "info"
			impact := "This bucket allows public access. This is expected for CDN usage but may expose internal files if unintentionally made public."
			if b.Info == "public_listable" {
				severity = "medium"
				impact = "Public listing is enabled, allowing anyone to enumerate all objects in this bucket. This may leak file structure and metadata."
			}
			findings = append(findings, model.Finding{
				ID:             "SUPA-STOR-INFO-001",
				Title:          fmt.Sprintf("Public storage bucket %q detected", b.Name),
				Severity:       severity,
				Category:       "storage_access",
				Evidence:       ev,
				Impact:         impact,
				Recommendation: "Review bucket permissions. If public access is not required, restrict it to authenticated users only.",
				Confidence:     "high",
			})
		} else {
			ev := model.Evidence{
				Source: "storage_check",
				URL:    projectURL + "/storage/v1/bucket/" + b.Name,
				Detail: fmt.Sprintf("bucket %q is private", b.Name),
			}
			findings = append(findings, model.Finding{
				ID:             "SUPA-STOR-INFO-002",
				Title:          fmt.Sprintf("Private storage bucket %q", b.Name),
				Severity:       "info",
				Category:       "storage_access",
				Evidence:       ev,
				Impact:         "Bucket is not publicly accessible, which is the recommended default.",
				Recommendation: "",
				Confidence:     "high",
			})
		}
	}
	return findings
}

func debugStorageCheck(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
