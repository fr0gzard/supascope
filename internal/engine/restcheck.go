package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"supascope/internal/model"
)

type RestCheckOptions struct {
	UserAgent string
	Headers   map[string]string
	Key       string
	Debug     bool
	Delay     time.Duration
}

type TableAccess struct {
	Table     string
	HasGet    bool
	HasPost   bool
	Readable  bool
	Writable  bool
	ScanError string
}

func ProbeRestTables(ctx context.Context, projectURL string, opts RestCheckOptions) ([]TableAccess, error) {
	if !strings.HasSuffix(projectURL, "/") {
		projectURL += "/"
	}

	openapiURL := projectURL + "rest/v1/"
	openapi, err := fetchOpenAPI(ctx, openapiURL, opts)
	if err != nil {
		return nil, err
	}

	tables := extractTables(openapi)
	if len(tables) == 0 {
		return nil, nil
	}

	if opts.Delay <= 0 {
		opts.Delay = 200 * time.Millisecond
	}

	var access []TableAccess
	for i, table := range tables {
		if err := ctx.Err(); err != nil {
			return access, err
		}
		ta := TableAccess{Table: table}
		if methods, ok := openapi.Paths["/"+table]; ok {
			if _, exists := methods["get"]; exists {
				ta.HasGet = true
			}
			if _, exists := methods["post"]; exists {
				ta.HasPost = true
			}
		}
		ta.Readable = probeReadAccess(ctx, projectURL, table, opts)
		ta.Writable = probeWriteAccess(ctx, projectURL, table, opts)
		access = append(access, ta)
		debugRestCheck(opts.Debug, "table %s: readable=%v writable=%v", table, ta.Readable, ta.Writable)

		if opts.Delay > 0 && i < len(tables)-1 {
			select {
			case <-ctx.Done():
				return access, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}
	return access, nil
}

type openAPIDef struct {
	Paths map[string]map[string]interface{} `json:"paths"`
}

func fetchOpenAPI(ctx context.Context, url string, opts RestCheckOptions) (*openAPIDef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openapi endpoint returned %d", resp.StatusCode)
	}

	var def openAPIDef
	if err := json.NewDecoder(resp.Body).Decode(&def); err != nil {
		return nil, err
	}
	return &def, nil
}

func extractTables(def *openAPIDef) []string {
	var tables []string
	for path := range def.Paths {
		if path == "/" || strings.HasPrefix(path, "/rpc/") {
			continue
		}
		table := strings.TrimPrefix(path, "/")
		if table != "" {
			tables = append(tables, table)
		}
	}
	return tables
}

func probeReadAccess(ctx context.Context, baseURL, table string, opts RestCheckOptions) bool {
	url := baseURL + "rest/v1/" + table + "?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func probeWriteAccess(ctx context.Context, baseURL, table string, opts RestCheckOptions) bool {
	url := baseURL + "rest/v1/" + table
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(`{"supascope_probe":true}`)))
	if err != nil {
		return false
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")
	if opts.Key != "" {
		req.Header.Set("apikey", opts.Key)
		req.Header.Set("Authorization", "Bearer "+opts.Key)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func RestAccessFindings(access []TableAccess, projectURL string) []model.Finding {
	var findings []model.Finding
	for _, ta := range access {
		if ta.Writable {
			ev := model.Evidence{
				Source: "rest_check",
				URL:    projectURL + "/rest/v1/" + ta.Table,
				Detail: "Anonymous users can insert rows into this table.",
			}
			findings = append(findings, model.Finding{
				ID:             "SUPA-REST-CRIT-001",
				Title:          fmt.Sprintf("Anonymous write access to table %q", ta.Table),
				Severity:       "critical",
				Category:       "rest_access",
				Evidence:       ev,
				Impact:         "Anonymous users can write arbitrary data to this table. This may lead to data corruption or resource exhaustion.",
				Recommendation: "Add restrictive RLS policies for INSERT and UPDATE operations or require authentication.",
				Confidence:     "high",
			})
		} else if ta.Readable {
			ev := model.Evidence{
				Source: "rest_check",
				URL:    projectURL + "/rest/v1/" + ta.Table,
				Detail: "Anonymous users can read all rows from this table.",
			}
			findings = append(findings, model.Finding{
				ID:             "SUPA-REST-HIGH-001",
				Title:          fmt.Sprintf("Anonymous read access to table %q", ta.Table),
				Severity:       "high",
				Category:       "rest_access",
				Evidence:       ev,
				Impact:         "Anonymous users can read all data from this table, potentially exposing sensitive information.",
				Recommendation: "Add or tighten RLS policies for SELECT operations to limit anonymous data access.",
				Confidence:     "high",
			})
		}
	}
	return findings
}

func debugRestCheck(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
