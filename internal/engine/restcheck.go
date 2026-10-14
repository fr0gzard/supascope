package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	urlpkg "net/url"
	"os"
	"sort"
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
		ta.Writable = probeWriteAccess(ctx, projectURL, table, openapi, opts)
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
	Paths       map[string]map[string]interface{} `json:"paths"`
	Definitions map[string]tableDefinition        `json:"definitions"`
}

// tableDefinition is one entry of the OpenAPI definitions section: the
// table's columns and which of them are required.
type tableDefinition struct {
	Required   []string       `json:"required"`
	Properties map[string]any `json:"properties"`
}

// probeColumns returns the table's non-required column names: columns that
// accept NULL or fall back to a default, so a write probe can POST a row of
// NULLs that the database will accept when INSERT is permitted. Empty when
// every column is required or the schema is unknown.
func (d *openAPIDef) probeColumns(table string) []string {
	if d == nil {
		return nil
	}
	var def tableDefinition
	found := false
	for name, td := range d.Definitions {
		if name == table || strings.HasSuffix(name, "."+table) {
			def, found = td, true
			break
		}
	}
	if !found || len(def.Properties) == 0 {
		return nil
	}
	required := make(map[string]bool, len(def.Required))
	for _, c := range def.Required {
		required[c] = true
	}
	var cols []string
	for col := range def.Properties {
		if !required[col] {
			cols = append(cols, col)
		}
	}
	sort.Strings(cols)
	return cols
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

// writeProbeResult is the outcome of a minimally-mutating write probe.
type writeProbeResult int

const (
	// writeDenied means the project rejected the INSERT (401/403).
	writeDenied writeProbeResult = iota
	// writeAllowed means the INSERT succeeded: one null row was inserted.
	writeAllowed
	// writeInconclusive means the probe could not determine write access
	// (validation error, unknown schema, network failure).
	writeInconclusive
)

type writeProbeOpts struct {
	UserAgent string
	Headers   map[string]string
	Debug     bool
}

// probeTableWrite tests INSERT permission by POSTing a row of NULLs over the
// table's non-required columns. Real column names are used: the previous
// probe sent a fake "supascope_probe" column, which PostgREST always rejects
// with 400 (PGRST204), so the write finding could never fire. A 2xx proves
// write access (one null row is inserted - documented, authorized testing
// only); 401/403 proves denial; anything else is inconclusive rather than a
// false negative.
func probeTableWrite(ctx context.Context, baseURL, table string, columns []string, token string, opts writeProbeOpts) writeProbeResult {
	if len(columns) == 0 {
		return writeInconclusive
	}
	payload := make(map[string]any, len(columns))
	for _, c := range columns {
		payload[c] = nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return writeInconclusive
	}
	probeURL := baseURL + "rest/v1/" + urlpkg.PathEscape(table)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, bytes.NewReader(body))
	if err != nil {
		return writeInconclusive
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")
	if token != "" {
		req.Header.Set("apikey", token)
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return writeInconclusive
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		debugWriteProbe(opts.Debug, "table %s: write probe accepted (HTTP %d), one null row inserted", table, resp.StatusCode)
		return writeAllowed
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return writeDenied
	default:
		debugWriteProbe(opts.Debug, "table %s: write probe inconclusive (HTTP %d)", table, resp.StatusCode)
		return writeInconclusive
	}
}

func debugWriteProbe(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}

func probeReadAccess(ctx context.Context, baseURL, table string, opts RestCheckOptions) bool {
	url := baseURL + "rest/v1/" + urlpkg.PathEscape(table) + "?limit=1"
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

func probeWriteAccess(ctx context.Context, baseURL, table string, def *openAPIDef, opts RestCheckOptions) bool {
	return probeTableWrite(ctx, baseURL, table, def.probeColumns(table), opts.Key, writeProbeOpts{
		UserAgent: opts.UserAgent,
		Headers:   opts.Headers,
		Debug:     opts.Debug,
	}) == writeAllowed
}

func RestAccessFindings(access []TableAccess, projectURL string) []model.Finding {
	var findings []model.Finding
	for _, ta := range access {
		if ta.Writable {
			ev := model.Evidence{
				Source: "rest_check",
				URL:    projectURL + "/rest/v1/" + ta.Table,
				Detail: "Anonymous users can insert rows into this table. The scanner inserted one null probe row to confirm this.",
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
