package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"supascope/internal/model"
)

type Identity struct {
	Name  string
	Token string
}

type RLSCheckOptions struct {
	UserAgent string
	Headers   map[string]string
	AnonKey   string
	Tokens    []Identity
	Debug     bool
	Delay     time.Duration
}

type RLSTableResult struct {
	Table     string
	Access    map[string]TableAccess
	CrossUser *CrossUserResult
}

type CrossUserResult struct {
	UserA    string
	UserB    string
	Overlap  int
	TotalA   int
	TotalB   int
	Isolated bool
}

func ProbeRLS(ctx context.Context, projectURL string, opts RLSCheckOptions) ([]RLSTableResult, error) {
	if !strings.HasSuffix(projectURL, "/") {
		projectURL += "/"
	}

	allIdentities := append([]Identity{{Name: "anon", Token: opts.AnonKey}}, opts.Tokens...)

	openapi, err := fetchOpenAPIForRLS(ctx, projectURL, opts, allIdentities)
	if err != nil {
		return nil, fmt.Errorf("could not fetch REST OpenAPI with any identity: %w", err)
	}

	tables := extractTables(openapi)
	if len(tables) == 0 {
		return nil, nil
	}

	if opts.Delay <= 0 {
		opts.Delay = 200 * time.Millisecond
	}

	var results []RLSTableResult
	for i, table := range tables {
		if err := ctx.Err(); err != nil {
			return results, err
		}

		result := RLSTableResult{
			Table:  table,
			Access: make(map[string]TableAccess),
		}

		for _, identity := range allIdentities {
			ta := TableAccess{Table: table}
			ta.Readable = probeReadAccessRLS(ctx, projectURL, table, identity, opts)
			ta.Writable = probeWriteAccessRLS(ctx, projectURL, table, identity, opts)
			result.Access[identity.Name] = ta
			debugRLS(opts.Debug, "table=%s identity=%s readable=%v writable=%v", table, identity.Name, ta.Readable, ta.Writable)
		}

		if len(opts.Tokens) >= 2 {
			result.CrossUser = probeCrossUserIsolation(ctx, projectURL, table, opts.Tokens[0], opts.Tokens[1], opts)
		}

		results = append(results, result)

		if opts.Delay > 0 && i < len(tables)-1 {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}
	return results, nil
}

func fetchOpenAPIForRLS(ctx context.Context, baseURL string, opts RLSCheckOptions, identities []Identity) (*openAPIDef, error) {
	openapiURL := baseURL + "rest/v1/"
	for _, identity := range identities {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, openapiURL, nil)
		if err != nil {
			continue
		}
		applyRequestHeaders(req, opts.UserAgent, opts.Headers)
		req.Header.Set("Accept", "application/json")
		if identity.Token != "" {
			req.Header.Set("apikey", identity.Token)
			req.Header.Set("Authorization", "Bearer "+identity.Token)
		}

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var def openAPIDef
		if err := json.NewDecoder(resp.Body).Decode(&def); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		return &def, nil
	}
	return nil, fmt.Errorf("no identity could access OpenAPI endpoint")
}

func probeReadAccessRLS(ctx context.Context, baseURL, table string, identity Identity, opts RLSCheckOptions) bool {
	url := baseURL + "rest/v1/" + table + "?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Accept", "application/json")
	if identity.Token != "" {
		req.Header.Set("apikey", identity.Token)
		req.Header.Set("Authorization", "Bearer "+identity.Token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func probeWriteAccessRLS(ctx context.Context, baseURL, table string, identity Identity, opts RLSCheckOptions) bool {
	url := baseURL + "rest/v1/" + table
	body := []byte(`{"supascope_rls_probe":true}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")
	if identity.Token != "" {
		req.Header.Set("apikey", identity.Token)
		req.Header.Set("Authorization", "Bearer "+identity.Token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func probeCrossUserIsolation(ctx context.Context, baseURL, table string, userA, userB Identity, opts RLSCheckOptions) *CrossUserResult {
	idsA, totalA := fetchRowIDs(ctx, baseURL, table, userA, opts)
	idsB, totalB := fetchRowIDs(ctx, baseURL, table, userB, opts)

	overlap := 0
	setA := make(map[string]bool, len(idsA))
	for _, id := range idsA {
		setA[id] = true
	}
	for _, id := range idsB {
		if setA[id] {
			overlap++
		}
	}

	return &CrossUserResult{
		UserA:    userA.Name,
		UserB:    userB.Name,
		Overlap:  overlap,
		TotalA:   totalA,
		TotalB:   totalB,
		Isolated: overlap == 0 && len(idsA) > 0 && len(idsB) > 0,
	}
}

func fetchRowIDs(ctx context.Context, baseURL, table string, identity Identity, opts RLSCheckOptions) ([]string, int) {
	url := baseURL + "rest/v1/" + table + "?select=id&limit=20"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	applyRequestHeaders(req, opts.UserAgent, opts.Headers)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Range", "0-19")
	if identity.Token != "" {
		req.Header.Set("apikey", identity.Token)
		req.Header.Set("Authorization", "Bearer "+identity.Token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0
	}

	var rows []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, 0
	}

	var ids []string
	for _, row := range rows {
		if id, ok := row["id"]; ok {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return ids, len(rows)
}

func RLSFindings(results []RLSTableResult, projectURL string) []model.Finding {
	var findings []model.Finding
	for _, result := range results {
		anonAccess := result.Access["anon"]

		if anonAccess.Writable {
			findings = append(findings, rlsFinding("SUPA-RLS-CRIT-001",
				fmt.Sprintf("Anonymous write access to table %q", result.Table),
				"critical",
				fmt.Sprintf("Anonymous users can insert rows into %q without authentication.", result.Table),
				"Add restrictive RLS policies for INSERT/UPDATE or require authentication.",
				projectURL, result.Table))
		}

		if anonAccess.Readable {
			findings = append(findings, rlsFinding("SUPA-RLS-HIGH-001",
				fmt.Sprintf("Anonymous read access to table %q", result.Table),
				"high",
				fmt.Sprintf("Anonymous users can read all rows from %q.", result.Table),
				"Add or tighten RLS SELECT policies to limit anonymous data access.",
				projectURL, result.Table))
		}

		for name, access := range result.Access {
			if name == "anon" {
				continue
			}
			if access.Writable && !anonAccess.Writable {
				findings = append(findings, rlsFinding("SUPA-RLS-MED-001",
					fmt.Sprintf("Authenticated write access to table %q (%s)", result.Table, name),
					"medium",
					fmt.Sprintf("Authenticated user %s can write to %q. Verify this is intended and RLS scopes writes to the user's own rows.", name, result.Table),
					"Ensure INSERT/UPDATE policies check auth.uid() = user_id for user-scoped tables.",
					projectURL, result.Table))
			}
		}

		if result.CrossUser != nil {
			if result.CrossUser.Overlap > 0 {
				findings = append(findings, model.Finding{
					ID:       "SUPA-RLS-CRIT-002",
					Title:    fmt.Sprintf("Cross-user data leak in table %q", result.Table),
					Severity: "critical",
					Category: "rls_isolation",
					Evidence: model.Evidence{
						Source: "rls_check",
						URL:    projectURL + "/rest/v1/" + result.Table,
						Detail: fmt.Sprintf("Users %s and %s share %d overlapping rows (A: %d, B: %d). RLS may not be user-scoped.",
							result.CrossUser.UserA, result.CrossUser.UserB,
							result.CrossUser.Overlap, result.CrossUser.TotalA, result.CrossUser.TotalB),
					},
					Impact:         "One authenticated user can see another user's private data. This indicates broken or missing RLS policies.",
					Recommendation: "Add RLS policies with auth.uid() = user_id for SELECT on user-scoped tables.",
					Confidence:     "high",
				})
			} else if result.CrossUser.TotalA > 0 && result.CrossUser.TotalB > 0 {
				findings = append(findings, model.Finding{
					ID:       "SUPA-RLS-INFO-001",
					Title:    fmt.Sprintf("RLS isolation verified for table %q", result.Table),
					Severity: "info",
					Category: "rls_isolation",
					Evidence: model.Evidence{
						Source: "rls_check",
						URL:    projectURL + "/rest/v1/" + result.Table,
						Detail: fmt.Sprintf("Users %s and %s see disjoint row sets (A: %d, B: %d). RLS appears user-scoped.",
							result.CrossUser.UserA, result.CrossUser.UserB,
							result.CrossUser.TotalA, result.CrossUser.TotalB),
					},
					Impact:         "No cross-user data leakage was detected. RLS policies appear to correctly isolate user data.",
					Recommendation: "",
					Confidence:     "high",
				})
			}
		}
	}
	return findings
}

func rlsFinding(id, title, severity, impact, recommendation, projectURL, table string) model.Finding {
	return model.Finding{
		ID:       id,
		Title:    title,
		Severity: severity,
		Category: "rls_access",
		Evidence: model.Evidence{
			Source: "rls_check",
			URL:    projectURL + "/rest/v1/" + table,
		},
		Impact:         impact,
		Recommendation: recommendation,
		Confidence:     "high",
	}
}

func debugRLS(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}