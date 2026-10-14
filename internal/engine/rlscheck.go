package engine

import (
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

// RLSReport bundles per-table RLS results with identity-level warnings
// (rejected or duplicate tokens) that don't belong to any single table.
type RLSReport struct {
	Results  []RLSTableResult
	Warnings []string
}

func ProbeRLS(ctx context.Context, projectURL string, opts RLSCheckOptions) (*RLSReport, error) {
	if !strings.HasSuffix(projectURL, "/") {
		projectURL += "/"
	}

	allIdentities := append([]Identity{{Name: "anon", Token: opts.AnonKey}}, opts.Tokens...)

	tables, columns, rejected, anyOK := fetchTablesForRLS(ctx, projectURL, opts, allIdentities)
	if !anyOK {
		return nil, fmt.Errorf("could not fetch REST OpenAPI with any identity")
	}

	report := &RLSReport{}
	rejectedSet := make(map[string]bool, len(rejected))
	for _, id := range rejected {
		rejectedSet[id.Name] = true
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("identity %q was rejected by the project (HTTP 401/403): token may be expired, malformed, or issued for a different project; its RLS checks were skipped", id.Name))
	}

	// Only probe with identities the project actually accepted.
	var probeIdentities []Identity
	for _, id := range allIdentities {
		if !rejectedSet[id.Name] {
			probeIdentities = append(probeIdentities, id)
		}
	}
	var crossTokens []Identity
	for _, t := range opts.Tokens {
		if !rejectedSet[t.Name] {
			crossTokens = append(crossTokens, t)
		}
	}
	crossUserSkipped := ""
	if len(crossTokens) >= 2 && crossTokens[0].Token == crossTokens[1].Token {
		crossUserSkipped = "cross-user RLS check skipped: the two auth tokens are identical"
		report.Warnings = append(report.Warnings, crossUserSkipped)
	}

	if opts.Delay <= 0 {
		opts.Delay = 200 * time.Millisecond
	}

	for i, table := range tables {
		if err := ctx.Err(); err != nil {
			return report, err
		}

		result := RLSTableResult{
			Table:  table,
			Access: make(map[string]TableAccess),
		}

		for _, identity := range probeIdentities {
			ta := TableAccess{Table: table}
			ta.Readable = probeReadAccessRLS(ctx, projectURL, table, identity, opts)
			ta.Writable = probeWriteAccessRLS(ctx, projectURL, table, columns[table], identity, opts)
			result.Access[identity.Name] = ta
			debugRLS(opts.Debug, "table=%s identity=%s readable=%v writable=%v", table, identity.Name, ta.Readable, ta.Writable)
		}

		if len(crossTokens) >= 2 && crossUserSkipped == "" {
			result.CrossUser = probeCrossUserIsolation(ctx, projectURL, table, crossTokens[0], crossTokens[1], opts)
		}

		report.Results = append(report.Results, result)

		if opts.Delay > 0 && i < len(tables)-1 {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}
	return report, nil
}

// fetchTablesForRLS returns the union of tables visible to any identity, plus
// the identities whose token was refused (HTTP 401/403). PostgREST scopes its
// fetchTablesForRLS returns the union of tables visible to any identity -
// PostgREST scopes the OpenAPI per role, so authenticated-only tables are
// invisible to anon; unioning avoids skipping them in RLS testing. It also
// returns per-table probe columns for the write check.
func fetchTablesForRLS(ctx context.Context, baseURL string, opts RLSCheckOptions, identities []Identity) (tables []string, columns map[string][]string, rejected []Identity, anyOK bool) {
	columns = make(map[string][]string)
	seen := make(map[string]bool)
	for _, identity := range identities {
		def, status, err := fetchOpenAPIForIdentity(ctx, baseURL, opts, identity)
		if err != nil {
			continue
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden:
			if identity.Token != "" {
				rejected = append(rejected, identity)
			}
			continue
		case http.StatusOK:
			anyOK = true
			for _, t := range extractTables(def) {
				if !seen[t] {
					seen[t] = true
					tables = append(tables, t)
				}
				if _, ok := columns[t]; !ok {
					columns[t] = def.probeColumns(t)
				}
			}
		}
	}
	return tables, columns, rejected, anyOK
}

func fetchOpenAPIForIdentity(ctx context.Context, baseURL string, opts RLSCheckOptions, identity Identity) (*openAPIDef, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"rest/v1/", nil)
	if err != nil {
		return nil, 0, err
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
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var def openAPIDef
	if err := json.NewDecoder(resp.Body).Decode(&def); err != nil {
		return nil, 0, err
	}
	return &def, resp.StatusCode, nil
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

func probeWriteAccessRLS(ctx context.Context, baseURL, table string, columns []string, identity Identity, opts RLSCheckOptions) bool {
	return probeTableWrite(ctx, baseURL, table, columns, identity.Token, writeProbeOpts{
		UserAgent: opts.UserAgent,
		Headers:   opts.Headers,
		Debug:     opts.Debug,
	}) == writeAllowed
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
	url := baseURL + "rest/v1/" + urlpkg.PathEscape(table) + "?select=id&limit=20"
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

func RLSFindings(report *RLSReport, projectURL string) []model.Finding {
	var findings []model.Finding
	for _, warning := range report.Warnings {
		severity := "medium"
		if strings.HasPrefix(warning, "cross-user RLS check skipped") {
			severity = "low"
		}
		findings = append(findings, model.Finding{
			ID:             "SUPA-RLS-WARN-001",
			Title:          "RLS check coverage gap",
			Severity:       severity,
			Category:       "rls_access",
			Evidence:       model.Evidence{Source: "rls_check", URL: projectURL},
			Impact:         warning,
			Recommendation: "Verify the auth tokens are valid, unexpired, and issued for this project, then re-run the scan.",
			Confidence:     "high",
		})
	}
	for _, result := range report.Results {
		anonAccess := result.Access["anon"]

		if anonAccess.Writable {
			findings = append(findings, rlsFinding("SUPA-RLS-CRIT-001",
				fmt.Sprintf("Anonymous write access to table %q", result.Table),
				"critical",
				fmt.Sprintf("Anonymous users can insert rows into %q without authentication. The scanner inserted one null probe row to confirm this.", result.Table),
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

		for _, name := range sortedIdentityNames(result.Access) {
			if name == "anon" {
				continue
			}
			access := result.Access[name]
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
			} else if result.CrossUser.Isolated {
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

func sortedIdentityNames(access map[string]TableAccess) []string {
	names := make([]string, 0, len(access))
	for name := range access {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
