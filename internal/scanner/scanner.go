package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"supascope/internal/engine"
	"supascope/internal/keyclass"
	"supascope/internal/mask"
	"supascope/internal/model"
)

type Scanner struct{}

func New() Scanner {
	return Scanner{}
}

func (s Scanner) Scan(ctx context.Context, opts model.Options) (model.Report, error) {
	var discoveries []model.Discovery

	switch opts.Target.Type {
	case model.TargetLocalPath:
		found, err := engine.ScanLocal(opts.Target.Value)
		if err != nil {
			return model.Report{}, err
		}
		discoveries = append(discoveries, found...)
	case model.TargetURL:
		found, err := engine.NewStatic(opts.UserAgent, opts.Headers, opts.Debug, opts.MaxAssets, engine.StaticOptions{
			Delay:          opts.Delay,
			MaxConcurrency: opts.MaxConcurrency,
		}).ScanURL(ctx, opts.Target.Value)
		if err != nil {
			return model.Report{}, err
		}
		discoveries = append(discoveries, found...)
	case model.TargetSupabaseProject:
		ev := model.Evidence{Source: "provided", URL: opts.Target.Value}
		discoveries = append(discoveries, model.Discovery{Type: "supabase_url", Value: opts.Target.Value, Source: "provided", Evidence: &ev})
	}

	if opts.Key != "" {
		classified := keyclass.Classify(opts.Key)
		ev := model.Evidence{Source: "provided", MaskedValue: classified.MaskedValue, Detail: classified.Detail}
		discoveries = append(discoveries, model.Discovery{Type: "key", Value: opts.Key, MaskedValue: classified.MaskedValue, Source: "provided", Evidence: &ev})
	}

	discoveries = dedupeDiscoveries(discoveries)
	services := fingerprintServices(discoveries)
	activeServices := emptyServiceMap()
	if opts.ActiveChecks {
		activeDiscoveries := []model.Discovery{}
		activeServices, activeDiscoveries = activeServiceChecks(ctx, discoveries, opts)
		discoveries = dedupeDiscoveries(append(discoveries, activeDiscoveries...))
		services = mergeServiceMaps(services, activeServices)
	}
	findings := discoveriesToFindings(discoveries, opts.ShowSecrets)
	if opts.ActiveChecks {
		findings = append(findings, activeStatusFindings(activeServices)...)
	}
	if opts.GraphQLIntrospection {
		results := graphqlIntrospectionChecks(ctx, discoveries, opts)
		findings = append(findings, graphqlIntrospectionFindings(results)...)
		if opts.GraphQLSchemaOutput != "" {
			if err := writeGraphQLIntrospectionOutput(opts.GraphQLSchemaOutput, results); err != nil {
				return model.Report{}, err
			}
		}
	}

	if hasSupabaseEvidence(discoveries) && restCheckMissing(opts, services.REST) {
		findings = append(findings, model.Finding{
			ID:             "SUPA-REST-INFO-001",
			Title:          "REST API was not directly accessible",
			Severity:       "info",
			Category:       "service_status",
			Evidence:       model.Evidence{Source: "provided", Detail: "SupaScope could not perform REST/RLS capability checks. Other Supabase surfaces were still scanned."},
			Impact:         "REST/RLS capability checks were skipped for this scan.",
			Recommendation: "Run a dynamic scan or provide observed REST endpoints if REST/RLS inference is required.",
			Confidence:     "medium",
		})
	}
	findings = dedupeFindings(findings)

	return model.Report{
		Scanner:     model.ScannerInfo{Name: "SupaScope", Version: "0.1.0"},
		Target:      opts.Target,
		Mode:        mode(opts),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Services:    services,
		Discoveries: reportDiscoveries(discoveries, opts.ShowSecrets),
		Findings:    findings,
	}, nil
}

func graphqlIntrospectionChecks(ctx context.Context, discoveries []model.Discovery, opts model.Options) []engine.GraphQLIntrospectionResult {
	key := activeKey(discoveries, opts.Key)
	var results []engine.GraphQLIntrospectionResult
	for _, projectURL := range supabaseProjectURLs(discoveries, opts.Target) {
		result, err := engine.ProbeGraphQLIntrospection(ctx, projectURL, engine.ActiveOptions{
			UserAgent: opts.UserAgent,
			Headers:   opts.Headers,
			Key:       key,
			Debug:     opts.Debug,
		})
		if err != nil {
			continue
		}
		results = append(results, result)
	}
	return results
}

func graphqlIntrospectionFindings(results []engine.GraphQLIntrospectionResult) []model.Finding {
	findings := make([]model.Finding, 0, len(results))
	for _, result := range results {
		if result.Enabled {
			findings = append(findings, model.Finding{
				ID:             "SUPA-GRAPHQL-MED-001",
				Title:          "GraphQL introspection is enabled",
				Severity:       "medium",
				Category:       "graphql_introspection",
				Evidence:       model.Evidence{Source: "active_check", URL: result.ProjectURL + "/graphql/v1", Detail: "introspection status: enabled"},
				Impact:         "GraphQL introspection exposes schema structure to callers that can reach the endpoint. This can help attackers understand available types and operations.",
				Recommendation: "Disable introspection for public clients if it is not required, and confirm all exposed GraphQL access is protected by RLS and least-privilege policies.",
				Confidence:     "high",
			})
			continue
		}
		if result.Status == model.ServiceReachable || result.Response != "" {
			findings = append(findings, model.Finding{
				ID:             "SUPA-GRAPHQL-INFO-002",
				Title:          "GraphQL introspection did not return a schema",
				Severity:       "info",
				Category:       "graphql_introspection",
				Evidence:       model.Evidence{Source: "active_check", URL: result.ProjectURL + "/graphql/v1", Detail: graphqlIntrospectionDetail(result)},
				Impact:         "The GraphQL endpoint handled the request, but schema introspection was unavailable or returned errors.",
				Recommendation: "Review the GraphQL response body from --graphql-schema-output to confirm whether pg_graphql is disabled, introspection is blocked, or a key is required.",
				Confidence:     "medium",
			})
		}
	}
	return findings
}

func graphqlIntrospectionDetail(result engine.GraphQLIntrospectionResult) string {
	detail := fmt.Sprintf("introspection status: no_schema; http_status: %s", result.Status)
	if messages := graphQLErrorMessages(result.Response); len(messages) > 0 {
		detail += "; errors: " + strings.Join(messages, "; ")
	}
	return detail
}

func graphQLErrorMessages(response string) []string {
	var decoded struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(response), &decoded); err != nil {
		return nil
	}
	messages := make([]string, 0, len(decoded.Errors))
	for _, graphqlErr := range decoded.Errors {
		message := strings.TrimSpace(graphqlErr.Message)
		if message != "" {
			messages = append(messages, message)
		}
	}
	return messages
}

func writeGraphQLIntrospectionOutput(path string, results []engine.GraphQLIntrospectionResult) error {
	var b strings.Builder
	for i, result := range results {
		if result.Response == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		if len(results) > 1 {
			fmt.Fprintf(&b, "# %s\n\n", result.ProjectURL)
		} else if i == 0 {
			fmt.Fprintf(&b, "# %s\n\n", result.ProjectURL)
		}
		b.WriteString(result.Response)
		if !strings.HasSuffix(result.Response, "\n") {
			b.WriteString("\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func activeStatusFindings(services model.ServiceMap) []model.Finding {
	checks := []struct {
		name           string
		status         model.ServiceStatus
		reachableID    string
		reachableTitle string
		recommendation string
	}{
		{"REST", services.REST, "SUPA-ACTIVE-REST-INFO-001", "REST endpoint is reachable", "Confirm exposed tables are protected by RLS and least-privilege policies."},
		{"Auth", services.Auth, "SUPA-ACTIVE-AUTH-INFO-001", "Auth settings endpoint is reachable", "Review public auth settings and confirm enabled providers are intended."},
		{"Storage", services.Storage, "SUPA-ACTIVE-STORAGE-INFO-001", "Storage endpoint is reachable", "Confirm public bucket access and storage policies are intentional."},
		{"Realtime", services.Realtime, "SUPA-ACTIVE-REALTIME-INFO-001", "Realtime endpoint is reachable", "Confirm realtime channels and database changes are protected by authorization rules."},
		{"Functions", services.Functions, "SUPA-ACTIVE-FUNCTIONS-INFO-001", "Edge Functions endpoint is reachable", "Confirm functions enforce authorization where required."},
		{"GraphQL", services.GraphQL, "SUPA-ACTIVE-GRAPHQL-INFO-001", "GraphQL endpoint is reachable", "Confirm GraphQL exposure is intended and protected by RLS. This check does not test introspection."},
	}

	findings := make([]model.Finding, 0, len(checks))
	for _, check := range checks {
		finding, ok := activeStatusFinding(check.name, check.status, check.reachableID, check.reachableTitle, check.recommendation)
		if ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func activeStatusFinding(service string, status model.ServiceStatus, reachableID, reachableTitle, recommendation string) (model.Finding, bool) {
	source := strings.ToLower(service)
	detail := source + " status: " + string(status)
	slug := strings.ToUpper(service)

	switch status {
	case model.ServiceReachable:
		return model.Finding{
			ID:             reachableID,
			Title:          reachableTitle,
			Severity:       "info",
			Category:       "service_status",
			Evidence:       model.Evidence{Source: "active_check", Detail: detail},
			Impact:         service + " responded successfully to a safe active probe. This is not necessarily a vulnerability by itself.",
			Recommendation: recommendation,
			Confidence:     "medium",
		}, true
	case model.ServiceUnauthorized, model.ServiceForbidden:
		return model.Finding{
			ID:             "SUPA-ACTIVE-" + slug + "-INFO-002",
			Title:          service + " endpoint requires authorization",
			Severity:       "info",
			Category:       "service_status",
			Evidence:       model.Evidence{Source: "active_check", Detail: detail},
			Impact:         service + " rejected the safe active probe with an authorization-related response.",
			Recommendation: "No immediate issue was confirmed. Review this alongside static exposures and any authenticated scan results.",
			Confidence:     "medium",
		}, true
	case model.ServiceBlocked:
		return model.Finding{
			ID:             "SUPA-ACTIVE-" + slug + "-INFO-003",
			Title:          service + " active probe was blocked",
			Severity:       "info",
			Category:       "service_status",
			Evidence:       model.Evidence{Source: "active_check", Detail: detail},
			Impact:         service + " returned a rate-limit or temporary blocking response during active probing.",
			Recommendation: "Retry with pacing controls or verify manually if this service needs assessment.",
			Confidence:     "low",
		}, true
	default:
		return model.Finding{}, false
	}
}

func restCheckMissing(opts model.Options, status model.ServiceStatus) bool {
	if status == model.ServiceObserved || status == model.ServiceReachable {
		return false
	}
	if opts.ActiveChecks {
		return status == model.ServiceNotObserved || status == model.ServiceUnknown || status == model.ServiceBlocked
	}
	return true
}

func activeServiceChecks(ctx context.Context, discoveries []model.Discovery, opts model.Options) (model.ServiceMap, []model.Discovery) {
	services := emptyServiceMap()
	var activeDiscoveries []model.Discovery
	key := activeKey(discoveries, opts.Key)
	for _, projectURL := range supabaseProjectURLs(discoveries, opts.Target) {
		probed, disc, err := engine.ProbeProjectServices(ctx, projectURL, engine.ActiveOptions{
			UserAgent:          opts.UserAgent,
			Headers:            opts.Headers,
			Key:                key,
			Debug:              opts.Debug,
			ActiveStorageTests: opts.ActiveStorageTests,
			Delay:              opts.Delay,
			MaxConcurrency:     opts.MaxConcurrency,
		})
		if err != nil {
			continue
		}
		services = mergeServiceMaps(services, probed)
		activeDiscoveries = append(activeDiscoveries, disc...)
	}
	return services, activeDiscoveries
}

func emptyServiceMap() model.ServiceMap {
	return model.ServiceMap{
		REST: model.ServiceNotObserved, Auth: model.ServiceNotObserved, Storage: model.ServiceNotObserved,
		Realtime: model.ServiceNotObserved, Functions: model.ServiceNotObserved, GraphQL: model.ServiceNotObserved,
	}
}

func supabaseProjectURLs(discoveries []model.Discovery, target model.Target) []string {
	seen := map[string]bool{}
	var urls []string
	if target.Type == model.TargetSupabaseProject && target.Value != "" {
		seen[target.Value] = true
		urls = append(urls, target.Value)
	}
	for _, discovery := range discoveries {
		if discovery.Type != "supabase_url" || discovery.Value == "" || seen[discovery.Value] {
			continue
		}
		seen[discovery.Value] = true
		urls = append(urls, discovery.Value)
	}
	return urls
}

func activeKey(discoveries []model.Discovery, provided string) string {
	if provided != "" {
		return provided
	}
	for _, discovery := range discoveries {
		if discovery.Type != "key" || discovery.Value == "" {
			continue
		}
		classified := keyclass.Classify(discovery.Value)
		switch classified.Type {
		case "publishable_key", "legacy_anon_jwt":
			return discovery.Value
		}
	}
	return ""
}

func mergeServiceMaps(base, next model.ServiceMap) model.ServiceMap {
	base.REST = mergeServiceStatus(base.REST, next.REST)
	base.Auth = mergeServiceStatus(base.Auth, next.Auth)
	base.Storage = mergeServiceStatus(base.Storage, next.Storage)
	base.Realtime = mergeServiceStatus(base.Realtime, next.Realtime)
	base.Functions = mergeServiceStatus(base.Functions, next.Functions)
	base.GraphQL = mergeServiceStatus(base.GraphQL, next.GraphQL)
	return base
}

func mergeServiceStatus(base, next model.ServiceStatus) model.ServiceStatus {
	if base == model.ServiceObserved {
		return base
	}
	if next == "" || next == model.ServiceNotObserved {
		return base
	}
	if base == "" || base == model.ServiceNotObserved || base == model.ServiceUnknown {
		return next
	}
	if next == model.ServiceReachable {
		return next
	}
	return base
}

func discoveriesToFindings(discoveries []model.Discovery, showSecrets bool) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, discovery := range discoveries {
		switch discovery.Type {
		case "supabase_url":
			source := sourceCategory(discovery)
			findings = append(findings, model.Finding{
				ID: source.id, Title: source.title, Severity: "info", Category: source.category,
				Evidence:       evidenceOrDefault(discovery),
				Impact:         "Supabase usage was detected. Exposed project URLs are expected in frontend apps.",
				Recommendation: "Review exposed keys, RLS policies, and public storage settings for this project.",
				Confidence:     "high",
			})
		case "key":
			classified := keyclass.Classify(discovery.Value)
			source := sourceCategory(discovery)
			title := classified.Title
			category := "key_exposure"
			if source.category == "source_map_exposure" || source.category == "env_exposure" {
				title += " in " + source.label
				category = source.category
			}
			evidence := evidenceOrDefault(discovery)
			if showSecrets {
				evidence.MaskedValue = discovery.Value
			}
			evidence.Detail = classified.Detail
			findings = append(findings, model.Finding{
				ID: classified.FindingID, Title: title, Severity: classified.Severity, Category: category,
				Evidence: evidence,
				Impact:   classified.Impact, Recommendation: classified.Recommendation, Confidence: classified.Confidence,
			})
		case "endpoint":
			evidence := evidenceOrDefault(discovery)
			if showSecrets {
				evidence.MaskedValue = discovery.Value
			}
			findings = append(findings, model.Finding{
				ID: "SUPA-ENDPOINT-INFO-001", Title: "Supabase service endpoint observed", Severity: "info", Category: "service_detection",
				Evidence:       evidence,
				Impact:         "A Supabase API surface was referenced by the scanned application artifact.",
				Recommendation: "Confirm the referenced service is intended to be reachable and protected by least-privilege policies.",
				Confidence:     "high",
			})
		case "waf_block":
			findings = append(findings, model.Finding{
				ID:             "SUPA-WAF-INFO-001",
				Title:          "WAF or CDN blocking may have limited scan coverage",
				Severity:       "info",
				Category:       "scan_coverage",
				Evidence:       evidenceOrDefault(discovery),
				Impact:         "Some public assets or responses may not have been available to the scanner, so passive results may be incomplete.",
				Recommendation: "Retry with authorized headers, a browser-like User-Agent, pacing controls when available, or validate coverage manually.",
				Confidence:     "medium",
			})
		}
	}
	return findings
}

func evidenceOrDefault(discovery model.Discovery) model.Evidence {
	if discovery.Evidence != nil {
		return *discovery.Evidence
	}
	ev := model.Evidence{Source: discovery.Source}
	if discovery.MaskedValue != "" {
		ev.MaskedValue = discovery.MaskedValue
	}
	return ev
}

type sourceInfo struct {
	id       string
	title    string
	category string
	label    string
}

func sourceCategory(discovery model.Discovery) sourceInfo {
	location := ""
	if discovery.Evidence != nil {
		location = strings.ToLower(discovery.Evidence.File + " " + discovery.Evidence.URL)
	}
	switch {
	case discovery.Source == "source_map" || strings.Contains(location, ".map"):
		return sourceInfo{"SUPA-SOURCEMAP-INFO-001", "Supabase artifact detected in source map", "source_map_exposure", "source map"}
	case strings.Contains(location, ".env") || strings.Contains(location, "env.js") || strings.Contains(location, "config.js") || strings.Contains(location, "runtime-config.json"):
		return sourceInfo{"SUPA-ENV-INFO-001", "Supabase artifact detected in public configuration", "env_exposure", "public configuration"}
	default:
		return sourceInfo{"SUPA-PROJECT-INFO-001", "Supabase project URL detected", "project_detection", "static artifact"}
	}
}

func fingerprintServices(discoveries []model.Discovery) model.ServiceMap {
	services := model.ServiceMap{
		REST: model.ServiceNotObserved, Auth: model.ServiceNotObserved, Storage: model.ServiceNotObserved,
		Realtime: model.ServiceNotObserved, Functions: model.ServiceNotObserved, GraphQL: model.ServiceNotObserved,
	}
	for _, discovery := range discoveries {
		haystack := discovery.Value
		if discovery.Evidence != nil {
			haystack += " " + discovery.Evidence.URL + " " + discovery.Evidence.Detail
		}
		if strings.Contains(haystack, "/rest/v1/") {
			services.REST = model.ServiceObserved
		}
		if strings.Contains(haystack, "/auth/v1/") {
			services.Auth = model.ServiceObserved
		}
		if strings.Contains(haystack, "/storage/v1/") {
			services.Storage = model.ServiceObserved
		}
		if strings.Contains(haystack, "/realtime/v1/") {
			services.Realtime = model.ServiceObserved
		}
		if strings.Contains(haystack, "/functions/v1/") {
			services.Functions = model.ServiceObserved
		}
		if strings.Contains(haystack, "/graphql/v1/") {
			services.GraphQL = model.ServiceObserved
		}
	}
	return services
}

func hasSupabaseEvidence(discoveries []model.Discovery) bool {
	for _, discovery := range discoveries {
		if discovery.Type == "supabase_url" || discovery.Type == "key" || discovery.Type == "endpoint" {
			return true
		}
	}
	return false
}

func reportDiscoveries(discoveries []model.Discovery, showSecrets bool) []model.Discovery {
	if showSecrets {
		return revealDiscoveries(discoveries)
	}
	return sanitizeDiscoveries(discoveries)
}

func revealDiscoveries(discoveries []model.Discovery) []model.Discovery {
	revealed := make([]model.Discovery, 0, len(discoveries))
	for _, discovery := range discoveries {
		if discovery.Type == "key" || discovery.Type == "endpoint" {
			discovery.MaskedValue = discovery.Value
			if discovery.Evidence != nil {
				discovery.Evidence.MaskedValue = discovery.Value
			}
		}
		revealed = append(revealed, discovery)
	}
	return revealed
}

func sanitizeDiscoveries(discoveries []model.Discovery) []model.Discovery {
	sanitized := make([]model.Discovery, 0, len(discoveries))
	for _, discovery := range discoveries {
		if discovery.Type == "key" {
			masked := discovery.MaskedValue
			if masked == "" {
				masked = mask.Secret(discovery.Value)
			}
			discovery.Value = masked
			discovery.MaskedValue = masked
			if discovery.Evidence != nil {
				discovery.Evidence.MaskedValue = masked
			}
		}
		sanitized = append(sanitized, discovery)
	}
	return sanitized
}

func dedupeDiscoveries(discoveries []model.Discovery) []model.Discovery {
	seen := map[string]bool{}
	out := make([]model.Discovery, 0, len(discoveries))
	for _, discovery := range discoveries {
		line, file, url := 0, "", ""
		if discovery.Evidence != nil {
			line, file, url = discovery.Evidence.Line, discovery.Evidence.File, discovery.Evidence.URL
		}
		key := strings.Join([]string{discovery.Type, discovery.Value, discovery.Source, file, url, string(rune(line))}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, discovery)
	}
	return out
}

func dedupeFindings(findings []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		key := strings.Join([]string{finding.ID, finding.Evidence.File, finding.Evidence.URL, finding.Evidence.MaskedValue, finding.Evidence.Detail}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding)
	}
	return out
}

func mode(opts model.Options) []string {
	mode := []string{string(opts.Target.Type)}
	if opts.Dynamic {
		mode = append(mode, "dynamic")
	}
	if opts.Interactive {
		mode = append(mode, "interactive")
	}
	if opts.ActiveChecks {
		mode = append(mode, "active_checks")
	}
	if opts.ActiveStorageTests {
		mode = append(mode, "active_storage_tests")
	}
	if opts.GraphQLIntrospection {
		mode = append(mode, "graphql_introspection")
	}
	return mode
}
