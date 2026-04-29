package scanner

import (
	"context"
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
		found, err := engine.NewStatic(opts.UserAgent, opts.Headers, opts.Debug, opts.MaxAssets).ScanURL(ctx, opts.Target.Value)
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
		ev := model.Evidence{Source: "provided", MaskedValue: classified.MaskedValue, Detail: classified.Type}
		discoveries = append(discoveries, model.Discovery{Type: "key", Value: opts.Key, MaskedValue: classified.MaskedValue, Source: "provided", Evidence: &ev})
	}

	discoveries = dedupeDiscoveries(discoveries)
	services := fingerprintServices(discoveries)
	activeServices := emptyServiceMap()
	if opts.ActiveChecks {
		activeServices = activeServiceChecks(ctx, discoveries, opts)
		services = mergeServiceMaps(services, activeServices)
	}
	findings := discoveriesToFindings(discoveries)
	if opts.ActiveChecks {
		findings = append(findings, activeStatusFindings(activeServices)...)
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
		Discoveries: sanitizeDiscoveries(discoveries),
		Findings:    findings,
	}, nil
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

func activeServiceChecks(ctx context.Context, discoveries []model.Discovery, opts model.Options) model.ServiceMap {
	services := emptyServiceMap()
	key := activeKey(discoveries, opts.Key)
	for _, projectURL := range supabaseProjectURLs(discoveries, opts.Target) {
		probed, err := engine.ProbeProjectServices(ctx, projectURL, engine.ActiveOptions{
			UserAgent:          opts.UserAgent,
			Headers:            opts.Headers,
			Key:                key,
			Debug:              opts.Debug,
			ActiveStorageTests: opts.ActiveStorageTests,
		})
		if err != nil {
			continue
		}
		services = mergeServiceMaps(services, probed)
	}
	return services
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

func discoveriesToFindings(discoveries []model.Discovery) []model.Finding {
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
			findings = append(findings, model.Finding{
				ID: classified.FindingID, Title: title, Severity: classified.Severity, Category: category,
				Evidence: evidenceOrDefault(discovery),
				Impact:   classified.Impact, Recommendation: classified.Recommendation, Confidence: classified.Confidence,
			})
		case "endpoint":
			findings = append(findings, model.Finding{
				ID: "SUPA-ENDPOINT-INFO-001", Title: "Supabase service endpoint observed", Severity: "info", Category: "service_detection",
				Evidence:       evidenceOrDefault(discovery),
				Impact:         "A Supabase API surface was referenced by the scanned application artifact.",
				Recommendation: "Confirm the referenced service is intended to be reachable and protected by least-privilege policies.",
				Confidence:     "high",
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
	case strings.Contains(location, ".map"):
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
	return mode
}
