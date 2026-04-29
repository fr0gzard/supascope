package report

import (
	"fmt"
	"strings"

	"supascope/internal/model"
)

var severities = []string{"critical", "high", "medium", "low", "info"}

func Markdown(report model.Report) string {
	var b strings.Builder
	counts := map[string]int{}
	for _, finding := range report.Findings {
		counts[finding.Severity]++
	}

	projects := map[string]bool{}
	for _, discovery := range report.Discoveries {
		if discovery.Type == "supabase_url" {
			projects[discovery.Value] = true
		}
	}

	fmt.Fprintln(&b, "# SupaScope Report")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Target: %s\n", report.Target.Value)
	fmt.Fprintf(&b, "Target type: %s\n", report.Target.Type)
	fmt.Fprintf(&b, "Scan mode: %s\n", strings.Join(report.Mode, " + "))
	fmt.Fprintf(&b, "Timestamp: %s\n\n", report.Timestamp)

	fmt.Fprintln(&b, "## Summary")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Detected Supabase projects: %d\n", len(projects))
	fmt.Fprintf(&b, "Discoveries: %d\n", len(report.Discoveries))
	fmt.Fprintf(&b, "Findings: %d\n\n", len(report.Findings))
	for _, severity := range severities {
		fmt.Fprintf(&b, "- %s: %d\n", strings.ToUpper(severity), counts[severity])
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Detected Services")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- rest: %s\n", report.Services.REST)
	fmt.Fprintf(&b, "- auth: %s\n", report.Services.Auth)
	fmt.Fprintf(&b, "- storage: %s\n", report.Services.Storage)
	fmt.Fprintf(&b, "- realtime: %s\n", report.Services.Realtime)
	fmt.Fprintf(&b, "- functions: %s\n", report.Services.Functions)
	fmt.Fprintf(&b, "- graphql: %s\n", report.Services.GraphQL)

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Findings")
	fmt.Fprintln(&b)
	if len(report.Findings) == 0 {
		fmt.Fprintln(&b, "No findings were generated.")
		return b.String()
	}

	for _, severity := range severities {
		var filtered []model.Finding
		for _, finding := range report.Findings {
			if finding.Severity == severity {
				filtered = append(filtered, finding)
			}
		}
		if len(filtered) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s\n\n", strings.ToUpper(severity))
		for _, finding := range filtered {
			fmt.Fprintf(&b, "#### %s\n\n", finding.Title)
			fmt.Fprintf(&b, "ID: %s\n", finding.ID)
			fmt.Fprintf(&b, "Category: %s\n", finding.Category)
			fmt.Fprintf(&b, "Confidence: %s\n\n", finding.Confidence)
			fmt.Fprintf(&b, "Impact: %s\n\n", finding.Impact)
			fmt.Fprintf(&b, "Recommendation: %s\n\n", finding.Recommendation)
			writeEvidence(&b, finding.Evidence)
		}
	}

	return b.String()
}

func writeEvidence(b *strings.Builder, evidence model.Evidence) {
	if evidence.File == "" && evidence.URL == "" && evidence.Line == 0 && evidence.MaskedValue == "" && evidence.Detail == "" && evidence.Snippet == "" {
		return
	}
	fmt.Fprintln(b, "Evidence:")
	fmt.Fprintln(b)
	if evidence.File != "" {
		fmt.Fprintf(b, "- File: %s\n", evidence.File)
	}
	if evidence.URL != "" {
		fmt.Fprintf(b, "- URL: %s\n", evidence.URL)
	}
	if evidence.Line != 0 {
		fmt.Fprintf(b, "- Line: %d\n", evidence.Line)
	}
	if evidence.MaskedValue != "" {
		fmt.Fprintf(b, "- Value: %s\n", evidence.MaskedValue)
	}
	if evidence.Detail != "" {
		fmt.Fprintf(b, "- Detail: %s\n", evidence.Detail)
	}
	if evidence.Snippet != "" {
		fmt.Fprintf(b, "- Snippet: %s\n", evidence.Snippet)
	}
	fmt.Fprintln(b)
}
