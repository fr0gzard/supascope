package report

import (
	"bytes"
	"fmt"
	"html"
	"os"
	"strings"

	"supascope/internal/model"
)

var severityColors = map[string]string{
	"critical": "#dc2626",
	"high":     "#ea580c",
	"medium":   "#ca8a04",
	"low":      "#2563eb",
	"info":     "#6b7280",
}

func WriteHTML(report model.Report, path string) error {
	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SupaScope Report</title>`)
	buf.WriteString(`<style>`)
	buf.WriteString(css)
	buf.WriteString(`</style></head><body>`)

	buf.WriteString("<header>")
	buf.WriteString(fmt.Sprintf("<h1>SupaScope Scan Report</h1>"))
	buf.WriteString(fmt.Sprintf("<p class=\"meta\">Target: <strong>%s</strong> (%s) | Mode: %s | %s</p>",
		html.EscapeString(report.Target.Value),
		html.EscapeString(string(report.Target.Type)),
		strings.Join(report.Mode, ", "),
		report.Timestamp,
	))
	buf.WriteString("</header>")
	severityCounts := countSeverities(report.Findings)
	buf.WriteString("<section><h2>Summary</h2>")
	buf.WriteString(fmt.Sprintf("<p>%d findings discovered across %d categories.</p>", len(report.Findings), len(uniqueCategories(report.Findings))))
	buf.WriteString("<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := severityCounts[severity]; ok {
			buf.WriteString(fmt.Sprintf("<tr><td><span class=\"severity %s\">%s</span></td><td>%d</td></tr>", severity, strings.ToUpper(severity), count))
		}
	}
	buf.WriteString("</tbody></table></section>")
	buf.WriteString("<section><h2>Services</h2>")
	buf.WriteString(renderServices(report.Services))
	buf.WriteString("</section>")
	buf.WriteString("<section><h2>Findings</h2>")
	if len(report.Findings) == 0 {
		buf.WriteString("<p>No findings.</p>")
	} else {
		for _, finding := range report.Findings {
			buf.WriteString(renderFinding(finding))
		}
	}
	buf.WriteString("</section></body></html>")
	return os.WriteFile(path, buf.Bytes(), 0644)
}

func renderServices(services model.ServiceMap) string {
	styles := map[model.ServiceStatus]string{
		model.ServiceReachable:    "reachable",
		model.ServiceUnauthorized: "unauthorized",
		model.ServiceForbidden:    "forbidden",
		model.ServiceNotFound:     "not_found",
		model.ServiceObserved:     "observed",
		model.ServiceBlocked:      "blocked",
		model.ServiceUnknown:      "unknown",
	}
	rows := []struct {
		name   string
		status model.ServiceStatus
	}{
		{"REST", services.REST},
		{"Auth", services.Auth},
		{"Storage", services.Storage},
		{"Realtime", services.Realtime},
		{"Functions", services.Functions},
		{"GraphQL", services.GraphQL},
	}
	var buf bytes.Buffer
	buf.WriteString("<table><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>")
	for _, row := range rows {
		cls := styles[row.status]
		if cls == "" {
			cls = "not_observed"
		}
		buf.WriteString(fmt.Sprintf("<tr><td>%s</td><td class=\"status %s\">%s</td></tr>",
			row.name, cls, html.EscapeString(string(row.status))))
	}
	buf.WriteString("</tbody></table>")
	return buf.String()
}

func renderFinding(finding model.Finding) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("<div class=\"finding %s\">", finding.Severity))
	buf.WriteString(fmt.Sprintf("<h3><span class=\"severity %s\">%s</span> %s</h3>",
		finding.Severity, strings.ToUpper(finding.Severity), html.EscapeString(finding.Title)))
	buf.WriteString(fmt.Sprintf("<p class=\"category\">%s &middot; %s &middot; Confidence: %s</p>",
		html.EscapeString(finding.Category),
		html.EscapeString(finding.ID),
		html.EscapeString(finding.Confidence),
	))
	if finding.Impact != "" {
		buf.WriteString(fmt.Sprintf("<p><strong>Impact:</strong> %s</p>", html.EscapeString(finding.Impact)))
	}
	if finding.Recommendation != "" {
		buf.WriteString(fmt.Sprintf("<p><strong>Recommendation:</strong> %s</p>", html.EscapeString(finding.Recommendation)))
	}
	if finding.Evidence.Detail != "" || finding.Evidence.URL != "" || finding.Evidence.File != "" || finding.Evidence.MaskedValue != "" || finding.Evidence.Snippet != "" {
		buf.WriteString("<details class=\"evidence\"><summary>Evidence</summary><dl>")
		if finding.Evidence.URL != "" {
			buf.WriteString(fmt.Sprintf("<dt>URL</dt><dd><code>%s</code></dd>", html.EscapeString(finding.Evidence.URL)))
		}
		if finding.Evidence.File != "" {
			buf.WriteString(fmt.Sprintf("<dt>File</dt><dd><code>%s</code></dd>", html.EscapeString(finding.Evidence.File)))
		}
		if finding.Evidence.Detail != "" {
			buf.WriteString(fmt.Sprintf("<dt>Detail</dt><dd>%s</dd>", html.EscapeString(finding.Evidence.Detail)))
		}
		if finding.Evidence.MaskedValue != "" {
			buf.WriteString(fmt.Sprintf("<dt>Value</dt><dd><code>%s</code></dd>", html.EscapeString(finding.Evidence.MaskedValue)))
		}
		if finding.Evidence.Snippet != "" {
			buf.WriteString(fmt.Sprintf("<dt>Snippet</dt><dd><pre>%s</pre></dd>", html.EscapeString(finding.Evidence.Snippet)))
		}
		buf.WriteString("</dl></details>")
	}
	buf.WriteString("</div>")
	return buf.String()
}

func countSeverities(findings []model.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func uniqueCategories(findings []model.Finding) []string {
	seen := make(map[string]bool)
	var cats []string
	for _, f := range findings {
		if !seen[f.Category] {
			seen[f.Category] = true
			cats = append(cats, f.Category)
		}
	}
	return cats
}

const css = `
:root {
	--bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
}
body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height:1.6; }
header { background: var(--surface); padding: 1.5rem 2rem; border-radius: 8px; margin-bottom: 2rem; border: 1px solid var(--border); }
h1 { margin: 0 0 .5rem; font-size: 1.5rem; }
h2 { margin: 2rem 0 1rem; font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: .25rem; }
section { margin-bottom: 2rem; }
.meta { color: var(--muted); font-size: .875rem; margin: 0; }
table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
th, td { padding: .75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
th { background: rgba(255,255,255,.05); font-weight: 600; }
td { font-size: .875rem; }
.status.reachable,.status.observed { color: #22c55e; }
.status.unauthorized,.status.forbidden { color: #eab308; }
.status.not_observed,.status.unknown { color: var(--muted); }
.status.blocked { color: #ef4444; }
.status.not_found { color: var(--muted); }
.severity { display: inline-block; padding: .125rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
.severity.critical { background: #dc262620; color: #dc2626; border: 1px solid #dc2626; }
.severity.high { background: #ea580c20; color: #ea580c; border: 1px solid #ea580c; }
.severity.medium { background: #ca8a0420; color: #ca8a04; border: 1px solid #ca8a04; }
.severity.low { background: #2563eb20; color: #2563eb; border: 1px solid #2563eb; }
.severity.info { background: #6b728020; color: #6b7280; border: 1px solid #6b7280; }
.finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; border-left: 4px solid transparent; }
.finding.critical { border-left-color: #dc2626; }
.finding.high { border-left-color: #ea580c; }
.finding.medium { border-left-color: #ca8a04; }
.finding.low { border-left-color: #2563eb; }
.finding.info { border-left-color: #6b7280; }
.finding h3 { margin: 0 0 .5rem; font-size: 1rem; }
.category { font-size: .75rem; color: var(--muted); margin: .25rem 0; }
.evidence { margin-top: .75rem; }
.evidence summary { cursor: pointer; font-size: .8rem; color: var(--muted); }
.evidence dl { font-size: .8rem; display: grid; grid-template-columns: auto 1fr; gap: .25rem .75rem; margin-top: .5rem; }
.evidence dt { color: var(--muted); }
.evidence dd { margin: 0; word-break: break-all; }
.evidence pre { margin: 0; font-size: .75rem; white-space: pre-wrap; background: rgba(0,0,0,.2); padding: .5rem; border-radius: 4px; }
code { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: .8rem; background: rgba(0,0,0,.2); padding: .1rem .3rem; border-radius: 3px; }
`
