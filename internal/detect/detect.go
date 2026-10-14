package detect

import (
	"regexp"
	"strings"
	"unicode"

	"supascope/internal/mask"
	"supascope/internal/model"
)

var (
	supabaseURLPattern     = regexp.MustCompile(`(?:https|wss)://[a-z0-9-]+\.supabase\.co\b`)
	publishablePattern     = regexp.MustCompile(`sb_publishable_[A-Za-z0-9._-]+`)
	secretPattern          = regexp.MustCompile(`sb_secret_[A-Za-z0-9._-]+`)
	jwtPattern             = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	databaseURLPattern     = regexp.MustCompile(`(?i)postgres(?:ql)?://[^\s"'` + "`" + `<>]+`)
	serviceEndpointPattern = regexp.MustCompile(`(?:https|wss)://[a-z0-9-]+\.supabase\.co/(?:rest|auth|storage|realtime|functions|graphql)/v1/[^\s"'` + "`" + `<>)]*`)
	// supabase-js table access: .from('table_name'). The supabase gate below
	// keeps other libraries' .from( calls out.
	supabaseTablePattern = regexp.MustCompile(`\.from\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\)`)
	supabaseHintPattern  = regexp.MustCompile(`(?i)supabase`)
)

// maxExtractedTables caps table names per content: each one becomes probe
// traffic in active scans.
const maxExtractedTables = 64

func Artifacts(content string, evidence model.Evidence) []model.Discovery {
	var discoveries []model.Discovery

	for _, match := range uniqueMatches(content, supabaseURLPattern) {
		ev := withLine(evidence, content, match.start)
		if ev.URL == "" {
			ev.URL = match.value
		}
		discoveries = append(discoveries, model.Discovery{
			Type:     "supabase_url",
			Value:    match.value,
			Source:   evidence.Source,
			Evidence: &ev,
		})
	}

	for _, pattern := range []*regexp.Regexp{publishablePattern, secretPattern, jwtPattern, databaseURLPattern} {
		for _, match := range uniqueMatches(content, pattern) {
			masked := mask.Secret(match.value)
			ev := withLine(evidence, content, match.start)
			ev.MaskedValue = masked
			discoveries = append(discoveries, model.Discovery{
				Type:        "key",
				Value:       match.value,
				MaskedValue: masked,
				Source:      evidence.Source,
				Evidence:    &ev,
			})
		}
	}

	for _, match := range uniqueMatches(content, serviceEndpointPattern) {
		masked := mask.Secret(match.value)
		ev := withLine(evidence, content, match.start)
		ev.MaskedValue = masked
		discoveries = append(discoveries, model.Discovery{
			Type:        "endpoint",
			Value:       match.value,
			MaskedValue: masked,
			Source:      evidence.Source,
			Evidence:    &ev,
		})
	}

	// Table names from supabase-js calls, used as a fallback when the REST
	// OpenAPI is unavailable. Gated on a supabase mention so other
	// libraries' .from( calls don't become probe targets.
	if supabaseHintPattern.MatchString(content) {
		seen := map[string]bool{}
		count := 0
		for _, loc := range supabaseTablePattern.FindAllStringSubmatchIndex(content, -1) {
			if count >= maxExtractedTables {
				break
			}
			table := content[loc[2]:loc[3]]
			if seen[table] {
				continue
			}
			seen[table] = true
			count++
			ev := withLine(evidence, content, loc[0])
			discoveries = append(discoveries, model.Discovery{
				Type:     "supabase_table",
				Value:    table,
				Source:   evidence.Source,
				Evidence: &ev,
			})
		}
	}

	return discoveries
}

type regexMatch struct {
	value string
	start int
}

func uniqueMatches(content string, pattern *regexp.Regexp) []regexMatch {
	seen := map[string]bool{}
	var matches []regexMatch
	for _, loc := range pattern.FindAllStringIndex(content, -1) {
		value := content[loc[0]:loc[1]]
		if seen[value] {
			continue
		}
		seen[value] = true
		matches = append(matches, regexMatch{value: value, start: loc[0]})
	}
	return matches
}

func withLine(evidence model.Evidence, content string, index int) model.Evidence {
	line := strings.Count(content[:index], "\n") + 1
	evidence.Line = line
	evidence.Snippet = maskSnippet(lineText(content, line))
	return evidence
}

func lineText(content string, line int) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if line <= 0 || line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[line-1])
}

func maskSnippet(snippet string) string {
	for _, pattern := range []*regexp.Regexp{publishablePattern, secretPattern, jwtPattern, databaseURLPattern} {
		snippet = pattern.ReplaceAllStringFunc(snippet, mask.Secret)
	}
	return truncateSnippet(snippet, 100, 800)
}

func truncateSnippet(snippet string, maxWords int, maxRunes int) string {
	fields := strings.Fields(snippet)
	truncated := false
	if len(fields) > maxWords {
		snippet = strings.Join(fields[:maxWords], " ")
		truncated = true
	}

	runes := []rune(snippet)
	if len(runes) > maxRunes {
		cut := maxRunes
		for cut > 0 && !unicode.IsSpace(runes[cut-1]) {
			cut--
		}
		if cut < maxRunes/2 {
			cut = maxRunes
		}
		snippet = strings.TrimSpace(string(runes[:cut]))
		truncated = true
	}

	if truncated {
		return snippet + "..."
	}
	return snippet
}
