package keyclass

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"supascope/internal/mask"
)

type Classification struct {
	Type           string
	Severity       string
	Confidence     string
	MaskedValue    string
	FindingID      string
	Title          string
	Impact         string
	Recommendation string
	Detail         string
}

func Classify(value string) Classification {
	switch {
	case strings.HasPrefix(value, "sb_publishable_"):
		return base(value, "publishable_key", "low", "SUPA-KEY-LOW-001", "Publishable key detected", "Publishable keys are expected in frontend Supabase apps.", "Ensure RLS and least-privilege policies protect exposed resources.")
	case strings.HasPrefix(value, "sb_secret_"):
		return base(value, "secret_key", "critical", "SUPA-KEY-CRIT-001", "Secret key exposed", "Secret keys can grant privileged access and must not be present in public code.", "Rotate the key immediately and move privileged operations server-side.")
	case regexp.MustCompile(`(?i)^postgres(?:ql)?://`).MatchString(value):
		return base(value, "database_url", "critical", "SUPA-DB-CRIT-001", "Database URL exposed", "Database URLs can expose direct database credentials.", "Rotate database credentials and remove the URL from public artifacts.")
	case strings.HasPrefix(value, "eyJ"):
		metadata := jwtMetadata(value)
		if metadata.role == "service_role" {
			classified := base(value, "legacy_service_role_jwt", "critical", "SUPA-KEY-CRIT-002", "Legacy service role JWT exposed", "Service role keys bypass Row Level Security.", "Rotate the key immediately and remove it from frontend code.")
			classified.Detail = classified.Type + metadata.detail()
			return classified
		}
		if metadata.role == "anon" {
			classified := base(value, "legacy_anon_jwt", "low", "SUPA-KEY-LOW-002", "Legacy anon JWT detected", "Anon keys are expected in frontend apps when policies are correctly scoped.", "Review RLS policies and anon permissions.")
			classified.Detail = classified.Type + metadata.detail()
			return classified
		}
		classified := base(value, "unknown_jwt", "medium", "SUPA-KEY-MED-001", "Unknown JWT-like token detected", "The token role could not be confidently classified.", "Review the token source and ensure sensitive tokens are not exposed.")
		classified.Detail = classified.Type + metadata.detail()
		return classified
	default:
		return base(value, "unknown", "info", "SUPA-KEY-INFO-001", "Key-like value detected", "The value could not be classified.", "Review whether this value should be public.")
	}
}

func base(value, typ, severity, findingID, title, impact, recommendation string) Classification {
	confidence := "high"
	if typ == "unknown" {
		confidence = "low"
	}
	return Classification{
		Type: typ, Severity: severity, Confidence: confidence, MaskedValue: mask.Secret(value),
		FindingID: findingID, Title: title, Impact: impact, Recommendation: recommendation, Detail: typ,
	}
}

type metadata struct {
	role       string
	issuer     string
	expiresAt  string
	projectRef string
}

func jwtMetadata(jwt string) metadata {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return metadata{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return metadata{}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return metadata{}
	}

	issuer, _ := claims["iss"].(string)
	meta := metadata{issuer: issuer, projectRef: projectRefFromIssuer(issuer)}
	if role, ok := claims["role"].(string); ok {
		meta.role = role
	}
	for _, key := range []string{"app_metadata", "user_metadata"} {
		if metadata, ok := claims[key].(map[string]any); ok {
			if meta.role == "" {
				if role, ok := metadata["role"].(string); ok {
					meta.role = role
				}
			}
			if meta.projectRef == "" {
				if projectRef, ok := metadata["project_ref"].(string); ok {
					meta.projectRef = projectRef
				}
			}
		}
	}
	if projectRef, ok := claims["project_ref"].(string); ok && meta.projectRef == "" {
		meta.projectRef = projectRef
	}
	meta.expiresAt = expiry(claims["exp"])
	return meta
}

func (m metadata) detail() string {
	var parts []string
	if m.role != "" {
		parts = append(parts, "role: "+m.role)
	}
	if m.issuer != "" {
		parts = append(parts, "issuer: "+m.issuer)
	}
	if m.expiresAt != "" {
		parts = append(parts, "expiry: "+m.expiresAt)
	}
	if m.projectRef != "" {
		parts = append(parts, "project_ref: "+m.projectRef)
	}
	if len(parts) == 0 {
		return ""
	}
	return "; " + strings.Join(parts, "; ")
}

func expiry(value any) string {
	var seconds int64
	switch exp := value.(type) {
	case float64:
		seconds = int64(exp)
	case json.Number:
		parsed, err := exp.Int64()
		if err != nil {
			return ""
		}
		seconds = parsed
	case string:
		parsed, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			return ""
		}
		seconds = parsed
	default:
		return ""
	}
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func projectRefFromIssuer(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return ""
	}
	host := parsed.Hostname()
	if !strings.HasSuffix(host, ".supabase.co") {
		return ""
	}
	return strings.TrimSuffix(host, ".supabase.co")
}
