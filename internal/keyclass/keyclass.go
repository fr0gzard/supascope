package keyclass

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

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
		role := jwtRole(value)
		if role == "service_role" {
			return base(value, "legacy_service_role_jwt", "critical", "SUPA-KEY-CRIT-002", "Legacy service role JWT exposed", "Service role keys bypass Row Level Security.", "Rotate the key immediately and remove it from frontend code.")
		}
		if role == "anon" {
			return base(value, "legacy_anon_jwt", "low", "SUPA-KEY-LOW-002", "Legacy anon JWT detected", "Anon keys are expected in frontend apps when policies are correctly scoped.", "Review RLS policies and anon permissions.")
		}
		return base(value, "unknown_jwt", "medium", "SUPA-KEY-MED-001", "Unknown JWT-like token detected", "The token role could not be confidently classified.", "Review the token source and ensure sensitive tokens are not exposed.")
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
		FindingID: findingID, Title: title, Impact: impact, Recommendation: recommendation,
	}
}

func jwtRole(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if role, ok := claims["role"].(string); ok {
		return role
	}
	for _, key := range []string{"app_metadata", "user_metadata"} {
		if metadata, ok := claims[key].(map[string]any); ok {
			if role, ok := metadata["role"].(string); ok {
				return role
			}
		}
	}
	return ""
}
