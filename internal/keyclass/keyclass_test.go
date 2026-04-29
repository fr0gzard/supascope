package keyclass

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestClassifyJWTIncludesSafeMetadata(t *testing.T) {
	jwt := testJWT(map[string]any{
		"role": "anon",
		"iss":  "https://abcxyz.supabase.co/auth/v1",
		"exp":  float64(1893456000),
	})

	classified := Classify(jwt)
	if classified.Type != "legacy_anon_jwt" {
		t.Fatalf("Type = %q, want legacy_anon_jwt", classified.Type)
	}
	for _, want := range []string{
		"role: anon",
		"issuer: https://abcxyz.supabase.co/auth/v1",
		"expiry: 2030-01-01T00:00:00Z",
		"project_ref: abcxyz",
	} {
		if !strings.Contains(classified.Detail, want) {
			t.Fatalf("Detail = %q, want to contain %q", classified.Detail, want)
		}
	}
	if strings.Contains(classified.Detail, jwt) {
		t.Fatal("Detail contains raw JWT")
	}
}

func testJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
