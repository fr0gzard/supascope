package detect

import (
	"strings"
	"testing"

	"supascope/internal/model"
)

func TestArtifactSnippetIsTruncated(t *testing.T) {
	longLine := strings.Repeat("word ", 120) + "https://abcxyz.supabase.co " + strings.Repeat("tail ", 120)

	discoveries := Artifacts(longLine, model.Evidence{Source: "test"})
	if len(discoveries) == 0 || discoveries[0].Evidence == nil {
		t.Fatal("expected discovery with evidence")
	}

	snippet := discoveries[0].Evidence.Snippet
	if got := len(strings.Fields(snippet)); got > 101 {
		t.Fatalf("snippet word count = %d, want <= 101 including ellipsis suffix", got)
	}
	if !strings.HasSuffix(snippet, "...") {
		t.Fatalf("snippet = %q, want truncated suffix", snippet)
	}
}

func TestArtifactSnippetTruncatesMinifiedLine(t *testing.T) {
	longToken := strings.Repeat("a", 1200)
	content := longToken + "https://abcxyz.supabase.co"

	discoveries := Artifacts(content, model.Evidence{Source: "test"})
	if len(discoveries) == 0 || discoveries[0].Evidence == nil {
		t.Fatal("expected discovery with evidence")
	}

	if got := len([]rune(discoveries[0].Evidence.Snippet)); got > 803 {
		t.Fatalf("snippet rune count = %d, want <= 803 including ellipsis", got)
	}
}
