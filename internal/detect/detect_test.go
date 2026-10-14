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

func TestExtractSupabaseTables(t *testing.T) {
	content := `
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(url, key);
const { data } = await supabase.from('profiles').select('*');
await supabase.from("orders").insert(row);
`
	discoveries := Artifacts(content, model.Evidence{Source: "static"})
	var tables []string
	for _, d := range discoveries {
		if d.Type == "supabase_table" {
			tables = append(tables, d.Value)
		}
	}
	if len(tables) != 2 || tables[0] != "profiles" || tables[1] != "orders" {
		t.Fatalf("tables = %v, want [profiles orders]", tables)
	}
}

func TestExtractSupabaseTablesRequiresSupabaseMention(t *testing.T) {
	// lodash-style .from( without any supabase reference must not match.
	content := `const x = _.from('pairs');`
	for _, d := range Artifacts(content, model.Evidence{Source: "static"}) {
		if d.Type == "supabase_table" {
			t.Fatalf("unexpected table discovery: %#v", d)
		}
	}
}

func TestExtractSupabaseTablesDedupes(t *testing.T) {
	content := `supabase.from('a').select(); supabase.from('a').select(); supabase.from('b').select();`
	count := 0
	for _, d := range Artifacts(content, model.Evidence{Source: "static"}) {
		if d.Type == "supabase_table" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 unique tables, got %d", count)
	}
}
