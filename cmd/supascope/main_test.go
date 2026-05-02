package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"supascope/internal/model"
)

func TestNormalizeScanArgsMovesFlagsBeforeTarget(t *testing.T) {
	got := normalizeScanArgs([]string{
		"https://example.com",
		"--profile",
		"deep",
		"--yes",
		"--json",
		"--header",
		"Accept: text/html",
		"--max-assets",
		"70",
		"--output",
		"report.md",
		"--graphql-schema-output",
		"schema.txt",
	})
	want := []string{
		"--profile",
		"deep",
		"--yes",
		"--json",
		"--header",
		"Accept: text/html",
		"--max-assets",
		"70",
		"--output",
		"report.md",
		"--graphql-schema-output",
		"schema.txt",
		"https://example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeScanArgs() = %#v, want %#v", got, want)
	}
}

func TestScanOptionsRequiresGraphQLIntrospectionForSchemaOutput(t *testing.T) {
	opts, err := scanOptions(scanConfig{Args: []string{"https://example.com"}, Yes: true, GraphQLSchemaOutput: "schema.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.GraphQLIntrospection {
		t.Fatal("expected schema output to imply GraphQL introspection")
	}
}

func TestScanOptionsAppliesProfiles(t *testing.T) {
	active, err := scanOptions(scanConfig{Args: []string{"https://example.com"}, Profile: "active", Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !active.ActiveChecks || active.GraphQLIntrospection {
		t.Fatalf("active profile options = %#v", active)
	}

	deep, err := scanOptions(scanConfig{Args: []string{"https://example.com"}, Profile: "deep", Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !deep.ActiveChecks || !deep.GraphQLIntrospection {
		t.Fatalf("deep profile options = %#v", deep)
	}
}

func TestScanOptionsRejectsInvalidProfile(t *testing.T) {
	_, err := scanOptions(scanConfig{Args: []string{"https://example.com"}, Profile: "nope", Yes: true})
	if err == nil {
		t.Fatal("expected invalid profile error")
	}
}

func TestParseHeaders(t *testing.T) {
	got, err := parseHeaders([]string{"accept-language: en-US,en;q=0.9,id;q=0.8"})
	if err != nil {
		t.Fatal(err)
	}
	if got["Accept-Language"] != "en-US,en;q=0.9,id;q=0.8" {
		t.Fatalf("Accept-Language = %q", got["Accept-Language"])
	}
}

func TestNormalizeScanArgsKeepsEqualsValueFlags(t *testing.T) {
	got := normalizeScanArgs([]string{
		"https://example.com",
		"--output=report.md",
	})
	want := []string{
		"--output=report.md",
		"https://example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeScanArgs() = %#v, want %#v", got, want)
	}
}

func TestNormalizeScanArgsHandlesOutputAliases(t *testing.T) {
	got := normalizeScanArgs([]string{
		"https://example.com",
		"-o",
		"report.md",
		"--output-json",
		"report.json",
		"-oj",
		"extra.json",
	})
	want := []string{
		"-o",
		"report.md",
		"--output-json",
		"report.json",
		"-oj",
		"extra.json",
		"https://example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeScanArgs() = %#v, want %#v", got, want)
	}
}

func TestRenderReportRespectsJSONFlag(t *testing.T) {
	rendered, err := renderReport(model.Report{
		Scanner: model.ScannerInfo{Name: "SupaScope", Version: "test"},
		Target:  model.Target{Type: model.TargetLocalPath, Value: "."},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rendered, "{\n") {
		t.Fatalf("rendered report should be JSON, got %q", rendered)
	}
	if strings.Contains(rendered, "# SupaScope Report") {
		t.Fatal("rendered JSON report contains Markdown output")
	}
}

func TestWriteOutputReportsWritesMarkdownAndJSON(t *testing.T) {
	dir := t.TempDir()
	markdownPath := filepath.Join(dir, "report.md")
	jsonPath := filepath.Join(dir, "report.json")

	written, err := writeOutputReports(model.Report{
		Scanner: model.ScannerInfo{Name: "SupaScope", Version: "test"},
		Target:  model.Target{Type: model.TargetLocalPath, Value: "."},
	}, markdownPath, jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{markdownPath, jsonPath}
	if !reflect.DeepEqual(written, want) {
		t.Fatalf("written = %#v, want %#v", written, want)
	}

	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "# SupaScope Report") {
		t.Fatalf("markdown report = %q", string(markdown))
	}

	jsonReport, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(jsonReport), "{\n") || strings.Contains(string(jsonReport), "# SupaScope Report") {
		t.Fatalf("json report = %q", string(jsonReport))
	}
}
