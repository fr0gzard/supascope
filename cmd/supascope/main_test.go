package main

import (
	"reflect"
	"strings"
	"testing"

	"supascope/internal/model"
)

func TestNormalizeScanArgsMovesFlagsBeforeTarget(t *testing.T) {
	got := normalizeScanArgs([]string{
		"https://example.com",
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
	_, err := scanOptions([]string{"https://example.com"}, "", "", "", "", nil, false, "", false, 0, true, false, false, false, false, false, "schema.txt")
	if err == nil {
		t.Fatal("expected schema output without introspection to fail")
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
