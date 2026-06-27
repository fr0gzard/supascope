package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
		"--har",
		"network.har",
		"--wait",
		"30s",
		"-w",
		"45s",
		"--attach",
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
		"--har",
		"network.har",
		"--wait",
		"30s",
		"-w",
		"45s",
		"--attach",
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

func TestMergeCLIConfigSupportsShortDynamicFlags(t *testing.T) {
	got := mergeCLIConfig(scanConfig{}, scanConfig{
		Args:          []string{"https://example.com"},
		JSON:          true,
		Yes:           true,
		Dynamic:       true,
		AttachBrowser: true,
		DynamicWait:   90 * time.Second,
	}, map[string]bool{"j": true, "y": true, "d": true, "b": true, "w": true})

	if !got.JSON || !got.Yes || !got.Dynamic || !got.AttachBrowser || got.DynamicWait != 90*time.Second {
		t.Fatalf("merged short flags = %#v", got)
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

func TestScanOptionsAcceptsHARTarget(t *testing.T) {
	opts, err := scanOptions(scanConfig{HAR: "network.har"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Target.Type != model.TargetHAR || opts.Target.Value != "network.har" {
		t.Fatalf("target = %#v, want HAR target", opts.Target)
	}
}

func TestScanOptionsSetsDynamicWait(t *testing.T) {
	opts, err := scanOptions(scanConfig{Args: []string{"https://example.com"}, AttachBrowser: true, DynamicWait: 45 * time.Second, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if opts.DynamicWait != 45*time.Second {
		t.Fatalf("DynamicWait = %s, want 45s", opts.DynamicWait)
	}
	if !opts.Dynamic {
		t.Fatal("expected attach browser to imply dynamic scan")
	}
	if opts.BrowserDebuggerURL != defaultBrowserDebuggerURL {
		t.Fatalf("BrowserDebuggerURL = %q", opts.BrowserDebuggerURL)
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

func TestScanConfigFromFile(t *testing.T) {
	trueValue := true
	maxAssets := 70
	maxConcurrency := 2

	config, err := scanConfigFromFile(scanFileConfig{
		Target:         "https://example.com",
		HAR:            "network.har",
		Profile:        "active",
		UserAgent:      "SupaScope-Test/1.0",
		Headers:        map[string]string{"accept-language": "en-US"},
		JSON:           &trueValue,
		Output:         "report.md",
		OutputJSON:     "report.json",
		MaxAssets:      &maxAssets,
		Yes:            &trueValue,
		DynamicWait:    "30s",
		AttachBrowser:  &trueValue,
		Delay:          "250ms",
		MaxConcurrency: &maxConcurrency,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Args, []string{"https://example.com"}) || config.HAR != "network.har" {
		t.Fatalf("targets = %#v har=%q", config.Args, config.HAR)
	}
	if config.Profile != "active" || config.UserAgent != "SupaScope-Test/1.0" {
		t.Fatalf("config = %#v", config)
	}
	if config.Headers["Accept-Language"] != "en-US" {
		t.Fatalf("headers = %#v", config.Headers)
	}
	if !config.JSON || config.Output != "report.md" || config.OutputJSON != "report.json" {
		t.Fatalf("output config = %#v", config)
	}
	if config.MaxAssets != 70 || !config.Yes || config.DynamicWait.String() != "30s" || !config.AttachBrowser || config.Delay.String() != "250ms" || config.MaxConcurrency != 2 {
		t.Fatalf("scan controls = %#v", config)
	}
}

func TestMergedConfigJSONControlsRenderMode(t *testing.T) {
	config := mergeCLIConfig(scanConfig{JSON: true}, scanConfig{}, map[string]bool{})
	rendered, err := renderReport(model.Report{
		Scanner: model.ScannerInfo{Name: "SupaScope", Version: "test"},
		Target:  model.Target{Type: model.TargetLocalPath, Value: "."},
	}, config.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rendered, "{\n") {
		t.Fatalf("rendered report should be JSON from merged config, got %q", rendered)
	}
}

func TestMergeCLIConfigTargetOverrideClearsConfiguredTarget(t *testing.T) {
	got := mergeCLIConfig(scanConfig{Args: []string{"https://configured.example"}}, scanConfig{Path: ".", MaxConcurrency: 4}, map[string]bool{"path": true})
	if len(got.Args) != 0 || got.Path != "." || got.HAR != "" || got.SupabaseURL != "" {
		t.Fatalf("merged target = %#v", got)
	}
}

func TestMergeCLIConfigOverridesFileConfig(t *testing.T) {
	base := scanConfig{
		Args:           []string{"https://configured.example"},
		Profile:        "active",
		Headers:        map[string]string{"Accept-Language": "en-US", "Accept": "application/json"},
		Output:         "configured.md",
		OutputJSON:     "configured.json",
		MaxAssets:      25,
		MaxConcurrency: 2,
	}
	cli := scanConfig{
		Args:           []string{"https://cli.example"},
		Profile:        "deep",
		Headers:        map[string]string{"Accept": "text/html"},
		OutputJSON:     "cli.json",
		MaxConcurrency: 8,
	}

	got := mergeCLIConfig(base, cli, map[string]bool{
		"profile":         true,
		"header":          true,
		"output-json":     true,
		"max-concurrency": true,
	})
	if !reflect.DeepEqual(got.Args, []string{"https://cli.example"}) {
		t.Fatalf("Args = %#v", got.Args)
	}
	if got.Profile != "deep" || got.Output != "configured.md" || got.OutputJSON != "cli.json" {
		t.Fatalf("merged config = %#v", got)
	}
	if got.Headers["Accept-Language"] != "en-US" || got.Headers["Accept"] != "text/html" {
		t.Fatalf("headers = %#v", got.Headers)
	}
	if got.MaxAssets != 25 || got.MaxConcurrency != 8 {
		t.Fatalf("limits = %#v", got)
	}
}

func TestReadScanConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supascope.config.json")
	if err := os.WriteFile(path, []byte(`{"target":"https://example.com","profile":"passive","outputJson":"report.json"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	config, err := readScanConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Target != "https://example.com" || config.OutputJSON != "report.json" {
		t.Fatalf("config = %#v", config)
	}
}
