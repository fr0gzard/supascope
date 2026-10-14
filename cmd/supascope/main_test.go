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

func TestParseCommandRejectsUnknownSubcommand(t *testing.T) {
	_, err := parseCommand("nope", []string{})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestParseURLCommand(t *testing.T) {
	cfg, _, err := parseTargetCommand("url", []string{"https://example.com", "--yes", "--json", "--header", "Accept: text/html"}, "target URL")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "url" || cfg.Target != "https://example.com" {
		t.Fatalf("config = %#v", cfg)
	}
	if !cfg.Yes || !cfg.JSON {
		t.Fatalf("shared flags not applied: %#v", cfg)
	}
	if cfg.Headers["Accept"] != "text/html" {
		t.Fatalf("headers = %#v", cfg.Headers)
	}
}

func TestParseURLCommandFlagsAfterTarget(t *testing.T) {
	cfg, _, err := parseTargetCommand("url", []string{"--profile", "deep", "https://example.com"}, "target URL")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "https://example.com" || cfg.Profile != "deep" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestParseTargetCommandRejectsExtraPositionals(t *testing.T) {
	_, _, err := parseTargetCommand("url", []string{"https://a.example", "https://b.example"}, "target URL")
	if err == nil {
		t.Fatal("expected error for extra positional targets")
	}
}

func TestParseTargetCommandAllowsTargetFromConfig(t *testing.T) {
	cfg, _, err := parseTargetCommand("folder", []string{"--yes"}, "folder path")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "" {
		t.Fatalf("expected empty target before config merge, got %q", cfg.Target)
	}
	if _, err := scanOptions(cfg); err == nil {
		t.Fatal("expected error for missing target with no config file")
	}
}

func TestParseBrowserCommandDefaults(t *testing.T) {
	cfg, _, err := parseBrowserCommand([]string{"https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BrowserMode != "headless" {
		t.Fatalf("BrowserMode = %q, want headless", cfg.BrowserMode)
	}
	if cfg.DynamicWait != 2*time.Second || cfg.DynamicWaitSet {
		t.Fatalf("DynamicWait = %s set=%v, want 2s unset", cfg.DynamicWait, cfg.DynamicWaitSet)
	}
}

func TestParseBrowserCommandHeaded(t *testing.T) {
	cfg, _, err := parseBrowserCommand([]string{"https://example.com", "--headed"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BrowserMode != "headed" || !cfg.BrowserModeSet {
		t.Fatalf("BrowserMode = %q set=%v", cfg.BrowserMode, cfg.BrowserModeSet)
	}
}

func TestParseBrowserCommandAttach(t *testing.T) {
	cfg, _, err := parseBrowserCommand([]string{"https://example.com", "--attach"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BrowserMode != "attach" {
		t.Fatalf("BrowserMode = %q, want attach", cfg.BrowserMode)
	}

	custom, _, err := parseBrowserCommand([]string{"https://example.com", "--attach-url", "http://10.0.0.5:9222"})
	if err != nil {
		t.Fatal(err)
	}
	if custom.BrowserMode != "attach" || custom.AttachURL != "http://10.0.0.5:9222" {
		t.Fatalf("attach config = %#v", custom)
	}
}

func TestParseBrowserCommandRejectsHeadedPlusAttach(t *testing.T) {
	_, _, err := parseBrowserCommand([]string{"https://example.com", "--headed", "--attach"})
	if err == nil {
		t.Fatal("expected error for --headed with --attach")
	}
}

func TestParseProjectCommandRejectsPositionals(t *testing.T) {
	_, _, err := parseProjectCommand([]string{"https://example.com", "--supabase-url", "https://x.supabase.co"})
	if err == nil {
		t.Fatal("expected error for positional argument to scan project")
	}
}

func TestScanOptionsBuildsTargetsPerMode(t *testing.T) {
	cases := []struct {
		mode      string
		target    string
		supabase  string
		wantType  model.TargetType
		wantValue string
	}{
		{"url", "https://example.com", "", model.TargetURL, "https://example.com"},
		{"folder", "./dist", "", model.TargetLocalPath, "./dist"},
		{"har", "network.har", "", model.TargetHAR, "network.har"},
		{"project", "", "https://x.supabase.co", model.TargetSupabaseProject, "https://x.supabase.co"},
		{"browser", "https://example.com", "", model.TargetURL, "https://example.com"},
	}
	for _, tc := range cases {
		opts, err := scanOptions(scanConfig{Mode: tc.mode, Target: tc.target, SupabaseURL: tc.supabase, Yes: true})
		if err != nil {
			t.Fatalf("mode %s: %v", tc.mode, err)
		}
		if opts.Target.Type != tc.wantType || opts.Target.Value != tc.wantValue {
			t.Fatalf("mode %s: target = %#v", tc.mode, opts.Target)
		}
	}
}

func TestScanOptionsRequiresProjectURL(t *testing.T) {
	_, err := scanOptions(scanConfig{Mode: "project", Yes: true})
	if err == nil {
		t.Fatal("expected error for scan project without --supabase-url")
	}
}

func TestScanOptionsRequiresGraphQLIntrospectionForSchemaOutput(t *testing.T) {
	opts, err := scanOptions(scanConfig{Mode: "url", Target: "https://example.com", Yes: true, GraphQLSchemaOutput: "schema.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.GraphQLIntrospection {
		t.Fatal("expected schema output to imply GraphQL introspection")
	}
}

func TestScanOptionsAppliesProfiles(t *testing.T) {
	active, err := scanOptions(scanConfig{Mode: "url", Target: "https://example.com", Profile: "active", Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !active.ActiveChecks || active.GraphQLIntrospection {
		t.Fatalf("active profile options = %#v", active)
	}

	deep, err := scanOptions(scanConfig{Mode: "url", Target: "https://example.com", Profile: "deep", Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !deep.ActiveChecks || !deep.GraphQLIntrospection {
		t.Fatalf("deep profile options = %#v", deep)
	}
}

func TestScanOptionsRejectsInvalidProfile(t *testing.T) {
	_, err := scanOptions(scanConfig{Mode: "url", Target: "https://example.com", Profile: "nope", Yes: true})
	if err == nil {
		t.Fatal("expected invalid profile error")
	}
}

func TestScanOptionsBrowserModeMapping(t *testing.T) {
	headed, err := scanOptions(scanConfig{Mode: "browser", Target: "https://example.com", BrowserMode: "headed", Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !headed.Dynamic || !headed.Live {
		t.Fatalf("headed options = %#v", headed)
	}
	if headed.DynamicWait != 10*time.Minute {
		t.Fatalf("headed DynamicWait = %s, want 10m default", headed.DynamicWait)
	}

	attach, err := scanOptions(scanConfig{Mode: "browser", Target: "https://example.com", BrowserMode: "attach", Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !attach.Dynamic || attach.BrowserDebuggerURL != defaultBrowserDebuggerURL {
		t.Fatalf("attach options = %#v", attach)
	}
	if attach.DynamicWait != 10*time.Minute {
		t.Fatalf("attach DynamicWait = %s, want 10m default", attach.DynamicWait)
	}

	headless, err := scanOptions(scanConfig{Mode: "browser", Target: "https://example.com", BrowserMode: "headless", DynamicWait: 5 * time.Second, DynamicWaitSet: true, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !headless.Dynamic || headless.Live {
		t.Fatalf("headless options = %#v", headless)
	}
	if headless.DynamicWait != 5*time.Second {
		t.Fatalf("headless DynamicWait = %s, want explicit 5s", headless.DynamicWait)
	}
}

func TestScanOptionsRespectsExplicitWaitForInteractiveBrowser(t *testing.T) {
	opts, err := scanOptions(scanConfig{Mode: "browser", Target: "https://example.com", BrowserMode: "attach", DynamicWait: 90 * time.Second, DynamicWaitSet: true, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if opts.DynamicWait != 90*time.Second {
		t.Fatalf("DynamicWait = %s, want explicit 90s", opts.DynamicWait)
	}
}

func TestNeedsAuthorization(t *testing.T) {
	cases := []struct {
		target model.Target
		active bool
		want   bool
	}{
		{model.Target{Type: model.TargetURL}, false, true},
		{model.Target{Type: model.TargetSupabaseProject}, false, true},
		{model.Target{Type: model.TargetLocalPath}, false, false},
		{model.Target{Type: model.TargetHAR}, false, false},
		{model.Target{Type: model.TargetLocalPath}, true, true},
		{model.Target{Type: model.TargetHAR}, true, true},
	}
	for _, tc := range cases {
		got := needsAuthorization(model.Options{Target: tc.target, ActiveChecks: tc.active})
		if got != tc.want {
			t.Fatalf("needsAuthorization(%v, active=%v) = %v, want %v", tc.target.Type, tc.active, got, tc.want)
		}
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

func TestNormalizeScanArgsMovesFlagsBeforeTarget(t *testing.T) {
	got := normalizeScanArgs([]string{
		"https://example.com",
		"--profile",
		"deep",
		"--yes",
		"--json",
		"--header",
		"Accept: text/html",
		"--wait",
		"30s",
		"-w",
		"45s",
		"--attach",
		"--output",
		"report.md",
		"--graphql-schema-output",
		"schema.txt",
		"--auth-token",
		"tok123",
	})
	want := []string{
		"--profile",
		"deep",
		"--yes",
		"--json",
		"--header",
		"Accept: text/html",
		"--wait",
		"30s",
		"-w",
		"45s",
		"--attach",
		"--output",
		"report.md",
		"--graphql-schema-output",
		"schema.txt",
		"--auth-token",
		"tok123",
		"https://example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeScanArgs() = %#v, want %#v", got, want)
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
		Profile:        "active",
		UserAgent:      "SupaScope-Test/1.0",
		Headers:        map[string]string{"accept-language": "en-US"},
		JSON:           &trueValue,
		Output:         "report.md",
		OutputJSON:     "report.json",
		MaxAssets:      &maxAssets,
		Yes:            &trueValue,
		DynamicWait:    "30s",
		Delay:          "250ms",
		MaxConcurrency: &maxConcurrency,
	}, "url")
	if err != nil {
		t.Fatal(err)
	}
	if config.Target != "https://example.com" {
		t.Fatalf("target = %q", config.Target)
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
	if config.MaxAssets != 70 || !config.Yes || config.Delay.String() != "250ms" || config.MaxConcurrency != 2 {
		t.Fatalf("scan controls = %#v", config)
	}
	// Regression: config-file dynamicWait must count as "set" so the browser
	// subcommand does not overwrite it with the interactive default.
	if config.DynamicWait.String() != "30s" || !config.DynamicWaitSet {
		t.Fatalf("dynamicWait = %s set=%v, want 30s set", config.DynamicWait, config.DynamicWaitSet)
	}
}

func TestScanConfigFromFileBrowserMode(t *testing.T) {
	config, err := scanConfigFromFile(scanFileConfig{
		Target:      "https://example.com",
		BrowserMode: "headed",
		AttachURL:   "http://10.0.0.5:9222",
	}, "browser")
	if err != nil {
		t.Fatal(err)
	}
	if config.BrowserMode != "headed" || config.AttachURL != "http://10.0.0.5:9222" {
		t.Fatalf("browser config = %#v", config)
	}
}

func TestScanConfigFromFileLegacyPathAlias(t *testing.T) {
	config, err := scanConfigFromFile(scanFileConfig{Path: "./dist"}, "folder")
	if err != nil {
		t.Fatal(err)
	}
	if config.Target != "./dist" {
		t.Fatalf("target = %q, want legacy path alias", config.Target)
	}
}

func TestMergeCLIConfigTargetOverride(t *testing.T) {
	base, err := scanConfigFromFile(scanFileConfig{Target: "https://configured.example", Profile: "active"}, "url")
	if err != nil {
		t.Fatal(err)
	}
	cli, set, err := parseTargetCommand("url", []string{"https://cli.example", "--profile", "deep"}, "target URL")
	if err != nil {
		t.Fatal(err)
	}
	got := mergeCLIConfig(base, cli, set)
	if got.Target != "https://cli.example" || got.Profile != "deep" {
		t.Fatalf("merged = %#v", got)
	}
}

func TestMergeCLIConfigKeepsFileValuesWhenCLIDefault(t *testing.T) {
	base, err := scanConfigFromFile(scanFileConfig{Target: "https://configured.example", Profile: "active", MaxAssets: intPtr(25)}, "url")
	if err != nil {
		t.Fatal(err)
	}
	cli, set, err := parseTargetCommand("url", []string{"https://cli.example"}, "target URL")
	if err != nil {
		t.Fatal(err)
	}
	got := mergeCLIConfig(base, cli, set)
	if got.Profile != "active" || got.MaxAssets != 25 {
		t.Fatalf("merged = %#v", got)
	}
}

func TestMergeCLIConfigKeepsAuthTokensWithConfigFile(t *testing.T) {
	base, err := scanConfigFromFile(scanFileConfig{Target: "https://configured.example"}, "url")
	if err != nil {
		t.Fatal(err)
	}
	cli, set, err := parseTargetCommand("url", []string{
		"https://cli.example", "--auth-token", "TOKEN_A", "--auth-token-2", "TOKEN_B",
	}, "target URL")
	if err != nil {
		t.Fatal(err)
	}
	// Regression: mergeCLIConfig used to drop AuthTokens when a config file
	// was in play, silently disabling RLS multi-identity testing.
	got := mergeCLIConfig(base, cli, set)
	want := []string{"TOKEN_A", "TOKEN_B"}
	if !reflect.DeepEqual(got.AuthTokens, want) {
		t.Fatalf("AuthTokens = %#v, want %#v", got.AuthTokens, want)
	}
}

func intPtr(v int) *int { return &v }

func TestReadScanConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supascope.config.json")
	if err := os.WriteFile(path, []byte(`{"target":"https://example.com","profile":"passive","outputJson":"report.json","browserMode":"headed"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	config, err := readScanConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Target != "https://example.com" || config.OutputJSON != "report.json" || config.BrowserMode != "headed" {
		t.Fatalf("config = %#v", config)
	}
}

func TestParseCommandEndToEnd(t *testing.T) {
	run, err := parseCommand("project", []string{"--supabase-url", "https://x.supabase.co", "--yes", "--profile", "active"})
	if err != nil {
		t.Fatal(err)
	}
	if run.opts.Target.Type != model.TargetSupabaseProject || !run.opts.ActiveChecks || !run.opts.Yes {
		t.Fatalf("run = %#v", run.opts)
	}
}
