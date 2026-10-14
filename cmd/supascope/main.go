package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"supascope/internal/model"
	"supascope/internal/report"
	"supascope/internal/scanner"
)

const defaultBrowserDebuggerURL = "http://127.0.0.1:9222"

// errUsage marks errors that should print command usage instead of just the
// error text.
var errUsage = errors.New("usage")

const usageText = `SupaScope - authorized Supabase security reconnaissance scanner.

Usage:
  supascope scan <command> [flags]

Commands:
  url <target>       scan a public URL (static asset + key discovery)
  folder <dir>       scan a local folder (build output or source)
  har <file>         scan a HAR network log file
  project            probe a known Supabase project (requires --supabase-url)
  browser <target>   capture live browser traffic (headless by default)

Shared flags (all commands):
  --config file            load scan settings from a JSON config file
  --profile name           scan profile: passive (default), active, or deep
  --yes, -y                confirm authorization for the scan
  --json, -j               print JSON report instead of Markdown
  --output, -o file        write Markdown report to file (.html auto-detected)
  --output-json, -oj file  write JSON report to file
  --key key                Supabase anon or publishable key
  --auth-token token       authenticated user JWT for RLS testing (user A)
  --auth-token-2 token     second authenticated user JWT for cross-user RLS testing (user B)
  --unsafe-show-secrets    print full discovered secrets in reports
  --debug                  print remote request diagnostics to stderr
  --user-agent ua           User-Agent header for remote HTTP requests
  --header "Name: value"   additional header for remote HTTP requests (repeatable)

Command flags:
  browser: --headed, --attach, --attach-url url, --wait, -w duration
  project: --supabase-url url, --active-storage-tests,
           --graphql-introspection, --graphql-schema-output file

Request tuning (delay, max-assets, max-concurrency, idle-timeout) is configured
via the JSON config file only. See README.md for config file reference.
`

const browserUsageText = `Usage:
  supascope scan browser <target> [flags]

Captures browser network traffic for a public URL. Headless by default.

  --headed            launch Chrome with your existing profile (interactive,
                      keeps logins); capture ends on idle or --wait timeout
  --attach            attach to a running Chrome with remote debugging enabled
  --attach-url url    Chrome DevTools URL to attach to (default ` + defaultBrowserDebuggerURL + `)
  --wait, -w duration browser observation window (headless), or max capture
                      timeout for --headed/--attach (default 2s, 10m for
                      --headed/--attach unless set)
`

const projectUsageText = `Usage:
  supascope scan project --supabase-url https://<ref>.supabase.co [flags]

Probes a known Supabase project directly. Requires --yes (active probing).

  --supabase-url url         Supabase project URL to probe (required)
  --active-storage-tests     enable active storage tests
  --graphql-introspection    enable GraphQL introspection probe
  --graphql-schema-output f  write GraphQL introspection response to a text file
`

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	run, err := parseCommand(os.Args[2], os.Args[3:])
	if err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprintf(os.Stderr, "error: %s\n\n", strings.TrimPrefix(err.Error(), errUsage.Error()+": "))
			printCommandUsage(os.Args[2])
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(2)
	}

	if needsAuthorization(run.opts) && !run.opts.Yes {
		fmt.Println(strings.Join([]string{
			"SupaScope is intended for authorized security testing only.",
			"Only scan applications you own or have permission to test.",
			"By continuing, you confirm that you are authorized to scan this target.",
			"",
			"Pass --yes to run non-interactively.",
		}, "\n"))
		os.Exit(1)
	}

	result, err := scanner.New().Scan(context.Background(), run.opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if run.output != "" || run.outputJSON != "" {
		written, err := writeOutputReports(result, run.output, run.outputJSON)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		for _, path := range written {
			fmt.Printf("Report written to: %s\n", path)
		}
		return
	}

	rendered, err := renderReport(result, run.opts.JSON)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Print(rendered)
}

func printCommandUsage(cmd string) {
	switch cmd {
	case "browser":
		fmt.Fprint(os.Stderr, browserUsageText)
	case "project":
		fmt.Fprint(os.Stderr, projectUsageText)
	default:
		fmt.Fprint(os.Stderr, usageText)
	}
}

// scanRun bundles the scanner options with the output routing derived from
// the CLI/config, which model.Options does not fully carry.
type scanRun struct {
	opts       model.Options
	output     string
	outputJSON string
}

func parseCommand(cmd string, args []string) (scanRun, error) {
	var cfg scanConfig
	var set map[string]bool
	var err error
	switch cmd {
	case "url":
		cfg, set, err = parseTargetCommand(cmd, args, "target URL")
	case "folder":
		cfg, set, err = parseTargetCommand(cmd, args, "folder path")
	case "har":
		cfg, set, err = parseTargetCommand(cmd, args, "HAR file")
	case "browser":
		cfg, set, err = parseBrowserCommand(args)
	case "project":
		cfg, set, err = parseProjectCommand(args)
	default:
		return scanRun{}, fmt.Errorf("%w: unknown scan command %q", errUsage, cmd)
	}
	if err != nil {
		return scanRun{}, err
	}

	if cfg.ConfigPath != "" {
		fileConfig, err := readScanConfigFile(cfg.ConfigPath)
		if err != nil {
			return scanRun{}, err
		}
		fileCfg, err := scanConfigFromFile(fileConfig, cfg.Mode)
		if err != nil {
			return scanRun{}, err
		}
		cfg = mergeCLIConfig(fileCfg, cfg, set)
	}

	opts, err := scanOptions(cfg)
	if err != nil {
		return scanRun{}, err
	}
	return scanRun{opts: opts, output: cfg.Output, outputJSON: cfg.OutputJSON}, nil
}

// needsAuthorization reports whether the scan touches remote targets or
// performs active probing, in which case --yes is required.
func needsAuthorization(opts model.Options) bool {
	switch opts.Target.Type {
	case model.TargetURL, model.TargetSupabaseProject:
		return true
	}
	return opts.ActiveChecks
}

// sharedValues holds the flags available on every scan subcommand.
type sharedValues struct {
	configPath  string
	profile     string
	key         string
	authToken   string
	authToken2  string
	userAgent   string
	headers     headerFlags
	output      string
	outputJSON  string
	jsonOut     bool
	showSecrets bool
	debug       bool
	yes         bool
}

func registerSharedFlags(fs *flag.FlagSet, v *sharedValues) {
	fs.StringVar(&v.configPath, "config", "", "load scan settings from JSON config file")
	fs.StringVar(&v.profile, "profile", "passive", "scan profile: passive, active, or deep")
	fs.StringVar(&v.key, "key", "", "Supabase anon or publishable key")
	fs.StringVar(&v.authToken, "auth-token", "", "authenticated user JWT for RLS testing (user A)")
	fs.StringVar(&v.authToken2, "auth-token-2", "", "second authenticated user JWT for cross-user RLS testing (user B)")
	fs.StringVar(&v.userAgent, "user-agent", "", "User-Agent header for remote HTTP requests")
	fs.Var(&v.headers, "header", "additional header for remote HTTP requests, formatted as 'Name: value' (repeatable)")
	fs.StringVar(&v.output, "output", "", "write Markdown report to file")
	fs.StringVar(&v.output, "o", "", "write Markdown report to file")
	fs.StringVar(&v.outputJSON, "output-json", "", "write JSON report to file")
	fs.StringVar(&v.outputJSON, "oj", "", "write JSON report to file")
	fs.BoolVar(&v.jsonOut, "json", false, "print JSON report instead of Markdown")
	fs.BoolVar(&v.jsonOut, "j", false, "print JSON report instead of Markdown")
	fs.BoolVar(&v.showSecrets, "unsafe-show-secrets", false, "print full discovered secrets in reports")
	fs.BoolVar(&v.debug, "debug", false, "print remote request diagnostics to stderr")
	fs.BoolVar(&v.yes, "yes", false, "confirm authorization for the scan")
	fs.BoolVar(&v.yes, "y", false, "confirm authorization for the scan")
}

// sharedScanConfig builds the mode-independent part of scanConfig from parsed
// shared flags.
func sharedScanConfig(mode string, v *sharedValues) (scanConfig, error) {
	headers, err := parseHeaders(v.headers)
	if err != nil {
		return scanConfig{}, err
	}
	cfg := scanConfig{
		Mode:        mode,
		ConfigPath:  v.configPath,
		Profile:     v.profile,
		Key:         v.key,
		UserAgent:   v.userAgent,
		Headers:     headers,
		JSON:        v.jsonOut,
		Output:      v.output,
		OutputJSON:  v.outputJSON,
		ShowSecrets: v.showSecrets,
		Debug:       v.debug,
		Yes:         v.yes,
	}
	if v.authToken != "" {
		cfg.AuthTokens = append(cfg.AuthTokens, v.authToken)
	}
	if v.authToken2 != "" {
		cfg.AuthTokens = append(cfg.AuthTokens, v.authToken2)
	}
	return cfg, nil
}

// parseTargetCommand handles the url, folder, and har subcommands, each of
// which takes exactly one positional target plus the shared flags.
func parseTargetCommand(mode string, args []string, what string) (scanConfig, map[string]bool, error) {
	shared := sharedValues{}
	fs := flag.NewFlagSet("scan "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerSharedFlags(fs, &shared)

	target, err := parsePositionalTarget(fs, args, what)
	if err != nil {
		return scanConfig{}, nil, err
	}
	cfg, err := sharedScanConfig(mode, &shared)
	if err != nil {
		return scanConfig{}, nil, err
	}
	cfg.Target = target
	return cfg, visitedFlags(fs), nil
}

// parseBrowserCommand handles `scan browser <target>`: headless dynamic
// capture by default, --headed for an interactive profile session, --attach
// for an existing Chrome with remote debugging.
func parseBrowserCommand(args []string) (scanConfig, map[string]bool, error) {
	shared := sharedValues{}
	fs := flag.NewFlagSet("scan browser", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerSharedFlags(fs, &shared)
	headed := fs.Bool("headed", false, "launch Chrome with your existing profile (interactive, keeps logins)")
	attach := fs.Bool("attach", false, "attach to a running Chrome with remote debugging enabled")
	attachURL := fs.String("attach-url", "", "Chrome DevTools URL to attach to (default "+defaultBrowserDebuggerURL+")")
	var wait time.Duration
	fs.DurationVar(&wait, "wait", 2*time.Second, "browser observation window (headless), or max capture timeout for --headed/--attach")
	fs.DurationVar(&wait, "w", 2*time.Second, "alias for --wait")

	target, err := parsePositionalTarget(fs, args, "target URL")
	if err != nil {
		return scanConfig{}, nil, err
	}
	set := visitedFlags(fs)

	if *headed && (*attach || flagSet(set, "attach-url")) {
		return scanConfig{}, nil, fmt.Errorf("%w: --headed and --attach are mutually exclusive", errUsage)
	}
	browserMode := "headless"
	switch {
	case *headed:
		browserMode = "headed"
	case *attach || flagSet(set, "attach-url"):
		browserMode = "attach"
	}

	cfg, err := sharedScanConfig("browser", &shared)
	if err != nil {
		return scanConfig{}, nil, err
	}
	cfg.Target = target
	cfg.BrowserMode = browserMode
	cfg.BrowserModeSet = flagSet(set, "headed", "attach", "attach-url")
	cfg.AttachURL = *attachURL
	cfg.DynamicWait = wait
	if flagSet(set, "wait", "w") {
		cfg.DynamicWaitSet = true
	}
	return cfg, set, nil
}

// parseProjectCommand handles `scan project --supabase-url ...`.
func parseProjectCommand(args []string) (scanConfig, map[string]bool, error) {
	shared := sharedValues{}
	fs := flag.NewFlagSet("scan project", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerSharedFlags(fs, &shared)
	supabaseURL := fs.String("supabase-url", "", "Supabase project URL to probe (required)")
	activeStorage := fs.Bool("active-storage-tests", false, "enable active storage tests")
	graphqlIntrospection := fs.Bool("graphql-introspection", false, "enable GraphQL introspection probe")
	graphqlSchemaOutput := fs.String("graphql-schema-output", "", "write GraphQL introspection response to a text file")

	if err := fs.Parse(normalizeScanArgs(args)); err != nil {
		return scanConfig{}, nil, fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return scanConfig{}, nil, fmt.Errorf("%w: scan project takes no positional arguments, got %q", errUsage, fs.Arg(0))
	}
	cfg, err := sharedScanConfig("project", &shared)
	if err != nil {
		return scanConfig{}, nil, err
	}
	cfg.SupabaseURL = *supabaseURL
	cfg.ActiveStorageTests = *activeStorage
	cfg.GraphQLIntrospection = *graphqlIntrospection
	cfg.GraphQLSchemaOutput = *graphqlSchemaOutput
	return cfg, visitedFlags(fs), nil
}

// parsePositionalTarget parses flags and extracts the single positional scan
// target. Zero positionals are allowed so the target can come from the config
// file instead; scanOptions rejects an empty target.
func parsePositionalTarget(fs *flag.FlagSet, args []string, what string) (string, error) {
	if err := fs.Parse(normalizeScanArgs(args)); err != nil {
		return "", fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 1 {
		return "", fmt.Errorf("%w: %s expects at most one %s, got %d", errUsage, fs.Name(), what, fs.NArg())
	}
	if fs.NArg() == 0 {
		return "", nil
	}
	return fs.Arg(0), nil
}

func renderReport(result model.Report, jsonOut bool) (string, error) {
	if jsonOut {
		return report.JSON(result)
	}
	return report.Markdown(result), nil
}

func writeOutputReports(result model.Report, markdownOutput string, jsonOutput string) ([]string, error) {
	var written []string
	if markdownOutput != "" {
		if strings.HasSuffix(strings.ToLower(markdownOutput), ".html") {
			if err := report.WriteHTML(result, markdownOutput); err != nil {
				return nil, err
			}
		} else {
			content := report.Markdown(result)
			if err := os.WriteFile(markdownOutput, []byte(content), 0o644); err != nil {
				return nil, err
			}
		}
		written = append(written, markdownOutput)
	}
	if jsonOutput != "" {
		rendered, err := report.JSON(result)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(jsonOutput, []byte(rendered), 0o644); err != nil {
			return nil, err
		}
		written = append(written, jsonOutput)
	}
	return written, nil
}

// normalizeScanArgs moves positional arguments after flags so targets can be
// given before or after flags (e.g. `scan url https://x --yes`).
func normalizeScanArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--config":                true,
		"--profile":               true,
		"--key":                   true,
		"--auth-token":            true,
		"--auth-token-2":          true,
		"--user-agent":            true,
		"--header":                true,
		"--output":                true,
		"-o":                      true,
		"--output-json":           true,
		"-oj":                     true,
		"--wait":                  true,
		"-w":                      true,
		"--supabase-url":          true,
		"--attach-url":            true,
		"--graphql-schema-output": true,
	}

	var flags []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		flags = append(flags, arg)
		name := arg
		if idx := strings.Index(arg, "="); idx >= 0 {
			name = arg[:idx]
		}
		if valueFlags[name] && !strings.Contains(arg, "=") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}

	return append(flags, positional...)
}

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func parseHeaders(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	headers := make(map[string]string, len(values))
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			return nil, fmt.Errorf("invalid --header %q: expected 'Name: value'", raw)
		}
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return nil, fmt.Errorf("invalid --header %q: header name and value are required", raw)
		}
		headers[name] = value
	}
	return headers, nil
}

// scanFileConfig is the JSON config file schema. Tuning knobs that have no
// CLI flag (delay, max-assets, max-concurrency, idle-timeout) live here.
type scanFileConfig struct {
	Target               string            `json:"target"`
	Path                 string            `json:"path"` // legacy alias for folder target
	HAR                  string            `json:"har"`  // legacy alias for har target
	SupabaseURL          string            `json:"supabaseUrl"`
	BrowserMode          string            `json:"browserMode"` // headless|headed|attach
	AttachURL            string            `json:"attachUrl"`
	Key                  string            `json:"key"`
	Profile              string            `json:"profile"`
	UserAgent            string            `json:"userAgent"`
	Headers              map[string]string `json:"headers"`
	JSON                 *bool             `json:"json"`
	Output               string            `json:"output"`
	OutputJSON           string            `json:"outputJson"`
	ShowSecrets          *bool             `json:"unsafeShowSecrets"`
	Debug                *bool             `json:"debug"`
	MaxAssets            *int              `json:"maxAssets"`
	Yes                  *bool             `json:"yes"`
	DynamicWait          string            `json:"dynamicWait"`
	IdleTimeout          string            `json:"idleTimeout"`
	ActiveStorageTests   *bool             `json:"activeStorageTests"`
	GraphQLIntrospection *bool             `json:"graphqlIntrospection"`
	GraphQLSchemaOutput  string            `json:"graphqlSchemaOutput"`
	Delay                string            `json:"delay"`
	MaxConcurrency       *int              `json:"maxConcurrency"`
}

func readScanConfigFile(path string) (scanFileConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return scanFileConfig{}, err
	}
	var config scanFileConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return scanFileConfig{}, fmt.Errorf("invalid config file %q: %w", path, err)
	}
	return config, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func scanConfigFromFile(fileConfig scanFileConfig, mode string) (scanConfig, error) {
	config := scanConfig{
		Mode:                mode,
		Profile:             fileConfig.Profile,
		Key:                 fileConfig.Key,
		UserAgent:           fileConfig.UserAgent,
		Headers:             canonicalHeaders(fileConfig.Headers),
		Output:              fileConfig.Output,
		OutputJSON:          fileConfig.OutputJSON,
		GraphQLSchemaOutput: fileConfig.GraphQLSchemaOutput,
		BrowserMode:         fileConfig.BrowserMode,
		AttachURL:           fileConfig.AttachURL,
	}
	switch mode {
	case "url", "browser":
		config.Target = fileConfig.Target
	case "folder":
		config.Target = firstNonEmpty(fileConfig.Target, fileConfig.Path)
	case "har":
		config.Target = firstNonEmpty(fileConfig.Target, fileConfig.HAR)
	case "project":
		config.SupabaseURL = fileConfig.SupabaseURL
	}
	if fileConfig.JSON != nil {
		config.JSON = *fileConfig.JSON
	}
	if fileConfig.ShowSecrets != nil {
		config.ShowSecrets = *fileConfig.ShowSecrets
	}
	if fileConfig.Debug != nil {
		config.Debug = *fileConfig.Debug
	}
	if fileConfig.MaxAssets != nil {
		config.MaxAssets = *fileConfig.MaxAssets
	}
	if fileConfig.Yes != nil {
		config.Yes = *fileConfig.Yes
	}
	if fileConfig.DynamicWait != "" {
		dynamicWait, err := time.ParseDuration(fileConfig.DynamicWait)
		if err != nil {
			return scanConfig{}, fmt.Errorf("invalid config dynamicWait %q: %w", fileConfig.DynamicWait, err)
		}
		config.DynamicWait = dynamicWait
		config.DynamicWaitSet = true
	}
	if fileConfig.IdleTimeout != "" {
		idleTimeout, err := time.ParseDuration(fileConfig.IdleTimeout)
		if err != nil {
			return scanConfig{}, fmt.Errorf("invalid config idleTimeout %q: %w", fileConfig.IdleTimeout, err)
		}
		config.IdleTimeout = idleTimeout
	}
	if fileConfig.ActiveStorageTests != nil {
		config.ActiveStorageTests = *fileConfig.ActiveStorageTests
	}
	if fileConfig.GraphQLIntrospection != nil {
		config.GraphQLIntrospection = *fileConfig.GraphQLIntrospection
	}
	if fileConfig.Delay != "" {
		delay, err := time.ParseDuration(fileConfig.Delay)
		if err != nil {
			return scanConfig{}, fmt.Errorf("invalid config delay %q: %w", fileConfig.Delay, err)
		}
		config.Delay = delay
	}
	if fileConfig.MaxConcurrency != nil {
		config.MaxConcurrency = *fileConfig.MaxConcurrency
	}
	return config, nil
}

func canonicalHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		out[name] = value
	}
	return out
}

func visitedFlags(fs *flag.FlagSet) map[string]bool {
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	return visited
}

func flagSet(visited map[string]bool, names ...string) bool {
	for _, name := range names {
		if visited[name] {
			return true
		}
	}
	return false
}

// mergeCLIConfig overlays CLI-parsed values on top of the config-file base.
// Only flags the user actually set override the file.
func mergeCLIConfig(config scanConfig, cli scanConfig, setFlags map[string]bool) scanConfig {
	if cli.Target != "" {
		config.Target = cli.Target
	}
	if cli.SupabaseURL != "" {
		config.SupabaseURL = cli.SupabaseURL
	}
	if flagSet(setFlags, "profile") {
		config.Profile = cli.Profile
	}
	if flagSet(setFlags, "key") {
		config.Key = cli.Key
	}
	if flagSet(setFlags, "user-agent") {
		config.UserAgent = cli.UserAgent
	}
	if len(cli.Headers) > 0 {
		config.Headers = mergeHeaderMaps(config.Headers, cli.Headers)
	}
	if flagSet(setFlags, "json", "j") {
		config.JSON = cli.JSON
	}
	if flagSet(setFlags, "output", "o") {
		config.Output = cli.Output
	}
	if flagSet(setFlags, "output-json", "oj") {
		config.OutputJSON = cli.OutputJSON
	}
	if flagSet(setFlags, "unsafe-show-secrets") {
		config.ShowSecrets = cli.ShowSecrets
	}
	if flagSet(setFlags, "debug") {
		config.Debug = cli.Debug
	}
	if flagSet(setFlags, "yes", "y") {
		config.Yes = cli.Yes
	}
	if len(cli.AuthTokens) > 0 {
		config.AuthTokens = cli.AuthTokens
	}
	if flagSet(setFlags, "supabase-url") {
		config.SupabaseURL = cli.SupabaseURL
	}
	if cli.BrowserModeSet {
		config.BrowserMode = cli.BrowserMode
		config.BrowserModeSet = true
	}
	if flagSet(setFlags, "attach-url") {
		config.AttachURL = cli.AttachURL
	}
	if flagSet(setFlags, "wait", "w") {
		config.DynamicWait = cli.DynamicWait
		config.DynamicWaitSet = true
	} else if config.DynamicWait == 0 {
		config.DynamicWait = cli.DynamicWait
	}
	if flagSet(setFlags, "active-storage-tests") {
		config.ActiveStorageTests = cli.ActiveStorageTests
	}
	if flagSet(setFlags, "graphql-introspection") {
		config.GraphQLIntrospection = cli.GraphQLIntrospection
	}
	if flagSet(setFlags, "graphql-schema-output") {
		config.GraphQLSchemaOutput = cli.GraphQLSchemaOutput
	}
	return config
}

func mergeHeaderMaps(base map[string]string, overrides map[string]string) map[string]string {
	if len(base) == 0 {
		return overrides
	}
	merged := make(map[string]string, len(base)+len(overrides))
	for name, value := range base {
		merged[name] = value
	}
	for name, value := range overrides {
		merged[name] = value
	}
	return merged
}

// scanConfig is the merged CLI + config-file state for one scan invocation.
type scanConfig struct {
	Mode               string // url|folder|har|project|browser
	Target             string
	SupabaseURL        string
	ConfigPath         string
	BrowserMode        string // headless|headed|attach (browser mode only)
	BrowserModeSet     bool
	AttachURL          string
	BrowserDebuggerURL string
	Dynamic            bool
	Live               bool

	Profile     string
	Key         string
	AuthTokens  []string
	UserAgent   string
	Headers     map[string]string
	JSON        bool
	Output      string
	OutputJSON  string
	ShowSecrets bool
	Debug       bool
	Yes         bool

	// Request tuning: config file only, except DynamicWait which the browser
	// subcommand also exposes via --wait.
	MaxAssets      int
	Delay          time.Duration
	MaxConcurrency int
	DynamicWait    time.Duration
	DynamicWaitSet bool
	IdleTimeout    time.Duration

	ActiveChecks         bool
	ActiveStorageTests   bool
	GraphQLIntrospection bool
	GraphQLSchemaOutput  string
}

func scanOptions(config scanConfig) (model.Options, error) {
	config = applyProfile(config)
	if !validProfile(config.Profile) {
		return model.Options{}, fmt.Errorf("invalid --profile %q: expected passive, active, or deep", config.Profile)
	}

	var target model.Target
	switch config.Mode {
	case "url", "browser":
		if strings.TrimSpace(config.Target) == "" {
			return model.Options{}, fmt.Errorf("scan %s requires a target URL", config.Mode)
		}
		target = model.Target{Type: model.TargetURL, Value: config.Target}
	case "folder":
		if strings.TrimSpace(config.Target) == "" {
			return model.Options{}, fmt.Errorf("scan folder requires a directory path")
		}
		target = model.Target{Type: model.TargetLocalPath, Value: config.Target}
	case "har":
		if strings.TrimSpace(config.Target) == "" {
			return model.Options{}, fmt.Errorf("scan har requires a HAR file path")
		}
		target = model.Target{Type: model.TargetHAR, Value: config.Target}
	case "project":
		if strings.TrimSpace(config.SupabaseURL) == "" {
			return model.Options{}, fmt.Errorf("scan project requires --supabase-url")
		}
		target = model.Target{Type: model.TargetSupabaseProject, Value: config.SupabaseURL}
	default:
		return model.Options{}, fmt.Errorf("unknown scan mode %q", config.Mode)
	}

	return model.Options{
		Target:               target,
		Key:                  config.Key,
		UserAgent:            config.UserAgent,
		Headers:              config.Headers,
		Debug:                config.Debug,
		MaxAssets:            config.MaxAssets,
		JSON:                 config.JSON,
		Output:               config.Output,
		ShowSecrets:          config.ShowSecrets,
		Yes:                  config.Yes,
		Dynamic:              config.Dynamic,
		DynamicWait:          config.DynamicWait,
		BrowserDebuggerURL:   config.BrowserDebuggerURL,
		Live:                 config.Live,
		IdleTimeout:          config.IdleTimeout,
		ActiveChecks:         config.ActiveChecks,
		ActiveStorageTests:   config.ActiveStorageTests,
		GraphQLIntrospection: config.GraphQLIntrospection,
		GraphQLSchemaOutput:  config.GraphQLSchemaOutput,
		Delay:                config.Delay,
		MaxConcurrency:       config.MaxConcurrency,
		AuthTokens:           config.AuthTokens,
	}, nil
}

func applyProfile(config scanConfig) scanConfig {
	if config.Profile == "" {
		config.Profile = "passive"
	}
	if config.MaxConcurrency <= 0 {
		config.MaxConcurrency = 4
	}
	switch config.Profile {
	case "passive":
		config.ActiveChecks = false
	case "active":
		config.ActiveChecks = true
	case "deep":
		config.ActiveChecks = true
		config.GraphQLIntrospection = true
	default:
	}
	if config.GraphQLSchemaOutput != "" {
		config.GraphQLIntrospection = true
	}
	if config.Mode == "browser" {
		switch config.BrowserMode {
		case "", "headless":
			config.BrowserMode = "headless"
			config.Dynamic = true
		case "headed":
			config.Dynamic = true
			config.Live = true
		case "attach":
			config.Dynamic = true
			if config.AttachURL == "" {
				config.AttachURL = defaultBrowserDebuggerURL
			}
			config.BrowserDebuggerURL = config.AttachURL
		}
		if config.BrowserMode != "headless" {
			if !config.DynamicWaitSet {
				config.DynamicWait = 10 * time.Minute
			}
			if config.IdleTimeout == 0 {
				config.IdleTimeout = 20 * time.Second
			}
		}
	}
	return config
}

func validProfile(profile string) bool {
	switch profile {
	case "passive", "active", "deep":
		return true
	default:
		return false
	}
}
