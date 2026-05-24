package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"supascope/internal/model"
	"supascope/internal/report"
	"supascope/internal/scanner"
)

const defaultBrowserDebuggerURL = "http://127.0.0.1:9222"

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: supascope scan [target] [--config file] [--profile passive|active|deep] [--path dir] [--har file] [--supabase-url url] [--key key] [--json|-j] [--dynamic|-d] [--wait|-w duration] [--attach-browser|-b] [--yes|-y]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var headers headerFlags
	var output string
	var outputJSON string
	configPath := fs.String("config", "", "load scan settings from JSON config file")
	profile := fs.String("profile", "passive", "scan profile: passive, active, or deep")
	path := fs.String("path", "", "local folder to scan")
	har := fs.String("har", "", "HAR file to scan")
	supabaseURL := fs.String("supabase-url", "", "known Supabase project URL")
	key := fs.String("key", "", "Supabase anon or publishable key")
	userAgent := fs.String("user-agent", "", "User-Agent header for remote HTTP requests")
	fs.Var(&headers, "header", "additional header for remote HTTP requests, formatted as 'Name: value'")
	var jsonOut bool
	fs.BoolVar(&jsonOut, "json", false, "print JSON report")
	fs.BoolVar(&jsonOut, "j", false, "print JSON report")
	fs.StringVar(&output, "output", "", "write Markdown report to file")
	fs.StringVar(&output, "o", "", "write Markdown report to file")
	fs.StringVar(&outputJSON, "output-json", "", "write JSON report to file")
	fs.StringVar(&outputJSON, "oj", "", "write JSON report to file")
	showSecrets := fs.Bool("unsafe-show-secrets", false, "print full discovered secrets in reports")
	debug := fs.Bool("debug", false, "print remote request diagnostics to stderr")
	maxAssets := fs.Int("max-assets", 0, "maximum same-origin assets to fetch during URL scans")
	var yes bool
	fs.BoolVar(&yes, "yes", false, "confirm authorization notice for public URL scans")
	fs.BoolVar(&yes, "y", false, "confirm authorization notice for public URL scans")
	var dynamic bool
	fs.BoolVar(&dynamic, "dynamic", false, "capture browser network traffic with chromedp")
	fs.BoolVar(&dynamic, "d", false, "capture browser network traffic with chromedp")
	var dynamicWait time.Duration
	fs.DurationVar(&dynamicWait, "dynamic-wait", 2*time.Second, "time to observe browser network traffic after page load")
	fs.DurationVar(&dynamicWait, "wait", 2*time.Second, "alias for --dynamic-wait")
	fs.DurationVar(&dynamicWait, "w", 2*time.Second, "alias for --dynamic-wait")
	var attachBrowser bool
	fs.BoolVar(&attachBrowser, "attach-browser", false, "attach to Chrome at http://127.0.0.1:9222 and observe browser traffic")
	fs.BoolVar(&attachBrowser, "b", false, "attach to Chrome at http://127.0.0.1:9222 and observe browser traffic")
	browserDebuggerURL := fs.String("browser-debugger-url", "", "attach dynamic scan to an existing Chrome DevTools URL, e.g. http://127.0.0.1:9222")
	interactive := fs.Bool("interactive", false, "run dynamic browser scan with a visible browser")
	activeStorage := fs.Bool("active-storage-tests", false, "enable active storage tests")
	graphqlIntrospection := fs.Bool("graphql-introspection", false, "enable GraphQL introspection probe")
	graphqlSchemaOutput := fs.String("graphql-schema-output", "", "write GraphQL introspection response to a text file")
	delay := fs.Duration("delay", 0, "delay between remote requests (e.g. 500ms)")
	maxConcurrency := fs.Int("max-concurrency", 4, "maximum concurrent remote requests")

	if err := fs.Parse(normalizeScanArgs(os.Args[2:])); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	setFlags := visitedFlags(fs)

	parsedHeaders, err := parseHeaders(headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	config := scanConfig{}
	if *configPath != "" {
		fileConfig, err := readScanConfigFile(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		config, err = scanConfigFromFile(fileConfig)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	config = mergeCLIConfig(config, scanConfig{
		Args:                 fs.Args(),
		Profile:              *profile,
		Path:                 *path,
		HAR:                  *har,
		SupabaseURL:          *supabaseURL,
		Key:                  *key,
		UserAgent:            *userAgent,
		Headers:              parsedHeaders,
		JSON:                 jsonOut,
		Output:               output,
		OutputJSON:           outputJSON,
		ShowSecrets:          *showSecrets,
		Debug:                *debug,
		MaxAssets:            *maxAssets,
		Yes:                  yes,
		Dynamic:              dynamic,
		DynamicWait:          dynamicWait,
		AttachBrowser:        attachBrowser,
		BrowserDebuggerURL:   *browserDebuggerURL,
		Interactive:          *interactive,
		ActiveStorageTests:   *activeStorage,
		GraphQLIntrospection: *graphqlIntrospection,
		GraphQLSchemaOutput:  *graphqlSchemaOutput,
		Delay:                *delay,
		MaxConcurrency:       *maxConcurrency,
	}, setFlags)
	jsonOut = config.JSON
	output = config.Output
	outputJSON = config.OutputJSON

	opts, err := scanOptions(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if opts.Target.Type == model.TargetURL && !opts.Yes {
		fmt.Println(strings.Join([]string{
			"SupaScope is intended for authorized security testing only.",
			"Only scan applications you own or have permission to test.",
			"By continuing, you confirm that you are authorized to scan this target.",
			"",
			"Pass --yes to run non-interactively.",
		}, "\n"))
		os.Exit(1)
	}

	s := scanner.New()
	result, err := s.Scan(context.Background(), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if output != "" || outputJSON != "" {
		written, err := writeOutputReports(result, output, outputJSON)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, path := range written {
			fmt.Printf("Report written to: %s\n", path)
		}
		return
	}

	rendered, err := renderReport(result, jsonOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(rendered)
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
		if err := os.WriteFile(markdownOutput, []byte(report.Markdown(result)), 0o644); err != nil {
			return nil, err
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

func normalizeScanArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--profile":               true,
		"--config":                true,
		"--path":                  true,
		"--har":                   true,
		"--supabase-url":          true,
		"--key":                   true,
		"--user-agent":            true,
		"--header":                true,
		"--max-assets":            true,
		"--delay":                 true,
		"--dynamic-wait":          true,
		"--wait":                  true,
		"-w":                      true,
		"--browser-debugger-url":  true,
		"--max-concurrency":       true,
		"--output":                true,
		"-o":                      true,
		"--output-json":           true,
		"-oj":                     true,
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

type scanFileConfig struct {
	Target               string            `json:"target"`
	Path                 string            `json:"path"`
	HAR                  string            `json:"har"`
	SupabaseURL          string            `json:"supabaseUrl"`
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
	Dynamic              *bool             `json:"dynamic"`
	DynamicWait          string            `json:"dynamicWait"`
	AttachBrowser        *bool             `json:"attachBrowser"`
	BrowserDebuggerURL   string            `json:"browserDebuggerUrl"`
	Interactive          *bool             `json:"interactive"`
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

func scanConfigFromFile(fileConfig scanFileConfig) (scanConfig, error) {
	config := scanConfig{
		Profile:             fileConfig.Profile,
		Path:                fileConfig.Path,
		HAR:                 fileConfig.HAR,
		SupabaseURL:         fileConfig.SupabaseURL,
		Key:                 fileConfig.Key,
		UserAgent:           fileConfig.UserAgent,
		Headers:             canonicalHeaders(fileConfig.Headers),
		BrowserDebuggerURL:  fileConfig.BrowserDebuggerURL,
		Output:              fileConfig.Output,
		OutputJSON:          fileConfig.OutputJSON,
		GraphQLSchemaOutput: fileConfig.GraphQLSchemaOutput,
	}
	if strings.TrimSpace(fileConfig.Target) != "" {
		config.Args = []string{fileConfig.Target}
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
	if fileConfig.Dynamic != nil {
		config.Dynamic = *fileConfig.Dynamic
	}
	if fileConfig.AttachBrowser != nil {
		config.AttachBrowser = *fileConfig.AttachBrowser
	}
	if fileConfig.DynamicWait != "" {
		dynamicWait, err := time.ParseDuration(fileConfig.DynamicWait)
		if err != nil {
			return scanConfig{}, fmt.Errorf("invalid config dynamicWait %q: %w", fileConfig.DynamicWait, err)
		}
		config.DynamicWait = dynamicWait
	}
	if fileConfig.Interactive != nil {
		config.Interactive = *fileConfig.Interactive
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

func mergeCLIConfig(config scanConfig, cli scanConfig, setFlags map[string]bool) scanConfig {
	if len(cli.Args) > 0 {
		config.Args = cli.Args
		config.Path = ""
		config.HAR = ""
		config.SupabaseURL = ""
	}
	if flagSet(setFlags, "profile") {
		config.Profile = cli.Profile
	}
	if flagSet(setFlags, "path") {
		config.Path = cli.Path
		config.Args = nil
		config.HAR = ""
		config.SupabaseURL = ""
	}
	if flagSet(setFlags, "har") {
		config.HAR = cli.HAR
		config.Args = nil
		config.Path = ""
		config.SupabaseURL = ""
	}
	if flagSet(setFlags, "supabase-url") {
		config.SupabaseURL = cli.SupabaseURL
		config.Args = nil
		config.Path = ""
		config.HAR = ""
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
	if flagSet(setFlags, "max-assets") {
		config.MaxAssets = cli.MaxAssets
	}
	if flagSet(setFlags, "yes", "y") {
		config.Yes = cli.Yes
	}
	if flagSet(setFlags, "dynamic", "d") {
		config.Dynamic = cli.Dynamic
	}
	if flagSet(setFlags, "dynamic-wait", "wait", "w") {
		config.DynamicWait = cli.DynamicWait
	} else if config.DynamicWait == 0 {
		config.DynamicWait = cli.DynamicWait
	}
	if flagSet(setFlags, "attach-browser", "b") {
		config.AttachBrowser = cli.AttachBrowser
	}
	if flagSet(setFlags, "browser-debugger-url") {
		config.BrowserDebuggerURL = cli.BrowserDebuggerURL
	}
	if flagSet(setFlags, "interactive") {
		config.Interactive = cli.Interactive
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
	if flagSet(setFlags, "delay") {
		config.Delay = cli.Delay
	}
	if flagSet(setFlags, "max-concurrency") {
		config.MaxConcurrency = cli.MaxConcurrency
	} else if config.MaxConcurrency == 0 {
		config.MaxConcurrency = cli.MaxConcurrency
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

type scanConfig struct {
	Args                 []string
	Profile              string
	Path                 string
	HAR                  string
	SupabaseURL          string
	Key                  string
	UserAgent            string
	Headers              map[string]string
	JSON                 bool
	Output               string
	OutputJSON           string
	ShowSecrets          bool
	Debug                bool
	MaxAssets            int
	Yes                  bool
	Dynamic              bool
	DynamicWait          time.Duration
	AttachBrowser        bool
	BrowserDebuggerURL   string
	Interactive          bool
	ActiveChecks         bool
	ActiveStorageTests   bool
	GraphQLIntrospection bool
	GraphQLSchemaOutput  string
	Delay                time.Duration
	MaxConcurrency       int
}

func scanOptions(config scanConfig) (model.Options, error) {
	config = applyProfile(config)
	if !validProfile(config.Profile) {
		return model.Options{}, fmt.Errorf("invalid --profile %q: expected passive, active, or deep", config.Profile)
	}

	targets := 0
	if len(config.Args) > 0 && config.Args[0] != "" {
		targets++
	}
	if config.Path != "" {
		targets++
	}
	if config.HAR != "" {
		targets++
	}
	if config.SupabaseURL != "" {
		targets++
	}
	if targets != 1 {
		return model.Options{}, fmt.Errorf("provide exactly one scan target: URL, --path, --har, or --supabase-url")
	}

	var target model.Target
	switch {
	case config.Path != "":
		target = model.Target{Type: model.TargetLocalPath, Value: config.Path}
	case config.HAR != "":
		target = model.Target{Type: model.TargetHAR, Value: config.HAR}
	case config.SupabaseURL != "":
		target = model.Target{Type: model.TargetSupabaseProject, Value: config.SupabaseURL}
	default:
		target = model.Target{Type: model.TargetURL, Value: config.Args[0]}
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
		Interactive:          config.Interactive,
		ActiveChecks:         config.ActiveChecks,
		ActiveStorageTests:   config.ActiveStorageTests,
		GraphQLIntrospection: config.GraphQLIntrospection,
		GraphQLSchemaOutput:  config.GraphQLSchemaOutput,
		Delay:                config.Delay,
		MaxConcurrency:       config.MaxConcurrency,
	}, nil
}

func applyProfile(config scanConfig) scanConfig {
	if config.Profile == "" {
		config.Profile = "passive"
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
	if config.AttachBrowser && config.BrowserDebuggerURL == "" {
		config.BrowserDebuggerURL = defaultBrowserDebuggerURL
	}
	if config.BrowserDebuggerURL != "" || config.Interactive {
		config.Dynamic = true
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
