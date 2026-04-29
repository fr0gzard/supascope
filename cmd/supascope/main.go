package main

import (
	"context"
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

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: supascope scan [target] [--profile passive|active|deep] [--path dir] [--supabase-url url] [--key key] [--json] [--output report.md|report.json] [--yes]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var headers headerFlags
	profile := fs.String("profile", "passive", "scan profile: passive, active, or deep")
	path := fs.String("path", "", "local folder to scan")
	supabaseURL := fs.String("supabase-url", "", "known Supabase project URL")
	key := fs.String("key", "", "Supabase anon or publishable key")
	userAgent := fs.String("user-agent", "", "User-Agent header for remote HTTP requests")
	fs.Var(&headers, "header", "additional header for remote HTTP requests, formatted as 'Name: value'")
	jsonOut := fs.Bool("json", false, "print JSON report")
	output := fs.String("output", "", "write report to file; respects --json")
	debug := fs.Bool("debug", false, "print remote request diagnostics to stderr")
	maxAssets := fs.Int("max-assets", 0, "maximum same-origin assets to fetch during URL scans")
	yes := fs.Bool("yes", false, "confirm authorization notice for public URL scans")
	dynamic := fs.Bool("dynamic", false, "dynamic browser scan; planned for chromedp phase")
	interactive := fs.Bool("interactive", false, "interactive dynamic scan; planned for chromedp phase")
	activeStorage := fs.Bool("active-storage-tests", false, "enable active storage tests")
	graphqlIntrospection := fs.Bool("graphql-introspection", false, "enable GraphQL introspection probe")
	graphqlSchemaOutput := fs.String("graphql-schema-output", "", "write GraphQL introspection response to a text file")
	delay := fs.Duration("delay", 0, "delay between active probes (e.g. 500ms)")
	maxConcurrency := fs.Int("max-concurrency", 4, "maximum concurrent active probes")

	if err := fs.Parse(normalizeScanArgs(os.Args[2:])); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	parsedHeaders, err := parseHeaders(headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	opts, err := scanOptions(scanConfig{
		Args:                 fs.Args(),
		Profile:              *profile,
		Path:                 *path,
		SupabaseURL:          *supabaseURL,
		Key:                  *key,
		UserAgent:            *userAgent,
		Headers:              parsedHeaders,
		JSON:                 *jsonOut,
		Output:               *output,
		Debug:                *debug,
		MaxAssets:            *maxAssets,
		Yes:                  *yes,
		Dynamic:              *dynamic,
		Interactive:          *interactive,
		ActiveStorageTests:   *activeStorage,
		GraphQLIntrospection: *graphqlIntrospection,
		GraphQLSchemaOutput:  *graphqlSchemaOutput,
		Delay:                *delay,
		MaxConcurrency:       *maxConcurrency,
	})
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

	rendered, err := renderReport(result, *jsonOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(rendered), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("Report written to: %s\n", *output)
		return
	}

	fmt.Print(rendered)
}

func renderReport(result model.Report, jsonOut bool) (string, error) {
	if jsonOut {
		return report.JSON(result)
	}
	return report.Markdown(result), nil
}

func normalizeScanArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--profile":               true,
		"--path":                  true,
		"--supabase-url":          true,
		"--key":                   true,
		"--user-agent":            true,
		"--header":                true,
		"--max-assets":            true,
		"--delay":                 true,
		"--max-concurrency":       true,
		"--output":                true,
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

type scanConfig struct {
	Args                 []string
	Profile              string
	Path                 string
	SupabaseURL          string
	Key                  string
	UserAgent            string
	Headers              map[string]string
	JSON                 bool
	Output               string
	Debug                bool
	MaxAssets            int
	Yes                  bool
	Dynamic              bool
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
	if config.SupabaseURL != "" {
		targets++
	}
	if targets != 1 {
		return model.Options{}, fmt.Errorf("provide exactly one scan target: URL, --path, or --supabase-url")
	}

	var target model.Target
	switch {
	case config.Path != "":
		target = model.Target{Type: model.TargetLocalPath, Value: config.Path}
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
		Yes:                  config.Yes,
		Dynamic:              config.Dynamic,
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
