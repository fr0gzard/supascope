package engine

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"supascope/internal/model"
)

type EnvLeakOptions struct {
	UserAgent string
	Headers   map[string]string
	Key       string
	Debug     bool
}

var envProbePaths = []string{
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.development",
	"/env.js",
	"/config.js",
	"/config.json",
	"/runtime-config.json",
	"/runtimeConfig.json",
	"/manifest.json",
}

func ProbeEnvLeaks(ctx context.Context, baseURL string, opts EnvLeakOptions) []model.Discovery {
	// Don't follow redirects: a /.env that 302s to a 200 login page is not
	// an exposed config file.
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var discoveries []model.Discovery

	for _, path := range envProbePaths {
		target := baseURL + path
		if err := ctx.Err(); err != nil {
			return discoveries
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		applyRequestHeaders(req, opts.UserAgent, opts.Headers)
		if opts.Key != "" {
			req.Header.Set("apikey", opts.Key)
			req.Header.Set("Authorization", "Bearer "+opts.Key)
		}

		resp, err := client.Do(req)
		if err != nil {
			debugEnvLeak(opts.Debug, "env probe failed: url=%s err=%v", target, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			debugEnvLeak(opts.Debug, "env probe hit: url=%s status=%d", target, resp.StatusCode)
			ev := model.Evidence{Source: "env_probe", URL: target, Detail: fmt.Sprintf("found at %s (HTTP %d)", target, resp.StatusCode)}
			discoveries = append(discoveries, model.Discovery{
				Type:     "config_file",
				Value:    target,
				Source:   "env_probe",
				Evidence: &ev,
			})
		}
	}

	return discoveries
}

func EnvLeakFindings(discoveries []model.Discovery) []model.Finding {
	var findings []model.Finding
	for _, discovery := range discoveries {
		if discovery.Type != "config_file" {
			continue
		}
		ev := evidenceOrDefault(discovery)
		findings = append(findings, model.Finding{
			ID:             "SUPA-ENV-INFO-001",
			Title:          "Public configuration file detected",
			Severity:       "info",
			Category:       "env_exposure",
			Evidence:       ev,
			Impact:         "A configuration or environment file is publicly accessible and may expose Supabase credentials, API keys, or environment variables.",
			Recommendation: "Remove public access to this file or restrict it at the web server/edge level.",
			Confidence:     "high",
		})
	}
	return findings
}

func evidenceOrDefault(discovery model.Discovery) model.Evidence {
	if discovery.Evidence != nil {
		return *discovery.Evidence
	}
	return model.Evidence{Source: discovery.Source, URL: discovery.Value}
}

func debugEnvLeak(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
