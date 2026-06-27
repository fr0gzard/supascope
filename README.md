# SupaScope

Authorized Supabase security reconnaissance scanner. Detects exposed keys, public storage buckets, risky anon access, weak RLS assumptions, runtime Supabase API usage, and frontend configuration leaks.

## Features

- **Static URL scans** — fetches public frontend assets, recursively discovers same-origin JS/CSS, parses source maps
- **Local folder scans** — scans build output or source directories
- **HAR import** — offline scanning of exported browser network logs
- **Live browser sessions** — launches Chrome with your existing profile (logins preserved), captures HTTP + WebSocket traffic, auto-completes on idle
- **Dynamic headless scans** — headless Chrome network capture for public pages
- **Key classification** — publishable keys, secret keys, legacy JWT anon/service-role keys, database URLs
- **Safe JWT metadata** — decodes role, issuer, expiry, and project ref without signature verification
- **Secret masking** — all secrets masked by default; `--unsafe-show-secrets` for raw values
- **Active service probes** — REST, Auth, Storage, Realtime, Edge Functions, GraphQL (read-only)
- **Auth settings inspection** — reports signup state, OAuth providers, anonymous sign-in
- **Env leak detection** — probes common config paths (`.env`, `env.js`, `config.js`, etc.)
- **REST table discovery** — enumerates tables via `/rest/v1/`, tests anonymous read/write access
- **Storage bucket checks** — lists buckets, checks public access and object listing
- **Browser storage capture** — extracts cookies and localStorage in live mode for credential leaks
- **GraphQL introspection** — optional `__schema` query with schema output to file
- **WAF/CDN detection** — identifies Cloudflare, Akamai, Fastly, Sucuri, Imperva, Vercel blocks
- **JSON + Markdown + HTML reports** — stdout or file output; auto-detect `.html` extension

## Quick Start

```bash
# Build
go build ./cmd/supascope

# Scan a public URL
./supascope scan https://example.com --yes

# Scan a local folder
./supascope scan --path ./dist --json

# Scan a login-gated app (launches Chrome with your logins)
./supascope scan https://example.com --yes --live

# Scan from a HAR file
./supascope scan --har network.har --json

# Scan a public URL with HTML report
./supascope scan https://example.com --yes -o report.html

# Scan a known Supabase project with all active checks
./supascope scan --supabase-url https://project.supabase.co --key sb_publishable_xxx --profile deep -o report.html
```

## Scan Modes

| Mode | Command | Use Case |
|------|---------|----------|
| Static URL | `scan https://example.com --yes` | Public pages, frontend asset scanning |
| Local folder | `scan --path ./dist` | Build output, source code |
| HAR import | `scan --har network.har` | Offline browser network log analysis |
| Live browser | `scan https://example.com --yes --live` | Login-gated apps (uses your Chrome profile) |
| Headless dynamic | `scan https://example.com --yes -d` | Public pages with runtime traffic |
| Attach browser | `scan https://example.com --yes --attach` | Advanced: attach to Chrome with debugging port |
| Supabase project | `scan --supabase-url URL --key KEY` | Direct project probing |

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--yes` | `-y` | Confirm authorization for public URL scans |
| `--json` | `-j` | Print JSON report instead of Markdown |
| `--output file` | `-o` | Write report to file (`.md` or `.html` auto-detected) |
| `--output-json file` | `-oj` | Write JSON report to file |
| `--profile` | | `passive` (default), `active`, or `deep` |
| `--live` | | Launch Chrome with your profile, idle-based capture |
| `--dynamic` | `-d` | Headless dynamic browser scan |
| `--attach` | `-b` | Attach to Chrome at `http://127.0.0.1:9222` |
| `--wait duration` | `-w` | Browser observation window / max timeout for live |
| `--idle-timeout` | | Idle auto-completion for live captures (default 20s) |
| `--path dir` | | Local folder to scan |
| `--har file` | | HAR file to scan |
| `--supabase-url url` | | Known Supabase project URL |
| `--key key` | | Supabase anon or publishable key |
| `--config file` | | Load settings from JSON config file |
| `--user-agent` | | Override User-Agent for remote requests |
| `--header "Name: value"` | | Add a request header (repeatable) |
| `--max-assets n` | | Limit recursive asset fetching (default 50) |
| `--delay duration` | | Delay between remote requests |
| `--max-concurrency n` | | Max concurrent requests (default 4) |
| `--graphql-introspection` | | Enable GraphQL `__schema` introspection |
| `--graphql-schema-output file` | | Write GraphQL response to file |
| `--active-storage-tests` | | Enable storage bucket listing probe |
| `--unsafe-show-secrets` | | Print full secrets in reports |
| `--debug` | | Print request diagnostics to stderr |

## Live Browser Sessions

For login-gated apps, `--live` is the recommended approach. SupaScope auto-launches Chrome with your existing user profile — no manual `--remote-debugging-port` needed.

```bash
./supascope scan https://example.com --yes --live
```

1. SupaScope detects your Chrome installation and user profile
2. If Chrome is running, you'll be asked to close it first
3. Chrome opens with your existing logins — use the app normally
4. SupaScope captures all HTTP + WebSocket traffic (including Supabase Realtime)
5. After 20s of no network activity, capture auto-completes and the report prints
6. Max safety timeout: 10 min (override with `--wait`)

Override Chrome detection with environment variables:
- `SUPASCOPE_CHROME_PATH` — path to Chrome/Chromium executable
- `SUPASCOPE_CHROME_PROFILE` — path to Chrome user data directory

## Config File

```json
{
  "target": "https://example.com",
  "profile": "active",
  "yes": true,
  "live": true,
  "idleTimeout": "20s",
  "maxAssets": 70,
  "headers": { "Accept-Language": "en-US,en;q=0.9" },
  "output": "report.md",
  "outputJson": "report.json",
  "delay": "500ms",
  "maxConcurrency": 4
}
```

CLI flags override config file values. Supported target fields: `target`, `path`, `har`, `supabaseUrl`.

## Safety

- SupaScope is for **authorized testing only**. Only scan apps you own or have permission to test.
- Public URL scans display an authorization notice unless `--yes` is passed.
- All secrets are masked by default. Use `--unsafe-show-secrets` only in trusted environments.
- Active checks require explicit `--profile active` or `--profile deep`.
- The scanner does not exploit vulnerabilities, dump database records, brute-force endpoints, or bypass authentication.

## Tech

- **Language:** Go 1.26
- **Browser automation:** chromedp
- **License:** MIT
