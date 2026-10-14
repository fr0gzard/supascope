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
- **Active service probes** — REST, Auth, Storage, Realtime, Edge Functions, GraphQL. Write-access probes insert a single null row per writable table to confirm the finding.
- **Auth settings inspection** — reports signup state, OAuth providers, anonymous sign-in
- **Env leak detection** — probes common config paths (`.env`, `env.js`, `config.js`, etc.)
- **REST table discovery** — enumerates tables via `/rest/v1/`, tests anonymous read/write access
- **Storage bucket checks** — lists buckets, checks public access and object listing
- **RLS isolation testing** — multi-identity access matrix (anon + authenticated users), cross-user data leak detection
- **Browser storage capture** — extracts cookies and localStorage in live mode for credential leaks
- **GraphQL introspection** — optional `__schema` query with schema output to file
- **WAF/CDN detection** — identifies Cloudflare, Akamai, Fastly, Sucuri, Imperva, Vercel blocks
- **JSON + Markdown + HTML reports** — stdout or file output; auto-detect `.html` extension

## Quick Start

```bash
# Build
go build ./cmd/supascope

# Scan a public URL
./supascope scan url https://example.com --yes

# Scan a local folder
./supascope scan folder ./dist --json

# Scan a login-gated app (launches Chrome with your logins)
./supascope scan browser https://example.com --yes --headed

# Scan from a HAR file
./supascope scan har network.har --json

# Scan a public URL with HTML report
./supascope scan url https://example.com --yes -o report.html

# Scan a known Supabase project with all active checks
./supascope scan project --supabase-url https://project.supabase.co --key sb_publishable_xxx --profile deep --yes -o report.html
```

## Scan Modes

| Mode | Command | Use Case |
|------|---------|----------|
| Static URL | `scan url <target> --yes` | Public pages, frontend asset scanning |
| Local folder | `scan folder ./dist` | Build output, source code |
| HAR import | `scan har network.har` | Offline browser network log analysis |
| Headless browser | `scan browser <target> --yes` | Public pages with runtime traffic |
| Headed browser | `scan browser <target> --yes --headed` | Login-gated apps (uses your Chrome profile) |
| Attach browser | `scan browser <target> --yes --attach` | Attach to Chrome with remote debugging |
| Supabase project | `scan project --supabase-url URL --key KEY --yes` | Direct project probing |

## Flags

Shared flags (every subcommand):

| Flag | Short | Description |
|------|-------|-------------|
| `--config file` | | Load settings from JSON config file |
| `--profile` | | `passive` (default), `active`, or `deep` |
| `--yes` | `-y` | Confirm authorization (required for remote/active scans) |
| `--json` | `-j` | Print JSON report instead of Markdown |
| `--output file` | `-o` | Write report to file (`.md` or `.html` auto-detected) |
| `--output-json file` | `-oj` | Write JSON report to file |
| `--key key` | | Supabase anon or publishable key |
| `--auth-token jwt` | | Authenticated user JWT for RLS testing (user A) |
| `--auth-token-2 jwt` | | Second user JWT for cross-user RLS isolation testing |
| `--unsafe-show-secrets` | | Print full secrets in reports |
| `--debug` | | Print request diagnostics to stderr |
| `--user-agent` | | Override User-Agent for remote requests |
| `--header "Name: value"` | | Add a request header (repeatable) |

`scan browser` flags:

| Flag | Short | Description |
|------|-------|-------------|
| `--headed` | | Launch Chrome with your profile, idle-based capture |
| `--attach` | | Attach to Chrome at `http://127.0.0.1:9222` |
| `--attach-url url` | | Chrome DevTools URL to attach to |
| `--wait duration` | `-w` | Browser observation window / max timeout for headed/attach |

`scan project` flags:

| Flag | Description |
|------|-------------|
| `--supabase-url url` | Known Supabase project URL (required) |
| `--active-storage-tests` | Enable storage bucket listing probe |
| `--graphql-introspection` | Enable GraphQL `__schema` introspection |
| `--graphql-schema-output file` | Write GraphQL response to file |

Request tuning (`delay`, `max-assets`, `max-concurrency`, `idle-timeout`) is
configured via the JSON config file only.

## Browser Sessions

For login-gated apps, `scan browser --headed` is the recommended approach. SupaScope auto-launches Chrome with your existing user profile — no manual `--remote-debugging-port` needed.

```bash
./supascope scan browser https://example.com --yes --headed
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

The subcommand is always given on the CLI; the config file supplies values
for it (target, profile, headers, tuning, browser mode, ...).

```json
{
  "target": "https://example.com",
  "profile": "active",
  "yes": true,
  "browserMode": "headed",
  "idleTimeout": "20s",
  "maxAssets": 70,
  "headers": { "Accept-Language": "en-US,en;q=0.9" },
  "output": "report.md",
  "outputJson": "report.json",
  "delay": "500ms",
  "maxConcurrency": 4
}
```

CLI flags override config file values. Supported target fields: `target`
(plus legacy `path`/`har` aliases), and `supabaseUrl` for `scan project`.

## Safety

- SupaScope is for **authorized testing only**. Only scan apps you own or have permission to test.
- Remote scans (`url`, `browser`, `project`) and any active/deep profile scan display an authorization notice unless `--yes` is passed.
- All secrets are masked by default. Use `--unsafe-show-secrets` only in trusted environments.
- Active checks require explicit `--profile active` or `--profile deep`.
- The scanner does not exploit vulnerabilities, dump database records, brute-force endpoints, or bypass authentication.
- Write-access probes are minimally mutating: to confirm an INSERT finding, the scanner inserts a single row of NULLs into the writable table. Run them only against targets you are authorized to modify.

## Tech

- **Language:** Go 1.26
- **Browser automation:** chromedp
- **License:** MIT
