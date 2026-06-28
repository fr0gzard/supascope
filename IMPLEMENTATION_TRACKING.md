# SupaScope Implementation Tracker

Last updated: 2026-06-27

## Completed

### Core Scanning
- [x] Static URL scans with recursive asset discovery
- [x] Local folder scans (detects `.env` files)
- [x] HAR import
- [x] Dynamic browser scanning with chromedp
- [x] Live browser sessions with idle auto-completion
- [x] WebSocket/Realtime capture

### Artifact Detection
- [x] Supabase URL discovery (`supabase_url`, `wss://`)
- [x] Key extraction and classification (publishable, secret, JWT, database URL)
- [x] Secret masking and exposure controls
- [x] Service endpoint detection (`/rest/v1/`, `/auth/v1/`, `/storage/v1/`, etc.)

### Active Probing
- [x] Service probe (REST, Auth, Storage, Realtime, Functions, GraphQL)
- [x] GraphQL introspection with schema output
- [x] WAF/CDN block detection
- [x] Source map parsing and content scanning

### Authentication & Configuration
- [x] **Auth settings inspection** — parses `/auth/v1/settings`, reports signup state, OAuth providers, anonymous sign-in, email auto-confirm settings
- [x] **Env leak detection** — probes common env/config paths (`.env`, `env.js`, `config.js`, `runtime-config.json`) for URL and project targets

### Data Access Checks
- [x] **REST table discovery** — parses `/rest/v1/` OpenAPI response, extracts table names
- [x] **Anonymous read/write access checks** — probes each table for read (`GET ?limit=1`) and write (`POST`) access, generates severity-based findings (critical/high)
- [x] **Storage bucket enumeration** — lists buckets via `/storage/v1/bucket`, checks public access, tests object listing per bucket
- [x] **RLS isolation testing** — multi-identity access matrix (anon + 2 auth users), cross-user row ID comparison, leak detection (critical), isolation verification (info)

### Browser Integration
- [x] **Cookie/localStorage inspection** — captures `document.cookie` and `localStorage` via chromedp in live mode, scans for Supabase artifacts
- [x] Flag consolidation: `--live`, `--dynamic/-d`, `--attach/-b`, `--wait/-w`, `--idle-timeout`
- [x] Idle-based auto-completion (20s default)
- [x] Chrome profile reuse for preserved logins

### Output & Reporting
- [x] JSON report (`--output-json`)
- [x] Markdown report (`--output`)
- [x] **HTML report** — self-contained single-file with severity colors, collapsible evidence, summary table, service status grid; auto-detected by `.html` extension

### Verification
- [x] Auth settings tests: parsing, findings generation, empty features
- [x] Env leak tests: path probing, detection, findings
- [x] REST table tests: OpenAPI parsing, access probing, findings severity
- [x] Storage bucket tests: bucket listing, public access, findings
- [x] All existing tests pass (44 tests across 5 packages)

## Implementation Details

### Files Created/Modified
| File | Change |
|------|--------|
| `internal/engine/active.go` | Added `ProbeAuthSettings`, `parseAuthSettings`, `AuthSettingsFindings` |
| `internal/engine/active_test.go` | Added 5 auth settings tests |
| `internal/engine/envleak.go` | New — `ProbeEnvLeaks`, `EnvLeakFindings` |
| `internal/engine/envleak_test.go` | New — 3 env leak tests |
| `internal/engine/restcheck.go` | New — `ProbeRestTables`, `RestAccessFindings`, table access probing |
| `internal/engine/restcheck_test.go` | New — 3 REST table tests |
| `internal/engine/storagecheck.go` | New — `ProbeStorageBuckets`, `StorageBucketFindings` |
| `internal/engine/storagecheck_test.go` | New — 2 storage bucket tests |
| `internal/engine/dynamic.go` | Added `captureBrowserStorage` for cookie/localStorage in live mode |
| `internal/scanner/scanner.go` | Added `envLeakChecks`, `authSettingsFindings`, `restTableAccessFindings`, `storageBucketFindings` integrations |
| `internal/report/html.go` | New — `WriteHTML` with dark-themed, self-contained HTML output |
| `cmd/supascope/main.go` | Auto-detection of `.html` extension in `writeOutputReports` |
| `IMPLEMENTATION_TRACKING.md` | This file — progress log |
| `README.md` | Updated with new features |

## Remaining (Future)

- [ ] SARIF export for GitHub Code Scanning
- [ ] CI/CD integration (GitHub Action)
- [ ] Authenticated two-user RLS testing
- [ ] Edge Function authorization testing
- [ ] Realtime policy checks
- [ ] Web dashboard
- [ ] Baseline/diff mode