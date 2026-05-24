# SupaScope

SupaScope is an authorized Supabase security reconnaissance scanner for detecting exposed keys, public storage buckets, risky anon access, weak RLS assumptions, runtime Supabase API usage, and frontend configuration leaks.

## Status

Go implementation in progress. The current implementation supports static public URL scans, local folder scans, recursive same-origin asset discovery, adjacent source map probing, source map `sourcesContent` scanning, Supabase URL/key/endpoint detection, key classification, safe JWT metadata reporting, secret masking, active service checks, optional GraphQL introspection checks, JSON reports, and Markdown reports.

## Usage

```bash
go test ./...
go run ./cmd/supascope scan --path . --json
go run ./cmd/supascope scan https://example.com --yes
go run ./cmd/supascope scan https://example.com --yes --profile active --output-json report.json
go run ./cmd/supascope scan https://example.com --yes --dynamic --dynamic-wait 30s --json
go run ./cmd/supascope scan https://example.com -y -d -w 30s -j
go run ./cmd/supascope scan https://example.com --yes -o report.md --output-json report.json
go run ./cmd/supascope scan --config supascope.config.json
go run ./cmd/supascope scan --har network.har --json
go run ./cmd/supascope scan --supabase-url https://project-ref.supabase.co --key sb_publishable_xxx --profile deep --graphql-schema-output schema.txt
```

Public URL scans display an authorization notice unless `--yes` is provided.

## Targets

Provide exactly one target:

- `https://example.com` scans a public URL and recursively fetches same-origin assets.
- `--path .` scans a local folder.
- `--har network.har` scans an exported HTTP Archive file offline.
- `--supabase-url https://project-ref.supabase.co` scans a known Supabase project URL.

Passive URL scans inspect fetched public frontend assets. If referenced, adjacent, or framework-inferred source maps are reachable, SupaScope parses `sourcesContent` and reports evidence against the original source entry inside the map. Source map scanning uses conservative early-stop limits so very large maps do not dominate passive scans.

Framework source map discovery includes same-origin chunk references from common build directories such as `_next/static`, `_nuxt`, `_astro`, `_app/immutable`, `assets`, `build`, `static`, `packs`, `js`, and `css`. For hashed bundle names such as `index-Dg_4Nfjf.js`, SupaScope also probes conservative hash-stripped map candidates such as `index.js.map` within the same asset directory.

If a fetched asset appears blocked by a WAF/CDN such as Cloudflare, Akamai, Fastly, Sucuri, Imperva, or a generic challenge page, SupaScope adds an informational scan coverage finding. This means passive results may be incomplete for blocked assets.

## Output

- Default output is Markdown written to stdout.
- `--json` writes JSON to stdout instead of Markdown.
- `--output file` or `-o file` writes a Markdown report to a file.
- `--output-json file` or `-oj file` writes a JSON report to a file.
- `--output report.md --output-json report.json` writes both report formats from one scan.
- `--unsafe-show-secrets` prints full discovered secrets in reports. Use only in trusted local environments.

## Scan Controls

- `--profile passive` runs static/local scanning only. This is the default.
- `--profile active` enables safe active service probes.
- `--profile deep` enables active service probes and GraphQL introspection.
- `--dynamic` loads public URL targets in a browser with `chromedp` and captures observed network traffic.
- `--dynamic-wait duration` controls how long the browser stays open after page load to observe network traffic. Use longer windows for login-gated apps.
- `--attach-browser` attaches dynamic scanning to Chrome on `http://127.0.0.1:9222`, useful for CAPTCHA, OAuth, wallet, and SSO flows.
- `--browser-debugger-url url` attaches dynamic scanning to a custom Chrome DevTools URL.
- `--interactive` runs the dynamic browser scan with a visible browser window.
- Short aliases are available for common dynamic scans: `-y`, `-j`, `-d`, `-b`, and `-w`.
- `--yes` confirms authorization for public URL scans.
- `--user-agent value` sets the User-Agent for remote HTTP requests.
- `--header "Name: value"` adds a remote HTTP request header. Repeat it for multiple headers.
- `--max-assets n` limits recursive same-origin asset fetching during URL scans.
- `--delay duration` pauses between remote request launches, for example `500ms`.
- `--max-concurrency n` limits concurrent remote requests during URL scans and active probes.
- `--config file` loads reusable scan settings from a JSON config file. Explicit CLI flags override config file values.
- `--debug` prints request diagnostics to stderr.
 - When no headers are provided, SupaScope applies a set of browser-like default request headers (including a modern User-Agent and navigation headers) to improve passive fetch coverage and reduce false positives from WAF/CDN challenge pages. These defaults can be overridden via `--user-agent` or `--header`.

## Config File

Use `--config supascope.config.json` to load reusable scan settings. CLI flags override values from the config file.

```json
{
  "target": "https://example.com",
  "profile": "active",
  "yes": true,
  "maxAssets": 70,
  "dynamic": true,
  "dynamicWait": "30s",
  "attachBrowser": true,
  "headers": {
    "Accept-Language": "en-US,en;q=0.9"
  },
  "output": "report.md",
  "outputJson": "report.json",
  "delay": "500ms",
  "maxConcurrency": 4
}
```

Supported target fields are `target`, `path`, `har`, and `supabaseUrl`. Provide exactly one target after CLI overrides are applied.

## HAR Import

Use `--har network.har` to scan an exported browser network log without visiting the target. HAR scans inspect request URLs, request headers, request bodies, and text response bodies for Supabase URLs, service endpoints, and keys. Secrets are masked in reports by default.

## Key And JWT Reporting

Detected secrets are masked in discoveries, findings, and evidence snippets. JWT-like Supabase keys are decoded only for safe, non-secret metadata used in report evidence:

- role
- issuer
- expiry timestamp
- Supabase project ref when inferable

JWT metadata is decoded without signature verification and is used only to classify/report exposed artifacts. Raw token values are not printed in reports unless `--unsafe-show-secrets` is passed.

Pass `--unsafe-show-secrets` only when you explicitly need raw values in the report output. Evidence snippets remain shortened for readability.

Database URL-like values are classified more conservatively when they look like templates, placeholders, examples, or mock data. Concrete database URLs with user, password, host, and database remain critical findings.

## Active Checks

Active checks are disabled by default and must be explicitly enabled:

```bash
go run ./cmd/supascope scan https://example.com --yes --profile active
```

Current active checks perform safe service probes for REST, Auth, Storage, Realtime, Edge Functions, and GraphQL. GraphQL uses a POST probe with `__typename`; it does not test introspection.

- `--profile active` enables active service probes.
- `--active-storage-tests` changes the storage probe to bucket listing and should only be used when authorized.

## GraphQL Introspection

GraphQL introspection is disabled by default and must be explicitly enabled:

```bash
go run ./cmd/supascope scan --supabase-url https://project-ref.supabase.co --key sb_publishable_xxx --profile deep
```

- `--profile deep` enables GraphQL introspection and active service probes.
- `--graphql-introspection` sends an explicit `__schema` introspection query to `/graphql/v1`.
- `--graphql-schema-output schema.txt` writes the raw GraphQL response to a text file and implies GraphQL introspection, including error responses when no schema is returned.
- If introspection succeeds, SupaScope generates a medium-severity finding because schema exposure can help attackers map available GraphQL types and operations.
- If the endpoint returns GraphQL errors or no schema, SupaScope generates an informational finding with the error message when available.
- Use this only for projects you are authorized to test.

## Dynamic Browser Scanning

Dynamic browser scanning is enabled with `--dynamic` for public URL targets. It uses `chromedp` to load the page, captures request URLs, request headers, request bodies when available, response URLs, response headers, and available text response bodies, then runs the same Supabase artifact detection used by static and HAR scans.

Use `--interactive` with `--dynamic --dynamic-wait 60s` or longer to run with a visible browser window for sites that need manual login or navigation. Session data is not persisted by SupaScope.

For Cloudflare CAPTCHA, OAuth, wallet, or SSO flows, prefer attaching to a normal Chrome session you control. Start Chrome with remote debugging and a dedicated profile, then run SupaScope against that browser:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="$env:TEMP\supascope-chrome"
go run ./cmd/supascope scan https://example.com --yes --dynamic --browser-debugger-url http://127.0.0.1:9222 --dynamic-wait 120s --json
```

Complete CAPTCHA/OAuth/login in that browser while SupaScope observes network traffic. SupaScope does not bypass CAPTCHA or OAuth protections.

Short form:

```powershell
go run ./cmd/supascope scan https://example.com --yes --attach-browser --wait 120s --json
```

Shortest common form:

```powershell
go run ./cmd/supascope scan https://example.com -y -b -w 120s -j
```
