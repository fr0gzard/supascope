# SupaScope Progress

Last updated: 2026-04-29

## Current State

SupaScope is a Go CLI for authorized Supabase reconnaissance. The current implementation supports:

- Local folder scans.
- Static public URL scans.
- Recursive same-origin asset discovery, including Next.js `_next/static` chunks.
- Source map parsing for reachable `.map` files with `sourcesContent` scanning.
- Conservative source map early stopping by source count, scanned bytes, per-source bytes, and discovery count.
- Final URL handling after redirects for correct same-origin asset resolution.
- Static WAF/CDN block detection for common Cloudflare, Akamai, Fastly, Sucuri, Imperva, Vercel, and generic challenge fingerprints.
- Informational scan coverage findings when WAF/CDN blocking may have limited passive scan coverage.
- Supabase project URL, endpoint, publishable key, secret key, legacy JWT, and database URL detection.
- Key classification for publishable keys, secret keys, legacy anon JWTs, legacy service-role JWTs, database URLs, and unknown JWTs.
- Conservative database URL classification for templates, placeholders, examples, and mock/dummy contexts.
- Safe JWT report metadata for role, issuer, expiry, and project ref when inferable.
- Secret masking in reports.
- Explicit unsafe opt-in for raw report values with `--unsafe-show-secrets`.
- JSON and Markdown reports.
- Custom remote request controls:
  - `--user-agent`
  - repeated `--header "Name: value"`
  - `--max-assets n`
  - `--debug`
 - Default browser-like request headers are applied when no headers are provided. These include a modern User-Agent and common navigation headers to reduce WAF/edge blocking false positives. Use `--user-agent` or repeated `--header` to override defaults.
- Read-only active service checks behind `--profile active`.
- Informational findings generated from active service statuses.
- Optional storage bucket listing probe behind `--active-storage-tests`.
- Optional GraphQL introspection checks behind `--graphql-introspection`.
- Optional raw GraphQL response output with `--graphql-schema-output`, including error responses when no schema is returned.
- Informational GraphQL introspection findings when the endpoint responds but returns errors or no schema.
- Scan profiles for common flag bundles:
  - `--profile passive`
  - `--profile active`
  - `--profile deep`

## Active Check Behavior

Active checks are explicitly gated by `--profile active` or `--profile deep`. They use discovered or provided Supabase project URLs and an anon-style key when available.

Current active probes:

- `GET /rest/v1/`
- `GET /auth/v1/settings`
- `GET /storage/v1/`
- `GET /storage/v1/bucket` when `--active-storage-tests` is enabled
- `GET /realtime/v1/`
- `GET /functions/v1/`
- `POST /graphql/v1` with a minimal read-only query:

```json
{"query":"query SupaScopeProbe { __typename }"}
```

HTTP statuses map to service states:

- `2xx` -> `reachable`
- `401` -> `unauthorized`
- `403` -> `forbidden`
- `404` -> `not_found`
- `429` or `503` -> `blocked`
- other/network errors -> `unknown`

Active probe results are reported in `services` and also generate informational `service_status` findings for reachable, authorization-gated, or blocked services. These findings explain exposure context only; they do not claim a vulnerability by themselves.

GraphQL active probing currently uses a safe POST query for `__typename`. GraphQL introspection testing is separate and only runs when `--graphql-introspection` is explicitly enabled.

## Recent Real-Site Test

Target tested with authorization:

```text
https://sectors.app
```

Useful command shape:

```powershell
go run ./cmd/supascope scan https://sectors.app --yes --json --profile active --max-assets 70 --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" --header "Accept-Language: en-US,en;q=0.9,id;q=0.8" --header "Cache-Control: no-cache" --header "Pragma: no-cache" --header "Sec-Fetch-Dest: document" --header "Sec-Fetch-Mode: navigate" --header "Sec-Fetch-Site: same-origin" --header "Sec-Fetch-User: ?1" --header "Upgrade-Insecure-Requests: 1"
```

Observed active service result:

```json
{
  "rest": "unauthorized",
  "auth": "reachable",
  "storage": "not_found",
  "realtime": "forbidden",
  "functions": "not_found",
  "graphql": "reachable"
}
```

The scanner discovered a Supabase project URL in a Next.js chunk:

```text
https://sectors.app/_next/static/chunks/1486-335ec3ea21efa9ee.js
```

The project URL was:

```text
https://rfiycxgjbnkefczvbosm.supabase.co
```

## Debug And Snippets

`--debug` was reduced to summary-level output:

- response metadata
- root asset count
- skipped fetches
- active check responses
- final totals

It no longer prints every queued/fetched asset.

Evidence snippets are capped:

- max 100 words
- max 800 runes for minified single-line bundles
- secrets are masked before truncation
- `--unsafe-show-secrets` reveals full detected values in report fields, but snippets remain capped.

## Tests

Current verification command:

```powershell
go test ./...
```

This passes as of this progress note.

## Known Gaps / Next Work

High-value next steps:

- Add config file support for reusable scan settings.
- Improve source map heuristics for unreferenced maps.
- Add dynamic browser network discovery later, probably with `chromedp` or Playwright.
- Add HAR import support.
- Add rate limiting/pacing options, e.g. `--delay` and `--max-concurrency`.
