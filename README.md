# SupaScope

SupaScope is an authorized Supabase security reconnaissance scanner for detecting exposed keys, public storage buckets, risky anon access, weak RLS assumptions, runtime Supabase API usage, and frontend configuration leaks.

## Status

Go implementation in progress. The current implementation supports static public URL scans, local folder scans, recursive same-origin asset discovery, source map `sourcesContent` scanning, Supabase URL/key/endpoint detection, key classification, safe JWT metadata reporting, secret masking, active service checks, optional GraphQL introspection checks, JSON reports, and Markdown reports.

## Usage

```bash
go test ./...
go run ./cmd/supascope scan --path . --json
go run ./cmd/supascope scan https://example.com --yes
go run ./cmd/supascope scan https://example.com --yes --profile active --json --output report.json
go run ./cmd/supascope scan --supabase-url https://project-ref.supabase.co --key sb_publishable_xxx --profile deep --graphql-schema-output schema.txt
```

Public URL scans display an authorization notice unless `--yes` is provided.

## Targets

Provide exactly one target:

- `https://example.com` scans a public URL and recursively fetches same-origin assets.
- `--path .` scans a local folder.
- `--supabase-url https://project-ref.supabase.co` scans a known Supabase project URL.

Passive URL scans inspect fetched public frontend assets. If referenced source maps are reachable, SupaScope parses `sourcesContent` and reports evidence against the original source entry inside the map. Source map scanning uses conservative early-stop limits so very large maps do not dominate passive scans.

If a fetched asset appears blocked by a WAF/CDN such as Cloudflare, Akamai, Fastly, Sucuri, Imperva, or a generic challenge page, SupaScope adds an informational scan coverage finding. This means passive results may be incomplete for blocked assets.

## Output

- Default output is Markdown written to stdout.
- `--json` writes JSON instead of Markdown.
- `--output file` writes the selected report format to a file.
- `--json --output report.json` writes JSON to `report.json`.
- `--unsafe-show-secrets` prints full discovered secrets in reports. Use only in trusted local environments.

## Scan Controls

- `--profile passive` runs static/local scanning only. This is the default.
- `--profile active` enables safe active service probes.
- `--profile deep` enables active service probes and GraphQL introspection.
- `--yes` confirms authorization for public URL scans.
- `--user-agent value` sets the User-Agent for remote HTTP requests.
- `--header "Name: value"` adds a remote HTTP request header. Repeat it for multiple headers.
- `--max-assets n` limits recursive same-origin asset fetching during URL scans.
- `--debug` prints request diagnostics to stderr.
 - When no headers are provided, SupaScope applies a set of browser-like default request headers (including a modern User-Agent and navigation headers) to improve passive fetch coverage and reduce false positives from WAF/CDN challenge pages. These defaults can be overridden via `--user-agent` or `--header`.

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

Dynamic browser scanning is planned for a later phase using `chromedp`.
