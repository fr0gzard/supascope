# SupaScope

SupaScope is an authorized Supabase security reconnaissance scanner for detecting exposed keys, public storage buckets, risky anon access, weak RLS assumptions, runtime Supabase API usage, and frontend configuration leaks.

## Status

Go implementation in progress. The current implementation supports static public URL scans, local folder scans, recursive same-origin asset discovery, Supabase URL/key/endpoint detection, key classification, safe JWT metadata reporting, secret masking, active service checks, optional GraphQL introspection checks, JSON reports, and Markdown reports.

## Usage

```bash
go test ./...
go run ./cmd/supascope scan --path . --json
go run ./cmd/supascope scan https://example.com --yes
go run ./cmd/supascope scan https://example.com --yes --active-checks --json --output report.json
go run ./cmd/supascope scan --supabase-url https://project-ref.supabase.co --key sb_publishable_xxx --graphql-introspection --graphql-schema-output schema.txt
```

Public URL scans display an authorization notice unless `--yes` is provided.

## Targets

Provide exactly one target:

- `https://example.com` scans a public URL and recursively fetches same-origin assets.
- `--path .` scans a local folder.
- `--supabase-url https://project-ref.supabase.co` scans a known Supabase project URL.

## Output

- Default output is Markdown written to stdout.
- `--json` writes JSON instead of Markdown.
- `--output file` writes the selected report format to a file.
- `--json --output report.json` writes JSON to `report.json`.

## Scan Controls

- `--yes` confirms authorization for public URL scans.
- `--user-agent value` sets the User-Agent for remote HTTP requests.
- `--header "Name: value"` adds a remote HTTP request header. Repeat it for multiple headers.
- `--max-assets n` limits recursive same-origin asset fetching during URL scans.
- `--debug` prints request diagnostics to stderr.

## Key And JWT Reporting

Detected secrets are masked in discoveries, findings, and evidence snippets. JWT-like Supabase keys are decoded only for safe, non-secret metadata used in report evidence:

- role
- issuer
- expiry timestamp
- Supabase project ref when inferable

JWT metadata is decoded without signature verification and is used only to classify/report exposed artifacts. Raw token values are not printed in reports.

## Active Checks

Active checks are disabled by default and must be explicitly enabled:

```bash
go run ./cmd/supascope scan https://example.com --yes --active-checks
```

Current active checks perform safe service probes for REST, Auth, Storage, Realtime, Edge Functions, and GraphQL. GraphQL uses a POST probe with `__typename`; it does not test introspection.

- `--active-checks` enables active service probes.
- `--active-storage-tests` changes the storage probe to bucket listing and should only be used when authorized.

## GraphQL Introspection

GraphQL introspection is disabled by default and must be explicitly enabled:

```bash
go run ./cmd/supascope scan --supabase-url https://project-ref.supabase.co --key sb_publishable_xxx --graphql-introspection
```

- `--graphql-introspection` sends an explicit `__schema` introspection query to `/graphql/v1`.
- `--graphql-schema-output schema.txt` writes the raw introspection response to a text file when introspection is enabled.
- If introspection succeeds, SupaScope generates a medium-severity finding because schema exposure can help attackers map available GraphQL types and operations.
- Use this only for projects you are authorized to test.

Dynamic browser scanning is planned for a later phase using `chromedp`.
