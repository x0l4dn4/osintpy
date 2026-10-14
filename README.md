Simple website reconnaissance with readable, color-coded output, third-party information sources, and optional direct-target checks.

### Install

Use Python 3.10 or newer. In the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 2. Run

```bash
# Passive: registration information and public subdomain candidates.
python recon.py example.com

# Active: DNS, TLS, and HTTP/technology inspection.
python recon.py your-authorized-domain.com --active

# Both sets of checks. Does not enable crawling or wordlists.
python recon.py your-authorized-domain.com --all
```

Replace the target with your actual authorized domain. `example.com` is a
placeholder, not a promise that every illustrated port/path exists there.
A bare hostname is interpreted as an HTTPS URL.

The older option-based syntax also works:

```bash
python recon.py -u example.com
```

## The commands you will use most

| Goal | Command |
| --- | --- |
| Normal passive overview | `python recon.py example.com` |
| Direct-target overview | `python recon.py example.com --active` |
| Passive and direct checks | `python recon.py example.com --all` |
| Registration only | `python recon.py www.example.com --only registration` |
| Public subdomains only | `python recon.py example.com --only subdomains` |
| DNS only | `python recon.py example.com --only dns` |
| TLS certificate only | `python recon.py https://example.com --only tls` |
| Website and technology hints | `python recon.py https://example.com --only http` |
| Save a readable report | `python recon.py example.com -o report.txt` |
| Save JSONL | `python recon.py example.com -o results.jsonl` |
| Save TSV | `python recon.py example.com -o results.tsv` |
| JSONL to the terminal | `python recon.py example.com --json` |
| Disable colors | `python recon.py example.com --no-color` |
| Everyday help | `python recon.py -h` |
| Complete help | `python recon.py --help-all` |

No API key is needed for normal passive or active checks. Only optional Google
result retrieval needs `SERPAPI_KEY`.

## What runs and what does not

| Profile | Checks included |
| --- | --- |
| Default | Domain registration and public subdomain discovery. |
| `--active` | DNS records, a verified TLS connection, and HTTP inspection. |
| `--all` | Both profiles above. |

None of these profiles automatically enables Wayback, Google dorks, crawling,
DNS wordlists, HTTP path wordlists, or public metadata fetches.

Passive checks contact third-party providers, not the target website. Providers
can see your lookup queries; passive does not mean anonymous.

Active checks query DNS and/or connect to the target. Technology fingerprinting
is part of HTTP inspection, not a separate module. It produces hints, not a
verified inventory or vulnerability report.

## Optional extras

```bash
# Add historical Wayback URL metadata to a passive run.
python recon.py example.com --archive

# Generate Google queries. Does not execute searches.
python recon.py example.com --dorks

# Add a direct same-origin crawl.
python recon.py your-authorized-domain.com --crawl

# HTTP plus robots.txt and sitemap.xml, without the passive defaults.
python recon.py your-authorized-domain.com --only http --metadata
```

Use `--only archive`, `--only dorks`, or `--only crawl` to run just that check.
Convenience flags add checks; `--only` replaces the profile's default selection.
For example, `--only http --archive` runs HTTP and the explicitly added archive.

`--crawl` and `--metadata` enable direct target requests even without `--active`.

## Saving output

```bash
python recon.py example.com -o report.txt
python recon.py example.com -o results.jsonl
python recon.py example.com --active -o dns-and-web.tsv
```

- `.jsonl` and `.ndjson` automatically select JSONL.
- `.tsv` automatically selects TSV.
- Other extensions use readable tables unless a format is explicitly selected.
- Existing output files are overwritten, not appended or automatically backed up.
- JSONL and TSV never include ANSI color codes.
- Readable tables show at most 30 rows each by default; this does not truncate
  collected JSONL/TSV records. Collection limits still apply.

Use `--display-limit 100` to show more table rows, or `--verbose` to include raw
evidence. Readable reports may wrap long URLs; use structured output for parsing.

## Registration and provider errors

The definitive script includes the color-default fix for the previous
`KeyError: None` startup crash.

It also handles the two earlier lookup problems:

- Registration uses the registrable domain. `www.geeksforgeeks.org` is queried
  as `geeksforgeeks.org`, not as a separately registered `www` domain.
- Public subdomain discovery normally tries crt.name, then crt.sh. A timeout
  does not mean the target has no subdomains.

A bundled Public Suffix List handles domains such as `example.co.uk` without
naively taking the last two labels. Private suffixes are considered separately
for passive discovery, so hosted tenants are not automatically widened to every
tenant beneath the hosting domain. Registration may still concern the underlying
hosting-provider domain rather than an individual tenant.

If RDAP.org fails, the tool attempts the relevant registry using IANA bootstrap
data. Other checks continue when one source is unavailable.

### Status meanings

| Status | Meaning |
| --- | --- |
| `ok` | The check completed. Does not establish exhaustive coverage. |
| `cached` | Fresh cached provider data was used instead of a new retrieval. |
| `partial` | Some operations failed, evidence was truncated, or explicitly labeled stale data was used. |
| `unavailable` | The selected lookup/check could not complete. |
| `failed` | Another error prevented completion. |
| `interrupted` | The user interrupted the check. |

Provider availability cannot be guaranteed. Timeouts and HTTP errors are not
silently converted into successful empty results. A failed target request says
that the check is incomplete rather than claiming there were no findings.

## Windows

On Windows PowerShell, create and activate the environment with:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If activation is restricted, use the environment's interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe recon.py -h
```

<details>
<summary><strong>Advanced options and examples</strong></summary>

## Module selection

Available checks:

```text
registration, subdomains, dns, tls, http, crawl, dns-brute, paths, archive, dorks
```

`--only CHECK` selects one starting check. `--modules CHECK,CHECK` selects an
explicit list. They cannot be used together. Both replace profile defaults;
explicit convenience flags and wordlist options still add their checks.

```bash
python recon.py example.com --modules registration,subdomains,dns,tls,http
```

Legacy aliases:

- `--modules rdap` means `registration`.
- `--modules ct` means public `subdomains`.
- `--modules subdomains` with `--dns-wordlist` means `dns-brute` for compatibility.
  Prefer `--only dns-brute` in new commands.
- `--mode passive` and `--mode active` remain available. The mode selector is
  mutually exclusive with `--active` and `--all`.

### DNS record selection and resolvers

```bash
python recon.py example.com --only dns --dns-types A,AAAA,MX,NS,TXT,SOA,CAA
python recon.py example.com --only dns --resolver 1.1.1.1 --resolver 8.8.8.8
```

Use DNS infrastructure approved for your assessment. `--resolver` accepts IPs,
not HTTPS DNS endpoint URLs. Omit it to use the system resolver configuration.

The normal DNS module queries each configured resolver. These options affect
explicit DNS enumeration, not the OS resolution used by HTTP/TLS clients.
All selected record types are queried at the supplied owner hostname; an apex
TXT query does not automatically discover DMARC or DKIM selectors.

### Live TLS inspection

```bash
python recon.py https://example.com --only tls
python recon.py https://your-authorized-host.test:8443 --only tls
```

Replace the custom-port placeholder with a real authorized service. Reports the
negotiated protocol/cipher and the verified certificate's subject, issuer,
validity dates and DNS SANs. SAN names are not automatically probed.

An HTTP target does not trigger an implicit TLS probe. Invalid/untrusted or
hostname-mismatched certificates fail verification; there is no `--insecure`
option. This is one verified connection, not a full TLS audit.

### HTTP inspection and public metadata

```bash
python recon.py https://example.com --only http
python recon.py https://example.com --only http --metadata
```

The normal HTTP check fetches only the starting URL. `--metadata` also requests
`/robots.txt` and `/sitemap.xml` at the origin root. It does not recursively parse
sitemaps. Each metadata request is independent, so a failed starting request
does not prevent the additional requested checks from being attempted.

Headers, generator metadata and common HTML/asset markers supply technology
hints. They can be absent, misleading or spoofed. Neither a server header nor a
framework marker establishes that a specific vulnerable version is running.

### Same-origin crawling

```bash
python recon.py https://example.com --only crawl --max-pages 10 --delay 1
```

The crawler follows HTML anchors, stays on the exact origin, and does not execute
JavaScript or submit forms. It skips query-bearing follow-up links, common static
assets and obvious action paths. Discovered URLs are not necessarily fetched.
These safeguards do not guarantee that GET requests cannot change state.

### DNS-prefix wordlist

Create `subdomains.txt`:

```text
www
api
mail
staging
```

```bash
python recon.py example.com --only dns-brute \
  --dns-wordlist subdomains.txt --max-words 100 --delay 1
```

Queries A/AAAA/CNAME beneath the exact URL hostname and performs two random-name
wildcard checks. `api` beneath `www.example.com` means `api.www.example.com`.
The first configured resolver is used for this module. Results are candidates;
wildcard detection is heuristic, not proof that a distinct service exists.

### HTTP-path wordlist

Create `paths.txt`:

```text
admin
login
api
health
about
```

```bash
python recon.py https://example.com --only paths \
  --path-wordlist paths.txt --max-words 100 --delay 1
```

Paths are relative to the origin root, not the starting path. With a starting
URL ending in `/app/`, `admin` means `/admin`; use `app/admin` for `/app/admin`.
The tool makes two random-path soft-404 baseline requests before the list.
Ordinary 404/410 responses and baseline matches are excluded, but dynamic
catch-all pages can still produce false positives.

Allowed path characters are letters, digits, `_`, `.`, `/`, `~`, and `-`.
Parent-directory components are rejected; query strings and arbitrary absolute
URLs are unsupported. Empty lines and lines starting with `#` are ignored in
both wordlist types. A candidate status is not proof of exposure or a flaw.

### Wayback URLs

```bash
python recon.py example.com --only archive --archive-limit 500
```

Retrieves historical URL metadata through CDX. Does not download archived bodies
or visit the returned live URLs. Historical URLs may be stale or unavailable.

### Google dorks and optional search retrieval

```bash
# Generate queries only.
python recon.py example.com --only dorks

# Execute the five queries through SerpApi.
export SERPAPI_KEY='your-api-key'
python recon.py example.com --only dorks --google-search -o google.jsonl
```

PowerShell environment variable syntax:

```powershell
$env:SERPAPI_KEY = 'your-api-key'
```

Queries cover documents, directory listings, backup/log/SQL extensions,
admin/login pages, and confidentiality phrases. API calls may consume paid
quota. Only returned search metadata is recorded; discovered documents are not
downloaded. Full result pagination is not implemented. A search hit is a lead
for authorized review, not a confirmed sensitive-data exposure.

### Provider selection and cache controls

```bash
python recon.py github.com --only subdomains --subdomain-source crtsh
python recon.py github.com --only subdomains --provider-timeout 45 --retries 0
python recon.py example.com --no-cache
python recon.py www.example.co.uk --domain example.co.uk
```

`auto` normally selects crt.name, then crt.sh. crt.name is skipped when its apex
lookup would broaden a tenant/narrow-domain discovery scope. Explicitly forcing
that source in an unsupported scope reports unavailable instead of widening it.
The sources differ in coverage and metadata; neither guarantees completeness.

`--domain` changes passive discovery scope, not the registrable domain used for
RDAP or the direct HTTP origin. It must equal or be a parent of the input host.
The bundled suffix list is used without a runtime suffix-list download, but can
age; update the dependency to obtain a newer bundled snapshot.

### Structured filtering

Requires separately installed `jq`:

```bash
# Public subdomain names.
python recon.py example.com --json \
  | jq -r 'select(.type == "subdomain") | .name' | sort -u

# DNS answers.
python recon.py example.com --only dns --json \
  | jq -r 'select(.type == "dns_record") | [.name, .value.rrtype, .value.value] | @tsv'

# Historical URLs.
python recon.py example.com --only archive --json \
  | jq -r 'select(.type == "archived_url") | .value.url' | sort -u

# Crawl-discovered URLs.
python recon.py https://example.com --only crawl --json \
  | jq -r 'select(.type == "public_url") | .name' | sort -u

# Provider/check warnings.
python recon.py example.com --json \
  | jq -r 'select(.type == "warning" or .type == "error") | [.source, .value.message] | @tsv'

# Status of each completed/attempted check.
python recon.py example.com --json \
  | jq -r 'select(.type == "check_status") | [.source, .value.status] | @tsv'
```

JSONL has one JSON object per line, not one JSON array. Top-level fields are:

| Field | Meaning |
| --- | --- |
| `time` | UTC timestamp. |
| `mode` | `passive`, `active`, or `mixed`, based on selected checks. |
| `target` | Input hostname. |
| `source` | Module/provider label. |
| `type` | Finding/status category. |
| `name` | Associated domain, URL, or item. |
| `value` | String or structured evidence object. |

Exports include scope, notices, warnings/errors, check statuses and a final
summary. Filter by `type` instead of assuming every record is a finding.
TSV uses the same seven columns and escapes control characters; structured
values are serialized in its last column. Human tables can wrap across lines.

For plain filtering:

```bash
python recon.py example.com --no-color | grep -F example.com
```

In Bash, use `set -o pipefail` if scanner failures must propagate through a
pipeline rather than being hidden by the final program's exit status.

## Complete option reference

| Option | Purpose / default |
| --- | --- |
| `target` | Positional domain or HTTP(S) URL. |
| `-u`, `--url` | Compatible option-based target. Conflicting targets are rejected. |
| `-h`, `--help` | Short help. |
| `--help-all` | Full help without a target requirement. |
| `-a`, `--active` | Direct DNS/TLS/HTTP profile. |
| `--all` | Passive + active profiles; no extra crawling/archive/wordlists. |
| `-m`, `--mode` | Legacy `passive`/`active` profile selector. |
| `--only` | One check, replacing profile defaults. |
| `--modules` | Explicit comma-separated check list. |
| `--archive` | Add archive metadata lookup. |
| `--dorks` | Add local Google query generation. |
| `--crawl` | Add direct same-origin crawling. |
| `--metadata` | Add HTTP plus origin-root robots/sitemap fetches. |
| `--domain` | Override passive discovery-domain scope. |
| `-o`, `--output` | Output file; overwritten if it exists. |
| `--json` | Select JSONL output. |
| `-f`, `--format` | `pretty`, `text`, `jsonl`, `tsv`; inferred if omitted. `text` is a readable-output alias. |
| `--color` | `auto` (default), `always`, `never`; machine formats never include ANSI. |
| `--no-color` | Disable readable-output colors. |
| `-v`, `--verbose` | Raw evidence and additional provider diagnostics. |
| `--display-limit` | Maximum visible rows per table; default `30`. |
| `--timeout` | Direct-target operation timeout; default `15` seconds. |
| `--provider-timeout` | Provider read timeout; default `30` seconds. Provider connection timeout is at most `10` seconds. |
| `--retries` | Extra provider attempts; default `1`, allowed `0`â€“`3`. |
| `--delay` | Minimum delay between operations; default `0.5` seconds. |
| `--max-bytes` | HTTP body-read cap; default `30000000` bytes (30 MB decimal). |
| `--no-cache` | Disable fresh/stale provider-cache reads and writes. |
| `--cache-dir` | `$XDG_CACHE_HOME/easyrecon`, otherwise `~/.cache/easyrecon`. |
| `--subdomain-source` | `auto`, `crtname`, or `crtsh`; default `auto`. |
| `--resolver` | Repeatable DNS resolver IP; default system configuration. |
| `--dns-types` | Default `A,AAAA,MX,NS,TXT,SOA,CAA,CNAME,HTTPS,SVCB`. |
| `--dns-wordlist` | Local prefix list; enables `dns-brute`. |
| `--path-wordlist` | Local path list; enables `paths`. |
| `--max-words` | Wordlist entries processed per list; default `100`. |
| `--max-pages` | Crawl fetches; default `10`, not a whole-run request limit. |
| `--archive-limit` | Archive rows requested; default `200`. |
| `--google-search` | Execute queries using `SERPAPI_KEY`; may consume paid quota. |

## Caching and retries

- Successful provider responses are fresh for six hours.
- Registration and public-subdomain checks can use cached data up to seven days
  old after live attempts fail. Its age is displayed, it is not live-verified,
  and the check is marked `partial` rather than fresh success.
- Archive lookup uses fresh caching but does not have a stale-data fallback.
- Google search retrieval is not cached; API keys are not written into entries.
- Cache files are created with mode `0600` and new directories with `0700`,
  subject to platform behavior. Existing-directory permissions are not rewritten.
- Cache storage is not encrypted. Use `--no-cache` where appropriate.
- Default provider behavior is at most two attempts per request: initial request
  plus one retry. Fallback providers can add separate requests.
- Retries cover transient request failures and HTTP 408/429/500/502/503/504.
  Ordinary HTTP 400/403/404 requests are not repeated unchanged.
- Recognized `Retry-After` values are respected within the short retry budget.
  A wait over 15 seconds skips that service for the current attempt/run path
  rather than retrying early. A different fallback provider may still be tried.
- `--retries 0` disables extra attempts, not fallback sources.
- Per-operation timeouts are not whole-run deadlines; streaming data, redirects,
  multiple sources, retries and DNS resolution can extend elapsed time.

</details>

## Scope and operational limits

- Active HTTP stays on the exact input scheme, hostname and port.
- Redirects are reported but never followed by active requests, including
  same-origin redirects. Inspect another authorized origin in a separate run.
- A starting path is not a scope boundary: crawling, metadata and wordlists can
  access other paths on the same origin.
- Discovered CT/index names, archived URLs, search results and certificate SANs
  never automatically become new active targets.
- Provider-side registration-routing redirects are permitted for passive lookups.
- Requests are sequential, but DNS retries, OS resolution and provider redirects
  can generate additional traffic. Delay is not a packet-rate limit.
- `--max-pages` limits only crawl fetches. Metadata, TLS and path/wordlist checks
  add operations; selecting both HTTP and crawl fetches the starting page twice.
- GET requests can cause side effects on poorly designed applications. Prefer a
  lab or staging environment and use only checks your authorization permits.
- There is no JavaScript browser, authenticated crawl, port scanner, password
  attack, exploitation engine, zone transfer, or recursive sitemap discovery.
- URL-oriented hostname input does not support underscore-bearing DNS owners
  for dedicated DMARC/DKIM/SRV-owner queries. DKIM selector discovery is absent.
- Response bodies are capped, but there is no comprehensive whole-run memory or
  total-finding limit. Large public-domain datasets may take substantial time.
- HTTP environment proxy settings are disabled by the script. Private-CA setups
  need deliberate trust-store/code configuration; verification is not bypassed.
- Protect cache/report data: raw registration records, headers/cookies, archived
  query parameters and search snippets may contain personal or confidential data.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `ModuleNotFoundError` or dependency validation error | Activate the environment and run `python -m pip install -r requirements.txt` with the same interpreter. |
| Old `KeyError: None` on `a.color` | Use the supplied definitive 4.1 script. It sets the parser default after registering both color flags and also handles `None` defensively in the reporter. |
| Registration error for a `www` host | Confirm the banner's Registration field is the registrable domain, not `www`. The old script may still be running. |
| Provider unavailable | Other checks continue; retry later, select another source, or inspect `--verbose`. No option guarantees service availability. |
| Read timeout on a custom port | Verify the application actually serves that scheme/port/path. Increasing timeout does not create an unavailable endpoint. |
| Redirect destination not inspected | Intentional scope restriction. Run a separate authorized request to the destination. |
| No terminal colors | Check `--color always`; machine formats intentionally remain colorless. |
| Only 30 rows visible | Use `--display-limit` or structured export; collection limits are separate. |
| Google queries but no results | `--dorks` generates only. Execution needs `--google-search` and `SERPAPI_KEY`. |
| Cached/stale evidence appears | Review its status and age. Use `--no-cache` to disable all cache use. |
| TLS validation fails | Check hostname, port, certificate and trust configuration. No insecure retry is performed. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Selected checks completed, including recovered fallbacks or fresh cache. Not proof of security or exhaustive coverage. |
| `1` | At least one check is unavailable, partial or failed; useful partial results can still exist. |
| `2` | Argument, dependency, or input validation error. |
| `130` | User interruption. |

Normal empty DNS answers are not module errors. A closed output pipe is handled
as normal termination. Inspect check-status records when using pipelines.

