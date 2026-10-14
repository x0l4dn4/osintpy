# osintpy

A Python command-line tool for authorized passive and active website reconnaissance, with readable, color-coded terminal output and structured exports for automation.

> Only assess domains, hosts, and applications that you own or have explicit permission to test. A domain appearing in a public database does not grant authorization to scan it.

## Contents

- [What the tool does](#what-the-tool-does)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Modes and default behavior](#modes-and-default-behavior)
- [All command-line options](#all-command-line-options)
- [Module selection](#module-selection)
- [Passive use cases](#passive-use-cases)
- [Active use cases](#active-use-cases)
- [Readable output and colors](#readable-output-and-colors)
- [Saving, filtering, and automation](#saving-filtering-and-automation)
- [Scope and safety](#scope-and-safety)
- [Limitations and interpretation](#limitations-and-interpretation)
- [Troubleshooting](#troubleshooting)
- [Exit codes](#exit-codes)
- [Files and testing](#files-and-testing)

## What the tool does

osintpy collects domain and website information through independent modules.

| Capability | Mode | Module | Enabled by default? |
| --- | --- | --- | --- |
| Domain registration metadata through RDAP | Passive | `rdap` | Yes, in passive mode |
| Certificate Transparency names and certificate metadata | Passive | `ct` | Yes, in passive mode |
| Historical public URLs through Wayback CDX | Passive | `archive` | No |
| Scoped Google dork generation | Passive | `dorks` | No |
| Google result retrieval through SerpApi | Passive | `dorks` plus `--google-search` | No |
| DNS record queries | Active | `dns` | Yes, in active mode |
| Verified live TLS certificate and connection information | Active | `tls` | Yes, in active mode |
| HTTP headers, title, public metadata, and technology hints | Active | `http` | Yes, in active mode |
| Bounded same-origin HTML crawling | Active | `crawl` | No |
| DNS prefix wordlist enumeration | Active | `subdomains` | No |
| HTTP path wordlist enumeration | Active | `paths` | No |

Technology fingerprinting is part of HTTP inspection and crawling. There is no separate `fingerprint` module or `--fingerprint` option.

The tool uses Python libraries rather than launching `nslookup`, `dnsrecon`, or `gobuster`. Its wordlist checks cover a small subset of the workflows those dedicated tools support; they are not full replacements.

## Installation

### Requirements

- Python 3.10 or newer.
- The supplied `recon.py` and `requirements.txt`.
- Network access to the selected information providers and/or authorized target.
- A SerpApi API key only if you enable Google result retrieval.
- Optionally, `jq` for the JSONL filtering examples below.

### Linux / macOS

Run these commands inside the extracted project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python recon.py -h
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python recon.py -h
```

If your PowerShell configuration prevents activation, you can invoke the environment directly without changing its execution policy:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe recon.py -h
```

The collection code uses `requests` and `dnspython`. Earlier v2 packages also list `rich`; install the supplied requirements even if the output updater replaces the presentation code with a standard-library renderer.

### Applying the readable-output update

Skip this if your copy already has the updated output and opt-in flags.

```bash
python update_recon.py recon.py
```

The updater creates a backup before changing the scanner. To produce a separate updated copy instead:

```bash
python update_recon.py recon.py --output recon_readable.py
```

Run that copy with `python recon_readable.py ...` rather than `python recon.py ...`.

## Quick start

All examples use `example.com` as a placeholder. Replace it with an authorized target. The examples are usage illustrations, not a statement that any public example domain is authorized for active assessment.

All scanner arguments are named options. There are no positional target arguments.

```bash
# Show every available option.
python recon.py -h

# Passive defaults: registration metadata and certificate-derived names.
python recon.py --url example.com

# Active defaults: DNS, TLS, and HTTP inspection.
python recon.py --url https://example.com --mode active

# Add historical Wayback URLs explicitly.
python recon.py --url example.com --archive

# Export passive results as JSONL.
python recon.py --url example.com --format jsonl --output passive.jsonl
```

## Modes and default behavior

### Passive mode

Passive is the default mode. Its default modules are:

```text
rdap,ct
```

These modules query third-party services rather than directly resolving or fetching the target. Public information providers can see your lookup queries. Passive does not mean anonymous.

Wayback and Google dorks do not run unless you explicitly select them.

```bash
python recon.py --url example.com --mode passive
```

### Active mode

Active mode must be selected explicitly. Its default modules are:

```text
 dns,tls,http
```

The tool performs DNS queries and/or connects to the target, depending on the selected modules. Crawling, subdomain wordlists, and path wordlists remain opt-in.

```bash
python recon.py --url https://example.com --mode active
```

### URL handling

A hostname without a scheme is treated as HTTPS:

```bash
python recon.py --url example.com
# Equivalent target URL: https://example.com/
```

You can specify a port and starting path:

```bash
python recon.py --url https://example.com:8443/app/ --mode active --modules http
```

Active HTTP is restricted to the supplied origin: scheme, hostname, and port. A starting path such as `/app/` is not an authorization boundary; other paths on that origin can be requested by metadata checks, crawling, or path enumeration.

## All command-line options

Run `python recon.py -h` to confirm the exact help text and defaults for your local version. Applying the output updater preserves already-existing presentation options, so its human-table row limit can differ between earlier packages.

### Target, mode, and module selection

| Option | Purpose | Default / notes |
| --- | --- | --- |
| `-h`, `--help` | List options and exit. | Does not perform enumeration. |
| `-u`, `--url` | Target DNS hostname or HTTP(S) URL. | Required. A bare hostname uses HTTPS. |
| `-m`, `--mode` | Select `passive` or `active`. | `passive`. |
| `--domain` | Explicit passive parent-domain scope. | Target hostname. Must equal it or be a parent domain. |
| `--modules` | Comma-separated module list. | Replaces the mode's defaults. Module names must belong to the selected mode. |
| `--archive` | Add Wayback historical URLs. | Off; passive only. |
| `--dorks` | Add Google query generation. | Off; passive only. Does not execute searches by itself. |
| `--google-search` | Enable dorks and retrieve Google results through SerpApi. | Off; passive only. Requires `SERPAPI_KEY`; can consume paid quota. |
| `--crawl` | Add bounded same-origin crawling. | Off; active only. |

### Output and presentation

| Option | Purpose | Default / notes |
| --- | --- | --- |
| `-f`, `--format` | `pretty`, `text`, `jsonl`, or `tsv`. | `pretty`; `text` is a compatibility alias for readable output. |
| `-o`, `--output` | Write results to a file instead of stdout. | No file. Existing output files are overwritten. |
| `--color` | `auto`, `always`, or `never`. | `auto`; applies only to readable output. |
| `--no-color` | Disable readable-output colors. | Alias for `--color never`. |
| `--display-limit` | Maximum visible rows per human-readable table. | Positive integer. The updater adds a default of 30 where the option was absent; an existing v2 default of 40 is preserved. Check `-h`. |
| `-v`, `--verbose` | Include raw diagnostic evidence in human output. | Off. Machine-readable output already retains structured records. |

### Network and collection limits

| Option | Purpose | Default / notes |
| --- | --- | --- |
| `--timeout` | Timeout per network operation, in seconds. | `15`; positive number. Not a whole-run deadline. |
| `--delay` | Minimum delay between operations, in seconds. | `0.5`; zero or greater. Not a strict packet-rate limit. |
| `--max-bytes` | Maximum body bytes read per HTTP response. | `10000000` (10 MB decimal). Oversized JSON API responses fail explicitly rather than being parsed incompletely. |
| `--archive-limit` | Maximum historical URL rows requested from Wayback. | `200`; relevant only when `archive` is selected. |
| `--max-pages` | Maximum fetches by the crawl module. | `10`; not a whole-run HTTP-request limit. |
| `--max-words` | Maximum nonempty, noncomment entries processed per wordlist. | `100`. |

### DNS and wordlists

| Option | Purpose | Default / notes |
| --- | --- | --- |
| `--resolver` | DNS resolver IP. Repeat for multiple resolvers. | System resolver if omitted. Active only. |
| `--dns-types` | Comma-separated DNS record types. | `A,AAAA,MX,NS,TXT,SOA,CAA,CNAME,HTTPS,SVCB`. |
| `--dns-wordlist` | Read DNS prefixes from a file and enable `subdomains`. | Off; active only. Enumerates beneath the URL hostname. |
| `--path-wordlist` | Read URL paths from a file and enable `paths`. | Off; active only. Paths are relative to the origin root. |

## Module selection

### Replace defaults

`--modules` selects an exact starting set instead of running the defaults:

```bash
# Only Certificate Transparency.
python recon.py --url example.com --modules ct

# Only active DNS.
python recon.py --url example.com --mode active --modules dns

# Only historical archive URLs.
python recon.py --url example.com --modules archive
```

### Add an explicit extra

Convenience flags add their module to the selected/default set:

```bash
# Default passive checks plus Wayback.
python recon.py --url example.com --archive

# Only CT, plus the explicitly requested archive module.
python recon.py --url example.com --modules ct --archive

# Default active checks plus crawling.
python recon.py --url https://example.com --mode active --crawl
```

Wordlist arguments enable their corresponding modules even if they are not listed in `--modules`. `--google-search` enables `dorks` as well.

Do not mix passive and active module names in one invocation. Use separate runs when you need both kinds of assessment.

## Passive use cases

### 1. Collect registration data and certificate-derived names

```bash
python recon.py --url example.com --mode passive
```

Use this for a small default reconnaissance pass without archive or search-result noise.

### 2. Inspect domain registration information only

```bash
python recon.py --url example.com --modules rdap
```

The tool uses structured RDAP data for WHOIS-style registration information. Human output summarizes the domain, registrar when available, status, registration-related events, and nameservers. Redacted or unavailable fields are not invented.

It does not invoke raw port-43 WHOIS or scrape DNSDumpster.

### 3. Find certificate-derived subdomain candidates only

```bash
python recon.py --url example.com --modules ct
```

The tool queries crt.sh and reports in-scope certificate names, wildcard patterns, and available certificate metadata. These names are not automatically resolved or fetched.

To show more names in the terminal:

```bash
python recon.py --url example.com --modules ct --display-limit 100
```

To retain all collected names without a human display limit:

```bash
python recon.py --url example.com --modules ct --format jsonl --output certificates.jsonl
```

A wildcard such as `*.example.com` is a certificate pattern, not evidence that every possible hostname exists.

### 4. Set the passive domain scope explicitly

```bash
python recon.py \
  --url www.example.co.uk \
  --domain example.co.uk \
  --modules rdap,ct
```

Without `--domain`, passive lookups use `www.example.co.uk`, not an automatically inferred parent. RDAP may have no registration object for a subdomain.

The tool does not derive a registrable domain by blindly taking the final two hostname labels. Expanding `--domain` must remain within your authorization.

### 5. Collect historical URLs from Wayback

```bash
# Add archive results to the default passive modules.
python recon.py --url example.com --archive

# Run the archive module alone with a larger result request.
python recon.py \
  --url example.com \
  --modules archive \
  --archive-limit 500 \
  --format jsonl \
  --output archived-urls.jsonl
```

The module requests URL metadata from Wayback CDX. It does not download archived page bodies or visit the returned live URLs. Historical results may no longer exist.

`--archive-limit` controls collection; `--display-limit` controls only human presentation.

### 6. Generate Google dorks without executing them

```bash
python recon.py --url example.com --modules dorks
```

Alternatively, add them to the default passive checks:

```bash
python recon.py --url example.com --dorks
```

The generated queries cover these categories:

| Query category | Examples of what the query targets |
| --- | --- |
| Public documents | PDF, DOCX, and XLSX files. |
| Directory listings | Pages with an `index of` title. |
| Potentially exposed files | Backup, old, log, and SQL filename extensions. |
| Administrative pages | URLs containing admin, login, or dashboard. |
| Confidentiality labels | Text such as confidential or internal use only. |

The module emits queries and Google search URLs as data. It does not open a browser or perform Google searches unless `--google-search` is supplied. Readable output shows the queries rather than dumping the generated search URLs.

### 7. Retrieve Google search results through SerpApi

Linux / macOS:

```bash
export SERPAPI_KEY='your-api-key'
python recon.py \
  --url example.com \
  --modules dorks \
  --google-search \
  --format jsonl \
  --output google-results.jsonl
```

Windows PowerShell:

```powershell
$env:SERPAPI_KEY = 'your-api-key'
python recon.py --url example.com --modules dorks --google-search
```

This requests results for five scoped queries. API calls may consume paid quota. The implementation records returned result metadata, such as titles, links, and snippets; it does not paginate through all Google results or download discovered documents.

Search hits are leads for authorized review, not confirmation of sensitive-data exposure. An administrative login page is not automatically a vulnerability.

### 8. Run all implemented passive modules explicitly

```bash
python recon.py \
  --url example.com \
  --mode passive \
  --modules rdap,ct,archive,dorks \
  --format jsonl \
  --output passive-full.jsonl
```

Add `--google-search` only if you want the dork searches executed and have configured the API key.

## Active use cases

### 1. Run the default active overview

```bash
python recon.py --url https://example.com --mode active
```

This runs DNS, TLS, and HTTP modules. It does not enable crawling or wordlist enumeration.

### 2. Query DNS records only

```bash
python recon.py --url example.com --mode active --modules dns
```

Default record types:

```text
A, AAAA, MX, NS, TXT, SOA, CAA, CNAME, HTTPS, SVCB
```

Results include the owner name, record type, answer, TTL, and resolver label.

Record types and resolvers are different concepts. `MX` and `TXT` are record types; `--resolver` selects the DNS server used to query them.

### 3. Query selected DNS record types

```bash
python recon.py \
  --url example.com \
  --mode active \
  --modules dns \
  --dns-types A,AAAA,MX,NS,TXT,SOA,CAA
```

All requested types are queried at the supplied target hostname. Querying `TXT` at `example.com` does not automatically enumerate `_dmarc.example.com` or DKIM selector owners.

### 4. Compare answers from multiple DNS resolvers

```bash
python recon.py \
  --url example.com \
  --mode active \
  --modules dns \
  --resolver 1.1.1.1 \
  --resolver 8.8.8.8 \
  --dns-types A,AAAA,MX,TXT
```

Normal DNS enumeration queries each configured resolver. Different answers can have multiple explanations, including cache state or DNS-based routing; differences alone do not prove a problem.

Omit `--resolver` to use the system resolver configuration. A resolver argument must be an IP address, not a hostname or an HTTPS DNS endpoint.

### 5. Inspect a live TLS certificate

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules tls
```

The tool performs a verified TLS handshake and reports the negotiated protocol, cipher, certificate subject/issuer, validity dates, and DNS SAN names.

A custom HTTPS port is supported:

```bash
python recon.py \
  --url https://example.com:8443 \
  --mode active \
  --modules tls
```

TLS verification remains enabled. An expired, untrusted, or hostname-mismatched certificate produces an error. The tool does not silently retry with verification disabled.

An HTTP target does not cause an implicit TLS probe. Use an explicit HTTPS URL when TLS inspection is intended.

### 6. Inspect HTTP information and technology hints

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules http
```

The module fetches:

- The supplied starting URL.
- `/robots.txt` at the origin root.
- `/sitemap.xml` at the origin root.

It reports status, selected response information, page title, redirect destination, and available fingerprint evidence. The readable-output updater summarizes public metadata rather than printing the entire body.

Technology hints come from headers, generator metadata, and framework markers such as WordPress assets or Next.js paths. Hints can be absent, misleading, or spoofed; they are not a complete or verified technology inventory.

### 7. Inspect an explicit HTTP endpoint without TLS

```bash
python recon.py \
  --url http://example.com \
  --mode active \
  --modules http
```

Redirects are recorded but not followed. If the server returns an HTTPS redirect, inspect the HTTPS destination in a separate, explicitly authorized run.

### 8. Discover public URLs with a bounded crawl

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules crawl \
  --max-pages 10 \
  --delay 1
```

To add crawling to the active defaults instead:

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --crawl \
  --max-pages 10
```

The crawler discovers same-origin HTML links and inspects fetched pages. Its implementation skips query-bearing follow-up links, common static assets, and obvious action links as a precaution. It is not a JavaScript browser or an authenticated crawler.

Discovered URLs are not necessarily fetched. A crawl page limit does not limit every other module's requests.

### 9. Enumerate DNS subdomain prefixes from a wordlist

Create `subdomains.txt`:

```text
www
api
mail
vpn
staging
```

Run the wordlist module alone:

```bash
python recon.py \
  --url example.com \
  --mode active \
  --modules subdomains \
  --dns-wordlist subdomains.txt \
  --max-words 100 \
  --delay 1
```

Or add it to a DNS overview:

```bash
python recon.py \
  --url example.com \
  --mode active \
  --modules dns \
  --dns-wordlist subdomains.txt
```

Prefixes are appended to the URL hostname. A target of `www.example.com` would produce names such as `api.www.example.com`; use `example.com` if the intended authorized scope is beneath the parent domain.

The implementation queries A, AAAA, and CNAME for wordlist candidates and makes two random-name baseline checks for wildcard DNS. These checks do not prove that a hostname is a real distinct service. When multiple resolvers are supplied, this module uses only the first one.

The wordlist contains prefixes, not full URLs. Empty lines and lines beginning with `#` are ignored.

### 10. Enumerate HTTP paths from a wordlist

Create `paths.txt`:

```text
admin
login
api
health
about
```

Run path checks only:

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules paths \
  --path-wordlist paths.txt \
  --max-words 100 \
  --delay 1
```

Or add them to an HTTP overview:

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules http \
  --path-wordlist paths.txt
```

Paths are requested from the origin root. With a starting URL of `https://example.com/app/`, the entry `admin` checks `https://example.com/admin`, not `/app/admin`. Use `app/admin` in the wordlist when that is the intended path.

The implementation performs two random-path baseline requests, excludes ordinary 404/410 results, and compares response signatures to reduce obvious soft-404 noise. Dynamic catch-all pages can still produce false positives. Reported paths remain candidates; status 200, 301, or 403 alone is not proof of exposed sensitive information.

Wordlist paths use the implementation's restricted syntax: letters, digits, underscores, dots, slashes, tildes, and hyphens; parent-directory components are rejected. Query strings and arbitrary absolute URLs are not supported.

### 11. Run a broader, explicitly selected active assessment

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules dns,tls,http,crawl,subdomains,paths \
  --dns-wordlist subdomains.txt \
  --path-wordlist paths.txt \
  --max-pages 10 \
  --max-words 100 \
  --delay 1 \
  --format jsonl \
  --output active-full.jsonl
```

This performs substantially more work than the defaults. Confirm every selected module is authorized. Do not interpret `--max-pages 10` as a total of ten HTTP requests: HTTP metadata, wordlist baselines, and path checks add requests.

### 12. Adjust timeouts and response-size limits

```bash
python recon.py \
  --url https://example.com \
  --mode active \
  --modules http \
  --timeout 30 \
  --delay 1 \
  --max-bytes 2000000
```

Here, individual operations use a 30-second timeout and body reads are limited to 2 MB. A larger delay reduces the frequency of operations but does not impose a strict network-packet budget.

The same timeout/body-size controls apply to passive provider HTTP requests. For example, a large CT response may require a larger body cap:

```bash
python recon.py \
  --url example.com \
  --modules ct \
  --timeout 30 \
  --max-bytes 20000000
```

Increasing a cap does not guarantee a provider will complete the request or return exhaustive results.

## Readable output and colors

The default `pretty` format uses category headings and wrapping tables, with no raw record prefixes or per-record timestamps. `text` is a compatibility alias for that presentation.

| Category | Color in the output updater |
| --- | --- |
| Domain registration | Cyan |
| Subdomain names / DNS wordlist candidates | Magenta |
| DNS records | Bright blue |
| TLS | Green |
| HTTP | Yellow |
| Technology hints | Bright green |
| Crawled public URLs | Bright cyan |
| Path candidates | Bright red |
| Wayback archive | Grey |
| Google dorks | Orange |
| Errors | Red |

Colors default to automatic detection: enabled in an interactive terminal, disabled for redirected/file output. The updater's automatic mode respects `NO_COLOR` and `TERM=dumb`. Explicit `--color always` overrides auto detection. Actual shades depend on terminal support.

```bash
# Automatic colors.
python recon.py --url example.com

# Force colors when needed.
python recon.py --url example.com --color always

# Disable all readable-output colors.
python recon.py --url example.com --no-color

# Display more rows without changing the amount collected.
python recon.py --url example.com --modules ct --display-limit 100

# Opt in to raw diagnostic records.
python recon.py --url example.com --verbose
```

Readable tables may wrap long values across multiple terminal lines. Use JSONL or TSV when reliable record-by-record parsing matters.

## Saving, filtering, and automation

### Save a readable report

```bash
python recon.py --url example.com --no-color --output report.txt
```

Files are overwritten, not appended. The scanner does not create an automatic backup of result files; the updater's source-code backup is a separate feature.

### Export JSONL

```bash
python recon.py --url example.com --format jsonl --output passive.jsonl
```

JSONL contains one JSON object per line. Human display limits do not truncate structured exports. Collection limits such as `--archive-limit` and `--max-words` still apply.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `time` | UTC event timestamp. |
| `mode` | Selected passive or active mode. |
| `target` | Target hostname. |
| `source` | Collector/provider label. |
| `type` | Record category, such as `dns_record` or `subdomain`. |
| `name` | Host, URL, or other item associated with the record. |
| `value` | A string or structured object containing the finding. |

Structured output also includes scope, error, and summary records. Filter on `type` rather than assuming every line is a finding. Nested evidence keys can differ between the earlier v1/v2 collection implementations; inspect a record before building a new parser.

### Export TSV

```bash
python recon.py \
  --url example.com \
  --mode active \
  --modules dns \
  --format tsv \
  --output dns.tsv
```

TSV has a header and the same seven top-level columns. Structured values are serialized in the final column; control characters are escaped to preserve row boundaries.

JSONL and TSV never include ANSI color sequences, even with `--color always`.

### Extract certificate-derived names

Requires `jq`:

```bash
python recon.py --url example.com --modules ct --format jsonl \
  | jq -r 'select(.type == "subdomain") | .name' \
  | sort -u
```

Save the name list:

```bash
python recon.py --url example.com --modules ct --format jsonl \
  | jq -r 'select(.type == "subdomain") | .name' \
  | sort -u > discovered-hostnames.txt
```

This does not authorize scanning those names or automatically add them to active scope.

### Extract DNS answers

```bash
python recon.py --url example.com --mode active --modules dns --format jsonl \
  | jq -r 'select(.type == "dns_record") | [.name, .value.rrtype, .value.value] | @tsv'
```

### Extract historical URLs

```bash
python recon.py --url example.com --modules archive --format jsonl \
  | jq -r 'select(.type == "archived_url") | .value.url' \
  | sort -u
```

### Extract crawl-discovered URLs

```bash
python recon.py --url https://example.com --mode active --modules crawl --format jsonl \
  | jq -r 'select(.type == "public_url") | .name' \
  | sort -u
```

### Extract path candidates

```bash
python recon.py --url https://example.com --mode active --modules paths \
  --path-wordlist paths.txt --format jsonl \
  | jq -r 'select(.type == "path_candidate") | [.name, .value.status] | @tsv'
```

### Extract Google result links

With `SERPAPI_KEY` configured:

```bash
python recon.py --url example.com --modules dorks --google-search --format jsonl \
  | jq -r 'select(.type == "search_result") | .value.url'
```

### Filter errors

```bash
python recon.py --url example.com --format jsonl \
  | jq -r 'select(.type == "error") | [.source, .name, .value.message] | @tsv'
```

### Use grep

```bash
python recon.py --url example.com --no-color | grep -F example.com
```

For record-based filtering, prefer TSV or JSONL over wrapping human tables:

```bash
python recon.py --url example.com --mode active --modules dns --format tsv \
  | grep -F dns_record
```

### Preserve scanner exit status in a Bash pipeline

```bash
set -o pipefail
python recon.py --url example.com --format jsonl \
  | jq -r 'select(.type == "subdomain") | .name'
```

Otherwise, the status of the final pipeline program can hide a scanner error. A run may produce useful partial results and still exit nonzero.

## Scope and safety

### Passive lookup scope

`--domain` controls passive domain lookups. Without it, the URL hostname is used exactly. Third-party providers can see these queries, and provider-side redirects may occur for registration lookup routing.

### Active HTTP scope

Active HTTP remains on the exact origin supplied:

```text
https://example.com:8443
```

That does not include:

```text
http://example.com:8443
https://example.com
https://www.example.com:8443
https://other.example.com:8443
```

Redirects are reported but never followed by active HTTP requests, including redirects that stay on the same origin. Use a separate explicit run for another authorized origin.

A path is not a scope boundary. `--url https://example.com/app/` does not constrain every request to `/app/`.

### Active DNS scope

Normal DNS queries use the target hostname. Wordlist enumeration checks explicitly requested child prefixes beneath that hostname.

Certificate names, CT names, archived URLs, and search results do not automatically expand active scope. A TLS SAN outside your intended scope is informational, not permission to probe it.

### Request volume and side effects

- Modules operate sequentially, without parallel workers.
- Delay applies between operations, not every packet. DNS retries, address resolution, and provider redirects can generate extra traffic.
- Crawl limits apply only to crawling; other modules add their own requests.
- Selecting both `http` and `crawl` fetches the starting page twice in these implementations.
- Path checks add two random baseline requests before wordlist requests.
- DNS wordlist checks add random-name baselines and query multiple record types per entry.
- A timeout is not a whole-run deadline; repeated operations or slow streamed responses can make a run longer.
- Even GET requests can change state on poorly designed applications. Avoid production targets unless your authorization explicitly permits the assessment.

### Protect collected data

Raw headers, RDAP objects, archived query parameters, and search snippets can contain personal or confidential information. Store outputs securely and do not publish them or commit them to a public repository without review.

## Limitations and interpretation

- CT names and archived URLs can be historical, incomplete, or stale.
- A certificate wildcard does not prove individual hosts exist.
- Search results are leads, not confirmed data exposure.
- Technology hints are heuristic and do not establish a complete inventory or exact vulnerable version.
- Wildcard DNS, load-balanced responses, and dynamic soft-404 pages can produce ambiguous candidates.
- HTTP status codes alone do not establish endpoint existence, confidentiality, or exploitability.
- TLS inspection is one verified connection, not a cipher-suite audit or exhaustive TLS vulnerability assessment.
- The crawler does not execute JavaScript, log in, submit forms, or fully reproduce a browser.
- Public metadata is fetched but the tool is not a recursive sitemap discovery engine.
- DNS queries do not perform a zone transfer or automatically discover every DNS owner name.
- The URL-oriented hostname validation does not support underscore-bearing owners for dedicated DMARC/DKIM/SRV-owner queries. DKIM selector discovery is not implemented.
- The tool does not perform port scans, exploit vulnerabilities, attempt passwords, or bypass authentication.
- Response body reads are capped, but there is no comprehensive whole-run memory or total-result cap for large CT datasets.
- Provider availability, rate limits, account quota, and data quality are outside the tool's control.
- HTTP environment proxies are disabled by the collection implementation; environment proxy variables are not a supported routing control.

## Troubleshooting

These checks describe this implementation's behavior; they are not a guarantee that a provider or target will be reachable.

### Missing Python dependency

Install the supplied dependencies with the same interpreter used to run the scanner:

```bash
python -m pip install -r requirements.txt
```

The virtual environment's interpreter avoids confusion between multiple installations:

```bash
.venv/bin/python recon.py -h
```

### No colors

Redirected output and files are colorless by default. Check an explicit forced-color run:

```bash
python recon.py --url example.com --color always
```

Machine formats intentionally never include colors. In automatic mode, `NO_COLOR`, a dumb terminal, or noninteractive stdout disables colors.

### Too many or too few visible rows

Use `--display-limit` to change presentation:

```bash
python recon.py --url example.com --modules ct --display-limit 100
```

For complete collected records, use JSONL. A larger display limit does not increase provider collection limits.

### Wayback or dorks are appearing unexpectedly

Inspect the command for `--archive`, `--dorks`, `--google-search`, or a `--modules` list containing `archive`/`dorks`. If a default invocation still includes them, confirm you are running the updated script rather than an older copy.

### RDAP fails for a subdomain

A subdomain may not have its own registration object. Supply the authorized registrable domain explicitly:

```bash
python recon.py --url www.example.co.uk --domain example.co.uk --modules rdap
```

### Google queries appear but no results are retrieved

`--dorks` generates queries only. Actual retrieval requires `--google-search` and `SERPAPI_KEY`:

```bash
export SERPAPI_KEY='your-api-key'
python recon.py --url example.com --modules dorks --google-search
```

An empty result list can also mean the provider returned no matching organic results; it does not prove no relevant content exists.

### Provider timeout or response-size error

A focused retry can use a larger operation timeout/body limit:

```bash
python recon.py --url example.com --modules ct --timeout 30 --max-bytes 20000000
```

This does not bypass service limits. Avoid tight retry loops and respect provider responses.

### Certificate validation error

The scanner does not bypass verification. Check that the hostname and HTTPS port are correct and that the target certificate/trust setup is valid. Private-CA environments need a deliberate trust-store/code configuration change; there is no supported `--insecure` flag.

### Redirect destination is not inspected

That is intentional. Inspect the destination only in a separate run after confirming it is authorized:

```bash
python recon.py --url https://example.com --mode active --modules http
```

### Empty DNS result

No A, AAAA, CNAME, or other requested record at a particular owner can be a normal result. It does not necessarily indicate a scanner failure. `--verbose` or JSONL shows individual empty-answer records.

### Wordlist file not found

Wordlist paths are relative to the current working directory unless absolute paths are supplied:

```bash
python recon.py --url example.com --mode active --modules subdomains \
  --dns-wordlist ./wordlists/subdomains.txt
```

### Invalid module selection

Use only passive modules in passive mode and only active modules in active mode. The `subdomains` and `paths` modules require their corresponding wordlist arguments.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed without recorded module errors. Does not mean the target is secure or enumeration was exhaustive. |
| `1` | One or more module errors; partial results may still be useful. |
| `2` | Command-line validation or dependency validation error. |
| `130` | Interrupted by the user. |

Ordinary empty DNS answers are not module errors. The original script also handles a closed output pipe as a normal termination case.

## Files and testing

| File | Purpose |
| --- | --- |
| `recon.py` | The scanner. Run this for enumeration. |
| `requirements.txt` | Scanner dependencies. |
| `README.md` | This documentation. |
| `update_recon.py` | Applies the readable-output/default-module update to an earlier copy and creates a backup. Not used for scans. |
| `test_recon.py` | Optional development tests if included with your scanner package. Not needed for ordinary use. |

The readable-output updater was checked using 14 offline compatibility/presentation checks against representative earlier-version fixtures. These covered opt-in defaults, module overrides, color behavior, JSONL/TSV formatting, argument validation, backup creation, repeated updates, and v2-style hooks.

Those checks did not scan a live website or establish current provider availability. The older `test_recon.py` files were written for their original output implementations; Reporter-interface and default-selection assertions may need updating after applying the output updater. Do not treat an old test suite as a verified post-update regression suite without reviewing it.

## Recommended minimal workflow

1. Confirm the authorized host/domain scope.
2. Run passive defaults and export JSONL if you need durable evidence.
3. Review discovered names without automatically expanding scope.
4. Run the active DNS/TLS/HTTP overview only on authorized targets.
5. Add archive, search, crawling, or wordlist modules only for a specific purpose.
6. Review candidates manually and protect the resulting files.
