# ScopedRecon

Standalone Python 3.10+ CLI for authorized website reconnaissance. All parameters
are named options. `-u/--url` is the only required option; passive is the default.
Do not assess a target without appropriate authorization.

## Install and run

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python recon.py -h
python recon.py --url example.com --mode passive
python recon.py --url https://example.com --mode active
```

These are usage examples, not statements of authorization for example.com.
Replace the target with your own lab or authorized assessment scope.

## Passive

Default modules: rdap,ct,archive,dorks.

- RDAP: structured registration data via rdap.org and the responsible registry.
  A WHOIS-style replacement, not the raw port-43 WHOIS protocol or DNSDumpster.
- Certificate Transparency: crt.sh names, certificate dates, issuer and wildcard
  flag. Names are NOT resolved or tested for liveness.
- Wayback CDX: historical public URLs; no archived pages or live pages fetched.
- Google: generates five scoped dork queries and browser URLs. Execution is
  opt-in with --google-search and SERPAPI_KEY through SerpApi. The opt-in makes
  five third-party search API calls, which may consume paid quota. Only returned
  search metadata is recorded; discovered documents are not downloaded.

```sh
python recon.py -u example.com -m passive -f jsonl -o passive.jsonl
python recon.py -u www.example.co.uk --domain example.co.uk --modules rdap,ct,dorks
export SERPAPI_KEY='your-key'
python recon.py -u example.com --modules dorks --google-search -f jsonl
```

--domain is explicit: the script does NOT guess the registrable domain by taking
its last two labels. For www.example.co.uk, use --domain example.co.uk when that
entire domain is authorized. By default the exact provided hostname is used;
RDAP queries for non-registered subdomains may return no registration record.
Public databases may be incomplete, historical, redacted, unavailable or rate
limited. Providers see your lookup queries; passive does not mean anonymous.

## Active

Default modules: dns,tls,http,crawl.

- DNS: A,AAAA,MX,NS,TXT,SOA,CAA,CNAME,HTTPS,SVCB on the target hostname.
  Repeat --resolver to query multiple recursive DNS servers. Resolver and RR
  type are different concepts; MX/TXT/etc. are record types, not registries.
  Uses dnspython directly, not shell commands such as nslookup or dnsrecon.
- TLS: verified handshake, protocol, cipher, issuer/subject, validity and SANs.
  No verification bypass; invalid/untrusted certificates yield an error.
  SAN names outside scope are informational and are never automatically probed.
- HTTP: response headers, redirect locations, title, robots.txt and sitemap.xml.
- Crawl: bounded same-origin HTML link discovery, plus heuristic fingerprinting
  from headers, meta generator and common framework asset markers.
- Subdomains: opt-in DNS prefix wordlist, two random wildcard-DNS checks;
  candidates are flagged rather than claimed to be confirmed hosts.
- Paths: opt-in origin-root path wordlist, two random soft-404 baselines;
  emits candidates, not proof of existence or exposure.

```sh
python recon.py -u https://example.com -m active --modules dns,tls,http -f tsv
python recon.py -u example.com -m active --modules dns \
  --resolver 1.1.1.1 --resolver 8.8.8.8 --dns-types A,AAAA,MX,NS,TXT,SOA,CAA
python recon.py -u https://example.com -m active --modules crawl --max-pages 10
python recon.py -u example.com -m active --modules dns \
  --dns-wordlist subdomains.txt --max-words 100
python recon.py -u https://example.com -m active --modules http \
  --path-wordlist paths.txt --max-words 100 --delay 1 -f jsonl -o active.jsonl
```

Supplying a wordlist enables its corresponding module even with --modules.
Subdomain enumeration is under the URL hostname, not --domain. With multiple
resolvers, normal DNS enumeration queries all of them; the subdomain wordlist
uses only the first resolver. Query DNS records at the actual owner name:
TXT at example.com does not enumerate _dmarc.example.com or DKIM selectors.
You can query a known owner using --url _... only if hostname validation permits
it; underscore-bearing DNS owner names are not supported by this URL-oriented
CLI. This tool does not attempt DKIM selector discovery.

## Scope and operational safeguards

- Passive modules contact third-party providers only, not the target directly.
- Active HTTP stays at the exact scheme, hostname and port supplied.
  Redirects are reported and NOT followed, even same-origin redirects. Thus an
  HTTP-to-HTTPS redirect requires a separate explicit HTTPS run. A URL path is
  not a scope boundary: robots, sitemap, links and paths can include the whole
  origin. Use --modules and your authorization accordingly.
- Active DNS queries the URL hostname and requested wordlist children. Names
  discovered from CT, archives, search or TLS SANs do not expand active scope.
- No port scanning, exploitation, login attempts, form submission, JavaScript
  execution, zone transfer, authenticated crawling or sensitive-file fetching
  from Google results. Path enumeration performs GETs at wordlist paths, so
  choose an appropriate list and protect the output.
- Sequential operations; default 0.5-second delay before operations. This is not
  a strict network-packet rate limiter: DNS retries, address resolution and
  third-party redirects can entail additional network traffic.
- Crawl defaults to 10 fetches; wordlists default to 100 entries. The page limit
  is per crawl module, NOT a total run-wide HTTP-request budget. HTTP metadata
  and path modules add requests. Default active HTTP and crawl both fetch the
  starting page. Use --modules to avoid unnecessary checks.
- Default network timeout is 15 seconds. It is an individual network-operation
  timeout, not a whole-run deadline; a slow streaming response can take longer.
- Body reads are capped at 10 MB per response; JSON APIs that exceed this fail
  explicitly. Third-party service responses can be larger than this.
- TLS verification remains enabled. Proxy/environment settings are disabled
  for predictable scope. A legitimate private CA requires adapting the code or
  installing it in the trust store used by the relevant TLS client.
- GET requests can cause side effects on poorly designed sites. Some common
  action links and query-bearing links are not followed by the crawler, but
  that heuristic cannot guarantee safety. Prefer a lab or staging environment.
- Technology indicators can be spoofed; versions are not automatically
  established. DNS wildcards, dynamic soft-404s, CDNs and catch-all redirects
  cause ambiguity. Review candidates manually within your authorization.
- No whole-run memory/result-count cap exists for CT; select a narrow domain.
- Results may include emails, cookies, archived query parameters or confidential
  metadata. Store them securely. Do not commit output files to public repos.

## Output

text: one record per line, human-readable delimiters, no colors.
tsv: header + seven columns, escaped tabs/newlines/control characters.
jsonl: one JSON object per line; recommended for robust automation.
Fields: time (UTC), mode, target, source, type, name, value.
The value field can be a string or a structured object.
Progress is stderr. Results are stdout, or --output when provided.
Output files are overwritten. Error records remain in the chosen results format.
A final summary includes counts. Exit codes: 0 no module errors, 1 module
error(s)/partial result, 2 CLI validation error, 130 keyboard interruption.
An empty DNS answer is not a module error.

```sh
python recon.py -u example.com --modules ct -f jsonl \
  | jq -r 'select(.type == "subdomain") | .name' | sort -u
python recon.py -u example.com -m active --modules dns -f jsonl \
  | jq -r 'select(.type == "dns_record") | [.name,.value.rrtype,.value.value] | @tsv'
python recon.py -u example.com -m active --modules dns -f tsv \
  | grep -F 'dns_record'
```

Illustrative JSONL record (not a real scan result):

```json
{"time":"2026-10-14T17:00:00+00:00","mode":"active","target":"example.com","source":"dns","type":"dns_record","name":"example.com","value":{"resolver":"system","rrtype":"A","ttl":300,"value":"192.0.2.10"}}
```

## Tests

```sh
python -m unittest -v test_recon.py
```

Offline tests cover normalization, CLI validation, origin restrictions, HTML
parsing, output escaping, CT filtering, archive filtering and offline dorks.
They do not establish live provider availability or full scanner correctness.
No real website was scanned when this deliverable was produced.

## Public implementation references

RDAP protocol bootstrap: https://rdap.org/
dnspython: https://dnspython.readthedocs.io/en/latest/resolver-functions.html
Certificate Transparency lookup: https://crt.sh/
Internet Archive CDX: https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
Python TLS: https://docs.python.org/3/library/ssl.html
Google search API integration: https://serpapi.com/search-api
