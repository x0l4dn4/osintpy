#!/usr/bin/env python3
"""EasyRecon 4.1 — simple, authorized website reconnaissance.

Save this file as recon.py, then install dependencies:
    python3 -m pip install requests dnspython tldextract rich

Examples:
    python3 recon.py example.com
    python3 recon.py -u example.com
    python3 recon.py example.com --active
    python3 recon.py example.com --all
    python3 recon.py example.com --only registration
    python3 recon.py -h
    python3 recon.py --help-all

Passive defaults use third-party registration and subdomain sources.
Active checks require authorization. Provider availability is not guaranteed.
"""
import argparse
import collections
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

VERSION = '4.1'
MODULES = {'registration', 'subdomains', 'dns', 'tls', 'http', 'crawl',
           'dns-brute', 'paths', 'archive', 'dorks'}
ACTIVE = {'dns', 'tls', 'http', 'crawl', 'dns-brute', 'paths'}
STYLE = {'registration': 'cyan', 'subdomains': 'magenta', 'dns': 'bright_blue',
         'tls': 'green', 'http': 'yellow', 'crawl': 'bright_cyan',
         'dns-brute': 'bright_magenta', 'paths': 'bright_red',
         'archive': 'grey70', 'dorks': '#ff8700'}
LABEL = {'registration': 'Domain registration', 'subdomains': 'Public subdomain discovery',
         'dns': 'DNS records', 'tls': 'TLS certificate', 'http': 'Website overview',
         'crawl': 'Public URL discovery', 'dns-brute': 'DNS wordlist candidates',
         'paths': 'Path candidates', 'archive': 'Wayback URLs (opt-in)',
         'dorks': 'Google dorks (opt-in)'}
DEFAULT_RR = 'A,AAAA,MX,NS,TXT,SOA,CAA,CNAME,HTTPS,SVCB'
FRESH_SECONDS = 6 * 3600
STALE_SECONDS = 7 * 24 * 3600


def clean(value):
    text = str(value if value is not None else '—')
    return ''.join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159 else ' ' for c in text)


def hostname(value):
    name = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(name) > 253 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in name.split('.')
    ):
        raise ValueError('invalid hostname')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError('use a DNS hostname rather than an IP address')


def normalize(value):
    p = urlsplit(value if '://' in value else 'https://' + value)
    if (p.scheme not in ('http', 'https') or not p.hostname
            or p.username is not None or p.password is not None):
        raise ValueError('use an HTTP(S) URL or hostname without credentials')
    host = hostname(p.hostname)
    netloc = host + (f':{p.port}' if p.port is not None else '')
    return urlunsplit((p.scheme, netloc, p.path or '/', p.query, '')), host


def within(name, domain):
    return name == domain or name.endswith('.' + domain)


def same_origin(a, b):
    def origin(value):
        p = urlsplit(value)
        return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)
    try:
        p = urlsplit(b)
        return (p.scheme in ('http', 'https') and p.username is None
                and p.password is None and origin(a) == origin(b))
    except ValueError:
        return False


def derive_scopes(host):
    import tldextract
    kwargs = {'suffix_list_urls': (), 'cache_dir': None}
    icann = tldextract.TLDExtract(include_psl_private_domains=False, **kwargs)(host)
    private = tldextract.TLDExtract(include_psl_private_domains=True, **kwargs)(host)
    def base(e):
        return e.domain + '.' + e.suffix if e.domain and e.suffix else None
    return base(icann), base(private) or host


def positive(value):
    n = float(value)
    if not 0 < n < float('inf'):
        raise argparse.ArgumentTypeError('must be a finite positive number')
    return n


def count(value):
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return n


def nonnegative(value):
    n = float(value)
    if not 0 <= n < float('inf'):
        raise argparse.ArgumentTypeError('must be finite and zero or greater')
    return n


def retry_count(value):
    n = int(value)
    if not 0 <= n <= 3:
        raise argparse.ArgumentTypeError('must be between 0 and 3')
    return n


def parser(show_advanced=False):
    p = argparse.ArgumentParser(
        description='EasyRecon — one target, sensible defaults.',
        epilog=('Examples:\n'
                '  recon.py github.com\n'
                '  recon.py example.com --active\n'
                '  recon.py example.com --all\n\n'
                'Passive defaults: registration + public subdomains.\n'
                'Archives, dorks, crawling and wordlists require explicit options.\n'
                'Only scan authorized targets. Use --help-all for advanced settings.'),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('target', nargs='?', help='domain or URL; -u is also supported')
    p.add_argument('-u', '--url', help='target, compatible with older versions')
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('-a', '--active', action='store_true',
                       help='direct DNS, TLS and website checks')
    modes.add_argument('--all', action='store_true',
                       help='passive + direct checks; no crawling or wordlists')
    modes.add_argument('-m', '--mode', choices=['passive', 'active'],
                       help='legacy profile selector' if show_advanced else argparse.SUPPRESS)
    p.add_argument('--only', choices=sorted(MODULES), help='run one specific check')
    p.add_argument('--archive', action='store_true', help='also retrieve historical Wayback URLs')
    p.add_argument('--dorks', action='store_true', help='also generate Google search queries')
    p.add_argument('--crawl', action='store_true', help='also crawl same-origin links (active)')
    p.add_argument('-o', '--output', help='save results; .jsonl/.tsv choose structured output')
    p.add_argument('--json', dest='format', action='store_const', const='jsonl',
                   help='JSONL output: one JSON record per line')
    p.add_argument('--no-color', dest='color', action='store_const', const='never',
                   help='disable terminal colors')
    p.add_argument('--help-all', action='store_true', help='show advanced settings')
    advanced = p.add_argument_group('Advanced settings')
    def add(*args, **kwargs):
        if not show_advanced:
            kwargs['help'] = argparse.SUPPRESS
        advanced.add_argument(*args, **kwargs)
    add('--modules', help='comma-separated selection; rdap/ct aliases supported')
    add('--domain', help='override passive discovery scope, not registration domain')
    add('-f', '--format', choices=['pretty', 'text', 'jsonl', 'tsv'], default=None,
        help='output format; otherwise infer from file extension or use pretty')
    add('--color', choices=['auto', 'always', 'never'], default='auto', help='color behavior')
    add('-v', '--verbose', action='store_true', help='raw evidence and extra diagnostics')
    add('--display-limit', type=count, default=30, help='visible rows per table; exports retain all')
    add('--timeout', type=positive, default=15, help='target operation timeout in seconds')
    add('--provider-timeout', type=positive, default=30, help='provider read timeout in seconds')
    add('--retries', type=retry_count, default=1, help='extra provider attempts, 0–3')
    add('--delay', type=nonnegative, default=0.5, help='minimum seconds between operations')
    add('--max-bytes', type=count, default=30_000_000, help='maximum bytes per HTTP body')
    add('--no-cache', action='store_true', help='disable all provider cache reads/writes')
    add('--cache-dir', default=str(Path(os.environ.get(
        'XDG_CACHE_HOME', str(Path.home() / '.cache'))) / 'easyrecon'), help='provider cache directory')
    add('--subdomain-source', choices=['auto', 'crtname', 'crtsh'], default='auto',
        help='auto: crt.name first, crt.sh fallback')
    add('--resolver', action='append', help='DNS resolver IP; repeat; default system resolver')
    add('--dns-types', default=DEFAULT_RR, help='comma-separated DNS record types')
    add('--dns-wordlist', help='enable DNS prefix enumeration using this file')
    add('--path-wordlist', help='enable HTTP path enumeration using this file')
    add('--max-words', type=count, default=100, help='wordlist entry limit')
    add('--max-pages', type=count, default=10, help='crawl fetch limit')
    add('--archive-limit', type=count, default=200, help='maximum archive rows requested')
    add('--google-search', action='store_true',
        help='retrieve dork results through SERPAPI_KEY; may use paid quota')
    add('--metadata', action='store_true', help='add HTTP plus robots.txt and sitemap.xml')
    # Both color options share a destination. Set its default AFTER registering them.
    p.set_defaults(color='auto')
    return p


def choose_modules(a, p):
    if a.only and a.modules:
        p.error('use --only or --modules, not both')
    if a.only:
        modules = [a.only]
    elif a.modules:
        aliases = {'rdap': 'registration', 'ct': 'subdomains',
                   'subdomains': 'dns-brute' if a.dns_wordlist else 'subdomains'}
        modules = [aliases.get(m.strip(), m.strip())
                   for m in a.modules.split(',') if m.strip()]
    elif a.all:
        modules = ['registration', 'subdomains', 'dns', 'tls', 'http']
    elif a.active or a.mode == 'active':
        modules = ['dns', 'tls', 'http']
    else:
        modules = ['registration', 'subdomains']
    extras = [(a.archive, 'archive'), (a.dorks or a.google_search, 'dorks'),
              (a.crawl, 'crawl'), (a.dns_wordlist, 'dns-brute'),
              (a.path_wordlist, 'paths'), (a.metadata, 'http')]
    for enabled, module in extras:
        if enabled and module not in modules:
            modules.append(module)
    if not modules or set(modules) - MODULES:
        p.error('unknown module; see --help-all')
    if 'dns-brute' in modules and not a.dns_wordlist:
        p.error('DNS wordlist checks require --dns-wordlist FILE')
    if 'paths' in modules and not a.path_wordlist:
        p.error('path checks require --path-wordlist FILE')
    return list(dict.fromkeys(modules))


class Reporter:
    def __init__(self, a, host, mode):
        self.a, self.host, self.mode = a, host, mode
        self.pending, self.counts, self.status = [], collections.Counter(), {}
        self.human = a.format in ('pretty', 'text')
        self.stream = open(a.output, 'w', encoding='utf-8') if a.output else sys.stdout
        self.console = None
        if self.human:
            from rich.console import Console
            color = getattr(a, 'color', None) or 'auto'
            force = {'auto': None, 'always': True, 'never': False}.get(color)
            self.console = Console(
                file=self.stream, force_terminal=force, no_color=color == 'never',
                highlight=False,
                width=120 if a.output or not self.stream.isatty() else None)
        elif a.format == 'tsv':
            self.stream.write('time\tmode\ttarget\tsource\ttype\tname\tvalue\n')

    def text(self, value, style=None):
        from rich.text import Text
        self.console.print(Text(clean(value), style=style))

    def emit(self, source, kind, name, value):
        record = {'time': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'mode': self.mode, 'target': self.host, 'source': source,
                  'type': kind, 'name': name, 'value': value}
        self.counts[kind] += 1
        if self.human:
            self.pending.append(record)
        elif self.a.format == 'jsonl':
            self.stream.write(json.dumps(record, ensure_ascii=True) + '\n')
        else:
            def field(v):
                s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=True)
                return ''.join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159
                               else f'\\x{ord(c):02x}' for c in s.replace('\\', '\\\\'))
            keys = ('time', 'mode', 'target', 'source', 'type', 'name', 'value')
            self.stream.write('\t'.join(field(record[k]) for k in keys) + '\n')
        self.stream.flush()

    def table(self, headers, rows, color):
        from rich import box
        from rich.table import Table
        from rich.text import Text
        rows = list(rows)
        if not rows:
            return
        table = Table(box=box.ROUNDED, header_style='bold ' + color,
                      border_style=color, show_lines=False)
        for h in headers:
            table.add_column(h, overflow='fold')
        for row in rows[:self.a.display_limit]:
            table.add_row(*(Text(clean(v)) for v in row))
        self.console.print(table)
        if len(rows) > self.a.display_limit:
            self.text(f'Showing {self.a.display_limit} of {len(rows)} rows. '
                      'JSONL/TSV retain all collected rows.', 'dim')

    def begin(self, module):
        if self.human:
            from rich.text import Text
            self.console.print()
            self.console.rule(Text(LABEL[module], style='bold ' + STYLE[module]),
                              style=STYLE[module], align='left')

    def render(self, module):
        if not self.human:
            return
        rows, self.pending = self.pending, []
        color = STYLE[module]
        by = lambda kind: [r for r in rows if r['type'] == kind]
        for r in by('registration'):
            d = r['value']
            registrar = 'Not disclosed'
            for entity in d.get('entities', []):
                if 'registrar' in entity.get('roles', []):
                    registrar = entity.get('handle', registrar)
                    card = entity.get('vcardArray') or [None, []]
                    for entry in card[1] if len(card) > 1 else []:
                        if len(entry) > 3 and entry[0] == 'fn':
                            registrar = entry[3]
            fields = [('Registered domain', d.get('ldhName', r['name'])),
                      ('Registrar', registrar),
                      ('Status', ', '.join(d.get('status', [])) or 'Not disclosed')]
            fields += [(e.get('eventAction', 'Event').capitalize(), e.get('eventDate'))
                       for e in d.get('events', [])]
            fields += [('Nameservers', ', '.join(n.get('ldhName', '')
                        for n in d.get('nameservers', [])) or 'Not disclosed')]
            self.table(['Field', 'Value'], fields, color)
        self.table(['Hostname', 'Source', 'Pattern'],
                   [(r['name'], r['source'], 'Wildcard' if r['value'].get('wildcard')
                     else 'Exact') for r in by('subdomain')], color)
        self.table(['Name', 'Type', 'Answer', 'TTL', 'Resolver'],
                   [(r['name'], r['value']['rrtype'], r['value']['value'],
                     r['value']['ttl'], r['value']['resolver'])
                    for r in by('dns_record')], color)
        if by('dns_empty'):
            self.text(f"{len(by('dns_empty'))} queries had no records.", 'dim')
        for r in by('certificate'):
            d = r['value']
            self.table(['Field', 'Value'], [(k, v) for k, v in d.items()
                       if k != 'dns_names'], color)
            self.table(['Certificate DNS names — not automatically probed'],
                       [(v,) for v in d.get('dns_names', [])], color)
        self.table(['URL', 'Status', 'Content type', 'Server'],
                   [(r['name'], r['value']['status'], r['value']['content_type'],
                     r['value']['server']) for r in by('http_response')], color)
        self.table(['Page', 'Title'], [(r['name'], r['value']) for r in by('title')], color)
        self.table(['Redirect destination — not followed'],
                   [(r['value']['url'],) for r in by('redirect')], color)
        self.table(['Public metadata', 'Status'],
                   [(r['name'], r['value']['status']) for r in by('public_metadata')], color)
        hints, seen = [], set()
        for r in by('technology_hint'):
            pair = (r['value']['technology'], r['value']['evidence'])
            if pair not in seen:
                seen.add(pair)
                hints.append(pair)
        if hints:
            self.text('Technology hints — not verified', 'bright_green')
            self.table(['Hint', 'Evidence'], hints, 'bright_green')
        self.table(['Discovered URL'], [(r['name'],) for r in by('public_url')], color)
        self.table(['Candidate', 'DNS answers', 'Wildcard detected'],
                   [(r['name'], ', '.join(v for _, v in r['value']['records']),
                     r['value']['wildcard_detected'])
                    for r in by('subdomain_candidate')], color)
        self.table(['Path candidate', 'Status', 'Bytes sampled'],
                   [(r['name'], r['value']['status'], r['value']['bytes_sampled'])
                    for r in by('path_candidate')], color)
        self.table(['Historical URL — not live-verified'],
                   [(r['value']['url'],) for r in by('archived_url')], color)
        self.table(['Generated Google query'], [(r['value']['query'],) for r in by('dork')], color)
        self.table(['Search result', 'URL'],
                   [(r['value'].get('title'), r['value']['url'])
                    for r in by('search_result')], color)
        for kind in ('notice', 'warning', 'error'):
            for r in by(kind):
                value = r['value']
                message = value.get('message', value) if isinstance(value, dict) else value
                self.text(message, 'yellow' if kind == 'warning' else 'red'
                          if kind == 'error' else 'dim')
        if not any(r['type'] != 'check_status' for r in rows):
            self.text('Completed; no candidates found.', 'dim')
        state = self.status.get(module, 'ok')
        self.text('Status: ' + state.replace('_', ' '),
                  'green' if state in ('ok', 'cached') else 'yellow'
                  if state in ('partial', 'unavailable', 'interrupted') else 'red')
        if self.a.verbose:
            for r in rows:
                self.text(json.dumps(r, ensure_ascii=True), 'dim')

    def finish(self, elapsed):
        summary = dict(collections.Counter(self.status.values()))
        self.emit('run', 'summary', self.host,
                  {'modules': self.status, 'counts': dict(self.counts),
                   'elapsed_seconds': round(elapsed, 2)})
        if self.human:
            self.console.print()
            self.text('Finished in %.1fs · ' % elapsed + ' · '.join(
                f'{n} {status}' for status, n in summary.items()), 'bold')
        if self.a.output:
            self.stream.close()


class ProviderUnavailable(Exception):
    pass


class Cache:
    def __init__(self, args):
        self.root = Path(args.cache_dir)
        self.enabled = not args.no_cache

    @staticmethod
    def key(url, params):
        return hashlib.sha256(json.dumps([url, params], sort_keys=True).encode()).hexdigest()

    def read(self, url, params, max_age):
        if not self.enabled:
            return None
        try:
            item = json.loads((self.root / (self.key(url, params) + '.json')).read_text())
            age = time.time() - item['saved_at']
            if 0 <= age <= max_age:
                return item['data'], age
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return None

    def write(self, url, params, data):
        if not self.enabled:
            return
        temp = None
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            dest = self.root / (self.key(url, params) + '.json')
            temp = dest.with_name(dest.name + '.' + uuid.uuid4().hex + '.tmp')
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({'saved_at': time.time(), 'data': data}, f)
            os.replace(temp, dest)
        except OSError:
            pass
        finally:
            if temp is not None:
                try:
                    temp.unlink(missing_ok=True)
                except OSError:
                    pass


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.generators, self.title = set(), [], []
        self.inside = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and a.get('href'):
            self.links.add(a['href'])
        if tag == 'meta' and a.get('name', '').lower() == 'generator':
            self.generators.append(a.get('content', ''))
        if tag == 'title':
            self.inside = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.title.append(data)


class Recon:
    def __init__(self, args, reporter, url, host, registered, domain):
        import requests
        self.requests, self.a, self.r = requests, args, reporter
        self.url, self.host, self.registered, self.domain = url, host, registered, domain
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['User-Agent'] = 'EasyRecon/' + VERSION + ' (authorized assessment)'
        self.cache, self.last, self.current = Cache(args), 0.0, None

    def pause(self):
        time.sleep(max(0, self.a.delay - (time.monotonic() - self.last)))
        self.last = time.monotonic()

    def note(self, message, warning=False):
        self.r.emit(self.current, 'warning' if warning else 'notice', self.host,
                    {'message': message})

    def describe(self, exc):
        if isinstance(exc, self.requests.exceptions.Timeout):
            return 'timed out while waiting for the service'
        if isinstance(exc, self.requests.exceptions.SSLError):
            return 'TLS verification or handshake failed'
        if isinstance(exc, self.requests.exceptions.ConnectionError):
            return 'connection failed'
        message = str(exc)
        key = os.environ.get('SERPAPI_KEY')
        if key:
            message = message.replace(key, '[REDACTED]')
        return message[:1000]

    def read_response(self, response):
        raw, truncated = bytearray(), False
        for chunk in response.iter_content(16384):
            remaining = self.a.max_bytes - len(raw)
            if len(chunk) > remaining:
                raw.extend(chunk[:remaining])
                truncated = True
                break
            raw.extend(chunk)
        return bytes(raw), truncated

    def provider(self, url, params=None, text=False, cache=True, validate=None):
        cached = self.cache.read(url, params, FRESH_SECONDS) if cache else None
        if cached and (validate is None or validate(cached[0])):
            return cached[0], {'cached': True, 'age_seconds': int(cached[1])}
        failure = 'unavailable'
        for attempt in range(self.a.retries + 1):
            self.pause()
            retry, wait = False, min(2 ** (attempt + 1), 8)
            try:
                with self.session.get(
                    url, params=params, stream=True, allow_redirects=True,
                    timeout=(min(10, self.a.provider_timeout), self.a.provider_timeout)
                ) as response:
                    status = response.status_code
                    if status >= 400:
                        failure = f'HTTP {status}'
                        retry = status in (408, 429, 500, 502, 503, 504)
                        if status == 429:
                            header = response.headers.get('Retry-After', '')
                            retry_after = None
                            if header.isdigit():
                                retry_after = int(header)
                            elif header:
                                try:
                                    from email.utils import parsedate_to_datetime
                                    retry_after = max(0, int(
                                        parsedate_to_datetime(header).timestamp() - time.time()) + 1)
                                except (ValueError, TypeError, OverflowError):
                                    pass
                            if retry_after is not None:
                                if retry_after > 15:
                                    retry = False
                                else:
                                    wait = max(wait, retry_after)
                        if not retry:
                            raise ProviderUnavailable(failure)
                    else:
                        raw, truncated = self.read_response(response)
                        if truncated:
                            raise ProviderUnavailable('response exceeded the configured size limit')
                        data = raw.decode(response.encoding or 'utf-8', errors='replace') if text else json.loads(raw)
                        if validate is not None and not validate(data):
                            raise ProviderUnavailable('unexpected response format')
                        if cache:
                            self.cache.write(url, params, data)
                        return data, {'cached': False}
            except ProviderUnavailable:
                raise
            except (self.requests.exceptions.RequestException, ValueError) as exc:
                failure = self.describe(exc)
                retry = isinstance(exc, self.requests.exceptions.RequestException)
            if not retry or attempt >= self.a.retries:
                break
            if self.a.verbose:
                self.note(f'{urlsplit(url).hostname}: {failure}; retrying.')
            time.sleep(wait)
        raise ProviderUnavailable(failure)

    def stale(self, requests, validate=None):
        for url, params in requests:
            found = self.cache.read(url, params, STALE_SECONDS)
            if found:
                data, age = found
                if validate is not None and not validate(data):
                    continue
                self.note(f'Live sources unavailable. Using saved data from {age / 3600:.1f} '
                          'hours ago; not live-verified.', True)
                self.r.status[self.current] = 'partial'
                return data, url, {'cached': True, 'stale': True, 'age_seconds': int(age)}
        return None

    @staticmethod
    def valid_registration(data):
        return isinstance(data, dict) and any(
            k in data for k in ('ldhName', 'unicodeName', 'objectClassName'))

    def registration(self):
        if not self.registered:
            raise ProviderUnavailable('no registrable domain recognized by the bundled suffix list')
        domain = self.registered
        primary = 'https://rdap.org/domain/' + quote(domain, safe='')
        tried, failure = [(primary, None)], None
        valid = self.valid_registration
        try:
            data, meta = self.provider(primary, validate=valid)
        except ProviderUnavailable as exc:
            failure, data = str(exc), None
            try:
                bootstrap, _ = self.provider('https://data.iana.org/rdap/dns.json',
                    validate=lambda d: isinstance(d, dict) and isinstance(d.get('services'), list))
                matches = []
                for entries, bases in bootstrap.get('services', []):
                    for entry in entries:
                        entry = entry.lower().rstrip('.')
                        if entry and within(domain, entry):
                            matches.append((len(entry.split('.')), bases))
                bases = max(matches, key=lambda item: item[0])[1] if matches else []
                for base in bases:
                    if not base.startswith('https://'):
                        continue
                    endpoint = base.rstrip('/') + '/domain/' + quote(domain, safe='')
                    tried.append((endpoint, None))
                    try:
                        data, meta = self.provider(endpoint, validate=valid)
                        self.note('Registration retrieved directly from the registry '
                                  'after the routing service failed.')
                        break
                    except ProviderUnavailable:
                        continue
            except ProviderUnavailable:
                pass
            if data is None:
                saved = self.stale(tried, validate=valid)
                if saved:
                    data, _, meta = saved
                else:
                    raise ProviderUnavailable('registration service unavailable (' +
                                              failure + '); other checks continue')
        if meta.get('cached') and self.r.status.get(self.current) != 'partial':
            self.r.status[self.current] = 'cached'
            self.note('Using cached registration data.')
        self.r.emit('rdap', 'registration', domain, data)

    @staticmethod
    def valid_name_text(data):
        if not isinstance(data, str):
            return False
        try:
            for line in data.splitlines():
                if line.strip():
                    hostname(line.strip().removeprefix('*.'))
        except (ValueError, UnicodeError):
            return False
        return True

    @staticmethod
    def valid_ct_json(data):
        return isinstance(data, list) and all(isinstance(row, dict) for row in data)

    def subdomains(self):
        sources = [
            ('crt.name', 'https://crt.name/v1/search', {'apex': self.registered}, True),
            ('crt.sh', 'https://crt.sh/', {'q': '%.' + self.domain, 'output': 'json'}, False)]
        if self.a.subdomain_source == 'crtname':
            sources = sources[:1]
        elif self.a.subdomain_source == 'crtsh':
            sources = sources[1:]
        tried, failures, data, meta, label = [], [], None, {}, None
        for label, url, params, is_text in sources:
            if label == 'crt.name' and (not self.registered or self.domain != self.registered):
                continue
            tried.append((url, params))
            valid = self.valid_name_text if is_text else self.valid_ct_json
            try:
                data, meta = self.provider(url, params, text=is_text, validate=valid)
                break
            except ProviderUnavailable as exc:
                failures.append(label + ': ' + str(exc))
                data = None
        if data is None:
            saved = self.stale(tried, validate=lambda d:
                               self.valid_name_text(d) if isinstance(d, str) else self.valid_ct_json(d))
            if saved:
                data, url, meta = saved
                label = 'crt.name' if urlsplit(url).hostname == 'crt.name' else 'crt.sh'
            else:
                detail = '; '.join(failures) or 'selected source does not support this discovery scope'
                raise ProviderUnavailable('public subdomain sources unavailable; ' + detail)
        if failures:
            self.note('Selected source: ' + label + '. Earlier source: ' + '; '.join(failures))
        if meta.get('cached') and self.r.status.get(self.current) != 'partial':
            self.r.status[self.current] = 'cached'
            self.note('Using cached subdomain data.')
        if label == 'crt.name':
            entries = [(line.strip(), {}) for line in data.splitlines() if line.strip()]
        else:
            entries = []
            for row in data:
                names = row.get('name_value', '')
                if isinstance(names, str):
                    entries.extend((name, row) for name in names.splitlines())
        seen = set()
        for raw, record in entries:
            wildcard = raw.startswith('*.')
            try:
                name = hostname(raw.removeprefix('*.'))
            except (ValueError, UnicodeError):
                continue
            if not within(name, self.domain) or (name, wildcard) in seen:
                continue
            seen.add((name, wildcard))
            self.r.emit(label, 'subdomain', name,
                {'wildcard': wildcard, 'live_verified': False, 'cache': meta,
                 'not_before': record.get('not_before'), 'not_after': record.get('not_after'),
                 'issuer': record.get('issuer_name')})
        self.note(f'{len(seen)} unique name/pattern candidate(s). '
                  'Historical index results are not live-host confirmation.')

    def target_get(self, url):
        if not same_origin(self.url, url):
            raise ValueError('off-origin request blocked')
        self.pause()
        with self.session.get(url, timeout=self.a.timeout,
                              allow_redirects=False, stream=True) as response:
            raw, truncated = self.read_response(response)
            return {'status': response.status_code, 'headers': dict(response.headers),
                    'text': raw.decode(response.encoding or 'utf-8', errors='replace'),
                    'bytes': len(raw), 'truncated': truncated}

    def hint(self, url, name, evidence):
        self.r.emit('fingerprint', 'technology_hint', url,
                    {'technology': name, 'evidence': evidence, 'verified': False})

    def inspect(self, url, data):
        h = {k.lower(): v for k, v in data['headers'].items()}
        self.r.emit('http', 'http_response', url,
            {'status': data['status'], 'headers': data['headers'],
             'content_type': h.get('content-type', '—'), 'server': h.get('server', '—'),
             'truncated': data['truncated']})
        if h.get('location'):
            self.r.emit('http', 'redirect', url,
                        {'url': urljoin(url, h['location']), 'followed': False})
        for key in ('server', 'x-powered-by', 'x-generator', 'x-aspnet-version'):
            if h.get(key):
                self.hint(url, h[key], key)
        page = Page()
        if 'html' not in h.get('content-type', '').lower():
            return page
        page.feed(data['text'])
        if page.title:
            self.r.emit('http', 'title', url, ''.join(page.title).strip())
        for generator in page.generators:
            self.hint(url, generator, 'meta generator')
        patterns = {'WordPress': r'wp-content/|wp-includes/',
                    'Drupal': r'Drupal\.settings|drupalSettings',
                    'Next.js': r'/_next/|__NEXT_DATA__', 'Nuxt': r'/_nuxt/|__NUXT__',
                    'Angular': r'ng-version=', 'React': r'data-reactroot',
                    'Django': r'csrfmiddlewaretoken'}
        for name, pattern in patterns.items():
            if re.search(pattern, data['text'], re.I):
                self.hint(url, name, pattern)
        if data['truncated']:
            self.note('HTML body truncated at --max-bytes; analysis may be incomplete.', True)
            self.r.status[self.current] = 'partial'
        return page

    def http(self):
        targets = [(self.url, False)]
        if self.a.metadata:
            targets += [(urljoin(self.url, '/robots.txt'), True),
                        (urljoin(self.url, '/sitemap.xml'), True)]
        failures = []
        for url, metadata in targets:
            try:
                data = self.target_get(url)
                if metadata:
                    self.r.emit('http', 'public_metadata', url,
                        {'status': data['status'], 'truncated': data['truncated'],
                         'text_sample': data['text'][:12000]})
                else:
                    self.inspect(url, data)
            except Exception as exc:
                failures.append(url)
                self.note(url + ': ' + self.describe(exc) + '; check incomplete.', True)
        if failures:
            self.r.status[self.current] = 'unavailable' if len(failures) == len(targets) else 'partial'

    def tls(self):
        p = urlsplit(self.url)
        if p.scheme != 'https':
            self.note('HTTP target: no implicit TLS probe.')
            return
        self.pause()
        with socket.create_connection((self.host, p.port or 443), timeout=self.a.timeout) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) as conn:
                c = conn.getpeercert()
                flat = lambda groups: ', '.join(f'{k}={v}' for group in groups for k, v in group)
                cipher = conn.cipher()
                self.r.emit('tls', 'certificate', self.host,
                    {'protocol': conn.version(), 'cipher': cipher[0] if cipher else None,
                     'subject': flat(c.get('subject', [])), 'issuer': flat(c.get('issuer', [])),
                     'valid_from': c.get('notBefore'), 'valid_until': c.get('notAfter'),
                     'verification': 'passed',
                     'dns_names': [v for k, v in c.get('subjectAltName', []) if k == 'DNS']})

    def resolvers(self):
        import dns.resolver
        for ip in self.a.resolver or [None]:
            resolver = dns.resolver.Resolver(configure=ip is None)
            if ip:
                resolver.nameservers = [ip]
            resolver.timeout = resolver.lifetime = self.a.timeout
            yield ip or 'system', resolver

    def resolve(self, resolver, name, kind):
        self.pause()
        return resolver.resolve(name, kind, lifetime=self.a.timeout, search=False)

    def dns(self):
        import dns.resolver
        failures = 0
        for label, resolver in self.resolvers():
            for kind in self.a.dns_types.split(','):
                kind = kind.strip().upper()
                try:
                    answers = self.resolve(resolver, self.host, kind)
                    for value in answers:
                        self.r.emit('dns', 'dns_record', self.host,
                            {'rrtype': kind, 'value': value.to_text(),
                             'ttl': answers.rrset.ttl, 'resolver': label})
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
                    self.r.emit('dns', 'dns_empty', self.host,
                        {'rrtype': kind, 'resolver': label, 'reason': type(exc).__name__})
                except Exception as exc:
                    failures += 1
                    self.note(f'{kind} via {label}: ' + self.describe(exc), True)
        if failures:
            self.r.status[self.current] = 'partial'

    def crawl(self):
        queue, visited, found = deque([self.url]), set(), set()
        while queue and len(visited) < self.a.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                page = self.inspect(url, self.target_get(url))
                for link in sorted(page.links):
                    p = urlsplit(urljoin(url, link))
                    full = urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))
                    if not same_origin(self.url, full):
                        continue
                    if full not in found:
                        found.add(full)
                        self.r.emit('crawl', 'public_url', full,
                                    {'found_on': url, 'fetched_at_discovery': False})
                    if p.query or re.search(r'logout|signout|delete|remove|unsubscribe', p.path, re.I):
                        continue
                    if re.search(r'\.(?:png|jpe?g|gif|svg|webp|ico|css|js|pdf|zip|mp4|woff2?)$', p.path, re.I):
                        continue
                    if full not in visited and len(queue) < self.a.max_pages * 10:
                        queue.append(full)
            except Exception as exc:
                self.note(url + ': ' + self.describe(exc), True)
                self.r.status[self.current] = 'partial'

    def words(self, filename):
        n = 0
        with open(filename, encoding='utf-8') as file:
            for line in file:
                word = line.strip()
                if not word or word.startswith('#'):
                    continue
                if n >= self.a.max_words:
                    self.note(f'Stopped at {n} wordlist entries.')
                    break
                n += 1
                yield word

    def dns_brute(self):
        import dns.resolver
        label, resolver = next(self.resolvers())
        def answers(name):
            records = set()
            for kind in ('A', 'AAAA', 'CNAME'):
                try:
                    records.update((kind, str(v)) for v in self.resolve(resolver, name, kind))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
            return sorted(records)
        samples = [answers(uuid.uuid4().hex + '.' + self.host) for _ in range(2)]
        wildcard = any(samples)
        self.note('Wildcard DNS ' + ('detected; candidates require review.'
                  if wildcard else 'not observed in random samples.'))
        for prefix in self.words(self.a.dns_wordlist):
            try:
                name = hostname(prefix + '.' + self.host)
                records = answers(name)
                if records:
                    self.r.emit('dns', 'subdomain_candidate', name,
                        {'records': records, 'resolver': label, 'wildcard_detected': wildcard,
                         'matches_baseline': records in samples})
            except Exception as exc:
                self.note(prefix + ': ' + self.describe(exc), True)
                self.r.status[self.current] = 'partial'

    def paths(self):
        origin = urlunsplit((*urlsplit(self.url)[:2], '/', '', ''))
        def signature(data, path):
            text = data['text'].replace(path, '<PATH>').replace(quote(path, safe=''), '<PATH>')
            return data['status'], hashlib.sha256(re.sub(r'\s+', ' ', text).encode()).hexdigest()
        baselines = []
        for _ in range(2):
            path = '/' + uuid.uuid4().hex
            baselines.append(signature(self.target_get(urljoin(origin, path)), path))
        for word in self.words(self.a.path_wordlist):
            path = '/' + word.lstrip('/')
            if (not re.fullmatch(r'/[A-Za-z0-9_./~-]+', path)
                    or '..' in path.split('/') or path.startswith('//')):
                self.note('Skipped unsupported path: ' + word)
                continue
            url = urljoin(origin, path)
            try:
                data = self.target_get(url)
                if data['status'] not in (404, 410) and signature(data, path) not in baselines:
                    self.r.emit('paths', 'path_candidate', url,
                        {'status': data['status'], 'bytes_sampled': data['bytes'],
                         'truncated': data['truncated'], 'existence_confirmed': False})
            except Exception as exc:
                self.note(url + ': ' + self.describe(exc), True)
                self.r.status[self.current] = 'partial'

    def archive(self):
        rows, meta = self.provider('https://web.archive.org/cdx/search/cdx',
            {'url': self.domain, 'matchType': 'domain', 'output': 'json',
             'fl': 'original', 'collapse': 'urlkey', 'limit': self.a.archive_limit},
            validate=lambda d: isinstance(d, list) and all(isinstance(row, list) for row in d))
        seen = set()
        for row in rows[1:]:
            if not row or not isinstance(row[0], str):
                continue
            p = urlsplit(row[0])
            if (p.scheme in ('http', 'https') and p.hostname
                    and within(p.hostname.lower(), self.domain) and row[0] not in seen):
                seen.add(row[0])
                self.r.emit('wayback', 'archived_url', p.hostname,
                            {'url': row[0], 'live_verified': False, 'cache': meta})
        if meta.get('cached'):
            self.r.status[self.current] = 'cached'
            self.note('Using cached archive metadata.')

    def dorks(self):
        queries = [
            f'site:{self.domain} (filetype:pdf OR filetype:docx OR filetype:xlsx)',
            f'site:{self.domain} intitle:"index of"',
            f'site:{self.domain} (ext:bak OR ext:old OR ext:log OR ext:sql)',
            f'site:{self.domain} (inurl:admin OR inurl:login)',
            f'site:{self.domain} ("confidential" OR "internal use only")']
        for query in queries:
            self.r.emit('google', 'dork', self.domain,
                        {'query': query, 'url': 'https://www.google.com/search?' + urlencode({'q': query})})
        if not self.a.google_search:
            self.note('Queries generated only; searches were not executed.')
            return
        key = os.environ.get('SERPAPI_KEY')
        if not key:
            raise ProviderUnavailable('Google retrieval needs SERPAPI_KEY; '
                                      'queries were generated, but not executed')
        for query in queries:
            data, _ = self.provider('https://serpapi.com/search.json',
                {'engine': 'google', 'q': query, 'api_key': key}, cache=False,
                validate=lambda d: isinstance(d, dict))
            if data.get('error'):
                raise ProviderUnavailable(self.describe(ValueError(data['error'])))
            for item in data.get('organic_results', []):
                link = item.get('link', '')
                host = urlsplit(link).hostname
                if host and within(host.lower(), self.domain):
                    self.r.emit('google', 'search_result', host,
                        {'title': item.get('title'), 'url': link, 'snippet': item.get('snippet'),
                         'exposure_confirmed': False})


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if '--help-all' in argv:
        parser(True).print_help()
        return 0
    p = parser()
    a = p.parse_args(argv)
    # Defensive normalization as well as the parser-level default.
    a.color = a.color or 'auto'
    if a.target and a.url and a.target != a.url:
        p.error('provide the target once: as a domain/URL or with -u')
    target = a.url or a.target
    if not target:
        p.print_help()
        return 2
    modules = choose_modules(a, p)
    try:
        url, host = normalize(target)
        for ip in a.resolver or []:
            ipaddress.ip_address(ip)
        import requests
        import tldextract
        if a.format is None:
            suffix = Path(a.output).suffix.lower() if a.output else ''
            a.format = 'jsonl' if suffix in ('.jsonl', '.ndjson') else 'tsv' if suffix == '.tsv' else 'pretty'
        if a.format in ('pretty', 'text'):
            import rich
        if set(modules) & {'dns', 'dns-brute'}:
            import dns.resolver
            import dns.rdatatype
            for kind in a.dns_types.split(','):
                dns.rdatatype.from_text(kind.strip().upper())
        registered, discovery = derive_scopes(host)
        if a.domain:
            discovery = hostname(a.domain)
            if not within(host, discovery):
                p.error('--domain must equal or be a parent of the input hostname')
    except ImportError as exc:
        p.error(f'missing dependency ({exc}); run: '
                'python3 -m pip install requests dnspython tldextract rich')
    except (ValueError, UnicodeError) as exc:
        p.error(str(exc))
    for filename in (a.dns_wordlist, a.path_wordlist):
        if filename and not Path(filename).is_file():
            p.error('wordlist not found: ' + filename)
        if filename and a.output and Path(filename).resolve() == Path(a.output).resolve():
            p.error('output cannot overwrite a wordlist')
    mode = ('mixed' if set(modules) & ACTIVE and set(modules) - ACTIVE
            else 'active' if set(modules) & ACTIVE else 'passive')
    try:
        r = Reporter(a, host, mode)
    except OSError as exc:
        p.error('cannot open output file: ' + str(exc))
    recon = Recon(a, r, url, host, registered, discovery)
    start, interrupted = time.monotonic(), False
    if r.human:
        r.text('EasyRecon ' + VERSION, 'bold white')
        r.text('Target       ' + url)
        r.text('Registration ' + str(registered or 'not recognized'), 'dim')
        r.text('Discovery    ' + discovery, 'dim')
        r.text('Checks       ' + ', '.join(modules), 'dim')
        if set(modules) & ACTIVE:
            r.text('Direct target requests enabled. Authorization is required.', 'yellow')
    else:
        r.emit('run', 'scope', host, {'url': url, 'registered_domain': registered,
               'discovery_domain': discovery, 'modules': modules, 'mode': mode})
    try:
        for module in modules:
            recon.current = module
            r.status[module] = 'ok'
            r.begin(module)
            try:
                if r.human and r.console.is_terminal:
                    with r.console.status('Running ' + LABEL[module].lower() + '…', spinner='dots'):
                        getattr(recon, module.replace('-', '_'))()
                else:
                    getattr(recon, module.replace('-', '_'))()
            except KeyboardInterrupt:
                r.status[module] = 'interrupted'
                raise
            except ProviderUnavailable as exc:
                r.status[module] = 'unavailable'
                recon.note(str(exc), True)
            except Exception as exc:
                r.status[module] = 'failed'
                r.emit(module, 'error', host, {'message': recon.describe(exc),
                                             'exception': type(exc).__name__})
            finally:
                r.emit(module, 'check_status', host, {'status': r.status[module]})
                r.render(module)
    except KeyboardInterrupt:
        interrupted = True
        if recon.current:
            r.status[recon.current] = 'interrupted'
    finally:
        recon.session.close()
        failed = any(status in ('unavailable', 'failed', 'partial', 'interrupted')
                     for status in r.status.values())
        r.finish(time.monotonic() - start)
    return 130 if interrupted else 1 if failed else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)
