#!/usr/bin/env python3
"""Scoped, rate-limited website reconnaissance. Python 3.10+."""
import argparse
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
from collections import Counter, deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

requests = None
DEFAULT_TYPES = "A,AAAA,MX,NS,TXT,SOA,CAA,CNAME,HTTPS,SVCB"
MODULES = {"passive": {"rdap", "ct", "archive", "dorks"},
           "active": {"dns", "tls", "http", "crawl", "subdomains", "paths"}}


def positive(value):
    n = float(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return n


def nonnegative(value):
    n = float(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return n


def positive_int(value):
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return n


def hostname(value):
    name = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(name) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                                  for x in name.split('.')):
        raise ValueError("invalid DNS hostname")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("provide a DNS hostname, not an IP address")


def target_url(value):
    p = urlsplit(value if '://' in value else 'https://' + value)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError("target must be an HTTP(S) URL or hostname, without credentials")
    host = hostname(p.hostname)
    port = p.port
    netloc = host + (f':{port}' if port is not None else '')
    return urlunsplit((p.scheme, netloc, p.path or '/', p.query, '')), host


def same_origin(a, b):
    def origin(url):
        p = urlsplit(url)
        return (p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80))
    try:
        p = urlsplit(b)
        return p.username is None and p.password is None and origin(a) == origin(b)
    except ValueError:
        return False


def under(name, domain):
    return name == domain or name.endswith('.' + domain)


class Reporter:
    """Human-readable presentation; stable JSONL/TSV for automation."""
    COLORS = {'registration': '36', 'subdomains': '35', 'dns': '94', 'tls': '32',
              'http': '33', 'technologies': '92', 'crawl': '96', 'paths': '91',
              'archive': '90', 'dorks': '38;5;208', 'errors': '31', 'notes': '37'}
    LABELS = {'registration': 'DOMAIN REGISTRATION', 'subdomains': 'SUBDOMAINS',
              'dns': 'DNS RECORDS', 'tls': 'TLS CERTIFICATE', 'http': 'HTTP OVERVIEW',
              'technologies': 'TECHNOLOGY HINTS', 'crawl': 'PUBLIC URLS',
              'paths': 'PATH CANDIDATES', 'archive': 'WAYBACK — OPT-IN',
              'dorks': 'GOOGLE DORKS — OPT-IN', 'errors': 'ERRORS', 'notes': 'NOTES'}

    def __init__(self, a, target):
        import collections, os, shutil, sys
        self.a, self.target, self.mode = a, target, a.mode
        self.fmt = a.format
        self.human = self.fmt in ('pretty', 'text')
        self.owned = bool(a.output)
        self.stream = open(a.output, 'w', encoding='utf-8') if a.output else sys.stdout
        self.counts = collections.Counter()
        self.pending = []
        self.current = None
        self.last_heading = None
        self.started = False
        self.finished = False
        self.width = max(60, min(150, shutil.get_terminal_size((110, 24)).columns))
        color = getattr(a, 'color', 'auto')
        self.color = self.human and (color == 'always' or
            (color == 'auto' and self.stream.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'))
        if self.fmt == 'tsv':
            self.stream.write('time\tmode\ttarget\tsource\ttype\tname\tvalue\n')

    @staticmethod
    def safe(value):
        import re
        if value is None:
            return '—'
        text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(value))
        return ''.join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159 else ' ' for c in text)

    def line(self, value='', category=None, bold=False):
        text = self.safe(value)
        if self.color and category:
            code = self.COLORS[category]
            text = '\033[' + ('1;' if bold else '') + code + 'm' + text + '\033[0m'
        self.stream.write(text + '\n')

    def heading(self, category):
        if self.last_heading != category:
            self.line()
            title = self.LABELS[category]
            self.line('── ' + title + ' ' + '─' * max(2, self.width - len(title) - 5), category, True)
            self.last_heading = category

    def banner(self, url, modules):
        if self.human and not self.started:
            self.line('SCOPED RECON', 'notes', True)
            self.line('Target   ' + self.safe(url))
            self.line('Mode     ' + self.mode)
            self.line('Modules  ' + ', '.join(modules))
            self.started = True

    def begin(self, module):
        self.current = module
        if self.human:
            category = {'rdap': 'registration', 'ct': 'subdomains', 'subdomains': 'subdomains'}.get(module, module)
            if category in self.LABELS:
                self.heading(category)

    def emit(self, source, kind, name, value):
        import datetime, json
        record = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'mode': self.mode,
                  'target': self.target, 'source': source, 'type': kind, 'name': name, 'value': value}
        self.counts[kind] += 1
        if not self.human:
            if self.fmt == 'jsonl':
                self.stream.write(json.dumps(record, ensure_ascii=True) + '\n')
            else:
                def cell(v):
                    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=True)
                    return ''.join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159 else f'\\x{ord(c):02x}'
                                   for c in s.replace('\\', '\\\\'))
                self.stream.write('\t'.join(cell(record[k]) for k in
                    ('time', 'mode', 'target', 'source', 'type', 'name', 'value')) + '\n')
            self.stream.flush()
            return
        if kind == 'scope':
            self.banner(value.get('url', self.target), value.get('modules', []))
        elif kind == 'summary':
            self.flush()
            self.end(value.get('errors', self.counts['error']), value.get('interrupted', False))
        else:
            self.pending.append(record)

    def table(self, category, headers, rows):
        import textwrap
        if not rows:
            return
        self.heading(category)
        limit = getattr(self.a, 'display_limit', 30)
        data = [[self.safe(v) for v in row] for row in rows[:limit]]
        widths = [max(len(h), min(65, max((len(row[i]) for row in data), default=0))) for i, h in enumerate(headers)]
        budget = self.width - (3 * len(headers) + 1)
        while sum(widths) > budget:
            i = max(range(len(widths)), key=lambda i: widths[i])
            if widths[i] <= 7:
                break
            widths[i] -= 1
        border = lambda left, middle, right: left + middle.join('─' * (w + 2) for w in widths) + right
        self.line(border('╭', '┬', '╮'), category)
        self.line('│ ' + ' │ '.join(h.ljust(w) for h, w in zip(headers, widths)) + ' │', category, True)
        self.line(border('├', '┼', '┤'), category)
        for row in data:
            lines = [textwrap.wrap(v, width=w, break_long_words=True, break_on_hyphens=False) or [''] for v, w in zip(row, widths)]
            for j in range(max(map(len, lines))):
                self.line('│ ' + ' │ '.join((parts[j] if j < len(parts) else '').ljust(w)
                          for parts, w in zip(lines, widths)) + ' │')
        self.line(border('╰', '┴', '╯'), category)
        if len(rows) > limit:
            self.line(f'  Showing {limit} of {len(rows)} rows. Increase --display-limit or export JSONL/TSV.', category)

    def flush(self):
        import json
        if not self.human:
            return
        rows, self.pending = self.pending, []
        by = lambda kind: [r for r in rows if r['type'] == kind]
        rendered = False
        def table(category, headers, values):
            nonlocal rendered
            values = list(values)
            if values:
                rendered = True
                self.table(category, headers, values)
        for r in by('registration'):
            d = r['value']
            registrar = 'Not disclosed'
            for e in d.get('entities', []):
                if 'registrar' in e.get('roles', []):
                    registrar = e.get('handle', registrar)
                    card = e.get('vcardArray') or [None, []]
                    for v in card[1] if len(card) > 1 else []:
                        if len(v) > 3 and v[0] == 'fn':
                            registrar = v[3]
            fields = [('Domain', d.get('ldhName', r['name'])), ('Registrar', registrar),
                      ('Status', ', '.join(d.get('status', [])) or 'Not disclosed')]
            fields += [(e.get('eventAction', 'Event').capitalize(), e.get('eventDate', '—')) for e in d.get('events', [])]
            fields += [('Nameservers', ', '.join(n.get('ldhName', '') for n in d.get('nameservers', [])) or 'Not disclosed')]
            table('registration', ['Field', 'Value'], fields)
        table('subdomains', ['Hostname', 'Pattern', 'Certificate expires'],
              [(r['name'], 'Wildcard' if r['value'].get('wildcard') else 'Exact', r['value'].get('not_after')) for r in by('subdomain')])
        table('dns', ['Name', 'Type', 'Answer', 'TTL', 'Resolver'],
              [(r['name'], r['value'].get('rrtype'), r['value'].get('value'), r['value'].get('ttl'), r['value'].get('resolver')) for r in by('dns_record')])
        if by('dns_empty'):
            self.line(f"  {len(by('dns_empty'))} DNS queries had no records. Details: --verbose.", 'dns')
            rendered = True
        for r in by('certificate'):
            d = r['value']; c = d.get('certificate', {})
            flat = lambda items: ', '.join(f'{k}={v}' for group in items for k, v in group)
            table('tls', ['Field', 'Value'], [('Host', r['name']), ('Protocol', d.get('protocol')),
                  ('Cipher', (d.get('cipher') or ['—'])[0]), ('Subject', flat(c.get('subject', []))),
                  ('Issuer', flat(c.get('issuer', []))), ('Valid from', c.get('notBefore')),
                  ('Valid until', c.get('notAfter')), ('Verification', 'Passed')])
        table('tls', ['Certificate DNS names'], [(r['name'],) for r in by('certificate_name')])
        http = []
        for r in by('http_response'):
            d = r['value']; h = {k.lower(): v for k, v in d.get('headers', {}).items()}
            http.append((r['name'], d.get('status'), d.get('content_type', h.get('content-type', '—')), d.get('server', h.get('server', '—'))))
        table('http', ['URL', 'Status', 'Content type', 'Server'], http)
        table('http', ['Page', 'Title'], [(r['name'], r['value']) for r in by('title')])
        table('http', ['From', 'Redirect — not followed'], [(r['name'], r['value'].get('url')) for r in by('redirect')])
        table('http', ['Public metadata', 'Status'], [(r['name'], r['value'].get('status')) for r in by('public_metadata')])
        table('http', ['robots.txt directive', 'Value'], [(r['value'].get('directive'), r['value'].get('value')) for r in by('robots_rule')])
        hints, seen = [], set()
        for r in by('technology_hint'):
            d = r['value']
            pair = (d.get('technology', d.get('value', 'Unknown')), d.get('evidence', 'Heuristic'))
            if pair not in seen:
                hints.append(pair); seen.add(pair)
        table('technologies', ['Technology / header hint', 'Evidence — not verified'], hints)
        table('crawl', ['Discovered public URL'], [(r['name'],) for r in by('public_url')])
        table('subdomains', ['Candidate hostname', 'DNS answers', 'Wildcard detected'],
              [(r['name'], ', '.join(str(v) for _, v in r['value'].get('records', [])), r['value'].get('wildcard_detected')) for r in by('subdomain_candidate')])
        table('paths', ['Path candidate', 'Status', 'Sampled bytes'],
              [(r['name'], r['value'].get('status'), r['value'].get('bytes_sampled')) for r in by('path_candidate')])
        table('archive', ['Historical URL — not live-verified'], [(r['value'].get('url'),) for r in by('archived_url')])
        table('dorks', ['Google query — generated'], [(r['value'].get('query'),) for r in by('dork')])
        table('dorks', ['Search result', 'URL'], [(r['value'].get('title'), r['value'].get('url')) for r in by('search_result')])
        for r in by('wildcard_check'):
            self.line('  Wildcard DNS: ' + ('detected; results require review' if r['value'].get('detected') else 'not observed in random samples'), 'subdomains')
            rendered = True
        for r in by('error'):
            message = r['value'].get('message', r['value']) if isinstance(r['value'], dict) else r['value']
            self.line('  ERROR: ' + self.safe(r['name']) + ' — ' + self.safe(message), 'errors')
            rendered = True
        for r in by('skipped') + by('limit') + by('interrupted'):
            self.line('  ' + self.safe(r['name']) + ': ' + self.safe(r['value']), 'notes')
            rendered = True
        if not rendered:
            self.line('  No findings returned.', 'notes')
        if getattr(self.a, 'verbose', False):
            self.line('  RAW EVIDENCE (--verbose)', 'notes')
            for r in rows:
                self.line(json.dumps(r, ensure_ascii=True), 'notes')
        self.stream.flush()

    def render(self, module=None):
        self.flush()

    def end(self, errors=0, interrupted=False, elapsed=None):
        if not self.finished:
            self.line()
            label = 'Interrupted' if interrupted else 'Finished'
            suffix = f' in {elapsed:.1f}s' if elapsed is not None else ''
            self.line(f'{label}{suffix} · {errors} error(s)', 'errors' if errors or interrupted else 'tls', True)
            self.finished = True

    def finish(self, elapsed, interrupted=False):
        self.flush()
        errors = self.counts['error']
        if self.human:
            self.end(errors, interrupted, elapsed)
        else:
            self.emit('run', 'summary', self.target, {'errors': errors, 'counts': dict(self.counts),
                      'elapsed_seconds': round(elapsed, 2), 'interrupted': interrupted})
        self.close()

    def close(self):
        if self.stream.closed:
            return
        if self.human and not self.finished:
            self.flush()
            self.end(self.counts['error'])
        if self.owned:
            self.stream.close()


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls, self.generators, self.title = set(), [], []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('a', 'link', 'script', 'img', 'iframe', 'form'):
            for key in ('href', 'src', 'action'):
                if a.get(key):
                    self.urls.add(a[key])
        if tag == 'meta' and a.get('name', '').lower() == 'generator':
            self.generators.append(a.get('content', ''))
        if tag == 'title':
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)


class Recon:
    def __init__(self, args, report, url, host, domain):
        self.a, self.r, self.url, self.host, self.domain = args, report, url, host, domain
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['User-Agent'] = 'ScopedRecon/1.0 (authorized security assessment)'
        self.last = 0.0
        self.limit = args.max_bytes

    def pause(self):
        time.sleep(max(0.0, self.a.delay - (time.monotonic() - self.last)))
        self.last = time.monotonic()

    def get(self, url, params=None, third_party=False):
        if not third_party and not same_origin(self.url, url):
            raise ValueError('off-origin HTTP request blocked')
        self.pause()
        with self.session.get(url, params=params, timeout=self.a.timeout, stream=True,
                              allow_redirects=third_party) as response:
            raw = bytearray()
            truncated = False
            for chunk in response.iter_content(16384):
                if len(raw) + len(chunk) > self.limit:
                    raw.extend(chunk[:self.limit-len(raw)])
                    truncated = True
                    break
                raw.extend(chunk)
            data = dict(url=response.url, status=response.status_code, headers=dict(response.headers),
                        raw=bytes(raw), truncated=truncated,
                        text=bytes(raw).decode(response.encoding or 'utf-8', errors='replace'))
            if third_party and not response.ok:
                raise RuntimeError(f'HTTP {response.status_code} from third-party service')
            return data

    def api(self, url, params=None):
        data = self.get(url, params, third_party=True)
        if data['truncated']:
            raise ValueError('API response exceeded --max-bytes; increase the limit')
        return json.loads(data['text'])

    def error(self, source, name, exc):
        # Do not expose request URLs containing API keys in exceptions.
        message = str(exc)
        key = os.environ.get('SERPAPI_KEY', '')
        if key:
            message = message.replace(key, '[REDACTED]')
        self.r.emit(source, 'error', name, {'exception': type(exc).__name__, 'message': message[:1000]})

    def rdap(self):
        data = self.api('https://rdap.org/domain/' + quote(self.domain, safe=''))
        self.r.emit('rdap', 'registration', self.domain, data)

    def ct(self):
        data = self.api('https://crt.sh/', {'q': '%.' + self.domain, 'output': 'json'})
        seen = set()
        for row in data:
            for raw in row.get('name_value', '').splitlines():
                wildcard = raw.startswith('*.')
                try:
                    name = hostname(raw.removeprefix('*.'))
                except ValueError:
                    continue
                if not under(name, self.domain):
                    continue
                key = (name, wildcard)
                if key in seen:
                    continue
                seen.add(key)
                self.r.emit('crt.sh', 'subdomain', name, {'wildcard': wildcard, 'cert_id': row.get('id'),
                            'not_before': row.get('not_before'), 'not_after': row.get('not_after'),
                            'issuer': row.get('issuer_name'), 'live_verified': False})

    def archive(self):
        rows = self.api('https://web.archive.org/cdx/search/cdx',
                        {'url': self.domain, 'matchType': 'domain', 'output': 'json',
                         'fl': 'original', 'collapse': 'urlkey', 'limit': self.a.archive_limit})
        seen = set()
        for row in rows[1:]:
            if not row:
                continue
            url = row[0]
            p = urlsplit(url)
            if p.scheme in ('http', 'https') and p.hostname and under(p.hostname.lower(), self.domain) and url not in seen:
                seen.add(url)
                self.r.emit('wayback', 'archived_url', p.hostname, {'url': url, 'live_verified': False})

    def dorks(self):
        queries = [f'site:{self.domain} (filetype:pdf OR filetype:docx OR filetype:xlsx)',
                   f'site:{self.domain} intitle:"index of"',
                   f'site:{self.domain} (ext:bak OR ext:old OR ext:log OR ext:sql)',
                   f'site:{self.domain} (inurl:admin OR inurl:login OR inurl:dashboard)',
                   f'site:{self.domain} ("confidential" OR "internal use only")']
        for query in queries:
            self.r.emit('google', 'dork', self.domain,
                        {'query': query, 'url': 'https://www.google.com/search?' + urlencode({'q': query})})
        if not self.a.google_search:
            return
        key = os.environ.get('SERPAPI_KEY')
        if not key:
            raise ValueError('--google-search needs SERPAPI_KEY in the environment')
        for query in queries:
            data = self.api('https://serpapi.com/search.json',
                            {'engine': 'google', 'q': query, 'api_key': key})
            if data.get('error'):
                raise ValueError(data['error'])
            for item in data.get('organic_results', []):
                link = item.get('link', '')
                h = urlsplit(link).hostname
                if h and under(h.lower(), self.domain):
                    self.r.emit('google', 'search_result', h,
                                {'query': query, 'url': link, 'title': item.get('title'),
                                 'snippet': item.get('snippet'), 'exposure_confirmed': False})

    def resolvers(self):
        import dns.resolver
        servers = self.a.resolver or [None]
        for address in servers:
            resolver = dns.resolver.Resolver(configure=address is None)
            if address:
                resolver.nameservers = [address]
            resolver.timeout = self.a.timeout
            resolver.lifetime = self.a.timeout
            yield address or 'system', resolver

    def resolve(self, resolver, name, kind):
        self.pause()
        return resolver.resolve(name, kind, lifetime=self.a.timeout, search=False)

    def dns(self):
        import dns.resolver
        for label, resolver in self.resolvers():
            for kind in self.a.dns_types.split(','):
                kind = kind.strip().upper()
                name = self.host
                try:
                    answer = self.resolve(resolver, name, kind)
                    for item in answer:
                        self.r.emit('dns', 'dns_record', name, {'resolver': label, 'rrtype': kind,
                                    'ttl': answer.rrset.ttl, 'value': item.to_text()})
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
                    self.r.emit('dns', 'dns_empty', name, {'resolver': label, 'rrtype': kind,
                                                        'reason': type(exc).__name__})
                except Exception as exc:
                    self.error('dns', f'{name} {kind} via {label}', exc)

    def tls(self):
        p = urlsplit(self.url)
        if p.scheme != 'https':
            self.r.emit('tls', 'skipped', self.host, 'HTTP target: no implicit TLS probe')
            return
        self.pause()
        context = ssl.create_default_context()
        with socket.create_connection((self.host, p.port or 443), timeout=self.a.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as conn:
                cert = conn.getpeercert()
                self.r.emit('tls', 'certificate', self.host,
                            {'protocol': conn.version(), 'cipher': conn.cipher(), 'certificate': cert})
                for kind, name in cert.get('subjectAltName', []):
                    if kind == 'DNS':
                        self.r.emit('tls', 'certificate_name', name,
                                    {'in_passive_domain_scope': under(name.removeprefix('*.'), self.domain),
                                     'automatically_probed': False})

    def inspect(self, url, data):
        h = {k.lower(): v for k, v in data['headers'].items()}
        self.r.emit('http', 'http_response', url, {'status': data['status'], 'bytes_sampled': len(data['raw']),
                    'truncated': data['truncated'], 'headers': data['headers']})
        if 'location' in h:
            self.r.emit('http', 'redirect', url, {'url': urljoin(url, h['location']), 'followed': False})
        for header in ('server', 'x-powered-by', 'x-generator', 'x-aspnet-version'):
            if h.get(header):
                self.r.emit('fingerprint', 'technology_hint', url,
                            {'evidence': header, 'value': h[header], 'confidence': 'unverified header'})
        parser = Links()
        if 'html' not in h.get('content-type', '').lower():
            return parser
        parser.feed(data['text'])
        if parser.title:
            self.r.emit('http', 'title', url, ''.join(parser.title).strip())
        for generator in parser.generators:
            self.r.emit('fingerprint', 'technology_hint', url, {'evidence': 'meta generator', 'value': generator})
        patterns = {'WordPress': r'wp-content/|wp-includes/', 'Drupal': r'Drupal\.settings|drupalSettings',
                    'Next.js': r'/_next/|__NEXT_DATA__', 'Nuxt': r'/_nuxt/|__NUXT__',
                    'React': r'data-reactroot', 'Angular': r'ng-version=', 'Django': r'csrfmiddlewaretoken'}
        for technology, pattern in patterns.items():
            if re.search(pattern, data['text'], re.I):
                self.r.emit('fingerprint', 'technology_hint', url,
                            {'technology': technology, 'evidence': pattern, 'confidence': 'heuristic'})
        return parser

    def http(self):
        self.inspect(self.url, self.get(self.url))
        origin = urlunsplit((*urlsplit(self.url)[:2], '/', '', ''))
        for name in ('robots.txt', 'sitemap.xml'):
            url = urljoin(origin, name)
            data = self.get(url)
            self.r.emit('http', 'public_metadata', url, {'status': data['status'],
                        'truncated': data['truncated'], 'text_sample': data['text'][:12000]})

    def crawl(self):
        queue, visited, emitted = deque([self.url]), set(), set()
        while queue and len(visited) < self.a.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                data = self.get(url)
                parser = self.inspect(url, data)
                for ref in sorted(parser.urls):
                    full = urljoin(url, ref)
                    p = urlsplit(full)
                    full = urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))
                    if not same_origin(self.url, full):
                        continue
                    if full not in emitted:
                        emitted.add(full)
                        self.r.emit('crawl', 'public_url', full, {'found_on': url, 'fetched_at_discovery': False})
                    # Do not follow forms/query links or obvious logout/destructive action links.
                    if p.query or re.search(r'logout|signout|delete|remove|unsubscribe', p.path, re.I):
                        continue
                    if re.search(r'\.(?:png|jpe?g|gif|svg|webp|ico|css|js|pdf|zip|mp4|woff2?)$', p.path, re.I):
                        continue
                    if full not in visited and len(queue) < self.a.max_pages * 10:
                        queue.append(full)
            except Exception as exc:
                self.error('crawl', url, exc)

    def words(self, filename):
        count = 0
        with open(filename, encoding='utf-8') as file:
            for line in file:
                word = line.strip()
                if word and not word.startswith('#'):
                    if count >= self.a.max_words:
                        self.r.emit('wordlist', 'limit', filename, {'max_words': self.a.max_words})
                        break
                    count += 1
                    yield word

    def subdomains(self):
        import dns.resolver
        label, resolver = next(self.resolvers())
        def addresses(name):
            found = set()
            for kind in ('A', 'AAAA', 'CNAME'):
                try:
                    answer = self.resolve(resolver, name, kind)
                    found.update((kind, str(item)) for item in answer)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
            return sorted(found)
        baselines = []
        for _ in range(2):
            baselines.append(addresses(uuid.uuid4().hex + '.' + self.host))
        wildcard = any(baselines)
        self.r.emit('dns', 'wildcard_check', self.host, {'resolver': label, 'detected': wildcard,
                    'samples': baselines, 'warning': 'Wildcard detection is heuristic, not a proof.'})
        for word in self.words(self.a.dns_wordlist):
            if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*', word):
                self.r.emit('dns', 'skipped', word, 'invalid subdomain prefix')
                continue
            try:
                name = hostname(word + '.' + self.host)
                values = addresses(name)
                if values:
                    self.r.emit('dns', 'subdomain_candidate', name, {'resolver': label, 'records': values,
                                'wildcard_detected': wildcard, 'matches_baseline': values in baselines})
            except Exception as exc:
                self.error('dns', word, exc)

    def paths(self):
        origin = urlunsplit((*urlsplit(self.url)[:2], '/', '', ''))
        def signature(data, path):
            body = data['text'].replace(path, '<PATH>').replace(quote(path, safe=''), '<PATH>')
            body = re.sub(r'\s+', ' ', body)
            return (data['status'], hashlib.sha256(body.encode()).hexdigest())
        baselines = []
        for _ in range(2):
            path = '/' + uuid.uuid4().hex
            baselines.append(signature(self.get(urljoin(origin, path)), path))
        self.r.emit('paths', 'soft404_baseline', origin, {'samples': baselines,
                    'warning': 'Dynamic catch-all pages may still produce false positives.'})
        for word in self.words(self.a.path_wordlist):
            path = '/' + word.lstrip('/')
            if not re.fullmatch(r'/[A-Za-z0-9_./~-]+', path) or '..' in path.split('/') or path.startswith('//'):
                self.r.emit('paths', 'skipped', word, 'unsafe or unsupported path syntax')
                continue
            url = urljoin(origin, path)
            try:
                data = self.get(url)
                if data['status'] not in (404, 410) and signature(data, path) not in baselines:
                    self.r.emit('paths', 'path_candidate', url, {'status': data['status'],
                                'bytes_sampled': len(data['raw']), 'truncated': data['truncated'],
                                'location': data['headers'].get('Location'), 'existence_confirmed': False})
            except Exception as exc:
                self.error('paths', url, exc)

    def close(self):
        self.session.close()


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter, epilog='Only assess authorized targets. Passive contacts third-party services, not the target. Active GET requests can have side effects on badly designed applications.')
    p.add_argument('-u', '--url', required=True, help='target hostname or HTTP(S) URL; no positional arguments')
    p.add_argument('-m', '--mode', choices=('passive', 'active'), default='passive')
    p.add_argument('--domain', help='explicit passive domain scope (e.g. example.co.uk); defaults to target hostname')
    p.add_argument('--modules', help='comma-separated modules; passive: rdap,ct,archive,dorks; active: dns,tls,http,crawl,subdomains,paths')
    p.add_argument('-f', '--format', choices=['pretty', 'text', 'tsv', 'jsonl'], default='pretty')
    p.add_argument('-o', '--output', help='write results to this file instead of stdout')
    p.add_argument('--timeout', type=positive, default=15, help='network timeout in seconds')
    p.add_argument('--delay', type=nonnegative, default=0.5, help='minimum seconds between operations; sequential, no parallel workers')
    p.add_argument('--max-bytes', type=positive_int, default=10000000, help='maximum bytes read per HTTP response')
    p.add_argument('--archive-limit', type=positive_int, default=200, help='maximum archive rows requested')
    p.add_argument('--google-search', action='store_true', help='execute 5 Google queries through SerpApi; needs SERPAPI_KEY; may use paid quota')
    p.add_argument('--resolver', action='append', help='DNS resolver IP; repeat for multiple resolvers; default: system resolver')
    p.add_argument('--dns-types', default=DEFAULT_TYPES, help='comma-separated DNS record types')
    p.add_argument('--max-pages', type=positive_int, default=10, help='maximum pages fetched by crawl module')
    p.add_argument('--dns-wordlist', help='prefix wordlist; opts into active subdomain enumeration under target hostname')
    p.add_argument('--path-wordlist', help='path wordlist; opts into active path checks from origin root')
    p.add_argument('--max-words', type=positive_int, default=100, help='maximum entries processed per wordlist')
    p.add_argument('--archive', action='store_true', help='opt in to historical Wayback URLs (passive only)')
    p.add_argument('--dorks', action='store_true', help='opt in to Google dork generation (passive only)')
    p.add_argument('--crawl', action='store_true', help='opt in to same-origin crawling (active only)')
    p.add_argument('--color', choices=['auto', 'always', 'never'], default='auto', help='terminal colors; machine formats never use ANSI')
    p.add_argument('--no-color', action='store_const', dest='color', const='never', help='disable terminal colors')
    p.add_argument('--display-limit', type=int, default=30, help='maximum displayed rows per human table; must be positive')
    p.add_argument('-v', '--verbose', action='store_true', help='include raw diagnostic evidence')
    return p


def main(argv=None):
    global requests
    p = parser()
    a = p.parse_args(argv)
    if a.display_limit <= 0:
        p.error('--display-limit must be positive')
    try:
        url, host = target_url(a.url)
        domain = hostname(a.domain) if a.domain else host
        if not under(host, domain):
            p.error('--domain must equal or be a parent of the target hostname')
        for resolver in a.resolver or []:
            ipaddress.ip_address(resolver)
    except (ValueError, UnicodeError) as exc:
        p.error(str(exc))
    modules = _recon_select_modules(a, p)
    if a.mode == 'passive' and (a.dns_wordlist or a.path_wordlist or a.resolver):
        p.error('DNS resolvers and wordlists require --mode active')
    if a.mode == 'active' and a.google_search:
        p.error('--google-search requires passive mode')
    if a.dns_wordlist and 'subdomains' not in modules:
        modules.append('subdomains')
    if a.path_wordlist and 'paths' not in modules:
        modules.append('paths')
    if not modules or set(modules) - MODULES[a.mode]:
        p.error('invalid modules for selected mode: ' + ','.join(sorted(set(modules) - MODULES[a.mode])))
    if a.google_search and 'dorks' not in modules:
        p.error('--google-search requires the dorks module')
    if 'subdomains' in modules and (not a.dns_wordlist):
        p.error('subdomains module requires --dns-wordlist')
    if 'paths' in modules and (not a.path_wordlist):
        p.error('paths module requires --path-wordlist')
    for filename in (a.dns_wordlist, a.path_wordlist):
        if filename and (not Path(filename).is_file()):
            p.error(f'wordlist not found: {filename}')
        if filename and a.output and (Path(filename).resolve() == Path(a.output).resolve()):
            p.error('output must not overwrite an input wordlist')
    try:
        import requests as requests_module
        requests = requests_module
        if set(modules) & {'dns', 'subdomains'}:
            import dns.resolver
            import dns.rdatatype
            for kind in a.dns_types.split(','):
                dns.rdatatype.from_text(kind.strip().upper())
    except ImportError as exc:
        p.error(f'missing dependency ({exc}); run: python -m pip install -r requirements.txt')
    except Exception as exc:
        p.error(f'invalid DNS type: {exc}')
    r = Reporter(a, host)
    recon = Recon(a, r, url, host, domain)
    interrupted = False
    try:
        r.emit('run', 'scope', host, {'url': url, 'passive_domain': domain, 'modules': modules, 'active_http_scope': 'exact origin only; redirects recorded, never followed', 'active_dns_scope': 'target hostname and explicitly requested wordlist children'})
        for module in dict.fromkeys(modules):
            r.begin(module)
            pass
            try:
                getattr(recon, module)()
            except Exception as exc:
                recon.error(module, host, exc)
            r.render(module)
    except KeyboardInterrupt:
        interrupted = True
        r.emit('run', 'interrupted', host, 'Interrupted by user')
    finally:
        errors = r.counts['error']
        r.emit('run', 'summary', host, {'counts': dict(r.counts), 'errors': errors, 'interrupted': interrupted})
        recon.close()
        r.close()
    return 130 if interrupted else 1 if errors else 0


def _recon_select_modules(a, p):
    allowed = {'passive': {'rdap', 'ct', 'archive', 'dorks'},
               'active': {'dns', 'tls', 'http', 'crawl', 'subdomains', 'paths'}}
    modules = ([m.strip() for m in a.modules.split(',') if m.strip()] if a.modules is not None
               else (['rdap', 'ct'] if a.mode == 'passive' else ['dns', 'tls', 'http']))
    if a.mode == 'passive' and (a.crawl or a.dns_wordlist or a.path_wordlist or a.resolver):
        p.error('crawling, resolvers and wordlists require --mode active')
    if a.mode == 'active' and (a.archive or a.dorks or a.google_search):
        p.error('archive and Google dorks require --mode passive')
    for enabled, module in [(a.archive, 'archive'), (a.dorks or a.google_search, 'dorks'),
                            (a.crawl, 'crawl'), (a.dns_wordlist, 'subdomains'), (a.path_wordlist, 'paths')]:
        if enabled and module not in modules:
            modules.append(module)
    if not modules or set(modules) - allowed[a.mode]:
        p.error('invalid modules for ' + a.mode + ': ' + ','.join(modules))
    if 'subdomains' in modules and not a.dns_wordlist:
        p.error('subdomains requires --dns-wordlist')
    if 'paths' in modules and not a.path_wordlist:
        p.error('paths requires --path-wordlist')
    return list(dict.fromkeys(modules))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
