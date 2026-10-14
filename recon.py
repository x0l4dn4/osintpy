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
    def __init__(self, fmt, filename, mode, target):
        self.fmt, self.mode, self.target = fmt, mode, target
        self.stream = open(filename, 'w', encoding='utf-8') if filename else sys.stdout
        self.owned = bool(filename)
        self.counts = Counter()
        if fmt == 'tsv':
            self.stream.write('time\tmode\ttarget\tsource\ttype\tname\tvalue\n')

    def emit(self, source, kind, name, value):
        record = dict(time=datetime.now(timezone.utc).isoformat(), mode=self.mode,
                      target=self.target, source=source, type=kind, name=name, value=value)
        self.counts[kind] += 1
        if self.fmt == 'jsonl':
            line = json.dumps(record, ensure_ascii=True, separators=(',', ':'))
        else:
            fields = [str(record[k]) if isinstance(record[k], str) else json.dumps(record[k], ensure_ascii=True)
                      for k in ('time', 'mode', 'target', 'source', 'type', 'name', 'value')]
            fields = [s.replace('\\', '\\\\').replace('\t', '\\t').replace('\r', '\\r').replace('\n', '\\n')
                      for s in fields]
            # Escape terminal controls from untrusted remote input.
            fields = [''.join(c if ord(c) >= 32 and ord(c) != 127 else f'\\x{ord(c):02x}' for c in s)
                      for s in fields]
            line = '\t'.join(fields) if self.fmt == 'tsv' else ' | '.join(fields[3:])
        self.stream.write(line + '\n')
        self.stream.flush()

    def close(self):
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
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='Only assess authorized targets. Passive contacts third-party services, not the target. '
               'Active GET requests can have side effects on badly designed applications.')
    p.add_argument('-u', '--url', required=True, help='target hostname or HTTP(S) URL; no positional arguments')
    p.add_argument('-m', '--mode', choices=('passive', 'active'), default='passive')
    p.add_argument('--domain', help='explicit passive domain scope (e.g. example.co.uk); defaults to target hostname')
    p.add_argument('--modules', help='comma-separated modules; passive: rdap,ct,archive,dorks; active: dns,tls,http,crawl,subdomains,paths')
    p.add_argument('-f', '--format', choices=('text', 'tsv', 'jsonl'), default='text')
    p.add_argument('-o', '--output', help='write results to this file instead of stdout')
    p.add_argument('--timeout', type=positive, default=15, help='network timeout in seconds')
    p.add_argument('--delay', type=nonnegative, default=0.5, help='minimum seconds between operations; sequential, no parallel workers')
    p.add_argument('--max-bytes', type=positive_int, default=10_000_000, help='maximum bytes read per HTTP response')
    p.add_argument('--archive-limit', type=positive_int, default=200, help='maximum archive rows requested')
    p.add_argument('--google-search', action='store_true', help='execute 5 Google queries through SerpApi; needs SERPAPI_KEY; may use paid quota')
    p.add_argument('--resolver', action='append', help='DNS resolver IP; repeat for multiple resolvers; default: system resolver')
    p.add_argument('--dns-types', default=DEFAULT_TYPES, help='comma-separated DNS record types')
    p.add_argument('--max-pages', type=positive_int, default=10, help='maximum pages fetched by crawl module')
    p.add_argument('--dns-wordlist', help='prefix wordlist; opts into active subdomain enumeration under target hostname')
    p.add_argument('--path-wordlist', help='path wordlist; opts into active path checks from origin root')
    p.add_argument('--max-words', type=positive_int, default=100, help='maximum entries processed per wordlist')
    return p


def main(argv=None):
    global requests
    p = parser()
    a = p.parse_args(argv)
    try:
        url, host = target_url(a.url)
        domain = hostname(a.domain) if a.domain else host
        if not under(host, domain):
            p.error('--domain must equal or be a parent of the target hostname')
        for resolver in a.resolver or []:
            ipaddress.ip_address(resolver)
    except (ValueError, UnicodeError) as exc:
        p.error(str(exc))
    modules = ([m.strip() for m in a.modules.split(',') if m.strip()] if a.modules else
               (['rdap', 'ct', 'archive', 'dorks'] if a.mode == 'passive' else ['dns', 'tls', 'http', 'crawl']))
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
    if 'subdomains' in modules and not a.dns_wordlist:
        p.error('subdomains module requires --dns-wordlist')
    if 'paths' in modules and not a.path_wordlist:
        p.error('paths module requires --path-wordlist')
    for filename in (a.dns_wordlist, a.path_wordlist):
        if filename and not Path(filename).is_file():
            p.error(f'wordlist not found: {filename}')
        if filename and a.output and Path(filename).resolve() == Path(a.output).resolve():
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
    r = Reporter(a.format, a.output, a.mode, host)
    recon = Recon(a, r, url, host, domain)
    interrupted = False
    try:
        r.emit('run', 'scope', host, {'url': url, 'passive_domain': domain, 'modules': modules,
               'active_http_scope': 'exact origin only; redirects recorded, never followed',
               'active_dns_scope': 'target hostname and explicitly requested wordlist children'})
        for module in dict.fromkeys(modules):
            print(f'[*] {module}', file=sys.stderr)
            try:
                getattr(recon, module)()
            except Exception as exc:
                recon.error(module, host, exc)
    except KeyboardInterrupt:
        interrupted = True
        r.emit('run', 'interrupted', host, 'Interrupted by user')
    finally:
        errors = r.counts['error']
        r.emit('run', 'summary', host, {'counts': dict(r.counts), 'errors': errors,
                                     'interrupted': interrupted})
        recon.close()
        r.close()
    return 130 if interrupted else (1 if errors else 0)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
