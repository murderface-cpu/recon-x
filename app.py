#!/usr/bin/env python3
"""
RECON-X: Attack Surface Intelligence Platform
Inspired by the projectdiscovery ecosystem:
  nuclei → vuln checks        | httpx → http probing
  tlsx → TLS inspection       | wappalyzergo → tech fingerprinting
  cdncheck → CDN detection    | asnmap → ASN intelligence
  retryabledns → DNS recon    | fastdialer → port scanning
  gologger → streaming output | nuclei DSL → risk scoring
"""

import os, json, time, ssl, socket, re, queue, threading, hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import httpx
import dns.resolver, dns.rdatatype, dns.exception
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, Response, jsonify, stream_with_context
import ipwhois as ipwhois_lib

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,993,995,
                1433,1521,3306,3389,5432,5900,6379,8080,8443,
                8888,9200,27017,50070]

PORT_SERVICES = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
    110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',
    995:'POP3S',1433:'MSSQL',1521:'Oracle',3306:'MySQL',
    3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',
    8080:'HTTP-Alt',8443:'HTTPS-Alt',8888:'HTTP-Alt',
    9200:'Elasticsearch',27017:'MongoDB',50070:'Hadoop'
}

HIGH_RISK_PORTS  = {23,21,445,3389,5900,6379,9200,27017,50070}
MEDIUM_RISK_PORTS= {22,25,1433,1521,3306,5432}

# ─────────────────────────────────────────────────────────────────────────────
# TECH FINGERPRINTING SIGNATURES  (≈ projectdiscovery/wappalyzergo)
# ─────────────────────────────────────────────────────────────────────────────

TECH_SIGNATURES = {
    'WordPress':     {'body':[r'wp-content/',r'wp-includes/',r'/wp-json/'],         'meta_gen':r'WordPress',  'cookies':[r'wordpress_',r'wp-settings']},
    'Drupal':        {'headers':{'X-Generator':r'Drupal'},                           'body':[r'Drupal\.settings',r'/sites/default/files/'], 'meta_gen':r'Drupal'},
    'Joomla':        {'body':[r'/components/com_content',r'Joomla\s+CMS'],           'meta_gen':r'Joomla'},
    'Shopify':       {'body':[r'cdn\.shopify\.com',r'Shopify\.theme'],               'meta_gen':r'Shopify',    'headers':{'X-ShopId':r'.+'}},
    'WooCommerce':   {'body':[r'woocommerce',r'/wc-ajax=']},
    'Magento':       {'body':[r'mage/cookies\.js',r'requirejs/require\.js'],         'cookies':[r'frontend_cid']},
    'Next.js':       {'headers':{'X-Powered-By':r'Next\.js'},                        'body':[r'__NEXT_DATA__',r'/_next/static/']},
    'Nuxt.js':       {'body':[r'__nuxt',r'/_nuxt/',r'window\.__nuxt__']},
    'Gatsby':        {'body':[r'___gatsby',r'gatsby-image',r'/page-data/']},
    'React':         {'body':[r'data-reactroot',r'__reactFiber',r'ReactDOM\.render']},
    'Vue.js':        {'body':[r'data-v-\w{8}',r'__vue_app__',r'vue\.runtime\.min\.js']},
    'Angular':       {'body':[r'ng-version=',r'data-ng-app',r'angular\.min\.js']},
    'jQuery':        {'body':[r'jquery[-/][\d.]+(?:\.min)?\.js']},
    'Bootstrap':     {'body':[r'bootstrap(?:\.min)?\.css',r'bootstrap(?:\.min)?\.js']},
    'Tailwind CSS':  {'body':[r'tailwindcss']},
    'Nginx':         {'headers':{'Server':r'nginx'}},
    'Apache':        {'headers':{'Server':r'Apache'}},
    'Microsoft IIS': {'headers':{'Server':r'Microsoft-IIS','X-Powered-By':r'ASP\.NET'}},
    'Caddy':         {'headers':{'Server':r'Caddy'}},
    'PHP':           {'headers':{'X-Powered-By':r'PHP'},                             'cookies':[r'PHPSESSID']},
    'Node.js/Express':{'headers':{'X-Powered-By':r'Express'}},
    'Ruby on Rails': {'headers':{'X-Runtime':r'^\d+\.\d+$'},                         'cookies':[r'_session_id']},
    'Django':        {'cookies':[r'csrftoken',r'sessionid'],                         'body':[r'csrfmiddlewaretoken']},
    'Laravel':       {'cookies':[r'laravel_session',r'XSRF-TOKEN']},
    'Cloudflare':    {'headers':{'CF-RAY':r'.+','cf-cache-status':r'.+'},            'server_re':r'cloudflare'},
    'AWS CloudFront':{'headers':{'X-Amz-Cf-Id':r'.+'},                              'via_re':r'CloudFront'},
    'Google Analytics':{'body':[r'google-analytics\.com/analytics\.js',r'gtag\(\'config\'',r'UA-\d{4,10}-\d']},
    'Google Tag Manager':{'body':[r'googletagmanager\.com/gtm\.js',r'GTM-[A-Z0-9]+']},
    'Stripe':        {'body':[r'js\.stripe\.com',r"Stripe\('pk_"]},
    'Intercom':      {'body':[r'widget\.intercom\.io',r'Intercom\(']},
    'Hotjar':        {'body':[r'static\.hotjar\.com',r'hjid:']},
    'reCAPTCHA':     {'body':[r'google\.com/recaptcha',r'grecaptcha']},
    'Elasticsearch': {'body':[r'"cluster_name"',r'"number_of_nodes"']},
    'GraphQL':       {'body':[r'/graphql',r'"__typename"']},
    'Swagger/OpenAPI':{'body':[r'swagger-ui',r'"openapi"\s*:\s*"3\.\d']},
    'Vercel':        {'headers':{'X-Vercel-Id':r'.+'},                              'server_re':r'Vercel'},
    'Netlify':       {'headers':{'X-Nf-Request-Id':r'.+'},                          'server_re':r'Netlify'},
}

# ─────────────────────────────────────────────────────────────────────────────
# CDN DETECTION  (≈ projectdiscovery/cdncheck)
# ─────────────────────────────────────────────────────────────────────────────

CDN_PATTERNS = {
    'Cloudflare':    {'headers':['CF-RAY','cf-cache-status'],         'server':r'cloudflare'},
    'AWS CloudFront':{'headers':['X-Amz-Cf-Id'],                     'via':r'CloudFront'},
    'Fastly':        {'headers':['X-Served-By','Fastly-Request-ID'],  'via':r'varnish'},
    'Akamai':        {'headers':['X-Check-Cacheable'],                'server':r'AkamaiGHost'},
    'Google CDN':    {'via':r'1\.1 google',                          'headers':['X-Goog-Hash']},
    'Azure CDN':     {'headers':['X-Azure-Ref'],                     'via':r'1\.1 Azure'},
    'Varnish':       {'headers':['X-Varnish'],                       'via':r'varnish'},
    'Sucuri':        {'headers':['X-Sucuri-ID'],                     'server':r'Sucuri'},
    'Imperva':       {'headers':['X-Iinfo'],                         'cookies':[r'visid_incap_',r'incap_ses_']},
    'Vercel':        {'headers':['X-Vercel-Id'],                     'server':r'Vercel'},
    'Netlify':       {'headers':['X-Nf-Request-Id'],                 'server':r'Netlify'},
    'BunnyCDN':      {'headers':['CDN-PullZone'],                    'server':r'BunnyCDN'},
}

# ─────────────────────────────────────────────────────────────────────────────
# SECRET DETECTION  (≈ nuclei secret-detection templates)
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    'AWS Access Key':       r'AKIA[0-9A-Z]{16}',
    'Google API Key':       r'AIza[0-9A-Za-z\-_]{35}',
    'GitHub Token':         r'gh[pousr]_[A-Za-z0-9_]{36}',
    'Slack Token':          r'xox[baprs]-[0-9A-Za-z]{10,48}',
    'Stripe Secret Key':    r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Publishable':   r'pk_live_[0-9a-zA-Z]{24}',
    'Private Key':          r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    'JWT Token':            r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'Database URL':         r'(?:mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+',
    'SendGrid Key':         r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    'Firebase URL':         r'https://[a-z0-9-]+\.firebaseio\.com',
    'Hardcoded Password':   r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
    'Private IP Leak':      r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
    'AWS Secret Key':       r'(?i)aws[_\-\s]?secret[_\-\s]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}',
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY HEADERS  (≈ nuclei header-security templates)
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    'Strict-Transport-Security':  {'weight':20,'desc':'HSTS','good':r'max-age=\d+','rec':'max-age=31536000; includeSubDomains; preload'},
    'Content-Security-Policy':    {'weight':25,'desc':'XSS/injection protection','good':r'.+','rec':'Define a strict CSP policy'},
    'X-Frame-Options':            {'weight':10,'desc':'Clickjacking protection','good':r'(?i)(DENY|SAMEORIGIN)','rec':'X-Frame-Options: SAMEORIGIN'},
    'X-Content-Type-Options':     {'weight':10,'desc':'MIME sniffing','good':r'(?i)nosniff','rec':'X-Content-Type-Options: nosniff'},
    'Referrer-Policy':            {'weight':5, 'desc':'Referrer control','good':r'(?i)(no-referrer|strict-origin)','rec':'strict-origin-when-cross-origin'},
    'Permissions-Policy':         {'weight':5, 'desc':'Browser feature policy','good':r'.+','rec':'Restrict camera/mic/geolocation'},
    'X-XSS-Protection':           {'weight':5, 'desc':'XSS filter (legacy)','good':r'1; mode=block','rec':'1; mode=block'},
    'Cross-Origin-Opener-Policy': {'weight':5, 'desc':'Cross-origin isolation','good':r'(?i)same-origin','rec':'same-origin'},
    'Cross-Origin-Resource-Policy':{'weight':5,'desc':'Resource loading control','good':r'(?i)same-origin','rec':'same-origin'},
}

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY CHECKS  (≈ nuclei templates DSL)
# ─────────────────────────────────────────────────────────────────────────────

VULN_CHECKS = [
    {'name':'Git Repository Exposed',   'paths':['/.git/HEAD','/.git/config'],             'body_re':r'ref: refs/|\[core\]',         'severity':'critical'},
    {'name':'.env File Exposed',        'paths':['/.env','/.env.local','/.env.production'], 'body_re':r'APP_KEY=|DB_PASSWORD=',       'severity':'critical'},
    {'name':'PHP Info Exposed',         'paths':['/phpinfo.php','/info.php','/test.php'],   'body_re':r'PHP Version|phpinfo\(\)',      'severity':'high'},
    {'name':'Spring Boot Actuator',     'paths':['/actuator','/actuator/env'],              'body_re':r'systemProperties|activeProfiles','severity':'high'},
    {'name':'Debug Interface',          'paths':['/debug','/__debug__/','/telescope'],      'body_re':r'(?i)(debug|telescope)',        'severity':'high'},
    {'name':'Backup File Exposed',      'paths':['/backup.sql','/db.sql','/site.zip'],      'status_ok':[200],                        'severity':'high'},
    {'name':'Admin Panel',              'paths':['/admin','/wp-admin/','/administrator/'],  'status_ok':[200,302],                    'severity':'medium'},
    {'name':'Swagger UI Exposed',       'paths':['/swagger-ui.html','/api-docs','/api/swagger/'],'body_re':r'(?i)swagger',           'severity':'low'},
    {'name':'GraphQL Introspection',    'paths':['/graphql','/api/graphql'],                'body_re':r'"__schema"',                  'severity':'medium'},
    {'name':'Directory Listing',        'paths':['/'],                                      'body_re':r'(?i)Index of /|Directory listing','severity':'medium'},
]

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def normalize_target(target: str) -> Tuple[str, str]:
    target = target.strip()
    if not target.startswith(('http://','https://')):
        target_url = f'https://{target}'
    else:
        target_url = target
    parsed = urlparse(target_url)
    hostname = parsed.netloc or parsed.path
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    return hostname, target_url


def detect_secrets(content: str) -> List[Dict]:
    found = []
    for stype, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            match = matches[0] if isinstance(matches[0], str) else str(matches[0])
            found.append({'type': stype, 'match': match[:80]})
    return found


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1: DNS SCANNER  (≈ projectdiscovery/retryabledns)
# ─────────────────────────────────────────────────────────────────────────────

def scan_dns(hostname: str, event_q: queue.Queue) -> Dict:
    results = {'module':'dns','records':{},'findings':[],'risk_items':[]}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in ['A','AAAA','MX','NS','TXT','CNAME','SOA','CAA']:
        try:
            answers = resolver.resolve(hostname, rtype)
            records = [str(r) for r in answers]
            results['records'][rtype] = records

            if rtype == 'TXT':
                combined = ' '.join(records)
                if 'v=spf1' in combined:
                    spf = next((r for r in records if 'v=spf1' in r), '')
                    results['findings'].append({'type':'SPF Record','value':spf[:80],'status':'info'})
                    if '+all' in spf:
                        results['risk_items'].append({'severity':'high','description':'SPF uses "+all" — any server can send email on behalf of this domain'})
                else:
                    results['risk_items'].append({'severity':'medium','description':'No SPF record — domain may be used for email spoofing'})
                if 'v=DMARC1' in combined or '_dmarc' in combined.lower():
                    results['findings'].append({'type':'DMARC','value':'DMARC record present','status':'good'})
                else:
                    results['risk_items'].append({'severity':'medium','description':'No DMARC record — email authentication not enforced'})
                if 'DKIM1' in combined:
                    results['findings'].append({'type':'DKIM','value':'DKIM signing configured','status':'good'})

            if rtype == 'CAA':
                results['findings'].append({'type':'CAA Record','value':' | '.join(records),'status':'good'})
            if rtype == 'NS':
                results['findings'].append({'type':'Name Servers','value':' | '.join(records[:4]),'status':'info'})
            if rtype == 'MX':
                results['findings'].append({'type':'Mail Servers','value':' | '.join(records[:4]),'status':'info'})

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception:
            pass

    if 'CAA' not in results['records']:
        results['risk_items'].append({'severity':'low','description':'No CAA record — any CA can issue certificates for this domain'})

    event_q.put({'type':'module_complete','module':'dns','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: HTTP PROBER  (≈ projectdiscovery/httpx)
# ─────────────────────────────────────────────────────────────────────────────

def probe_http(hostname: str, base_url: str, event_q: queue.Queue) -> Dict:
    results = {'module':'http','responses':[],'final_url':None,
               'findings':[],'risk_items':[],'redirect_chain':[]}

    probes = [base_url]
    if base_url.startswith('https://'):
        probes.append(base_url.replace('https://','http://'))
    else:
        probes.append(base_url.replace('http://','https://'))

    UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
    headers = {'User-Agent':UA,'Accept':'text/html,application/xhtml+xml,*/*;q=0.8',
               'Accept-Language':'en-US,en;q=0.5','Connection':'keep-alive'}

    for url in probes:
        try:
            t0 = time.time()
            with httpx.Client(timeout=15, follow_redirects=True, verify=False,
                              headers=headers, http2=True) as client:
                resp = client.get(url)
                elapsed = round((time.time()-t0)*1000, 1)

                for h in resp.history:
                    results['redirect_chain'].append({
                        'url':str(h.url),'status':h.status_code,
                        'location':h.headers.get('location','')
                    })

                resp_data = {
                    'url':url,'final_url':str(resp.url),
                    'status_code':resp.status_code,
                    'response_time_ms':elapsed,
                    'content_length':len(resp.content),
                    'headers':dict(resp.headers),
                    'http_version':resp.http_version,
                    'body_preview':resp.text[:3000]
                }
                results['responses'].append(resp_data)
                results['final_url'] = str(resp.url)

                hdrs = resp.headers
                if 'server' in hdrs:
                    sv = hdrs['server']
                    results['findings'].append({'type':'Server','value':sv,'status':'info'})
                    if re.search(r'[\d.]{3,}', sv):
                        results['risk_items'].append({'severity':'low','description':f'Server version disclosed: {sv}'})

                if 'x-powered-by' in hdrs:
                    xpb = hdrs['x-powered-by']
                    results['findings'].append({'type':'X-Powered-By','value':xpb,'status':'info'})
                    results['risk_items'].append({'severity':'low','description':f'Technology fingerprint via X-Powered-By: {xpb}'})

                results['findings'].append({'type':'HTTP Version','value':resp.http_version,'status':'good' if resp.http_version=='HTTP/2' else 'info'})
                results['findings'].append({'type':'Response Time','value':f'{elapsed} ms','status':'good' if elapsed<500 else 'info'})
                results['findings'].append({'type':'Status Code','value':str(resp.status_code),'status':'good' if resp.status_code==200 else 'info'})

                # CORS probe
                try:
                    cors_resp = client.get(url, headers={**headers,'Origin':'https://evil.example.com'})
                    acao = cors_resp.headers.get('access-control-allow-origin','')
                    if acao == '*':
                        results['risk_items'].append({'severity':'medium','description':'CORS: Access-Control-Allow-Origin is wildcard (*) — all origins accepted'})
                    elif 'evil.example.com' in acao:
                        results['risk_items'].append({'severity':'high','description':'CORS: Arbitrary origin reflection — potential CORS misconfiguration'})
                except Exception:
                    pass

                break
        except httpx.ConnectError:
            results['findings'].append({'type':'Connection','value':f'Cannot connect: {url}','status':'error'})
        except Exception:
            pass

    if any(r['url'].startswith('http://') and 'https://' in r.get('location','') for r in results['redirect_chain']):
        results['findings'].append({'type':'HTTPS Redirect','value':'HTTP → HTTPS redirect detected','status':'good'})
    elif results['responses'] and results['responses'][0]['url'].startswith('http://'):
        results['risk_items'].append({'severity':'medium','description':'Site served over HTTP without redirect to HTTPS'})

    event_q.put({'type':'module_complete','module':'http','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3: TLS INSPECTOR  (≈ projectdiscovery/tlsx)
# ─────────────────────────────────────────────────────────────────────────────

def inspect_tls(hostname: str, event_q: queue.Queue) -> Dict:
    results = {'module':'tls','certificate':{},'tls_version':None,
               'cipher_suite':None,'findings':[],'risk_items':[]}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                proto    = ssock.version()
                cipher   = ssock.cipher()
                results['tls_version']  = proto
                results['cipher_suite'] = cipher[0] if cipher else None
                results['cipher_bits']  = cipher[2] if cipher else None

                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                # Subject / Issuer
                def get_attr(obj, oid):
                    try:
                        attrs = obj.get_attributes_for_oid(oid)
                        return attrs[0].value if attrs else None
                    except Exception:
                        return None

                results['certificate']['common_name']  = get_attr(cert.subject, NameOID.COMMON_NAME)
                results['certificate']['organization'] = get_attr(cert.subject, NameOID.ORGANIZATION_NAME)
                results['certificate']['issuer']       = get_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
                results['certificate']['issuer_cn']    = get_attr(cert.issuer, NameOID.COMMON_NAME)

                # Dates
                now = datetime.now(timezone.utc)
                try:
                    not_after = cert.not_valid_after_utc
                except AttributeError:
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                try:
                    not_before = cert.not_valid_before_utc
                except AttributeError:
                    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

                days_left = (not_after - now).days
                results['certificate']['not_before']       = not_before.strftime('%Y-%m-%d')
                results['certificate']['not_after']        = not_after.strftime('%Y-%m-%d')
                results['certificate']['days_until_expiry']= days_left
                results['certificate']['serial_number']    = str(cert.serial_number)

                # SANs
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    results['certificate']['sans'] = [str(n.value) for n in san_ext.value][:20]
                except Exception:
                    results['certificate']['sans'] = []

                # Sig algo
                try:
                    results['certificate']['sig_algo'] = cert.signature_hash_algorithm.name
                except Exception:
                    results['certificate']['sig_algo'] = 'unknown'

                # Risk assessment
                if days_left < 0:
                    results['risk_items'].append({'severity':'critical','description':f'Certificate EXPIRED {abs(days_left)} days ago'})
                elif days_left < 14:
                    results['risk_items'].append({'severity':'critical','description':f'Certificate expires in {days_left} days — URGENT renewal needed'})
                elif days_left < 30:
                    results['risk_items'].append({'severity':'high','description':f'Certificate expires in {days_left} days'})

                if proto and proto in ('TLSv1','TLSv1.1','SSLv3','SSLv2'):
                    results['risk_items'].append({'severity':'high','description':f'Deprecated TLS protocol: {proto}'})

                if cipher and any(w in cipher[0] for w in ('RC4','DES','NULL','EXPORT','anon')):
                    results['risk_items'].append({'severity':'critical','description':f'Broken cipher suite: {cipher[0]}'})

                if cipher and cipher[2] and cipher[2] < 128:
                    results['risk_items'].append({'severity':'high','description':f'Weak cipher key length: {cipher[2]} bits'})

                results['findings'].extend([
                    {'type':'TLS Version','value':proto,'status':'good' if proto=='TLSv1.3' else 'info'},
                    {'type':'Certificate Expiry','value':f'{days_left} days','status':'good' if days_left>30 else 'warning'},
                    {'type':'Issued By','value':results['certificate'].get('issuer','Unknown'),'status':'info'},
                    {'type':'Cipher','value':results['cipher_suite'],'status':'info'},
                    {'type':'Key Bits','value':str(results['cipher_bits']),'status':'good' if results['cipher_bits'] and results['cipher_bits']>=256 else 'info'},
                ])

    except ConnectionRefusedError:
        results['risk_items'].append({'severity':'medium','description':'HTTPS port 443 not accessible'})
    except ssl.SSLError as e:
        results['risk_items'].append({'severity':'high','description':f'SSL error: {str(e)[:80]}'})
    except Exception as e:
        results['findings'].append({'type':'TLS','value':str(e)[:80],'status':'error'})

    event_q.put({'type':'module_complete','module':'tls','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4: TECH FINGERPRINTER  (≈ projectdiscovery/wappalyzergo)
# ─────────────────────────────────────────────────────────────────────────────

def fingerprint_tech(http_results: Dict, event_q: queue.Queue) -> Dict:
    results = {'module':'tech','detected':[],'cdn':None,'findings':[],'risk_items':[],'secrets':[]}

    if not http_results.get('responses'):
        event_q.put({'type':'module_complete','module':'tech','data':results})
        return results

    rd = http_results['responses'][0]
    headers  = {k.lower():v for k,v in rd.get('headers',{}).items()}
    body     = rd.get('body_preview','')
    cookies  = headers.get('set-cookie','')

    soup     = BeautifulSoup(body, 'lxml')
    meta_gen = ''
    for m in soup.find_all('meta', attrs={'name':'generator'}):
        meta_gen = m.get('content','')
    scripts_str = ' '.join(s.get('src','') for s in soup.find_all('script', src=True))

    for tech, sig in TECH_SIGNATURES.items():
        hit = False
        if not hit and 'headers' in sig:
            for h, pat in sig['headers'].items():
                if h.lower() in headers and re.search(pat, headers[h.lower()], re.I):
                    hit = True; break
        if not hit and 'server_re' in sig:
            if re.search(sig['server_re'], headers.get('server',''), re.I): hit = True
        if not hit and 'via_re' in sig:
            if re.search(sig['via_re'], headers.get('via',''), re.I): hit = True
        if not hit and 'body' in sig:
            for pat in sig['body']:
                if re.search(pat, body+scripts_str, re.I): hit = True; break
        if not hit and 'meta_gen' in sig and meta_gen:
            if re.search(sig['meta_gen'], meta_gen, re.I): hit = True
        if not hit and 'cookies' in sig:
            for cp in sig['cookies']:
                if re.search(cp, cookies, re.I): hit = True; break
        if hit:
            results['detected'].append(tech)

    # CDN detection
    for cdn_name, cdn_sig in CDN_PATTERNS.items():
        found = False
        if 'headers' in cdn_sig:
            for h in cdn_sig['headers']:
                if h.lower() in headers: found = True; break
        if not found and 'server' in cdn_sig:
            if re.search(cdn_sig['server'], headers.get('server',''), re.I): found = True
        if not found and 'via' in cdn_sig:
            if re.search(cdn_sig['via'], headers.get('via',''), re.I): found = True
        if not found and 'cookies' in cdn_sig:
            for cp in cdn_sig['cookies']:
                if re.search(cp, cookies, re.I): found = True; break
        if found:
            results['cdn'] = cdn_name
            results['findings'].append({'type':'CDN','value':cdn_name,'status':'info'})
            break

    # Secret detection
    secrets = detect_secrets(body)
    results['secrets'] = secrets
    for s in secrets:
        results['risk_items'].append({'severity':'critical','description':f'Secret pattern in HTML: {s["type"]}'})
        results['findings'].append({'type':f'⚠ Secret: {s["type"]}','value':s['match'][:60],'status':'critical'})

    for tech in results['detected']:
        results['findings'].append({'type':'Tech','value':tech,'status':'info'})

    if 'WordPress' in results['detected']:
        results['risk_items'].append({'severity':'info','description':'WordPress detected — verify plugins are up to date'})

    event_q.put({'type':'module_complete','module':'tech','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5: SECURITY HEADER ANALYZER  (≈ nuclei header templates)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_headers(http_results: Dict, event_q: queue.Queue) -> Dict:
    results = {'module':'security_headers','score':0,'headers_present':[],'headers_missing':[],'findings':[],'risk_items':[]}

    if not http_results.get('responses'):
        event_q.put({'type':'module_complete','module':'security_headers','data':results})
        return results

    resp_hdrs = {k.lower():v for k,v in http_results['responses'][0].get('headers',{}).items()}
    total_weight = sum(h['weight'] for h in SECURITY_HEADERS.values())
    score = 0

    for hname, cfg in SECURITY_HEADERS.items():
        h_lo = hname.lower()
        if h_lo in resp_hdrs:
            val = resp_hdrs[h_lo]
            if re.search(cfg['good'], val, re.I):
                score += cfg['weight']
                results['headers_present'].append({'name':hname,'value':val,'status':'good','desc':cfg['desc']})
            else:
                score += cfg['weight']//2
                results['headers_present'].append({'name':hname,'value':val,'status':'weak','desc':cfg['desc']})
                results['risk_items'].append({'severity':'low','description':f'{hname} present but possibly misconfigured'})
        else:
            results['headers_missing'].append({'name':hname,'desc':cfg['desc'],'rec':cfg['rec']})
            sev = 'high' if cfg['weight']>=20 else ('medium' if cfg['weight']>=10 else 'low')
            results['risk_items'].append({'severity':sev,'description':f'Missing security header: {hname}'})

    results['score'] = round((score/total_weight)*100) if total_weight else 0
    results['findings'].append({'type':'Header Score','value':f"{results['score']}/100",'status':'good' if results['score']>=70 else 'warning'})

    event_q.put({'type':'module_complete','module':'security_headers','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6: ASN / IP INTELLIGENCE  (≈ projectdiscovery/asnmap)
# ─────────────────────────────────────────────────────────────────────────────

def lookup_asn(hostname: str, event_q: queue.Queue) -> Dict:
    results = {'module':'asn','ip':None,'asn':None,'asn_desc':None,
               'network':None,'country':None,'findings':[],'risk_items':[]}
    try:
        ip = socket.gethostbyname(hostname)
        results['ip'] = ip
        results['findings'].append({'type':'Resolved IP','value':ip,'status':'info'})

        obj   = ipwhois_lib.IPWhois(ip)
        data  = obj.lookup_rdap(depth=1)
        results['asn']      = data.get('asn')
        results['asn_desc'] = data.get('asn_description','')
        results['network']  = data.get('network',{}).get('cidr','')
        results['country']  = data.get('asn_country_code','')

        if results['asn']:
            results['findings'].append({'type':'ASN','value':f"AS{results['asn']} — {results['asn_desc']}","status":'info'})
        if results['network']:
            results['findings'].append({'type':'IP Network','value':results['network'],'status':'info'})
        if results['country']:
            results['findings'].append({'type':'Country','value':results['country'],'status':'info'})

        desc_lower = (results['asn_desc'] or '').lower()
        cloud_names = ['amazon','aws','google','microsoft','azure','cloudflare','digitalocean','linode','ovh']
        for cn in cloud_names:
            if cn in desc_lower:
                results['findings'].append({'type':'Hosting','value':results['asn_desc'],'status':'info'})
                break

    except socket.gaierror as e:
        results['risk_items'].append({'severity':'high','description':f'DNS resolution failed: {e}'})
    except Exception as e:
        results['findings'].append({'type':'ASN Lookup','value':str(e)[:80],'status':'warning'})

    event_q.put({'type':'module_complete','module':'asn','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 7: PORT SCANNER  (≈ projectdiscovery/fastdialer)
# ─────────────────────────────────────────────────────────────────────────────

def scan_ports(hostname: str, event_q: queue.Queue) -> Dict:
    results = {'module':'ports','open_ports':[],'findings':[],'risk_items':[]}

    def check_port(port: int) -> Optional[Dict]:
        try:
            with socket.create_connection((hostname, port), timeout=2) as s:
                banner = ''
                try:
                    s.settimeout(1)
                    if port not in (80,443,8080,8443):
                        s.send(b'\r\n')
                        raw = s.recv(256)
                        banner = raw.decode('utf-8', errors='ignore').strip()[:100]
                except Exception:
                    pass
                svc  = PORT_SERVICES.get(port,'unknown')
                risk = 'high' if port in HIGH_RISK_PORTS else ('medium' if port in MEDIUM_RISK_PORTS else 'low')
                return {'port':port,'service':svc,'banner':banner,'risk':risk}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check_port, p): p for p in COMMON_PORTS}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results['open_ports'].append(r)

    results['open_ports'].sort(key=lambda x: x['port'])

    for p in results['open_ports']:
        status = 'critical' if p['risk']=='high' else ('warning' if p['risk']=='medium' else 'info')
        label  = f"{p['port']}/{p['service']}"
        results['findings'].append({'type':f'Port {label}','value':p['banner'] or 'Open','status':status})
        if p['risk'] in ('high','medium'):
            results['risk_items'].append({'severity':p['risk'],'description':f"Sensitive port open: {label}" + (f" — {p['banner'][:60]}" if p['banner'] else '')})

    event_q.put({'type':'module_complete','module':'ports','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 8: VULN CHECKS  (≈ nuclei template engine)
# ─────────────────────────────────────────────────────────────────────────────

def run_vuln_checks(base_url: str, event_q: queue.Queue) -> Dict:
    results = {'module':'vulns','findings':[],'risk_items':[]}

    def check(vuln: Dict) -> Optional[Dict]:
        for path in vuln['paths']:
            url = base_url.rstrip('/') + path
            try:
                with httpx.Client(timeout=8, verify=False, follow_redirects=False) as c:
                    resp = c.get(url)
                    body_ok   = not vuln.get('body_re') or bool(re.search(vuln['body_re'], resp.text, re.I))
                    status_ok = not vuln.get('status_ok') or (resp.status_code in vuln['status_ok'])
                    # If body_re is set, we also need 200 status
                    if vuln.get('body_re') and not vuln.get('status_ok'):
                        status_ok = resp.status_code == 200
                    if body_ok and status_ok:
                        return {'name':vuln['name'],'url':url,'severity':vuln['severity'],'code':resp.status_code}
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(check, v): v for v in VULN_CHECKS}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results['findings'].append({'type':r['name'],'value':r['url'],'status':r['severity']})
                results['risk_items'].append({'severity':r['severity'],'description':f"{r['name']} at {r['url']}"})

    event_q.put({'type':'module_complete','module':'vulns','data':results})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORER  (≈ nuclei severity DSL + CVSS-style aggregation)
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk(all_results: Dict) -> Dict:
    weights = {'critical':30,'high':15,'medium':8,'low':3,'info':0}
    all_items = []
    for mod_data in all_results.values():
        if isinstance(mod_data, dict):
            all_items.extend(mod_data.get('risk_items', []))

    penalty = sum(weights.get(i.get('severity','low').lower(), 0) for i in all_items)
    score   = max(0, 100 - penalty)

    grade, color = (
        ('A+','#30d158') if score>=95 else
        ('A', '#34c759') if score>=85 else
        ('B', '#9de94b') if score>=70 else
        ('C', '#ffd60a') if score>=55 else
        ('D', '#ff9f0a') if score>=40 else
        ('F', '#ff453a')
    )

    sev_counts: Dict[str,int] = {}
    for item in all_items:
        sv = item.get('severity','low').lower()
        sev_counts[sv] = sev_counts.get(sv, 0) + 1

    return {
        'score':score,'grade':grade,'grade_color':color,
        'total_findings':len(all_items),
        'severity_breakdown':sev_counts,
        'all_risk_items':all_items
    }


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(target: str, event_q: queue.Queue):
    hostname, base_url = normalize_target(target)
    event_q.put({'type':'status','hostname':hostname,'base_url':base_url})

    all_results: Dict = {}

    # Phase 1 — parallel independent recon
    event_q.put({'type':'phase','phase':1,'message':'Launching recon modules…'})
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            ex.submit(scan_dns,    hostname, event_q): 'dns',
            ex.submit(probe_http,  hostname, base_url, event_q): 'http',
            ex.submit(inspect_tls, hostname, event_q): 'tls',
            ex.submit(lookup_asn,  hostname, event_q): 'asn',
            ex.submit(scan_ports,  hostname, event_q): 'ports',
        }
        for f in as_completed(futures):
            mod = futures[f]
            try:
                all_results[mod] = f.result()
            except Exception as e:
                all_results[mod] = {'module':mod,'error':str(e),'risk_items':[],'findings':[]}

    # Phase 2 — dependent analysis (needs HTTP response)
    event_q.put({'type':'phase','phase':2,'message':'Running analysis modules…'})
    http_data = all_results.get('http', {})
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(fingerprint_tech, http_data, event_q): 'tech',
            ex.submit(analyze_headers,  http_data, event_q): 'security_headers',
            ex.submit(run_vuln_checks,  base_url,  event_q): 'vulns',
        }
        for f in as_completed(futures):
            mod = futures[f]
            try:
                all_results[mod] = f.result()
            except Exception as e:
                all_results[mod] = {'module':mod,'error':str(e),'risk_items':[],'findings':[]}

    # Phase 3 — risk scoring
    event_q.put({'type':'phase','phase':3,'message':'Computing risk score…'})
    risk = compute_risk(all_results)
    all_results['risk_score'] = risk

    event_q.put({'type':'complete','data':all_results,'risk':risk})


# ─────────────────────────────────────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan')
def scan():
    target = request.args.get('target','').strip()
    if not target:
        return jsonify({'error':'Target required'}), 400

    event_q: queue.Queue = queue.Queue()
    threading.Thread(target=run_scan, args=(target, event_q), daemon=True).start()

    def stream():
        while True:
            try:
                evt = event_q.get(timeout=120)
                yield f"data: {json.dumps(evt)}\n\n"
                if evt.get('type') == 'complete':
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type':'timeout'})}\n\n"
                break

    return Response(
        stream_with_context(stream()),
        mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Access-Control-Allow-Origin':'*'}
    )


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
