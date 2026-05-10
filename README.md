# RECON-X - Attack Surface Intelligence Platform

A Python Flask web app that combines multiple open-source security libraries to
perform real-time, streaming attack surface recon inspired by the
projectdiscovery Go ecosystem (nuclei, httpx, tlsx, wappalyzergo, cdncheck, asnmap).

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    RECON-X  (Flask + SSE)                │
│                                                          │
│  Phase 1 — Parallel (ThreadPoolExecutor x5)              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────┐ ┌─────┐ │
│  │   DNS    │ │   HTTP   │ │   TLS    │ │ASN │ │PORT │ │
│  │dnspython │ │  httpx   │ │cryptogr. │ │ipwh│ │sock │ │
│  └──────────┘ └──────────┘ └──────────┘ └────┘ └─────┘ │
│                                                          │
│  Phase 2 — Analysis (depends on HTTP response)           │
│  ┌───────────────┐ ┌────────────────┐ ┌──────────────┐  │
│  │ Tech Fingerpr │ │ Sec Headers    │ │ Vuln Checks  │  │
│  │ beautifulsoup │ │ regex matcher  │ │ httpx+nuclei │  │
│  └───────────────┘ └────────────────┘ └──────────────┘  │
│                                                          │
│  Phase 3 — Risk Scoring (CVSS-style aggregation)         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Score: critical×30 + high×15 + medium×8 + low×3 │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  Real-time streaming via SSE → EventSource (JS)          │
└──────────────────────────────────────────────────────────┘
```

## Modules & Library Mapping

| Module              | Library Used           | Inspired By                        |
|---------------------|------------------------|------------------------------------|
| DNS Intelligence    | `dnspython`            | projectdiscovery/retryabledns      |
| HTTP Prober         | `httpx` (HTTP/2)       | projectdiscovery/httpx             |
| TLS Inspector       | `ssl` + `cryptography` | projectdiscovery/tlsx              |
| ASN / IP Intel      | `ipwhois`              | projectdiscovery/asnmap            |
| Port Scanner        | `socket` + threads     | projectdiscovery/fastdialer        |
| Tech Fingerprinter  | `beautifulsoup4`+regex | projectdiscovery/wappalyzergo      |
| Security Headers    | regex pattern engine   | nuclei header-security templates   |
| Vuln Checks         | `httpx` + DSL rules    | nuclei template engine             |
| Risk Scoring        | custom aggregation     | nuclei severity DSL / CVSS         |
| Streaming output    | Flask SSE              | projectdiscovery/gologger          |
| Secret Detection    | regex patterns         | nuclei secret-detection templates  |
| CDN Detection       | header fingerprints    | projectdiscovery/cdncheck          |

## Setup & Run

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## Capabilities

- **DNS**: A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records, SPF/DMARC/DKIM analysis
- **HTTP**: Status, redirect chains, HTTP/2 detection, response timing, CORS probe
- **TLS**: Certificate expiry, SANs, cipher strength, protocol version (TLS 1.3?)
- **ASN**: IP → ASN → org → country → hosting provider
- **Ports**: 24 common ports with service/banner detection
- **Tech**: 35+ technology signatures (CMS, frameworks, CDNs, analytics)
- **CDN**: 12 CDN providers via header/server fingerprinting
- **Headers**: 9 security headers with scoring and remediation advice
- **Vulns**: 10 nuclei-style checks (git, .env, phpinfo, actuator, swagger…)
- **Secrets**: 14 secret patterns in page source (keys, tokens, DB URLs)
- **Risk Score**: 0–100 with A+/A/B/C/D/F grade and severity breakdown
