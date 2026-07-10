# Recon Tool

A passive (and optionally active) reconnaissance toolkit for authorized
security assessments, bug-bounty recon, and asset inventory. It aggregates
publicly available information about a domain from well-known public sources.

> **⚠️ Only run this against domains/assets you own or have explicit written
> authorization to test.** Unauthorized reconnaissance of third-party systems
> may violate computer-fraud laws (e.g., CFAA in the US), even when only public
> data sources are used.

## Features

| # | Technique | Type |
|---|-----------|------|
| 1 | WHOIS lookup | Passive |
| 2 | DNS record enumeration (A, AAAA, MX, NS, TXT, SOA) | Passive |
| 3 | Subdomain discovery via Certificate Transparency logs (crt.sh) | Passive |
| 4 | HTTP banner / header grab + basic tech fingerprinting | Passive |
| 5 | robots.txt / sitemap.xml / security.txt discovery | Passive |
| 6 | Shodan lookup (optional, `--shodan-key`) | Passive |
| 7 | Common-port TCP connect scan (`--scan-ports`, opt-in) | **Active** |

Active port scanning directly contacts the target host and is gated behind an
explicit `--i-am-authorized` flag.

## Requirements

- Python 3.8+
- `requests` (required)
- `python-whois` (optional — WHOIS)
- `dnspython` (optional — DNS enumeration)

## Installation

This environment is externally managed (PEP 668), so install into a virtual
environment created inside the folder:

```bash
cd recon_toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install requests python-whois dnspython
```

Then run the tool with the activated venv (`./recon_tool.py` or `python
recon_tool.py ...`). Running with the system `python3` will report the optional
dependencies as "not installed".

`requests` is required. `python-whois` and `dnspython` are optional; the tool
reports a clear message instead of crashing if they are missing. The tool
gracefully degrades when an optional dependency fails to import for any reason.

## Usage

The positional `target` accepts a **domain**, a **bare IP address**, or a full
**URL** (including scheme and optional port). The tool adapts each check:

- **Domain** — full recon (WHOIS, forward DNS, subdomain/CT, HTTP, files, Shodan, port scan).
- **IP address** — reverse DNS (PTR) instead of forward DNS, no Certificate
  Transparency subdomain lookup, and the IP is used directly for HTTP, Shodan,
  and port scan.
- **URL** — scheme (and port, if present) is honored for the HTTP/well-known
  checks; the host is extracted for the rest.

```bash
# Basic passive recon — domain, IP, or URL all accepted
python3 recon_tool.py example.com
python3 recon_tool.py 93.184.216.34
python3 recon_tool.py https://example.com
python3 recon_tool.py http://example.com:8080

# Save full report as JSON and HTML
python3 recon_tool.py example.com --json report.json --html report.html

# Enrich the primary IP with Shodan data
python3 recon_tool.py example.com --shodan-key YOUR_KEY

# Active port scan (requires explicit authorization)
python3 recon_tool.py 93.184.216.34 --scan-ports --i-am-authorized
```

If `--scan-ports` is supplied without `--i-am-authorized`, the tool refuses to
run the active scan and exits.

## Output

- `--json FILE` — writes the full structured report as JSON.
- `--html FILE` — writes a formatted, styled HTML report.

## File notes

- `recon_tool.py` and `recon_tool1.py` are identical copies.
- Known environment caveat: on systems with a mismatched `pyOpenSSL` /
  `cryptography` version, `import dns.resolver` can raise an `AttributeError`
  (`module 'lib' has no attribute 'GEN_EMAIL'`). The import guard catches this
  so the rest of the tool still runs; install a compatible `dnspython` +
  `pyOpenSSL` / `cryptography` pair to enable DNS enumeration.
