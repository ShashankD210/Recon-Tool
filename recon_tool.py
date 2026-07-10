#!/usr/bin/env python3
"""
Recon Toolkit
======================
Aggregates publicly available information about a domain for authorized
security assessments, bug bounty recon, or asset-inventory purposes.

Passive techniques (default — no packets sent to the target beyond normal
HTTP page loads and DNS lookups):
  1. WHOIS lookup
  2. DNS record enumeration (A, AAAA, MX, NS, TXT, SOA)
  3. Subdomain discovery via Certificate Transparency logs (crt.sh)
  4. HTTP banner / header grab + basic tech fingerprinting
  5. robots.txt / sitemap.xml discovery
  6. Shodan lookup (optional, --shodan-key) — queries Shodan's existing
     scan database for the target's primary IP; Shodan does the scanning,
     not this script

Active technique (opt-in only):
  7. Common-port TCP connect scan (--scan-ports), gated behind an explicit
     --i-am-authorized flag since it directly contacts the target host

Output:
  Every scan automatically writes BOTH a JSON and an HTML report to the
  `reports/` directory (timestamped). Use --json FILE / --html FILE to write
  to explicit paths instead.

IMPORTANT: Only run this against domains/assets you own or have explicit
written authorization to test. Unauthorized reconnaissance of third-party
systems may violate computer-fraud laws (e.g., CFAA in the US) even though
most techniques here only touch public data sources.

Usage:
    python3 recon_tool.py example.com
    python3 recon_tool.py example.com --json report.json --html report.html
    python3 recon_tool.py example.com --shodan-key YOUR_KEY
    python3 recon_tool.py example.com --scan-ports --i-am-authorized
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    import dns.resolver
except Exception:
    dns = None

REQUEST_TIMEOUT = 8
USER_AGENT = "PassiveReconToolkit/1.0 (+authorized-use-only)"

# Common ports checked by the optional (opt-in) port scanner. This is a small,
# well-known set — not a stealth/evasion scanner. For serious active scanning
# use Nmap directly against assets you're authorized to test.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Every scan automatically writes both a JSON and an HTML report here
# (unless an explicit --json/--html path overrides it).
DEFAULT_OUTPUT_DIR = "reports"


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))


def write_reports(report, json_path=None, html_path=None, output_dir=DEFAULT_OUTPUT_DIR):
    """Persist the full report as both JSON and HTML.

    Returns the (json_path, html_path) actually written. When no explicit path
    is given, unique timestamped files are created under `output_dir`.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = report.get("host") or report.get("target") or "target"
    base = f"{safe_filename(target)}_{stamp}"
    json_path = json_path or os.path.join(output_dir, base + ".json")
    html_path = html_path or os.path.join(output_dir, base + ".html")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    generate_html_report(report, html_path)
    return json_path, html_path


def banner(title):
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def normalize_target(raw):
    """Accept a domain, a bare IP, or a full URL and return a normalized
    descriptor used throughout the run.

    Returns a dict with:
        raw     - original input
        host    - hostname or IP (no scheme, no port, no path)
        scheme  - scheme if a URL was supplied, else None
        is_ip   - True when `host` is an IP address
        port    - port if a URL included one, else None
    """
    raw = (raw or "").strip()
    scheme = None
    port = None
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or raw
        scheme = parsed.scheme or None
        if parsed.port:
            port = parsed.port
    else:
        host = raw

    # Strip any stray user@host or host:port not captured by urlparse
    if host and "@" in host:
        host = host.split("@", 1)[1]
    if host and ":" in host and not host.startswith("["):
        maybe_host, _, maybe_port = host.rpartition(":")
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    return {"raw": raw, "host": host, "scheme": scheme, "is_ip": is_ip, "port": port}


def get_reverse_dns(ip):
    """PTR lookup for an IP target (reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. WHOIS
# ---------------------------------------------------------------------------
def get_whois(domain):
    if pywhois is None:
        return {"error": "python-whois not installed"}
    try:
        w = pywhois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "org": getattr(w, "org", None),
            "emails": w.emails,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# 2. DNS enumeration
# ---------------------------------------------------------------------------
def get_dns_records(domain):
    if dns is None:
        return {"error": "dnspython not installed"}

    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = REQUEST_TIMEOUT
    resolver.lifetime = REQUEST_TIMEOUT

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records


# ---------------------------------------------------------------------------
# 3. Subdomain discovery via Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------
def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
        subs = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lstrip("*.")
                if line.endswith(domain):
                    subs.add(line)
        return sorted(subs)
    except Exception as e:
        return {"error": str(e)}


def resolve_subdomains(subdomains, max_workers=20):
    """Resolve which discovered subdomains are currently live (A record)."""
    live = {}

    def resolve_one(sub):
        try:
            ip = socket.gethostbyname(sub)
            return sub, ip
        except Exception:
            return sub, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for sub, ip in ex.map(resolve_one, subdomains):
            if ip:
                live[sub] = ip
    return live


# ---------------------------------------------------------------------------
# 4. HTTP header / tech fingerprint
# ---------------------------------------------------------------------------
def get_http_info(host, schemes=None, port=None):
    result = {}
    schemes = schemes or ["https", "http"]
    for scheme in schemes:
        netloc = f"{host}:{port}" if port else host
        url = f"{scheme}://{netloc}"
        try:
            resp = requests.get(
                url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
            )
            result[scheme] = {
                "status_code": resp.status_code,
                "final_url": resp.url,
                "server": resp.headers.get("Server"),
                "powered_by": resp.headers.get("X-Powered-By"),
                "headers": dict(resp.headers),
            }
        except Exception as e:
            result[scheme] = {"error": str(e)}
    return result


# ---------------------------------------------------------------------------
# 5. robots.txt / sitemap.xml
# ---------------------------------------------------------------------------
def get_well_known_files(host, schemes=None, port=None):
    result = {}
    schemes = schemes or ["https", "http"]
    for scheme in schemes:
        netloc = f"{host}:{port}" if port else host
        for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
            url = f"{scheme}://{netloc}{path}"
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
                result[path] = {
                    "status_code": resp.status_code,
                    "snippet": resp.text[:300] if resp.status_code == 200 else None,
                }
            except Exception as e:
                result[path] = {"error": str(e)}
    return result


# ---------------------------------------------------------------------------
# 6. Shodan (optional — requires API key)
# ---------------------------------------------------------------------------
def get_shodan_info(ip, api_key):
    """Pulls Shodan's existing scan data for an IP. This is passive from our
    side — Shodan did the scanning; we're just querying their database."""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return {"info": "No Shodan data for this host"}
        resp.raise_for_status()
        data = resp.json()
        return {
            "org": data.get("org"),
            "isp": data.get("isp"),
            "os": data.get("os"),
            "ports": data.get("ports"),
            "hostnames": data.get("hostnames"),
            "vulns": sorted(data.get("vulns", [])) if data.get("vulns") else [],
            "services": [
                {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                }
                for item in data.get("data", [])
            ],
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# 7. Opt-in active port scanner
# ---------------------------------------------------------------------------
def scan_ports(ip, ports=None, timeout=1.5, max_workers=50):
    """
    Active TCP connect scan against a small set of common ports.
    This is ACTIVE reconnaissance (unlike everything else in this script) —
    it directly touches the target host. Only enabled via --scan-ports and
    requires the --i-am-authorized flag as a deliberate confirmation step.
    """
    ports = ports or COMMON_PORTS
    open_ports = {}

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port, True
        except Exception:
            pass
        return port, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for port, is_open in ex.map(check_port, ports.keys()):
            if is_open:
                open_ports[port] = ports[port]
    return open_ports


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------
def generate_html_report(report, out_path):
    def esc(val):
        return (
            str(val)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def kv_table(d):
        if not isinstance(d, dict):
            return f"<pre>{esc(d)}</pre>"
        rows = "".join(
            f"<tr><th>{esc(k)}</th><td><pre>{esc(json.dumps(v, indent=2, default=str))}</pre></td></tr>"
            for k, v in d.items()
        )
        return f"<table>{rows}</table>"

    subs = report.get("subdomains_found", [])
    live = report.get("live_subdomains", {})
    sub_rows = "".join(
        f"<tr><td>{esc(s)}</td><td>{esc(live.get(s, '—'))}</td></tr>"
        for s in (subs if isinstance(subs, list) else [])
    )

    open_ports = report.get("port_scan", {})
    port_rows = "".join(
        f"<tr><td>{esc(p)}</td><td>{esc(svc)}</td></tr>" for p, svc in open_ports.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
   <title>Recon Report — {esc(report.get('host', report.get('target')))}</title>
<style>
  :root {{
    --bg: #0f1117; --panel: #161923; --border: #262a38;
    --text: #e5e7eb; --muted: #9099ab; --accent: #6ee7b7;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    margin: 0; padding: 2.5rem 1.5rem;
  }}
  .wrap {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 0.2rem; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }}
  section {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
  }}
  h2 {{
    font-size: 1.05rem; margin-top: 0; color: var(--accent);
    border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; vertical-align: top; }}
  th {{ color: var(--muted); width: 160px; white-space: nowrap; }}
  tr {{ border-bottom: 1px solid var(--border); }}
  pre {{ white-space: pre-wrap; word-break: break-word; margin: 0; font-size: 0.8rem; }}
  .warn {{
    background: #2a1f14; border: 1px solid #5c4420; color: #f0c987;
    padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.85rem; margin-bottom: 1.5rem;
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Reconnaissance Report</h1>
  <div class="meta">Target: {esc(report.get('host', report.get('target')))} &nbsp;·&nbsp; Generated: {esc(report.get('generated_at'))}</div>
  <div class="warn">For use only on assets you own or are explicitly authorized to test.</div>

  <section><h2>WHOIS</h2>{kv_table(report.get('whois', {}))}</section>
  <section><h2>DNS Records</h2>{kv_table(report.get('dns', {}))}</section>

  <section>
    <h2>Subdomains ({len(subs) if isinstance(subs, list) else 0} found, {len(live)} live)</h2>
    <table><tr><th>Subdomain</th><th>Resolved IP</th></tr>{sub_rows or '<tr><td colspan=2>None found</td></tr>'}</table>
  </section>

  <section><h2>HTTP Fingerprint</h2>{kv_table(report.get('http', {}))}</section>
  <section><h2>Well-Known Files</h2>{kv_table(report.get('well_known_files', {}))}</section>
"""

    if "shodan" in report:
        html += f'<section><h2>Shodan</h2>{kv_table(report.get("shodan", {}))}</section>\n'

    if open_ports or "port_scan" in report:
        html += f"""<section>
    <h2>Open Ports (active scan)</h2>
    <table><tr><th>Port</th><th>Service</th></tr>{port_rows or '<tr><td colspan=2>None open (of ports checked)</td></tr>'}</table>
  </section>
"""

    html += """</div>
</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_recon(target, shodan_key=None, do_port_scan=False):
    target = normalize_target(target)
    host = target["host"]
    is_ip = target["is_ip"]
    # When a URL (scheme) was supplied, probe that scheme first, then the other.
    schemes = [target["scheme"], ("https" if target["scheme"] == "http" else "http")] \
        if target["scheme"] else ["https", "http"]
    schemes = [s for s in schemes if s]

    report = {
        "target": target["raw"],
        "host": host,
        "is_ip": is_ip,
        "generated_at": datetime.now(datetime.now().astimezone().tzinfo).isoformat(),
    }

    if is_ip:
        report["input_type"] = "ip"
        resolved = get_reverse_dns(host)
        report["reverse_dns"] = resolved
        whois_target = host
    else:
        report["input_type"] = "domain"
        whois_target = host

    banner(f"WHOIS — {whois_target}")
    report["whois"] = get_whois(whois_target)
    print(json.dumps(report["whois"], indent=2, default=str))

    if is_ip:
        banner(f"REVERSE DNS (PTR) — {host}")
        report["dns"] = {"PTR": [resolved] if resolved else []}
        print(json.dumps(report["dns"], indent=2, default=str))
    else:
        banner(f"DNS RECORDS — {host}")
        report["dns"] = get_dns_records(host)
        print(json.dumps(report["dns"], indent=2, default=str))

    if not is_ip:
        banner(f"SUBDOMAINS (Certificate Transparency) — {host}")
        subs = get_subdomains_crtsh(host)
        report["subdomains_found"] = subs
        if isinstance(subs, list):
            print(f"Found {len(subs)} unique subdomains. Resolving liveness...")
            live = resolve_subdomains(subs[:200])  # cap to keep it fast
            report["live_subdomains"] = live
            for sub, ip in sorted(live.items()):
                print(f"  {sub:<40} -> {ip}")
            print(f"\n{len(live)} of {min(len(subs), 200)} checked subdomains resolved live.")
        else:
            print(subs)
    else:
        report["subdomains_found"] = []
        print("Subdomain discovery via Certificate Transparency is skipped for IP targets.")

    banner(f"HTTP HEADERS / FINGERPRINT — {host}")
    report["http"] = get_http_info(host, schemes=schemes, port=target["port"])
    for scheme, info in report["http"].items():
        print(f"[{scheme}] {json.dumps(info, indent=2, default=str)}")

    banner(f"WELL-KNOWN FILES — {host}")
    report["well_known_files"] = get_well_known_files(host, schemes=schemes, port=target["port"])
    print(json.dumps(report["well_known_files"], indent=2, default=str))

    # Resolve the primary IP once, reused by Shodan lookup and port scan
    primary_ip = host if is_ip else None
    if not primary_ip and report["dns"].get("A"):
        primary_ip = report["dns"]["A"][0]

    if shodan_key and primary_ip:
        banner(f"SHODAN — {primary_ip}")
        report["shodan"] = get_shodan_info(primary_ip, shodan_key)
        print(json.dumps(report["shodan"], indent=2, default=str))

    if do_port_scan and primary_ip:
        banner(f"ACTIVE PORT SCAN — {primary_ip}")
        print(f"Scanning {len(COMMON_PORTS)} common ports on {primary_ip}...")
        open_ports = scan_ports(primary_ip)
        report["port_scan"] = open_ports
        if open_ports:
            for port, svc in sorted(open_ports.items()):
                print(f"  {port:<6} open  ({svc})")
        else:
            print("  No open ports found among the common set checked.")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Passive reconnaissance toolkit (authorized use only)."
    )
    parser.add_argument("target", help="Target domain, IP address, or URL, e.g. example.com, 93.184.216.34, https://example.com")
    parser.add_argument("--json", help="Write full report to a JSON file", metavar="FILE")
    parser.add_argument("--html", help="Write full report to an HTML file", metavar="FILE")
    parser.add_argument("--shodan-key", help="Shodan API key to enrich the primary IP", metavar="KEY")
    parser.add_argument(
        "--scan-ports", action="store_true",
        help="Enable ACTIVE TCP port scan of the domain's primary IP (requires --i-am-authorized)",
    )
    parser.add_argument(
        "--i-am-authorized", action="store_true",
        help="Confirms you own or are explicitly authorized to actively scan this target",
    )
    args = parser.parse_args()

    print("Passive Recon Toolkit — for use only on assets you own or are")
    print("explicitly authorized to test.\n")

    do_port_scan = False
    if args.scan_ports:
        if not args.i_am_authorized:
            print(
                "Refusing to run --scan-ports without --i-am-authorized.\n"
                "Port scanning is ACTIVE reconnaissance — it sends packets directly to the\n"
                "target host, unlike the passive checks above. Re-run with both flags once\n"
                "you've confirmed you own or are authorized to test this target:\n\n"
                f"    python3 {sys.argv[0]} {args.target} --scan-ports --i-am-authorized\n"
            )
            sys.exit(1)
        do_port_scan = True

    report = run_recon(args.target, shodan_key=args.shodan_key, do_port_scan=do_port_scan)

    # Always emit both a JSON and an HTML report after a scan. Explicit
    # --json/--html paths override the default timestamped output location.
    json_path, html_path = write_reports(
        report, json_path=args.json, html_path=args.html
    )
    print(f"\nJSON report written to {json_path}")
    print(f"HTML report written to {html_path}")


if __name__ == "__main__":
    main()
