import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# Safe, lightweight nmap: top ports only, service detection, hard timeouts.
NMAP_ARGS = ["-F", "-sV", "--host-timeout", "45s", "--max-retries", "2", "--version-light"]

def normalize_domain(target: str) -> str:
    t = (target or "").strip().lower()
    if not t:
        raise ValueError("missing_target")

    if not t.startswith("http://") and not t.startswith("https://"):
        t = "https://" + t

    p = urlparse(t)
    if not p.hostname:
        raise ValueError("invalid_target")

    if p.port is not None:
        raise ValueError("port_not_allowed")

    if p.path not in ("", "/") or p.params or p.query or p.fragment:
        raise ValueError("path_query_not_allowed")

    host = p.hostname.strip(".").lower()

    if not re.match(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", host):
        raise ValueError("invalid_domain_format")

    if host in ("localhost",):
        raise ValueError("invalid_domain_format")

    return host

def run_nmap(domain: str) -> str:
    cmd = ["nmap", *NMAP_ARGS, domain]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return "nmap_timeout"
    out = (p.stdout or "").strip()
    return out or "nmap_no_output"

def tls_summary(domain: str) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        return {"supported": False, "error": "tls_connect_failed"}

    not_after = cert.get("notAfter")
    expires_iso = None
    days_remaining = None
    if not_after:
        try:
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expires_iso = dt.isoformat()
            days_remaining = (dt - datetime.now(timezone.utc)).days
        except Exception:
            pass

    issuer = {}
    try:
        issuer = dict(x[0] for x in cert.get("issuer", []))
    except Exception:
        issuer = {}

    return {"supported": True, "issuer": issuer, "expires": expires_iso, "days_remaining": days_remaining}

def header_check(domain: str) -> dict:
    url = f"https://{domain}"
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "ACTIVSCAN-Lite/1.0"})
    except requests.RequestException:
        try:
            url = f"http://{domain}"
            r = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "ACTIVSCAN-Lite/1.0"})
        except requests.RequestException:
            return {"reachable": False}

    h = {k.lower(): v for k, v in r.headers.items()}

    return {
        "reachable": True,
        "final_url": r.url,
        "status": r.status_code,
        "hsts": "strict-transport-security" in h,
        "csp": "content-security-policy" in h,
        "x_frame_options": "x-frame-options" in h,
        "x_content_type_options": "x-content-type-options" in h,
        "referrer_policy": "referrer-policy" in h,
        "permissions_policy": "permissions-policy" in h,
        "server_header_present": "server" in h,
    }

def wordpress_hint(domain: str) -> dict:
    try:
        r = requests.get(f"https://{domain}/wp-login.php", timeout=8, allow_redirects=True)
        wp_login = (r.status_code == 200)
    except Exception:
        wp_login = False

    try:
        r2 = requests.get(f"https://{domain}/wp-json/", timeout=8, allow_redirects=True)
        wp_json = (r2.status_code in (200, 401))
    except Exception:
        wp_json = False

    return {"wp_login": wp_login, "wp_json": wp_json, "wordpress_likely": (wp_login or wp_json)}

def run_scan(target: str) -> dict:
    domain = normalize_domain(target)
    return {
        "target": domain,
        "nmap_raw": run_nmap(domain),
        "tls": tls_summary(domain),
        "headers": header_check(domain),
        "wordpress": wordpress_hint(domain),
    }
