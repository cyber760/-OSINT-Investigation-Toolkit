import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

TIMEOUT = 12
USER_AGENT = "OSINT-Investigation-Toolkit/1.0 (educational research)"


def normalize_target(value):
    value = value.strip()
    if not value:
        raise ValueError("Enter a domain name, IP address, or URL.")
    if "://" not in value and "/" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    host = parsed.hostname
    if not host:
        raise ValueError("Could not identify a valid hostname.")
    return host.lower().strip(".")


def domain_report(target):
    host = normalize_target(target)
    try:
        ipaddress.ip_address(host)
        return ip_report(host)
    except ValueError:
        pass

    result = {
        "target": host,
        "type": "domain",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dns": {},
        "rdap": {},
        "http": {},
        "notes": [
            "Only public DNS, RDAP, and website response information is queried.",
            "Results can be incomplete or affected by network/API limits."
        ],
    }

    try:
        result["resolved_addresses"] = sorted({
            item[4][0] for item in socket.getaddrinfo(host, None)
        })
    except socket.gaierror as exc:
        result["resolution_error"] = str(exc)

    try:
        import dns.resolver
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(host, record_type, lifetime=5)
                result["dns"][record_type] = [str(answer) for answer in answers]
            except Exception as exc:
                result["dns"][record_type] = [f"Unavailable: {exc.__class__.__name__}"]
    except ImportError:
        result["dns"]["notice"] = "Install dnspython to enable detailed DNS records."

    try:
        response = requests.get(
            f"https://rdap.org/domain/{host}",
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if response.ok:
            data = response.json()
            result["rdap"] = {
                "handle": data.get("handle"),
                "ldhName": data.get("ldhName"),
                "status": data.get("status", []),
                "events": data.get("events", []),
                "nameservers": [
                    ns.get("ldhName") for ns in data.get("nameservers", [])
                ],
            }
        else:
            result["rdap"]["error"] = f"RDAP returned HTTP {response.status_code}"
    except requests.RequestException as exc:
        result["rdap"]["error"] = str(exc)

    try:
        response = requests.get(
            f"https://{host}",
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        result["http"] = {
            "final_url": response.url,
            "status_code": response.status_code,
            "server_header": response.headers.get("Server", "Not disclosed"),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "https": response.url.lower().startswith("https://"),
        }
    except requests.RequestException as exc:
        result["http"]["error"] = str(exc)

    return result


def ip_report(target):
    ip = str(ipaddress.ip_address(target.strip()))
    result = {
        "target": ip,
        "type": "ip",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "classification": {
            "is_private": ipaddress.ip_address(ip).is_private,
            "is_global": ipaddress.ip_address(ip).is_global,
            "is_loopback": ipaddress.ip_address(ip).is_loopback,
            "version": ipaddress.ip_address(ip).version,
        },
        "reverse_dns": None,
        "public_geolocation": {},
        "notes": [
            "Geolocation is approximate and may identify an ISP or hosting provider, not a person.",
            "No port scanning, exploitation, or account access is performed."
        ],
    }
    try:
        result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        result["reverse_dns"] = "No PTR record found"

    if ipaddress.ip_address(ip).is_global:
        try:
            response = requests.get(
                f"https://ipwho.is/{ip}",
                timeout=TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
            data = response.json()
            if data.get("success"):
                result["public_geolocation"] = {
                    "country": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "isp": (data.get("connection") or {}).get("isp"),
                    "organization": (data.get("connection") or {}).get("org"),
                }
            else:
                result["public_geolocation"]["notice"] = data.get("message", "Lookup unavailable")
        except requests.RequestException as exc:
            result["public_geolocation"]["error"] = str(exc)
    else:
        result["public_geolocation"]["notice"] = "Private/reserved IP: public geolocation skipped."
    return result


def email_domain_report(email):
    email = email.strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter an email address in a valid format.")
    domain = email.rsplit("@", 1)[1].lower()
    result = {
        "target": email,
        "type": "email-domain-check",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "syntax_valid": True,
        "domain": domain,
        "mx_records": [],
        "warning": "This checks syntax and public domain mail records only. It does not verify mailbox ownership or existence.",
    }
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["mx_records"] = [str(answer) for answer in answers]
    except Exception as exc:
        result["mx_records"] = [f"MX lookup unavailable: {exc.__class__.__name__}"]
    return result


def save_report(data, output_dir="reports"):
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", data.get("target", "investigation"))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = folder / f"{safe}_{stamp}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
