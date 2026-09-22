"""
Heuristic Security Analyzer Module.
Audits URLs and payloads for zero-day quishing indicators:
IP hostnames, suspicious TLDs, embedded credentials, Wi-Fi auth flaws, and typosquatting.
"""

import re
import ipaddress
from typing import Dict, Any, List
from urllib.parse import urlparse, unquote
from core.dns_analyzer import DNSAnalyzer


class HeuristicAnalyzer:
    """
    Rule-based security engine that flags phishing/quishing risk indicators.
    """

    SUSPICIOUS_TLDS = {
        "xyz", "top", "gq", "tk", "cf", "ml", "buzz", "work", "click", "monster",
        "fit", "rest", "country", "stream", "download", "zip", "mov", "racing",
        "loan", "icu", "cam", "bid", "win", "party", "space", "site", "online"
    }

    BRAND_KEYWORDS = [
        "paypal", "google", "apple", "microsoft", "amazon", "netflix", "bankofamerica",
        "chase", "wellsfargo", "facebook", "instagram", "linkedin", "meta", "binance",
        "coinbase", "wallet", "login", "secure", "verification", "update-account"
    ]

    EXECUTABLE_EXTENSIONS = [
        ".exe", ".scr", ".bat", ".vbs", ".apk", ".jar", ".iso", ".dmg", ".ps1", ".cmd"
    ]

    @classmethod
    def is_ip_address(cls, hostname: str) -> bool:
        """
        Returns True if hostname is a raw IPv4 or IPv6 address.
        """
        try:
            clean_host = hostname.strip("[]")
            ipaddress.ip_address(clean_host)
            return True
        except ValueError:
            return False

    @classmethod
    def audit_url(cls, url: str) -> Dict[str, Any]:
        """
        Audits a target URL against quishing heuristic rules and live DNS lookup.
        Returns triggered flags, sub-risk score, and safety advice.
        """
        flags: List[Dict[str, Any]] = []
        score = 0

        clean_url = url.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = "http://" + clean_url

        try:
            parsed = urlparse(clean_url)
            hostname = parsed.hostname or ""
            domain = hostname.lower()
            port = parsed.port
            path = parsed.path.lower()
            query = parsed.query.lower()
            scheme = parsed.scheme.lower()
            user_info = parsed.username or parsed.password

            # Live DNS & Host Resolution Audit
            dns_audit = DNSAnalyzer.audit_domain(hostname)
            if dns_audit.get("is_nxdomain") or not dns_audit.get("resolved"):
                flags.append({
                    "id": "DNS_UNRESOLVED_DOMAIN",
                    "severity": "HIGH",
                    "points": 30,
                    "title": "Non-Existent / Unresolved Host (NXDOMAIN)",
                    "description": f"Domain '{hostname}' does not exist or failed DNS resolution. Dead/parking links in QR codes represent high-risk phishing or domain takeover vectors."
                })
                score += 30

            if dns_audit.get("is_private"):
                flags.append({
                    "id": "INTERNAL_RFC1918_EXPOSURE",
                    "severity": "HIGH",
                    "points": 35,
                    "title": "Internal Private Network IP Exposure (SSRF)",
                    "description": f"Domain or IP '{hostname}' resolves to a private RFC1918 / localhost IP address, presenting Server-Side Request Forgery (SSRF) and intranet exposure risk."
                })
                score += 35

            # Rule 1: Embedded Credentials in URL (e.g. http://user:pass@host)
            if "@" in parsed.netloc or user_info:
                flags.append({
                    "id": "EMBEDDED_CREDENTIALS",
                    "severity": "HIGH",
                    "points": 35,
                    "title": "Embedded User Credentials Detected",
                    "description": "URL contains user credentials or '@' symbol, a common trick to disguise the real destination host."
                })
                score += 35

            # Rule 2: IP Address Hostname
            if cls.is_ip_address(hostname):
                flags.append({
                    "id": "IP_HOSTNAME",
                    "severity": "HIGH",
                    "points": 30,
                    "title": "IP Address Hostname Detected",
                    "description": f"URL uses a raw IP address ('{hostname}') instead of a registered domain name."
                })
                score += 30

            # Rule 3: Suspicious TLD
            domain_parts = domain.split(".")
            tld = domain_parts[-1] if len(domain_parts) > 1 else ""
            if tld in cls.SUSPICIOUS_TLDS:
                flags.append({
                    "id": "SUSPICIOUS_TLD",
                    "severity": "MEDIUM",
                    "points": 20,
                    "title": f"High-Risk TLD (.{tld})",
                    "description": f"The top-level domain '.{tld}' is frequently associated with spam and phishing campaigns."
                })
                score += 20

            # Rule 4: Excessive Subdomains
            if len(domain_parts) > 4:
                flags.append({
                    "id": "EXCESSIVE_SUBDOMAINS",
                    "severity": "MEDIUM",
                    "points": 15,
                    "title": "Excessive Subdomains (>3 levels)",
                    "description": f"Domain '{domain}' has {len(domain_parts)-1} subdomains, often used to spoof legitimate brand names."
                })
                score += 15

            # Rule 5: Brand Keyword Spoofing / Typosquatting in Subdomains
            subdomains_str = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""
            for brand in cls.BRAND_KEYWORDS:
                if brand in subdomains_str:
                    flags.append({
                        "id": "BRAND_TYPOSQUATTING",
                        "severity": "HIGH",
                        "points": 25,
                        "title": f"Potential Brand Impersonation ('{brand}')",
                        "description": f"Brand name '{brand}' detected in subdomain string ('{subdomains_str}'), likely attempting to mimic legitimate login portals."
                    })
                    score += 25
                    break

            # Rule 6: Insecure HTTP Scheme with Sensitive Terms
            if scheme == "http":
                sensitive_terms = ["login", "signin", "bank", "account", "verify", "auth", "password", "crypto", "dashboard"]
                if any(term in path or term in query or term in domain for term in sensitive_terms):
                    flags.append({
                        "id": "INSECURE_HTTP_SENSITIVE",
                        "severity": "HIGH",
                        "points": 35,
                        "title": "Insecure HTTP Protocol for Sensitive Endpoint",
                        "description": "URL uses unencrypted HTTP protocol for a credential or login-sensitive endpoint."
                    })
                    score += 35
                else:
                    flags.append({
                        "id": "INSECURE_HTTP",
                        "severity": "MEDIUM",
                        "points": 20,
                        "title": "Unencrypted Plain HTTP Protocol",
                        "description": "URL uses unencrypted http:// protocol instead of secure TLS/HTTPS."
                    })
                    score += 20

            # Rule 7: Non-Standard Web Port
            if port and port not in [80, 443]:
                flags.append({
                    "id": "NON_STANDARD_PORT",
                    "severity": "MEDIUM",
                    "points": 15,
                    "title": f"Non-Standard Port (:{port})",
                    "description": f"URL connects to custom port :{port} rather than standard web ports (80/443)."
                })
                score += 15

            # Rule 8: Dangerous Executable Download Payload
            if any(path.endswith(ext) for ext in cls.EXECUTABLE_EXTENSIONS):
                flags.append({
                    "id": "EXECUTABLE_DOWNLOAD",
                    "severity": "HIGH",
                    "points": 35,
                    "title": "Direct Executable Download Payload",
                    "description": "Target URL points directly to an executable or script installer file."
                })
                score += 35

        except Exception as e:
            flags.append({
                "id": "MALFORMED_URL",
                "severity": "HIGH",
                "points": 30,
                "title": "Malformed URL Structure",
                "description": f"Failed to parse URL structure: {str(e)}"
            })
            score += 30

        return {
            "heuristic_score": min(score, 100),
            "flag_count": len(flags),
            "flags": flags
        }

    @classmethod
    def audit_wifi(cls, wifi_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Audits Wi-Fi QR configuration payloads for security vulnerabilities.
        """
        flags: List[Dict[str, Any]] = []
        score = 0

        auth_type = wifi_details.get("auth_type", "open").upper()
        ssid = wifi_details.get("ssid", "Unknown")

        if auth_type in ["NOPASS", "OPEN", ""]:
            flags.append({
                "id": "WIFI_OPEN_NETWORK",
                "severity": "HIGH",
                "points": 40,
                "title": "Unencrypted / Open Wi-Fi Network",
                "description": f"Network '{ssid}' requires no password authentication. Traffic can be easily intercepted via Man-in-the-Middle (MitM) attacks."
            })
            score += 40

        elif auth_type == "WEP":
            flags.append({
                "id": "WIFI_DEPRECATED_WEP",
                "severity": "HIGH",
                "points": 35,
                "title": "Deprecated WEP Security Protocol",
                "description": f"Network '{ssid}' uses WEP encryption, which is broken and can be cracked in seconds."
            })
            score += 35

        if wifi_details.get("hidden", False):
            flags.append({
                "id": "WIFI_HIDDEN_SSID",
                "severity": "INFO",
                "points": 5,
                "title": "Hidden Network SSID",
                "description": f"Network '{ssid}' is hidden. Client devices broadcast probes continuously to locate it."
            })
            score += 5

        return {
            "heuristic_score": min(score, 100),
            "flag_count": len(flags),
            "flags": flags
        }
