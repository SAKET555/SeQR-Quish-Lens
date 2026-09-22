"""
DNS & Host Resolution Security Module.
Performs live DNS lookups, detects non-existent/unresolved domains (NXDOMAIN),
and checks for internal RFC1918 private IP exposure (SSRF risk).
"""

import socket
import ipaddress
from typing import Dict, Any, List, Optional


class DNSAnalyzer:
    """
    Performs real-time DNS resolution and network host verification.
    """

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """
        Checks if an IP address belongs to RFC1918 private or loopback ranges.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
        except ValueError:
            return False

    @classmethod
    def audit_domain(cls, hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Performs live DNS resolution for a hostname.
        Returns IP addresses, resolution status, and security warnings.
        """
        clean_host = hostname.strip().lower().split(":")[0].strip("[]")
        
        if not clean_host:
            return {
                "resolved": False,
                "hostname": hostname,
                "ip": None,
                "all_ips": [],
                "error": "Empty hostname provided",
                "is_nxdomain": True,
                "is_private": False
            }

        # Check if already a raw IP
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            return {
                "resolved": True,
                "hostname": hostname,
                "ip": clean_host,
                "all_ips": [clean_host],
                "error": None,
                "is_nxdomain": False,
                "is_private": ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            }
        except ValueError:
            pass  # It's a domain name, proceed to DNS lookup

        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        try:
            name, aliases, ip_list = socket.gethostbyname_ex(clean_host)
            primary_ip = ip_list[0] if ip_list else None
            is_private = any(cls.is_private_ip(ip) for ip in ip_list)

            return {
                "resolved": True,
                "hostname": clean_host,
                "ip": primary_ip,
                "all_ips": ip_list,
                "aliases": aliases,
                "error": None,
                "is_nxdomain": False,
                "is_private": is_private
            }

        except socket.gaierror as e:
            # getaddrinfo / gaierror: host not found (NXDOMAIN)
            return {
                "resolved": False,
                "hostname": clean_host,
                "ip": None,
                "all_ips": [],
                "aliases": [],
                "error": f"DNS Lookup Failed (NXDOMAIN / Non-Existent Domain): {str(e)}",
                "is_nxdomain": True,
                "is_private": False
            }
        except socket.timeout:
            return {
                "resolved": False,
                "hostname": clean_host,
                "ip": None,
                "all_ips": [],
                "aliases": [],
                "error": f"DNS Server Timeout ({timeout}s)",
                "is_nxdomain": False,
                "is_private": False
            }
        except Exception as e:
            return {
                "resolved": False,
                "hostname": clean_host,
                "ip": None,
                "all_ips": [],
                "aliases": [],
                "error": f"DNS Resolution Error: {str(e)}",
                "is_nxdomain": False,
                "is_private": False
            }
        finally:
            socket.setdefaulttimeout(old_timeout)
