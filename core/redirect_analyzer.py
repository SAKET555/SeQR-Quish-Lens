"""
Redirect & HTTP Hop Analyzer Module.
Traces HTTP 301/302/307/308 redirects to unshorten URLs, audit hop chains,
and detect cloaking or suspicious redirection patterns.
"""

import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class RedirectAnalyzer:
    """
    Traces HTTP redirect chains and analyzes unshortened final destinations.
    """

    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "rebrand.ly",
        "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "t.ly"
    }

    @classmethod
    def is_shortened_url(cls, url: str) -> bool:
        """
        Determines if the given URL domain matches known URL shortener services.
        """
        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            domain = parsed.netloc.lower()
            return domain in cls.KNOWN_SHORTENERS or any(domain.endswith(f".{s}") for s in cls.KNOWN_SHORTENERS)
        except Exception:
            return False

    @classmethod
    def trace_redirects(cls, target_url: str, max_hops: int = 5, timeout: int = 6) -> Dict[str, Any]:
        """
        Follows redirects step-by-step and collects full hop information.
        Returns a structured trace report.
        """
        url = target_url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        chain: List[Dict[str, Any]] = []
        visited = set()
        current_url = url
        is_shortened = cls.is_shortened_url(url)
        has_protocol_downgrade = False
        excessive_hops = False

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 QuishingAnalyzer/1.0"
        }

        try:
            session = requests.Session()
            session.max_redirects = max_hops

            response = session.get(current_url, allow_redirects=True, headers=headers, timeout=timeout, stream=True)

            # Extract history chain from requests response
            if response.history:
                for idx, resp in enumerate(response.history):
                    loc = resp.headers.get("Location", "")
                    chain.append({
                        "step": idx + 1,
                        "url": resp.url,
                        "status_code": resp.status_code,
                        "server": resp.headers.get("Server", "Unknown"),
                        "content_type": resp.headers.get("Content-Type", "Unknown"),
                        "location_header": loc
                    })

                    # Protocol downgrade check
                    if resp.url.startswith("https://") and loc.startswith("http://"):
                        has_protocol_downgrade = True

                # Add final destination
                chain.append({
                    "step": len(response.history) + 1,
                    "url": response.url,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server", "Unknown"),
                    "content_type": response.headers.get("Content-Type", "Unknown"),
                    "location_header": None
                })
            else:
                # Direct destination without redirects
                chain.append({
                    "step": 1,
                    "url": response.url,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server", "Unknown"),
                    "content_type": response.headers.get("Content-Type", "Unknown"),
                    "location_header": None
                })

            final_url = response.url
            hop_count = len(chain) - 1
            if hop_count >= max_hops:
                excessive_hops = True

            return {
                "success": True,
                "initial_url": url,
                "final_url": final_url,
                "is_shortened": is_shortened,
                "redirect_count": hop_count,
                "chain": chain,
                "has_protocol_downgrade": has_protocol_downgrade,
                "excessive_hops": excessive_hops,
                "error": None
            }

        except requests.TooManyRedirects:
            return {
                "success": False,
                "initial_url": url,
                "final_url": current_url,
                "is_shortened": is_shortened,
                "redirect_count": max_hops,
                "chain": chain,
                "has_protocol_downgrade": has_protocol_downgrade,
                "excessive_hops": True,
                "error": f"Redirect limit exceeded (>{max_hops} hops). Potential redirect loop or cloaking."
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "initial_url": url,
                "final_url": current_url,
                "is_shortened": is_shortened,
                "redirect_count": len(chain),
                "chain": chain,
                "has_protocol_downgrade": has_protocol_downgrade,
                "excessive_hops": False,
                "error": f"Network unreachable or DNS lookup failed: {str(e)}"
            }
