"""
VirusTotal API v3 Integration Client.
Handles URL Base64 encoding per VT v3 specification, queries analysis metrics,
and provides graceful fallback when API keys are absent or rate-limited.
"""

import base64
import os
import requests
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables if present
load_dotenv()


class VirusTotalClient:
    """
    Client for VirusTotal API v3 URL lookup and verdict extraction.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VT client with optional explicit API key.
        If not provided, attempts to load from environment variable VIRUSTOTAL_API_KEY.
        """
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    @staticmethod
    def encode_url(url: str) -> str:
        """
        Encodes a URL into Base64 format without trailing '=' padding
        as required by VirusTotal API v3.
        """
        # Ensure URL has protocol if missing
        clean_url = url.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = "http://" + clean_url
        
        encoded_bytes = base64.urlsafe_b64encode(clean_url.encode("utf-8"))
        return encoded_bytes.decode("utf-8").strip("=")

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for the target URL.
        Returns structured analysis results or a graceful fallback report if API key is missing/invalid.
        """
        if not self.api_key or self.api_key.strip() in ("", "your_virustotal_api_key_here"):
            return {
                "success": False,
                "fallback_mode": True,
                "reason": "No VirusTotal API Key provided. Operating in Heuristic-Only Fallback Mode.",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "vendor_results": {},
                "reputation": 0
            }

        url_id = self.encode_url(url)
        endpoint = f"{self.BASE_URL}/{url_id}"
        headers = {
            "x-apikey": self.api_key.strip(),
            "Accept": "application/json"
        }

        try:
            response = requests.get(endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {
                    "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0
                })
                vendor_results = attributes.get("last_analysis_results", {})
                reputation = attributes.get("reputation", 0)

                # Process vendor results into a clean list/dict
                vendor_summary = {}
                for vendor_name, vendor_data in vendor_results.items():
                    category = vendor_data.get("category", "undetected")
                    result = vendor_data.get("result", category)
                    vendor_summary[vendor_name] = {
                        "category": category,
                        "result": result
                    }

                return {
                    "success": True,
                    "fallback_mode": False,
                    "stats": stats,
                    "vendor_results": vendor_summary,
                    "reputation": reputation,
                    "categories": attributes.get("categories", {}),
                    "tags": attributes.get("tags", []),
                    "scan_date": attributes.get("last_analysis_date")
                }

            elif response.status_code == 404:
                return {
                    "success": False,
                    "fallback_mode": True,
                    "reason": "URL not found in VirusTotal database (not scanned yet).",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "vendor_results": {},
                    "reputation": 0
                }

            elif response.status_code == 401:
                return {
                    "success": False,
                    "fallback_mode": True,
                    "reason": "Invalid VirusTotal API Key supplied. Falling back to local heuristic analysis.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "vendor_results": {},
                    "reputation": 0
                }

            elif response.status_code == 429:
                return {
                    "success": False,
                    "fallback_mode": True,
                    "reason": "VirusTotal API rate limit / quota exceeded (429). Falling back to heuristic analysis.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "vendor_results": {},
                    "reputation": 0
                }

            else:
                return {
                    "success": False,
                    "fallback_mode": True,
                    "reason": f"VirusTotal API error (HTTP {response.status_code}). Falling back to heuristic analysis.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "vendor_results": {},
                    "reputation": 0
                }

        except requests.RequestException as e:
            return {
                "success": False,
                "fallback_mode": True,
                "reason": f"Network error connecting to VirusTotal API: {str(e)}",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "vendor_results": {},
                "reputation": 0
            }
