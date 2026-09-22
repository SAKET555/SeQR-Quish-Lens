"""
Unit tests for VirusTotal API client module.
"""

import pytest
from core.virustotal_client import VirusTotalClient


def test_url_base64_encoding():
    url = "https://www.google.com"
    encoded = VirusTotalClient.encode_url(url)

    assert "=" not in encoded
    assert isinstance(encoded, str)
    assert len(encoded) > 10


def test_missing_api_key_fallback():
    vt_client = VirusTotalClient(api_key="")
    res = vt_client.analyze_url("https://example.com")

    assert res["success"] is False
    assert res["fallback_mode"] is True
    assert "No VirusTotal API Key provided" in res["reason"]
    assert res["stats"]["malicious"] == 0
