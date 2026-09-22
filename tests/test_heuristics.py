"""
Unit tests for Heuristic Security Analyzer module.
"""

import pytest
from core.heuristic_analyzer import HeuristicAnalyzer


def test_ip_hostname_detection():
    url = "http://192.168.1.1/login.php"
    res = HeuristicAnalyzer.audit_url(url)
    flag_ids = [f["id"] for f in res["flags"]]

    assert "IP_HOSTNAME" in flag_ids
    assert res["heuristic_score"] >= 30


def test_suspicious_tld_detection():
    url = "https://secure-update.xyz/auth"
    res = HeuristicAnalyzer.audit_url(url)
    flag_ids = [f["id"] for f in res["flags"]]

    assert "SUSPICIOUS_TLD" in flag_ids
    assert res["heuristic_score"] >= 20


def test_embedded_credentials():
    url = "http://admin:secret123@phishing-portal.com"
    res = HeuristicAnalyzer.audit_url(url)
    flag_ids = [f["id"] for f in res["flags"]]

    assert "EMBEDDED_CREDENTIALS" in flag_ids
    assert res["heuristic_score"] >= 35


def test_brand_typosquatting_subdomain():
    url = "http://paypal.com.login-verify.site/signin"
    res = HeuristicAnalyzer.audit_url(url)
    flag_ids = [f["id"] for f in res["flags"]]

    assert "BRAND_TYPOSQUATTING" in flag_ids


def test_open_wifi_heuristic():
    wifi_data = {"ssid": "Airport_Guest", "auth_type": "nopass", "password": "", "hidden": False}
    res = HeuristicAnalyzer.audit_wifi(wifi_data)
    flag_ids = [f["id"] for f in res["flags"]]

    assert "WIFI_OPEN_NETWORK" in flag_ids
    assert res["heuristic_score"] >= 40
