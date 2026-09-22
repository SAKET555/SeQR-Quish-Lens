"""
Unit tests for DNS & Host Resolution Module.
"""

import pytest
from core.dns_analyzer import DNSAnalyzer


def test_nxdomain_detection():
    # Test a guaranteed non-existent domain (.invalid top-level domain per RFC 2606)
    res = DNSAnalyzer.audit_domain("this-domain-definitely-does-not-exist-123456789.invalid")
    assert res["resolved"] is False
    assert res["is_nxdomain"] is True
    assert "NXDOMAIN" in res["error"] or "DNS" in res["error"]


def test_valid_domain_resolution():
    res = DNSAnalyzer.audit_domain("wikipedia.org")
    assert res["resolved"] is True
    assert res["ip"] is not None
    assert res["is_nxdomain"] is False


def test_private_ip_detection():
    assert DNSAnalyzer.is_private_ip("127.0.0.1") is True
    assert DNSAnalyzer.is_private_ip("192.168.1.1") is True
    assert DNSAnalyzer.is_private_ip("10.0.0.1") is True
    assert DNSAnalyzer.is_private_ip("8.8.8.8") is False
