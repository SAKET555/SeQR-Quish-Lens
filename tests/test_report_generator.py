"""
Unit tests for ReportGenerator PDF export module.
"""

import pytest
from core.report_generator import ReportGenerator


def test_pdf_report_generation():
    raw_text = "https://example.com"
    payload_type = "URL"
    heuristic_result = {"heuristic_score": 10, "flag_count": 1, "flags": [{"severity": "LOW", "title": "Unencrypted HTTP", "description": "Test", "points": 10}]}
    redirect_result = {"success": True, "is_shortened": False, "chain": [], "redirect_count": 0}
    vt_result = {"fallback_mode": True, "reason": "Test", "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}}
    risk_summary = {"verdict": "SAFE", "risk_score": 10, "summary": "Low risk test", "recommendations": ["Verify domain"]}
    dns_result = {"resolved": True, "ip": "93.184.216.34", "error": None}

    pdf_bytes = ReportGenerator.generate_pdf(
        raw_text, payload_type, heuristic_result, redirect_result, vt_result, risk_summary, dns_result
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
