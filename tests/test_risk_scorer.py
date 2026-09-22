"""
Unit tests for Risk Scorer module.
"""

import pytest
from core.risk_scorer import RiskScorer


def test_malicious_verdict_classification():
    heuristic_res = {"heuristic_score": 70, "flag_count": 2, "flags": []}
    redirect_res = {"is_shortened": True, "has_protocol_downgrade": False, "excessive_hops": False}
    vt_res = {"fallback_mode": True, "stats": {}}

    res = RiskScorer.calculate_risk("URL", heuristic_res, redirect_res, vt_res)

    assert res["verdict"] == "MALICIOUS"
    assert res["risk_score"] >= 65


def test_safe_verdict_classification():
    heuristic_res = {"heuristic_score": 0, "flag_count": 0, "flags": []}
    redirect_res = {"is_shortened": False, "has_protocol_downgrade": False, "excessive_hops": False}
    vt_res = {"fallback_mode": False, "stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5}}

    res = RiskScorer.calculate_risk("URL", heuristic_res, redirect_res, vt_res)

    assert res["verdict"] == "SAFE"
    assert res["risk_score"] < 30
