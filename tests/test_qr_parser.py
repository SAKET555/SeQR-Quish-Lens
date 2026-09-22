"""
Unit tests for QR Code Parser module.
"""

import os
import pytest
from core.qr_parser import QRParser


def test_classify_payload():
    assert QRParser.classify_payload("https://google.com") == "URL"
    assert QRParser.classify_payload("WIFI:S:MyNet;T:WPA;P:secret;;") == "WIFI"
    assert QRParser.classify_payload("mailto:admin@example.com") == "EMAIL"
    assert QRParser.classify_payload("SMSTO:+123456789:Hello") == "SMS"
    assert QRParser.classify_payload("Just plain text content") == "PLAIN_TEXT"


def test_parse_wifi_payload():
    wifi_str = "WIFI:S:HomeNetwork;T:WPA;P:MySecretPass;H:true;;"
    parsed = QRParser.parse_wifi_payload(wifi_str)

    assert parsed["ssid"] == "HomeNetwork"
    assert parsed["auth_type"] == "WPA"
    assert parsed["password"] == "MySecretPass"
    assert parsed["hidden"] is True


def test_parse_open_wifi():
    wifi_str = "WIFI:S:Cafe_Free;T:nopass;;"
    parsed = QRParser.parse_wifi_payload(wifi_str)

    assert parsed["ssid"] == "Cafe_Free"
    assert parsed["auth_type"] == "nopass"
    assert parsed["password"] == ""


def test_decode_image_file():
    sample_path = os.path.join("sample_qrs", "legit_url.png")
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            image_bytes = f.read()
        res = QRParser.parse(image_bytes, is_raw_text=False)
        assert res["success"] is True
        assert res["raw_text"] == "https://www.wikipedia.org"
        assert res["payload_type"] == "URL"
