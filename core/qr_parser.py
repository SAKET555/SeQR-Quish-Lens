"""
QR Code Parser Module.
Decodes QR images using OpenCV and PIL, extracts raw payloads,
and parses specialized structures like Wi-Fi configurations or URLs.
"""

import re
from typing import Dict, Any, Tuple, Optional
import cv2
import numpy as np
from PIL import Image
import io


class QRParser:
    """
    Decodes QR code images and extracts raw payloads along with structured details.
    """

    @staticmethod
    def decode_image(image_input: Any) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Decodes a QR code from a PIL Image, bytes, or file-like object.
        Returns (success, decoded_text, error_message).
        """
        try:
            pil_image = None
            if isinstance(image_input, Image.Image):
                pil_image = image_input
            elif isinstance(image_input, bytes):
                pil_image = Image.open(io.BytesIO(image_input))
            elif hasattr(image_input, "read"):
                pil_image = Image.open(image_input)
            else:
                return False, None, "Unsupported image input format."

            # Convert PIL image to RGB numpy array for OpenCV
            rgb_image = pil_image.convert("RGB")
            cv_image = np.array(rgb_image)
            # Convert RGB to BGR for OpenCV
            bgr_image = cv2.cvtColor(cv_image, cv2.COLOR_RGB2BGR)

            # Try OpenCV built-in QR Code Detector
            detector = cv2.QRCodeDetector()
            decoded_text, points, _ = detector.detectAndDecode(bgr_image)

            if decoded_text and decoded_text.strip():
                return True, decoded_text.strip(), None

            # Fallback: Convert to grayscale and apply thresholding / contrast adjustment
            gray_image = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
            decoded_text, points, _ = detector.detectAndDecode(gray_image)

            if decoded_text and decoded_text.strip():
                return True, decoded_text.strip(), None

            # Fallback 2: OpenCV WeChat QRCode Detector if available or equalized histogram
            equalized = cv2.equalizeHist(gray_image)
            decoded_text, points, _ = detector.detectAndDecode(equalized)

            if decoded_text and decoded_text.strip():
                return True, decoded_text.strip(), None

            return False, None, "No readable QR code found in the image. Please ensure the QR code is clear and well-lit."

        except Exception as e:
            return False, None, f"Error processing QR image: {str(e)}"

    @staticmethod
    def classify_payload(raw_text: str) -> str:
        """
        Classifies raw decoded text into payload categories:
        'WIFI', 'URL', 'EMAIL', 'SMS', 'PLAIN_TEXT'
        """
        text = raw_text.strip()

        if text.startswith("WIFI:") or text.startswith("wifi:"):
            return "WIFI"
        elif re.match(r"^(https?://|www\.)[^\s]+", text, re.IGNORECASE):
            return "URL"
        elif text.startswith("mailto:") or re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", text):
            return "EMAIL"
        elif text.startswith("SMSTO:") or text.startswith("sms:"):
            return "SMS"
        elif re.search(r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/.*)?$", text):
            # Domain string without explicit http protocol prefix
            return "URL"
        else:
            return "PLAIN_TEXT"

    @staticmethod
    def parse_wifi_payload(raw_text: str) -> Dict[str, Any]:
        """
        Parses standard Wi-Fi QR format:
        WIFI:S:<SSID>;T:<WEP|WPA|nopass>;P:<PASSWORD>;H:<true|false>;;
        """
        result = {
            "ssid": "Unknown",
            "auth_type": "open",
            "password": "",
            "hidden": False,
            "raw_payload": raw_text
        }

        # Remove WIFI: prefix and trailing semicolons
        content = raw_text
        if content.upper().startswith("WIFI:"):
            content = content[5:]

        # Tokenize by semicolon while respecting escaped characters if any
        items = content.split(";")
        for item in items:
            if not item or ":" not in item:
                continue
            key, val = item.split(":", 1)
            key_u = key.upper()
            if key_u == "S":
                result["ssid"] = val
            elif key_u == "T":
                result["auth_type"] = val if val else "open"
            elif key_u == "P":
                result["password"] = val
            elif key_u == "H":
                result["hidden"] = val.lower() in ["true", "1", "y"]

        return result

    @classmethod
    def parse(cls, input_data: Any, is_raw_text: bool = False) -> Dict[str, Any]:
        """
        Full parsing pipeline.
        Accepts image (if is_raw_text=False) or string (if is_raw_text=True).
        """
        if is_raw_text:
            raw_text = str(input_data).strip()
            if not raw_text:
                return {"success": False, "error": "Provided raw text is empty."}
            payload_type = cls.classify_payload(raw_text)
            parsed_details = {}
            if payload_type == "WIFI":
                parsed_details = cls.parse_wifi_payload(raw_text)
            return {
                "success": True,
                "raw_text": raw_text,
                "payload_type": payload_type,
                "parsed_details": parsed_details,
                "error": None
            }

        success, raw_text, error = cls.decode_image(input_data)
        if not success:
            return {"success": False, "error": error}

        payload_type = cls.classify_payload(raw_text)
        parsed_details = {}
        if payload_type == "WIFI":
            parsed_details = cls.parse_wifi_payload(raw_text)

        return {
            "success": True,
            "raw_text": raw_text,
            "payload_type": payload_type,
            "parsed_details": parsed_details,
            "error": None
        }
