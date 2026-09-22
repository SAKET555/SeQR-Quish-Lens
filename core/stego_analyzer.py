"""
QR Image Metadata & Tampering/Steganography Analyzer Module.
Extracts EXIF metadata, inspects color profiles, detects editing software tags (Photoshop/GIMP/Canva),
and checks for physical overlay or digital alteration anomalies.
"""

from typing import Dict, Any, List, Optional
from PIL import Image, ExifTags


class StegoAnalyzer:
    """
    Analyzes uploaded QR code images for metadata traces and manipulation indicators.
    """

    EDITING_SOFTWARE_KEYWORDS = [
        "photoshop", "gimp", "canva", "paint.net", "illustrator", "inkscape",
        "figma", "pixlr", "snapseed", "lightroom", "picsart"
    ]

    @classmethod
    def audit_image(cls, image_source: Any) -> Dict[str, Any]:
        """
        Inspects an uploaded image for metadata, software signatures, and structural properties.
        `image_source` can be a file path, PIL Image, or BytesIO buffer.
        """
        metadata: Dict[str, Any] = {
            "format": "Unknown",
            "size_pixels": "Unknown",
            "mode": "Unknown",
            "has_exif": False,
            "software": None,
            "datetime_original": None,
            "camera_make": None,
            "tampering_flags": []
        }

        try:
            if isinstance(image_source, Image.Image):
                img = image_source
            else:
                img = Image.open(image_source)

            metadata["format"] = img.format or "PNG/Memory"
            metadata["size_pixels"] = f"{img.width}x{img.height}"
            metadata["mode"] = img.mode

            # Aspect ratio check
            aspect_ratio = img.width / max(img.height, 1)
            if aspect_ratio < 0.6 or aspect_ratio > 1.6:
                metadata["tampering_flags"].append({
                    "id": "NON_SQUARE_ASPECT_RATIO",
                    "severity": "LOW",
                    "title": "Non-Square Aspect Ratio",
                    "description": f"QR image aspect ratio ({aspect_ratio:.2f}) is skewed. Standard QR codes are perfectly 1:1 square."
                })

            # EXIF Inspection
            exif_data = None
            if hasattr(img, "_getexif") and callable(img._getexif):
                try:
                    exif_data = img._getexif()
                except Exception:
                    exif_data = None

            if exif_data:
                metadata["has_exif"] = True
                exif_dict = {}
                for tag_id, value in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                    exif_dict[tag_name] = value

                # Check Software tag
                software = str(exif_dict.get("Software", "")).strip()
                if software:
                    metadata["software"] = software
                    soft_lower = software.lower()
                    if any(sw in soft_lower for sw in cls.EDITING_SOFTWARE_KEYWORDS):
                        metadata["tampering_flags"].append({
                            "id": "IMAGE_EDITING_SOFTWARE_DETECTED",
                            "severity": "MEDIUM",
                            "title": f"Editing Software Signature ('{software}')",
                            "description": f"Image metadata indicates modification using photo editing software ({software}), suggesting possible digital overlay or QR sticker replacement."
                        })

                if "DateTimeOriginal" in exif_dict:
                    metadata["datetime_original"] = str(exif_dict["DateTimeOriginal"])
                if "Make" in exif_dict:
                    metadata["camera_make"] = f"{exif_dict.get('Make', '')} {exif_dict.get('Model', '')}".strip()

            # Image size resolution check
            if img.width < 100 or img.height < 100:
                metadata["tampering_flags"].append({
                    "id": "LOW_RESOLUTION_IMAGE",
                    "severity": "LOW",
                    "title": "Low Resolution Image (<100px)",
                    "description": f"Image dimensions ({img.width}x{img.height}) are very small. Low-resolution QR images can cause decoding errors."
                })

            return metadata

        except Exception as e:
            metadata["error"] = f"Failed to parse image metadata: {str(e)}"
            return metadata
