"""
Sample QR Code Generator Script.
Generates realistic sample QR code images for academic testing and UI demonstration:
- Legitimate URL QR
- Phishing / Quishing Attack QR (IP hostname + suspicious TLD)
- Shortened Link QR
- Open Insecure Wi-Fi QR
"""

import os
import qrcode


def generate_samples(output_dir: str = "sample_qrs"):
    """
    Generates sample QR code images in output_dir.
    """
    os.makedirs(output_dir, exist_ok=True)

    samples = [
        {
            "filename": "legit_url.png",
            "data": "https://www.wikipedia.org",
            "label": "Legitimate URL (Wikipedia)"
        },
        {
            "filename": "phishing_url.png",
            "data": "http://192.168.1.100/login.xyz?auth=user@chase.com",
            "label": "Phishing QR (IP Host + Suspicious TLD)"
        },
        {
            "filename": "shortened_url.png",
            "data": "https://tinyurl.com/2p8v2h8z",
            "label": "Shortened Link QR (TinyURL)"
        },
        {
            "filename": "open_wifi.png",
            "data": "WIFI:S:Free_Coffee_Guest;T:nopass;;",
            "label": "Insecure Open Wi-Fi QR"
        }
    ]

    print("Generating sample QR code images...")
    generated_paths = []

    for s in samples:
        path = os.path.join(output_dir, s["filename"])
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4
        )
        qr.add_data(s["data"])
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(path)
        print(f"  [+] Created: {path} ({s['label']})")
        generated_paths.append(path)

    print("Done! Sample QR codes ready for testing.")
    return generated_paths


if __name__ == "__main__":
    generate_samples()
