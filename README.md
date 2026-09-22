# 🛡️ SeQR QuishLens — Smart QR & Quishing Defense Tool

An academic-grade, production-ready Python cybersecurity platform for detecting and mitigating **Quishing (QR Code Phishing)** threats. Integrates VirusTotal API v3, live DNS socket resolution, zero-day heuristic rule auditing, HTTP redirect unshortening, image EXIF tampering inspection, executive PDF report exports, and a dynamic Streamlit dark-mode dashboard.

---

## 🌟 Key Features

1. **📷 QR Code Decoding & Parsing**:
   - Accepts image uploads (`PNG`, `JPG`, `JPEG`, `WEBP`) or direct URL/text strings.
   - Built with `OpenCV` (`cv2.QRCodeDetector`) & `Pillow` for reliable decoding.
   - Classifies payload formats: `URL`, `WIFI`, `EMAIL`, `SMS`, `PLAIN_TEXT`.

2. **🌐 Real-Time DNS & Host Resolution Audit**:
   - Performs live socket IP resolution (`socket.gethostbyname`).
   - Flags `NXDOMAIN` (non-existent/dead domains) with +30 risk points.
   - Detects internal RFC1918 private IP exposure (SSRF risk) with +35 risk points.

3. **🦠 VirusTotal API v3 Intelligence**:
   - Base64-encodes target URLs per VT v3 specification.
   - Queries VirusTotal's threat cloud checking 70+ antivirus engines (Kaspersky, Sophos, Google Safe Browsing, BitDefender, Fortinet, etc.).
   - **Graceful Fallback**: Operates seamlessly in Heuristic-Only mode if no API key is supplied or if rate limits are reached.

4. **🔍 Zero-Day Heuristics & HTTP Redirect Trace**:
   - **Redirect Unshortener**: Traces HTTP 301/302/307/308 redirects for shortened links (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, etc.).
   - **IP Hostname Audit**: Flags raw IPv4/IPv6 host addresses.
   - **Suspicious TLD Detection**: Flags high-risk TLDs (`.xyz`, `.top`, `.tk`, `.gq`, `.buzz`, `.work`, `.click`).
   - **Credential Leakage**: Identifies embedded user credentials in URLs (`http://user:pass@domain`).
   - **Typosquatting & Impersonation**: Detects deceptive brand names inside subdomains (`paypal.com.login-verify.xyz`).
   - **Wi-Fi Security Audit**: Identifies open unencrypted networks (`nopass`) and broken WEP authentication.

5. **📄 Executive PDF Security Audit Report**:
   - 1-click export of a formal PDF report summarizing scan findings, risk breakdown, DNS lookup status, VirusTotal engine results, and SOC recommendations.

6. **🖼️ QR Image Metadata & EXIF Tampering Detector**:
   - Extracts EXIF metadata, aspect ratio, image resolution, and flags software signatures (Photoshop, GIMP, Canva) indicating QR sticker overlay or digital alteration.

7. **📦 Batch / Bulk Multi-URL Threat Scanner**:
   - Scan multiple URLs/payloads simultaneously to produce a comparative risk matrix table with 1-click CSV export.

8. **📜 Session History & CSV Export**:
   - Automatically tracks all scanned QR codes with timestamps, verdicts, risk scores, and 1-click CSV download for SOC compliance.

---

## 🔑 Environment Variables & Security Setup

### Setting Your VirusTotal API Key in `.env`
Create a `.env` file in the root project directory:

```env
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here
```

*Note: If no key is provided, SeQR QuishLens operates in Heuristic-Only Fallback Mode.*

---

## 🚀 How to Run the Project

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Generate Sample QR Code Images (Optional)
```powershell
python generate_sample_qrs.py
```

### 3. Run Automated Unit Tests
```powershell
pytest -v
```

### 4. Launch Streamlit Web Application
```powershell
streamlit run app.py
```

### 🌐 Accessing the Dashboard
Open your web browser at:
- **Local URL**: `http://localhost:8501`

---

## 🧪 Preset Test Scenarios

Select any scenario from the sidebar dropdown **"Load Sample QR Scenario"**:

| Preset Scenario | Payload / URL | Expected Verdict | Key Triggers Inspected |
| :--- | :--- | :--- | :--- |
| **Safe Link (Wikipedia)** | `https://www.wikipedia.org` | **SAFE (0-29)** | Valid HTTPS, active DNS, 0 VT flags |
| **Phishing Attack** | `http://192.168.1.100/login.xyz?auth=user@chase.com` | **MALICIOUS / SUSPICIOUS** | Raw IP host, high-risk `.xyz` TLD, brand impersonation |
| **Shortened URL** | `https://tinyurl.com/2p8v2h8z` | **SUSPICIOUS / SAFE** | URL shortener detected, multi-hop HTTP redirect trace |
| **Insecure Wi-Fi** | `WIFI:S:Free_Coffee_Guest;T:nopass;;` | **SUSPICIOUS / HIGH RISK** | Open unencrypted network (`nopass`) |

---

## 📜 Technical Architecture & Documentation
For a deep dive into system design, technical architecture, and module breakdown, refer to [TECHNICAL_ARCHITECTURE.md](file:///c:/Users/HP/CyberAssignment/TECHNICAL_ARCHITECTURE.md).

---

## ⚖️ License
Licensed under the **Apache License, Version 2.0**. See [LICENSE](file:///c:/Users/HP/CyberAssignment/LICENSE) for full details.

