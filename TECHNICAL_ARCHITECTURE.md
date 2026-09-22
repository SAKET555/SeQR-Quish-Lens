# 🛡️ SeQR QuishLens — Technical Architecture, System Design & Tech Stack Specification

---

## 📋 Table of Contents
1. [Executive Summary & Project Overview](#1-executive-summary--project-overview)
2. [Quishing Threat Taxonomy & Cyber Attack Vectors](#2-quishing-threat-taxonomy--cyber-attack-vectors)
3. [End-to-End System Architecture & Data Flow](#3-end-to-end-system-architecture--data-flow)
4. [Comprehensive Technology Stack Matrix](#4-comprehensive-technology-stack-matrix)
5. [Deep-Dive Core Security Module Specifications](#5-deep-dive-core-security-module-specifications)
   - [5.1 QR Code Parser & Image Decoder (`core/qr_parser.py`)](#51-qr-code-parser--image-decoder-coreqr_parserpy)
   - [5.2 Live DNS & Network Host Resolution Engine (`core/dns_analyzer.py`)](#52-live-dns--network-host-resolution-engine-coredns_analyzerpy)
   - [5.3 Zero-Day Heuristic Threat Auditor (`core/heuristic_analyzer.py`)](#53-zero-day-heuristic-threat-auditor-coreheuristic_analyzerpy)
   - [5.4 HTTP Redirect & URL Unshortening Engine (`core/redirect_analyzer.py`)](#54-http-redirect--url-unshortening-engine-coreredirect_analyzerpy)
   - [5.5 VirusTotal API v3 Threat Intelligence Client (`core/virustotal_client.py`)](#55-virustotal-api-v3-threat-intelligence-client-corevirustotal_clientpy)
   - [5.6 Image EXIF Metadata & Tampering Auditor (`core/stego_analyzer.py`)](#56-image-exif-metadata--tampering-auditor-corestego_analyzerpy)
   - [5.7 Unified Risk Scoring & Verdict Classifier (`core/risk_scorer.py`)](#57-unified-risk-scoring--verdict-classifier-corerisk_scorerpy)
   - [5.8 Executive PDF Security Report Generator (`core/report_generator.py`)](#58-executive-pdf-security-report-generator-corereport_generatorpy)
   - [5.9 Main Web Platform & Dashboard UI (`app.py`)](#59-main-web-platform--dashboard-ui-apppy)
6. [Mathematical Formulations & Risk Scoring Algorithms](#6-mathematical-formulations--risk-scoring-algorithms)
7. [Security Threat Model & Air-Gapped Defense Mechanisms](#7-security-threat-model--air-gapped-defense-mechanisms)
8. [JSON Data Schemas & API Structures](#8-json-data-schemas--api-structures)
9. [Deployment & Operational Execution Manual](#9-deployment--operational-execution-manual)
10. [Automated Testing & Quality Assurance Framework](#10-automated-testing--quality-assurance-framework)
11. [Future Engineering Roadmap & Research Directions](#11-future-engineering-roadmap--research-directions)

---

## 1. Executive Summary & Project Overview

### 1.1 The Rising Threat of Quishing
In modern enterprise environments, **QR (Quick Response) codes** have emerged as ubiquitous touchpoints for seamless interaction—enabling instant access to menus, payment portals, Wi-Fi networks, authentication flows, and event check-ins. However, this convenience introduces a profound cybersecurity vulnerability commonly known as **Quishing (QR Code Phishing)**.

Unlike traditional email phishing links, QR codes present several unique security challenges:
- **Opaque Visual Encoding**: Human eyes cannot read or interpret QR code matrix patterns to evaluate target URLs before scanning.
- **Mobile Browser Blindspots**: Mobile devices often automatically launch target links upon scanning, bypassing endpoint security agents and URL defense controls.
- **Physical Tampering (Sticker Overlay Attacks)**: Attackers physically apply malicious QR code stickers over legitimate public codes (e.g., parking meters, public transit, shared workspaces).
- **Evasion of Secure Email Gateways (SEGs)**: Email security scanners designed to inspect plain text links frequently fail to extract or parse URLs embedded inside inline QR code image attachments.

### 1.2 Mission & Design Philosophy of SeQR QuishLens
**SeQR QuishLens** is an academic-grade, production-ready Python cybersecurity platform built to neutralize Quishing threats. It operates on a strict **Zero-Trust, Static-First Inspection Philosophy**:
1. **Air-Gapped Parsing**: Payloads are decoded and audited in an isolated Python memory sandbox without triggering automated browser execution or client-side JavaScript execution.
2. **Multi-Layered Defense-in-Depth**: Threat detection fuses zero-day heuristic rules, real-time DNS socket resolution, HTTP redirect unshortening, image EXIF tampering audits, and multi-vendor threat intelligence from VirusTotal API v3.
3. **Actionable SOC Intelligence**: Results are delivered via an interactive Streamlit dashboard, exportable CSV audit logs, and downloadable executive PDF security reports.

### 1.3 Key Features & Platform Capabilities Breakdown

```
+-----------------------------------------------------------------------------------+
|                        PLATFORM FEATURE CAPABILITIES MATRIX                       |
+-----------------------------------------------------------------------------------+
| 1. Multi-Format QR Decoding   | OpenCV + Pillow thresholding (PNG, JPG, WEBP)     |
| 2. Real-Time DNS Socket Audit | Live IP lookup, NXDOMAIN & RFC1918 SSRF detection  |
| 3. VirusTotal Cloud API v3   | Base64 URL queries across 70+ security vendors    |
| 4. Zero-Day Heuristic Engine | Typosquatting, suspicious TLDs, IP host rules     |
| 5. HTTP Redirect Trace       | Unshortens bit.ly/tinyurl, tracks 301/302 hops    |
| 6. Image Tampering Audit     | EXIF metadata, Photoshop/Canva signature checks   |
| 7. Executive PDF Export      | 1-click ReportLab PDF report generation           |
| 8. Batch / Bulk URL Scanner  | Multi-payload audit matrix table with CSV export  |
| 9. Session Threat Logger     | Live SOC compliance logging & CSV history export  |
| 10. Wi-Fi Security Auditor   | Inspects open APs (nopass) & broken WEP protocols |
| 11. Production Risk Gating   | Prevents dead/unresolved domains receiving SAFE   |
| 12. Automated Test Suite     | 17/17 Pytest automated verification coverage      |
+-----------------------------------------------------------------------------------+
```

- **📷 Multi-Format QR Decoding Engine**: Processes raw string inputs and uploaded images (`PNG`, `JPG`, `JPEG`, `WEBP`) using dual OpenCV (`cv2.QRCodeDetector`) and Pillow adaptive thresholding backends.
- **🌐 Real-Time DNS & Host Resolution**: Direct socket resolution (`socket.gethostbyname`) detecting non-existent/unregistered domains (`NXDOMAIN`) and private network IP binding (SSRF risk).
- **🦠 VirusTotal API v3 Cloud Intelligence**: Queries VirusTotal's global database checking 70+ security vendors (Kaspersky, Sophos, Google Safe Browsing, BitDefender, Fortinet) with custom Base64 URL identifier encoding.
- **🔍 Zero-Day Heuristic Analyzer**: Rule-based evaluation of domain structures, brand keyword typosquatting (`paypal`, `chase`, `google`), high-risk TLDs (`.xyz`, `.top`, `.tk`), unencrypted HTTP schemes, and executable download links (`.exe`, `.apk`).
- **🔗 HTTP Redirect Trace & Unshortener**: Traces HTTP location headers across up to 5 redirect hops for shortened links (`bit.ly`, `tinyurl.com`, `t.co`), capturing HTTP status codes and detecting HTTPS-to-HTTP protocol downgrades.
- **🖼️ Image EXIF Metadata & Tampering Auditor**: Reads EXIF metadata tags, inspects image dimensions and aspect ratios, and detects photo-editing software signatures (`Photoshop`, `Canva`, `GIMP`) indicating physical sticker overlays or digital tampering.
- **📄 Executive PDF Security Report Generator**: 1-click export of downloadable, formatted PDF security reports built in-memory with ReportLab.
- **📦 Batch / Bulk Multi-URL Threat Scanner**: Processes lists of multiple URLs/payloads simultaneously, rendering a comparative risk matrix table with 1-click CSV download.
- **📜 Session Threat Log & CSV Compliance Export**: Tracks all scans performed during a session with timestamps, verdicts, risk scores, and VirusTotal stats, exportable as a CSV file for SOC compliance auditing.
- **📶 Wi-Fi Payload Security Auditor**: Decodes Wi-Fi configuration strings (`WIFI:S:SSID;T:WPA;P:password;;`) and flags unencrypted open networks (`nopass`) and deprecated WEP protocols.

---

### 1.4 Fascinating Cybersecurity & QR Code "Fun Facts"

💡 **Did You Know? 6 Mind-Blowing Facts About QR Codes & Quishing Security**:

1. **🏎️ Invented for Auto Parts, Not Web Links**:  
   QR codes were originally invented in **1994** by **Masahiro Hara** at **Denso Wave** (a subsidiary of Toyota). The original purpose was tracking automobile components during manufacturing at high speeds—far before smartphones or web browsing existed!

2. **📐 Why QR Codes Have 3 Corner Squares**:  
   The three large square patterns at the corners of a QR code are called **Position Detection Patterns**. They allow camera sensors to recognize the code orientation and scan it at any 360-degree angle in fractions of a millisecond.

3. **🛡️ The Built-in 30% Damage Healing Trick (Reed-Solomon Error Correction)**:  
   QR codes use **Reed-Solomon Error Correction algorithms**, allowing up to **30% of the QR image to be completely destroyed, dirty, or torn** while remaining 100% readable by cameras! *Cyber Security Insight*: Attackers exploit this error correction capability to physically paste malicious sticker overlays over parts of legitimate public QR codes without breaking camera readability.

4. **🚀 The Word "Quishing" Was Coined in 2022**:  
   A blend of **"QR Code"** and **"Phishing"**, the term *Quishing* gained widespread recognition in 2022 after cybersecurity researchers documented a **587% surge** in malicious QR codes embedded inside enterprise email attachments to bypass Secure Email Gateways (SEGs).

5. **🕵️ Stego-Quishing (The Reverse Contrast Attack)**:  
   Advanced threat actors use **Stego-Quishing**, where malicious URLs are visually hidden inside QR code contrast variations. While human eyes see a benign logo or plain graphic, camera sensors decode the hidden high-contrast matrix pixels, taking victims to phishing pages.

6. **🔑 VirusTotal's Tricky Base64 Encoding Quirk**:  
   When querying VirusTotal API v3, target URLs cannot be sent directly as plain strings. They must be encoded using **URL-safe Base64 encoding with all trailing `=` padding characters stripped**. If the trailing `=` padding is left intact, the VirusTotal API returns a `400 Invalid Identifier` error! *SeQR QuishLens* handles this automatically via `VirusTotalClient.encode_url_identifier()`.

---

## 2. Quishing Threat Taxonomy & Cyber Attack Vectors

To provide defense-in-depth protection, **SeQR QuishLens** is engineered to detect seven distinct categories of Quishing attack vectors:

```
+-----------------------------------------------------------------------------------+
|                            QUISHING THREAT TAXONOMY                               |
+-----------------------------------------------------------------------------------+
| 1. URL Redirection & Cloaking       | Multi-hop 301/302 redirects, URL shorteners  |
| 2. Phishing & Brand Impersonation   | Typosquatting subdomains, fake login portals|
| 3. Physical & Digital Tampering     | QR sticker overlays, editing tool metadata |
| 4. Insecure Wi-Fi Payloads          | Open unencrypted APs (nopass), WEP flaws    |
| 5. Malicious Executable Downloads   | Direct payload links (.exe, .apk, .vbs)     |
| 6. SSRF / Intranet Exposure         | RFC1918 private IP binding (127.0.0.1, 10.x)|
| 7. Unresolved / Dead Domains        | NXDOMAIN host registration hijacking risks  |
+-----------------------------------------------------------------------------------+
```

### 2.1 URL Redirection & Cloaking (Shortener Abuse)
Attackers frequently use URL shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`) or custom redirection scripts to disguise malicious landing pages. 
- **Attack Vector**: The QR code encodes `https://tinyurl.com/xyz`, which redirects through multiple intermediary hops to `http://malicious-phishing-site.com`.
- **Defense**: SeQR QuishLens's `RedirectAnalyzer` recursively traces HTTP location headers up to a configurable maximum hop depth (`max_hops=5`) to reveal the true final destination before risk scoring.

### 2.2 Brand Impersonation & Typosquatting
Phishers register domains or create excessive subdomains mimicking trusted institutions (e.g., `paypal.com.login-verify.xyz` or `chase.auth-security.top`).
- **Attack Vector**: Tricking users into entering credentials on deceptive subdomains.
- **Defense**: `HeuristicAnalyzer` parses domain structures, evaluates subdomain strings against brand keyword dictionaries (`paypal`, `chase`, `google`, `bankofamerica`), and flags suspicious high-risk TLDs (`.xyz`, `.top`, `.tk`, `.buzz`).

### 2.3 Physical & Digital QR Code Tampering
Threat actors print physical QR code stickers and paste them over legitimate codes in public venues, or digitally alter QR images using photo editing software.
- **Attack Vector**: Physical overlay attacks or steganographic payload embedding.
- **Defense**: `StegoAnalyzer` inspects image EXIF metadata for software signatures (`Photoshop`, `Canva`, `GIMP`, `Paint.NET`), evaluates aspect ratio distortions, and flags image resolution anomalies.

### 2.4 Rogue Wi-Fi Payloads (`WIFI:S:...;T:nopass;;`)
QR codes can contain Wi-Fi configuration strings that automatically prompt smartphones to join wireless networks.
- **Attack Vector**: An attacker deploys an Evil Twin access point using an open unencrypted network (`nopass`) or deprecated encryption (`WEP`) to conduct Man-in-the-Middle (MitM) traffic sniffing.
- **Defense**: `QRParser` extracts Wi-Fi parameters (`SSID`, `Authentication Type`, `Password`, `Hidden Status`), and `HeuristicAnalyzer` flags open or WEP-encrypted network configurations with high severity risk warnings.

### 2.5 Malicious Executable Downloads
QR codes engineered to directly trigger binary executable downloads on vulnerable endpoints.
- **Attack Vector**: Direct download links ending in `.exe`, `.apk`, `.bat`, `.vbs`, `.ps1`, or `.cmd`.
- **Defense**: Heuristic pattern filters inspect target file extensions and flag direct executable download links with maximum severity risk points (+35 pts).

### 2.6 Server-Side Request Forgery (SSRF) & Private IP Exposure
Phishers embed raw IP addresses or internal hostnames targeting private corporate networks.
- **Attack Vector**: QR codes targeting `http://127.0.0.1/admin` or RFC1918 private IP ranges (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) to exploit internal corporate intranets or local device management panels.
- **Defense**: `DNSAnalyzer` performs IP address classification, detecting private/loopback IP bindings and flagging `INTERNAL_RFC1918_EXPOSURE` (+35 pts).

### 2.7 Non-Existent & Dead Domains (`NXDOMAIN`)
QR codes pointing to expired, unregistered, or dead domain names.
- **Attack Vector**: Abandoned QR codes on legacy marketing collateral can be purchased by threat actors for domain takeover attacks.
- **Defense**: `DNSAnalyzer` conducts live socket IP resolution (`socket.gethostbyname`). Unresolved domains (`NXDOMAIN`) trigger a `DNS_UNRESOLVED_DOMAIN` flag (+30 pts).

---

## 3. End-to-End System Architecture & Data Flow

### 3.1 Architectural Flowchart
The following diagram illustrates the complete execution pipeline from initial input ingestion to dashboard visualization, report generation, and session logging:

```mermaid
flowchart TD
    subgraph Input Layer
        A1[📷 QR Image File Upload] --> B1[QRParser Module]
        A2[🔗 Raw URL / Text Input] --> B1
        A3[📦 Bulk URL List] --> B2[Batch Scanner Loop]
    end

    subgraph Parsing & Image Inspection Layer
        B1 --> C{Success?}
        C -->|No| D[Display Error Alert]
        C -->|Yes| E[Extract Raw Payload & Payload Type]
        A1 --> F[StegoAnalyzer EXIF Audit]
        F --> G[Extract EXIF Tags & Software Signatures]
    end

    subgraph Parallel Security Audit Layer
        E -->|URL Payload| H1[DNSAnalyzer - Live Socket Lookup]
        E -->|URL Payload| H2[HeuristicAnalyzer - Zero-Day Rules]
        E -->|URL Payload| H3[RedirectAnalyzer - HTTP Unshortener]
        E -->|URL Payload| H4[VirusTotalClient - API v3 Cloud Query]
        E -->|WIFI Payload| H5[HeuristicAnalyzer - Wi-Fi Audit]
    end

    subgraph Unified Risk Scoring Layer
        H1 --> I[RiskScorer Fusion Engine]
        H2 --> I
        H3 --> I
        H4 --> I
        H5 --> I
        G --> I
        
        I --> J1[Compute Base Heuristic Score]
        I --> J2[Compute Redirect Penalties]
        I --> J3[Compute Scaled VirusTotal Vendor Score]
        I --> J4[Apply Consensus Override & Production Gating]
        
        J1 --> K[Final Normalized Risk Score 0-100 & Verdict]
        J2 --> K
        J3 --> K
        J4 --> K
    end

    subgraph Output & Visualization Layer
        K --> L1[Streamlit Reactive Dashboard]
        K --> L2[ReportGenerator - Executive PDF Builder]
        K --> L3[Session Threat Logger - CSV Export]
    end
```

### 3.2 Execution Lifecycle Phases

#### Phase 1: Ingestion & Parsing
1. User uploads a QR image file or inputs text.
2. `QRParser` invokes OpenCV (`cv2.QRCodeDetector`) to detect finder patterns and decode matrix bytes.
3. If OpenCV fails, PIL (`Pillow`) fallback filters process contrast and grayscale channels to recover payload text.
4. Payload text is passed to regex classifiers to determine payload type: `URL`, `WIFI`, `EMAIL`, `SMS`, or `PLAIN_TEXT`.

#### Phase 2: Static Image & EXIF Audit
1. If an image file was uploaded, `StegoAnalyzer` reads EXIF metadata tags using `PIL.ExifTags`.
2. Evaluates `Software` metadata tags against photo-editing software dictionaries (`Photoshop`, `Canva`, `GIMP`, `Paint.NET`).
3. Computes image aspect ratio and resolution bounds.

#### Phase 3: Parallel Security Audits
1. **DNS Lookup**: `DNSAnalyzer` attempts socket IP resolution (`socket.gethostbyname_ex`). Captures `socket.gaierror` for `NXDOMAIN` status.
2. **Heuristic Evaluation**: `HeuristicAnalyzer` tests domain structure, TLD safety, brand typosquatting, unencrypted HTTP protocols, and executable payload extensions.
3. **Redirect Tracing**: `RedirectAnalyzer` initiates bounded HTTP GET requests (`max_hops=5`) with custom User-Agent headers, tracing `Location` headers across redirect steps.
4. **Cloud Intelligence Query**: `VirusTotalClient` encodes target URL into Base64 format and queries VirusTotal REST API v3 endpoint (`/api/v3/urls/{id}`).

#### Phase 4: Risk Scoring Fusion & Gating
1. `RiskScorer` combines sub-scores from VirusTotal, heuristics, redirect penalties, and image metadata.
2. Applies consensus weighting (60% VirusTotal + 40% Heuristic) when API key is active.
3. Filters isolated single-vendor false positives when 50+ major vendors verify a domain as clean.
4. Enforces production gating rules (unresolved DNS or unencrypted sensitive endpoints cannot be marked `SAFE`).

#### Phase 5: Visualization & Export
1. Streamlit dashboard renders verdict banner, metric cards, interactive Plotly charts, and detailed tab views.
2. `ReportGenerator` constructs an in-memory PDF audit report using ReportLab.
3. Scan result is appended to `st.session_state.scan_history` dataframe for 1-click CSV download.

---

## 4. Comprehensive Technology Stack Matrix

The table below documents every core technology, library, version requirement, component responsibility, design rationale, and alternative technology evaluated during system design:

| Technology / Library | Version Requirement | System Component | Primary Role & Responsibility | Architectural Rationale | Alternative Evaluated & Reason Rejected |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python** | `>=3.11.0` | Core Runtime Environment | Powers all analysis modules, network sockets, parsing algorithms, and web servers. | Excellent performance, standard library networking, vast security library ecosystem. | **Node.js**: Inferior native computer vision support; weaker academic PDF generation tools. |
| **Streamlit** | `>=1.30.0` | Web UI Platform | Renders interactive cybersecurity dashboard, reactive input tabs, and file downloads. | Enables fast, purely Python-driven UI generation with modern CSS styling and session state management. | **Flask / Django**: Required writing custom React/Vue frontends, increasing code complexity without added benefit. |
| **OpenCV (`opencv-python`)** | `>=4.8.0` | Computer Vision Engine | Decodes QR code matrix patterns using `cv2.QRCodeDetector()`. | C++ optimized computer vision backend providing fast matrix alignment and decoding. | **pyzbar**: Requires external C-library binaries (`libzbar`) which complicate cross-platform Windows installation. |
| **Pillow (`PIL`)** | `>=10.0.0` | Image Processing & EXIF | Image buffer manipulation, color mode conversion, and EXIF metadata extraction. | Native Python image processing standard; provides clean interface for image properties and EXIF dictionary parsing. | **ImageMagick**: Requires CLI sub-process calls; higher security vulnerability attack surface. |
| **Requests** | `>=2.31.0` | HTTP Client | Follows redirect chains, inspects HTTP response headers, and queries VirusTotal REST API v3. | De-facto standard for Python HTTP networking; clean session management, custom timeouts, and header handling. | **urllib3**: Lower-level syntax requiring manual redirect tracking and header parsing code. |
| **Socket (`socket`)** | `Standard Library` | Network DNS Engine | Executes live IP lookups (`socket.gethostbyname_ex`) and checks host reachability. | Zero external dependencies; direct operating system DNS resolver interface with configurable timeouts. | **dnspython**: Excellent library, but native `socket` handles host-level DNS resolution without extra packages. |
| **ipaddress** | `Standard Library` | IP Range Auditor | Evaluates IPv4/IPv6 addresses against RFC1918 private, loopback, and reserved ranges. | Standard library module for strict IP validation and CIDR subnet checking. | **Custom Regex**: Prone to parsing errors and IPv6 notation edge-case failures. |
| **VirusTotal API v3** | `v3 REST` | Cloud Threat Intelligence | Queries global database of 70+ antivirus engines for domain and URL reputation. | Industry-standard threat intelligence platform aggregating top vendors (Kaspersky, Sophos, Fortinet, etc.). | **Google Safe Browsing API**: Covers fewer engines compared to VirusTotal's 70+ aggregated vendor network. |
| **ReportLab** | `>=4.0.0` | Executive PDF Engine | Constructs downloadable executive PDF security reports in memory (`io.BytesIO`). | Programmatic PDF design standard in Python; supports custom flowables, tables, vector graphics, and dynamic styling. | **pdfkit / FPDF**: Required external `wkhtmltopdf` binary dependencies; weaker layout control. |
| **Pandas** | `>=2.0.0` | Data Structuring | Manages scan history tables, formats batch audit matrices, and generates CSV exports. | Powerful dataframe manipulation for bulk scan operations and seamless Streamlit table rendering. | **Native CSV Module**: Less flexible for dynamic table filtering, batch mapping, and Streamlit display. |
| **Plotly** | `>=5.18.0` | Interactive Data Visualization | Renders dynamic donut charts displaying VirusTotal vendor verdict distributions. | Modern JavaScript-backed chart rendering integrated into Streamlit with custom dark-mode styling support. | **Matplotlib / Seaborn**: Renders static raster images which look pixelated and lack interactive hover tooltips. |
| **Pytest** | `>=8.0.0` | Automated Testing Suite | Unit test runner executing automated test cases across all core modules. | Clean fixture syntax, fast execution, rich assertion error reporting, and seamless CI integration. | **unittest**: Boilerplate verbose class syntax compared to Pytest's simple pythonic function tests. |

---

## 5. Deep-Dive Core Security Module Specifications

### 5.1 QR Code Parser & Image Decoder (`core/qr_parser.py`)

#### Purpose & Architecture
`QRParser` is the primary entry point for payload extraction. It handles two operational input formats:
1. **Raw Payload Strings**: Direct user text or pre-decoded URLs.
2. **QR Code Image Files**: Uploaded image buffers requiring computer vision decoding.

#### Implementation Specification
```python
"""
QR Code Parser & Decoding Module.
Decodes QR image matrix patterns using OpenCV and Pillow,
and classifies payload formats (URL, WIFI, EMAIL, SMS, PLAIN_TEXT).
"""

import re
import cv2
import numpy as np
from PIL import Image
from typing import Dict, Any, Tuple, Optional
from urllib.parse import parse_qs, unquote


class QRParser:
    """
    Decodes QR code images and classifies payload structures.
    """

    @classmethod
    def parse(cls, input_data: Any, is_raw_text: bool = False) -> Dict[str, Any]:
        """
        Parses input data (raw text or image file) and returns decoded details.
        """
        if is_raw_text or isinstance(input_data, str):
            raw_text = str(input_data).strip()
            if not raw_text:
                return {"success": False, "error": "Empty text payload provided"}
            payload_type, parsed_details = cls.classify_payload(raw_text)
            return {
                "success": True,
                "raw_text": raw_text,
                "payload_type": payload_type,
                "parsed_details": parsed_details
            }

        # Handle Image File Input
        decoded_text, error = cls.decode_image(input_data)
        if not decoded_text:
            return {"success": False, "error": error or "Could not decode QR code pattern"}

        payload_type, parsed_details = cls.classify_payload(decoded_text)
        return {
            "success": True,
            "raw_text": decoded_text,
            "payload_type": payload_type,
            "parsed_details": parsed_details
        }

    @classmethod
    def decode_image(cls, file_buffer: Any) -> Tuple[Optional[str], Optional[str]]:
        """
        Attempts QR image decoding using OpenCV with PIL preprocessing fallback.
        """
        try:
            # Step 1: Read PIL Image and convert to OpenCV BGR Format
            pil_img = Image.open(file_buffer).convert('RGB')
            open_cv_img = np.array(pil_img)[:, :, ::-1].copy()

            detector = cv2.QRCodeDetector()
            decoded_text, points, _ = detector.detectAndDecode(open_cv_img)

            if decoded_text and decoded_text.strip():
                return decoded_text.strip(), None

            # Step 2: Fallback Preprocessing - Grayscale & Thresholding
            gray = cv2.cvtColor(open_cv_img, cv2.COLOR_BGR2GRAY)
            decoded_text_gray, _, _ = detector.detectAndDecode(gray)
            if decoded_text_gray and decoded_text_gray.strip():
                return decoded_text_gray.strip(), None

            # Step 3: Adaptive Threshold Fallback
            thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            decoded_text_thresh, _, _ = detector.detectAndDecode(thresh)
            if decoded_text_thresh and decoded_text_thresh.strip():
                return decoded_text_thresh.strip(), None

            return None, "QR Code matrix pattern could not be recognized. Ensure image is clear and unblurred."

        except Exception as e:
            return None, f"Image decoding exception: {str(e)}"

    @classmethod
    def classify_payload(cls, raw_text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Classifies raw text into structured payload types using regex matching.
        """
        text = raw_text.strip()

        # Check Wi-Fi Payload Format (WIFI:S:SSID;T:WPA;P:pass;;)
        if text.startswith("WIFI:") or text.startswith("wifi:"):
            parsed_wifi = cls.parse_wifi_payload(text)
            return "WIFI", parsed_wifi

        # Check URL Format
        url_pattern = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        
        if url_pattern.match(text) or text.startswith("http://") or text.startswith("https://") or "www." in text.lower():
            return "URL", {"url": text}

        # Check Email Format
        if text.startswith("mailto:") or re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text):
            clean_email = text.replace("mailto:", "").split("?")[0]
            return "EMAIL", {"email": clean_email}

        # Check SMS Format
        if text.startswith("smsto:") or text.startswith("SMS:"):
            parts = text.split(":")
            number = parts[1] if len(parts) > 1 else "Unknown"
            message = parts[2] if len(parts) > 2 else ""
            return "SMS", {"number": number, "message": message}

        return "PLAIN_TEXT", {"text": text}

    @staticmethod
    def parse_wifi_payload(text: str) -> Dict[str, Any]:
        """
        Parses standard Wi-Fi QR payload fields: WIFI:S:<SSID>;T:<WPA|WEP|nopass>;P:<PASSWORD>;H:<true|false>;;
        """
        details = {
            "ssid": "Unknown",
            "auth_type": "OPEN",
            "password": "",
            "hidden": False
        }

        # Remove WIFI: prefix and trailing ;;
        clean = re.sub(r'^WIFI:', '', text, flags=re.IGNORECASE).rstrip(';')
        items = clean.split(';')

        for item in items:
            if not item or ':' not in item:
                continue
            key, val = item.split(':', 1)
            key_upper = key.upper()

            if key_upper == 'S':
                details["ssid"] = val
            elif key_upper == 'T':
                details["auth_type"] = val.upper()
            elif key_upper == 'P':
                details["password"] = val
            elif key_upper == 'H':
                details["hidden"] = val.lower() in ['true', '1']

        return details
```

---

### 5.2 Live DNS & Network Host Resolution Engine (`core/dns_analyzer.py`)

#### Purpose & Architecture
`DNSAnalyzer` isolates domain name resolution from web browsing. It executes socket-level DNS queries to identify non-existent domains (`NXDOMAIN`) and private IP address exposures without making HTTP connections.

#### Implementation Specification
```python
"""
DNS & Host Resolution Security Module.
Performs live DNS lookups, detects non-existent/unresolved domains (NXDOMAIN),
and checks for internal RFC1918 private IP exposure (SSRF risk).
"""

import socket
import ipaddress
from typing import Dict, Any, List, Optional


class DNSAnalyzer:
    """
    Performs real-time DNS resolution and network host verification.
    """

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """
        Checks if an IP address belongs to RFC1918 private, loopback, or reserved ranges.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_reserved or 
                ip_obj.is_link_local
            )
        except ValueError:
            return False

    @classmethod
    def audit_domain(cls, hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Performs live DNS resolution for a target hostname.
        """
        clean_host = hostname.strip().lower().split(":")[0].strip("[]")

        if not clean_host:
            return {
                "resolved": False,
                "hostname": hostname,
                "ip": None,
                "all_ips": [],
                "error": "Empty hostname provided",
                "is_nxdomain": True,
                "is_private": False
            }

        # If already a raw IP address
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            return {
                "resolved": True,
                "hostname": hostname,
                "ip": clean_host,
                "all_ips": [clean_host],
                "error": None,
                "is_nxdomain": False,
                "is_private": ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            }
        except ValueError:
            pass  # Host is a domain name, proceed to DNS lookup

        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        try:
            name, aliases, ip_list = socket.gethostbyname_ex(clean_host)
            primary_ip = ip_list[0] if ip_list else None
            is_private = any(cls.is_private_ip(ip) for ip in ip_list)

            return {
                "resolved": True,
                "hostname": clean_host,
                "ip": primary_ip,
                "all_ips": ip_list,
                "aliases": aliases,
                "error": None,
                "is_nxdomain": False,
                "is_private": is_private
            }

        except socket.gaierror as e:
            # gaierror: Name or service not known (NXDOMAIN)
            return {
                "resolved": False,
                "hostname": clean_host,
                "ip": None,
                "all_ips": [],
                "aliases": [],
                "error": f"DNS Lookup Failed (NXDOMAIN / Non-Existent Domain): {str(e)}",
                "is_nxdomain": True,
                "is_private": False
            }
        except socket.timeout:
            return {
                "resolved": False,
                "hostname": clean_host,
                "ip": None,
                "all_ips": [],
                "aliases": [],
                "error": f"DNS Server Timeout ({timeout}s)",
                "is_nxdomain": False,
                "is_private": False
            }
        except Exception as e:
            return {
                "resolved": False,
                "hostname": clean_host,
                "ip": None,
                "all_ips": [],
                "aliases": [],
                "error": f"DNS Resolution Error: {str(e)}",
                "is_nxdomain": False,
                "is_private": False
            }
        finally:
            socket.setdefaulttimeout(old_timeout)
```

---

### 5.3 Zero-Day Heuristic Threat Auditor (`core/heuristic_analyzer.py`)

#### Heuristic Rule Scoring Specifications
The table below details all rule identifiers, severity ratings, assigned risk points, and description logic enforced by `HeuristicAnalyzer`:

| Rule ID | Severity | Risk Points | Trigger Condition / Description |
| :--- | :--- | :--- | :--- |
| `DNS_UNRESOLVED_DOMAIN` | **HIGH** | `+30 pts` | Host fails DNS resolution (`NXDOMAIN`), indicating dead links, expired domains, or domain takeover risks. |
| `INTERNAL_RFC1918_EXPOSURE` | **HIGH** | `+35 pts` | Host resolves to private RFC1918 or loopback IP (`127.0.0.1`, `10.x`, `192.168.x`), presenting SSRF threat. |
| `EMBEDDED_CREDENTIALS` | **HIGH** | `+35 pts` | URL contains `@` or user credentials (`http://user:pass@host`), disguising real host. |
| `IP_HOSTNAME` | **HIGH** | `+30 pts` | URL uses raw IPv4/IPv6 address instead of registered domain. |
| `SUSPICIOUS_TLD` | **MEDIUM** | `+20 pts` | Domain uses spam-heavy TLD (`.xyz`, `.top`, `.tk`, `.gq`, `.buzz`, `.click`, `.work`). |
| `EXCESSIVE_SUBDOMAINS` | **MEDIUM** | `+15 pts` | Domain contains more than 3 subdomain levels (`>4 domain parts`). |
| `BRAND_TYPOSQUATTING` | **HIGH** | `+25 pts` | Subdomain contains trusted brand keywords (`paypal`, `chase`, `google`, `login`). |
| `INSECURE_HTTP_SENSITIVE` | **HIGH** | `+35 pts` | Unencrypted `http://` protocol used for sensitive paths (`/login`, `/auth`, `/dashboard`). |
| `INSECURE_HTTP` | **MEDIUM** | `+20 pts` | Unencrypted `http://` protocol used instead of `https://`. |
| `NON_STANDARD_PORT` | **MEDIUM** | `+15 pts` | URL connects to custom port outside standard web ports (80/443). |
| `EXECUTABLE_DOWNLOAD` | **HIGH** | `+35 pts` | Path ends in executable extension (`.exe`, `.apk`, `.vbs`, `.ps1`, `.bat`). |
| `WIFI_OPEN_NETWORK` | **HIGH** | `+40 pts` | Wi-Fi payload specifies unencrypted network (`T:nopass`), exposing traffic to MitM. |
| `WIFI_DEPRECATED_WEP` | **HIGH** | `+35 pts` | Wi-Fi payload specifies broken WEP encryption (`T:WEP`). |

---

### 5.4 HTTP Redirect & URL Unshortening Engine (`core/redirect_analyzer.py`)

#### Implementation Specification
```python
"""
Redirect & HTTP Hop Analyzer Module.
Traces HTTP 301/302/307/308 redirects to unshorten URLs, audit hop chains,
and detect cloaking or suspicious redirection patterns.
"""

import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class RedirectAnalyzer:
    """
    Traces HTTP redirect chains and analyzes unshortened final destinations.
    """

    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "rebrand.ly",
        "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "t.ly"
    }

    @classmethod
    def is_shortened_url(cls, url: str) -> bool:
        """
        Determines if the URL domain matches known shorteners.
        """
        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            domain = parsed.netloc.lower()
            return domain in cls.KNOWN_SHORTENERS or any(domain.endswith(f".{s}") for s in cls.KNOWN_SHORTENERS)
        except Exception:
            return False

    @classmethod
    def trace_redirects(cls, target_url: str, max_hops: int = 5, timeout: int = 6) -> Dict[str, Any]:
        """
        Follows redirects step-by-step and collects full hop information.
        """
        url = target_url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        chain: List[Dict[str, Any]] = []
        current_url = url
        is_shortened = cls.is_shortened_url(url)
        has_protocol_downgrade = False
        excessive_hops = False

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 QuishingAnalyzer/1.0"
        }

        try:
            session = requests.Session()
            session.max_redirects = max_hops

            response = session.get(current_url, allow_redirects=True, headers=headers, timeout=timeout, stream=True)

            if response.history:
                for idx, resp in enumerate(response.history):
                    loc = resp.headers.get("Location", "")
                    chain.append({
                        "step": idx + 1,
                        "url": resp.url,
                        "status_code": resp.status_code,
                        "server": resp.headers.get("Server", "Unknown"),
                        "content_type": resp.headers.get("Content-Type", "Unknown"),
                        "location_header": loc
                    })

                    # Check HTTPS -> HTTP protocol downgrade
                    if resp.url.startswith("https://") and loc.startswith("http://"):
                        has_protocol_downgrade = True

                # Add final destination
                chain.append({
                    "step": len(response.history) + 1,
                    "url": response.url,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server", "Unknown"),
                    "content_type": response.headers.get("Content-Type", "Unknown"),
                    "location_header": None
                })
            else:
                chain.append({
                    "step": 1,
                    "url": response.url,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server", "Unknown"),
                    "content_type": response.headers.get("Content-Type", "Unknown"),
                    "location_header": None
                })

            final_url = response.url
            hop_count = len(chain) - 1
            if hop_count >= max_hops:
                excessive_hops = True

            return {
                "success": True,
                "initial_url": url,
                "final_url": final_url,
                "is_shortened": is_shortened,
                "redirect_count": hop_count,
                "chain": chain,
                "has_protocol_downgrade": has_protocol_downgrade,
                "excessive_hops": excessive_hops,
                "error": None
            }

        except requests.TooManyRedirects:
            return {
                "success": False,
                "initial_url": url,
                "final_url": current_url,
                "is_shortened": is_shortened,
                "redirect_count": max_hops,
                "chain": chain,
                "has_protocol_downgrade": has_protocol_downgrade,
                "excessive_hops": True,
                "error": f"Redirect limit exceeded (>{max_hops} hops). Potential redirect loop or cloaking."
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "initial_url": url,
                "final_url": current_url,
                "is_shortened": is_shortened,
                "redirect_count": len(chain),
                "chain": chain,
                "has_protocol_downgrade": has_protocol_downgrade,
                "excessive_hops": False,
                "error": f"Network unreachable or connection failed: {str(e)}"
            }
```

---

### 5.5 VirusTotal API v3 Threat Intelligence Client (`core/virustotal_client.py`)

#### Base64 URL Identifier Encoding Standard
Per the VirusTotal API v3 specification, target URLs must be converted into a URL-safe Base64 string without trailing `=` padding:

```text
vt_id = base64url_encode(url).rstrip('=')
```

#### Implementation Specification
```python
"""
VirusTotal API v3 Client Engine.
Queries VirusTotal REST API v3 for URL threat analysis statistics.
Includes custom Base64 URL encoding without padding and heuristic fallback handling.
"""

import base64
import requests
from typing import Dict, Any, Optional


class VirusTotalClient:
    """
    Communicates with VirusTotal REST API v3 endpoint.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key.strip() if api_key else ""

    @staticmethod
    def encode_url_identifier(url: str) -> str:
        """
        Base64url encodes target URL without trailing '=' padding per VT v3 specification.
        """
        raw_bytes = url.strip().encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw_bytes).decode('utf-8')
        return encoded.rstrip("=")

    def analyze_url(self, target_url: str, timeout: int = 8) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for URL security statistics.
        """
        if not self.api_key:
            return {
                "success": False,
                "fallback_mode": True,
                "reason": "VirusTotal API Key not configured. Running in Heuristic Fallback Mode.",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
            }

        url_id = self.encode_url_identifier(target_url)
        endpoint = f"{self.BASE_URL}/{url_id}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(endpoint, headers=headers, timeout=timeout)

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                vendor_results = attributes.get("last_analysis_results", {})

                return {
                    "success": True,
                    "fallback_mode": False,
                    "stats": stats,
                    "vendor_results": vendor_results,
                    "reputation": attributes.get("reputation", 0),
                    "categories": attributes.get("categories", {}),
                    "tags": attributes.get("tags", []),
                    "scan_date": attributes.get("last_analysis_date", 0)
                }

            elif response.status_code == 404:
                return {
                    "success": True,
                    "fallback_mode": False,
                    "reason": "URL not previously scanned in VirusTotal dataset.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "vendor_results": {}
                }
            elif response.status_code == 429:
                return {
                    "success": False,
                    "fallback_mode": True,
                    "reason": "VirusTotal API rate limit exceeded (HTTP 429). Falling back to Heuristic Mode.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
                }
            else:
                return {
                    "success": False,
                    "fallback_mode": True,
                    "reason": f"VirusTotal API HTTP {response.status_code} Error.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
                }

        except requests.RequestException as e:
            return {
                "success": False,
                "fallback_mode": True,
                "reason": f"VirusTotal API Network Timeout: {str(e)}",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
            }
```

---

### 5.6 Image EXIF Metadata & Tampering Auditor (`core/stego_analyzer.py`)

#### Software Signature Inspection List
`StegoAnalyzer` cross-references `Software` EXIF tags against known editing tool signatures:
- `photoshop`, `gimp`, `canva`, `paint.net`, `illustrator`, `inkscape`, `figma`, `pixlr`, `snapseed`, `lightroom`, `picsart`.

---

### 5.7 Unified Risk Scoring & Verdict Classifier (`core/risk_scorer.py`)

#### Implementation Specification
```python
"""
Unified Risk Scorer & Verdict Classifier Engine.
Combines VirusTotal engine verdicts, heuristic indicators, DNS state, and redirect hops
into a normalized 0-100 risk score and security verdict.
"""

from typing import Dict, Any, List


class RiskScorer:
    """
    Calculates unified risk score (0-100) and assigns final verdict classification.
    """

    @classmethod
    def calculate_risk(
        cls,
        payload_type: str,
        heuristic_result: Dict[str, Any],
        redirect_result: Dict[str, Any],
        vt_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Computes normalized overall risk score and outputs verdict details.
        """
        heuristic_score = heuristic_result.get("heuristic_score", 0)
        redirect_penalty = 0

        # Redirect Risk Additions
        if redirect_result.get("is_shortened", False):
            redirect_penalty += 15
        if redirect_result.get("has_protocol_downgrade", False):
            redirect_penalty += 20
        if redirect_result.get("excessive_hops", False):
            redirect_penalty += 25

        base_heuristic_total = min(heuristic_score + redirect_penalty, 100)

        # VirusTotal Integration Scoring
        vt_fallback = vt_result.get("fallback_mode", True)
        vt_stats = vt_result.get("stats", {})
        vt_malicious = vt_stats.get("malicious", 0)
        vt_suspicious = vt_stats.get("suspicious", 0)
        vt_harmless = vt_stats.get("harmless", 0)
        vt_undetected = vt_stats.get("undetected", 0)
        vt_total_engines = vt_malicious + vt_suspicious + vt_harmless + vt_undetected

        final_score = 0
        score_breakdown = {}

        if not vt_fallback and vt_total_engines > 0:
            vt_risk_ratio = (vt_malicious * 100 + vt_suspicious * 50) / vt_total_engines
            vt_score = min(vt_risk_ratio * 3.5, 100)

            # Weighted combination: 60% VT + 40% Heuristic
            combined_score = (vt_score * 0.60) + (base_heuristic_total * 0.40)

            # Consensus Overrides
            if vt_malicious >= 3:
                final_score = max(combined_score, 85)
            elif vt_malicious >= 2 or (vt_malicious == 1 and vt_harmless < 10) or vt_suspicious >= 2:
                final_score = max(combined_score, 60)
            else:
                # Single isolated detection with 10+ harmless vendors -> false positive suppression
                final_score = combined_score

            score_breakdown = {
                "vt_score_contrib": round(vt_score * 0.60, 1),
                "heuristic_score_contrib": round(base_heuristic_total * 0.40, 1),
                "redirect_penalty": redirect_penalty,
                "mode": "Hybrid (VirusTotal + Heuristic)"
            }
        else:
            # Fallback mode (100% Heuristic + Redirect)
            final_score = base_heuristic_total
            score_breakdown = {
                "vt_score_contrib": 0,
                "heuristic_score_contrib": base_heuristic_total,
                "redirect_penalty": redirect_penalty,
                "mode": "Heuristic Only (Fallback Mode)"
            }

        # Production Gating Rules
        h_flag_ids = [f["id"] for f in heuristic_result.get("flags", [])]

        if "DNS_UNRESOLVED_DOMAIN" in h_flag_ids:
            final_score = max(final_score, 35)

        if "INTERNAL_RFC1918_EXPOSURE" in h_flag_ids:
            final_score = max(final_score, 40)

        final_score = round(min(max(final_score, 0), 100))

        # Verdict Classification
        if final_score >= 65:
            verdict = "MALICIOUS"
            verdict_color = "#FF4B4B"
            badge_icon = "🚨"
            summary = "HIGH DANGER: Payload exhibits clear malicious quishing patterns, DNS anomalies, or security vendor detections."
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
            verdict_color = "#FFAA00"
            badge_icon = "⚠️"
            summary = "MODERATE RISK: Payload contains suspicious parameters, unresolved DNS hostnames, or insecure configurations."
        else:
            verdict = "SAFE"
            verdict_color = "#00CC96"
            badge_icon = "✅"
            summary = "LOW RISK: No significant security threats or malicious indicators detected."

        recommendations = cls.generate_recommendations(verdict, payload_type, heuristic_result, redirect_result, vt_result)

        return {
            "risk_score": final_score,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "badge_icon": badge_icon,
            "summary": summary,
            "score_breakdown": score_breakdown,
            "recommendations": recommendations
        }
```

---

## 6. Mathematical Formulations & Risk Scoring Algorithms

### 6.1 Base Heuristic Accumulation Formula
Let $F$ be the set of triggered heuristic flags $f_i \in F$, each carrying risk points $w(f_i)$. The accumulated heuristic score $S_{\text{heur}}$ is bounded in $[0, 100]$:

$$S_{\text{heur}} = \min\left(100, \sum_{i=1}^{|F|} w(f_i)\right)$$

### 6.2 Redirect Penalty Addition Formula
Let $P_{\text{redir}}$ represent accumulated redirect chain penalties:

$$P_{\text{redir}} = P_{\text{short}} + P_{\text{downgrade}} + P_{\text{hops}}$$

where:
- $P_{\text{short}} = 15$ if domain matches URL shortener dictionary, else $0$.
- $P_{\text{downgrade}} = 20$ if HTTPS redirects to plain HTTP, else $0$.
- $P_{\text{hops}} = 25$ if total redirect count $H \ge \text{max\_hops}$, else $0$.

The total combined heuristic sub-score $S_{\text{base}}$ is:

$$S_{\text{base}} = \min\left(100, S_{\text{heur}} + P_{\text{redir}}\right)$$

### 6.3 VirusTotal Detection Ratio & Scaling Formula
Let $M$ be the count of malicious engine detections, $S$ be suspicious detections, and $N_{\text{total}}$ be the total scanned engines. The raw risk ratio $R_{\text{vt}}$ is:

$$R_{\text{vt}} = \frac{100 \cdot M + 50 \cdot S}{N_{\text{total}}}$$

To account for engine coverage density, $R_{\text{vt}}$ is scaled by factor $\alpha = 3.5$:

$$S_{\text{vt}} = \min\left(100, R_{\text{vt}} \cdot 3.5\right)$$

### 6.4 Hybrid Fusion Equation
When VirusTotal cloud intelligence is active ($N_{\text{total}} > 0$), the raw combined score $S_{\text{combined}}$ fuses cloud data (60%) and local heuristics (40%):

$$S_{\text{combined}} = (0.60 \cdot S_{\text{vt}}) + (0.40 \cdot S_{\text{base}})$$

### 6.5 Consensus Overrides & False Positive Suppression
To prevent single niche engine false positives from distorting legitimate site scores, consensus logic applies the following piecewise threshold:

$$S_{\text{final}} = \begin{cases} 
\max(S_{\text{combined}}, 85) & \text{if } M \ge 3 \quad \text{(Strong Malicious Consensus)} \\
\max(S_{\text{combined}}, 60) & \text{if } M \ge 2 \text{ or } (M = 1 \text{ and } H_{\text{clean}} < 10) \text{ or } S \ge 2 \\
S_{\text{combined}} & \text{if } M = 1 \text{ and } H_{\text{clean}} \ge 10 \quad \text{(False Positive Suppression)}
\end{cases}$$

---

## 7. Security Threat Model & Air-Gapped Defense Mechanisms

```
+-----------------------------------------------------------------------------------+
|                        AIR-GAPPED SECURITY BOUNDARY                               |
+-----------------------------------------------------------------------------------+
|  [ User Input / QR File ] ---> ( Memory Buffer )                                 |
|                                       |                                           |
|                                [ OpenCV / PIL ] (No JS / HTML Execution)          |
|                                       |                                           |
|                                [ Direct Socket ] (DNS Lookup Only)                |
|                                       |                                           |
|                                [ Bounded HTTP ] (No Script / File Downloads)     |
|                                       |                                           |
|                                [ REST API ] (Base64 VT Cloud Query)               |
+-----------------------------------------------------------------------------------+
```

### 7.1 Air-Gapped Sandboxing Principles
1. **No Client Browser Rendering**: Uploaded QR codes are never opened in a headless web browser like Selenium or Puppeteer. This prevents drive-by downloads, zero-day browser exploits, and client-side cookie theft.
2. **Bounded Request Streaming**: HTTP redirect tracing uses `stream=True` in Requests. Only header metadata (`Location`, `Server`, `Content-Type`) is parsed; response bodies containing potential web shell exploits are discarded.
3. **Socket Timeout Hardening**: All DNS lookups use strict OS socket timeouts (`timeout=3.0s`) to prevent Denial-of-Service (DoS) thread blocking caused by slow-loris DNS responders.

---

## 8. JSON Data Schemas & API Structures

### 8.1 Unified Audit Result Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "SeQR_QuishLens_AuditResult",
  "type": "object",
  "properties": {
    "raw_text": { "type": "string" },
    "payload_type": { "type": "string", "enum": ["URL", "WIFI", "EMAIL", "SMS", "PLAIN_TEXT"] },
    "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
    "verdict": { "type": "string", "enum": ["SAFE", "SUSPICIOUS", "MALICIOUS"] },
    "verdict_color": { "type": "string" },
    "summary": { "type": "string" },
    "score_breakdown": {
      "type": "object",
      "properties": {
        "vt_score_contrib": { "type": "number" },
        "heuristic_score_contrib": { "type": "number" },
        "redirect_penalty": { "type": "integer" },
        "mode": { "type": "string" }
      }
    },
    "heuristic_result": {
      "type": "object",
      "properties": {
        "heuristic_score": { "type": "integer" },
        "flag_count": { "type": "integer" },
        "flags": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": { "type": "string" },
              "severity": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] },
              "points": { "type": "integer" },
              "title": { "type": "string" },
              "description": { "type": "string" }
            }
          }
        }
      }
    },
    "dns_result": {
      "type": "object",
      "properties": {
        "resolved": { "type": "boolean" },
        "hostname": { "type": "string" },
        "ip": { "type": ["string", "null"] },
        "all_ips": { "type": "array", "items": { "type": "string" } },
        "is_nxdomain": { "type": "boolean" },
        "is_private": { "type": "boolean" }
      }
    },
    "recommendations": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

---

## 9. Deployment & Operational Execution Manual

### 9.1 Prerequisites & System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), or macOS (12.0+).
- **Python Runtime**: Python 3.11 or higher.
- **Memory**: Minimum 2 GB RAM (4 GB recommended).
- **Network**: HTTP/HTTPS access on outbound port 443 for VirusTotal API and DNS socket lookups on port 53.

### 9.2 Step-by-Step Installation
```powershell
# 1. Clone repository
git clone https://github.com/your-username/seqr-quishlens.git
cd seqr-quishlens

# 2. Create Python virtual environment
python -m venv venv

# 3. Activate virtual environment
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# 4. Install production dependencies
pip install -r requirements.txt
```

### 9.3 Environment Variable Setup
Create a `.env` file in the project root:
```env
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here
```

### 9.4 Executing the Application
```powershell
# Launch Streamlit Web Application
streamlit run app.py
```
Access the dashboard at `http://localhost:8501`.

---

## 10. Automated Testing & Quality Assurance Framework

### 10.1 Pytest Execution Suite
The automated test suite in `tests/` verifies end-to-end component integrity:

```powershell
# Run all unit test cases with verbose logging
pytest -v
```

### 10.2 Unit Test Matrix Summary

```
============================= test session starts =============================
platform win32 -- Python 3.11.6, pytest-9.0.3, pluggy-1.6.0
rootdir: C:\Users\HP\CyberAssignment
collected 17 items

tests/test_dns_analyzer.py::test_nxdomain_detection PASSED               [  5%]
tests/test_dns_analyzer.py::test_valid_domain_resolution PASSED          [ 11%]
tests/test_dns_analyzer.py::test_private_ip_detection PASSED             [ 17%]
tests/test_heuristics.py::test_ip_hostname_detection PASSED              [ 23%]
tests/test_heuristics.py::test_suspicious_tld_detection PASSED           [ 29%]
tests/test_heuristics.py::test_embedded_credentials PASSED               [ 35%]
tests/test_heuristics.py::test_brand_typosquatting_subdomain PASSED      [ 41%]
tests/test_heuristics.py::test_open_wifi_heuristic PASSED                [ 47%]
tests/test_qr_parser.py::test_classify_payload PASSED                    [ 52%]
tests/test_qr_parser.py::test_parse_wifi_payload PASSED                  [ 58%]
tests/test_qr_parser.py::test_parse_open_wifi PASSED                     [ 64%]
tests/test_qr_parser.py::test_decode_image_file PASSED                   [ 70%]
tests/test_report_generator.py::test_pdf_report_generation PASSED        [ 76%]
tests/test_risk_scorer.py::test_malicious_verdict_classification PASSED  [ 82%]
tests/test_risk_scorer.py::test_safe_verdict_classification PASSED       [ 88%]
tests/test_virustotal.py::test_url_base64_encoding PASSED                [ 94%]
tests/test_virustotal.py::test_missing_api_key_fallback PASSED           [100%]

============================= 17 passed in 1.18s ==============================
```

---

## 11. Future Engineering Roadmap & Research Directions

### 11.1 Machine Learning NLP URL Classifier
- Train a Random Forest / XGBoost model on TF-IDF character n-grams of 500,000 malicious vs benign URLs to complement rule-based heuristics.

### 11.2 Automated YARA Rule Matching
- Integrate YARA scanning engine to evaluate landing page HTML content and embedded script attachments for malware signatures.

### 11.3 Enterprise SIEM & Webhook Integrations
- Add syslog, Splunk HEC, and Webhook notification connectors to automatically alert SOC security operations centers when malicious Quishing attacks are detected.
