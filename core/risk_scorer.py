"""
Unified Risk Scorer & Verdict Classifier Engine.
Combines VirusTotal engine verdicts, heuristic indicators, and redirect hops
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
            # VT is available
            vt_risk_ratio = (vt_malicious * 100 + vt_suspicious * 50) / vt_total_engines
            vt_score = min(vt_risk_ratio * 3.5, 100)  # Scale up vendor detection ratio

            # Weighted combination: 60% VT + 40% Heuristic
            combined_score = (vt_score * 0.60) + (base_heuristic_total * 0.40)

            # Override penalties for strong VT consensus
            if vt_malicious >= 3:
                final_score = max(combined_score, 85)
            elif vt_malicious >= 2 or (vt_malicious == 1 and vt_harmless < 10) or vt_suspicious >= 2:
                final_score = max(combined_score, 60)
            else:
                # Single isolated detection with 10+ harmless vendors -> treated as probable false positive
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
            verdict_color = "#FF4B4B"  # Vibrant Red
            badge_icon = "🚨"
            summary = "HIGH DANGER: Payload exhibits clear malicious quishing patterns, DNS anomalies, or security vendor detections."
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
            verdict_color = "#FFAA00"  # Vibrant Amber/Yellow
            badge_icon = "⚠️"
            summary = "MODERATE RISK: Payload contains suspicious parameters, unresolved DNS hostnames, or insecure configurations."
        else:
            verdict = "SAFE"
            verdict_color = "#00CC96"  # Vibrant Green
            badge_icon = "✅"
            summary = "LOW RISK: No significant security threats or malicious indicators detected."

        # Recommendations
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

    @staticmethod
    def generate_recommendations(
        verdict: str,
        payload_type: str,
        heuristic_result: Dict[str, Any],
        redirect_result: Dict[str, Any],
        vt_result: Dict[str, Any]
    ) -> List[str]:
        """
        Generates actionable security recommendations for the end user.
        """
        recs = []

        h_flag_ids = [f["id"] for f in heuristic_result.get("flags", [])]

        if "DNS_UNRESOLVED_DOMAIN" in h_flag_ids:
            recs.append("🌐 Domain DNS lookup failed (NXDOMAIN). The website does not exist or is parked, presenting domain takeover risks.")

        if "INTERNAL_RFC1918_EXPOSURE" in h_flag_ids:
            recs.append("🛡️ Target IP belongs to an internal private network (RFC1918). Do not attempt connection outside trusted LAN.")

        if "INSECURE_HTTP" in h_flag_ids or "INSECURE_HTTP_SENSITIVE" in h_flag_ids:
            recs.append("🔒 Target uses unencrypted http:// protocol. Never transmit credentials or passwords over unencrypted HTTP.")

        if verdict == "MALICIOUS":
            recs.append("❌ DO NOT open or click the target link. It presents an imminent quishing or malware threat.")
            recs.append("🔒 Report this QR code to your organization's IT Security / SOC team immediately.")
        elif verdict == "SUSPICIOUS":
            recs.append("⚠️ Inspect the destination URL carefully before entering any personal credentials or passwords.")
            recs.append("🔍 Verify the legitimacy of the sender or physical location where the QR code was scanned.")
        else:
            recs.append("✅ Payload appears safe, but always verify domain names in your browser address bar.")

        if redirect_result.get("is_shortened", False):
            recs.append(f"🔗 Link unshortened: Final destination is '{redirect_result.get('final_url')}'. Verify this matches expected domain.")

        if payload_type == "WIFI":
            if "WIFI_OPEN_NETWORK" in h_flag_ids:
                recs.append("📡 Avoid joining open Wi-Fi networks without an active VPN service to prevent traffic sniffing.")
            if "WIFI_DEPRECATED_WEP" in h_flag_ids:
                recs.append("🛡️ Avoid connecting to WEP-encrypted networks as WEP security is compromised.")

        return recs
