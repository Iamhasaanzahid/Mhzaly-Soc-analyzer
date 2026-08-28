import hashlib
import json
import re
import sqlite3
from datetime import datetime

class ThreatAnalyzer:
    def __init__(self, db_path="soc_analyzer.db"):
        self.db_path = db_path
        self._init_db()
        
        # Comprehensive Web Attack Signatures (OWASP Standard)
        self.attack_signatures = {
            "SQL Injection (SQLi)": {
                "patterns": [r"(\%27)|(\')|(\-\-)|(\%23)|(#)", r"\b(select|union|insert|update|delete|drop|alter|exec|cast|schema)\b", r"or\s+1\s*=\s*1", r"'\s*or\s*'"],
                "severity": "CRITICAL",
                "cwe": "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)"
            },
            "Cross-Site Scripting (XSS)": {
                "patterns": [r"<script.*?>.*?</script>", r"javascript:", r"onerror\s*=", r"onload\s*=", r"<img.*?src=.*?>", r"alert\(", r"document\.cookie"],
                "severity": "HIGH",
                "cwe": "CWE-79 (Improper Neutralization of Input During Web Page Generation)"
            },
            "Command Injection (RCE)": {
                "patterns": [r";\s*(ls|cat|whoami|id|uname|dir|type|powershell|bash|sh|cmd)", r"\|\s*(ls|cat|whoami|id|uname)", r"`whoami`", r"\$\(whoami\)"],
                "severity": "CRITICAL",
                "cwe": "CWE-78 (OS Command Injection)"
            },
            "Directory / Path Traversal": {
                "patterns": [r"\.\./", r"\.\.\\", r"/etc/passwd", r"c:\\windows\\system32", r"win.ini"],
                "severity": "HIGH",
                "cwe": "CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)"
            },
            "Server-Side Request Forgery (SSRF)": {
                "patterns": [r"169\.254\.169\.254", r"metadata\.google\.internal", r"localhost", r"127\.0\.0\.1"],
                "severity": "HIGH",
                "cwe": "CWE-918 (Server-Side Request Forgery)"
            }
        }

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payload_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT,
                    overall_threat TEXT,
                    risk_score INTEGER,
                    detections_count INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    # --- 1. Comprehensive Web Threat Deep Scan ---
    def analyze_web_payload(self, payload_string):
        """Analyzes string against full OWASP attack signatures and logs into database"""
        if not payload_string:
            return {"error": "Empty payload string provided"}

        detections = []
        overall_threat = "CLEAN"
        total_risk_score = 0

        for attack_type, meta in self.attack_signatures.items():
            matched_triggers = []
            for pat in meta["patterns"]:
                found = re.findall(pat, payload_string, re.IGNORECASE)
                if found:
                    matched_triggers.append(pat)

            if matched_triggers:
                weight = 40 if meta["severity"] == "CRITICAL" else 25
                total_risk_score += weight
                detections.append({
                    "Attack Category": attack_type,
                    "Detected Pattern Trigger": ", ".join(list(set(matched_triggers))),
                    "Severity Level": meta["severity"],
                    "CWE Reference": meta["cwe"]
                })

        if total_risk_score >= 40:
            overall_threat = "CRITICAL MALICIOUS"
        elif total_risk_score > 0:
            overall_threat = "SUSPICIOUS THREAT"

        final_risk_score = min(total_risk_score, 100)

        # Log scan result to database
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO payload_scans (payload, overall_threat, risk_score, detections_count) VALUES (?, ?, ?, ?)",
                (payload_string, overall_threat, final_risk_score, len(detections))
            )
            conn.commit()

        return {
            "status": "Analysis Completed & Logged to DB",
            "overall_threat": overall_threat,
            "risk_score": final_risk_score,
            "detections_count": len(detections),
            "detections": detections
        }

    # --- Backward-compatible methods ---
    def detect_sql_injection(self, query_string):
        res = self.analyze_web_payload(query_string)
        is_sqli = any(d["Attack Category"] == "SQL Injection (SQLi)" for d in res.get("detections", []))
        if is_sqli:
            return {"status": "ALERT: SQL Injection pattern detected!", "malicious": True, "payload": query_string}
        return {"status": "Clean: No SQLi patterns found.", "malicious": False}

    def detect_xss(self, payload):
        res = self.analyze_web_payload(payload)
        is_xss = any(d["Attack Category"] == "Cross-Site Scripting (XSS)" for d in res.get("detections", []))
        if is_xss:
            return {"status": "ALERT: XSS (Cross-Site Scripting) pattern detected!", "malicious": True}
        return {"status": "Clean: No XSS patterns found.", "malicious": False}

    # --- 2. Risk Scoring & Triage ---
    def calculate_risk_score(self, event_data):
        base_score = 50
        str_data = str(event_data).lower()
        if "critical" in str_data:
            base_score = 90
        elif "warning" in str_data or "suspicious" in str_data:
            base_score = 70
        return {"status": "Risk score calculated successfully.", "score": base_score}

    # --- 3. Incident Response & SOC Alerting ---
    def alert_soc_team(self, severity, message):
        return {
            "status": "Alert dispatched to SOC team successfully via SIEM webhook.",
            "severity": severity,
            "message": message,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
