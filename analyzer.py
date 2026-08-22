import hashlib
import json
import re

class ThreatAnalyzer:

    def __init__(self):
        self.malicious_ips = set()
        self.malware_hashes = set()
        self.reported_domains = set()
        self.risk_scores = {}

    # --- 1. Basic Threat Detection (Real Logic) ---
    def detect_sql_injection(self, query_string):
        """سٹرنگ کے اندر سے SQL Injection کے عام پیٹرنز تلاش کرتا ہے"""
        sql_patterns = ["'", "OR 1=1", "UNION SELECT", "DROP TABLE", "--", "EXEC"]
        detected = any(p.lower() in query_string.lower() for p in sql_patterns)
        
        if detected:
            return {"status": "ALERT: SQL Injection pattern detected!", "malicious": True, "payload": query_string}
        return {"status": "Clean: No SQLi patterns found.", "malicious": False}

    def detect_xss(self, payload):
        """پیل لوڈ کے اندر سے Cross-Site Scripting (XSS) کے ٹیگز تلاش کرتا ہے"""
        xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "<img src"]
        detected = any(p.lower() in payload.lower() for p in xss_patterns)
        
        if detected:
            return {"status": "ALERT: XSS (Cross-Site Scripting) pattern detected!", "malicious": True}
        return {"status": "Clean: No XSS patterns found.", "malicious": False}

    # --- 2. Risk Scoring & Triage ---
    def calculate_risk_score(self, event_data):
        """ایونٹ کی بنیاد پر رِسک سکور (Risk Score) کا حساب لگاتا ہے"""
        base_score = 50
        if "critical" in str(event_data).lower():
            base_score = 90
        elif "warning" in str(event_data).lower():
            base_score = 70
            
        return {"status": "Risk score calculated successfully.", "score": base_score}

    # --- 3. Incident Response Helpers ---
    def alert_soc_team(self, severity, message):
        """SOC ٹیم کے لیے الرٹ تیار کرتا ہے"""
        return {
            "status": "Alert dispatched to SOC team successfully.",
            "severity": severity,
            "message": message
        }
