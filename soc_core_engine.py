import sqlite3
import json
import re
import requests
from config_loader import ConfigLoader

class EnterpriseSOCPlatform:
    def __init__(self):
        self.config = ConfigLoader()
        self.db_path = "enterprise_soc.db"
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT,
                    severity TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def log_enterprise_event(self, module, severity, details):
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO security_events (module, severity, details) VALUES (?, ?, ?)",
                (module, severity, json.dumps(details) if isinstance(details, dict) else str(details))
            )
            conn.commit()

    def run_threat_scan(self, target):
        vt_key = self.config.get_setting("threat_intelligence", "virustotal_api_key")
        if not vt_key or vt_key.startswith("YOUR"):
            return {"status": "Error", "message": "Valid VirusTotal API key required in config.json"}
        
        is_ip = target.replace(".", "").isdigit()
        url_type = "ip_addresses" if is_ip else "domains"
        url = f"https://www.virustotal.com/api/v3/{url_type}/{target}"
        headers = {"x-apikey": vt_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                self.log_enterprise_event("ThreatIntel", "HIGH" if stats.get("malicious", 0) > 0 else "LOW", stats)
                return {"target": target, "stats": stats}
            return {"error": f"API failed with status {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def analyze_payload(self, payload_string):
        patterns = [r"(\%27)|(\')|(\-\-)|(\%23)|(#)", r"\b(select|union|insert|update|delete|drop)\b", r"<script.*?>"]
        malicious = any(re.search(p, payload_string, re.IGNORECASE) for p in patterns)
        severity = "CRITICAL" if malicious else "LOW"
        
        self.log_enterprise_event("PayloadAnalyzer", severity, {"payload": payload_string})
        return {"malicious": malicious, "severity": severity}
