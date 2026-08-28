import sqlite3
import requests
import os
from datetime import datetime

class ThreatIntelligence:
    def __init__(self, db_path="soc_threat_intel.db", vt_api_key=None):
        self.db_path = db_path
        self.vt_api_key = vt_api_key or os.getenv("VT_API_KEY", "")
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    scan_type TEXT,
                    threat_level TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def check_threat_intel(self, log_data):
        """لاگ ڈیٹا یا انڈیکیٹر کی بنیاد پر تھریٹ انٹیلی جنس کا تجزیہ اور لائیو سکین"""
        str_data = str(log_data).lower()
        
        # Heuristic Risk Analysis
        if any(keyword in str_data for keyword in ["malicious", "attack", "c2", "payload", "exploit", "unauthorized"]):
            risk_level = "Critical"
        elif any(keyword in str_data for keyword in ["fail", "error", "suspicious", "warning"]):
            risk_level = "High"
        else:
            risk_level = "Low"

        # Log to database
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO threat_scans (target, scan_type, threat_level, details) VALUES (?, ?, ?, ?)",
                (str(log_data), "Heuristic/Log Analysis", risk_level, str(log_data))
            )
            conn.commit()

        return {
            "status": "Success",
            "threat_level": risk_level,
            "analyzed_data": log_data,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def scan_target_virustotal(self, target):
        """VirusTotal API ke zariye IP ya Domain ka real-time global threat score check karta hai"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key is not configured."}

        headers = {"x-apikey": self.vt_api_key}
        # Determine if target is IP or domain
        is_ip = target.replace(".", "").isdigit()
        url_type = "ip_addresses" if is_ip else "domains"
        url = f"https://www.virustotal.com/api/v3/{url_type}/{target}"

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                
                malicious_count = stats.get("malicious", 0)
                risk_level = "Critical" if malicious_count > 0 else "Low"

                return {
                    "target": target,
                    "last_analysis_stats": stats,
                    "threat_level": risk_level,
                    "reputation": data.get("reputation", 0)
                }
            else:
                return {"error": f"API request failed with status code {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def map_to_mitre_att_ck(self, technique_id):
        """تھریڈ تکنیک کو MITRE ATT&CK فریم ورک کے ساتھ جوڑتا ہے (Extended Database)"""
        mitre_mapping = {
            "T1078": "Valid Accounts",
            "T1059": "Command and Scripting Interpreter",
            "T1566": "Phishing",
            "T1110": "Brute Force",
            "T1003": "OS Credential Dumping",
            "T1021": "Remote Services",
            "T1204": "User Execution",
            "T1046": "Network Service Discovery",
            "T1486": "Data Encrypted for Impact (Ransomware)"
        }
        return mitre_mapping.get(technique_id.upper(), "Unknown Technique")

    def assess_threat_severity(self, indicators):
        """اشاریوں (Indicators) کی فہرست کی بنیاد پر خطرے کی شدت کا تعین کرتا ہے"""
        if not indicators:
            return "Low"
        
        count = len(indicators)
        if count > 5:
            return "Critical"
        elif count > 2:
            return "High"
        return "Medium"

    def export_threat_intelligence(self):
        """تمام محفوظ شدہ تھریٹ انٹیلی جنس ڈیٹا کو ڈیٹا بیس سے ایکسپورٹ کرتا ہے"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM threat_scans ORDER BY created_at DESC").fetchall()
            data = [dict(row) for row in rows]
            
        return {
            "status": "Threat intelligence exported successfully.", 
            "total_records": len(data), 
            "data": data
        }
