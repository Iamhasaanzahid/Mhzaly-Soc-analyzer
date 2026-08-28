# threat_hunting.py - Proactive Threat Hunting & Deobfuscation Engine

import uuid
import re
import base64
from datetime import datetime
import sqlite3
import json

class ThreatHunter:

    def __init__(self, db_path="soc_threat_hunting.db"):
        self.db_path = db_path
        self._init_db()
        
        # Comprehensive evasion & obfuscation detection patterns
        self.suspicious_patterns = {
            "Base64 Decoding Pattern": r"FromBase64String|-enc|-encodedcommand",
            "Dynamic Expression Execution": r"iex|invoke-expression|Invoke-Command",
            "Hidden Window / Process Evasion": r"-w\s+hidden|-windowstyle\s+hidden|-nop|-noprofile",
            "Remote Payload Staging": r"invoke-webrequest|downloadstring|downloadfile|Net\.WebClient|curl|wget",
            "Execution Policy / AMSI Bypass": r"bypass|-exec\s+bypass|rundll32|regsvr32"
        }

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_campaigns (
                    hunt_id TEXT PRIMARY KEY,
                    campaign_name TEXT,
                    description TEXT,
                    status TEXT,
                    created_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_hypotheses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hunt_id TEXT,
                    hypothesis TEXT,
                    timestamp TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    severity TEXT,
                    risk_score INTEGER,
                    findings TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    # --- 1. Hunt Planning & Hypothesis Generation ---
    def create_hunt_campaign(self, campaign_name, description):
        """ایک نئی تھریٹ ہنٹنگ کمپین اور یونیک آئی ڈی بناتا ہے اور ڈیٹا بیس میں سیو کرتا ہے"""
        hunt_id = f"HUNT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO hunt_campaigns (hunt_id, campaign_name, description, status, created_at) VALUES (?, ?, ?, ?, ?)",
                (hunt_id, campaign_name, description, "Active Hunt", timestamp)
            )
            conn.commit()

        campaign = {
            "hunt_id": hunt_id,
            "campaign_name": campaign_name,
            "description": description,
            "status": "Active Hunt",
            "created_at": timestamp
        }
        
        return {"status": f"Hunt campaign '{campaign_name}' created and saved successfully.", "hunt_id": hunt_id, "campaign": campaign}

    def define_hypothesis(self, hunt_id, hypothesis_statement):
        """کمپین کے لیے ہائپوتھیسس (فرضہ) سیٹ کرتا ہے اور ڈیٹا بیس میں درج کرتا ہے"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO hunt_hypotheses (hunt_id, hypothesis, timestamp) VALUES (?, ?, ?)",
                (hunt_id, hypothesis_statement, timestamp)
            )
            conn.commit()

        hypothesis = {
            "hunt_id": hunt_id,
            "hypothesis": hypothesis_statement,
            "timestamp": timestamp
        }
        return {"status": "Hypothesis defined and persisted securely in database.", "hypothesis": hypothesis}

    # --- 2. Advanced Endpoint & PowerShell Threat Hunting (Deep Deobfuscation) ---
    def hunt_powershell_obfuscation(self, script_content):
        """پاورشیل سکرپٹس کے اندر سے اوبفسکیٹڈ کمانڈز تلاش، ڈی کوڈ اور تجزیہ کرتا ہے"""
        if not script_content:
            return {"error": "Empty payload string"}

        findings = []
        decoded_strings = []
        risk_score = 0

        # 1. Regex check for suspicious patterns & techniques
        for name, pattern in self.suspicious_patterns.items():
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            if matches:
                risk_score += 25
                findings.append({
                    "Technique": name,
                    "Detected Trigger": ", ".join(list(set(matches))),
                    "Threat Weight": "High" if "Dynamic" in name or "Base64" in name else "Medium"
                })

        # 2. Extract and decode Base64 chunks automatically
        b64_matches = re.findall(r'[A-Za-z0-9+/=]{16,}', script_content)
        for chunk in b64_matches:
            try:
                decoded = base64.b64decode(chunk).decode('utf-8', errors='ignore')
                if not decoded.isprintable() or len(decoded.strip()) < 3:
                    decoded = base64.b64decode(chunk).decode('utf-16le', errors='ignore')
                
                clean_text = "".join([c for c in decoded if c.isprintable()]).strip()
                if len(clean_text) > 3:
                    decoded_strings.append(clean_text)
            except Exception:
                pass

        # 3. Extract IOCs from both raw payload and decoded text
        combined_text = script_content + " " + " ".join(decoded_strings)
        extracted_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', combined_text)
        extracted_urls = re.findall(r'https?://[^\s"\'>]+', combined_text)
        extracted_paths = re.findall(r'[A-Za-z]:\\[A-Za-z0-9_\-\\]+', combined_text)

        severity = "CLEAN"
        if risk_score >= 50 or decoded_strings:
            severity = "HIGH THREAT" if risk_score >= 50 else "SUSPICIOUS"

        final_risk = min(risk_score, 100)

        # Log scan into database
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO hunt_scans (severity, risk_score, findings) VALUES (?, ?, ?)",
                (severity, final_risk, json.dumps(findings))
            )
            conn.commit()

        return {
            "status": "Analysis Complete & Logged to DB",
            "severity": severity,
            "risk_score": final_risk,
            "findings": findings,
            "decoded_payloads": decoded_strings,
            "iocs": {
                "IP Addresses": list(set(extracted_ips)),
                "URLs": list(set(extracted_urls)),
                "File Paths": list(set(extracted_paths))
            }
        }

    # --- 3. IOC Sweeping & Threat Intel Integration ---
    def sweep_ip_addresses(self, target_ips, known_malicious_ips):
        """محیط (Environment) میں مشکوک آئی پیز کو سویپ/تلاش کرتا ہے"""
        matched_ips = [ip for ip in target_ips if ip in known_malicious_ips]
        return {
            "status": "IP sweep completed.",
            "matched_malicious_ips": matched_ips,
            "total_scanned": len(target_ips)
        }

    def query_mitre_attack_matrix(self, technique_id):
        """MITRE ATT&CK فریم ورک کے ساتھ فائنڈنگز کو جوڑتا ہے"""
        mitre_mapping = {
            "T1059.001": "Command and Scripting Interpreter: PowerShell",
            "T1078": "Valid Accounts",
            "T1021": "Remote Services",
            "T1027": "Obfuscated Files or Information",
            "T1105": "Ingress Tool Transfer"
        }
        technique_name = mitre_mapping.get(technique_id.upper(), "Unknown Technique")
        return {
            "status": "Mapped hunt findings to MITRE ATT&CK.",
            "technique_id": technique_id,
            "technique_name": technique_name
        }

    # --- 4. Hunt Conclusion & Reporting ---
    def generate_hunt_report(self, hunt_id):
        """تھریٹ ہنٹ کا تفصیلی رپورٹ ڈیٹا ڈیٹا بیس سے تیار کرتا ہے"""
        with self._get_connection() as conn:
            camp_row = conn.execute("SELECT * FROM hunt_campaigns WHERE hunt_id = ?", (hunt_id,)).fetchone()
            hyp_count = conn.execute("SELECT COUNT(*) FROM hunt_hypotheses WHERE hunt_id = ?", (hunt_id,)).fetchone()[0]
            
            if camp_row:
                return {
                    "status": "Comprehensive threat hunt report generated from database.",
                    "campaign_details": dict(camp_row),
                    "total_hypotheses": hyp_count
                }
        return {"status": "Hunt campaign not found in database."}
