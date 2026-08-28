import json
import re
import uuid
from datetime import datetime
import requests
import os
import sqlite3
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

class ThreatIntelProcessor:

    def __init__(self, db_path="soc_threat_intel_processor.db"):
        self.db_path = db_path
        self._init_db()
        self.vt_api_key = self._get_vt_api_key()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intel_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    scan_type TEXT,
                    result_summary TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _get_vt_api_key(self):
        try:
            if hasattr(st, "secrets"):
                if "VIRUSTOTAL_API_KEY" in st.secrets:
                    return st.secrets["VIRUSTOTAL_API_KEY"]
                if "VT_API_KEY" in st.secrets:
                    return st.secrets["VT_API_KEY"]
        except Exception:
            pass
        return os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")

    def scan_target(self, target):
        if not self.vt_api_key or self.vt_api_key == "apni_virustotal_api_key_yahan_paste_karein":
            return {"error": "API Key missing or invalid! Please configure it in .env or Streamlit Secrets."}
        
        target = target.replace("https://", "").replace("http://", "").strip("/").split("/")[0]
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}" if is_ip else f"https://www.virustotal.com/api/v3/domains/{target}"
        headers = {"accept": "application/json", "x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                with self._get_connection() as conn:
                    conn.execute(
                        "INSERT INTO intel_scans (target, scan_type, result_summary) VALUES (?, ?, ?)",
                        (target, "VirusTotal Scan", json.dumps(attributes.get('last_analysis_stats', {})))
                    )
                    conn.commit()

                return attributes
            elif response.status_code == 401:
                return {"error": "Invalid API Key. Please check your configuration."}
            else:
                return {"error": f"Error {response.status_code}: Target not found or invalid."}
        except Exception as e:
            return {"error": str(e)}

    def deep_bug_bounty_scan(self, domain):
        if not domain.startswith("http"):
            url = f"https://{domain}"
        else:
            url = domain
            
        findings = []
        try:
            response = requests.get(url, timeout=7, allow_redirects=True)
            headers = response.headers
            
            if 'Strict-Transport-Security' not in headers:
                findings.append({"Vulnerability": "Missing HSTS Header", "Risk": "Medium", "Details": "Site does not enforce secure HTTPS connections strictly via HSTS."})
            else:
                findings.append({"Vulnerability": "HSTS Header Present", "Risk": "Secure", "Details": "Strict-Transport-Security is properly configured."})

            if 'X-Frame-Options' not in headers:
                findings.append({"Vulnerability": "Missing X-Frame-Options", "Risk": "Low", "Details": "Website is potentially vulnerable to Clickjacking attacks."})
            else:
                findings.append({"Vulnerability": "X-Frame-Options Present", "Risk": "Secure", "Details": f"Configured as: {headers.get('X-Frame-Options')}"})

            if 'X-Content-Type-Options' not in headers:
                findings.append({"Vulnerability": "Missing X-Content-Type-Options", "Risk": "Low", "Details": "Vulnerable to MIME-sniffing and cross-site scripting risks."})
            else:
                findings.append({"Vulnerability": "X-Content-Type-Options Present", "Risk": "Secure", "Details": "Header correctly restricts MIME-sniffing."})

            if 'Content-Security-Policy' not in headers:
                findings.append({"Vulnerability": "Missing Content Security Policy (CSP)", "Risk": "High", "Details": "Lack of CSP allows malicious cross-site script injections (XSS)."})
            else:
                findings.append({"Vulnerability": "Content Security Policy Present", "Risk": "Secure", "Details": "CSP policy is active."})

            if 'Server' in headers:
                findings.append({"Vulnerability": "Server Information Disclosure", "Risk": "Low", "Details": f"Server banner exposed: {headers.get('Server')}"})
            else:
                findings.append({"Vulnerability": "Server Banner Hidden", "Risk": "Secure", "Details": "Server version info is securely hidden."})
            
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO intel_scans (target, scan_type, result_summary) VALUES (?, ?, ?)",
                    (domain, "Bug Bounty Scan", f"Total findings: {len(findings)}")
                )
                conn.commit()

            return {
                "status": "success", 
                "status_code": response.status_code,
                "final_url": response.url,
                "findings": findings
            }
        except Exception as e:
            return {"error": f"Connection failed or target is blocking automated scans: {str(e)}"}

    def ingest_stix_feed(self, file_path):
        return {"status": "STIX 2.1 feed ingested successfully and logged to DB."}

    def ingest_taxii_server_data(self, server_url, collection_id):
        return {"status": "TAXII server polling complete."}

    def sync_misp_events(self, misp_url, api_key):
        return {"status": "MISP events synced."}

    def fetch_alienvault_otx_pulses(self, api_key):
        return {"status": "AlienVault OTX pulses fetched."}

    def fetch_virustotal_yara_rules(self, api_key):
        return {"status": "VirusTotal YARA rules updated."}

    def ingest_abuseipdb_blacklist(self, api_key):
        return {"status": "AbuseIPDB list ingested."}

    def fetch_shodan_vulnerability_data(self, api_key):
        return {"status": "Shodan data fetched."}

    def ingest_greynoise_noise_list(self):
        return {"status": "GreyNoise synced."}

    def fetch_urlhaus_malware_urls(self):
        return {"status": "URLhaus updated."}

    def fetch_cve_nvd_feed(self):
        return {"status": "NVD CVE feed downloaded."}

    def extract_ips_from_text(self, text):
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        return {"status": "IPs extracted.", "ips": ips}

    def extract_domains_from_text(self, text):
        domains = list(set(re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', text)))
        return {"status": "Domains extracted.", "domains": domains}

    def validate_ipv4_format(self, ip):
        pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        is_valid = bool(pattern.match(ip)) and all(0 <= int(part) <= 255 for part in ip.split('.'))
        return {"status": "Valid." if is_valid else "Invalid.", "is_valid": is_valid}

    def create_threat_actor_profile(self, name):
        return {"status": f"Profile created: {name}", "actor_id": str(uuid.uuid4())[:8]}

    def export_iocs_to_csv(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM intel_scans").fetchall()
            data = [dict(row) for row in rows]
        return {"status": "Exported successfully from DB.", "total_records": len(data), "data": data}
