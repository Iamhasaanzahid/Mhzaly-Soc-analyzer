# main_dashboard.py - MHZALY Enterprise SOC & Threat Hunting Platform (Updated with Custom UI/UX)

import streamlit as st
import pandas as pd
import os
import hashlib
import re
from datetime import datetime

# --- Safe Backend Modules Import (Fallback mechanism) ---
try:
    from threat_intel import ThreatIntelProcessor
except ImportError:
    class ThreatIntelProcessor:
        def scan_target(self, t): return {"error": "Module threat_intel not found"}
        def deep_bug_bounty_scan(self, d): return {"error": "Module threat_intel not found"}

try:
    from digital_forensics import DigitalForensicsAnalyzer
except ImportError:
    class DigitalForensicsAnalyzer:
        def parse_text_artifacts(self, t): return {"status": "Module digital_forensics not found"}

try:
    from incident_response import IncidentResponder
except ImportError:
    class IncidentResponder:
        def create_incident_ticket(self, t, s, d): return {"status": "Module incident_response not found"}

try:
    from soar_automation import SOARAutomation
except ImportError:
    class SOARAutomation:
        pass

try:
    from threat_hunting import ThreatHunter
except ImportError:
    try:
        from threat_hunter import ThreatHunter
    except ImportError:
        class ThreatHunter:
            def hunt_powershell_obfuscation(self, s): return {"status": "Threat hunter module missing"}

try:
    from vulnerability_management import VulnerabilityManager
except ImportError:
    class VulnerabilityManager:
        def calculate_cvss_score(self, s): return {"status": "Module missing"}

try:
    from analyzer import ThreatAnalyzer
except ImportError:
    class ThreatAnalyzer:
        def detect_sql_injection(self, q): return {"status": "Missing"}
        def detect_xss(self, p): return {"status": "Missing"}


class SOCDashboardUI:

    def __init__(self):
        self.app_name = "MHZALY Enterprise SOC & Threat Hunting Platform"
        self.version = "9.0 Pro Ultimate"
        
        # Initialize Engines safely
        self.processor = ThreatIntelProcessor()
        self.forensics = DigitalForensicsAnalyzer()
        self.incident_engine = IncidentResponder()
        self.soar = SOARAutomation()
        self.hunter = ThreatHunter()
        self.vuln_mgr = VulnerabilityManager()
        self.analyzer = ThreatAnalyzer()

    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")
        
        # ==========================================
        # CUSTOM CSS INJECTION FOR CYBER/DARK THEME
        # ==========================================
        st.markdown("""
        <style>
        /* Main background color */
        .stApp {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: 'Courier New', Courier, monospace;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background-color: #161b22;
            border-right: 2px solid #00ff00;
        }
        
        /* Button styling - Hacker Green */
        .stButton>button {
            background-color: transparent;
            color: #00ff00;
            border: 1px solid #00ff00;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #00ff00;
            color: #0d1117;
            box-shadow: 0 0 10px #00ff00;
        }
        
        /* Input fields styling */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #0d1117;
            color: #00ff00;
            border: 1px solid #30363d;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #00ff00;
            box-shadow: 0 0 5px #00ff00;
        }
        
        /* Metrics styling */
        [data-testid="stMetricValue"] {
            color: #00ff00;
            font-weight: bold;
        }
        [data-testid="stMetricLabel"] {
            color: #8b949e;
        }
        
        /* Headers & Text */
        h1, h2, h3 {
            color: #58a6ff !important;
        }
        
        /* Success/Warning/Error boxes */
        .stAlert {
            background-color: #161b22;
            border-left: 5px solid;
        }
        </style>
        """, unsafe_allow_html=True)

    def render_sidebar(self):
        st.sidebar.markdown(f"<h2 style='color:#00ff00; text-align:center;'>🛡️ SOC Command Center</h2>", unsafe_allow_html=True)
        st.sidebar.markdown(f"<p style='text-align:center; color:#8b949e;'>Version: {self.version}</p>", unsafe_allow_html=True)
        st.sidebar.markdown("---")
        return st.sidebar.radio("Navigation Menu", [
            "Overview & Dashboard",
            "Global Threat Intel (VirusTotal)", 
            "Deep Bug Bounty & Vulnerability Scanner", 
            "OSINT & Google Dork Reconnaissance",  
            "Crypto & Password Analyzer",  
            "Threat Hunting & IOCs",
            "Digital Forensics & Logs",
            "Incident Response & SOAR",
            "Vulnerability Management",
            "Threat Analyzer (SQLi/XSS)",
            "Live Incident Defense & Reporting"
        ])

    def run_overview(self):
        st.title("🛡️ MHZALY Enterprise Cyber Defense Platform")
        st.markdown("---")
        st.info("🟢 SYSTEM ONLINE | SECURITY PROTOCOLS ACTIVE | MODULES LOADED")
        
        # Upgraded layout with columns and cards style
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Modules", "10 Core Engines", "Fully Integrated")
        with col2:
            st.metric("SOC Status", "Online", "Protected")
        with col3:
            st.metric("Platform Version", self.version, "Stable")
        with col4:
            st.metric("Lead Analyst", "M. Hassaan Zahid", "Access: ROOT")

        st.markdown("---")
        st.markdown("### 📡 System Event Log")
        # Dummy data for visual effect on dashboard
        log_data = pd.DataFrame(
            [
                ["2026-08-24 03:15:00", "Firewall", "Blocked IP 192.168.1.55 (Malicious Signature)"],
                ["2026-08-24 03:20:12", "SIEM", "Multiple failed login attempts on Admin Portal"],
                ["2026-08-24 03:25:40", "Threat Intel", "Updated global IOC feeds successfully"]
            ],
            columns=["Timestamp", "Source", "Event Details"]
        )
        st.dataframe(log_data, use_container_width=True, hide_index=True)

    # --- 1. GLOBAL THREAT INTEL ---
    def run_threat_intel(self):
        st.title("🌐 Global Threat Intelligence (VirusTotal API)")
        st.markdown("Scan IP/Domain against global threat feeds:")
        
        target = st.text_input("Enter IP or Domain (e.g., 8.8.8.8):")
        if st.button("Initiate Deep Scan"):
            if target:
                with st.spinner("Establishing secure connection to threat databases..."):
                    result = self.processor.scan_target(target)
                    if "error" in result:
                        st.error(result['error'])
                    else:
                        st.success("Analysis Complete!")
                        stats = result.get('last_analysis_stats', {})
                        
                        c1, c2, c3 = st.columns(3)
                        c1.error(f"🚨 Malicious: {stats.get('malicious', 0)}")
                        c2.warning(f"⚠️ Suspicious: {stats.get('suspicious', 0)}")
                        c3.success(f"✅ Harmless: {stats.get('harmless', 0)}")
                        
                        vendors = result.get('last_analysis_results', {})
                        malicious_vendors = {k: v['result'] for k, v in vendors.items() if v.get('category') == 'malicious'}
                        if malicious_vendors:
                            st.subheader("🚨 Flagged by Security Vendors:")
                            st.table(pd.DataFrame(list(malicious_vendors.items()), columns=["Vendor", "Finding"]))

    # --- 2. DEEP BUG BOUNTY SCANNER ---
    def run_bug_bounty_scanner(self):
        st.title("🔍 Deep Bug Bounty & Security Header Analyzer")
        st.markdown("Analyze infrastructure and missing protections:")
        
        domain = st.text_input("Enter Target Domain:")
        
        if st.button("Execute Infrastructure Scan"):
            if domain:
                with st.spinner(f"Mapping attack surface for {domain}..."):
                    scan_res = self.processor.deep_bug_bounty_scan(domain)
                    
                    if "error" in scan_res:
                        st.error(scan_res['error'])
                    else:
                        st.success("Deep Scan Successful!")
                        st.write(f"**Target URL:** {scan_res.get('final_url')}")
                        st.write(f"**HTTP Status Code:** {scan_res.get('status_code')}")
                        
                        findings = scan_res.get('findings', [])
                        if findings:
                            st.subheader(f"⚠️ Found {len(findings)} Vulnerabilities:")
                            df_findings = pd.DataFrame(findings)
                            st.dataframe(df_findings, use_container_width=True)
                        else:
                            st.info("✨ Target infrastructure appears secure. No missing headers found.")
            else:
                st.warning("Input required.")

    # --- 3. OSINT & GOOGLE DORK RECONNAISSANCE ---
    def run_osint_dorks(self):
        st.title("🌐 OSINT & Google Dorking Reconnaissance")
        st.markdown("Generate advanced Google Dorking payloads.")

        dork_categories = {
            "01. Sensitive Files & Credentials": [
                ("Database Dumps & Backups", 'site:target.com filetype:sql OR filetype:bak OR filetype:dump'),
                ("Private Keys & Configs", 'site:target.com ext:pem OR ext:key OR ext:env OR inurl:config'),
                ("Log Files with Passwords", 'site:target.com intext:"password" filetype:log')
            ],
            "02. Cloud Infrastructure & DevOps": [
                ("Public S3 Buckets", 'site:s3.amazonaws.com "target.com"'),
                ("CI/CD Pipelines (Jenkins/GitLab)", 'site:target.com inurl:jenkins OR inurl:gitlab-ci'),
                ("Container Dashboards", 'site:target.com inurl:kubernetes OR inurl:grafana')
            ],
            "03. Modern SaaS & API Endpoints": [
                ("Swagger / API Docs", 'site:target.com inurl:swagger OR inurl:api-docs'),
                ("Admin Portals & SSO", 'site:target.com inurl:admin OR inurl:auth/login'),
                ("GraphQL Endpoints", 'site:target.com inurl:graphql')
            ],
            "04. AI & Machine Learning Infrastructure": [
                ("Exposed OpenAI/API Keys in Notebooks", 'site:target.com filetype:ipynb "OPENAI_API_KEY"'),
                ("Vector Databases & MLFlow", 'site:target.com inurl:mlflow OR inurl:chroma')
            ]
        }

        selected_category = st.selectbox("Select Target Vector", list(dork_categories.keys()))
        target_domain = st.text_input("Enter Target Domain:", "example.com")

        st.markdown("---")
        st.markdown("### Generated Dork Queries:")

        for name, query_template in dork_categories[selected_category]:
            final_query = query_template.replace("target.com", target_domain)
            col1, col2 = st.columns([4, 1])
            with col1:
                st.code(final_query, language="text")
            with col2:
                search_url = f"https://www.google.com/search?q={final_query}"
                st.markdown(f"<a href='{search_url}' target='_blank'><button style='width:100%; padding:10px; background-color:#0d1117; color:#00ff00; border:1px solid #00ff00; border-radius:5px;'>Execute Search</button></a>", unsafe_allow_html=True)

    # --- 4. CRYPTO & PASSWORD ANALYZER ---
    def run_crypto_analyzer(self):
        st.title("🔐 Cryptographic Hash & Password Strength Analyzer")

        target_input = st.text_input("Enter Data String:", type="password")

        if target_input:
            st.markdown("#### 🔍 Generated Hashes")
            
            md5_hash = hashlib.md5(target_input.encode()).hexdigest()
            sha256_hash = hashlib.sha256(target_input.encode()).hexdigest()

            col1, col2 = st.columns(2)
            with col1:
                st.text_input("MD5 Hash", value=md5_hash, disabled=True)
            with col2:
                st.text_input("SHA-256 Hash", value=sha256_hash, disabled=True)

            st.markdown("---")
            st.markdown("#### 🛡️ Complexity Audit")

            length_score = len(target_input) >= 8
            upper_score = bool(re.search(r'[A-Z]', target_input))
            lower_score = bool(re.search(r'[a-z]', target_input))
            digit_score = bool(re.search(r'\d', target_input))
            special_score = bool(re.search(r'[@$!%*?&]', target_input))

            score = sum([length_score, upper_score, lower_score, digit_score, special_score])

            if score == 5:
                st.success("🟢 STATUS: SECURE (High Entropy)")
            elif score >= 3:
                st.warning("🟡 STATUS: MODERATE (Vulnerable to targeted attacks)")
            else:
                st.error("🔴 STATUS: WEAK (Critical Risk)")

    # --- 5. THREAT HUNTING ---
    def run_threat_hunting(self):
        st.title("🎯 Proactive Threat Hunting & IOC Analysis")
        
        script_input = st.text_area("Input PowerShell / Base64 Payload:")
        if st.button("Execute Hunt Protocol"):
            if script_input:
                with st.spinner("Deobfuscating and analyzing payload..."):
                    res = self.hunter.hunt_powershell_obfuscation(script_input)
                    st.write(res)
            else:
                st.warning("Payload missing.")

    # --- 6. DIGITAL FORENSICS ---
    def run_digital_forensics(self):
        st.title("🔎 Digital Forensics & Log Artifacts")
        
        logs_input = st.text_area("Input Raw Logs / Hex Dump:")
        if st.button("Extract Artifacts"):
            if logs_input:
                with st.spinner("Parsing syntax and extracting IOCs..."):
                    res = self.forensics.parse_text_artifacts(logs_input)
                    st.json(res)
            else:
                st.warning("Log data required.")

    # --- 7. INCIDENT RESPONSE & SOAR ---
    def run_incident_response(self):
        st.title("⚡ Automated SOAR Playbooks")
        
        target = st.text_input("Target / Host ID:")
        severity = st.selectbox("Threat Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        desc = st.text_area("Event Description:")
        
        if st.button("Initialize Response Ticket"):
            if target:
                res = self.incident_engine.create_incident_ticket(target, severity, desc)
                st.success(f"Ticket [#{hashlib.md5(target.encode()).hexdigest()[:6]}] Generated Successfully!")
                st.json(res)
            else:
                st.warning("Target ID required.")

    # --- 8. VULNERABILITY MANAGEMENT ---
    def run_vulnerability_management(self):
        st.title("📊 Vulnerability & CVSS Assessment")
        score = st.slider("CVSS Base Score Input", 0.0, 10.0, 7.5)
        if st.button("Calculate Vector Risk"):
            res = self.vuln_mgr.calculate_cvss_score(score)
            st.json(res)

    # --- 9. THREAT ANALYZER (SQLi / XSS) ---
    def run_threat_analyzer(self):
        st.title("🔬 Web Application Threat Analyzer")
        payload = st.text_input("Input Parameter String:")
        if st.button("Scan Parameter"):
            if payload:
                sqli = self.analyzer.detect_sql_injection(payload)
                xss = self.analyzer.detect_xss(payload)
                st.write("**SQL Injection Vector:**", sqli)
                st.write("**XSS Vector:**", xss)
            else:
                st.warning("Parameter string required.")

    # --- 10. LIVE INCIDENT DEFENSE & REPORTING ---
    def run_incident_defense(self):
        st.title("📝 Incident Defense & Evidence Ledger")
        
        scam_target = st.text_input("Compromised/Malicious Asset:")
        evidence_notes = st.text_area("Forensic Notes:")
        
        if st.button("Commit to Immutable Ledger"):
            if scam_target:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_df = pd.DataFrame({"Timestamp": [timestamp], "Target": [scam_target], "Notes": [evidence_notes], "Status": ["Logged"]})
                
                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    audit_df.to_csv(file_name, mode='a', header=False, index=False)
                else:
                    audit_df.to_csv(file_name, index=False)
                    
                st.success("Evidence secured in local database.")
                if os.path.exists(file_name):
                    st.subheader("Recent Entries:")
                    st.dataframe(pd.read_csv(file_name), use_container_width=True)
            else:
                st.warning("Asset ID required.")

    def main(self):
        self.setup_page_config()
        choice = self.render_sidebar()
        
        if choice == "Overview & Dashboard": self.run_overview()
        elif choice == "Global Threat Intel (VirusTotal)": self.run_threat_intel()
        elif choice == "Deep Bug Bounty & Vulnerability Scanner": self.run_bug_bounty_scanner()
        elif choice == "OSINT & Google Dork Reconnaissance": self.run_osint_dorks()
        elif choice == "Crypto & Password Analyzer": self.run_crypto_analyzer() 
        elif choice == "Threat Hunting & IOCs": self.run_threat_hunting()
        elif choice == "Digital Forensics & Logs": self.run_digital_forensics()
        elif choice == "Incident Response & SOAR": self.run_incident_response()
        elif choice == "Vulnerability Management": self.run_vulnerability_management()
        elif choice == "Threat Analyzer (SQLi/XSS)": self.run_threat_analyzer()
        elif choice == "Live Incident Defense & Reporting": self.run_incident_defense()

if __name__ == "__main__":
    app = SOCDashboardUI()
    app.main()
