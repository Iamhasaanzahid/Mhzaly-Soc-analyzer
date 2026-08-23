# main_dashboard.py - MHZALY Enterprise SOC & Threat Hunting Platform (Updated with OSINT Dorks)

import streamlit as st
import pandas as pd
import os
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
        self.version = "8.5 Pro Ultimate"
        
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

    def render_sidebar(self):
        st.sidebar.title("🛡️ SOC Command Center")
        st.sidebar.markdown(f"**Version:** {self.version}")
        st.sidebar.markdown("---")
        return st.sidebar.radio("Navigation Menu", [
            "Overview & Dashboard",
            "Global Threat Intel (VirusTotal)", 
            "Deep Bug Bounty & Vulnerability Scanner", 
            "OSINT & Google Dork Reconnaissance",  # <-- New OSINT Module Added Here
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
        st.success("خوش آمدید! یہ آپ کا مکمل اور رئیل ورلڈ SOC پلیٹ فارم ہے جہاں OSINT ڈارکس سمیت تمام سکیورٹی ماڈیولز اب فعال ہیں۔")
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Active Modules", "9 Core Engines", "Fully Integrated")
        col2.metric("SOC Status", "Online", "Protected")
        col3.metric("Platform Version", self.version, "Stable")
        col4.metric("Analyst", "M. Hassaan Zahid", "Lead SOC")

    # --- 1. GLOBAL THREAT INTEL ---
    def run_threat_intel(self):
        st.title("🌐 Global Threat Intelligence (VirusTotal API)")
        st.markdown("کسی بھی مشکوک آئی پی یا ڈومین کی گلوبل سکیورٹی رپورٹ چیک کریں:")
        
        target = st.text_input("Enter IP or Domain (e.g., 8.8.8.8 or example.com):")
        if st.button("Query Global Database"):
            if target:
                with st.spinner("Fetching global threat intelligence..."):
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
        st.markdown("یہ ٹول ہدف کی ویب سائٹ کی گہرائی میں جا کر اس کے سکیورٹی ہیڈرز اور مسنگ پروٹیکشنز تلاش کرتا ہے:")
        
        domain = st.text_input("Enter Target Domain (e.g., ncbae.edu.pk or example.com):")
        
        if st.button("Run Deep Bug Scan"):
            if domain:
                with st.spinner(f"Analyzing infrastructure and security headers for {domain}..."):
                    scan_res = self.processor.deep_bug_bounty_scan(domain)
                    
                    if "error" in scan_res:
                        st.error(scan_res['error'])
                    else:
                        st.success("Deep Scan Successful!")
                        st.write(f"**Target URL:** {scan_res.get('final_url')}")
                        st.write(f"**HTTP Status Code:** {scan_res.get('status_code')}")
                        
                        findings = scan_res.get('findings', [])
                        if findings:
                            st.subheader(f"⚠️ Found {len(findings)} Security Vulnerabilities / Missing Protections:")
                            df_findings = pd.DataFrame(findings)
                            st.dataframe(df_findings, use_container_width=True)
                            st.warning("💡 آپ ان خامیوں کی بنیاد پر متعلقہ کمپنی یا ایڈمن کو پروفیشنل سکیورٹی رپورٹ بھیج سکتے ہیں!")
                        else:
                            st.info("✨ زبردست! اس ہدف پر کوئی بنیادی مسنگ ہیڈر یا کمزوری نہیں پائی گئی۔")
            else:
                st.warning("Please enter a domain name.")

    # --- 3. OSINT & GOOGLE DORK RECONNAISSANCE (NEW MODULE) ---
    def run_osint_dorks(self):
        st.title("🌐 OSINT & Google Dorking Reconnaissance")
        st.markdown("Leverage advanced search operators and Google Dorking payloads for threat intelligence, asset discovery, and vulnerability assessment.")

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

        selected_category = st.selectbox("Select Reconnaissance Category", list(dork_categories.keys()))
        
        st.markdown(f"#### 🔎 Payloads for: {selected_category}")
        target_domain = st.text_input("Enter Target Domain (e.g., target.com):", "example.com")

        st.markdown("---")
        st.markdown("### Generated Dork Queries (Click to Copy & Search):")

        for name, query_template in dork_categories[selected_category]:
            final_query = query_template.replace("target.com", target_domain)
            col1, col2 = st.columns([3, 1])
            with col1:
                st.code(final_query, language="text")
            with col2:
                search_url = f"https://www.google.com/search?q={final_query}"
                st.markdown(f"[🔍 Google Search]({search_url})", unsafe_allow_html=True)

    # --- 4. THREAT HUNTING ---
    def run_threat_hunting(self):
        st.title("🎯 Proactive Threat Hunting & IOC Analysis")
        st.markdown("پاورشیل سکرپٹس یا پے لوڈ میں چھپے ہوئے خطرات (Obfuscation) کی جانچ کریں:")
        
        script_input = st.text_area("Paste PowerShell script or payload to check:")
        if st.button("Hunt Payload"):
            if script_input:
                res = self.hunter.hunt_powershell_obfuscation(script_input)
                st.write(res)
            else:
                st.warning("Please enter a payload.")

    # --- 5. DIGITAL FORENSICS ---
    def run_digital_forensics(self):
        st.title("🔎 Digital Forensics & Log Artifacts")
        st.markdown("سسٹم کے لاگز یا ٹیکسٹ سے شواہد (IPs, Emails) خود بخود نکالیں:")
        
        logs_input = st.text_area("Paste system logs or text:")
        if st.button("Extract Forensic Evidence"):
            if logs_input:
                res = self.forensics.parse_text_artifacts(logs_input)
                st.json(res)
            else:
                st.warning("Please provide log text.")

    # --- 6. INCIDENT RESPONSE & SOAR ---
    def run_incident_response(self):
        st.title("⚡ Incident Response & Automated SOAR Playbooks")
        st.markdown("سکیورٹی انسیڈنٹس پر ٹکٹ بنائیں اور پلے بکس رن کریں:")
        
        target = st.text_input("Incident Target / Host:")
        severity = st.selectbox("Severity Level", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        desc = st.text_area("Incident Description:")
        
        if st.button("Create Incident Ticket"):
            if target:
                res = self.incident_engine.create_incident_ticket(target, severity, desc)
                st.success("Ticket Generated!")
                st.json(res)
            else:
                st.warning("Please enter target.")

    # --- 7. VULNERABILITY MANAGEMENT ---
    def run_vulnerability_management(self):
        st.title("📊 Vulnerability & CVSS Assessment")
        score = st.slider("CVSS Base Score", 0.0, 10.0, 7.5)
        if st.button("Calculate Severity & Risk"):
            res = self.vuln_mgr.calculate_cvss_score(score)
            st.json(res)

    # --- 8. THREAT ANALYZER (SQLi / XSS) ---
    def run_threat_analyzer(self):
        st.title("🔬 Threat & Attack Analyzer (SQLi / XSS)")
        payload = st.text_input("Enter query string or payload to inspect:")
        if st.button("Analyze Payload"):
            if payload:
                sqli = self.analyzer.detect_sql_injection(payload)
                xss = self.analyzer.detect_xss(payload)
                st.write("**SQL Injection Check:**", sqli)
                st.write("**XSS Check:**", xss)
            else:
                st.warning("Please enter a payload.")

    # --- 9. LIVE INCIDENT DEFENSE & REPORTING ---
    def run_incident_defense(self):
        st.title("📝 Incident Defense & Evidence Ledger")
        st.markdown("مشکوک یا سکیمنگ ویب سائٹ کے خلاف ثبوت درج کریں اور آڈٹ فائل میں محفوظ کریں:")
        
        scam_target = st.text_input("Enter Scam/Malicious Website URL:")
        evidence_notes = st.text_area("Investigation Findings / Notes:")
        
        if st.button("Log Evidence & Generate Report"):
            if scam_target:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_df = pd.DataFrame({"Timestamp": [timestamp], "Target": [scam_target], "Notes": [evidence_notes], "Status": ["Logged & Reported"]})
                
                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    audit_df.to_csv(file_name, mode='a', header=False, index=False)
                else:
                    audit_df.to_csv(file_name, index=False)
                    
                st.success("Successfully logged into corporate incident ledger!")
                if os.path.exists(file_name):
                    st.subheader("Saved Incident Reports:")
                    st.dataframe(pd.read_csv(file_name), use_container_width=True)
            else:
                st.warning("Please enter a target URL.")

    def main(self):
        self.setup_page_config()
        choice = self.render_sidebar()
        
        if choice == "Overview & Dashboard": self.run_overview()
        elif choice == "Global Threat Intel (VirusTotal)": self.run_threat_intel()
        elif choice == "Deep Bug Bounty & Vulnerability Scanner": self.run_bug_bounty_scanner()
        elif choice == "OSINT & Google Dork Reconnaissance": self.run_osint_dorks() # <-- Router for new module
        elif choice == "Threat Hunting & IOCs": self.run_threat_hunting()
        elif choice == "Digital Forensics & Logs": self.run_digital_forensics()
        elif choice == "Incident Response & SOAR": self.run_incident_response()
        elif choice == "Vulnerability Management": self.run_vulnerability_management()
        elif choice == "Threat Analyzer (SQLi/XSS)": self.run_threat_analyzer()
        elif choice == "Live Incident Defense & Reporting": self.run_incident_defense()

if __name__ == "__main__":
    app = SOCDashboardUI()
    app.main()
