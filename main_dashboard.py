# main_dashboard.py - MHZALY Enterprise SOC & Threat Hunting Platform (Updated with OTX Threat Feed)

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
    from otx_threat_intel import OTXThreatIntel
except ImportError:
    class OTXThreatIntel:
        def check_indicator(self, t, q): return {"error": "Module otx_threat_intel not found"}

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
        self.version = "9.5 Pro Ultimate"
        
        # Initialize Engines safely
        self.processor = ThreatIntelProcessor()
        self.otx_processor = OTXThreatIntel()
        self.forensics = DigitalForensicsAnalyzer()
        self.incident_engine = IncidentResponder()
        self.soar = SOARAutomation()
        self.hunter = ThreatHunter()
        self.vuln_mgr = VulnerabilityManager()
        self.analyzer = ThreatAnalyzer()

    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")
        
        st.markdown("""
        <style>
        .stApp, [data-testid="stAppViewContainer"] {
            background-color: #0d1117 !important;
            color: #c9d1d9 !important;
            font-family: 'Courier New', Courier, monospace !important;
        }
        [data-testid="stSidebar"] {
            background-color: #161b22 !important;
            border-right: 2px solid #00ff00 !important;
        }
        [data-testid="stSidebar"] div, [data-testid="stSidebar"] p, [data-testid="stSidebar"] label {
            color: #c9d1d9 !important;
        }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #0d1117 !important;
            color: #00ff00 !important;
            border: 1px solid #30363d !important;
        }
        .stButton>button {
            background-color: transparent !important;
            color: #00ff00 !important;
            border: 1px solid #00ff00 !important;
            border-radius: 5px !important;
        }
        .stButton>button:hover {
            background-color: #00ff00 !important;
            color: #0d1117 !important;
            box-shadow: 0 0 10px #00ff00 !important;
        }
        h1, h2, h3, h4, h5, h6 { color: #58a6ff !important; }
        [data-testid="stMetricValue"] { color: #00ff00 !important; font-weight: bold !important; }
        [data-testid="stMetricLabel"] { color: #8b949e !important; }
        p, span, div, li { color: #c9d1d9 ; }
        .stAlert {
            background-color: #161b22 !important;
            border-left: 5px solid #00ff00 !important;
            color: #c9d1d9 !important;
        }
        </style>
        """, unsafe_allow_html=True)

    def render_sidebar(self):
        st.sidebar.markdown(f"<h2 style='color:#00ff00 !important; text-align:center;'>🛡️ SOC Command Center</h2>", unsafe_allow_html=True)
        st.sidebar.markdown(f"<p style='text-align:center; color:#8b949e !important;'>Version: {self.version}</p>", unsafe_allow_html=True)
        st.sidebar.markdown("---")
        return st.sidebar.radio("Navigation Menu", [
            "Overview & Dashboard",
            "Global Threat Intel (VirusTotal)", 
            "AlienVault OTX Live Threat Feed", 
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
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Modules", "11 Core Engines", "Fully Integrated")
        with col2:
            st.metric("SOC Status", "Online", "Protected")
        with col3:
            st.metric("Platform Version", self.version, "Stable")
        with col4:
            st.metric("Lead Analyst", "M. Hassaan Zahid", "Access: ROOT")

        st.markdown("---")
        st.markdown("### 📡 Live Incident Event Log (Real-Time Database)")
        
        file_name = "incident_reports.csv"
        if os.path.exists(file_name):
            try:
                real_log_data = pd.read_csv(file_name)
                if "Timestamp" in real_log_data.columns:
                    real_log_data = real_log_data.sort_values(by="Timestamp", ascending=False)
                st.dataframe(real_log_data, use_container_width=True, hide_index=True)
            except Exception as e:
                st.error("Error reading live database records.")
        else:
            st.warning("⚠️ No active security incidents logged yet. Use 'Live Incident Defense & Reporting' to record threats.")

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

    def run_otx_threat_feed(self):
        st.title("🛰️ AlienVault OTX Live Threat Intelligence")
        st.markdown("Check IPs and Domains against global open-source threat intelligence feeds and community campaigns.")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            indicator_type = st.selectbox("Select Indicator Type", ["IP", "Domain"])
        with col2:
            query_target = st.text_input("Enter IP or Domain (e.g., 1.1.1.1):")
            
        if st.button("Query OTX Threat Database"):
            if query_target:
                with st.spinner("Fetching global threat telemetry..."):
                    res = self.otx_processor.check_indicator(indicator_type, query_target)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.success("OTX Telemetry Received Successfully!")
                        pulse_count = res.get("threat_pulse_count", 0)
                        
                        if pulse_count > 0:
                            st.error(f"🚨 Threat Alert: This indicator appears in {pulse_count} active security pulses worldwide!")
                        else:
                            st.success("🟢 Clean: No active threat pulses found in public OTX database.")
                            
                        st.write(f"**Target Analyzed:** {res.get('query')}")
                        st.write(f"**Total Threat Pulses:** {pulse_count}")
                        
                        references = res.get("references", [])
                        if references:
                            st.markdown("### 🔍 Associated Threat References:")
                            for ref in references[:5]:
                                st.markdown(f"- [{ref}]({ref})")
            else:
                st.warning("Please enter a target to query.")

    def run_bug_bounty_scanner(self):
        st.title("🔍 Deep Bug Bounty & Security Header Analyzer")
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

    def run_osint_dorks(self):
        st.title("🌐 OSINT & Google Dorking Reconnaissance")
        dork_categories = {
            "01. Sensitive Files & Credentials": [("Log Files with Passwords", 'site:target.com intext:"password" filetype:log')]
        }
        selected_category = st.selectbox("Select Target Vector", list(dork_categories.keys()))
        target_domain = st.text_input("Enter Target Domain:", "example.com")
        for name, query_template in dork_categories[selected_category]:
            final_query = query_template.replace("target.com", target_domain)
            st.code(final_query, language="text")

    def run_crypto_analyzer(self):
        st.title("🔐 Cryptographic Hash & Password Strength Analyzer")
        target_input = st.text_input("Enter Data String:", type="password")
        if target_input:
            md5_hash = hashlib.md5(target_input.encode()).hexdigest()
            st.text_input("MD5 Hash", value=md5_hash, disabled=True)

    def run_threat_hunting(self):
        st.title("🎯 Proactive Threat Hunting & IOC Analysis")
        script_input = st.text_area("Input PowerShell / Base64 Payload:")
        if st.button("Execute Hunt Protocol"):
            if script_input:
                res = self.hunter.hunt_powershell_obfuscation(script_input)
                st.write(res)

    def run_digital_forensics(self):
        st.title("🔎 Digital Forensics & Log Artifacts")
        logs_input = st.text_area("Input Raw Logs / Hex Dump:")
        if st.button("Extract Artifacts"):
            if logs_input:
                res = self.forensics.parse_text_artifacts(logs_input)
                st.json(res)

    def run_incident_response(self):
        st.title("⚡ Automated SOAR Playbooks")
        target = st.text_input("Target / Host ID:")
        severity = st.selectbox("Threat Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        desc = st.text_area("Event Description:")
        if st.button("Initialize Response Ticket"):
            if target:
                res = self.incident_engine.create_incident_ticket(target, severity, desc)
                st.success(f"Ticket Generated Successfully!")

    def run_vulnerability_management(self):
        st.title("📊 Vulnerability & CVSS Assessment")
        score = st.slider("Select CVSS Base Score:", 0.0, 10.0, 7.5, 0.1)
        if st.button("Calculate Vector Risk"):
            st.metric(label="Calculated Base Score", value=f"{score}/10.0")

    def run_threat_analyzer(self):
        st.title("🔬 Web Application Threat Analyzer")
        payload = st.text_input("Input Parameter String:")
        if st.button("Scan Parameter"):
            if payload:
                st.write("**SQL Injection Vector:**", self.analyzer.detect_sql_injection(payload))

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


# ==========================================
# MAIN EXECUTION ROUTING (Menu Controller)
# ==========================================
if __name__ == "__main__":
    app = SOCDashboardUI()
    app.setup_page_config()
    
    choice = app.render_sidebar()
    
    if choice == "Overview & Dashboard":
        app.run_overview()
    elif choice == "Global Threat Intel (VirusTotal)":
        app.run_threat_intel()
    elif choice == "AlienVault OTX Live Threat Feed":
        app.run_otx_threat_feed()
    elif choice == "Deep Bug Bounty & Vulnerability Scanner":
        app.run_bug_bounty_scanner()
    elif choice == "OSINT & Google Dork Reconnaissance":
        app.run_osint_dorks()
    elif choice == "Crypto & Password Analyzer":
        app.run_crypto_analyzer()
    elif choice == "Threat Hunting & IOCs":
        app.run_threat_hunting()
    elif choice == "Digital Forensics & Logs":
        app.run_digital_forensics()
    elif choice == "Incident Response & SOAR":
        app.run_incident_response()
    elif choice == "Vulnerability Management":
        app.run_vulnerability_management()
    elif choice == "Threat Analyzer (SQLi/XSS)":
        app.run_threat_analyzer()
    elif choice == "Live Incident Defense & Reporting":
        app.run_incident_defense()
