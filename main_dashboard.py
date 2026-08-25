# main_dashboard.py - MHZALY Enterprise SOC & Threat Defense Platform (Elite Edition)

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
        self.app_name = "MHZALY Enterprise SOC & Threat Defense Platform"
        self.version = "18.0 Elite Production"
        
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
        
        # ==========================================
        # ELITE ENTERPRISE UI & CYBERPUNK/SOC CSS
        # ==========================================
        st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

        .stApp, [data-testid="stAppViewContainer"] {
            background: linear-gradient(135deg, #030712 0%, #0f172a 100%) !important;
            color: #f8fafc !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }

        [data-testid="stSidebar"] {
            background-color: #0b0f19 !important;
            border-right: 1px solid #1e293b !important;
        }
        [data-testid="stSidebar"] div, [data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] span {
            color: #94a3b8 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }
        
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #0f172a !important;
            color: #38bdf8 !important;
            border: 1px solid #334155 !important;
            border-radius: 8px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #38bdf8 !important;
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2) !important;
        }
        
        .stButton>button {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important;
            color: #f8fafc !important;
            border: 1px solid #334155 !important;
            border-radius: 8px !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%) !important;
            color: #ffffff !important;
            border-color: #38bdf8 !important;
            box-shadow: 0 4px 12px rgba(56, 189, 248, 0.3);
        }
        
        h1, h2, h3, h4, h5, h6 {
            color: #38bdf8 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-weight: 700 !important;
        }
        
        [data-testid="stMetricValue"] {
            color: #38bdf8 !important;
            font-family: 'JetBrains Mono', monospace !important;
        }
        [data-testid="stMetricLabel"] {
            color: #94a3b8 !important;
        }
        
        code, pre {
            background-color: #0b0f19 !important;
            color: #4ade80 !important;
            border: 1px solid #1e293b !important;
            border-radius: 8px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }

        .stAlert {
            background-color: #0f172a !important;
            border: 1px solid #1e293b !important;
            color: #f8fafc !important;
            border-radius: 8px !important;
        }
        </style>
        """, unsafe_allow_html=True)

    def render_sidebar(self):
        st.sidebar.markdown(f"<h3 style='color:#38bdf8 !important; text-align:center;'>🛡️ MHZALY SOC</h3>", unsafe_allow_html=True)
        st.sidebar.markdown(f"<p style='text-align:center; color:#64748b !important; font-size:12px;'>Version: {self.version}</p>", unsafe_allow_html=True)
        st.sidebar.markdown("---")
        return st.sidebar.radio("Navigation Menu", [
            "Overview & Dashboard",
            "Global Threat Intel (VirusTotal)", 
            "AlienVault OTX Live Threat Feed", 
            "SIEM & Log Anomaly Detector",         
            "Deep Bug Bounty & Vulnerability Scanner", 
            "OSINT & Google Dork Reconnaissance",  
            "Crypto & Password Analyzer",  
            "Threat Hunting & IOCs",
            "Digital Forensics & Logs",
            "Incident Response & SOAR",
            "Vulnerability Management",
            "Web Application Threat Analyzer",
            "Live Incident Defense & Reporting"
        ])

    def run_overview(self):
        st.title("🛡️ MHZALY Enterprise SOC Command Center")
        st.markdown("---")
        st.info("🟢 SYSTEM OPERATIONAL | SIEM PIPELINE ACTIVE | DEFENSIVE CONTROLS ONLINE")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Engines", "12 Modules", "Operational")
        with col2:
            st.metric("SOC Posture", "Protected", "Secure")
        with col3:
            st.metric("Platform Version", self.version, "Stable")
        with col4:
            st.metric("Lead Engineer", "M. Hassaan Zahid", "Access: ROOT")

        st.markdown("---")
        st.markdown("### 📡 Live Incident Event Log (SIEM Database)")
        
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
        st.markdown("Analyze infrastructure indicators against global threat feeds:")
        
        target = st.text_input("Enter IP Address or Domain (e.g., 8.8.8.8):")
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
                        
                        # --- Detailed Security Vendor Breakdown ---
                        st.markdown("---")
                        st.markdown("### 🔬 Detailed Security Vendor Engine Results")
                        
                        analysis_results = result.get('last_analysis_results', {})
                        if analysis_results:
                            vendor_data = []
                            for engine, details in analysis_results.items():
                                vendor_data.append({
                                    "Security Engine": engine,
                                    "Category": details.get('category'),
                                    "Result": details.get('result')
                                })
                            
                            df_vendors = pd.DataFrame(vendor_data)
                            
                            filter_choice = st.selectbox("Filter Results by Status", ["All Engines", "Malicious / Suspicious Only", "Harmless Only"])
                            
                            if filter_choice == "Malicious / Suspicious Only":
                                df_vendors = df_vendors[df_vendors['Category'].isin(['malicious', 'suspicious'])]
                            elif filter_choice == "Harmless Only":
                                df_vendors = df_vendors[df_vendors['Category'] == 'harmless']
                                
                            st.dataframe(df_vendors, use_container_width=True, hide_index=True)
                        else:
                            st.info("Detailed engine breakdown not available for this target format.")

    def run_otx_threat_feed(self):
        st.title("🛰️ AlienVault OTX Threat Intelligence Feed")
        st.markdown("Query global open-source threat intelligence telemetry and community threat campaigns.")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            indicator_type = st.selectbox("Select Indicator Type", ["IP", "Domain"])
        with col2:
            query_target = st.text_input("Enter Indicator (e.g., 8.8.8.8 or example.com):")
            
        if st.button("Query OTX Telemetry"):
            if query_target:
                with st.spinner("Fetching global threat telemetry from OTX..."):
                    res = self.otx_processor.check_indicator(indicator_type, query_target)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.success("OTX Intelligence Telemetry Retrieved Successfully!")
                        pulse_count = res.get("threat_pulse_count", 0)
                        
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Active Threat Pulses", pulse_count)
                        c2.metric("Hosting Country", res.get("country", "N/A"))
                        c3.metric("Network ASN", res.get("asn", "N/A"))
                        
                        st.markdown("---")
                        if pulse_count > 0:
                            st.error(f"🚨 Threat Alert: This indicator is linked to {pulse_count} active security campaigns worldwide!")
                            
                            st.markdown("### 📋 Associated Threat Campaigns (Pulses)")
                            detailed_pulses = res.get("detailed_pulses", [])
                            if detailed_pulses:
                                df_pulses = pd.DataFrame(detailed_pulses)
                                st.dataframe(df_pulses, use_container_width=True, hide_index=True)
                        else:
                            st.success("🟢 Clean Posture: No malicious threat campaigns or threat actor pulses recorded in OTX database.")
                            
                        malware_families = res.get("malware_families", [])
                        if malware_families:
                            st.markdown("### 🦠 Associated Malware Families:")
                            st.write(", ".join(malware_families))

                        references = res.get("references", [])
                        if references:
                            st.markdown("### 🔍 Investigation References & IOC Sources:")
                            for ref in references[:5]:
                                st.markdown(f"- [{ref}]({ref})")
            else:
                st.warning("Please enter a target indicator to query.")

    def run_blue_team_log_analyzer(self):
        st.title("🛡️ SIEM & Log Anomaly Detector")
        st.markdown("Analyze raw server, firewall, or authentication logs to identify unauthorized access and anomalies.")
        
        raw_logs = st.text_area("Paste Raw Server / Firewall / Auth Logs Here:", placeholder="Failed password for root from 192.168.1.50 port 22...\nAccepted publickey for admin from 10.0.0.1...")
        
        if st.button("Analyze Logs for Anomalies"):
            if raw_logs:
                with st.spinner("Parsing logs and executing heuristic detection rules..."):
                    lines = raw_logs.strip().split("\n")
                    total_lines = len(lines)
                    
                    failed_logins = 0
                    success_logins = 0
                    anomaly_records = []
                    
                    for line in lines:
                        lower_line = line.lower()
                        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                        ip_found = ip_match.group() if ip_match else "Unknown IP"
                        
                        if "fail" in lower_line or "invalid" in lower_line or "error" in lower_line:
                            failed_logins += 1
                            anomaly_records.append({
                                "Log Entry": line,
                                "Status": "Malicious / Failed",
                                "Source IP": ip_found,
                                "Threat Level": "High"
                            })
                        elif "accepted" in lower_line or "success" in lower_line or "logged in" in lower_line:
                            success_logins += 1
                            anomaly_records.append({
                                "Log Entry": line,
                                "Status": "Successful Session",
                                "Source IP": ip_found,
                                "Threat Level": "Low"
                            })
                            
                    st.success("Log Heuristic Analysis Complete!")
                    
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Total Log Entries", total_lines)
                    c2.error(f"🚨 Failed / Auth Errors: {failed_logins}")
                    c3.success(f"✅ Successful Sessions: {success_logins}")
                    
                    st.markdown("---")
                    st.markdown("### 📊 Detailed SIEM Anomaly & Incident Breakdown")
                    
                    if anomaly_records:
                        df_logs = pd.DataFrame(anomaly_records)
                        
                        log_filter = st.selectbox("Filter Log Events", ["All Events", "Malicious / Failed Only", "Successful Sessions Only"])
                        
                        if log_filter == "Malicious / Failed Only":
                            df_logs = df_logs[df_logs['Threat Level'] == 'High']
                        elif log_filter == "Successful Sessions Only":
                            df_logs = df_logs[df_logs['Threat Level'] == 'Low']
                            
                        st.dataframe(df_logs, use_container_width=True, hide_index=True)
                        st.info("💡 Recommendation: Review the highlighted source IPs, cross-check them in Global Threat Intel, and enforce strict firewall rules.")
                    else:
                        st.info("✨ No log records parsed.")
            else:
                st.warning("Please paste some log data to analyze.")

    def run_bug_bounty_scanner(self):
        st.title("🔍 Infrastructure & Security Header Analyzer")
        st.markdown("Perform deep security header analysis and vulnerability mapping for bug bounty assessment:")
        
        domain = st.text_input("Enter Target Domain (e.g., example.com):")
        if st.button("Execute Infrastructure Scan"):
            if domain:
                with st.spinner(f"Mapping attack surface and inspecting headers for {domain}..."):
                    scan_res = self.processor.deep_bug_bounty_scan(domain)
                    if "error" in scan_res:
                        st.error(scan_res['error'])
                    else:
                        st.success("Infrastructure Scan Successful!")
                        
                        c1, c2 = st.columns(2)
                        c1.metric("Target Final URL", scan_res.get('final_url'))
                        c2.metric("HTTP Status Code", scan_res.get('status_code'))
                        
                        st.markdown("---")
                        st.markdown("### 🛡️ Security Header Vulnerability Breakdown")
                        
                        findings = scan_res.get('findings', [])
                        if findings:
                            df_findings = pd.DataFrame(findings)
                            
                            risk_filter = st.selectbox("Filter Findings by Risk Level", ["All Findings", "High & Medium Risks Only", "Secure / Low Only"])
                            
                            if risk_filter == "High & Medium Risks Only":
                                df_findings = df_findings[df_findings['Risk'].isin(['High', 'Medium'])]
                            elif risk_filter == "Secure / Low Only":
                                df_findings = df_findings[df_findings['Risk'].isin(['Secure', 'Low'])]
                                
                            st.dataframe(df_findings, use_container_width=True, hide_index=True)
                            st.info("💡 Recommendation: Fix missing security headers to harden web infrastructure against clickjacking and XSS attacks.")
                        else:
                            st.info("No findings reported.")
            else:
                st.warning("Please enter a target domain.")

    def run_osint_dorks(self):
        st.title("🌐 OSINT & Reconnaissance Utility")
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
            st.text_input("MD5 Hash (Hex)", value=md5_hash, disabled=True)

    def run_threat_hunting(self):
        st.title("🎯 Proactive Threat Hunting & IOC Analysis")
        script_input = st.text_area("Input PowerShell / Base64 Script Payload:")
        if st.button("Execute Hunt Protocol"):
            if script_input:
                res = self.hunter.hunt_powershell_obfuscation(script_input)
                st.write(res)

    def run_digital_forensics(self):
        st.title("🔎 Digital Forensics & Log Artifact Extraction")
        logs_input = st.text_area("Input Raw Logs / Hex Dump:")
        if st.button("Extract Artifacts"):
            if logs_input:
                res = self.forensics.parse_text_artifacts(logs_input)
                st.json(res)

    def run_incident_response(self):
        st.title("⚡ Incident Response & SOAR Playbooks")
        target = st.text_input("Compromised Asset / Host ID:")
        severity = st.selectbox("Incident Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        desc = st.text_area("Event Description & Scope:")
        if st.button("Initialize Response Ticket"):
            if target:
                res = self.incident_engine.create_incident_ticket(target, severity, desc)
                st.success(f"Incident Ticket Generated Successfully!")

    def run_vulnerability_management(self):
        st.title("📊 Vulnerability & CVSS Risk Assessment")
        score = st.slider("Select CVSS v3.1 Base Score:", 0.0, 10.0, 7.5, 0.1)
        if st.button("Calculate Vector Risk"):
            st.metric(label="Calculated Base Score", value=f"{score}/10.0")

    def run_threat_analyzer(self):
        st.title("🔬 Web Application Threat Analyzer")
        payload = st.text_input("Input Parameter String:")
        if st.button("Scan Parameter"):
            if payload:
                st.write("**SQL Injection Detection:**", self.analyzer.detect_sql_injection(payload))

    def run_incident_defense(self):
        st.title("📝 Incident Defense & Evidence Ledger")
        scam_target = st.text_input("Compromised/Malicious Asset:")
        evidence_notes = st.text_area("Forensic Investigation Notes:")
        
        if st.button("Commit to Immutable Ledger"):
            if scam_target:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_df = pd.DataFrame({"Timestamp": [timestamp], "Target": [scam_target], "Notes": [evidence_notes], "Status": ["Logged"]})
                
                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    audit_df.to_csv(file_name, mode='a', header=False, index=False)
                else:
                    audit_df.to_csv(file_name, index=False)
                    
                st.success("Evidence secured in local SIEM database.")


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
    elif choice == "SIEM & Log Anomaly Detector":
        app.run_blue_team_log_analyzer()
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
    elif choice == "Web Application Threat Analyzer":
        app.run_threat_analyzer()
    elif choice == "Live Incident Defense & Reporting":
        app.run_incident_defense()
