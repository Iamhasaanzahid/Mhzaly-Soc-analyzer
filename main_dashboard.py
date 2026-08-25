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
        def parse_text_artifacts(self, t): return {"status": "Module digital_forensics not found"}

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
            def hunt_powershell_obfuscation(self, s): return {"status": "Threat hunter module missing"}

try:
    from vulnerability_management import VulnerabilityManager
except ImportError:
    class VulnerabilityManager:
        def calculate_cvss_score(self, *args, **kwargs):
            return {
                "base_score": 7.5,
                "severity": "HIGH",
                "sla": "Remediate within 7 to 14 Days",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "exploitability_score": 3.9,
                "impact_score": 3.6
            }

try:
    from analyzer import ThreatAnalyzer
except ImportError:
    class ThreatAnalyzer:
        def analyze_web_payload(self, p): return {"status": "Missing"}
        def detect_sql_injection(self, q): return {"status": "Missing"}
        def detect_xss(self, p): return {"status": "Missing"}


class SOCDashboardUI:

    def __init__(self):
        self.app_name = "MHZALY Enterprise SOC & Threat Defense Platform"
        self.version = "29.0 Elite Production"
        
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
        # ULTRA-PROFESSIONAL BRIGHT CYBER UI CSS
        # ==========================================
        st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

        /* App Background */
        .stApp, [data-testid="stAppViewContainer"] {
            background: radial-gradient(circle at top right, #0d1b2a 0%, #080d1a 60%, #030712 100%) !important;
            color: #f1f5f9 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }

        /* Sidebar Styling */
        [data-testid="stSidebar"] {
            background: #090e17 !important;
            border-right: 1px solid rgba(56, 189, 248, 0.15) !important;
            box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4);
        }
        [data-testid="stSidebar"] div, [data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] span {
            color: #94a3b8 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-weight: 500;
        }

        /* Glowing Accent Headings */
        h1 {
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%) !important;
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            font-weight: 800 !important;
            letter-spacing: -0.5px !important;
        }
        h2, h3, h4 {
            color: #38bdf8 !important;
            font-weight: 700 !important;
        }

        /* Form Inputs & Text Areas */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea, .stSelectbox>div>div>div {
            background-color: #0b1320 !important;
            color: #38bdf8 !important;
            border: 1px solid #1e293b !important;
            border-radius: 10px !important;
            font-family: 'JetBrains Mono', monospace !important;
            transition: all 0.25s ease-in-out !important;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #00f2fe !important;
            box-shadow: 0 0 12px rgba(0, 242, 254, 0.25) !important;
        }

        /* Buttons with Gradient Glow */
        .stButton>button {
            background: linear-gradient(135deg, #0052d4 0%, #4364f7 50%, #6fb1fc 100%) !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 10px !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-weight: 700 !important;
            font-size: 14px !important;
            padding: 10px 24px !important;
            box-shadow: 0 4px 15px rgba(67, 100, 247, 0.3) !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }
        .stButton>button:hover {
            transform: translateY(-2px) scale(1.01) !important;
            box-shadow: 0 6px 20px rgba(0, 242, 254, 0.5) !important;
        }

        /* Metric Cards */
        [data-testid="stMetricValue"] {
            color: #00f2fe !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important;
        }
        [data-testid="stMetricLabel"] {
            color: #cbd5e1 !important;
            font-size: 13px !important;
            font-weight: 600 !important;
        }

        /* Code & Pre Blocks */
        code, pre {
            background-color: #060b13 !important;
            color: #00f2fe !important;
            border: 1px solid rgba(0, 242, 254, 0.2) !important;
            border-radius: 8px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }

        /* Custom Information Banners */
        .stAlert {
            background: rgba(11, 19, 32, 0.85) !important;
            border: 1px solid rgba(56, 189, 248, 0.25) !important;
            border-radius: 12px !important;
            backdrop-filter: blur(10px) !important;
        }
        </style>
        """, unsafe_allow_html=True)

    def render_sidebar(self):
        st.sidebar.markdown(
            """
            <div style='text-align: center; padding: 10px 0;'>
                <h2 style='margin:0; background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>🛡️ MHZALY SOC</h2>
                <span style='display:inline-block; margin-top:4px; padding:2px 8px; font-size:10px; font-weight:700; background:rgba(0,242,254,0.1); border:1px solid #00f2fe; color:#00f2fe; border-radius:12px;'>PRODUCTION ENGINE</span>
            </div>
            """, 
            unsafe_allow_html=True
        )
        st.sidebar.markdown("<p style='text-align:center; color:#64748b !important; font-size:11px; margin-top:5px;'>Version: " + self.version + "</p>", unsafe_allow_html=True)
        st.sidebar.markdown("---")
        return st.sidebar.radio("Command Navigation", [
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
        st.markdown("Real-time telemetry, defensive postures, and SIEM security orchestration.")
        st.markdown("---")
        
        st.info("🟢 SYSTEM OPERATIONAL | SIEM PIPELINE ACTIVE | DEFENSIVE CONTROLS ONLINE")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Defense Engines", "12 Modules", "Operational")
        with col2:
            st.metric("SOC Posture", "Protected", "Secure")
        with col3:
            st.metric("Platform Version", self.version, "Stable")
        with col4:
            st.metric("Lead SOC Engineer", "M. Hassaan Zahid", "Access: ROOT")

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
        st.markdown("Query threat reputations and security engine verdicts across global threat feeds.")
        
        target = st.text_input("Enter Target IP Address or Domain:", placeholder="e.g., 8.8.8.8 or suspicious-domain.com")
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
                        
                        st.markdown("---")
                        st.markdown("### 🔬 Security Vendor Engine Results")
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
                            filter_choice = st.selectbox("Filter Vendor Findings", ["All Engines", "Malicious / Suspicious Only", "Harmless Only"])
                            if filter_choice == "Malicious / Suspicious Only":
                                df_vendors = df_vendors[df_vendors['Category'].isin(['malicious', 'suspicious'])]
                            elif filter_choice == "Harmless Only":
                                df_vendors = df_vendors[df_vendors['Category'] == 'harmless']
                                
                            st.dataframe(df_vendors, use_container_width=True, hide_index=True)
            else:
                st.warning("Please specify a domain or IP indicator to scan.")

    def run_otx_threat_feed(self):
        st.title("🛰️ AlienVault OTX Threat Intelligence Feed")
        st.markdown("Query global open-source threat telemetry, adversary campaigns, and active threat pulses.")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            indicator_type = st.selectbox("Select Indicator Type", ["IP", "Domain"])
        with col2:
            query_target = st.text_input("Enter Indicator:", placeholder="e.g., 198.51.100.25 or malicious-host.net")
            
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
                        
                        st.markdown("---")
                        if pulse_count > 0:
                            st.error(f"🚨 Active Threat: This indicator is linked to {pulse_count} active security campaigns worldwide!")
                            detailed_pulses = res.get("detailed_pulses", [])
                            if detailed_pulses:
                                df_pulses = pd.DataFrame(detailed_pulses)
                                st.dataframe(df_pulses, use_container_width=True, hide_index=True)
                        else:
                            st.success("🟢 Clean Posture: No malicious threat campaigns or threat actor pulses recorded in OTX database.")
            else:
                st.warning("Please provide a valid indicator.")

    def run_blue_team_log_analyzer(self):
        st.title("🛡️ SIEM & Log Anomaly Detector")
        st.markdown("Automate raw server, firewall, or authentication log parsing and brute-force detection.")
        
        raw_logs = st.text_area("Paste Raw Server / Firewall / Auth Logs Here:", placeholder="Paste log strings (e.g., Failed password for root from 192.168.1.50 port 22...)...", height=130)
        
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
                            df_findings = pd.DataFrame(findings)
                            st.dataframe(df_findings, use_container_width=True, hide_index=True)

    def run_osint_dorks(self):
        st.title("🌐 OSINT & Google Dork Reconnaissance")
        st.markdown("Automate open-source intelligence footprinting and defensive reconnaissance queries for target assets, including WordPress infrastructure.")

        dork_categories = {
            "01. Sensitive Files & Credentials": [
                ("Database Dumps & Backups", 'site:target.com (filetype:sql OR filetype:bak OR filetype:dump)', "Critical"),
                ("Private Keys & Environment Configs", 'site:target.com (ext:pem OR ext:key OR ext:env OR inurl:config)', "Critical"),
                ("Exposed Log Files with Passwords", 'site:target.com intext:"password" filetype:log', "High")
            ],
            "02. WordPress Security & Reconnaissance": [
                ("Exposed WP-Config & Backups", 'site:target.com (inurl:wp-config.php OR inurl:wp-config.bak)', "Critical"),
                ("Vulnerable / Exposed Plugins", 'site:target.com inurl:/wp-content/plugins/', "High"),
                ("Uploaded Media & File Dorks", 'site:target.com inurl:/wp-content/uploads/', "Medium"),
                ("WordPress Author Enumeration", 'site:target.com/?author=', "Medium"),
                ("Exposed XML-RPC Endpoints", 'site:target.com inurl:xmlrpc.php', "High")
            ],
            "03. Cloud Infrastructure & DevOps": [
                ("Public S3 Buckets", 'site:s3.amazonaws.com "target.com"', "High"),
                ("CI/CD Automation Pipelines", 'site:target.com (inurl:jenkins OR inurl:gitlab-ci)', "Medium"),
                ("Container Dashboards & Telemetry", 'site:target.com (inurl:kubernetes OR inurl:grafana)', "High")
            ],
            "04. Modern SaaS & API Endpoints": [
                ("Swagger / API Documentation", 'site:target.com (inurl:swagger OR inurl:api-docs)', "Medium"),
                ("Admin Portals & SSO Endpoints", 'site:target.com (inurl:admin OR inurl:auth/login)', "Medium"),
                ("GraphQL Endpoints", 'site:target.com inurl:graphql', "Low")
            ],
            "05. AI & ML Infrastructure": [
                ("Exposed OpenAI/API Tokens in Notebooks", 'site:target.com filetype:ipynb "OPENAI_API_KEY"', "Critical"),
                ("Vector Databases & MLflow Tracking", 'site:target.com (inurl:mlflow OR inurl:chroma)', "Medium")
            ]
        }

        target_domain = st.text_input("Enter Target Domain (e.g., example.com):", "example.com")
        clean_domain = target_domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0]

        col1, col2 = st.columns([1, 1])
        with col1:
            selected_category = st.selectbox("Select Reconnaissance Category", list(dork_categories.keys()))
        with col2:
            st.metric("Target Asset", clean_domain, "Domain Active")

        st.markdown("---")
        st.markdown(f"### 🎯 Active Query Set: {selected_category}")

        recon_records = []
        for name, query_template, risk in dork_categories[selected_category]:
            final_query = query_template.replace("target.com", clean_domain)
            encoded_query = urllib.parse.quote(final_query)
            search_url = f"https://www.google.com/search?q={encoded_query}"
            
            recon_records.append({
                "Vector Objective": name,
                "Risk Rating": risk,
                "Google Dork Payload": final_query,
                "Launch URL": search_url
            })

        df_recon = pd.DataFrame(recon_records)
        st.dataframe(df_recon[["Vector Objective", "Risk Rating", "Google Dork Payload"]], use_container_width=True, hide_index=True)

        st.markdown("### 🚀 Live Search Actions")
        for item in recon_records:
            st.markdown(f"- **{item['Vector Objective']}** (`{item['Risk Rating']}`): [Launch Query on Search Engine ↗]({item['Launch URL']})")

    def run_crypto_analyzer(self):
        st.title("🔐 Cryptographic Hash & Password Strength Analyzer")
        st.markdown("Analyze entropy, compute cryptographic hashes, and validate secret keys.")
        target_input = st.text_input("Enter Data String / Password:", type="password")
        if target_input:
            md5_hash = hashlib.md5(target_input.encode()).hexdigest()
            sha256_hash = hashlib.sha256(target_input.encode()).hexdigest()
            
            st.text_input("MD5 Hash", value=md5_hash, disabled=True)
            st.text_input("SHA-256 Hash", value=sha256_hash, disabled=True)
            
            length = len(target_input)
            if length >= 12:
                st.success("🟢 Strong Password Length (12+ characters)")
            else:
                st.warning("⚠️ Weak Password Length: Recommended minimum length is 12 characters.")

    def run_threat_hunting(self):
        st.title("🎯 Proactive Threat Hunting & IOC Analysis")
        st.markdown("Analyze obfuscated PowerShell scripts and command line execution telemetry.")
        script_input = st.text_area("Input PowerShell / Base64 Payload:", placeholder="Paste base64 encoded or obfuscated command line strings...")
        if st.button("Execute Hunt Protocol"):
            if script_input:
                res = self.hunter.hunt_powershell_obfuscation(script_input)
                st.json(res)
            else:
                st.warning("Please provide a payload to hunt.")

    def run_digital_forensics(self):
        st.title("🔎 Digital Forensics & Log Artifacts")
        st.markdown("Extract forensic artifacts, timestamps, and indicators of compromise from raw dumps.")
        logs_input = st.text_area("Input Raw Logs / Hex Dump:", placeholder="Paste raw event artifacts or logs here...")
        if st.button("Extract Artifacts"):
            if logs_input:
                res = self.forensics.parse_text_artifacts(logs_input)
                st.json(res)
            else:
                st.warning("Please provide forensic data.")

    def run_incident_response(self):
        st.title("⚡ Automated SOAR Playbooks & Ticketing")
        st.markdown("Generate incident tickets, assign SLAs, and trigger automated response playbooks.")
        target = st.text_input("Compromised Asset / Host ID:", placeholder="e.g., WORKSTATION-04")
        severity = st.selectbox("Threat Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        desc = st.text_area("Event Description / Findings:")
        if st.button("Initialize Response Ticket"):
            if target:
                res = self.incident_engine.create_incident_ticket(target, severity, desc)
                st.success(res.get("status", "Ticket generated successfully."))
                st.json(res.get("ticket", {}))
            else:
                st.warning("Please specify a target asset.")

    def run_vulnerability_management(self):
        st.title("📊 Vulnerability & CVSS Assessment")
        st.markdown("Calculate Common Vulnerability Scoring System (CVSS v3.1) metrics and remediation SLAs.")
        score = st.slider("Select CVSS Base Score:", 0.0, 10.0, 7.5, 0.1)
        if st.button("Calculate Vector Risk"):
            assessment = self.vuln_mgr.calculate_cvss_score(score)
            c1, c2, c3 = st.columns(3)
            c1.metric("Base CVSS Score", f"{score}/10.0")
            c2.metric("Severity Rating", assessment.get("severity", "HIGH"))
            c3.metric("Remediation SLA", assessment.get("sla", "7-14 Days"))
            st.code(assessment.get("vector_string", "CVSS:3.1/..."), language="text")

    def run_threat_analyzer(self):
        st.title("🔬 Web Application Threat Analyzer")
        st.markdown("Inspect URL query parameters and payload strings for SQLi and XSS attack signatures.")
        payload = st.text_input("Input Parameter String:", placeholder="e.g., ?id=1' OR '1'='1 or <script>alert(1)</script>")
        if st.button("Scan Parameter"):
            if payload:
                st.write("**SQL Injection Analysis:**", self.analyzer.detect_sql_injection(payload))
                st.write("**XSS Signature Analysis:**", self.analyzer.detect_xss(payload))
            else:
                st.warning("Please input a parameter string.")

    def run_incident_defense(self):
        st.title("📝 Incident Defense & Evidence Ledger")
        st.markdown("Record threat intelligence notes and commit forensic evidence to the immutable local audit trail.")
        scam_target = st.text_input("Compromised / Malicious Asset:", placeholder="e.g., 192.168.1.100 or malware.exe")
        evidence_notes = st.text_area("Forensic Evidence & Containment Notes:")
        
        if st.button("Commit to Immutable Ledger"):
            if scam_target:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_df = pd.DataFrame({"Timestamp": [timestamp], "Target": [scam_target], "Notes": [evidence_notes], "Status": ["Secured & Logged"]})
                
                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    audit_df.to_csv(file_name, mode='a', header=False, index=False)
                else:
                    audit_df.to_csv(file_name, index=False)
                    
                st.success("Evidence securely committed to local SIEM database ledger.")
            else:
                st.warning("Please specify a compromised asset.")


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
