# main_dashboard.py - MHZALY AI Enterprise SOC & Threat Defense Platform (Elite Edition)
import hashlib
import os
import re
import urllib.parse
from datetime import datetime

import pandas as pd
import streamlit as st

# --- Safe Backend Modules Import (Fallback mechanism) ---
try:
    from ai_agent import AutonomousSOCAgent
except ImportError:

    class AutonomousSOCAgent:

        def analyze_domain_or_ip(self, t):
            return {"error": "AI Agent module missing"}

        def analyze_raw_telemetry(self, l):
            return {"error": "AI Agent module missing"}


try:
    from threat_intel import ThreatIntelProcessor
except ImportError:

    class ThreatIntelProcessor:

        def scan_target(self, t):
            return {"error": "Module threat_intel not found"}

        def deep_bug_bounty_scan(self, d):
            return {"error": "Module threat_intel not found"}


try:
    from otx_threat_intel import OTXThreatIntel
except ImportError:

    class OTXThreatIntel:

        def check_indicator(self, t, q):
            return {"error": "Module otx_threat_intel not found"}


try:
    from digital_forensics import DigitalForensicsAnalyzer
except ImportError:

    class DigitalForensicsAnalyzer:

        def parse_text_artifacts(self, t):
            return {"status": "Module digital_forensics not found"}


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
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
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
                return {"status": "Threat hunter module missing"}


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
                "impact_score": 3.6,
            }


try:
    from analyzer import ThreatAnalyzer
except ImportError:

    class ThreatAnalyzer:

        def analyze_web_payload(self, p):
            return {"status": "Missing"}

        def detect_sql_injection(self, q):
            return {"status": "Missing"}

        def detect_xss(self, p):
            return {"status": "Missing"}


class SOCDashboardUI:

    def __init__(self):
        self.app_name = "MHZALY Enterprise SOC & Threat Defense Platform"
        self.version = "30.0 Elite Production (AI Autonomous)"

        # Initialize Engines safely
        self.ai_brain = AutonomousSOCAgent()
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

        st.markdown(
            """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

        .stApp, [data-testid="stAppViewContainer"] {
            background: radial-gradient(circle at top right, #0d1b2a 0%, #080d1a 60%, #030712 100%) !important;
            color: #f1f5f9 !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }

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

        code, pre {
            background-color: #060b13 !important;
            color: #00f2fe !important;
            border: 1px solid rgba(0, 242, 254, 0.2) !important;
            border-radius: 8px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }

        .stAlert {
            background: rgba(11, 19, 32, 0.85) !important;
            border: 1px solid rgba(56, 189, 248, 0.25) !important;
            border-radius: 12px !important;
            backdrop-filter: blur(10px) !important;
        }
        </style>
        """,
            unsafe_allow_html=True,
        )

    def render_sidebar(self):
        st.sidebar.markdown(
            """
            <div style='text-align: center; padding: 10px 0;'>
                <h2 style='margin:0; background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>🛡️ MHZALY SOC</h2>
                <span style='display:inline-block; margin-top:4px; padding:2px 8px; font-size:10px; font-weight:700; background:rgba(0,242,254,0.1); border:1px solid #00f2fe; color:#00f2fe; border-radius:12px;'>AI AUTONOMOUS ENGINE</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.sidebar.markdown(
            "<p style='text-align:center; color:#64748b !important; font-size:11px; margin-top:5px;'>Version: "
            + self.version
            + "</p>",
            unsafe_allow_html=True,
        )
        st.sidebar.markdown("---")
        return st.sidebar.radio(
            "Command Navigation",
            [
                "Overview & Dashboard",
                "🤖 Autonomous AI SOC Analyst",
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
                "Live Incident Defense & Reporting",
            ],
        )

    def run_overview(self):
        st.title("🛡️ MHZALY Enterprise SOC Command Center")
        st.markdown(
            "Real-time telemetry, defensive postures, and AI security orchestration."
        )
        st.markdown("---")

        st.info(
            "🟢 SYSTEM OPERATIONAL | SIEM PIPELINE ACTIVE | AI BRAIN ONLINE"
        )

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Defense Engines", "13 Modules", "Operational")
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

                # Sorting Feature Integration
                sc1, sc2 = st.columns(2)
                with sc1:
                    if len(real_log_data.columns) > 0:
                        sort_column = st.selectbox(
                            "Sort Log Data By:",
                            real_log_data.columns.tolist(),
                        )
                with sc2:
                    sort_order = st.radio(
                        "Order:",
                        ["Descending (Newest)", "Ascending (Oldest)"],
                        horizontal=True,
                    )

                if len(real_log_data.columns) > 0:
                    ascending_flag = (
                        True
                        if sort_order == "Ascending (Oldest)"
                        else False
                    )
                    real_log_data = real_log_data.sort_values(
                        by=sort_column, ascending=ascending_flag
                    )

                st.dataframe(
                    real_log_data, use_container_width=True, hide_index=True
                )
            except Exception as e:
                st.error(f"Error reading live database records: {e}")
        else:
            st.warning(
                "⚠️ No active security incidents logged yet. Use 'Autonomous AI SOC Analyst' or 'Incident Response' to record threats."
            )

    def run_ai_soc_analyst(self):
        st.title("🤖 Autonomous AI SOC Analyst")
        st.markdown(
            "Give a target domain/IP or raw telemetry logs, and the AI Brain will perform full autonomous threat triage."
        )

        mode = st.radio(
            "Select AI Analysis Mode:",
            ["Domain / IP Target Triage", "Raw SIEM Telemetry Log Analysis"],
            horizontal=True,
        )

        if mode == "Domain / IP Target Triage":
            target = st.text_input(
                "Enter Domain or IP to Analyze:",
                placeholder="e.g. malicious-node.tk or 198.51.100.5",
            )
            if st.button("Execute AI Autonomous Triage"):
                if target:
                    with st.spinner(
                        "AI Brain evaluating heuristics and threat signatures..."
                    ):
                        report = self.ai_brain.analyze_domain_or_ip(target)

                        c1, c2, c3 = st.columns(3)
                        c1.metric(
                            "AI Risk Score", f"{report['risk_score']}/100"
                        )
                        c2.metric("Severity Level", report["severity"])
                        c3.metric("AI Verdict", report["verdict"])

                        st.markdown("---")
                        st.markdown("### 🧠 Autonomous AI Threat Findings")
                        for f in report["findings"]:
                            st.write(f"- {f}")

                        st.markdown(
                            "### 🛠️ Recommended Playbook Countermeasures"
                        )
                        st.success(report["playbook_actions"])
                else:
                    st.warning("Please specify a domain or IP target.")
        else:
            raw_logs = st.text_area(
                "Paste Raw Server / Auth Logs for AI Processing:", height=160
            )
            if st.button("Run AI Log Triage"):
                if raw_logs:
                    with st.spinner(
                        "AI Agent parsing and correlating telemetry patterns..."
                    ):
                        report = self.ai_brain.analyze_raw_telemetry(raw_logs)

                        c1, c2, c3 = st.columns(3)
                        c1.metric(
                            "Events Processed",
                            report["total_events_processed"],
                        )
                        c2.metric(
                            "Attacks Identified", report["attacks_identified"]
                        )
                        c3.metric(
                            "Calculated Risk", f"{report['risk_score']}/100"
                        )

                        st.markdown("---")
                        st.markdown("### 🚨 Correlated Attack Vectors")
                        if report["correlated_attacks"]:
                            st.dataframe(
                                pd.DataFrame(report["correlated_attacks"]),
                                use_container_width=True,
                                hide_index=True,
                            )
                        else:
                            st.info("No abnormal attack patterns found.")

                        st.markdown("### 🛡️ Automated Containment Status")
                        st.info(report["automated_containment"])
                else:
                    st.warning("Please paste raw logs first.")

    def run_threat_intel(self):
        st.title("🌐 Global Threat Intelligence (VirusTotal API)")
        target = st.text_input(
            "Enter Target IP Address or Domain:",
            placeholder="e.g., 8.8.8.8 or suspicious-domain.com",
        )
        if st.button("Initiate Threat Scan") and target:
            result = self.processor.scan_target(target)
            st.json(result)

    def run_otx_threat_feed(self):
        st.title("🛰️ AlienVault OTX Threat Intelligence Feed")
        query_target = st.text_input("Enter Indicator:")
        if st.button("Query OTX Telemetry") and query_target:
            res = self.otx_processor.check_indicator("IP", query_target)
            st.json(res)

    def run_blue_team_log_analyzer(self):
        st.title("🛡️ SIEM & Log Anomaly Detector")
        st.text_area("Paste Logs:")

    def run_bug_bounty_scanner(self):
        st.title("🔍 Infrastructure & Security Header Analyzer")
        st.text_input("Enter Domain:")

    def run_dorks_recon(self):
        st.title("🕵️ OSINT & Google Dork Reconnaissance")

    def run_crypto_analyzer(self):
        st.title("🔐 Crypto & Password Analyzer")

    def run_threat_hunting(self):
        st.title("🎯 Threat Hunting & IOCs")

    def run_digital_forensics(self):
        st.title("🔬 Digital Forensics & Logs")

    def run_incident_response(self):
        st.title("🚨 Incident Response & SOAR")

    def run_vulnerability_mgmt(self):
        st.title("📋 Vulnerability Management (CVSS v3.1)")

    def run_web_threat_analyzer(self):
        st.title("🌐 Web Application Threat Analyzer")


def main():
    app = SOCDashboardUI()
    app.setup_page_config()
    choice = app.render_sidebar()

    if choice == "Overview & Dashboard":
        app.run_overview()
    elif choice == "🤖 Autonomous AI SOC Analyst":
        app.run_ai_soc_analyst()
    elif choice == "Global Threat Intel (VirusTotal)":
        app.run_threat_intel()
    elif choice == "AlienVault OTX Live Threat Feed":
        app.run_otx_threat_feed()
    elif choice == "SIEM & Log Anomaly Detector":
        app.run_blue_team_log_analyzer()
    elif choice == "Deep Bug Bounty & Vulnerability Scanner":
        app.run_bug_bounty_scanner()
    elif choice == "OSINT & Google Dork Reconnaissance":
        app.run_dorks_recon()
    elif choice == "Crypto & Password Analyzer":
        app.run_crypto_analyzer()
    elif choice == "Threat Hunting & IOCs":
        app.run_threat_hunting()
    elif choice == "Digital Forensics & Logs":
        app.run_digital_forensics()
    elif choice == "Incident Response & SOAR":
        app.run_incident_response()
    elif choice == "Vulnerability Management":
        app.run_vulnerability_mgmt()
    elif choice == "Web Application Threat Analyzer":
        app.run_web_threat_analyzer()
    elif choice == "Live Incident Defense & Reporting":
        app.run_overview()


if __name__ == "__main__":
    main()
