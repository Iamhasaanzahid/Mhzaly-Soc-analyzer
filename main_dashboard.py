import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime
from threat_intel import ThreatIntelProcessor # Backend link kiya hai yahan

class SOCDashboardUI:

    def __init__(self):
        self.app_name = "Enterprise SOC Platform"
        self.version = "1.0"
        self.ti_processor = ThreatIntelProcessor() # Initializing backend

    # --- 1. Page Configuration & Layout ---
    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")

    def render_sidebar_navigation(self):
        st.sidebar.title("🛡️ SOC Navigation")
        return st.sidebar.radio("Go to", ["Overview", "Log Management", "Threat Analysis", "Incident Response", "Vulnerability Management", "Threat Hunting", "CTI Feeds"])

    def render_top_header(self, title):
        st.title(f"📊 {title}")
        st.markdown("---")

    def render_footer(self):
        st.markdown("---")
        st.caption(f"{self.app_name} v{self.version} | Real-time Security Monitoring Powered by MHZALY")

    def apply_custom_css(self):
        st.markdown("""<style>.stMetric { background-color: #f0f2f6; padding: 10px; border-radius: 5px; }</style>""", unsafe_allow_html=True)

    # --- 2. High-Level Metrics & KPIs ---
    def show_critical_alerts_metric(self, count=12):
        st.metric(label="🚨 Critical Alerts", value=count, delta="+2 since last hour", delta_color="inverse")

    def show_active_incidents_metric(self, count=5):
        st.metric(label="🔥 Active Incidents", value=count, delta="-1 resolved")

    def show_mttd_metric(self, time_str="15m"):
        st.metric(label="⏱️ MTTD (Mean Time to Detect)", value=time_str)

    def show_mttr_metric(self, time_str="4h 30m"):
        st.metric(label="🛠️ MTTR (Mean Time to Respond)", value=time_str)

    def show_log_volume_metric(self, volume="2.4 TB"):
        st.metric(label="📈 Logs Ingested (24h)", value=volume, delta="5% increase")

    def show_endpoints_monitored_metric(self, count=1542):
        st.metric(label="💻 Endpoints Monitored", value=count)

    def show_open_vulnerabilities_metric(self, count=89):
        st.metric(label="🔓 Open Vulnerabilities", value=count, delta="-12 patched")

    def show_threat_intel_hits_metric(self, count=34):
        st.metric(label="🌐 CTI Hits", value=count)

    def render_kpi_row(self):
        col1, col2, col3, col4 = st.columns(4)
        with col1: self.show_critical_alerts_metric()
        with col2: self.show_active_incidents_metric()
        with col3: self.show_mttd_metric()
        with col4: self.show_mttr_metric()

    # --- 3. Charts & Visualizations ---
    def plot_alert_trend_line(self):
        st.subheader("Alert Trends (Last 7 Days)")
        chart_data = pd.DataFrame(np.random.randn(7, 3), columns=['High', 'Medium', 'Low'])
        st.line_chart(chart_data)

    def plot_incident_by_category_bar(self):
        st.subheader("Incidents by Category")
        chart_data = pd.DataFrame(np.random.randint(1, 20, size=(5, 1)), index=['Malware', 'Phishing', 'DDoS', 'Insider Threat', 'Brute Force'])
        st.bar_chart(chart_data)

    def plot_log_sources_pie(self):
        st.subheader("Log Sources Distribution")
        st.write("Distribution: 40% Firewall, 30% EDR, 20% Windows Event, 10% CloudTrail")

    def plot_vulnerability_severity(self):
        st.subheader("Vulnerabilities by Severity")
        st.bar_chart({"Critical": 10, "High": 35, "Medium": 80, "Low": 45})

    def plot_geographic_threat_map(self):
        st.subheader("Geo-Location of Blocked Threats")
        df = pd.DataFrame(np.random.randn(10, 2) / [10, 10] + [37.76, -122.4], columns=['lat', 'lon'])
        st.map(df)

    # --- 4. Log Management UI ---
    def render_log_search_bar(self):
        return st.text_input("🔍 Search Logs (e.g., EventID:4625 OR src_ip:10.0.0.5)")

    def render_log_time_filter(self):
        return st.selectbox("Time Range", ["Last 15 mins", "Last 1 hour", "Last 24 hours", "Last 7 days", "Custom"])

    def display_raw_logs_table(self):
        st.subheader("Raw Log Events")
        df = pd.DataFrame({"Timestamp": ["2026-08-22 10:00"] * 5, "Source": (["Firewall", "EDR", "AD"] * 2)[:5]})
st.dataframe(df)
    def display_parsed_log_details(self):
        st.json({"event.action": "logged-in", "user.name": "admin", "source.ip": "192.168.1.50"})

    # --- 5. Threat Analysis UI ---
    def display_active_alerts_table(self):
        st.subheader("Triage Alerts")
        st.table({"Alert ID": ["ALT-101", "ALT-102"], "Severity": ["High", "Medium"], "Description": ["Multiple failed logins", "Unusual PowerShell"]})

    def render_alert_action_buttons(self):
        col1, col2, col3 = st.columns(3)
        col1.button("Acknowledge Alert")
        col2.button("Escalate to Incident")
        col3.button("Mark False Positive")

    def show_mitre_attack_mapping(self):
        st.subheader("MITRE ATT&CK Mapping")
        st.write("Technique Detected: T1078 - Valid Accounts")

    # --- 6. Incident Response UI ---
    def display_incident_kanban_board(self):
        st.subheader("Incident Workflow")
        st.write("New -> Investigating -> Contained -> Remediated -> Closed")

    def render_containment_actions(self):
        st.subheader("Quick Containment Actions")
        st.button("🔒 Isolate Host")
        st.button("🛑 Block IP on Firewall")
        st.button("👤 Disable AD Account")

    def render_incident_notes_area(self):
        st.text_area("Analyst Investigation Notes")

    def render_generate_report_button(self):
        st.button("📄 Generate Incident Report (PDF)")

    # --- 7. Vulnerability Management UI ---
    def display_asset_risk_scores(self):
        st.subheader("High-Risk Assets")
        st.table({"Hostname": ["SRV-DB-01", "DC-01"], "Risk Score": [95, 88], "Owner": ["DBA Team", "IT Ops"]})

    def render_patch_deployment_form(self):
        st.selectbox("Select Patch", ["KB5012345", "KB5019876"])
        st.button("Deploy Patch")

    def display_cve_lookup_tool(self):
        cve = st.text_input("Lookup CVE ID")
        if cve: st.write(f"Showing NVD data for {cve}...")

    # --- 8. Threat Hunting UI ---
    def render_hunt_campaign_creator(self):
        st.subheader("Start New Hunt")
        st.text_input("Hypothesis Name")
        st.button("Launch Hunt")

    def display_hunt_results(self):
        st.write("Hunt Results: 3 Anomalous Scheduled Tasks Found.")

    def render_yara_rule_tester(self):
        st.text_area("Paste YARA Rule Here")
        st.button("Run YARA Scan")

    # --- 9. Threat Intelligence (CTI) UI - WITH REAL API SCANNER ---
    def display_threat_feed_status(self):
        st.subheader("Active Intel Feeds")
        st.write("✅ OTX AlienVault | ✅ MISP | ✅ AbuseIPDB | ✅ VirusTotal (Live)")

    def render_ioc_lookup_tool(self):
        st.markdown("### 🌐 Live Website & IP Scanner")
        st.write("کسی بھی مشکوک ویب سائٹ کا آئی پی ایڈریس لکھیں (مثال کے طور پر 8.8.8.8) اور اصلی رپورٹ دیکھیں۔")
        
        target_ip = st.text_input("🔍 Enter IP Address to Scan:")
        
        if st.button("Start Security Scan"):
            if target_ip:
                with st.spinner(f"Scanning {target_ip} globally..."):
                    result = self.ti_processor.check_ip_virustotal(target_ip)
                    
                    if "error" in result:
                        st.error(f"Scan Failed: {result['error']}")
                    else:
                        st.success("Scan Completed!")
                        st.write(f"**IP Owner / ISP:** {result['owner']}")
                        
                        c1, c2, c3 = st.columns(3)
                        c1.error(f"🚨 Malicious (Hacker): {result['malicious']}")
                        c2.warning(f"⚠️ Suspicious (Shak): {result['suspicious']}")
                        c3.success(f"✅ Safe (Harmless): {result['harmless']}")
                        
                        if result['malicious'] > 0:
                            st.error("DANGER: یہ آئی پی خطرناک ہے! ویب سائٹ کے مالک کو الرٹ کریں۔")
                        else:
                            st.info("System Clean: یہ آئی پی بالکل محفوظ لگ رہا ہے۔")
            else:
                st.warning("Please enter an IP address first.")

    # --- 10. Dashboard Controller (Main App Logic) ---
    def run_overview_tab(self):
        self.render_top_header("SOC Overview")
        self.render_kpi_row()
        col1, col2 = st.columns(2)
        with col1: self.plot_alert_trend_line()
        with col2: self.plot_geographic_threat_map()

    def run_log_management_tab(self):
        self.render_top_header("Log Management & Search")
        self.render_log_search_bar()
        self.display_raw_logs_table()

    def run_threat_analysis_tab(self):
        self.render_top_header("Threat Analysis & Triage")
        self.display_active_alerts_table()
        self.render_alert_action_buttons()

    def run_incident_response_tab(self):
        self.render_top_header("Incident Response")
        self.render_containment_actions()
        self.render_incident_notes_area()

    def run_vulnerability_tab(self):
        self.render_top_header("Vulnerability Management")
        self.plot_vulnerability_severity()
        self.display_asset_risk_scores()

    def run_threat_hunting_tab(self):
        self.render_top_header("Proactive Threat Hunting")
        self.render_hunt_campaign_creator()
        self.display_hunt_results()

    def run_cti_tab(self):
        self.render_top_header("Cyber Threat Intelligence")
        self.display_threat_feed_status()
        self.render_ioc_lookup_tool()

    def main_loop(self):
        self.setup_page_config()
        self.apply_custom_css()
        selected_page = self.render_sidebar_navigation()

        if selected_page == "Overview":
            self.run_overview_tab()
        elif selected_page == "Log Management":
            self.run_log_management_tab()
        elif selected_page == "Threat Analysis":
            self.run_threat_analysis_tab()
        elif selected_page == "Incident Response":
            self.run_incident_response_tab()
        elif selected_page == "Vulnerability Management":
            self.run_vulnerability_tab()
        elif selected_page == "Threat Hunting":
            self.run_threat_hunting_tab()
        elif selected_page == "CTI Feeds":
            self.run_cti_tab()
        
        self.render_footer()

if __name__ == "__main__":
    dashboard = SOCDashboardUI()
    dashboard.main_loop()
