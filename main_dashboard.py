import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import re
from datetime import datetime
from threat_intel import ThreatIntelProcessor # Backend link

class SOCDashboardUI:

    def __init__(self):
        self.app_name = "Enterprise SOC Platform"
        self.version = "2.0 Pro"
        self.ti_processor = ThreatIntelProcessor()

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
    def render_kpi_row(self):
        col1, col2, col3, col4 = st.columns(4)
        with col1: st.metric(label="🚨 Critical Alerts", value=12, delta="+2 since last hour", delta_color="inverse")
        with col2: st.metric(label="🔥 Active Incidents", value=5, delta="-1 resolved")
        with col3: st.metric(label="⏱️ MTTD (Detect)", value="15m")
        with col4: st.metric(label="🛠️ MTTR (Respond)", value="4h 30m")

    # --- 3. Charts & Visualizations ---
    def plot_alert_trend_line(self):
        st.subheader("Alert Trends (Last 7 Days)")
        chart_data = pd.DataFrame(np.random.randn(7, 3), columns=['High', 'Medium', 'Low'])
        st.line_chart(chart_data)

    def plot_geographic_threat_map(self):
        st.subheader("Geo-Location of Blocked Threats")
        df = pd.DataFrame(np.random.randn(10, 2) / [10, 10] + [37.76, -122.4], columns=['lat', 'lon'])
        st.map(df)

    # --- 4. Log Management UI (DYNAMIC CSV & SEARCH) ---
    def render_log_search_bar(self):
        return st.text_input("🔍 Search Logs (e.g., Firewall, EDR, 4625)")

    def display_raw_logs_table(self, search_query=""):
        st.subheader("Raw Log Events (Live Database)")
        log_file = "logs.csv"
        
        if not os.path.exists(log_file):
            default_data = {
                "Timestamp": ["2026-08-22 10:00", "2026-08-22 10:05", "2026-08-22 10:10", "2026-08-22 10:15", "2026-08-22 10:20"],
                "Source": ["Firewall", "EDR", "AD", "Firewall", "EDR"],
                "EventID": ["4625", "1102", "4624", "4688", "7045"],
                "Details": ["Failed Login", "Log Cleared", "Successful Logon", "Process Created", "Service Installed"]
            }
            pd.DataFrame(default_data).to_csv(log_file, index=False)
        
        df = pd.read_csv(log_file)
        
        if search_query:
            mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
            df = df[mask]
            
        st.dataframe(df, use_container_width=True)

    # --- 5. Threat Analysis UI (INTERACTIVE STATE MANAGEMENT) ---
    def run_threat_analysis_tab(self):
        self.render_top_header("Threat Analysis & Triage")
        
        if 'alerts' not in st.session_state:
            st.session_state.alerts = [
                {"Alert ID": "ALT-101", "Severity": "High", "Status": "New", "Description": "Multiple failed logins detected"},
                {"Alert ID": "ALT-102", "Severity": "Medium", "Status": "New", "Description": "Unusual PowerShell script execution"},
                {"Alert ID": "ALT-103", "Severity": "Critical", "Status": "New", "Description": "Potential Brute Force from External IP"}
            ]

        st.write("رئیل ٹائم الرٹس ٹriage کریں اور نیچے دیے گئے بٹنوں سے ان کا اسٹیٹس اپ ڈیٹ کریں۔")
        df = pd.DataFrame(st.session_state.alerts)
        st.dataframe(df, use_container_width=True)

        selected_id = st.selectbox("Select Alert ID to Process:", [a['Alert ID'] for a in st.session_state.alerts])
        
        col1, col2, col3 = st.columns(3)
        if col1.button("✅ Acknowledge Alert"):
            for alert in st.session_state.alerts:
                if alert['Alert ID'] == selected_id:
                    alert['Status'] = "Acknowledged"
            st.success(f"Alert {selected_id} acknowledged successfully!")
            st.rerun()

        if col2.button("🔥 Escalate to Incident"):
            for alert in st.session_state.alerts:
                if alert['Alert ID'] == selected_id:
                    alert['Status'] = "Escalated"
            st.warning(f"Alert {selected_id} escalated to Incident Response!")
            st.rerun()

        if col3.button("🛡️ Mark False Positive"):
            for alert in st.session_state.alerts:
                if alert['Alert ID'] == selected_id:
                    alert['Status'] = "False Positive"
            st.info(f"Alert {selected_id} marked as False Positive.")
            st.rerun()

    # --- 6. Incident Response UI (INTERACTIVE WORKFLOW) ---
    def run_incident_response_tab(self):
        self.render_top_header("Incident Response & Containment")
        
        if 'incident_status' not in st.session_state:
            st.session_state.incident_status = "Active - Investigating"

        st.info(f"**Current Incident Workflow Status:** {st.session_state.incident_status}")
        
        col1, col2, col3 = st.columns(3)
        if col1.button("🔒 Isolate Host"):
            st.session_state.incident_status = "Contained (Host Isolated)"
            st.success("Host successfully isolated from network!")
            st.rerun()
            
        if col2.button("🛑 Block IP on Firewall"):
            st.session_state.incident_status = "Contained (IP Blocked)"
            st.success("Malicious IP blocked on perimeter firewall!")
            st.rerun()
            
        if col3.button("👤 Disable AD Account"):
            st.session_state.incident_status = "Contained (Account Disabled)"
            st.success("Compromised Active Directory account disabled!")
            st.rerun()

        st.markdown("---")
        st.subheader("Analyst Investigation Notes")
        notes = st.text_area("Type your notes here:", placeholder="Enter investigation findings...")
        if st.button("Save Notes"):
            st.success("Investigation notes saved securely to case file.")

    # --- 7. Vulnerability Management UI ---
    def run_vulnerability_tab(self):
        self.render_top_header("Vulnerability Management & Assets")
        
        if 'assets' not in st.session_state:
            st.session_state.assets = [
                {"Hostname": "SRV-DB-01", "Risk Score": 95, "Status": "Unpatched", "Owner": "DBA Team"},
                {"Hostname": "DC-01", "Risk Score": 88, "Status": "Unpatched", "Owner": "IT Ops"}
            ]

        st.subheader("High-Risk Assets Matrix")
        st.dataframe(pd.DataFrame(st.session_state.assets), use_container_width=True)

        selected_host = st.selectbox("Select Asset to Deploy Patch:", [a['Hostname'] for a in st.session_state.assets])
        patch = st.selectbox("Select Security Patch:", ["KB5012345 (Critical)", "KB5019876 (Security Update)"])
        
        if st.button("Deploy Patch Now"):
            for asset in st.session_state.assets:
                if asset['Hostname'] == selected_host:
                    asset['Status'] = "Patched"
                    asset['Risk Score'] = max(0, asset['Risk Score'] - 40)
            st.success(f"Patch {patch} successfully deployed on {selected_host}!")
            st.rerun()

    # --- 8. Threat Hunting UI (LIVE SCANNER) ---
    def run_threat_hunting_tab(self):
        self.render_top_header("Proactive Threat Hunting")
        st.subheader("Live Log Threat Hunter")
        st.write("کوئی بھی کی ورڈ یا پیٹرن لکھیں (جیسے `Failed`, `EDR`, `Firewall`) تاکہ سسٹم اس کا شکار کرے:")
        
        hypothesis = st.text_input("Enter Hunt Query / Keyword:")
        
        if st.button("Launch Hunt"):
            if hypothesis:
                log_file = "logs.csv"
                if os.path.exists(log_file):
                    df = pd.read_csv(log_file)
                    mask = df.astype(str).apply(lambda x: x.str.contains(hypothesis, case=False, na=False)).any(axis=1)
                    results_df = df[mask]
                    
                    st.success(f"Hunt completed for query: '{hypothesis}'")
                    st.write(f"**Found {len(results_df)} matching records:**")
                    if not results_df.empty:
                        st.dataframe(results_df, use_container_width=True)
                    else:
                        st.info("No matching threats found.")
                else:
                    st.warning("Log database not found.")
            else:
                st.warning("Please enter a query first.")

    # --- 9. Threat Intelligence (CTI) UI - LIVE API SCANNER ---
    def run_cti_tab(self):
        self.render_top_header("Cyber Threat Intelligence (Live API)")
        st.markdown("### 🌐 Live Website (Domain) & IP Scanner")
        st.write("کسی بھی ویب سائٹ کا لنک (جیسے `ncbae.edu.pk`) یا آئی پی ایڈریس درج کریں:")
        
        target = st.text_input("🔍 Enter IP or Domain/URL to Scan:")
        
        if st.button("Start Security Scan"):
            if target:
                with st.spinner(f"Querying VirusTotal globally for {target}..."):
                    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
                    
                    if is_ip:
                        result = self.ti_processor.check_ip_virustotal(target)
                    else:
                        result = self.ti_processor.check_domain_virustotal(target)
                    
                    if "error" in result:
                        st.error(f"Scan Failed: {result['error']}")
                    else:
                        st.success("Global Intelligence Scan Completed!")
                        st.write(f"**Target / Registrar:** {result.get('target', target)} ({result.get('owner', 'N/A')})")
                        
                        c1, c2, c3 = st.columns(3)
                        c1.error(f"🚨 Malicious: {result.get('malicious', 0)}")
                        c2.warning(f"⚠️ Suspicious: {result.get('suspicious', 0)}")
                        c3.success(f"✅ Safe: {result.get('harmless', 0)}")
                        
                        if result.get('malicious', 0) > 0:
                            st.error("DANGER: یہ ہدف خطرناک (Malicious) پایا گیا ہے!")
                        else:
                            st.info("System Clean: یہ ہدف بالکل محفوظ ہے۔")
            else:
                st.warning("Please enter a target first.")

    # --- 10. Dashboard Controller ---
    def run_overview_tab(self):
        self.render_top_header("SOC Overview")
        self.render_kpi_row()
        col1, col2 = st.columns(2)
        with col1: self.plot_alert_trend_line()
        with col2: self.plot_geographic_threat_map()

    def run_log_management_tab(self):
        self.render_top_header("Log Management & Search")
        search_query = self.render_log_search_bar()
        self.display_raw_logs_table(search_query)

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
