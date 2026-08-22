import streamlit as st
import pandas as pd
import os
import re
from datetime import datetime
from threat_intel import ThreatIntelProcessor

class SOCDashboardUI:
    def __init__(self):
        self.app_name = "Enterprise SOC Platform"
        self.version = "3.5 Pro"
        self.ti_processor = ThreatIntelProcessor()
        self.log_file = "logs.csv"
        self.audit_file = "audit_log.csv"
        self.check_and_create_files()

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

    # --- AUTOMATIC FILE CREATOR (ताकि कभी एरर न आए) ---
    def check_and_create_files(self):
        if not os.path.exists(self.log_file):
            default_data = {
                "Timestamp": ["2026-08-22 10:00", "2026-08-22 10:05", "2026-08-22 10:10", "2026-08-22 10:15"],
                "Source": ["Firewall", "EDR", "AD", "Firewall"],
                "EventID": ["4625", "1102", "4624", "4688"],
                "Details": ["Failed Login Attempt", "Security Log Cleared", "Successful Logon", "Suspicious Process Created"],
                "Severity": ["Critical", "Critical", "Low", "High"]
            }
            pd.DataFrame(default_data).to_csv(self.log_file, index=False)

    # --- DYNAMIC METRICS FROM LOGS ---
    def render_kpi_row(self):
        if os.path.exists(self.log_file):
            df = pd.read_csv(self.log_file)
            critical_count = len(df[df['Severity'] == 'Critical'])
            active_incidents = len(df)
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("🚨 Critical Alerts", critical_count, "Live from logs")
            col2.metric("🔥 Total Log Events", active_incidents, "Real-time")
            col3.metric("⏱️ Avg Detection", "12m")
            col4.metric("🛠️ Response Actions Logged", self.get_audit_count())

    def get_audit_count(self):
        if os.path.exists(self.audit_file):
            return len(pd.read_csv(self.audit_file))
        return 0

    # --- 1. OVERVIEW TAB ---
    def run_overview_tab(self):
        self.render_top_header("SOC Overview & Live Health")
        self.render_kpi_row()
        st.markdown("---")
        st.subheader("📊 Threat Severity Breakdown")
        if os.path.exists(self.log_file):
            df = pd.read_csv(self.log_file)
            severity_counts = df['Severity'].value_counts()
            st.bar_chart(severity_counts)

    # --- 2. LOG MANAGEMENT TAB ---
    def run_log_management_tab(self):
        self.render_top_header("Log Management & Search")
        search_query = st.text_input("🔍 Search Logs (e.g., Critical, Firewall, 4625)")
        
        df = pd.read_csv(self.log_file)
        if search_query:
            mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
            df = df[mask]
        st.dataframe(df, use_container_width=True)

    # --- 3. THREAT ANALYSIS TAB ---
    def run_threat_analysis_tab(self):
        self.render_top_header("Threat Analysis & Triage")
        if 'alerts' not in st.session_state:
            st.session_state.alerts = [
                {"Alert ID": "ALT-101", "Severity": "Critical", "Status": "New", "Description": "Multiple failed logins from external IP"},
                {"Alert ID": "ALT-102", "Severity": "High", "Status": "New", "Description": "Unusual PowerShell script execution"}
            ]
        st.dataframe(pd.DataFrame(st.session_state.alerts), use_container_width=True)
        selected_id = st.selectbox("Select Alert ID:", [a['Alert ID'] for a in st.session_state.alerts])
        
        if st.button("✅ Acknowledge & Process"):
            for a in st.session_state.alerts:
                if a['Alert ID'] == selected_id: a['Status'] = "Acknowledged"
            st.success(f"Alert {selected_id} status updated.")
            st.rerun()

    # --- 4. INCIDENT RESPONSE TAB ---
    def run_incident_response_tab(self):
        self.render_top_header("Incident Response & SOAR Actions")
        target = st.text_input("Enter Hostname or IP to Mitigate:")
        
        col1, col2 = st.columns(2)
        if col1.button("🔒 Isolate Host"):
            self.log_action("Isolate Host", target)
            st.success(f"Host {target} isolated successfully! Logged in audit trail.")
        if col2.button("🛑 Block IP on Firewall"):
            self.log_action("Block IP", target)
            st.success(f"IP {target} blocked on firewall! Logged in audit trail.")
            
        if os.path.exists(self.audit_file):
            st.subheader("Audit Trail (Professional Action Record)")
            st.dataframe(pd.read_csv(self.audit_file))

    def log_action(self, action, target):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = pd.DataFrame({"Timestamp": [timestamp], "Action": [action], "Target": [target]})
        if os.path.exists(self.audit_file):
            entry.to_csv(self.audit_file, mode='a', header=False, index=False)
        else:
            entry.to_csv(self.audit_file, index=False)

    # --- 5. VULNERABILITY MANAGEMENT TAB ---
    def run_vulnerability_tab(self):
        self.render_top_header("Vulnerability Management & Assets")
        assets = pd.DataFrame([
            {"Hostname": "SRV-DB-01", "Risk Score": 95, "Status": "Unpatched", "Owner": "DBA Team"},
            {"Hostname": "DC-01", "Risk Score": 88, "Status": "Unpatched", "Owner": "IT Ops"}
        ])
        st.dataframe(assets, use_container_width=True)
        if st.button("Deploy Critical Security Patch"):
            st.success("Patches deployed successfully across corporate assets!")

    # --- 6. THREAT HUNTING TAB ---
    def run_threat_hunting_tab(self):
        self.render_top_header("Proactive Threat Hunting")
        query = st.text_input("Enter Hunt Hypothesis / Keyword:")
        if st.button("Launch Hunt"):
            if query:
                df = pd.read_csv(self.log_file)
                mask = df.astype(str).apply(lambda x: x.str.contains(query, case=False, na=False)).any(axis=1)
                res = df[mask]
                st.success(f"Hunt complete. Found {len(res)} matches.")
                st.dataframe(res, use_container_width=True)

    # --- 7. CTI FEEDS (LIVE API SCANNER) ---
    def run_cti_tab(self):
        self.render_top_header("Cyber Threat Intelligence (Live API)")
        target = st.text_input("🔍 Enter IP or Domain to Scan (e.g., ncbae.edu.pk):")
        
        if st.button("Start Security Scan"):
            if target:
                with st.spinner(f"Scanning {target} globally..."):
                    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
                    res = self.ti_processor.check_ip_virustotal(target) if is_ip else self.ti_processor.check_domain_virustotal(target)
                    
                    if "error" in res:
                        st.error(f"Scan Failed: {res['error']}")
                    else:
                        st.success("Scan Completed!")
                        st.write(f"**Target:** {res.get('target', target)} | **Owner/Registrar:** {res.get('owner', 'N/A')}")
                        
                        c1, c2, c3 = st.columns(3)
                        c1.error(f"🚨 Malicious: {res.get('malicious', 0)}")
                        c2.warning(f"⚠️ Suspicious: {res.get('suspicious', 0)}")
                        c3.success(f"✅ Safe: {res.get('harmless', 0)}")
                        
                        vendors = res.get('malicious_vendors', {})
                        if vendors:
                            st.subheader("🚨 Security Vendors Flagging this Threat:")
                            st.table(pd.DataFrame(list(vendors.items()), columns=["Vendor", "Result"]))
                        else:
                            st.info("System Clean: No major security vendor flagged this target.")

    def main_loop(self):
        self.setup_page_config()
        page = self.render_sidebar_navigation()
        if page == "Overview": self.run_overview_tab()
        elif page == "Log Management": self.run_log_management_tab()
        elif page == "Threat Analysis": self.run_threat_analysis_tab()
        elif page == "Incident Response": self.run_incident_response_tab()
        elif page == "Vulnerability Management": self.run_vulnerability_tab()
        elif page == "Threat Hunting": self.run_threat_hunting_tab()
        elif page == "CTI Feeds": self.run_cti_tab()
        self.render_footer()

if __name__ == "__main__":
    dashboard = SOCDashboardUI()
    dashboard.main_loop()
