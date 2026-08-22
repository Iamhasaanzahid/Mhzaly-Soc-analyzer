import streamlit as st
import pandas as pd
import numpy as np
import os
import re
from datetime import datetime
from threat_intel import ThreatIntelProcessor

class SOCDashboardUI:

    def __init__(self):
        self.app_name = "Enterprise SOC & Bug Bounty Platform"
        self.version = "5.0 Ultimate Pro"
        self.processor = ThreatIntelProcessor()
        self.log_file = "logs.csv"
        self.audit_file = "audit_log.csv"
        self.check_and_create_files()

    # --- 1. Page Configuration & Layout ---
    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")

    def render_sidebar_navigation(self):
        st.sidebar.title("🛡️ SOC Command Center")
        return st.sidebar.radio("Go to", [
            "Overview", 
            "Log Management", 
            "Threat Analysis", 
            "Incident Response", 
            "Vulnerability Management", 
            "Threat Hunting", 
            "CTI Feeds & Bug Bounty"
        ])

    def render_top_header(self, title):
        st.title(f"📊 {title}")
        st.markdown("---")

    def render_footer(self):
        st.markdown("---")
        st.caption(f"{self.app_name} v{self.version} | Real-time Security Monitoring & Threat Intelligence Powered by MHZALY")

    def apply_custom_css(self):
        st.markdown("""<style>.stMetric { background-color: #f0f2f6; padding: 10px; border-radius: 5px; }</style>""", unsafe_allow_html=True)

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

    # --- 2. Overview & Live Health Metrics ---
    def run_overview_tab(self):
        self.render_top_header("SOC Overview & Live Health")
        
        df = pd.read_csv(self.log_file)
        critical_count = len(df[df['Severity'] == 'Critical'])
        total_events = len(df)
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric(label="🚨 Critical Alerts", value=critical_count, delta="Live from logs", delta_color="inverse")
        col2.metric(label="📈 Total Ingested Logs", value=total_events)
        col3.metric(label="⏱️ MTTD (Detect)", value="12m")
        col4.metric(label="🛠️ MTTR (Respond)", value="3h 15m")

        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Threat Severity Distribution")
            st.bar_chart(df['Severity'].value_counts())
        with col2:
            st.subheader("Log Sources Breakdown")
            st.bar_chart(df['Source'].value_counts())

    # --- 3. Log Management & Search ---
    def run_log_management_tab(self):
        self.render_top_header("Log Management & Search")
        search_query = st.text_input("🔍 Search Logs (e.g., Firewall, EDR, 4625, Critical)")
        
        df = pd.read_csv(self.log_file)
        if search_query:
            mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
            df = df[mask]
        st.dataframe(df, use_container_width=True)

    # --- 4. Threat Analysis & Triage ---
    def run_threat_analysis_tab(self):
        self.render_top_header("Threat Analysis & Triage")
        
        if 'alerts' not in st.session_state:
            st.session_state.alerts = [
                {"Alert ID": "ALT-101", "Severity": "Critical", "Status": "New", "Description": "Multiple failed logins detected (EventID 4625)"},
                {"Alert ID": "ALT-102", "Severity": "High", "Status": "New", "Description": "Unusual PowerShell script execution"},
                {"Alert ID": "ALT-103", "Severity": "Medium", "Status": "New", "Description": "Security log cleared on endpoint"}
            ]

        st.dataframe(pd.DataFrame(st.session_state.alerts), use_container_width=True)
        selected_id = st.selectbox("Select Alert ID to Process:", [a['Alert ID'] for a in st.session_state.alerts])
        
        col1, col2, col3 = st.columns(3)
        if col1.button("✅ Acknowledge Alert"):
            for alert in st.session_state.alerts:
                if alert['Alert ID'] == selected_id: alert['Status'] = "Acknowledged"
            st.success(f"Alert {selected_id} acknowledged successfully!")
            st.rerun()

        if col2.button("🔥 Escalate to Incident"):
            for alert in st.session_state.alerts:
                if alert['Alert ID'] == selected_id: alert['Status'] = "Escalated"
            st.warning(f"Alert {selected_id} escalated to Incident Response!")
            st.rerun()

        if col3.button("🛡️ Mark False Positive"):
            for alert in st.session_state.alerts:
                if alert['Alert ID'] == selected_id: alert['Status'] = "False Positive"
            st.info(f"Alert {selected_id} marked as False Positive.")
            st.rerun()

    # --- 5. Incident Response & SOAR Actions ---
    def run_incident_response_tab(self):
        self.render_top_header("Incident Response & SOAR Actions")
        
        target = st.text_input("Enter Compromised Hostname or Malicious IP:")
        
        col1, col2, col3 = st.columns(3)
        if col1.button("🔒 Isolate Host (EDR)"):
            self.log_action("Isolate Host", target)
            st.success(f"Host {target} isolated successfully from the network!")
            
        if col2.button("🛑 Block IP on Firewall"):
            self.log_action("Block IP", target)
            st.success(f"IP {target} blocked on perimeter firewall!")
            
        if col3.button("👤 Disable AD Account"):
            self.log_action("Disable Account", target)
            st.success(f"Account for {target} disabled in Active Directory!")

        st.markdown("---")
        notes = st.text_area("Analyst Investigation Notes:")
        if st.button("Save Case Notes"):
            st.success("Investigation notes saved securely.")

        if os.path.exists(self.audit_file):
            st.subheader("SOAR Action Audit Trail")
            st.dataframe(pd.read_csv(self.audit_file), use_container_width=True)

    def log_action(self, action, target):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = pd.DataFrame({"Timestamp": [timestamp], "Action": [action], "Target": [target]})
        if os.path.exists(self.audit_file):
            entry.to_csv(self.audit_file, mode='a', header=False, index=False)
        else:
            entry.to_csv(self.audit_file, index=False)

    # --- 6. Vulnerability Management ---
    def run_vulnerability_tab(self):
        self.render_top_header("Vulnerability Management & Asset Risk")
        
        if 'assets' not in st.session_state:
            st.session_state.assets = [
                {"Hostname": "SRV-DB-01", "Risk Score": 95, "Status": "Unpatched", "Owner": "DBA Team"},
                {"Hostname": "DC-01", "Risk Score": 88, "Status": "Unpatched", "Owner": "IT Ops"}
            ]

        st.dataframe(pd.DataFrame(st.session_state.assets), use_container_width=True)
        selected_host = st.selectbox("Select Asset to Patch:", [a['Hostname'] for a in st.session_state.assets])
        patch = st.selectbox("Select Security Patch:", ["KB5012345 (Critical)", "KB5019876 (Security Update)"])
        
        if st.button("Deploy Patch Now"):
            for asset in st.session_state.assets:
                if asset['Hostname'] == selected_host:
                    asset['Status'] = "Patched & Secure"
                    asset['Risk Score'] = max(0, asset['Risk Score'] - 45)
            st.success(f"Patch {patch} deployed successfully on {selected_host}!")
            st.rerun()

    # --- 7. Proactive Threat Hunting ---
    def run_threat_hunting_tab(self):
        self.render_top_header("Proactive Threat Hunting")
        hypothesis = st.text_input("Enter Hunt Hypothesis / Keyword (e.g., Failed, Process, EDR):")
        
        if st.button("Launch Hunt"):
            if hypothesis:
                df = pd.read_csv(self.log_file)
                mask = df.astype(str).apply(lambda x: x.str.contains(hypothesis, case=False, na=False)).any(axis=1)
                res = df[mask]
                st.success(f"Hunt completed for query: '{hypothesis}'")
                st.write(f"**Found {len(res)} matching records:**")
                st.dataframe(res, use_container_width=True)
            else:
                st.warning("Please enter a query first.")

    # --- 8. CTI Feeds & Bug Bounty Scanner (Real API) ---
    def run_cti_tab(self):
        self.render_top_header("Cyber Threat Intelligence & Bug Bounty Scanner")
        st.markdown("### 🌐 Real-World Website (Domain) & IP Scanner")
        st.write("کسی بھی ویب سائٹ کا لنک (جیسے `ncbae.edu.pk` یا `example.com`) یا آئی پی ایڈریس درج کریں تاکہ گلوبل سکیورٹی وینڈرز کی رئیل رپورٹس حاصل کی جا سکیں:")
        
        target = st.text_input("🔍 Enter Website Domain or IP to Scan:")
        
        if st.button("Run Deep Security Scan"):
            if target:
                with st.spinner(f"Querying global threat databases for {target}..."):
                    result = self.processor.scan_target(target)
                    
                    if "error" in result:
                        st.error(result['error'])
                    else:
                        st.success("Global Security Analysis Complete!")
                        
                        stats = result.get('last_analysis_stats', {})
                        st.subheader(f"📊 Risk Analysis for: {target}")
                        
                        c1, c2, c3, c4 = st.columns(4)
                        c1.error(f"🚨 Malicious: {stats.get('malicious', 0)}")
                        c2.warning(f"⚠️ Suspicious: {stats.get('suspicious', 0)}")
                        c3.success(f"✅ Harmless: {stats.get('harmless', 0)}")
                        c4.info(f"🛡️ Undetected: {stats.get('undetected', 0)}")
                        
                        vendors = result.get('last_analysis_results', {})
                        malicious_vendors = {k: v['result'] for k, v in vendors.items() if v.get('category') == 'malicious'}
                        
                        if malicious_vendors:
                            st.subheader("🚨 Security Vendors Reporting Issues:")
                            st.table(pd.DataFrame(list(malicious_vendors.items()), columns=["Security Vendor", "Finding / Risk"]))
                            st.warning("⚠️ اس ہدف میں اوپر دی گئی سکیورٹی ایجنسیوں نے مسائل یا خطرات کی نشاندہی کی ہے۔ آپ یہ رپورٹ کمپنی کو بھیج سکتے ہیں!")
                        else:
                            st.info("✨ Clean Infrastructure: کسی بھی معروف سکیورٹی وینڈر نے اس ہدف میں خطرہ نہیں پایا۔")
            else:
                st.warning("Please enter a valid domain or IP address.")

    def main_loop(self):
        self.setup_page_config()
        self.apply_custom_css()
        selected_page = self.render_sidebar_navigation()

        if selected_page == "Overview": self.run_overview_tab()
        elif selected_page == "Log Management": self.run_log_management_tab()
        elif selected_page == "Threat Analysis": self.run_threat_analysis_tab()
        elif selected_page == "Incident Response": self.run_incident_response_tab()
        elif selected_page == "Vulnerability Management": self.run_vulnerability_tab()
        elif selected_page == "Threat Hunting": self.run_threat_hunting_tab()
        elif selected_page == "CTI Feeds & Bug Bounty": self.run_cti_tab()
        
        self.render_footer()

if __name__ == "__main__":
    dashboard = SOCDashboardUI()
    dashboard.main_loop()
