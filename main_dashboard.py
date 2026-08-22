import streamlit as st
import pandas as pd
import numpy as np
# Backend files ko import kar rahe hain
from threat_intel import ThreatIntelProcessor

class SOCDashboardUI:

    def __init__(self):
        self.app_name = "Enterprise SOC Platform (Real-time)"
        self.version = "2.0 Pro"
        self.ti_processor = ThreatIntelProcessor()

    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")

    def render_sidebar_navigation(self):
        st.sidebar.title("🛡️ SOC Navigation")
        return st.sidebar.radio("Go to", ["Overview", "CTI & Website Scanner"])

    def render_top_header(self, title):
        st.title(f"📊 {title}")
        st.markdown("---")

    # --- 1. Overview Tab (Basic KPI) ---
    def run_overview_tab(self):
        self.render_top_header("SOC Overview")
        col1, col2, col3 = st.columns(3)
        col1.metric(label="🚨 Critical Alerts", value=12, delta="+2")
        col2.metric(label="🔥 Active Incidents", value=3)
        col3.metric(label="🌐 APIs Connected", value=1, delta="VirusTotal Online")
        
        st.subheader("Geographic Threat Map (Sample)")
        df = pd.DataFrame(np.random.randn(10, 2) / [10, 10] + [37.76, -122.4], columns=['lat', 'lon'])
        st.map(df)

    # --- 2. Asli Scanner Tab (CTI) ---
    def run_cti_tab(self):
        self.render_top_header("Cyber Threat Intelligence (Real API Scanner)")
        st.write(" Kisi bhi Website ka IP address yahan likhein (e.g., 8.8.8.8) aur asli report dekhein.")
        
        target_ip = st.text_input("🔍 Enter IP Address to Scan:")
        
        if st.button("Start Security Scan"):
            if target_ip:
                with st.spinner(f"Scanning {target_ip} globally..."):
                    # Asli backend function call ho raha hai yahan
                    result = self.ti_processor.check_ip_virustotal(target_ip)
                    
                    if "error" in result:
                        st.error(f"Scan Failed: {result['error']}")
                    else:
                        st.success("Scan Completed!")
                        st.write(f"**IP Owner / ISP:** {result['owner']}")
                        
                        # Result ko khoobsurat cards mein dikhana
                        c1, c2, c3 = st.columns(3)
                        c1.error(f"🚨 Malicious (Hacker): {result['malicious']}")
                        c2.warning(f"⚠️ Suspicious: {result['suspicious']}")
                        c3.success(f"✅ Safe (Harmless): {result['harmless']}")
                        
                        if result['malicious'] > 0:
                            st.error("DANGER: Yeh IP unsafe hai! Website owner ko alert karein!")
                        else:
                            st.info("System Clean: Yeh IP safe lag raha hai.")
            else:
                st.warning("Please enter an IP address first.")

    def main_loop(self):
        self.setup_page_config()
        selected_page = self.render_sidebar_navigation()

        if selected_page == "Overview":
            self.run_overview_tab()
        elif selected_page == "CTI & Website Scanner":
            self.run_cti_tab()
        
        st.markdown("---")
        st.caption("Powered by MHZALY | Real API Integration Enabled")

if __name__ == "__main__":
    dashboard = SOCDashboardUI()
    dashboard.main_loop()
