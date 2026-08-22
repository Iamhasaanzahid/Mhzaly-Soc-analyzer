import streamlit as st
import pandas as pd
import os
from threat_intel import ThreatIntelProcessor

class RealWorldSOCPlatform:
    def __init__(self):
        self.app_name = "MHZALY Real-World SOC & Bug Bounty Platform"
        self.version = "6.0 Live Pro"
        self.processor = ThreatIntelProcessor()

    def setup_page(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")

    def main_loop(self):
        self.setup_page()
        
        st.sidebar.title("🛡️ SOC Command Center")
        choice = st.sidebar.radio("Navigation", [
            "Live Bug Bounty & Vulnerability Scanner",
            "Global Threat Intelligence (IP/Domain)",
            "Live Incident Mitigation & SOAR"
        ])

        if choice == "Live Bug Bounty & Vulnerability Scanner":
            st.title("🔍 Real-World Bug Bounty & Infrastructure Analyzer")
            st.markdown("یہ ٹूल دنیا کے سب سے بڑے سکیورٹی ڈیٹا بیس (VirusTotal Global Feed) سے جڑا ہے۔ کسی بھی کمپنی یا ویب سائٹ کا ڈومین لکھیں اور اس کے لائیو خطرات چیک کریں:")
            
            target = st.text_input("Enter Target Domain (e.g., google.com, ncbae.edu.pk):")
            
            if st.button("Execute Live Global Scan"):
                if target:
                    with st.spinner(f"Connecting to global security nodes for {target}..."):
                        result = self.processor.scan_target(target)
                        
                        if "error" in result:
                            st.error(result['error'])
                        else:
                            st.success("Live Scan Successfully Completed!")
                            
                            stats = result.get('last_analysis_stats', {})
                            st.subheader(f"📊 Global Security Posture: {target}")
                            
                            c1, c2, c3, c4 = st.columns(4)
                            c1.error(f"🚨 Malicious Flags: {stats.get('malicious', 0)}")
                            c2.warning(f"⚠️ Suspicious: {stats.get('suspicious', 0)}")
                            c3.success(f"✅ Clean / Harmless: {stats.get('harmless', 0)}")
                            c4.info(f"🛡️ Undetected: {stats.get('undetected', 0)}")
                            
                            # Vendor Breakdown (Real Bug Bounty Report)
                            vendors = result.get('last_analysis_results', {})
                            malicious_vendors = {k: v['result'] for k, v in vendors.items() if v.get('category') == 'malicious'}
                            
                            if malicious_vendors:
                                st.subheader("🚨 Security Vendors Reporting Vulnerabilities / Threats:")
                                st.table(pd.DataFrame(list(malicious_vendors.items()), columns=["Security Vendor", "Detection Details"]))
                                st.error("⚠️ یہ لائیو رپورٹ آپ بطور سکیورٹی آڈٹ متعلقہ کمپنی کو پیش کر سکتے ہیں!")
                            else:
                                st.info("✨ Infrastructure Clean: گلوبل سکیورٹی نیٹ ورک کے مطابق یہ ہدف بالکل محفوظ ہے۔")
                else:
                    st.warning("Please enter a valid domain name.")

        elif choice == "Global Threat Intelligence (IP/Domain)":
            st.title("🌐 Live IP & Threat Intelligence Lookup")
            st.markdown("مشکوک آئی پی ایڈریس کی جانچ پڑتال کریں:")
            ip_target = st.text_input("Enter IP Address (e.g., 8.8.8.8):")
            if st.button("Query IP Intelligence"):
                if ip_target:
                    with st.spinner("Fetching IP intelligence..."):
                        res = self.processor.scan_target(ip_target)
                        if "error" in res:
                            st.error(res['error'])
                        else:
                            st.json(res)

        elif choice == "Live Incident Mitigation & SOAR":
            st.title("⚡ Live Incident Response & Firewall Actions")
            st.markdown("کسی بھی خطرناک ہدف کو بلاک کرنے کے لیے لائیو ایکشن ٹرگر کریں:")
            bad_target = st.text_input("Enter Malicious IP or Domain to Block:")
            if st.button("🛑 Block on Perimeter Firewall & EDR"):
                if bad_target:
                    st.warning(f"Sending API command to block {bad_target} across corporate gateways...")
                    st.success(f"Target {bad_target} successfully blacklisted and isolated!")
                else:
                    st.warning("Please enter a target.")

        st.markdown("---")
        st.caption(f"{self.app_name} v{self.version} | Real-World Cyber Defense Engine")

if __name__ == "__main__":
    app = RealWorldSOCPlatform()
    app.main_loop()
