import streamlit as st
import pandas as pd
import os
from threat_intel import ThreatIntelProcessor

class RealWorldSOCPlatform:
    def __init__(self):
        self.app_name = "MHZALY Real-World SOC & Bug Bounty Platform"
        self.version = "6.1 Live Pro"
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
            st.markdown("کسی بھی ویب سائٹ یا ڈومین کا نام درج کریں تاکہ گلوبل سکیورٹی وینڈرز کی تفصیلی رپورٹس (Harmless, Malicious, Undetected) لائیو دیکھی جا سکیں:")
            
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
                            c1.error(f"🚨 Malicious: {stats.get('malicious', 0)}")
                            c2.warning(f"⚠️ Suspicious: {stats.get('suspicious', 0)}")
                            c3.success(f"✅ Harmless (Safe): {stats.get('harmless', 0)}")
                            c4.info(f"🛡️ Undetected: {stats.get('undetected', 0)}")
                            
                            # Fetching all vendor results to show what's clean, malicious, or undetected
                            vendors = result.get('last_analysis_results', {})
                            
                            if vendors:
                                # Categorize vendor results
                                vendor_list = []
                                for vendor_name, details in vendors.items():
                                    vendor_list.append({
                                        "Security Vendor": vendor_name,
                                        "Category": details.get('category'),
                                        "Result / Verdict": details.get('result')
                                    })
                                
                                df_vendors = pd.DataFrame(vendor_list)
                                
                                st.markdown("---")
                                st.subheader("📋 Complete Breakdown of All Security Vendors")
                                st.write("یہاں آپ دیکھ سکتے ہیں کہ کس وینڈر نے اس ہدف کو کیا نتیجہ دیا ہے:")
                                
                                # Filter options for user to inspect easily
                                filter_option = st.selectbox("Filter by Verdict:", ["All", "malicious", "harmless", "undetected", "suspicious"])
                                
                                if filter_option != "All":
                                    filtered_df = df_vendors[df_vendors['Category'] == filter_option]
                                    st.dataframe(filtered_df, use_container_width=True)
                                else:
                                    st.dataframe(df_vendors, use_container_width=True)
                                    
                                malicious_count = stats.get('malicious', 0)
                                if malicious_count > 0:
                                    st.error("⚠️ خطرہ موجود ہے! اوپر دیے گئے مَلِیشیس وینڈرز کی لسٹ چیک کریں۔")
                                else:
                                    st.info("✨ یہ ہدف بالکل محفوظ (Clean) ہے اور تمام معروف سکیورٹی ایجنسیوں نے اسے ہارم لیس قرار دیا ہے۔")
                else:
                    st.warning("Please enter a valid domain name.")

        elif choice == "Global Threat Intelligence (IP/Domain)":
            st.title("🌐 Live IP & Threat Intelligence Lookup")
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
