import streamlit as st
import pandas as pd
import os
from threat_intel import ThreatIntelProcessor

class SOCDashboardUI:

    def __init__(self):
        self.app_name = "MHZALY Real-World SOC & Bug Bounty Platform"
        self.version = "6.2 Pro"
        self.processor = ThreatIntelProcessor()

    def setup_page_config(self):
        st.set_page_config(page_title=self.app_name, layout="wide", page_icon="🛡️")

    def render_sidebar(self):
        st.sidebar.title("🛡️ Command Center")
        return st.sidebar.radio("Navigation", [
            "Global Threat Intel (VirusTotal)", 
            "Deep Bug Bounty & Vulnerability Scanner", 
            "Live Incident Defense & Reporting"
        ])

    def run_overview(self):
        st.title("🛡️ MHZALY Real-World Cyber Defense Platform")
        st.markdown("---")
        st.info("خوش آمدید! یہ پلیٹ فارم اب فرضی یا ڈمی ڈیٹا پر نہیں بلکہ **اصلی گلوبل انٹیلی جنس اور ڈیپ ویب سکیننگ** پر کام کرتا ہے۔ سائیڈ بار سے آپشن منتخب کریں۔")

    # --- 1. GLOBAL THREAT INTEL TAB ---
    def run_threat_intel(self):
        st.title("🌐 Global Threat Intelligence (VirusTotal API)")
        st.markdown("کسی بھی مشکوک آئی پی یا ڈومین کی گلوبل سکیورٹی رپورٹ چیک کریں:")
        
        target = st.text_input("Enter IP or Domain (e.g., 8.8.8.8 or example.com):")
        if st.button("Query Global Database"):
            if target:
                with st.spinner("Fetching global threat intelligence..."):
                    result = self.processor.scan_target(target)
                    if "error" in result:
                        st.error(result['error'])
                    else:
                        st.success("Analysis Complete!")
                        stats = result.get('last_analysis_stats', {})
                        
                        c1, c2, c3 = st.columns(3)
                        c1.error(f"🚨 Malicious: {stats.get('malicious', 0)}")
                        c2.warning(f"⚠️ Suspicious: {stats.get('suspicious', 0)}")
                        c3.success(f"✅ Harmless: {stats.get('harmless', 0)}")
                        
                        vendors = result.get('last_analysis_results', {})
                        malicious_vendors = {k: v['result'] for k, v in vendors.items() if v.get('category') == 'malicious'}
                        if malicious_vendors:
                            st.subheader("🚨 Flagged by Security Vendors:")
                            st.table(pd.DataFrame(list(malicious_vendors.items()), columns=["Vendor", "Finding"]))

    # --- 2. DEEP BUG BOUNTY SCANNER TAB (NEW & REALISTIC) ---
    def run_bug_bounty_scanner(self):
        st.title("🔍 Deep Bug Bounty & Security Header Analyzer")
        st.markdown("یہ ٹول ہدف کی ویب سائٹ کی گہرائی میں جا کر اس کے **سکیورٹی ہیڈرز اور کمزوریاں (Missing Security Headers)** تلاش کرتا ہے — جو ایک اصلی بگ باؤنٹی ہنٹر کا پہلا قدم ہوتا ہے:")
        
        domain = st.text_input("Enter Target Domain (e.g., ncbae.edu.pk or example.com):")
        
        if st.button("Run Deep Bug Scan"):
            if domain:
                with st.spinner(f"Analyzing infrastructure and security headers for {domain}..."):
                    scan_res = self.processor.deep_bug_bounty_scan(domain)
                    
                    if "error" in scan_res:
                        st.error(scan_res['error'])
                    else:
                        st.success("Deep Scan Successful!")
                        st.write(f"**Target URL:** {scan_res.get('final_url')}")
                        st.write(f"**HTTP Status Code:** {scan_res.get('status_code')}")
                        
                        findings = scan_res.get('findings', [])
                        if findings:
                            st.subheader(f"⚠️ Found {len(findings)} Security Vulnerabilities / Missing Protections:")
                            df_findings = pd.DataFrame(findings)
                            st.dataframe(df_findings, use_container_width=True)
                            st.warning("💡 آپ ان خامیوں کی بنیاد پر متعلقہ کمپنی یا ایڈمن کو ایک پروفیشنل **Security Vulnerability Disclosure Report** بھیج سکتے ہیں تاکہ وہ اپنی سکیورٹی بہتر کر سکیں!")
                        else:
                            st.info("✨ زبردست! اس ہدف پر کوئی بنیادی مسنگ ہیڈر یا کمزوری نہیں پائی گئی۔ سکیورٹی بہترین ہے۔")
            else:
                st.warning("Please enter a domain name.")

    # --- 3. LIVE INCIDENT DEFENSE & REPORTING ---
    def run_incident_defense(self):
        st.title("⚡ Incident Defense & Evidence Logging")
        st.markdown("مشکوک یا سکیمنگ ویب سائٹ کے خلاف ثبوت درج کریں اور آڈٹ فائل میں محفوظ کریں:")
        
        scam_target = st.text_input("Enter Scam/Malicious Website URL:")
        evidence_notes = st.text_area("Investigation Findings / Notes:")
        
        if st.button("Log Evidence & Generate Report"):
            if scam_target:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_df = pd.DataFrame({"Timestamp": [timestamp], "Target": [scam_target], "Notes": [evidence_notes], "Status": [“Logged & Reported”]})
                
                file_name = "incident_reports.csv"
                if os.path.exists(file_name):
                    audit_df.to_csv(file_name, mode='a', header=False, index=False)
                else:
                    audit_df.to_csv(file_name, index=False)
                    
                st.success("Successfully logged into corporate incident ledger! You are helping build a safer internet.")
                if os.path.exists(file_name):
                    st.subheader("Saved Incident Reports:")
                    st.dataframe(pd.read_csv(file_name), use_container_width=True)
            else:
                st.warning("Please enter a target URL.")

    def main(self):
        self.setup_page_config()
        choice = self.render_sidebar()
        
        if choice == "Global Threat Intel (VirusTotal)": self.run_threat_intel()
        elif choice == "Deep Bug Bounty & Vulnerability Scanner": self.run_bug_bounty_scanner()
        elif choice == "Live Incident Defense & Reporting": self.run_incident_defense()

if __name__ == "__main__":
    app = SOCDashboardUI()
    app.main()
