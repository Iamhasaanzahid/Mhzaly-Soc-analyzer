# crypto_analyzer.py - Password Hashing & Strength Analyzer Module for MHZALY-SOC

import streamlit as st
import hashlib
import re

def render_crypto_analyzer():
    st.markdown("### 🔐 Cryptographic Hash & Password Strength Analyzer")
    st.markdown("Evaluate password complexity, check entropy standards, and generate instant cryptographic hashes (MD5, SHA-256) for forensic analysis.")

    # Input text or password
    target_input = st.text_input("Enter Password or String to Analyze:", type="password", placeholder="Enter secret or password...")

    if target_input:
        st.markdown("---")
        st.markdown("#### 🔍 Cryptographic Hashes")
        
        # Generate Hashes
        md5_hash = hashlib.md5(target_input.encode()).hexdigest()
        sha256_hash = hashlib.sha256(target_input.encode()).hexdigest()

        col1, col2 = st.columns(2)
        with col1:
            st.text_input("MD5 Hash", value=md5_hash, disabled=True)
        with col2:
            st.text_input("SHA-256 Hash", value=sha256_hash, disabled=True)

        st.markdown("---")
        st.markdown("#### 🛡️ Password Complexity & Strength Audit")

        # Strength calculation logic
        length_score = len(target_input) >= 8
        upper_score = bool(re.search(r'[A-Z]', target_input))
        lower_score = bool(re.search(r'[a-z]', target_input))
        digit_score = bool(re.search(r'\d', target_input))
        special_score = bool(re.search(r'[@$!%*?&]', target_input))

        score = sum([length_score, upper_score, lower_score, digit_score, special_score])

        # Display Metrics
        if score == 5:
            st.success("🟢 **Strength: EXTREMELY STRONG** - Meets all enterprise cryptographic complexity standards.")
        elif score >= 3:
            st.warning("🟡 **Strength: MODERATE** - Consider adding special characters and numbers for higher entropy.")
        else:
            st.error("🔴 **Strength: WEAK** - Vulnerable to Brute-Force and Dictionary attacks!")

        # Checklist details
        st.write("- **Length (>= 8 chars):**", "✅" if length_score else "❌")
        st.write("- **Uppercase Letter:**", "✅" if upper_score else "❌")
        st.write("- **Lowercase Letter:**", "✅" if lower_score else "❌")
        st.write("- **Numbers:**", "✅" if digit_score else "❌")
        st.write("- **Special Characters (@$!%*?&):**", "✅" if special_score else "❌")

if __name__ == "__main__":
    render_crypto_analyzer()
