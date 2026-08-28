import streamlit as st
import hashlib
import re
import sqlite3
from datetime import datetime

class CryptoAnalyzerManager:
    def __init__(self, db_path="soc_crypto.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS crypto_audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    strength_result TEXT,
                    score INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def log_audit(self, strength, score):
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO crypto_audits (strength_result, score) VALUES (?, ?)",
                (strength, score)
            )
            conn.commit()

def render_crypto_analyzer():
    manager = CryptoAnalyzerManager()
    
    st.markdown("### 🔐 Cryptographic Hash & Password Strength Analyzer")
    st.markdown("Evaluate password complexity, check entropy standards, and generate instant cryptographic hashes (MD5, SHA-256) for forensic analysis.")

    target_input = st.text_input("Enter Password or String to Analyze:", type="password", placeholder="Enter secret or password...")

    if target_input:
        st.markdown("---")
        st.markdown("#### 🔍 Cryptographic Hashes")
        
        md5_hash = hashlib.md5(target_input.encode()).hexdigest()
        sha256_hash = hashlib.sha256(target_input.encode()).hexdigest()

        col1, col2 = st.columns(2)
        with col1:
            st.text_input("MD5 Hash", value=md5_hash, disabled=True)
        with col2:
            st.text_input("SHA-256 Hash", value=sha256_hash, disabled=True)

        st.markdown("---")
        st.markdown("#### 🛡️ Password Complexity & Strength Audit")

        length_score = len(target_input) >= 8
        upper_score = bool(re.search(r'[A-Z]', target_input))
        lower_score = bool(re.search(r'[a-z]', target_input))
        digit_score = bool(re.search(r'\d', target_input))
        special_score = bool(re.search(r'[@$!%*?&]', target_input))

        score = sum([length_score, upper_score, lower_score, digit_score, special_score])

        strength_text = "WEAK"
        if score == 5:
            strength_text = "EXTREMELY STRONG"
            st.success("🟢 **Strength: EXTREMELY STRONG** - Meets all enterprise cryptographic complexity standards.")
        elif score >= 3:
            strength_text = "MODERATE"
            st.warning("🟡 **Strength: MODERATE** - Consider adding special characters and numbers for higher entropy.")
        else:
            st.error("🔴 **Strength: WEAK** - Vulnerable to Brute-Force and Dictionary attacks!")

        # Log audit result to database securely
        manager.log_audit(strength_text, score)

        st.write("- **Length (>= 8 chars):**", "✅" if length_score else "❌")
        st.write("- **Uppercase Letter:**", "✅" if upper_score else "❌")
        st.write("- **Lowercase Letter:**", "✅" if lower_score else "❌")
        st.write("- **Numbers:**", "✅" if digit_score else "❌")
        st.write("- **Special Characters (@$!%*?&):**", "✅" if special_score else "❌")

if __name__ == "__main__":
    render_crypto_analyzer()
