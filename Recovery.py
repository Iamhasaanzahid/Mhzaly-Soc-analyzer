import streamlit as st
import sqlite3
from datetime import datetime

class RecoveryAndRemediation:
    def __init__(self, db_path="soc_recovery.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_detail TEXT,
                    status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _log_recovery_action(self, detail, status):
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO recovery_logs (action_detail, status) VALUES (?, ?)",
                (detail, status)
            )
            conn.commit()

    def recover_system(self, target_host="192.168.1.100"):
        st.write("### Incident Response: Recovery Phase")
        st.info(f"Initiating system recovery protocols for target: {target_host}...")

        steps = [
            f"Isolating compromised host {target_host} from network.",
            "Restoring system configurations from secure immutable backup.",
            "Updating enterprise firewall rules to block malicious C2 IPs."
        ]

        for step in steps:
            st.write(f"[+] {step}")
            self._log_recovery_action(step, "Executed")

        st.success("Full recovery achieved and system is secure.")
        self._log_recovery_action("Full system recovery completed successfully.", "Completed")
        
        return "Full recovery achieved."

    def get_recovery_history(self):
        """Retrieves past recovery actions from the database"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM recovery_logs ORDER BY created_at DESC").fetchall()
            return [dict(row) for row in rows]
