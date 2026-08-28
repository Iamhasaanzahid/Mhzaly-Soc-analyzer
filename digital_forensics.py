import hashlib
import os
from datetime import datetime
import re
import sqlite3
import json

class DigitalForensicsAnalyzer:

    def __init__(self, db_path="soc_forensics.db"):
        self.db_path = db_path
        self._init_db()
        
        # Comprehensive regex patterns for full forensic artifact extraction
        self.patterns = {
            "IPv4 Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Email Address": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
            "MD5 Hash": r"\b[a-fA-F0-9]{32}\b",
            "SHA256 Hash": r"\b[a-fA-F0-9]{64}\b",
            "C2 / Web URL": r"https?://[^\s\"'>]+",
            "Windows File Path": r"[A-Za-z]:\\(?:[A-Za-z0-9_\-\s]+\\)*[A-Za-z0-9_\-\.]+"
        }

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT,
                    source TEXT,
                    description TEXT,
                    handler TEXT,
                    action TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    # --- 1. Evidence Handling & Chain of Custody ---
    def acquire_evidence(self, evidence_id, source, description):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO chain_of_custody (evidence_id, source, description, handler, action, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (evidence_id, source, description, "System Root", "Acquired", timestamp)
            )
            conn.commit()
            
        record = {
            "evidence_id": evidence_id,
            "source": source,
            "description": description,
            "timestamp": timestamp
        }
        return {"status": f"Evidence {evidence_id} acquired successfully from {source}.", "record": record}

    def generate_sha256_hash(self, file_bytes):
        """کسی بھی فائل یا ڈیٹا کا اصلی SHA-256 ہیش جنریٹ کرتا ہے تاکہ انٹیگریٹی ثابت ہو سکے"""
        sha256_val = hashlib.sha256(file_bytes).hexdigest()
        return {"status": "SHA-256 hash generated successfully.", "hash": sha256_val}

    def generate_md5_hash(self, file_bytes):
        """کسی بھی فائل یا ڈیٹا کا اصلی MD5 ہیش جنریٹ کرتا ہے"""
        md5_val = hashlib.md5(file_bytes).hexdigest()
        return {"status": "MD5 hash generated successfully.", "hash": md5_val}

    def verify_evidence_integrity(self, file_bytes, original_hash):
        current_hash = hashlib.sha256(file_bytes).hexdigest()
        if current_hash == original_hash:
            return {"status": "Evidence integrity verified successfully. Hashes match."}
        else:
            return {"status": "WARNING: Hash mismatch! Evidence may have been tampered with."}

    def log_chain_of_custody(self, evidence_id, handler_name, action):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO chain_of_custody (evidence_id, source, description, handler, action, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (evidence_id, "N/A", "Chain update", handler_name, action, timestamp)
            )
            conn.commit()
            
        return {"status": f"Chain of custody updated for {evidence_id} by {handler_name}."}

    # --- 2. Text & Log Artifact Parsing (Deep Multi-Category Extraction) ---
    def parse_text_artifacts(self, raw_text):
        """ٹیکسٹ یا لاگ کے اندر سے آئی پی، ای میل، ہیشز، یو آر ایل اور فائل پاتھس نکالتا ہے"""
        if not raw_text:
            return {"error": "Empty log or dump content provided."}

        artifacts = {}
        total_extracted = 0

        for name, pattern in self.patterns.items():
            matches = list(set(re.findall(pattern, raw_text, re.IGNORECASE)))
            artifacts[name] = matches
            total_extracted += len(matches)

        return {
            "status": "Artifacts successfully extracted from text/logs.",
            "total_artifacts": total_extracted,
            "artifacts": artifacts,
            "ips": artifacts.get("IPv4 Address", []),
            "emails": artifacts.get("Email Address", [])
        }

    # --- 3. Stubs for Advanced Forensics ---
    def parse_windows_registry(self, hive_path):
        return {"status": f"Registry hive ({hive_path}) structure validated (Simulated Parse)."}

    def analyze_browser_history_chrome(self, profile_path):
        return {"status": "Chrome SQLite history parsing interface ready."}

    def generate_forensic_report(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM chain_of_custody").fetchall()
            total_records = len(rows)
            
        return {
            "status": "Comprehensive digital forensics report generated.",
            "total_chain_records": total_records,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
