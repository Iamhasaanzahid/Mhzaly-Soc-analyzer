# digital_forensics.py - Advanced Digital Forensics & Log Artifact Extraction Engine

import hashlib
import os
from datetime import datetime
import re

class DigitalForensicsAnalyzer:

    def __init__(self):
        self.evidence_vault = {}
        self.chain_of_custody = []
        self.timeline_events = []
        
        # Comprehensive regex patterns for full forensic artifact extraction
        self.patterns = {
            "IPv4 Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Email Address": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
            "MD5 Hash": r"\b[a-fA-F0-9]{32}\b",
            "SHA256 Hash": r"\b[a-fA-F0-9]{64}\b",
            "C2 / Web URL": r"https?://[^\s\"'>]+",
            "Windows File Path": r"[A-Za-z]:\\(?:[A-Za-z0-9_\-\s]+\\)*[A-Za-z0-9_\-\.]+"
        }

    # --- 1. Evidence Handling & Chain of Custody ---
    def acquire_evidence(self, evidence_id, source, description):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record = {
            "evidence_id": evidence_id,
            "source": source,
            "description": description,
            "timestamp": timestamp
        }
        self.chain_of_custody.append(record)
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
        entry = {
            "evidence_id": evidence_id,
            "handler": handler_name,
            "action": action,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.chain_of_custody.append(entry)
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
            # Backward compatibility keys for older dashboard calls
            "ips": artifacts.get("IPv4 Address", []),
            "emails": artifacts.get("Email Address", [])
        }

    # --- 3. Stubs for Advanced Forensics ---
    def parse_windows_registry(self, hive_path):
        return {"status": f"Registry hive ({hive_path}) structure validated (Simulated Parse)."}

    def analyze_browser_history_chrome(self, profile_path):
        return {"status": "Chrome SQLite history parsing interface ready."}

    def generate_forensic_report(self):
        return {
            "status": "Comprehensive digital forensics report generated.",
            "total_chain_records": len(self.chain_of_custody),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
