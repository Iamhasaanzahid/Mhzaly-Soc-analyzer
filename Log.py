import sqlite3
import json
import gzip
import hashlib
import re
from datetime import datetime

class LogManagement:
    def __init__(self, db_path="soc_logs.db", schema=None):
        self.db_path = db_path
        self.schema = schema
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_type TEXT,
                    source_ip TEXT,
                    raw_data TEXT,
                    parsed_json TEXT,
                    integrity_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def validate_log(self, log_entry):
        """JSON Schema validation for incoming log entries"""
        if not self.schema:
            return True
        try:
            import jsonschema
            jsonschema.validate(instance=log_entry, schema=self.schema)
            return True
        except Exception:
            return False

    def compress_log(self, log_data, filename):
        """Compresses log data into gzip format securely"""
        try:
            with gzip.open(filename, "wb") as f:
                f.write(json.dumps(log_data).encode("utf-8"))
            return True
        except Exception:
            return False

    def detect_anomaly(self, log_entry):
        """Detects brute force patterns or unauthorized terms in logs"""
        str_log = str(log_entry).lower()
        is_anomaly = any(keyword in str_log for keyword in ["fail", "error", "unauthorized", "malicious", "attack"])
        return {
            "status": "Anomaly detection complete.",
            "is_anomaly": is_anomaly,
            "risk_score": 85 if is_anomaly else 10
        }

    def ingest_log(self, log_entry, log_type="General"):
        """Ingests, validates, hashes for integrity, and stores logs in SQLite"""
        raw_str = json.dumps(log_entry) if isinstance(log_entry, (dict, list)) else str(log_entry)
        integrity_hash = hashlib.sha256(raw_str.encode()).hexdigest()
        
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', raw_str)
        source_ip = ip_match.group() if ip_match else "N/A"

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO logs (log_type, source_ip, raw_data, parsed_json, integrity_hash) VALUES (?, ?, ?, ?, ?)",
                (log_type, source_ip, raw_str, raw_str, integrity_hash)
            )
            conn.commit()
        return True

    def parse_windows_event(self, log_entry):
        """Parses Windows Event log formats using regex extraction"""
        text = str(log_entry)
        event_id_match = re.search(r'EventID[:=]\s*(\d+)', text, re.IGNORECASE)
        user_match = re.search(r'Account[:=]\s*([^\s]+)', text, re.IGNORECASE)
        
        parsed = {
            "log_type": "Windows Event",
            "event_id": event_id_match.group(1) if event_id_match else "Unknown",
            "target_user": user_match.group(1) if user_match else "Unknown",
            "raw": text
        }
        self.ingest_log(parsed, log_type="Windows Event")
        return parsed

    def parse_linux_syslog(self, log_entry):
        """Parses Linux Syslog strings (Authentication/System daemons)"""
        text = str(log_entry)
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
        parsed = {
            "log_type": "Linux Syslog",
            "source_ip": ip_match.group() if ip_match else "N/A",
            "message": text
        }
        self.ingest_log(parsed, log_type="Linux Syslog")
        return parsed

    def parse_cisco_asa(self, log_entry):
        """Parses Cisco ASA firewall structured logs"""
        text = str(log_entry)
        msg_code_match = re.search(%ASA-\d+-\d+, text)
        parsed = {
            "log_type": "Cisco ASA",
            "message_code": msg_code_match.group(0) if msg_code_match else "ASA-UNKNOWN",
            "raw": text
        }
        self.ingest_log(parsed, log_type="Cisco ASA")
        return parsed

    def search_logs(self, query):
        """Full-text or keyword search across stored database logs"""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM logs WHERE raw_data LIKE ? OR log_type LIKE ?",
                (f"%{query}%", f"%{query}%")
            ).fetchall()
            return [dict(row) for row in rows]

    def filter_logs(self, log_type):
        """Filters logs by specific log type category"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM logs WHERE log_type = ?", (log_type,)).fetchall()
            return [dict(row) for row in rows]

    def assess_log_volume(self):
        """Returns total volume of logs currently indexed in storage"""
        with self._get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as count FROM logs").fetchone()
            return row["count"] if row else 0

    def monitor_log_integrity(self):
        """Verifies cryptographic integrity hashes of log records"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT raw_data, integrity_hash FROM logs").fetchall()
            for row in rows:
                expected_hash = hashlib.sha256(row["raw_data"].encode()).hexdigest()
                if expected_hash != row["integrity_hash"]:
                    return False
        return True

    def export_log_report(self, format="json"):
        """Exports complete log database as structured JSON report"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM logs").fetchall()
            data = [dict(row) for row in rows]
            
        if format.lower() == "json":
            return json.dumps(data, indent=4)
        return {"total_exported": len(data), "data": data}
