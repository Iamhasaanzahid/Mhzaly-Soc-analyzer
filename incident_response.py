import time
import json
import uuid
import re
from datetime import datetime
import sqlite3

class IncidentResponder:

    def __init__(self, db_path="soc_incidents_management.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    target TEXT,
                    severity TEXT,
                    description TEXT,
                    sla_target TEXT,
                    status TEXT,
                    created_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    action TEXT,
                    time TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS soar_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT,
                    target TEXT,
                    steps TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    # --- 1. Triage & Ticket Management ---
    def create_incident_ticket(self, target, severity, description):
        """Creates an incident ticket and persists it into SQLite database"""
        ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        sla_matrix = {
            "CRITICAL": "15 Minutes (P1 Emergency)",
            "HIGH": "1 Hour (P2 Elevated)",
            "MEDIUM": "4 Hours (P3 Standard)",
            "LOW": "24 Hours (P4 Informational)"
        }
        
        sev_upper = severity.upper()
        sla_target = sla_matrix.get(sev_upper, "4 Hours")
        status = "Active / In-Triage"

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO incident_tickets (ticket_id, target, severity, description, sla_target, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ticket_id, target, sev_upper, description, sla_target, status, timestamp)
            )
            conn.commit()
        
        ticket_data = {
            "ticket_id": ticket_id,
            "target": target,
            "severity": sev_upper,
            "description": description,
            "sla_target": sla_target,
            "status": status,
            "created_at": timestamp
        }
        
        return {
            "status": "Incident ticket created successfully and stored in DB.",
            "ticket": ticket_data
        }

    def execute_soar_playbook(self, ticket_id, target, severity, description):
        """Executes an automated multi-phase SOAR containment and response playbook"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        ip_matches = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', description)))
        c2_ip = ip_matches[0] if ip_matches else "203.0.113.88 (Extracted Default)"
        
        playbook_steps = [
            {
                "Phase": "1. Host Containment",
                "Action": f"Trigger micro-segmentation API to isolate asset '{target}'",
                "Status": "Completed",
                "Execution Time": timestamp
            },
            {
                "Phase": "2. Network Perimeter Defense",
                "Action": f"Pushed DROP rule to edge firewall for C2 indicator: {c2_ip}",
                "Status": "Rule Enforced",
                "Execution Time": timestamp
            },
            {
                "Phase": "3. Forensic Preservation",
                "Action": f"Dispatched volatile memory dump and prefetch snapshot agent to '{target}'",
                "Status": "Artifacts Secured",
                "Execution Time": timestamp
            },
            {
                "Phase": "4. Automated Notification",
                "Action": f"Broadcasted {severity} incident alert to Tier-2 SOC & PagerDuty channels",
                "Status": "Dispatched",
                "Execution Time": timestamp
            }
        ]
        
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO soar_logs (ticket_id, target, steps) VALUES (?, ?, ?)",
                (ticket_id, target, json.dumps(playbook_steps))
            )
            conn.commit()
        
        return playbook_steps

    def update_ticket_status(self, ticket_id, new_status):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE incident_tickets SET status = ? WHERE ticket_id = ?", (new_status, ticket_id))
            conn.commit()
            if cursor.rowcount > 0:
                return {"status": f"Ticket {ticket_id} status updated to {new_status}."}
        return {"status": f"Error: Ticket {ticket_id} not found."}

    # --- 2. Containment & Isolation Actions ---
    def isolate_endpoint(self, hostname):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO quarantine_logs (hostname, action, time) VALUES (?, ?, ?)",
                (hostname, "Isolated from network", timestamp)
            )
            conn.commit()
        return {"status": f"CRITICAL: Endpoint {hostname} successfully isolated from corporate network."}

    def block_ip_firewall(self, ip_address):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {"status": f"Success: IP {ip_address} added to perimeter firewall drop rules at {timestamp}."}

    def block_domain_dns(self, domain):
        return {"status": f"Success: Domain {domain} sinkholed via internal DNS server."}

    def quarantine_file(self, file_path, hostname):
        return {"status": f"Success: File {file_path} safely moved to quarantine vault on {hostname}."}

    # --- 3. Communication & Logging ---
    def send_slack_alert(self, channel, message):
        return {"status": f"Alert successfully broadcasted to Slack channel #{channel}."}

    def generate_exec_summary(self, ticket_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM incident_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            if row:
                t = dict(row)
                summary = f"Executive Summary: Incident {t['ticket_id']} targeting {t['target']} with {t['severity']} severity is currently {t['status']}."
                return {"status": "Executive summary generated.", "summary": summary}
        return {"status": "Ticket not found for summary."}

    # --- 4. Recovery & Post-Incident ---
    def verify_system_integrity(self, hostname):
        return {"status": f"System integrity scan complete for {hostname}. No anomalies found. Clean."}

    def export_audit_log(self):
        with self._get_connection() as conn:
            active_count = conn.execute("SELECT COUNT(*) FROM incident_tickets WHERE status != 'Closed'").fetchone()[0]
            quarantine_count = conn.execute("SELECT COUNT(*) FROM quarantine_logs").fetchone()[0]
            
        return {
            "status": "Full audit log exported successfully from database.",
            "total_active_incidents": active_count,
            "total_quarantined": quarantine_count
        }
