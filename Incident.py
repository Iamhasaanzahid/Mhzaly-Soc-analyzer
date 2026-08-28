import sqlite3
from datetime import datetime

class IncidentResponse:
    def __init__(self, db_path="soc_incidents.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'Open',
                    assignee TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def log_incident(self, incident_id, severity, description):
        with self._get_connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO incidents (id, severity, description, status, notes) VALUES (?, ?, ?, ?, ?)",
                    (incident_id, severity, description, "Open", "")
                )
                conn.commit()
                return {"status": "Success", "message": f"Incident {incident_id} logged successfully."}
            except sqlite3.IntegrityError:
                return {"status": "Error", "message": f"Incident ID {incident_id} already exists."}

    def update_status(self, incident_id, new_status):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    def assign_to_analyst(self, incident_id, analyst_name):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE incidents SET assignee = ? WHERE id = ?", (analyst_name, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_incident(self, incident_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            return dict(row) if row else None

    def add_note(self, incident_id, note):
        inc = self.get_incident(incident_id)
        if inc:
            current_notes = inc.get("notes", "") or ""
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_notes = f"{current_notes}\n[{timestamp}] {note}".strip()
            with self._get_connection() as conn:
                conn.execute("UPDATE incidents SET notes = ? WHERE id = ?", (updated_notes, incident_id))
                conn.commit()
            return True
        return False

    def close_incident(self, incident_id):
        return self.update_status(incident_id, "Closed")

    def escalate_incident(self, incident_id):
        return self.update_status(incident_id, "Escalated")

    def reopen_incident(self, incident_id):
        return self.update_status(incident_id, "Reopened")

    def get_open_incidents(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM incidents WHERE status = 'Open'").fetchall()
            return [dict(row) for row in rows]

    def get_incidents_by_severity(self, severity):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM incidents WHERE severity = ?", (severity,)).fetchall()
            return [dict(row) for row in rows]

    def delete_incident(self, incident_id):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_incident_log(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM incidents")
            conn.commit()

    def get_incident_count(self):
        with self._get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as count FROM incidents").fetchone()
            return row["count"] if row else 0

    def incident_exists(self, incident_id):
        return self.get_incident(incident_id) is not None

    def search_incidents(self, keyword):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM incidents WHERE description LIKE ?", (f"%{keyword}%",)).fetchall()
            return [dict(row) for row in rows]

    def list_all_assignees(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT DISTINCT assignee FROM incidents WHERE assignee IS NOT NULL").fetchall()
            return [row["assignee"] for row in rows]

    def count_by_status(self, status):
        with self._get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as count FROM incidents WHERE status = ?", (status,)).fetchone()
            return row["count"] if row else 0

    def update_severity(self, incident_id, new_severity):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE incidents SET severity = ? WHERE id = ?", (new_severity, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    def export_incidents(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM incidents").fetchall()
            return [dict(row) for row in rows]

    def get_latest_incident(self):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def get_oldest_incident(self):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM incidents ORDER BY created_at ASC LIMIT 1").fetchone()
            return dict(row) if row else None

    def get_incidents_by_assignee(self, analyst_name):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM incidents WHERE assignee = ?", (analyst_name,)).fetchall()
            return [dict(row) for row in rows]

    def get_unique_severities(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT DISTINCT severity FROM incidents").fetchall()
            return [row["severity"] for row in rows]

    def get_critical_incidents(self):
        return self.get_incidents_by_severity("Critical")

    def get_closed_incidents(self):
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM incidents WHERE status = 'Closed'").fetchall()
            return [dict(row) for row in rows]
