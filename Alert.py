class AlertManagement:
    def __init__(self):
        self.alerts = []

    def add_alert(self, severity, message):
        self.alerts.append({"severity": severity, "message": message})
        print(f"Alert added: {severity} - {message}")

    def remove_alert(self, message):
        self.alerts = [alert for alert in self.alerts if alert['message'] != message]
        print(f"Alert removed with message: {message}")

    def clear_all_alerts(self):
        self.alerts = []
        print("All alerts cleared.")

    def update_alert_severity(self, message, new_severity):
        for alert in self.alerts:
            if alert['message'] == message:
                alert['severity'] = new_severity
                print(f"Severity updated for alert: '{message}' to {new_severity}")
                break

    def filter_by_severity(self, severity):
        return [alert for alert in self.alerts if alert['severity'] == severity]

    def get_alert_summary(self):
        summary = {"high": 0, "medium": 0, "low": 0}
        for alert in self.alerts:
            severity = alert['severity']
            if severity in summary:
                summary[severity] += 1
        return summary

    def manage_alerts(self, threat_level):
        print("Alerts manage kiye ja rahay hain.")
        has_high_severity = any(alert['severity'] == "high" for alert in self.alerts)
        has_low_severity = any(alert['severity'] == "low" for alert in self.alerts)

        if threat_level == "critical" or has_high_severity:
            return "Trigger immediate alert"
        elif has_low_severity:
            return "Log as low priority"
        return "Log as informational"

    def get_all_alerts(self):
        return self.alerts

    def get_alert_count(self):
        return len(self.alerts)

    def has_alert(self, message):
        return any(alert['message'] == message for alert in self.alerts)

    def search_alerts_by_keyword(self, keyword):
        return [alert for alert in self.alerts if keyword in alert['message']]

    def export_alerts(self):
        return [f"{alert['severity']}: {alert['message']}" for alert in self.alerts]

    def get_latest_alert(self):
        return self.alerts[-1] if self.alerts else None

    def get_oldest_alert(self):
        return self.alerts[0] if self.alerts else None

    def remove_alerts_by_severity(self, severity):
        self.alerts = [alert for alert in self.alerts if alert['severity'] != severity]
        print(f"All {severity} severity alerts removed.")

    def get_unique_severities(self):
        return list(set(alert['severity'] for alert in self.alerts))

    def reverse_alerts(self):
        self.alerts.reverse()
        print("Alert order reversed.")

    def get_alerts_by_severity_range(self, start, end):
        return self.alerts[start:end]

    def get_high_severity_alerts(self):
        return [alert for alert in self.alerts if alert['severity'] == "high"]

    def get_medium_severity_alerts(self):
        return [alert for alert in self.alerts if alert['severity'] == "medium"]

    def get_low_severity_alerts(self):
        return [alert for alert in self.alerts if alert['severity'] == "low"]

    def alerts_exist(self):
        return len(self.alerts) > 0

    def duplicate_alert(self, message):
        for alert in self.alerts:
            if alert['message'] == message:
                self.add_alert(alert['severity'], f"Copy of: {alert['message']}")
                break

    def get_unique_messages(self):
        return list(set(alert['message'] for alert in self.alerts))

    def remove_alerts_with_keyword(self, keyword):
        self.alerts = [alert for alert in self.alerts if keyword not in alert['message']]
        print(f"Alerts containing '{keyword}' removed.")
