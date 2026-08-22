class AlertManagement:

    def manage_alerts(self, threat_level):
        print("Alerts manage kiye ja rahay hain.")
        if threat_level == "critical":
            return "Trigger immediate alert"
        return "Log as informational"
