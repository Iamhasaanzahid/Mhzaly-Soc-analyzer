# otx_threat_intel.py - AlienVault OTX Threat Intelligence Integration
import requests

class OTXThreatIntel:
    def __init__(self):
        # OTX ki public API free hai, iske liye complex keys ki zaroorat nahi parti
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"

    def check_indicator(self, indicator_type, query):
        try:
            if indicator_type == "IP":
                url = f"{self.base_url}/ip/{query}/general"
            elif indicator_type == "Domain":
                url = f"{self.base_url}/domain/{query}/general"
            else:
                return {"error": "Invalid indicator type selected."}

            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                count = pulse_info.get("count", 0)
                
                return {
                    "query": query,
                    "threat_pulse_count": count,
                    "references": pulse_info.get("references", []),
                    "status": "Success"
                }
            else:
                return {"error": f"API returned status code {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
