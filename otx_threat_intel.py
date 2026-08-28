# otx_threat_intel.py - Advanced AlienVault OTX Threat Intelligence Integration
import requests

class OTXThreatIntel:
    def __init__(self):
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"

    def check_indicator(self, indicator_type, query, api_key=""):
        try:
            if indicator_type == "IP":
                endpoint = f"ip/{query}/general"
            elif indicator_type == "Domain":
                endpoint = f"domain/{query}/general"
            else:
                return {"error": "Invalid indicator type selected."}

            url = f"{self.base_url}/{endpoint}"
            
            # --- Setup Authentication Headers ---
            headers = {}
            if api_key and api_key.strip():
                headers["X-OTX-API-KEY"] = api_key.strip()

            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                count = pulse_info.get("count", 0)
                pulses = pulse_info.get("pulses", [])
                
                # Extract rich details from pulses for professional SOC analytics
                detailed_pulses = []
                for p in pulses:
                    detailed_pulses.append({
                        "Pulse Name": p.get("name", "Unknown Campaign"),
                        "Author": p.get("author_name", "Anonymous"),
                        "Created": p.get("created", "")[:10],
                        "Description": p.get("description", "No description provided.")[:150] + "...",
                        "Tags": ", ".join(p.get("tags", []))
                    })

                return {
                    "query": query,
                    "threat_pulse_count": count,
                    "country": data.get("country_name", "N/A"),
                    "asn": data.get("asn", "N/A"),
                    "malware_families": data.get("malware_families", []),
                    "detailed_pulses": detailed_pulses,
                    "references": pulse_info.get("references", []),
                    "status": "Success"
                }
            elif response.status_code == 401:
                return {"error": "Authentication Failed: Invalid OTX API Key provided in sidebar."}
            else:
                return {"error": f"OTX API returned status code {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
            
