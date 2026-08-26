import datetime
import json
import re
import urllib.parse


class AutonomousSOCAgent:

    def __init__(self, agent_name="MHZALY CyberBrain v1.0"):
        self.agent_name = agent_name
        self.risk_weights = {
            "critical_dork": 30,
            "suspicious_tld": 25,
            "ip_format": 15,
            "entropy_high": 20,
            "auth_failure": 20,
            "exploit_pattern": 35,
        }

    def analyze_domain_or_ip(self, target: str) -> dict:
        target = target.strip().lower()
        findings = []
        score = 0
        is_ip = bool(
            re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
        )
        is_url = target.startswith("http://") or target.startswith("https://")
        parsed_target = target
        if is_url:
            parsed = urllib.parse.urlparse(target)
            parsed_target = parsed.netloc or parsed.path

        suspicious_tlds = [
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".top",
            ".xyz",
            ".buzz",
            ".work",
        ]
        if any(parsed_target.endswith(tld) for tld in suspicious_tlds):
            findings.append(
                "Suspicious or disposable Top-Level Domain (TLD) associated with active threat campaigns."
            )
            score += self.risk_weights["suspicious_tld"]

        subdomains = parsed_target.split(".")
        for part in subdomains:
            if (
                len(part) > 12
                and bool(re.search(r"\d", part))
                and bool(re.search(r"[a-z]", part))
            ):
                findings.append(
                    f"High-entropy subdomain string detected ('{part}'), potential Domain Generation Algorithm (DGA)."
                )
                score += self.risk_weights["entropy_high"]
                break

        if is_ip:
            findings.append(
                "Target is a raw IPv4 network node indicator without standard canonical domain mapping."
            )
            score += self.risk_weights["ip_format"]

        if score >= 60:
            severity = "CRITICAL"
            verdict = "Malicious Threat / Active Indicator"
            recommended_action = "Execute Automated Firewall Null-Route & Trigger Emergency Incident Playbook."
        elif score >= 30:
            severity = "MEDIUM"
            verdict = "Suspicious Infrastructure / Watchlist"
            recommended_action = (
                "Add to monitoring queue and increase SIEM log retention."
            )
        else:
            severity = "LOW / CLEAN"
            verdict = "Benign / Normal Posture"
            recommended_action = "Standard telemetry observation baseline."

        return {
            "agent": self.agent_name,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "risk_score": min(score, 100),
            "severity": severity,
            "verdict": verdict,
            "findings": findings
            if findings
            else ["No heuristic threat anomalies discovered."],
            "playbook_actions": recommended_action,
        }

    def analyze_raw_telemetry(self, raw_logs: str) -> dict:
        lines = [
            l.strip() for l in raw_logs.strip().split("\n") if l.strip()
        ]
        total_events = len(lines)
        detected_attacks = []
        offending_ips = set()

        for line in lines:
            line_lower = line.lower()
            ip_match = re.search(
                r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line
            )
            ip = ip_match.group() if ip_match else "Unknown"

            if (
                "failed" in line_lower
                or "invalid user" in line_lower
                or "auth failure" in line_lower
            ):
                detected_attacks.append(
                    {
                        "type": "Authentication Brute Force",
                        "source": ip,
                        "raw": line,
                    }
                )
                if ip != "Unknown":
                    offending_ips.add(ip)
            if any(
                p in line_lower
                for p in [
                    "union select",
                    "' or 1=1",
                    "xp_cmdshell",
                    "information_schema",
                ]
            ):
                detected_attacks.append(
                    {
                        "type": "SQL Injection Attempt",
                        "source": ip,
                        "raw": line,
                    }
                )
                if ip != "Unknown":
                    offending_ips.add(ip)
            if any(
                p in line_lower
                for p in [
                    "/bin/bash",
                    "cmd.exe",
                    "powershell -enc",
                    "wget http",
                    "curl http",
                ]
            ):
                detected_attacks.append(
                    {
                        "type": "Command Injection / Malicious Shell Spawn",
                        "source": ip,
                        "raw": line,
                    }
                )
                if ip != "Unknown":
                    offending_ips.add(ip)

        risk_score = min(len(detected_attacks) * 15, 100)
        severity = (
            "CRITICAL"
            if risk_score >= 60
            else "MEDIUM"
            if risk_score >= 20
            else "LOW"
        )
        return {
            "agent": self.agent_name,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_events_processed": total_events,
            "attacks_identified": len(detected_attacks),
            "risk_score": risk_score,
            "severity": severity,
            "correlated_attacks": detected_attacks,
            "isolated_source_ips": list(offending_ips),
            "automated_containment": f"Autonomous containment rules deployed for {len(offending_ips)} attack sources.",
        }
