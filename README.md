
# Enterprise SOC Automation & Analytics Platform

**Author:** Muhammad Hassaan Zahid (MHZALY)  
**Academic Domain:** BS (Hons) Information Systems Technology Management, NCBA&E  

## 🛡️ Project Overview
This repository contains a comprehensive Security Operations Center (SOC) architecture built from the ground up using Python. It is designed to demonstrate the intersection of deep technical security operations and strategic technology management. The platform simulates real-world SOC workflows, moving from reactive log monitoring to proactive threat hunting and automated incident response (SOAR).

## ⚙️ Core Capabilities
* **Centralized Log Management:** Automated ingestion, parsing, and indexing of enterprise logs (Windows, Linux, CloudTrail, Firewalls).
* **Advanced Threat Analysis:** Detection of brute-force attacks, lateral movement, and anomalous behaviors using customized algorithms.
* **Proactive Threat Hunting & CTI:** Integration with Threat Intelligence feeds (MISP, OTX, VirusTotal) and OSINT data for IOC sweeping.
* **SOAR & Incident Response:** Automated containment workflows, ticket generation, and ChatOps (Slack/Teams) integrations to reduce MTTR.
* **Vulnerability & Risk Management:** Tracking high-risk assets, calculating CVSS scores, and mapping compliance reports.
* **Digital Forensics:** Chain of custody logging, memory dump analysis, and disk artifact extraction features.

## 🚀 Installation & Usage
To run the interactive SOC dashboard on your local machine, follow these steps:

1. Ensure Python 3.8+ is installed on your system.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
