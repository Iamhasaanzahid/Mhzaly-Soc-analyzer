# 🛡️ Enterprise SOC Automation & Analytics Platform (MHZALY-SOC)

**Author:** Muhammad Hassaan Zahid  
**Academic Domain:** BS (Hons) Information Systems Technology Management, NCBA&E  
**Status:** Production Ready / Active Development  

---

## 🔍 Project Overview

This repository contains a comprehensive, modular Security Operations Center (SOC) architecture built from the ground up using Python and Streamlit. It is designed to demonstrate the intersection of deep technical security operations, threat intelligence feeds, digital forensics, and strategic incident response automation (SOAR). The platform simulates real-world SOC workflows, seamlessly bridging the gap between reactive log monitoring, proactive threat hunting, and automated mitigation.

---

## 🛠️ Core Capabilities & Architecture

* Centralized Log Management & SIEM: Automated ingestion, parsing, and indexing of enterprise logs (Windows security logs, Sysmon, Linux auth, and CloudTrail).
* Advanced Threat Analysis & Detection: Custom algorithms to catch brute-force attacks, lateral movement, SQL Injection (SQLi), XSS, and anomalous user behaviors.
* Proactive Threat Hunting & CTI: Integration with global Threat Intelligence feeds (VirusTotal API, OSINT, and IOC sweeping for PowerShell obfuscation).
* SOAR & Incident Response: Automated containment workflows, incident ticket generation, severity grading, and risk exception tracking to reduce MTTR.
* Vulnerability & Risk Management: Tracking high-risk assets, calculating CVSS v3.1 scores, mapping CISA KEV catalogs, and automated remediation assignments.
* Digital Forensics & Artifacts: Evidence parsing, hash verification, chain of custody logging, and file artifact extraction features.

---

## 📂 Project Repository Structure

Mhzaly-Soc-analyzer/
│
├── main_dashboard.py            # Main Streamlit Enterprise UI Command Center
├── threat_intel.py              # VirusTotal & Deep Bug Bounty / Header Scanner
├── threat_hunting.py            # IOC Sweeping & PowerShell Obfuscation Detection
├── digital_forensics.py         # Log Parsing & Evidence Artifact Extraction
├── incident_response.py         # Incident Ticket Lifecycle & Severity Management
├── soar_automation.py           # Automated Playbooks & Containment Workflows
├── vulnerability_management.py  # CVSS Scoring, CISA KEV, & Remediation Tracking
├── analyzer.py                  # Core Attack Detector (SQLi, XSS, Risk Scoring)
├── monitoring.py                # Proactive Health Auditing & System Monitoring
├── intelligence.py              # MITRE ATT&CK Mapping & Threat Intelligence Feeds
├── requirements.txt             # Project Dependencies
└── README.md                    # Documentation

---

## 🚀 Installation & Local Deployment Instructions

To run the interactive SOC dashboard on your local machine, execute these terminal commands in order:

1. Clone the repository: git clone https://github.com/lamhasaanzahid/Mhzaly-Soc-analyzer.git
2. Navigate to folder: cd Mhzaly-Soc-analyzer
3. Install dependencies: pip install -r requirements.txt
4. Run dashboard: streamlit run main_dashboard.py

---

## 💡 Tech Stack & Tools

* Core Language: Python 3.11+
* Dashboard Framework: Streamlit
* Data Processing & Analytics: Pandas, JSON, Regex
* Security Standards: CVSS v3.1, MITRE ATT&CK Framework, CISA KEV, VirusTotal API

---

## 📄 License & Academic Note
Developed as an advanced enterprise security automation project under Information Systems Technology Management standards. Feel free to reference or contribute!
