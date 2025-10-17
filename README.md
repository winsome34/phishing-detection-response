# 🛡️ Phishing Attack Detection & Response (SOC Analyst Project)

## 📘 Overview
This project simulates a real-world phishing attack detection and response scenario using **Splunk** and open-source datasets.  
It demonstrates how SOC Analysts investigate, detect, and respond to phishing-based compromises.

## 🎯 Objectives
1. Understand how phishing campaigns operate.
2. Use Splunk to analyze event logs and detect malicious activity.
3. Apply incident response steps to contain and report threats.

## 🧰 Tools & Resources
- [Splunk Free Version](https://www.splunk.com/en_us/download.html)
- [PhishTank](https://phishtank.org)
- [VirusTotal](https://www.virustotal.com)
- [URLScan.io](https://urlscan.io)
- [Splunk BOTSv3 Dataset](https://github.com/splunk/botsv3)

## 🔍 Data Sources
- Email logs (sender, subject, attachments)
- DNS logs (malicious domain lookups)
- Windows Event Logs (login attempts, PowerShell usage)
- HTTP logs (credential exfiltration)

## 🧪 Implementation Steps
1. Download and extract the **BOTSv3 dataset**.
2. Ingest data into **Splunk** via “Add Data.”
3. Run SPL queries to identify suspicious patterns.
4. Investigate findings and document results.
5. Produce a detection & incident response report.

## 💻 Sample SPL Queries
```spl
index=botsv3 sourcetype="stream:http" method=POST
| search uri_path="*/login*" AND http_user_agent="*Mozilla*"
| stats count by src_ip, dest_ip, uri_path
