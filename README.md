# Splunk Threat Detection

A practical security monitoring solution leveraging **Splunk Enterprise**, **MITRE ATT&CK framework**, and **SOAR automation**, designed to simulate a functional Security Operations Center (SOC).

## 🔍 Project Highlights

- 📊 **Log Ingestion & CIM Normalization** from web apps and simulated attacker activity
- 🎯 **MITRE ATT&CK-aligned detections** (T1110, T1078, T1583.006)
- 🤖 **SOAR Playbook integration** for automated responses
- 🌐 **Geolocation & Asset Tagging** using lookups and IP enrichment
- 🔐 **RBAC & Index Lifecycle** configuration

## ⚙️ Setup

1. Install Splunk Enterprise on:
   - Windows Server (Azure VM)
   - macOS (for testing and flexibility)

2. Deploy **Splunk Universal Forwarder** on local systems
3. Ingest data (e.g., BufferCup Games logs)

## 📂 MITRE-Aligned Detection Queries

- **Brute Force**: `T1110 - Credential Access`
- **Privilege Escalation**: `T1078 - Valid Accounts`
- **Financial Theft**: `T1583.006 - Impact`

Each detection includes:
- Raw SPL query
- MITRE tactic/technique mapping
- Enhancements like anomaly baselining, IP filtering

## 🧠 Enhancements

- **CIM Normalization** using field aliases & calculated fields
- **SOAR** playbooks for automated triage & alerts
- **Machine Learning Toolkit (MLTK)** for user baselining
- **Trusted IP filtering** to reduce false positives

## 📝 Sample Queries

```spl
index=main sourcetype="secure-2" "Failed password"
| rex "Failed password for (?<user>\\S+) from (?<src_ip>\\d+.\\d+.\\d+.\\d+)"
| stats count by src_ip, user
| where count > 5
| eval tactic="Credential Access", technique="T1110 - Brute Force"
