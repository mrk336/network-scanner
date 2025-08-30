# 🛡️ Network Scanner Tool

A Python-powered network scanner that uses Nmap to identify devices, detect operating systems, and uncover known vulnerabilities (CVEs). Built for sysadmins, security enthusiasts, and curious tinkerers who want visibility without the bloat.

## 🚀 Features

- Scan a single host or an entire subnet
- Detect OS and MAC address of each device
- Map MAC addresses to friendly device names via `dev.txt`
- Run Nmap's `vuln` scripts to detect CVEs
- Export results to a clean CSV file

## 📦 Requirements

- Python 3.6+
- [`python-nmap`](https://pypi.org/project/python-nmap/)
- Nmap installed on your system

Install dependencies:

```bash
pip install python-nmap
