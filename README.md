# 🔒 SOC Level 2 Advanced Dashboard

## 🎯 Overview
Professional SOC L2 Dashboard with **Active Directory Lab Simulation**, **SIEM Integration**, and **AI-Powered Threat Detection**.

## 🔥 Features

### Active Directory Lab Simulation
- Virtual Domain Controller (corp.local)
- Simulated users, groups, computers
- Real-time AD security events (Event IDs: 4624, 4625, 4768, 4769, etc.)
- Kerberos authentication monitoring

### Attack Simulation
- **Brute Force RDP** detection
- **Mimikatz LSASS Dump** detection
- **Kerberoasting** detection
- **DCSync Attack** detection
- **Lateral Movement** (PsExec) detection
- **MITRE ATT&CK** framework mapping

### AI-Powered Detection
- Isolation Forest anomaly detection
- Statistical Z-score analysis
- Behavioral learning
- Real-time threat scoring

### SIEM Integration
- Splunk HTTP Event Collector (HEC)
- Event forwarding
- Custom sourcetype

## 📋 Prerequisites

```bash
pip install -r requirements.txt
```

## 🚀 Running

```bash
python soc_advanced.py
```

Browser opens automatically at: http://127.0.0.1:5000

## 🏢 AD Lab Simulation

The dashboard simulates:
- Domain: `corp.local`
- DC: `DC01.corp.local`
- Users: administrator, john.doe, jane.smith, svc_sql, backup_admin
- Groups: Domain Admins, Enterprise Admins, SQL Admins, Backup Operators
- Computers: WS01, WS02, SRV01, SRV02

### Simulated Events:
- Successful/Failed logons
- Kerberos TGT/TGS requests
- Account changes
- Group modifications
- Directory service changes

## 🎯 Attack Scenarios

Click **"LAUNCH ATTACK SIMULATION"** to trigger:

1. **Reconnaissance** → **Initial Access** → **Execution**
2. **Persistence** → **Privilege Escalation** → **Lateral Movement**
3. **Collection** → **Exfiltration**

Each attack shows:
- Timeline of actions
- MITRE ATT&CK tactics
- Detection status (Detected/Blocked/Allowed)
- IOCs and indicators

## 📊 Dashboard Sections

| Section | Description |
|---------|-------------|
| Dashboard | Main overview, metrics, alerts |
| AD Lab | Domain info, users, computers, groups |
| Attack Sim | Trigger attacks, view timeline |
| Monitoring | FIM, Process, Network status |
| Threat Intel | MITRE ATT&CK mapped threats |
| Network | Topology visualization |
| Event Logs | Security events table |
| AI Analysis | Anomaly detection metrics |
| Config | System settings |

## 🔨 Building .EXE

```bash
pip install pyinstaller
pyinstaller --onefile --name SOC_L2_Advanced --hidden-import=flask --hidden-import=flask_socketio --hidden-import=requests --hidden-import=numpy --hidden-import=psutil --hidden-import=sklearn --hidden-import=sklearn.ensemble --hidden-import=sklearn.preprocessing --hidden-import=win32evtlog --hidden-import=win32evtlogutil --add-data "templates;templates" soc_advanced.py
```

## 📊 Splunk Setup

1. Enable HEC in Splunk
2. Create token
3. Edit `soc_config.ini`:
```ini
[splunk]
host = your-splunk-server
port = 8088
token = your-token
index = security
```

## 🎓 For SOC/IR Role

This project demonstrates:
- ✅ AD & SIEM understanding
- ✅ MITRE ATT&CK knowledge
- ✅ Threat detection capabilities
- ✅ Log analysis skills
- ✅ Incident response workflow

## 👨‍💻 Author
SOC Level 2 Incident Response Team
