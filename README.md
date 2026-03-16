# 🍯 Advanced Azure Honeypot & Threat Detection System

**Created by Feroz Khan | March 2026**

> A complete SSH/Telnet honeypot built on Microsoft Azure Free Trial — Real attackers. Real incidents. Real threat intelligence. Zero dollars.

---

## 📊 Real Results

| Metric | Value |
|--------|-------|
| Incidents Detected | **597** |
| High Severity | **277** |
| Attack Attempts | **2,110+** |
| Max from 1 IP | **492** |
| Total Cost | **$0** |

---

## 🌐 Live Website

Visit the project website: **[ferozkhan.github.io/azure-honeypot](https://ferozahmadkhan.github.io/advance-azure-siem-honeypot/)**

---

## 🏗️ Architecture

```
Attacker → Azure NSG (port 22/23) → iptables redirect → Cowrie Honeypot
                                                              ↓
                                                    cowrie.json logs
                                                              ↓
                                               Azure Monitor Agent
                                                              ↓
                                            Log Analytics Workspace
                                                              ↓
                                              Microsoft Sentinel SIEM
                                                              ↓
                                           4 KQL Detection Rules → 597 Incidents
```

---

## 🛠️ Tech Stack

- **Cloud**: Microsoft Azure (Free Trial)
- **VM**: Ubuntu 24.04 LTS — Standard B2ats_v2
- **Honeypot**: Cowrie SSH/Telnet
- **SIEM**: Microsoft Sentinel
- **Query Language**: KQL (Kusto Query Language)
- **Framework**: MITRE ATT&CK
- **Networking**: Azure NSG + Linux iptables

---

## 📁 Repository Structure

```
azure-honeypot/
├── index.html              # Main website
├── screenshots/            # Lab evidence screenshots
│   ├── azure_vm.png
│   ├── nsg_rules.png
│   ├── cowrie_logs.png
│   ├── log_analytics_query.png
│   ├── sentinel_analytics_rules.png
│   ├── sentinel_incidents_dashboard.png
│   ├── workbook_dashboard_1.png
│   ├── workbook_dashboard_2.png
│   └── workbook_dashboard_3.png
└── README.md
```

---

## ⚡ Quick Setup

### 1. Deploy VM
```bash
# Azure Portal → Virtual Machines → Create
# Image: Ubuntu 22.04 LTS | Size: B2ats_v2 (free)
```

### 2. Install Cowrie
```bash
sudo adduser --disabled-password cowrie
sudo git clone https://github.com/cowrie/cowrie.git /home/cowrie/cowrie
sudo chown -R cowrie:cowrie /home/cowrie/cowrie
sudo su - cowrie && cd cowrie
python3 -m venv cowrie-env && source cowrie-env/bin/activate
pip install -r requirements.txt
```

### 3. Configure & Start
```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Set [ssh] listen_endpoints = tcp:2222:interface=0.0.0.0
# Set [telnet] enabled = true, listen_endpoints = tcp:2223:interface=0.0.0.0
twistd --pidfile var/run/cowrie.pid -l var/log/cowrie/cowrie.log cowrie
```

### 4. iptables Port Forwarding
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save
```

### 5. KQL Detection Rules (Sentinel)
```kql
// Brute Force Detection
CowrieLogs_CL
| where RawData contains "cowrie.login.failed"
| extend src_ip = extract('"src_ip":"([^"]+)"', 1, RawData)
| summarize FailedAttempts = count() by src_ip, bin(TimeGenerated, 5m)
| where FailedAttempts > 2

// Successful Login Detection
CowrieLogs_CL
| where RawData contains "cowrie.login.success"
| extend src_ip = extract('"src_ip":"([^"]+)"', 1, RawData)
| extend username = extract('"username":"([^"]+)"', 1, RawData)
| extend password = extract('"password":"([^"]+)"', 1, RawData)
| project TimeGenerated, src_ip, username, password
```

---

## 🛡️ MITRE ATT&CK Coverage

| Rule | Severity | Tactic | Technique |
|------|----------|--------|-----------|
| SSH Brute Force Attack | Medium | Credential Access | T1110.001 |
| Successful Login Detected | High | Initial Access | T1078 |
| Command Execution Detected | Medium | Execution | T1059 |
| Malware Download Attempt | High | Command & Control | T1105 |

---

## ⚠️ Important Notes

- **iptables rules** are wiped on reboot — always run `sudo netfilter-persistent save`
- **Sentinel trial** expires after 31 days — set a reminder!
- **Port 4444** is the admin SSH door — never expose your real SSH on port 22 once Cowrie is running
- **Azure Bastion** is your emergency access if you get locked out

---

## 📝 License

This project is for educational purposes only. Use responsibly.

---

*Part 2 of Honeypot Series | Following Windows Honeypot*  
*Created by Feroz Khan — March 2026*
