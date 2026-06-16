# Neural Network Intrusion Detection System (IDS)

A production-grade, machine learning-powered Security Operations Center (SOC) with real-time threat detection, automated response, and enterprise SIEM integration.

## 🎯 Project Overview

This project implements a sophisticated intrusion detection system using deep learning to identify and respond to network security threats in real-time. The system achieves **95.61% detection accuracy** across 15 different attack types.

### Key Features

- **🧠 Two-Stage Neural Network Detection**
  - Stage 1: Multi-class classifier (15 attack types)
  - Stage 2: Autoencoder for anomaly detection
  
- **📊 Real-Time Monitoring**
  - Live packet capture and analysis
  - Network flow feature extraction
  - Sub-second detection latency

- **🔔 Multi-Channel Alerting**
  - Console alerts with color coding
  - Wazuh SIEM integration
  - Email notifications (rate-limited)
  - Syslog integration

- **🛡️ Automated Response**
  - Automatic IP blocking for severe threats
  - Configurable severity thresholds
  - Whitelist/blacklist management

- **📈 Threat Intelligence**
  - External threat feed integration
  - IP reputation scoring
  - Alert enrichment with context

## 🏗️ Architecture
┌─────────────────────────────────────────────────────┐
│ Windows 11 Host - Training Environment │
│ ├─ Neural Network Training (PyTorch) │
│ ├─ Dataset: CICIDS2017 (800K samples) │
│ └─ Model Export for Deployment │
└─────────────────────────────────────────────────────┘
↓
┌─────────────────────────────────────────────────────┐
│ Ubuntu VM - Production SIEM (192.168.80.128) │
│ ├─ Neural Network Inference Engine │
│ ├─ Wazuh SIEM (Manager + Indexer + Dashboard) │
│ ├─ Live Traffic Monitor │

## 🚀 Quick Start

### Prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
Installation
Bash

# Clone repository
cd ~/
git clone <repository-url> neural_ids
cd neural_ids

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

Configuration
Bash

# Edit configuration
nano config/ids_config.json

# Update:
# - Network interface
# - Target IP addresses
# - Email settings
# - Threat intelligence sources
Running the System
Bash

# Start live monitoring
sudo venv/bin/python3 live_monitor.py

# Access Wazuh Dashboard
# https://<ubuntu-ip>
# Username: admin
# Password: <from installation>
📧 Email Alert Configuration
The system sends intelligent, rate-limited email alerts:

Rate Limit: Max 5 emails/hour
Cooldown: 15 minutes per attack type
Aggregation: Multiple alerts combined (5-min window)
Severity Filter: Only HIGH and SEVERE threats
Format: Professional HTML + plain text
Gmail Setup
Enable 2-Factor Authentication
Generate App Password: https://myaccount.google.com/apppasswords
Update config/ids_config.json with credentials
🎯 Attack Detection Examples
DDoS Attack
text

============================================================
🚨 NEURAL IDS ALERT - SEVERE
============================================================
Attack Type : DDoS
Confidence  : 99.8%
Severity    : SEVERE
Source IP   : 192.168.80.132
Target IP   : 192.168.80.130
Anomaly     : YES
Threat Intel: IP in threat database (custom_blacklist)
============================================================
🚫 BLOCKED IP: 192.168.80.132 - Reason: DDoS
Port Scan
text

============================================================
🚨 NEURAL IDS ALERT - MEDIUM
============================================================
Attack Type : PortScan
Confidence  : 87.3%
Severity    : MEDIUM
Source IP   : 192.168.80.132
Target IP   : 192.168.80.130
Anomaly     : NO
============================================================
📊 System Statistics
Generate comprehensive report:

Bash

python3 scripts/generate_report.py
Sample output:

text

Total Alerts Generated: 156
Unique Attacker IPs: 3
Anomalies Detected: 45 (28.8%)

Alerts by Severity:
  SEVERE  :   89 (57.1%)
  HIGH    :   42 (26.9%)
  MEDIUM  :   25 (16.0%)

Top Attack Types:
  DoS Slowhttptest    :   67 (42.9%)
  DDoS                :   45 (28.8%)
  PortScan            :   25 (16.0%)
🔒 Security Considerations
Automatic IP Blocking
 Blocks SEVERE threats automatically
 Configurable whitelist
 Temporary blocks (1 hour default)
 Manual unblock available
False Positive Mitigation
 Two-stage detection (classifier + autoencoder)
 Confidence thresholds
 Alert aggregation
 Cooldown periods
📈 Performance Metrics
System Performance
 Training Time: ~10 minutes (800K samples)
 Inference Latency: <100ms per flow
 Memory Usage: ~2GB (with models loaded)
 Throughput: 1000+ flows/second
Detection Accuracy by Attack Type
 Attack Type	Precision	Recall	F1-Score
 DDoS	99.2%	98.7%	98.9%
 DoS Hulk	97.8%	96.5%	97.1%
 PortScan	89.3%	91.2%	90.2%
 SSH-Patator	94.5%	93.1%	93.8% 
🧪 Testing
Generate Test Traffic
Bash

# From Kali VM
# Port Scan
nmap -sS -p 1-1000 192.168.80.130

# DDoS Simulation
sudo hping3 -S --flood -p 80 192.168.80.130

# Brute Force
hydra -L users.txt -P pass.txt ssh://192.168.80.130
📝 Dataset Information
CICIDS2017 Dataset

 Total Samples: 800,000
 Attack Types: 15 categories
 Features: 18 network flow statistics
 Class Distribution:
 Normal: 30.4%
 Attacks: 69.6%
Features Used
 Flow Duration
 Total Fwd/Bwd Packets
 Packet Length Statistics (Mean, Std, Min, Max)
 Flow Bytes/s
 Flow Packets/s
 Inter-Arrival Time (IAT) Statistics 
🤝 Contributing
This is a portfolio project demonstrating SOC capabilities. Suggestions and improvements welcome!

📄 License
Educational/Portfolio Project

👨‍💻 Author
sharvesh


LinkedIn:https://www.linkedin.com/in/sharvesh-swaaminathan/
GitHub: https://github.com/sharvesh830
🙏 Acknowledgments
CICIDS2017 Dataset - Canadian Institute for Cybersecurity
Wazuh - Open Source SIEM Platform
PyTorch - Deep Learning Framework
