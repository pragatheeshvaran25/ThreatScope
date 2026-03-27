# 🛡️ ThreatScope

Cyber Risk Assessment & Threat Intelligence Dashboard

---

## 👥 Developed By
- Pragatheeshvaran R 
- PraveenKumar V

---

## 📌 Project Overview
ThreatScope is a cybersecurity dashboard that scans network targets using Nmap and analyzes risks using VirusTotal threat intelligence. It helps identify vulnerabilities, assign risk scores, and provide actionable security recommendations.

---

## 🧠 Technologies Used
- Python
- Streamlit (Dashboard)
- Nmap (Network Scanning)
- VirusTotal API (Threat Intelligence)
- SQLite (Database)
- Plotly (Visualization)

---

## 🧩 Project Modules

### 🔍 Scanner Module (`scanner.py`)
- Performs Nmap scan
- Extracts open ports and services
- Integrates VirusTotal API

### 📊 Analyser Module (`analyser.py`)
- Calculates:
  - Exposure Score
  - Threat Score
  - Context Score
- Generates final Risk Score & Severity

### 💾 Database Module (`database.py`)
- Stores scan results
- Maintains scan history

### 📧 Email Module (`emailer.py`)
- Sends alerts for High/Critical risks

### 🖥️ Dashboard (`Streamlit`)
- Displays insights, charts, and reports
- Multi-page interface (Analysis, Data, History)

---

## 📊 Features
- Multi-target scanning
- Risk scoring system
- Severity classification (Critical, High, Medium, Low)
- Interactive dashboard
- Email alerts
- Scan history tracking
- CSV export

---

## 📁 Project Structure
ThreatScope/
│
├── dashboard/
├── modules/
├── scan_results/
├── requirements.txt
├── license.txt
├── README.md
---

## ⚙️ How to Run

### 1. Install Python dependencies
pip install -r requirements.txt

### 2. Install Nmap (Required)
Download from: https://nmap.org/download.html

### 3. Run the dashboard
streamlit run dashboard/app.py

---

## 🔐 Security Note
Sensitive data such as API keys and passwords are stored in `.env` file and excluded using `.gitignore`.

---

## 🌐 Target Information
This project scans public IPs or domains (e.g., scanme.nmap.org) for educational purposes.

---

## 🚀 Future Improvements
- Add authentication system
- Use ML for risk prediction
- Deploy on cloud

---

## 📄 License
MIT License
