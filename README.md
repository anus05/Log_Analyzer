# 🛡️ Python Log Analyzer & Suspicious Activity Detector

## 📌 Project Overview
This project is a **Python-based Log Analyzer tool** that reads a web server access log file (`access.log`) and detects suspicious activities such as:

- Brute Force login attempts
- Directory scanning attempts
- High traffic / bot-like activity

It also generates a detailed report (`security_report.txt`) containing the summary of log analysis.

---

## 🎯 Features
✅ Reads log file line by line  
✅ Extracts important fields (IP, method, URL, status code)  
✅ Counts total requests  
✅ Finds Top 5 IP addresses generating most requests  
✅ Finds Top 5 attacked/visited URLs  
✅ Detects suspicious IP activities:
- **Brute Force Attack Detection** (multiple 403 errors)
- **Scanning Detection** (multiple 404 errors)
- **High Traffic Detection** (possible bot/DDoS behavior)

✅ Generates output report automatically

---

## 🧠 Cybersecurity Use Cases
This tool can be used in:

- SOC (Security Operations Center) monitoring
- Incident response investigations
- Server security auditing
- Brute force and reconnaissance detection
- Website traffic and suspicious behavior monitoring

---

## 📂 Project Structure
