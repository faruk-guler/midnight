# 🌌 Midnight Intelligence Dashboard

**Midnight (v2.2 Elite)** is a high-performance Cyber Threat Intelligence (CTI) dashboard designed to aggregate, analyze, and visualize real-time vulnerability data from multiple high-fidelity sources.

![Midnight Intelligence](https://img.shields.io/badge/Status-Active-brightgreen)
![Python](https://img.shields.io/badge/Backend-Python_3.9+-blue)
![Frontend](https://img.shields.io/badge/Frontend-Vanilla_JS_/_CSS-orange)

## 🚀 Key Features

- **Massive Parallel Aggregation:** Simultaneously fetches data from NVD, CISA KEV, Exploit-DB, GitHub Security Advisories, ZDI, Google Project Zero, and CERT/CC.
- **Midnight Threat Score (MTS):** A proprietary scoring algorithm (0-100) that factors in CVSS scores, EPSS (Exploit Prediction Scoring System) probability, active exploitation status, and vulnerability freshness.
- **Real-time Synchronization:** Built-in continuous execution mode that refreshes data every hour.
- **AI-Powered Analysis:** Frontend logic that generates instant technical briefings and remediation steps for every vulnerability.
- **Ultra-Fast Performance:** Optimized with parallel pagination and connection pooling to handle thousands of records in seconds.

## 🛠 Tech Stack

- **Backend:** Python (Requests, Concurrent.futures, XML/CSV parsing)
- **Frontend:** HTML5, CSS3 (Glassmorphism UI), Vanilla JavaScript
- **Icons:** Phosphor Icons

## 📡 Intelligence Sources

| Source | Type | Information Provided |
| :--- | :--- | :--- |
| **NVD (NIST)** | API v2.0 | Official CVE database, CVSS scores, and technical descriptions. |
| **CISA KEV** | JSON Feed | Catalog of actively exploited vulnerabilities (Known Exploited). |
| **Exploit-DB** | CSV Feed | Available public exploit codes and attack types. |
| **GitHub / OSV** | API | Security advisories belonging to the open-source ecosystem (GHSA). |
| **EPSS (FIRST)** | API | Probability of vulnerabilities being exploited within the next 30 days. |
| **ZDI** | RSS | Zero-day advisories published by the Zero Day Initiative. |
| **Google Project Zero** | RSS | Critical vulnerabilities discovered by Google's security team. |
| **CERT-CC** | RSS | Technical reports regarding software vulnerabilities and vendor advisories. |
| **TR-CERT** | REST API | Cybersecurity Directorate of Turkey (former USOM). USOM was transferred to the Directorate by Law No. 7545 (March 2025); old RSS/txt feeds ended on June 1, 2026. |

## ⚙️ Setup & Installation

### 1. Prerequisites
- Python 3.9 or higher
- An internet connection

### 2. Environment Variables (Optional)
To increase NVD API speed, obtain an API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) and set it:
```powershell
$env:NVD_API_KEY = "your-api-key-here"
```

### 3. Run the Dashboard
Open a terminal in the project directory and run:

```powershell
# 1. Start the data synchronizer
py fetch_cves.py

# 2. Start the web server (in another terminal or background)
py -m http.server 8000
```

Access the dashboard at: `http://localhost:8000`

## 🧠 Scoring Logic (MTS)

The **Midnight Threat Score (MTS)** is calculated as follows:
- **CVSS Impact (40%):** Weighted base score.
- **Exploitation Probability (30%):** Based on EPSS scores.
- **Active Exploitation (15%):** Bonus if listed in CISA KEV or Exploit-DB.
- **Freshness (15%):** Bonus for vulnerabilities discovered in the last 1-7 days.

## 📄 License
This project is for professional threat intelligence monitoring and security research purposes.
