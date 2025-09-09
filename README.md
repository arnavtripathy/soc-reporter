# SOC Reporter

SOC Reporter is a Django-based dashboard for security analysts to quickly investigate suspicious indicators such as IP addresses, domains, and URLs.  
It integrates with **AbuseIPDB** and **VirusTotal** to fetch OSINT data and generate a consolidated HTML report that can be copied directly into analyst notes or incident reports.

---

## ✨ Features
- 🔎 **IP Analysis** via [AbuseIPDB](https://www.abuseipdb.com)  
- 🌐 **Domain Analysis** via [VirusTotal](https://www.virustotal.com)  
- 🔗 **URL Analysis** via VirusTotal  
- 📑 **Consolidated Report View** with copy/paste friendly tables (Word-ready)  
- 🛡️ Defangs URLs/domains for safe reporting  

---

## ⚙️ Installation

Clone the repo:

```bash
git clone https://github.com/arnavtripathy/soc-reporter.git
cd soc-reporter
```
Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

pip install -r requirements.txt
```

## 🔑 API Keys

This project requires API keys for:

- AbuseIPDB
- VirusTotal

Add them to a settings.json file like shown below:

```json
{
'ABUSEIPDB_API_KEY' : 'xxxxx',
'VIRUSTOTAL_API_KEY' : 'xxxx'
}
```

## 🚀 Usage

Run the Django server:

```bash
python manage.py runserver
```

Open http://127.0.0.1:8000/soc/dynamic-form/ in your browser.
Enter indicators (IP, domain, or URL) and generate the consolidated report. You can add whatever fields you want. Once written you can copy paste into your SOC reports.

## 🛠️ Roadmap

- Add hash (MD5/SHA256) scanning via VirusTotal
- Export reports as PDF/Docx directly
- Analyst authentication and case management

