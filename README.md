````markdown
# domain-discovery  

## 📌 Overview
**domain-discovery** is a Python-based asset exposure analysis tool designed to help security engineers, red teamers, and IT admins identify domain/IP risks.  

It aligns with **ISO/NIST best practices** for asset discovery and provides:
- DNS resolution (A, AAAA, MX, NS, TXT, CNAME)
- WHOIS registrar lookup
- IP/ISP/Organization lookup
- HTTP(S) status classification (Internet / Intranet / Misconfig / Closed)
- Critical or Full port scanning
- Risk level assessment
- Export results to Excel with color-coded risk levels

---

## 🚀 Features
- 🔍 **Single or bulk mode** → scan a single domain/IP or multiple from a file  
- 🌐 **DNS & WHOIS integration**  
- 🛰️ **IP/ISP info via ip-api.com**  
- 📡 **Critical vs Full Port Scan options**  
- 🛡️ **Risk classification (Low / Medium / High)**  
- 📊 **Excel export with risk heatmap coloring**  

---

## ⚙️ Installation

### Prerequisites
- Python **3.8+**  
- pip installed  

### Clone & Install
```bash
git clone https://github.com/your-username/domain-discovery.git
cd domain-discovery
pip install -r requirements.txt
````

---

## 📖 Usage

### 🔹 Single Mode

```bash
python3 domain_discovery.py
```

Choose:

* Mode: **single**
* Enter: `example.com`
* Scan type: `(1) Critical ports` or `(2) Full scan`

---

### 🔹 Bulk Mode

Create a file `targets.txt` with domains/IPs:

```
example.com
8.8.8.8
github.com
```

Run:

```bash
python3 domain_discovery.py
```

Choose:

* Mode: **bulk**
* File: `targets.txt`
* Scan type: `1` or `2`

---

## 📂 Output

Results are exported to Excel in the current directory.
Example filename:

```
20250909_domain_discovery_ab12cd.xlsx
```

### Columns include:

* Domain
* IP
* Registrar
* ISP/Org
* CNAME
* Open Services
* HTTP Code
* Exposure
* Risk Level

---

## 📊 Example Output (Excel)

| Domain       | IP             | Registrar   | ISP/Org      | HTTP Code | Open Ports | Risk Level |
| ------------ | -------------- | ----------- | ------------ | --------- | ---------- | ---------- |
| example.com  | 93.184.216.34  | Example Inc | Cloudflare   | 200       | 80,443     | Low        |
| testsite.org | 142.250.190.14 | Google LLC  | Google Cloud | 302       | 22,80,443  | Medium     |

---

## 🤝 Contribution

Contributions are welcome!

1. Fork the repo
2. Create a new branch (`feature-xyz`)
3. Commit your changes
4. Push to your fork
5. Submit a Pull Request

---

## 🛡️ Disclaimer

This tool is for **educational and security research purposes only**.
Use it responsibly on domains/IPs you own or have explicit permission to test.

---
