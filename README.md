````markdown
# Domain Discovery Tool

## 📌 Overview
**AsyuLynx Domain Discovery** is a Python-based asset exposure analysis tool designed to help security engineers, red teamers, and IT admins identify domain/IP risks.  

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
- Single or bulk mode (scan one or many targets)  
- DNS & WHOIS integration  
- IP/ISP lookup via ip-api.com  
- Critical vs Full port scan options  
- Risk classification (Low / Medium / High)  
- Excel export with risk heatmap coloring  

---

## ⚙️ Installation & Usage

### 1️⃣ Clone and Install
```bash
git clone https://github.com/your-username/asyu-lynx-domain-discovery.git
cd asyu-lynx-domain-discovery
pip install -r requirements.txt
````

### 2️⃣ Run in Single Mode

```bash
python3 domain_discovery.py
```

* Mode: `single`
* Enter: `example.com`
* Scan type: `(1) Critical ports or (2) Full scan`

### 3️⃣ Run in Bulk Mode

Prepare a file `targets.txt`:

```
example.com
8.8.8.8
github.com
```

Then run:

```bash
python3 domain_discovery.py
```

* Mode: `bulk`
* File: `targets.txt`
* Scan type: `1` or `2`

---

## 📂 Output Example

Results are exported as Excel, e.g.:

```
20250909_domain_discovery_x8r9p3.xlsx
```

**Columns:**

* Domain | IP | Registrar | ISP/Org | CNAME | Open Services | HTTP Code | Exposure | Risk Level

Color coding is applied for risk:
🟩 Low | 🟨 Medium | 🟥 High

---

## 🛡️ Disclaimer

This tool is intended **for educational and authorized security testing only**.
Unauthorized scanning of external systems without explicit permission is illegal.

---
