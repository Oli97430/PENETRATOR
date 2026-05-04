<p align="center">
  <img src="assets/logo.svg" alt="PENET．" width="600"/>
</p>

<p align="center">
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/ci.yml/badge.svg"/></a&gt;
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/codeql.yml/badge.svg"/></a&gt;
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/security.yml"><img alt="Security" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/security.yml/badge.svg"/></a&gt;
  <a href="https://github.com/Oli97430/PENETRATOR/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/Oli97430/PENETRATOR?color=ff3860&logo=github"/></a&gt;
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-ff3860?logo=python&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-22d3ee"/>
</p>

<p align="center">
  <a href="#why-penetrator">Why PENETRATOR?</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#installation">Installation</a> &middot;
  <a href="#tech-stack">Tech Stack</a> &middot;
  <a href="#plugins">Plugins</a> &middot;
  <a href="#roadmap">Roadmap</a>
</p>

---

## 🚀 Why PENETRATOR?

Most penetration testing tools demand a Linux environment, complex WSL setups, or heavy VMs. **PENETRATOR breaks those barriers.**

It is a **Windows-native**, high-performance toolkit designed for security professionals and researchers who want power without the overhead. No Kali VM, no broken dependencies—just pure, streamlined capability.

### ✨ Key Advantages
*   **Windows-Native:** Zero reliance on WSL or Linux compatibility layers.
*     **Dual Interface:** Seamlessly switch between a modern **Dark GUI** (CustomTkinter) and a powerful **CLI** (Rich).
*   **Zero Configuration:** Ships as a standalone `.exe`. Just download and run.
*   **Multi-Language:** Support for **EN, FR, ZH, ES, and DE** out of the box.
*   **Session Persistence:** Save your workspace and reload it instantly to continue your audit.

---

## 🛠️ Tech Stack

Built with modern, high-performance Python libraries:
*   **Core:** Python 3.9+
*   **GUI:** `CustomTkTkinter` (Modern, sleek, dark-mode optimized)
*   **CLI:** `Rich` (Beautifully formatted tables, progress bars, and logs)
*   **Engine:** Modular Python-based security modules
*   **Packaging:** `PyInstaller` for standalone Windows execution

---

## 🛡️ Features

With **100+ specialized tools** across **20+ categories**, PENETRATOR covers the full attack lifecycle:

| Category | Capabilities |
| :--- | :--- |
| 🔍 **Recon & OSINT** | Port scanning, DNS, WHOIS, Subdomain enumeration, GitHub Dorking, Email/Phone/Geo lookup. |
| 🌐 **Web Security** | SQLi, XSS, SSRF, XXE, Directory Brute-forcing, WAF detection, WebSocket analysis. |
  | 🔐 **Auth & Crypto** | Password cracking, Hash ID, JWT analysis, RSA analyzer, Certificate Transparency. |
| ☁️ **Cloud & Infra** | S3 Bucket enumeration, Azure Blob, Firebase, LDAP, SMB, Kerberos attacks. |
| ⚡ **Network & Payload**| SMB Relay, LDAP Injection, Reverse/Bind Shell generation, Payload encoding. |
| 🧪 **Automation** | Attack chaining, automated risk correlation, and intelligent reporting. |

---

## 📥 Installation

### 🚀 The Easy Way (Recommended)
Download the latest **`PENETRATOR.exe`** from the [Releases Page](https://github.com/Oli97430/PENETRATOR/releases/latest). 
*No Python or dependencies required.*

### 🛠️ From Source
For developers and researchers wanting to customize the engine:

```bash
# Clone the repository
git clone https://github.com/Oli．97430/PENETRATOR.git
cd PENETRATOR

# Install dependencies
pip install -r requirements.txt

# Launch the GUI
python penetrator.py

# Launch the CLI
python penetrator_cli.py
```

---

## 🧩 Plugin System

Extending PENETRATOR is trivial. Drop any `.py` file into the `plugins/` directory, and it will be automatically loaded and integrated into the UI/CLI.

```python
# Example: plugins/my_scanner.py
PLUGIN_NAME = "Advanced Scanner"
PLUGIN_CATEGORY = "Custom"

def run(args):
    print(f"Scanning target: {args}")
```

---

## 🗺️ Roadmap

- [x] Initial Release (Core Engine + GUI/CLI)
- [ ] Integrated Nmap/Nuclei engine support
- [ ] Real-time vulnerability dashboard
- [ ] Automated Report Generation (PDF/HTML)
- [ ] Enhanced Cloud-native attack modules

---

## ⚖️ Legal & Disclaimer

> **WARNING:** PENETRATOR is an **educational** and **authorized** penetration testing tool. 
> Use it only on systems you own or have explicit, written permission to test. Unauthorized access to computer systems is **illegal**.
> The authors assume **no liability** for any misuse or damage caused by this tool.

**License:** MIT
**Author:** [Tarraw](https://github.com/Oli97430)
