<p align="center">
  <img src="assets/logo.svg" alt="PENET．" width="600"/>
</p>

<p align="center">
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/ci.yml/badge.svg"/></a>
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/codeql.yml/badge.svg"/></a>
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/security.yml"><img alt="Security" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/security.yml/badge.svg"/></a>
  <a href="https://github.com/Oli97430/PENETRATOR/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/Oli97430/PENETRATOR?color=ff3860&logo=github"/></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-ff3860?logo=python&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-22d3ee"/>
</p>

<p align="center">
  <a href="#why-penetrator">Why PENETRATOR?</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#installation">Installation</a> &middot;
  <a href="#rest-api">REST API</a> &middot;
  <a href="#docker">Docker</a> &middot;
  <a href="#plugins">Plugins</a> &middot;
  <a href="#roadmap">Roadmap</a>
</p>

---

## Why PENETRATOR?

Most penetration testing tools demand a Linux environment, complex WSL setups, or heavy VMs. **PENETRATOR breaks those barriers.**

It is a **Windows-native**, high-performance toolkit designed for security professionals and researchers who want power without the overhead. No Kali VM, no broken dependencies -- just pure, streamlined capability.

### Key Advantages
*   **Windows-Native:** Zero reliance on WSL or Linux compatibility layers.
*   **Triple Interface:** Modern **Dark GUI** (CustomTkinter), powerful **CLI** (Rich), and **REST API** (FastAPI) for headless/CI pipelines.
*   **Zero Configuration:** Ships as a standalone `.exe`. Just download and run.
*   **Multi-Language:** Support for **EN, FR, ZH, ES, and DE** out of the box.
*   **Session Persistence:** Save your workspace and reload it instantly to continue your audit.
*   **SQLite Findings DB:** Persistent storage of findings, sessions, and scope rules.

---

## Tech Stack

Built with modern, high-performance Python libraries:
*   **Core:** Python 3.9+
*   **GUI:** `CustomTkinter` (Modern, sleek, dark-mode optimized)
*   **CLI:** `Rich` (Beautifully formatted tables, progress bars, and logs)
*   **API:** `FastAPI` + `Uvicorn` (async REST API with OpenAPI docs)
*   **Database:** SQLite (WAL mode, parameterized queries)
*   **Engine:** 125+ modular pure-Python security functions
*   **Packaging:** `PyInstaller` for standalone Windows execution

---

## Features

With **125+ specialized tools** across **22 categories**, PENETRATOR covers the full attack lifecycle:

| Category | Capabilities |
| :--- | :--- |
| **Recon & OSINT** | Port scanning (sync + async), DNS, WHOIS, Subdomain enumeration, GitHub Dorking, Email/Phone/Geo lookup, Certificate Transparency monitoring. |
| **Web Security** | SQLi, XSS, SSRF, XXE, LFI, CRLF injection, SSTI (10 template engines), Directory Brute-forcing, WAF detection, Open redirect, HTTP smuggling, Prototype pollution. |
| **Auth & Crypto** | Password cracking, Hash ID, JWT decode/brute/none-attack/key-confusion, RSA analyzer, Cookie audit, CSRF analyzer, OAuth2 redirect tester. |
| **Cloud & Infra** | S3 Bucket enum, Azure Blob, Firebase, LDAP, SMB, Kerberos, SNMP walk, DNS rebinding, Virtual host discovery. |
| **Network & Payload** | TCP/UDP/IPv6 scanning, Banner grabbing, TLS analysis, Reverse/Bind shell generation, Payload encoding (8 formats), WebSocket fuzzing. |
| **Automation** | Attack chaining, scan profiles (quick/standard/deep), auto risk correlation, CVSS v3.1 calculator, executive reporting. |
| **Defense & Compliance** | Honeypot detection, YARA scanning, PCI-DSS checks, CIS benchmarks, Log analysis, Baseline comparison. |
| **Reporting** | SARIF v2.1.0 export, Burp Suite export, executive reports, scope management. |

---

## Installation

### The Easy Way (Recommended)
Download the latest **`PENETRATOR.exe`** from the [Releases Page](https://github.com/Oli97430/PENETRATOR/releases/latest).
*No Python or dependencies required.*

### From Source
For developers and researchers wanting to customize the engine:

```bash
# Clone the repository
git clone https://github.com/Oli97430/PENETRATOR.git
cd PENETRATOR

# Install dependencies
pip install -r requirements.txt

# Launch the GUI
python penetrator.py

# Launch the CLI
python penetrator_cli.py

# Launch the REST API
uvicorn penetrator_api:app --host 0.0.0.0 --port 8000
```

---

## REST API

PENETRATOR includes a headless REST API for CI/CD pipelines, automation, and remote scanning.

### Quick Start

```bash
# Set an API key (defaults to 'changeme' -- always override in production)
export PENETRATOR_API_KEY="your-secret-key"

# Start the server
uvicorn penetrator_api:app --host 0.0.0.0 --port 8000

# Interactive docs at http://localhost:8000/docs
```

### Authentication

All endpoints (except `/health`) require the `X-Api-Key` header:

```bash
curl -X POST http://localhost:8000/scan/ports \
  -H "X-Api-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "ports_str": "1-1024"}'
```

### Key Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| GET | `/health` | Health check (no auth) |
| POST | `/scan/ports` | TCP port scan |
| POST | `/scan/subdomains` | Subdomain enumeration |
| POST | `/scan/headers` | Security header analysis |
| POST | `/scan/cors` | CORS misconfiguration test |
| POST | `/scan/sqli` | SQL injection detection |
| POST | `/scan/xss-probe` | Reflected XSS scanner |
| POST | `/scan/csrf` | CSRF token analyzer |
| POST | `/scan/ssti` | SSTI scanner |
| POST | `/scan/cookie-audit` | Cookie security audit |
| POST | `/jwt/decode` | JWT token decoder |
| POST | `/jwt/none-attack` | JWT none-algorithm attack |
| POST | `/jwt/key-confusion` | JWT key confusion attack |
| POST | `/tools/cvss` | CVSS v3.1 score calculator |
| POST | `/tools/attack-chain` | Automated attack chain |
| POST | `/tools/executive-report` | Generate executive report |
| POST | `/scan/sqli-async` | Async SQL injection (aiohttp) |
| POST | `/scan/xss-async` | Async reflected XSS (aiohttp) |
| POST | `/scan/cors-async` | Async CORS test (aiohttp) |
| POST | `/scan/open-redirect-async` | Async open-redirect test (aiohttp) |
| POST | `/report/sarif` | SARIF v2.1.0 export |
| POST | `/profile/run` | Run a scan profile |

See the full API documentation at `http://localhost:8000/docs` (Swagger UI).

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PENETRATOR_API_KEY` | `changeme` | API authentication key |
| `PENETRATOR_DB_PATH` | `data/penetrator.db` | SQLite database file path |
| `PENETRATOR_RATE_LIMIT` | `60` | Max requests per minute per IP |

---

## Docker

### Quick Start

```bash
# Build and run
docker compose up -d

# Or with a custom API key
PENETRATOR_API_KEY=my-secret docker compose up -d

# Check health
curl http://localhost:8000/health
```

### docker-compose.yml

```yaml
services:
  penetrator:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      PENETRATOR_API_KEY: "${PENETRATOR_API_KEY:-changeme}"
    restart: unless-stopped
```

The container runs as a non-root user with a health check. The `data/` volume persists the SQLite database and SARIF reports.

---

## Plugin System

Extending PENETRATOR is trivial. Drop any `.py` file into the `plugins/` directory, and it will be automatically loaded and integrated into the GUI.

```python
# Example: plugins/my_scanner.py
PLUGIN_NAME = "My Custom Scanner"
PLUGIN_CATEGORY = "web_attacks"

FIELDS = [
    {"key": "url", "label": "Target URL", "type": "entry"},
    {"key": "depth", "label": "Scan depth", "type": "entry", "default": "3"},
]

def run(values: dict, log) -> dict:
    """Called by the engine with form values and a log callback."""
    url = values.get("url", "")
    log(f"[*] Scanning {url}...", "cyan")
    # Your scanning logic here
    return {"status": "complete", "findings": []}
```

---

## Roadmap

- [x] Initial Release (Core Engine + GUI/CLI)
- [x] Integrated Nmap/Nuclei engine support
- [x] Automated Report Generation (SARIF, executive reports)
- [x] REST API with FastAPI
- [x] Docker containerization
- [x] CVSS v3.1 calculator
- [x] JWT attack tools (none-algorithm, key confusion)
- [x] SQLite persistence layer
- [ ] Real-time vulnerability dashboard
- [ ] Enhanced async scanning engine
- [ ] WebSocket-based live scan streaming
- [ ] Collaborative multi-user sessions

---

## Legal & Disclaimer

> **WARNING:** PENETRATOR is an **educational** and **authorized** penetration testing tool.
> Use it only on systems you own or have explicit, written permission to test. Unauthorized access to computer systems is **illegal**.
> The authors assume **no liability** for any misuse or damage caused by this tool.

**License:** MIT
**Author:** [Tarraw](https://github.com/Oli97430)
