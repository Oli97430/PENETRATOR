<p align="center">
  <img src="assets/logo.svg" alt="PENETRATOR" width="960"/>
</p>

<p align="center">
  <strong>The modern Windows-native penetration testing toolkit.</strong><br/>
  <em>102 tools &middot; 22 categories &middot; 5 languages &middot; GUI + CLI</em>
</p>

<p align="center">
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/ci.yml/badge.svg"/></a>
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/codeql.yml/badge.svg"/></a>
  <a href="https://github.com/Oli97430/PENETRATOR/actions/workflows/security.yml"><img alt="Security" src="https://github.com/Oli97430/PENETRATOR/actions/workflows/security.yml/badge.svg"/></a>
  <a href="https://codecov.io/gh/Oli97430/PENETRATOR"><img alt="codecov" src="https://codecov.io/gh/Oli97430/PENETRATOR/branch/main/graph/badge.svg"/></a>
  <a href="https://github.com/Oli97430/PENETRATOR/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/Oli97430/PENETRATOR?color=ff3860&logo=github"/></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-ff3860?logo=python&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-22d3ee"/>
</p>

<p align="center">
  <a href="#installation">Install</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#plugins">Plugins</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

## What is PENETRATOR?

A complete, Windows-first Python 3 penetration testing toolkit -- **no WSL, no Kali VM, no half-broken ports.** Ships as a standalone `PENETRATOR.exe` or runs from source.

- **Modern dark GUI** built on CustomTkinter with Ctrl+P command launcher
- **Classic CLI** powered by Rich tables and prompts
- **5 languages** switchable live: EN / FR / ZH / ES / DE
- **Auto-updater** keeps you on the latest release
- **Workspace save/load** to persist sessions across restarts

---

## Features

| | Category | Highlights |
|---|---|---|
| 1 | **Information Gathering** | Port scan, DNS, WHOIS, subdomains, banners, TLS, Wayback, UDP, IPv6, AXFR, SNMP, ARP |
| 2 | **Wordlist Generator** | CUPP, combinator, leet mutations, charset patterns |
| 3 | **SQL Injection** | Detection, payload library |
| 4 | **Web Attacks** | Dir buster, CORS, WAF detect, HTTP smuggling, SSRF, XXE, CRLF, race conditions, WebSocket, LFI |
| 5 | **API Security** | Swagger discovery, broken auth, mass assignment, rate-limit testing |
| 6 | **Password Tools** | Hash ID, cracker, strength meter, generator, HIBP lookup, JWT analysis |
| 7 | **Crypto & TLS** | Cipher grader, RSA analyzer, Certificate Transparency monitor |
| 8 | **Cloud & Infrastructure** | S3 bucket enum, Azure blob, Git exposure, Firebase, LDAP, SMB, Kerberos |
| 9 | **Network Attacks** | LDAP injection, SMB relay, Kerberos attacks |
| 10 | **Steganography** | PNG LSB hide/extract, whitespace hide/extract |
| 11 | **XSS Tools** | Reflected scanner, polyglot payloads, WAF bypass |
| 12 | **Reverse Engineering** | Strings extractor, PE parser, hex dump |
| 13 | **Forensic** | File hashes, EXIF reader, magic bytes, binary diff |
| 14 | **Payload Generator** | Reverse/bind shells, encoder, msfvenom wrapper |
| 15 | **OSINT** | Email, geo, username, phone, GitHub dorking, paste monitor, domain reputation |
| 16 | **Automation & Intelligence** | Attack chains, risk correlator, smart payloads, executive reports |
| 17 | **Stealth & Evasion** | Proxy rotation, UA rotation, throttling, WAF bypass |
| 18 | **Integrations** | Nmap import, Nuclei, Burp export, Metasploit RPC, Shodan |
| 19 | **Email & Phishing Defense** | SPF/DKIM/DMARC validation, header analysis, homoglyph detection, phishing URL scanner |
| 20 | **Mobile & IoT** | APK analysis, MQTT fuzzing, firmware strings, UPnP discovery |
| 21 | **Blue Team** | Honeypot detection, log analysis, YARA rules, security baselines |
| 22 | **Compliance** | OWASP Top 10 mapper, PCI-DSS checks, CIS benchmarks |

---

## Installation

### Standalone executable (recommended)

Download `PENETRATOR.exe` from the [latest release](https://github.com/Oli97430/PENETRATOR/releases/latest) -- no Python required.

### From source

```bash
git clone https://github.com/Oli97430/PENETRATOR.git
cd PENETRATOR
pip install -r requirements.txt
```

---

## Quick Start

### GUI (CustomTkinter dark theme)

```bash
python penetrator.py
```

Or double-click `PENETRATOR.exe`. Use **Ctrl+P** to open the command launcher and jump to any tool instantly.

### CLI (Rich-powered)

```bash
python penetrator_cli.py
```

Both interfaces wrap the same engine -- results are identical.

---

## Plugins

Drop any `.py` file into the `plugins/` directory. PENETRATOR auto-discovers and loads it on startup. A minimal plugin:

```python
# plugins/my_tool.py
PLUGIN_NAME = "My Custom Tool"
PLUGIN_CATEGORY = "Custom"

def run(args):
    """Entry point called by PENETRATOR."""
    print(f"Running with: {args}")
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-tool`)
3. Commit your changes
4. Open a Pull Request

Please run the test suite before submitting:

```bash
pytest tests/
```

---

## Legal

> PENETRATOR is an **educational**, **authorized pentest**, and **CTF/lab** tool.
> Using it against systems you do not own or lack written authorization to test is **illegal** in most jurisdictions.
> The authors accept **no liability** for misuse.

---

## License

MIT License

**Author** -- Tarraw &middot; [Tarraw974@gmail.com](mailto:Tarraw974@gmail.com)
