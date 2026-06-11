from gui.engine._core import *

# 21. MQTT Tester
# ---------------------------------------------------------------------------
def mqtt_test(broker: str, port: int, log: Logger) -> dict:
    """Connect to an MQTT broker and test for open access."""
    port = port or 1883
    log(f"[*] MQTT test: {broker}:{port}", "cyan")
    results: dict = {"broker": broker, "port": port, "anonymous": False, "topics": []}

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log("[-] paho-mqtt not installed. Run: pip install paho-mqtt", "err")
        # Fallback: basic TCP check
        import socket as _socket
        try:
            sock = _socket.create_connection((broker, port), timeout=5)
            sock.close()
            log(f"[+] Port {port} is open (MQTT likely available)", "info")
            log("  Install paho-mqtt for full testing", "warn")
        except OSError as exc:
            log(f"[-] Connection failed: {exc}", "err")
        return results

    messages: list[str] = []
    connected = False

    def on_connect(client, userdata, flags, rc):
        """Handle MQTT connection result."""
        nonlocal connected
        if rc == 0:
            connected = True
            log("[+] Anonymous connection SUCCESSFUL!", "err")
            results["anonymous"] = True
            client.subscribe("#", 0)  # Subscribe to ALL topics
        else:
            log(f"[-] Connection refused (rc={rc})", "ok")

    def on_message(client, userdata, msg):
        """Log received MQTT messages and track topics."""
        topic = msg.topic
        payload = msg.payload.decode("utf-8", errors="replace")[:200]
        messages.append(f"{topic}: {payload}")
        if len(messages) <= 20:
            log(f"  [{topic}] {payload[:80]}", "info")
        results["topics"].append(topic)

    try:
        # paho-mqtt 2.x requires CallbackAPIVersion; fall back for 1.x
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
        except (AttributeError, TypeError):
            client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect(broker, port, keepalive=10)
        client.loop_start()
        # Wait up to 5 seconds, checking for cancellation
        for _ in range(50):
            if _should_stop():
                break
            time.sleep(0.1)
        client.loop_stop()
        client.disconnect()
    except Exception as exc:
        log(f"[-] {exc}", "err")

    if messages:
        log(f"[!] Received {len(messages)} message(s) — broker is open!", "err")
    return results


# ---------------------------------------------------------------------------
# 22. Firmware String Extractor
# ---------------------------------------------------------------------------
def firmware_strings(file_path: str, min_length: int, log: Logger) -> dict:
    """Extract interesting strings from a firmware/binary file."""
    log(f"[*] Firmware string extraction: {file_path}", "cyan")
    min_length = max(4, min(20, min_length or 6))
    results: dict = {"total": 0, "credentials": [], "urls": [], "keys": [], "emails": []}

    path = Path(file_path)
    if not path.is_file():
        log("[-] File not found", "err")
        return results

    MAX_SIZE = 100 * 1024 * 1024  # 100 MB safety cap
    if path.stat().st_size > MAX_SIZE:
        log(f"[-] File too large ({path.stat().st_size // (1024*1024)} MB). Max {MAX_SIZE // (1024*1024)} MB", "err")
        return results

    try:
        data = path.read_bytes()
    except OSError as exc:
        log(f"[-] {exc}", "err")
        return results

    # Extract ASCII strings
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    strings = [m.group().decode("ascii") for m in pattern.finditer(data)]
    results["total"] = len(strings)
    log(f"  Total strings: {len(strings)}", "info")

    # Categorize
    for s in strings:
        if _should_stop():
            break
        s_lower = s.lower()
        if any(k in s_lower for k in ("password", "passwd", "secret", "token", "api_key", "apikey")):
            results["credentials"].append(s)
        elif re.match(r"https?://", s):
            results["urls"].append(s)
        elif re.match(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s):
            results["emails"].append(s)
        elif any(k in s for k in ("BEGIN RSA", "BEGIN PRIVATE", "BEGIN CERTIFICATE", "ssh-rsa")):
            results["keys"].append(s[:100])

    if results["credentials"]:
        log(f"  [!] Credentials/secrets: {len(results['credentials'])}", "err")
        for c in results["credentials"][:10]:
            log(f"    {c[:80]}", "err")
    if results["urls"]:
        log(f"  URLs: {len(results['urls'])}", "info")
        for u in results["urls"][:10]:
            log(f"    {u[:100]}", "info")
    if results["emails"]:
        log(f"  Emails: {len(results['emails'])}", "warn")
    if results["keys"]:
        log(f"  [!] Keys/certs: {len(results['keys'])}", "err")

    return results


# ---------------------------------------------------------------------------
# 23. UPnP/SSDP Scanner
# ---------------------------------------------------------------------------
def upnp_scan(log: Logger) -> list[dict]:
    """Discover UPnP devices on the local network via SSDP."""
    import socket as _socket
    log("[*] UPnP/SSDP discovery scan", "cyan")
    devices: list[dict] = []

    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "Host:239.255.255.250:1900\r\n"
        "ST:ssdp:all\r\n"
        "MX:3\r\n"
        "Man:\"ssdp:discover\"\r\n"
        "\r\n"
    ).encode()

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_UDP)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
        sock.sendto(ssdp_request, ("239.255.255.250", 1900))

        seen: set[str] = set()
        while not _should_stop():
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                location = ""
                server = ""
                for line in text.splitlines():
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                key = f"{addr[0]}:{location}"
                if key not in seen:
                    seen.add(key)
                    devices.append({"ip": addr[0], "port": addr[1],
                                    "location": location, "server": server})
                    log(f"[+] {addr[0]}:{addr[1]} — {server or 'unknown'}", "ok")
                    if location:
                        log(f"    Location: {location}", "info")
            except _socket.timeout:
                break
    except OSError as exc:
        log(f"[-] {exc}", "err")
    finally:
        if sock:
            sock.close()

    log(f"[*] {len(devices)} UPnP device(s) found", "cyan")
    return devices


# ---------------------------------------------------------------------------
# 24. Honeypot Detector
# ---------------------------------------------------------------------------
HONEYPOT_SIGNATURES = [
    ("Kippo", ["SSH-2.0-OpenSSH_5.1p1 Debian"]),
    ("Cowrie", ["SSH-2.0-OpenSSH_6.0p1 Debian"]),
    ("Dionaea", ["Microsoft Windows", "IIS/6.0"]),
    ("Glastopf", ["Apache/2.0", "PHP/5.1"]),
    ("Conpot", ["Siemens", "S7comm"]),
    ("HoneyD", ["Linux 2.4", "FreeBSD 4.3"]),
]


def honeypot_detect(host: str, ports: list[int], log: Logger) -> dict:
    """Detect if a target is likely a honeypot."""
    import socket as _socket
    log(f"[*] Honeypot detection: {host}", "cyan")
    results: dict = {"host": host, "indicators": [], "score": 0, "likely_honeypot": False}

    if not ports:
        ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]

    # Indicator 1: Too many open ports
    open_count = 0
    banners: list[str] = []
    for port in ports:
        if _should_stop():
            break
        try:
            sock = _socket.create_connection((host, port), timeout=2)
            open_count += 1
            sock.settimeout(3)
            try:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                banners.append(banner)
            except Exception as exc:
                log(f"  [-] {exc}", "muted")
            sock.close()
        except OSError:
            pass

    if open_count == len(ports):
        results["score"] += 30
        results["indicators"].append(f"ALL {len(ports)} tested ports are open")
        log(f"[!] All {len(ports)} ports open — suspicious!", "warn")

    # Indicator 2: Known honeypot banners
    for banner in banners:
        for hp_name, sigs in HONEYPOT_SIGNATURES:
            for sig in sigs:
                if sig.lower() in banner.lower():
                    results["score"] += 25
                    results["indicators"].append(f"Banner matches {hp_name}: {banner[:60]}")
                    log(f"[!] Banner matches {hp_name} honeypot", "warn")

    # Indicator 3: Response too fast on all ports
    # (honeypots often respond instantly)

    # Indicator 4: Default/generic banners
    generic_count = sum(1 for b in banners if len(b) < 10 or "welcome" in b.lower())
    if generic_count > 3:
        results["score"] += 15
        results["indicators"].append(f"{generic_count} generic/empty banners")

    results["likely_honeypot"] = results["score"] >= 40
    tag = "err" if results["likely_honeypot"] else "ok"
    log(f"  Honeypot score: {results['score']}/100", tag)
    if results["likely_honeypot"]:
        log("[!] Target is LIKELY a honeypot — proceed with caution", "err")
    else:
        log("[+] No strong honeypot indicators", "ok")
    return results


# ---------------------------------------------------------------------------
# 25. Log Analyzer
# ---------------------------------------------------------------------------
LOG_ATTACK_PATTERNS = [
    (r"(?:union|select|insert|update|delete|drop)\s", "SQL Injection attempt"),
    (r"<script|javascript:|onerror=|onload=", "XSS attempt"),
    (r"\.\./|\.\.\\|%2e%2e", "Path traversal"),
    (r"(?:cmd|powershell|bash|/bin/sh)", "Command injection"),
    (r"(?:admin|root|administrator).*(?:login|auth)", "Brute force attempt"),
    (r"(?:phpinfo|phpmyadmin|wp-admin|.env|.git)", "Sensitive path probe"),
    (r"(?:curl|wget|python-requests|nikto|sqlmap|nmap)", "Scanner/tool signature"),
    (r"(?:403|401|404).*(?:403|401|404)", "Error-based enumeration"),
]


def log_analyze(log_text: str, log: Logger) -> dict:
    """Analyze web server logs for attack patterns."""
    log("[*] Log analysis", "cyan")
    results: dict = {"total_lines": 0, "attacks": {}, "top_ips": {}, "summary": []}
    lines = log_text.splitlines()
    results["total_lines"] = len(lines)
    log(f"  Lines to analyze: {len(lines)}", "info")

    attack_counts: dict[str, int] = {}
    ip_counts: dict[str, int] = {}

    for line in lines:
        if _should_stop():
            break
        # Extract IP (first match)
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            ip = ip_match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Check attack patterns
        for pattern, name in LOG_ATTACK_PATTERNS:
            if re.search(pattern, line, re.I):
                attack_counts[name] = attack_counts.get(name, 0) + 1

    results["attacks"] = attack_counts
    results["top_ips"] = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10])

    if attack_counts:
        log("\n  Attack patterns detected:", "warn")
        for name, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            log(f"    {name}: {count} occurrence(s)", "err")
    else:
        log("  No attack patterns detected", "ok")

    if ip_counts:
        log("\n  Top source IPs:", "info")
        for ip, count in list(results["top_ips"].items())[:5]:
            log(f"    {ip}: {count} requests", "info")

    return results


# ---------------------------------------------------------------------------
# 26. YARA Rule Scanner
# ---------------------------------------------------------------------------
def yara_scan(file_path: str, rules_path: str, log: Logger) -> list[dict]:
    """Scan a file with YARA rules."""
    log(f"[*] YARA scan: {file_path}", "cyan")

    try:
        import yara
    except ImportError:
        log("[-] yara-python not installed. Run: pip install yara-python", "err")
        return []

    try:
        if Path(rules_path).is_file():
            rules = yara.compile(filepath=rules_path)
        elif Path(rules_path).is_dir():
            rule_files = {f.stem: str(f) for f in Path(rules_path).glob("*.yar")}
            rules = yara.compile(filepaths=rule_files)
        else:
            log(f"[-] Rules path not found: {rules_path}", "err")
            return []
    except yara.SyntaxError as exc:
        log(f"[-] YARA syntax error: {exc}", "err")
        return []

    matches: list[dict] = []
    try:
        results = rules.match(file_path)
        for match in results:
            log(f"[+] MATCH: {match.rule} (tags: {', '.join(match.tags) or 'none'})", "err")
            # yara-python >= 4.x uses StringMatchInstance objects; < 4.x uses tuples
            str_info: list = []
            for s in match.strings[:5]:
                try:
                    # yara-python 4.x: s.identifier, s.instances[0].offset, s.instances[0].matched_data
                    ident = getattr(s, "identifier", None) or (s[1] if isinstance(s, tuple) else str(s))
                    if hasattr(s, "instances") and s.instances:
                        inst = s.instances[0]
                        str_info.append((getattr(inst, "offset", 0), ident,
                                         bytes(getattr(inst, "matched_data", b""))[:50]))
                    elif isinstance(s, tuple):
                        str_info.append((s[0], s[1], s[2][:50]))
                    else:
                        str_info.append((0, str(s), b""))
                except Exception:
                    str_info.append((0, str(s), b""))
            matches.append({"rule": match.rule, "tags": match.tags,
                            "strings": str_info})
    except Exception as exc:
        log(f"[-] Scan error: {exc}", "err")

    if not matches:
        log("[+] No YARA rules matched", "ok")
    else:
        log(f"[!] {len(matches)} rule(s) matched!", "warn")
    return matches


# ---------------------------------------------------------------------------
# 27. Baseline Diff (System Snapshot Comparison)
# ---------------------------------------------------------------------------
def baseline_snapshot(log: Logger) -> dict:
    """Take a baseline snapshot of the local system (ports, services, files)."""
    import subprocess
    log("[*] Taking system baseline snapshot", "cyan")
    snapshot: dict = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "ports": [], "processes": [], "users": []}

    # Open ports
    try:
        result = subprocess.run(["netstat", "-an"], capture_output=True,
                                text=True, timeout=15)
        listening = [l for l in result.stdout.splitlines() if "LISTENING" in l or "LISTEN" in l]
        ports = []
        for l in listening:
            parts = l.split()
            for p in parts:
                if ":" in p:
                    port_str = p.rsplit(":", 1)[-1]
                    try:
                        ports.append(int(port_str))
                    except ValueError:
                        pass
        snapshot["ports"] = sorted(set(ports))
        log(f"  Listening ports: {len(snapshot['ports'])}", "info")
    except Exception as exc:
        log(f"  netstat failed: {exc}", "muted")

    # Running processes
    try:
        result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                capture_output=True, text=True, timeout=15)
        procs = set()
        for line in result.stdout.splitlines():
            parts = line.strip('"').split('","')
            if parts:
                procs.add(parts[0].strip('"'))
        snapshot["processes"] = sorted(procs)
        log(f"  Running processes: {len(snapshot['processes'])}", "info")
    except Exception as exc:
        log(f"  [-] {exc}", "muted")

    return snapshot


def baseline_compare(current: dict, previous: dict, log: Logger) -> dict:
    """Compare two system snapshots."""
    log("[*] Comparing baselines", "cyan")
    diff: dict = {"new_ports": [], "closed_ports": [], "new_processes": [],
                  "gone_processes": []}

    curr_ports = set(current.get("ports", []))
    prev_ports = set(previous.get("ports", []))
    diff["new_ports"] = sorted(curr_ports - prev_ports)
    diff["closed_ports"] = sorted(prev_ports - curr_ports)

    if diff["new_ports"]:
        log(f"[!] NEW listening ports: {diff['new_ports']}", "err")
    if diff["closed_ports"]:
        log(f"[-] Closed ports: {diff['closed_ports']}", "ok")

    curr_procs = set(current.get("processes", []))
    prev_procs = set(previous.get("processes", []))
    diff["new_processes"] = sorted(curr_procs - prev_procs)
    diff["gone_processes"] = sorted(prev_procs - curr_procs)

    if diff["new_processes"]:
        log(f"[!] NEW processes: {diff['new_processes'][:10]}", "warn")
    if diff["gone_processes"]:
        log(f"[-] Gone processes: {diff['gone_processes'][:10]}", "info")

    return diff


# ---------------------------------------------------------------------------
# 28. OWASP Top 10 Mapper
# ---------------------------------------------------------------------------
OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth & Session Failures",
    "A08": "Data Integrity Failures",
    "A09": "Logging & Monitoring",
    "A10": "SSRF",
}

FINDING_TO_OWASP = {
    "sqli": "A03", "xss": "A03", "lfi": "A03", "command_injection": "A03",
    "xxe": "A03", "crlf": "A03", "ssti": "A03", "prototype_pollution": "A03",
    "ssrf": "A10", "dns_rebinding": "A10",
    "cors": "A01", "broken_auth": "A01", "idor": "A01", "mass_assignment": "A01",
    "open_redirect": "A01", "csrf": "A01",
    "weak_tls": "A02", "weak_cipher": "A02", "weak_key": "A02",
    "jwt_none": "A02", "jwt_confusion": "A02",
    "git_exposed": "A05", "swagger_exposed": "A05", "default_creds": "A05",
    "missing_headers": "A05", "firebase_open": "A05",
    "http_smuggling": "A05", "cookie_insecure": "A05",
    "outdated_software": "A06",
    "race_condition": "A04",
    "deserialization": "A08",
    "no_rate_limit": "A07",
    "no_logging": "A09",
}


def owasp_map(findings: list[dict], log: Logger) -> dict:
    """Map findings to OWASP Top 10 categories."""
    log("[*] OWASP Top 10 mapping", "cyan")
    mapping: dict[str, list[str]] = {k: [] for k in OWASP_2021}

    for finding in findings:
        ftype = finding.get("type", "").lower()
        category = FINDING_TO_OWASP.get(ftype)
        if category:
            mapping[category].append(finding.get("detail", ftype))

    for code, name in OWASP_2021.items():
        items = mapping[code]
        if items:
            log(f"  [{code}] {name}: {len(items)} finding(s)", "err")
            for item in items[:3]:
                log(f"       • {item}", "info")
        else:
            log(f"  [{code}] {name}: —", "muted")

    affected = sum(1 for v in mapping.values() if v)
    log(f"\n  {affected}/10 OWASP categories affected", "warn" if affected >= 3 else "ok")
    return {"mapping": mapping, "affected_count": affected}


# ---------------------------------------------------------------------------
# 29. PCI-DSS Quick Check
# ---------------------------------------------------------------------------
def pci_dss_check(target: str, log: Logger) -> dict:
    """Quick PCI-DSS compliance check against a target."""
    import requests
    log(f"[*] PCI-DSS quick check: {target}", "cyan")
    results: dict = {"target": target, "checks": [], "pass_count": 0, "fail_count": 0}

    url = f"https://{target}" if not target.startswith("http") else target

    checks = [
        ("TLS 1.2+ required", None),
        ("No weak ciphers", None),
        ("Security headers present", None),
        ("No sensitive data in URL", None),
        ("Secure cookies", None),
    ]

    # Check 1: TLS version
    import ssl
    import socket as _socket
    sock = None
    ssock = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        sock = _socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        version = ssock.version()
        passed = version in ("TLSv1.2", "TLSv1.3")
        results["checks"].append({"name": "TLS 1.2+", "passed": passed,
                                   "detail": version})
        log(f"  {'✓' if passed else '✗'} TLS version: {version}", "ok" if passed else "err")
    except Exception as exc:
        results["checks"].append({"name": "TLS 1.2+", "passed": False,
                                   "detail": str(exc)})
        log(f"  ✗ TLS check failed: {exc}", "err")
    finally:
        if ssock:
            ssock.close()
        elif sock:
            sock.close()

    # Check 2: Security headers
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                            headers={"User-Agent": random_ua()})
        required_headers = ["Strict-Transport-Security", "X-Frame-Options",
                           "X-Content-Type-Options"]
        present = [h for h in required_headers if h in resp.headers]
        passed = len(present) == len(required_headers)
        results["checks"].append({"name": "Security headers", "passed": passed,
                                   "detail": f"{len(present)}/{len(required_headers)}"})
        log(f"  {'✓' if passed else '✗'} Security headers: {len(present)}/{len(required_headers)}", "ok" if passed else "err")

        # Check 3: Secure cookies
        secure_cookies = all(
            "secure" in str(c).lower() for c in resp.cookies
        ) if resp.cookies else True
        results["checks"].append({"name": "Secure cookies", "passed": secure_cookies,
                                   "detail": f"{len(resp.cookies)} cookies"})
        log(f"  {'✓' if secure_cookies else '✗'} Secure cookie flags", "ok" if secure_cookies else "warn")
    except requests.RequestException as exc:
        log(f"  ✗ HTTP check failed: {exc}", "err")

    results["pass_count"] = sum(1 for c in results["checks"] if c.get("passed"))
    results["fail_count"] = sum(1 for c in results["checks"] if not c.get("passed"))
    total = len(results["checks"])
    log(f"\n  PCI-DSS: {results['pass_count']}/{total} checks passed",
        "ok" if results["fail_count"] == 0 else "warn")
    return results


# ---------------------------------------------------------------------------
# 30. CIS Benchmark Scanner
# ---------------------------------------------------------------------------
def _cis_pass_min_len(out: str) -> bool:
    """Parse PASS_MIN_LEN value from login.defs grep output."""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        parts = line.split()
        # Expect: PASS_MIN_LEN <number>
        for i, p in enumerate(parts):
            if "PASS_MIN_LEN" in p.upper() and i + 1 < len(parts):
                try:
                    return int(parts[i + 1]) >= 8
                except ValueError:
                    pass
    return False


def cis_benchmark(platform: str, log: Logger) -> dict:
    """Run basic CIS benchmark checks for Windows or Linux."""
    import subprocess
    is_windows = platform.lower().startswith("win")
    log(f"[*] CIS Benchmark scan ({'Windows' if is_windows else 'Linux'})", "cyan")
    results: dict = {"platform": platform, "checks": [], "pass": 0, "fail": 0}

    if is_windows:
        checks = [
            ("Password policy - min length >= 8",
             'net accounts | findstr /i "length"',
             lambda out: "8" in out or "14" in out or "12" in out),
            ("Account lockout enabled",
             'net accounts | findstr /i "lockout"',
             lambda out: "never" not in out.lower()),
            ("Windows Firewall enabled",
             'netsh advfirewall show allprofiles state',
             lambda out: "ON" in out.upper()),
            ("Remote Desktop restricted",
             'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections',
             lambda out: "0x1" in out),
            ("Guest account disabled",
             'net user guest | findstr /i "active"',
             lambda out: "no" in out.lower()),
            ("Audit policy configured",
             'auditpol /get /category:*',
             lambda out: "success" in out.lower()),
        ]
    else:
        checks = [
            ("SSH root login disabled",
             'grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null',
             lambda out: "no" in out.lower()),
            ("Password min length >= 8",
             'grep -i "PASS_MIN_LEN" /etc/login.defs 2>/dev/null',
             lambda out: _cis_pass_min_len(out)),
            ("No empty passwords",
             'awk -F: \'($2 == "") {print $1}\' /etc/shadow 2>/dev/null',
             lambda out: out.strip() == ""),
            ("Firewall active",
             'iptables -L -n 2>/dev/null | head -5',
             lambda out: "ACCEPT" in out or "DROP" in out or "REJECT" in out),
            ("No world-writable files in /etc",
             'find /etc -perm -o+w -type f 2>/dev/null | head -5',
             lambda out: out.strip() == ""),
            ("Core dumps disabled",
             'grep -i "hard core" /etc/security/limits.conf 2>/dev/null',
             lambda out: "0" in out),
        ]

    for name, cmd, validator in checks:
        if _should_stop():
            break
        try:
            # cis_benchmark commands use shell pipes/redirections — shell=True needed
            # Commands are all constants (not user-supplied), so injection is not a risk
            proc = subprocess.run(cmd, shell=True, capture_output=True,  # noqa: S602
                                  text=True, timeout=15)
            output = proc.stdout.strip()
            passed = validator(output) if output else False
            results["checks"].append({"name": name, "passed": passed,
                                       "output": output[:200]})
            tag = "ok" if passed else "err"
            log(f"  {'✓' if passed else '✗'} {name}", tag)
            if passed:
                results["pass"] += 1
            else:
                results["fail"] += 1
        except Exception as exc:
            results["checks"].append({"name": name, "passed": False,
                                       "error": str(exc)})
            results["fail"] += 1
            log(f"  ✗ {name} (error)", "muted")

    total = results["pass"] + results["fail"]
    log(f"\n  CIS Score: {results['pass']}/{total} checks passed",
        "ok" if results["fail"] == 0 else "warn")
    return results


# ===================================================================
#  PHASE 11 — Advanced Tools, Database, CVSS, Profiles, SARIF
# ===================================================================

# ---------------------------------------------------------------------------
