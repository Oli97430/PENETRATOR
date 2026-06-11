from gui.engine._core import *
from gui.engine.automation import smart_payload_gen, get_proxy

# ---------------------------------------------------------------------------
# 10. WAF Bypass Payload Tester
# ---------------------------------------------------------------------------
def waf_bypass_test(url: str, payload: str, waf_type: str, log: Logger) -> list[dict]:
    """Generate WAF-bypass variants and test them against the target."""
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    variants = smart_payload_gen(payload, waf_type, log)
    log(f"\n[*] Testing {len(variants)} bypass variants against {url}", "cyan")

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    target_param = next(iter(params), "q")
    results: list[dict] = []

    for variant in variants:
        if _should_stop():
            break
        mut = dict(params)
        mut[target_param] = variant
        test_url = urlunparse(parsed._replace(query=urlencode(mut, safe="")))
        try:
            resp = requests.get(test_url, timeout=REQUEST_TIMEOUT,
                                headers={"User-Agent": random_ua()},
                                proxies=get_proxy())
            blocked = resp.status_code in (403, 406, 429, 503)
            tag = "err" if not blocked else "muted"
            log(f"  HTTP {resp.status_code} {'BLOCKED' if blocked else 'PASSED!'} ← {variant[:60]}", tag)
            results.append({"variant": variant, "status": resp.status_code,
                            "blocked": blocked})
        except requests.RequestException:
            pass

    passed = sum(1 for r in results if not r["blocked"])
    log(f"[*] {passed}/{len(results)} variants bypassed the WAF", "warn" if passed else "ok")
    return results


# ---------------------------------------------------------------------------
# 11. Nmap XML Import
# ---------------------------------------------------------------------------
def nmap_import(xml_path: str, log: Logger) -> dict:
    """Parse an Nmap XML output file and load results into session."""
    from xml.etree.ElementTree import iterparse
    log(f"[*] Importing Nmap XML: {xml_path}", "cyan")
    results: dict = {"hosts": [], "total_ports": 0}

    # Use defusedxml if available; otherwise use iterparse with entity guard
    try:
        import defusedxml.ElementTree as _safe_ET
        tree = _safe_ET.parse(xml_path)
        root = tree.getroot()
    except ImportError:
        # Fallback: reject files with entity declarations (billion laughs defense)
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as _f:
            head = _f.read(4096)
        if "<!ENTITY" in head.upper():
            log("[-] XML entity declarations detected — refusing to parse "
                "(install defusedxml for safe parsing)", "err")
            return results
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as exc:
        log(f"[-] Parse error: {exc}", "err")
        return results

    all_ports: list[int] = []
    for host in root.findall(".//host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""
        host_data: dict = {"address": addr, "ports": []}

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                portid = int(port.get("portid", 0))
                protocol = port.get("protocol", "tcp")
                service_el = port.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                host_data["ports"].append({"port": portid, "proto": protocol,
                                           "service": service})
                all_ports.append(portid)
                log(f"  {addr}:{portid}/{protocol} ({service})", "info")

        if host_data["ports"]:
            results["hosts"].append(host_data)

    # Store in session
    session_set("last_open_ports", sorted(set(all_ports)))
    if results["hosts"]:
        session_set("last_target", results["hosts"][0]["address"])
    results["total_ports"] = len(all_ports)
    log(f"[+] Imported {len(results['hosts'])} host(s), {len(all_ports)} open port(s)", "ok")
    return results


# ---------------------------------------------------------------------------
# 12. Nuclei Template Runner
# ---------------------------------------------------------------------------
def nuclei_run(target: str, templates: str, log: Logger) -> list[dict]:
    """Run nuclei templates against a target (requires nuclei installed)."""
    import shutil
    import subprocess

    if not shutil.which("nuclei"):
        log("[-] nuclei not installed. Download from https://github.com/projectdiscovery/nuclei", "err")
        return []

    # Validate template path to prevent arbitrary file loading
    if templates:
        tpath = Path(templates).resolve()
        # Reject paths with traversal or absolute paths outside cwd
        if ".." in templates or (tpath.is_absolute() and not str(tpath).startswith(str(Path.cwd()))):
            log("[-] Template path rejected (path traversal detected)", "err")
            return []

    cmd = ["nuclei", "-u", target, "-silent", "-jsonl"]
    if templates:
        cmd.extend(["-t", templates])
    log(f"[*] Running: {' '.join(cmd)}", "cyan")

    findings: list[dict] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="ignore")
        assert proc.stdout is not None
        for line in proc.stdout:
            if _should_stop():
                proc.terminate()
                break
            line = line.strip()
            if line:
                try:
                    import json
                    finding = json.loads(line)
                    severity = finding.get("info", {}).get("severity", "info")
                    name = finding.get("info", {}).get("name", "?")
                    matched = finding.get("matched-at", "")
                    tag = "err" if severity in ("critical", "high") else "warn" if severity == "medium" else "info"
                    log(f"[{severity.upper()}] {name} → {matched}", tag)
                    findings.append(finding)
                except (ValueError, TypeError):
                    log(f"  {line}", "info")
        proc.wait()
    except OSError as exc:
        log(f"[-] {exc}", "err")

    log(f"[*] {len(findings)} finding(s) from nuclei", "cyan")
    return findings


# ---------------------------------------------------------------------------
# 13. Burp Suite XML Export
# ---------------------------------------------------------------------------
def burp_export(findings: list[dict], output_path: str, log: Logger) -> str:
    """Export findings in Burp Suite-compatible XML format."""
    log(f"[*] Exporting {len(findings)} findings to Burp XML: {output_path}", "cyan")
    import xml.etree.ElementTree as ET

    root = ET.Element("issues")
    root.set("burpVersion", "2024.0")
    root.set("exportTime", time.strftime("%Y-%m-%dT%H:%M:%S"))

    for finding in findings:
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "serialNumber").text = str(hash(str(finding)) % 10**8)
        ET.SubElement(issue, "type").text = str(finding.get("type", "0"))
        ET.SubElement(issue, "name").text = finding.get("name", "Finding")
        ET.SubElement(issue, "host").text = finding.get("host", "")
        ET.SubElement(issue, "path").text = finding.get("path", "/")
        ET.SubElement(issue, "severity").text = finding.get("severity", "Information")
        ET.SubElement(issue, "confidence").text = finding.get("confidence", "Tentative")
        ET.SubElement(issue, "issueDetail").text = finding.get("detail", "")

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    log(f"[+] Exported to {output_path}", "ok")
    return output_path


# ---------------------------------------------------------------------------
# 14. Metasploit RPC Interface
# ---------------------------------------------------------------------------
def msf_rpc_check(host: str, port: int, token: str, log: Logger) -> dict:
    """Check Metasploit RPC connectivity and list available modules."""
    import requests
    port = port or 55553
    url = f"https://{host}:{port}/api/"
    log(f"[*] Metasploit RPC check: {url}", "cyan")

    try:
        # Auth check
        resp = requests.post(url, json={"method": "auth.token_list", "token": token},
                             timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY)
        if resp.status_code == 200:
            data = resp.json()
            if "error" not in data:
                log("[+] Connected to Metasploit RPC!", "ok")

                # List exploit count
                resp2 = requests.post(url, json={"method": "module.exploits", "token": token},
                                      timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY)
                if resp2.status_code == 200:
                    modules = resp2.json().get("modules", [])
                    log(f"  Available exploits: {len(modules)}", "info")
                    return {"connected": True, "exploits": len(modules)}
            else:
                log(f"[-] Auth failed: {data.get('error_message', '')}", "err")
        else:
            log(f"[-] HTTP {resp.status_code}", "err")
    except requests.RequestException as exc:
        log(f"[-] Connection failed: {exc}", "err")
    return {"connected": False}


# ---------------------------------------------------------------------------
# 15. Shodan API Integration
# ---------------------------------------------------------------------------
def shodan_lookup(target: str, api_key: str, log: Logger) -> dict:
    """Query Shodan API for detailed host information."""
    import requests
    log(f"[*] Shodan lookup: {target}", "cyan")

    if not api_key:
        # Fall back to free InternetDB
        log("  No API key — using free InternetDB", "info")
        try:
            resp = requests.get(f"https://internetdb.shodan.io/{target}", timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                log(f"  Ports: {ports}", "info")
                if vulns:
                    log(f"  [!] Vulns: {vulns}", "err")
                return data
        except requests.RequestException as exc:
            log(f"[-] {exc}", "err")
        return {}

    # Full Shodan API
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{target}",
                            params={"key": api_key}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            log(f"  Organization: {data.get('org', '?')}", "info")
            log(f"  OS: {data.get('os', '?')}", "info")
            log(f"  Ports: {data.get('ports', [])}", "info")
            vulns = data.get("vulns", [])
            if vulns:
                log(f"  [!] {len(vulns)} known vulnerability(ies)", "err")
                for v in vulns[:10]:
                    log(f"    • {v}", "err")
            return data
        else:
            log(f"[-] Shodan API error: HTTP {resp.status_code}", "err")
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
    return {}


# ---------------------------------------------------------------------------
# 16. SPF/DKIM/DMARC Checker
# ---------------------------------------------------------------------------
def email_security_check(domain: str, log: Logger) -> dict:
    """Check SPF, DKIM, and DMARC records for a domain."""
    import socket as _socket
    log(f"[*] Email security check: {domain}", "cyan")
    results: dict = {"domain": domain, "spf": None, "dkim": None, "dmarc": None}

    try:
        import dns.resolver
        HAS_DNS = True
    except ImportError:
        HAS_DNS = False
        log("[!] dnspython not installed — using basic checks", "warn")

    # SPF
    try:
        if HAS_DNS:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=spf1" in txt:
                    results["spf"] = txt
                    has_all_fail = "-all" in txt
                    tag = "ok" if has_all_fail else "warn"
                    log(f"  SPF: {txt[:100]}", tag)
                    if not has_all_fail:
                        log("  [!] SPF does not end with -all (permissive)", "warn")
                    break
            if not results["spf"]:
                log("  [!] No SPF record found!", "err")
        else:
            import subprocess
            result = subprocess.run(["nslookup", "-type=TXT", domain],
                                    capture_output=True, text=True, timeout=REQUEST_TIMEOUT)
            if "v=spf1" in result.stdout:
                log("  SPF: found (install dnspython for details)", "ok")
                results["spf"] = "present"
    except Exception as exc:
        log(f"  SPF check failed: {exc}", "muted")

    # DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        if HAS_DNS:
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=DMARC1" in txt:
                    results["dmarc"] = txt
                    policy = "reject" if "p=reject" in txt else "quarantine" if "p=quarantine" in txt else "none"
                    tag = "ok" if policy == "reject" else "warn" if policy == "quarantine" else "err"
                    log(f"  DMARC: {txt[:100]}", tag)
                    log(f"    Policy: {policy}", tag)
                    break
            if not results["dmarc"]:
                log("  [!] No DMARC record found!", "err")
    except Exception:
        log("  [!] No DMARC record found!", "err")

    # DKIM (common selectors)
    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
    for sel in dkim_selectors:
        if _should_stop():
            break
        try:
            dkim_domain = f"{sel}._domainkey.{domain}"
            if HAS_DNS:
                answers = dns.resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        results["dkim"] = {"selector": sel, "record": txt[:200]}
                        log(f"  DKIM: found (selector={sel})", "ok")
                        break
                if results["dkim"]:
                    break
        except Exception as exc:
            log(f"  [-] {exc}", "muted")
            continue

    if not results["dkim"]:
        log("  [!] No DKIM record found (checked common selectors)", "warn")

    # Score
    score = sum(1 for v in (results["spf"], results["dkim"], results["dmarc"]) if v)
    log(f"\n  Email security score: {score}/3", "ok" if score == 3 else "warn" if score >= 2 else "err")
    return results


# ---------------------------------------------------------------------------
# 17. Email Header Analyzer
# ---------------------------------------------------------------------------
def email_header_analyze(headers_text: str, log: Logger) -> dict:
    """Parse email headers and trace the message path."""
    log("[*] Email header analysis", "cyan")
    results: dict = {"hops": [], "authentication": {}, "flags": []}

    lines = headers_text.splitlines()
    received_hops: list[str] = []
    current_header = ""

    for line in lines:
        if line.startswith(" ") or line.startswith("\t"):
            current_header += " " + line.strip()
        else:
            if current_header.lower().startswith("received:"):
                received_hops.append(current_header)
            current_header = line.strip()
    if current_header.lower().startswith("received:"):
        received_hops.append(current_header)

    log(f"  Message hops: {len(received_hops)}", "info")
    for i, hop in enumerate(reversed(received_hops)):
        log(f"  Hop {i+1}: {hop[:120]}", "info")
        results["hops"].append(hop)

    # Check authentication results
    for line in lines:
        lower = line.lower()
        if "authentication-results:" in lower:
            if "spf=pass" in lower:
                results["authentication"]["spf"] = "pass"
                log("  SPF: PASS", "ok")
            elif "spf=fail" in lower:
                results["authentication"]["spf"] = "fail"
                log("  SPF: FAIL", "err")
            if "dkim=pass" in lower:
                results["authentication"]["dkim"] = "pass"
                log("  DKIM: PASS", "ok")
            elif "dkim=fail" in lower:
                results["authentication"]["dkim"] = "fail"
                log("  DKIM: FAIL", "err")
            if "dmarc=pass" in lower:
                results["authentication"]["dmarc"] = "pass"
                log("  DMARC: PASS", "ok")
            elif "dmarc=fail" in lower:
                results["authentication"]["dmarc"] = "fail"
                log("  DMARC: FAIL", "err")

    # Suspicious indicators
    if len(received_hops) > 8:
        results["flags"].append("Unusually many hops (possible relay)")
        log("  [!] Unusually many hops", "warn")

    return results


# ---------------------------------------------------------------------------
# 18. Homoglyph Domain Detector
# ---------------------------------------------------------------------------
HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α'], 'c': ['с', 'ϲ'], 'd': ['ԁ'],
    'e': ['е', 'ё'], 'g': ['ɡ'], 'h': ['һ'],
    'i': ['і', 'ı', 'l', '1'], 'l': ['І', '1', 'i'],
    'o': ['о', '0', 'ο'], 'p': ['р'], 'q': ['ԛ'],
    's': ['ѕ'], 'w': ['ԝ'], 'x': ['х'], 'y': ['у'],
}


def homoglyph_detect(domain: str, log: Logger) -> list[str]:
    """Generate and check homoglyph (typosquat) variants of a domain."""
    import socket as _socket
    log(f"[*] Homoglyph detection for: {domain}", "cyan")

    base = domain.split(".")[0]
    tld = ".".join(domain.split(".")[1:]) or "com"
    variants: list[str] = []

    # Generate single-char substitutions
    for i, char in enumerate(base):
        if char.lower() in HOMOGLYPHS:
            for replacement in HOMOGLYPHS[char.lower()]:
                variant = base[:i] + replacement + base[i+1:]
                full = f"{variant}.{tld}"
                if full != domain:
                    variants.append(full)

    # Also check common typos
    for i in range(len(base) - 1):
        swapped = base[:i] + base[i+1] + base[i] + base[i+2:]
        full = f"{swapped}.{tld}"
        if full != domain:
            variants.append(full)

    log(f"  Generated {len(variants)} variants", "info")
    registered: list[str] = []

    for variant in variants[:50]:
        if _should_stop():
            break
        try:
            _socket.gethostbyname(variant)
            registered.append(variant)
            log(f"[!] {variant} — REGISTERED (potential typosquat!)", "err")
        except _socket.gaierror:
            pass

    if not registered:
        log("[+] No registered homoglyph domains found", "ok")
    else:
        log(f"[!] {len(registered)} typosquat domain(s) detected!", "warn")
    return registered


# ---------------------------------------------------------------------------
# 19. Phishing URL Analyzer
# ---------------------------------------------------------------------------
def phishing_url_analyze(url: str, log: Logger) -> dict:
    """Score a URL for phishing indicators."""
    from urllib.parse import urlparse
    log(f"[*] Phishing URL analysis: {url}", "cyan")
    parsed = urlparse(url if "://" in url else "http://" + url)
    score = 0
    indicators: list[str] = []

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Check indicators
    if len(url) > 75:
        score += 15
        indicators.append(f"Long URL ({len(url)} chars)")
    if hostname.count(".") > 3:
        score += 15
        indicators.append(f"Many subdomains ({hostname.count('.') + 1} levels)")
    if "@" in url:
        score += 30
        indicators.append("Contains @ (credential obfuscation)")
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname):
        score += 25
        indicators.append("IP address instead of domain")
    if any(s in hostname for s in ("login", "verify", "secure", "account", "update", "confirm")):
        score += 20
        indicators.append("Suspicious keywords in hostname")
    if "-" in hostname and hostname.count("-") > 2:
        score += 10
        indicators.append("Multiple hyphens in domain")
    if len(hostname) > 30:
        score += 10
        indicators.append("Unusually long hostname")
    if parsed.port and parsed.port not in (80, 443):
        score += 15
        indicators.append(f"Non-standard port: {parsed.port}")
    if "%" in url and url.count("%") > 3:
        score += 15
        indicators.append("Heavy URL encoding")
    # Check for data: or javascript:
    if parsed.scheme in ("data", "javascript"):
        score += 40
        indicators.append(f"Dangerous scheme: {parsed.scheme}")

    score = min(100, score)
    grade = "PHISHING" if score >= 70 else "SUSPICIOUS" if score >= 40 else "LOW RISK" if score >= 20 else "SAFE"

    log(f"  Score: {score}/100 ({grade})", "err" if score >= 70 else "warn" if score >= 40 else "ok")
    for ind in indicators:
        log(f"  • {ind}", "info")
    if not indicators:
        log("  No phishing indicators found", "ok")

    return {"url": url, "score": score, "grade": grade, "indicators": indicators}


# ---------------------------------------------------------------------------
# 20. APK Analyzer
# ---------------------------------------------------------------------------
def apk_analyze(apk_path: str, log: Logger) -> dict:
    """Extract metadata from an Android APK file."""
    import zipfile
    import xml.etree.ElementTree as ET
    log(f"[*] APK analysis: {apk_path}", "cyan")
    results: dict = {"permissions": [], "activities": [], "services": [],
                     "receivers": [], "meta": {}}

    if not Path(apk_path).is_file():
        log("[-] File not found", "err")
        return results

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            results["meta"]["files_count"] = len(names)
            results["meta"]["total_size"] = sum(i.file_size for i in zf.infolist())
            log(f"  Files: {len(names)}, Total size: {results['meta']['total_size']:,} bytes", "info")

            # Look for interesting files
            interesting = [n for n in names if any(
                p in n.lower() for p in (".json", ".xml", ".properties", "secret",
                                         "config", "api", "key", ".db", ".sqlite")
            )]
            if interesting:
                log("  Interesting files:", "warn")
                for f in interesting[:20]:
                    log(f"    {f}", "info")
                results["meta"]["interesting_files"] = interesting

            # Try to read AndroidManifest (it's in binary XML format in APK)
            if "AndroidManifest.xml" in names:
                log("  AndroidManifest.xml found", "info")
                # Binary XML needs special parsing, just report presence
                results["meta"]["has_manifest"] = True

            # Check for native libs
            libs = [n for n in names if n.startswith("lib/")]
            if libs:
                archs = set(n.split("/")[1] for n in libs if "/" in n[4:])
                log(f"  Native libraries: {', '.join(archs)}", "info")
                results["meta"]["native_archs"] = list(archs)

            # Check for DEX files
            dex_files = [n for n in names if n.endswith(".dex")]
            log(f"  DEX files: {len(dex_files)}", "info")
            results["meta"]["dex_count"] = len(dex_files)

    except zipfile.BadZipFile:
        log("[-] Not a valid ZIP/APK file", "err")
    except Exception as exc:
        log(f"[-] {exc}", "err")

    return results


# ---------------------------------------------------------------------------
