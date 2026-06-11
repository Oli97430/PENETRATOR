from gui.engine._core import *
from gui.engine.recon import scan_ports, find_subdomains, whois_lookup
from gui.engine.web import buster, check_security_headers, xss_reflected
from gui.engine.network import tls_scan, scan_with_banners, check_subdomain_takeover
from gui.engine.advanced import (
    cors_test, open_redirect_test, waf_detect,
    git_exposure_check,
    swagger_discovery, lfi_scan, ssrf_scan,
)
from gui.engine.auth import cookie_audit, csrf_analyze, subdomain_permutation
from gui.engine.discovery import tech_fingerprint, ssti_scan, js_endpoint_extract

# ===========================================================================
# PHASE 10 — Automation, Stealth, Integrations, Defense, Compliance
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. Attack Chain Runner
# ---------------------------------------------------------------------------
def attack_chain(target: str, chain: list[str], log: Logger) -> dict:
    """Run a sequence of tools automatically on a target.
    chain items: 'port_scan', 'banner', 'tls', 'headers', 'buster', 'waf', 'cors'
    """
    # Late import so that mocking gui.engine.X in tests intercepts calls.
    import gui.engine as _eng

    log(f"[*] Attack chain on {target}: {' → '.join(chain)}", "cyan")
    results: dict = {"target": target, "chain": chain, "outputs": {}}

    # Normalize: build a URL for web-facing tools, keep raw host for socket tools
    if target.startswith(("http://", "https://")):
        url = target
        # Extract hostname for socket-based tools
        _parsed = urllib.parse.urlparse(target)
        host = _parsed.hostname or target
    else:
        url = f"http://{target}"
        host = target
    session_set("last_target", host)

    for step in chain:
        if _should_stop():
            log("[!] Chain aborted by user", "warn")
            break
        log(f"\n{'='*60}", "muted")
        log(f"[CHAIN] Step: {step}", "cyan")
        log(f"{'='*60}", "muted")

        try:
            if step == "port_scan":
                results["outputs"]["port_scan"] = _eng.scan_ports(host, 1, 1024, 200, 0.5, log)
            elif step == "banner":
                results["outputs"]["banner"] = _eng.scan_with_banners(host, 1, 1024, 100, 0.6, log)
            elif step == "tls":
                results["outputs"]["tls"] = _eng.tls_scan(host, 443, log)
            elif step == "headers":
                results["outputs"]["headers"] = _eng.check_security_headers(url, log)
            elif step == "buster":
                results["outputs"]["buster"] = _eng.buster(url, DEFAULT_WEB_PATHS, 50, log)
            elif step == "waf":
                results["outputs"]["waf"] = _eng.waf_detect(url, log)
            elif step == "cors":
                results["outputs"]["cors"] = _eng.cors_test(url, log)
            elif step == "subdomain":
                results["outputs"]["subdomain"] = _eng.find_subdomains(host, 50, log)
            elif step == "takeover":
                results["outputs"]["takeover"] = _eng.check_subdomain_takeover(host, log)
            elif step == "git_exposure":
                results["outputs"]["git"] = _eng.git_exposure_check(url, log)
            elif step == "swagger":
                results["outputs"]["swagger"] = _eng.swagger_discovery(url, log)
            # Phase 11 aliases — map profile step names to functions
            elif step in ("tech_fingerprint", "tech_fp"):
                results["outputs"]["tech_fingerprint"] = _eng.tech_fingerprint(url, log)
            elif step in ("header_check", "security_headers"):
                results["outputs"]["header_check"] = _eng.check_security_headers(url, log)
            elif step in ("subdomain_find", "subdomains"):
                results["outputs"]["subdomain_find"] = _eng.find_subdomains(host, 50, log)
            elif step in ("tls_scan", "tls_check"):
                results["outputs"]["tls_scan"] = _eng.tls_scan(host, 443, log)
            elif step in ("cookie_audit", "cookies"):
                results["outputs"]["cookie_audit"] = _eng.cookie_audit(url, log)
            elif step in ("csrf_analyze", "csrf"):
                results["outputs"]["csrf_analyze"] = _eng.csrf_analyze(url, log)
            elif step in ("open_redirect", "redirect"):
                results["outputs"]["open_redirect"] = _eng.open_redirect_test(url, log)
            elif step in ("waf_detect", "waf_check"):
                results["outputs"]["waf_detect"] = _eng.waf_detect(url, log)
            elif step in ("ssti_scan", "ssti"):
                results["outputs"]["ssti_scan"] = _eng.ssti_scan(url, "q", log)
            elif step in ("xss_probe", "xss"):
                results["outputs"]["xss_probe"] = _eng.xss_reflected(url, log)
            elif step in ("lfi_scan", "lfi"):
                results["outputs"]["lfi_scan"] = _eng.lfi_scan(url, "page", log)
            elif step in ("ssrf_scan", "ssrf"):
                results["outputs"]["ssrf_scan"] = _eng.ssrf_scan(url, "url", log)
            elif step in ("js_endpoint_extract", "js_extract"):
                results["outputs"]["js_endpoint_extract"] = _eng.js_endpoint_extract(url, log)
            elif step in ("whois_lookup", "whois"):
                results["outputs"]["whois_lookup"] = _eng.whois_lookup(host, log)
            elif step in ("subdomain_perm", "altdns"):
                results["outputs"]["subdomain_perm"] = _eng.subdomain_permutation(host, log)
            elif step in ("cors_test", "cors_check"):
                results["outputs"]["cors_test"] = _eng.cors_test(url, log)
            else:
                log(f"  Unknown step: {step}", "warn")
        except Exception as exc:
            log(f"  [-] Step {step} failed: {exc}", "err")
            results["outputs"][step] = {"error": str(exc)}

    log(f"\n[*] Chain complete: {len(results['outputs'])} step(s) executed", "cyan")
    return results


# ---------------------------------------------------------------------------
# 2. Auto-Correlator (Risk Scorer)
# ---------------------------------------------------------------------------
def auto_correlate(log: Logger) -> dict:
    """Analyze all session data and produce a risk score."""
    log("[*] Auto-correlating session findings...", "cyan")
    score = 0
    findings: list[str] = []

    # Check open ports
    open_ports = session_get("last_open_ports", [])
    if open_ports:
        high_risk_ports = [p for p in open_ports if p in (21, 23, 445, 3389, 6379, 27017)]
        if high_risk_ports:
            score += 30
            findings.append(f"High-risk ports open: {high_risk_ports}")
        if len(open_ports) > 20:
            score += 10
            findings.append(f"Large attack surface: {len(open_ports)} open ports")

    # Check subdomains
    subs = session_get("last_subdomains", [])
    if len(subs) > 50:
        score += 10
        findings.append(f"Large subdomain footprint: {len(subs)}")

    # Check buster results
    paths = session_get("last_buster_paths", [])
    sensitive = [p for p in paths if any(s in str(p).lower()
                 for s in (".git", ".env", "admin", "backup", "config"))]
    if sensitive:
        score += 25
        findings.append(f"Sensitive paths exposed: {sensitive[:5]}")

    # Check last target
    target = session_get("last_target")
    if target:
        log(f"  Target: {target}", "info")

    # Grade
    if score >= 70:
        grade = "CRITICAL"
    elif score >= 50:
        grade = "HIGH"
    elif score >= 30:
        grade = "MEDIUM"
    elif score >= 10:
        grade = "LOW"
    else:
        grade = "INFO"

    log(f"\n  {'─'*40}", "muted")
    log(f"  Risk Score: {score}/100", "err" if score >= 50 else "warn" if score >= 30 else "ok")
    log(f"  Grade: {grade}", "err" if score >= 50 else "warn" if score >= 30 else "ok")
    for f in findings:
        log(f"  • {f}", "info")
    if not findings:
        log("  No significant findings in session memory", "ok")

    return {"score": score, "grade": grade, "findings": findings}


# ---------------------------------------------------------------------------
# 3. Scheduled Scan Diff
# ---------------------------------------------------------------------------
def scan_diff(current: dict, previous: dict, log: Logger) -> dict:
    """Compare two scan snapshots and highlight port/subdomain changes."""
    log("[*] Comparing scan results...", "cyan")
    diff: dict = {"new": [], "removed": [], "changed": []}

    curr_ports = set(current.get("ports", []))
    prev_ports = set(previous.get("ports", []))

    new_ports = curr_ports - prev_ports
    removed_ports = prev_ports - curr_ports

    if new_ports:
        diff["new"] = list(new_ports)
        log(f"[+] NEW ports: {sorted(new_ports)}", "err")
    if removed_ports:
        diff["removed"] = list(removed_ports)
        log(f"[-] CLOSED ports: {sorted(removed_ports)}", "ok")
    if not new_ports and not removed_ports:
        log("[=] No port changes detected", "info")

    # Compare subdomains
    curr_subs = set(current.get("subdomains", []))
    prev_subs = set(previous.get("subdomains", []))
    new_subs = curr_subs - prev_subs
    if new_subs:
        log(f"[+] NEW subdomains: {sorted(new_subs)[:10]}", "warn")
        diff["new_subdomains"] = list(new_subs)

    return diff


# ---------------------------------------------------------------------------
# 4. Smart Payload Generator (WAF-aware)
# ---------------------------------------------------------------------------
WAF_BYPASS_ENCODINGS = {
    "cloudflare": [
        lambda p: p.replace("<", "%EF%BC%9C").replace(">", "%EF%BC%9E"),
        lambda p: p.replace("'", "%EF%BC%87"),
        lambda p: "/**/".join(p.split(" ")),
    ],
    "modsecurity": [
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),
        lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    ],
    "aws": [
        lambda p: p.replace("<script>", "<scr\x00ipt>"),
        lambda p: urllib.parse.quote(p, safe=""),
    ],
    "generic": [
        lambda p: urllib.parse.quote(p, safe=""),
        lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
        lambda p: base64.b64encode(p.encode()).decode(),
        lambda p: "".join(f"&#x{ord(c):x};" for c in p),
    ],
}


def smart_payload_gen(payload: str, waf_type: str, log: Logger) -> list[str]:
    """Generate WAF-bypass variants of a payload based on detected WAF type."""
    waf_key = waf_type.lower()
    log(f"[*] Generating bypass payloads for WAF: {waf_type}", "cyan")
    log(f"  Original: {payload}", "info")

    encoders = WAF_BYPASS_ENCODINGS.get(waf_key, WAF_BYPASS_ENCODINGS["generic"])
    variants: list[str] = [payload]

    for encoder in encoders:
        try:
            variant = encoder(payload)
            if variant != payload and variant not in variants:
                variants.append(variant)
                log(f"  → {variant[:100]}", "ok")
        except Exception as exc:
            log(f"  [-] {exc}", "muted")

    # Always add generic encodings too
    if waf_key != "generic":
        for encoder in WAF_BYPASS_ENCODINGS["generic"]:
            try:
                variant = encoder(payload)
                if variant not in variants:
                    variants.append(variant)
                    log(f"  → {variant[:100]}", "info")
            except Exception as exc:
                log(f"  [-] {exc}", "muted")

    log(f"[*] {len(variants)} variant(s) generated", "cyan")
    return variants


# ---------------------------------------------------------------------------
# 5. Executive Report Generator
# ---------------------------------------------------------------------------
def executive_report(target: str, log: Logger) -> str:
    """Generate an executive summary from session memory."""
    log(f"[*] Generating executive report for: {target}", "cyan")

    open_ports = session_get("last_open_ports", [])
    subs = session_get("last_subdomains", [])
    paths = session_get("last_buster_paths", [])

    # Build report text
    lines: list[str] = []
    lines.append(f"# Penetration Test Report — {target}")
    lines.append(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"Target: {target}")
    lines.append(f"Open ports: {len(open_ports)}")
    lines.append(f"Subdomains discovered: {len(subs)}")
    lines.append(f"Sensitive paths found: {len(paths)}")
    lines.append("")

    # Risk assessment
    risk_score = 0
    if any(p in open_ports for p in (21, 23, 445, 3389)):
        risk_score += 30
    if paths:
        risk_score += 20
    if len(open_ports) > 15:
        risk_score += 15

    grade = "CRITICAL" if risk_score >= 60 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW"
    lines.append("## Risk Assessment")
    lines.append(f"Score: {risk_score}/100 ({grade})")
    lines.append("")

    if open_ports:
        lines.append("## Open Ports")
        for p in sorted(open_ports)[:30]:
            svc = COMMON_SERVICES.get(p, "unknown")
            lines.append(f"- {p}/{svc}")
        lines.append("")

    if subs:
        lines.append("## Subdomains")
        for s in sorted(subs)[:20]:
            if isinstance(s, (list, tuple)) and len(s) >= 2:
                lines.append(f"- {s[0]} ({s[1]})")
            else:
                lines.append(f"- {s}")
        lines.append("")

    lines.append("## Recommendations")
    if any(p in open_ports for p in (21, 23)):
        lines.append("- CRITICAL: Close FTP/Telnet ports — use SFTP/SSH instead")
    if 3389 in open_ports:
        lines.append("- HIGH: RDP exposed — restrict with VPN/firewall rules")
    if paths:
        lines.append("- HIGH: Remove sensitive files from web root (.git, .env, backups)")
    lines.append("- Implement rate limiting on all public endpoints")
    lines.append("- Enable security headers (HSTS, CSP, X-Frame-Options)")
    lines.append("")
    lines.append("---")
    lines.append("Generated by PENETRATOR v1.9.0")

    report = "\n".join(lines)
    for line in lines:
        log(line, "info")
    return report


# ---------------------------------------------------------------------------
# 6. Proxy Configuration
# ---------------------------------------------------------------------------
_proxy_config: dict[str, str] = {}


def set_proxy(proxy_url: str, log: Logger) -> dict:
    """Configure a global proxy for all requests."""
    global _proxy_config
    if not proxy_url:
        _proxy_config = {}
        log("[+] Proxy disabled", "ok")
        return {}
    _proxy_config = {"http": proxy_url, "https": proxy_url}
    log(f"[+] Proxy set: {proxy_url}", "ok")
    # Test connectivity
    import requests
    try:
        resp = requests.get("https://httpbin.org/ip", proxies=_proxy_config, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        log(f"  External IP via proxy: {data.get('origin', '?')}", "info")
    except requests.RequestException as exc:
        log(f"[!] Proxy test failed: {exc}", "warn")
    return _proxy_config


def get_proxy() -> dict:
    """Return the current proxy configuration dict."""
    return _proxy_config


# ---------------------------------------------------------------------------
# 7. User-Agent Rotation (UA_POOL & random_ua defined at top of module)
# ---------------------------------------------------------------------------


def ua_rotation_demo(url: str, count: int, log: Logger) -> list[dict]:
    """Send requests with rotating User-Agents to demonstrate stealth."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    count = max(1, min(50, count))
    log(f"[*] UA rotation: {count} requests to {url}", "cyan")
    results: list[dict] = []

    for i in range(count):
        if _should_stop():
            break
        ua = random_ua()
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": ua},
                                proxies=get_proxy())
            log(f"  [{resp.status_code}] UA: {ua[:50]}...", "info")
            results.append({"ua": ua, "status": resp.status_code})
        except requests.RequestException as exc:
            log(f"  [-] {exc}", "muted")
    return results


# ---------------------------------------------------------------------------
# 8. Request Throttling
# ---------------------------------------------------------------------------
def throttled_requests(url: str, count: int, min_delay: float,
                       max_delay: float, log: Logger) -> list[dict]:
    """Send requests with random delay between them (anti-ban)."""
    import requests
    import random
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    count = max(1, min(200, count))
    min_delay = max(0.1, min_delay)
    max_delay = max(min_delay, max_delay)
    log(f"[*] Throttled scan: {count} requests, delay {min_delay}-{max_delay}s", "cyan")
    results: list[dict] = []

    for i in range(count):
        if _should_stop():
            break
        ua = random_ua()
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": ua},
                                proxies=get_proxy())
            results.append({"idx": i, "status": resp.status_code, "ua": ua})
            log(f"  [{i+1}/{count}] HTTP {resp.status_code}", "info")
        except requests.RequestException as exc:
            log(f"  [{i+1}/{count}] Error: {exc}", "muted")
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)

    log(f"[*] {len(results)} requests completed", "cyan")
    return results


# ---------------------------------------------------------------------------
# 9. IP Rotation via Proxy List
# ---------------------------------------------------------------------------
def proxy_rotation_test(url: str, proxy_list: list[str], log: Logger) -> list[dict]:
    """Test a URL through multiple proxies to verify IP rotation."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] Proxy rotation test: {len(proxy_list)} proxies", "cyan")
    results: list[dict] = []

    for proxy in proxy_list:
        if _should_stop():
            break
        proxies = {"http": proxy, "https": proxy}
        try:
            resp = requests.get(url, proxies=proxies, timeout=15,
                                headers={"User-Agent": random_ua()})
            log(f"[+] {proxy} → HTTP {resp.status_code} ({len(resp.content)} bytes)", "ok")
            results.append({"proxy": proxy, "status": resp.status_code, "working": True})
        except requests.RequestException as exc:
            log(f"[-] {proxy} → FAILED ({exc})", "muted")
            results.append({"proxy": proxy, "status": 0, "working": False})

    working = sum(1 for r in results if r["working"])
    log(f"[*] {working}/{len(results)} proxies working", "cyan")
    return results


# ---------------------------------------------------------------------------
