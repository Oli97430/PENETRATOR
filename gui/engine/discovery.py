from gui.engine._core import *

# 37. Virtual Host Discovery
# ---------------------------------------------------------------------------
def vhost_discover(ip: str, wordlist: list[str] | str, log: Logger) -> list[dict]:
    """Discover virtual hosts by brute-forcing the Host header."""
    import requests
    log(f"[*] Virtual host discovery on {ip}", "cyan")
    results: list[dict] = []

    if isinstance(wordlist, str):
        # Treat as comma/newline-separated or file path
        path = Path(wordlist)
        if path.is_file():
            hosts = [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        else:
            hosts = [h.strip() for h in wordlist.replace(",", "\n").split("\n") if h.strip()]
    else:
        hosts = list(wordlist)

    if not hosts:
        hosts = [f"{w}.{ip}" for w in ALTDNS_WORDS[:30]]
        log(f"  Using default wordlist ({len(hosts)} entries)", "info")

    # Get baseline response (random non-existent host)
    baseline_len = 0
    try:
        resp = requests.get(f"http://{ip}", timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                            headers={"Host": "nonexistent.invalid", "User-Agent": random_ua()})
        baseline_len = len(resp.text)
    except requests.RequestException:
        pass

    log(f"  Baseline response size: {baseline_len} bytes", "info")

    for hostname in hosts:
        if _should_stop():
            break
        try:
            resp = requests.get(f"http://{ip}", timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                headers={"Host": hostname, "User-Agent": random_ua()})
            resp_len = len(resp.text)
            # Significant difference from baseline suggests a real vhost
            if abs(resp_len - baseline_len) > 50 and resp.status_code != 404:
                results.append({"hostname": hostname, "status": resp.status_code,
                                "size": resp_len})
                log(f"[+] {hostname} — {resp.status_code} ({resp_len} bytes)", "ok")
        except requests.RequestException:
            pass

    if not results:
        log("[+] No additional virtual hosts found", "muted")
    else:
        log(f"[*] {len(results)} virtual host(s) discovered", "cyan")
    session_set("last_vhosts", results)
    return results


# ---------------------------------------------------------------------------
# 38. JavaScript Endpoint Extractor
# ---------------------------------------------------------------------------
_JS_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)((?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/admin/)[\w/\-?&=.{}:]+)(?:"|'|`)""",
)
_JS_URL_RE = re.compile(
    r"""(?:"|'|`)(https?://[^\s"'`<>]{5,200})(?:"|'|`)""",
)


def js_endpoint_extract(url: str, log: Logger) -> dict:
    """Fetch JavaScript files from a page and extract API endpoints."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] JS endpoint extraction: {url}", "cyan")
    result: dict = {"url": url, "scripts": [], "endpoints": [], "full_urls": []}

    try:
        resp = requests.get(url, timeout=15, verify=TLS_VERIFY,
                            headers={"User-Agent": random_ua()})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return result

    # Find <script src="..."> tags
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
    # Also look for inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL | re.IGNORECASE)

    all_js = "\n".join(inline_scripts)
    result["scripts"] = script_srcs[:50]
    log(f"  Found {len(script_srcs)} external scripts, {len(inline_scripts)} inline", "info")

    # Fetch external scripts
    from urllib.parse import urljoin
    for src in script_srcs[:20]:
        if _should_stop():
            break
        full_url = urljoin(url, src)
        try:
            js_resp = requests.get(full_url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                   headers={"User-Agent": random_ua()})
            all_js += "\n" + js_resp.text
        except requests.RequestException:
            pass

    # Extract endpoints
    endpoints = set()
    for match in _JS_ENDPOINT_RE.finditer(all_js):
        endpoints.add(match.group(1))
    for match in _JS_URL_RE.finditer(all_js):
        result["full_urls"].append(match.group(1))

    result["endpoints"] = sorted(endpoints)
    result["full_urls"] = list(set(result["full_urls"]))[:100]

    for ep in sorted(endpoints)[:30]:
        log(f"  [+] {ep}", "ok")
    if result["full_urls"]:
        log(f"  Full URLs found: {len(result['full_urls'])}", "info")

    log(f"[*] {len(endpoints)} API endpoint(s) extracted", "cyan")
    session_set("last_js_endpoints", result)
    return result


# ---------------------------------------------------------------------------
# 39. HTTP Parameter Discovery
# ---------------------------------------------------------------------------
COMMON_PARAMS = [
    "id", "page", "q", "search", "query", "lang", "language", "redirect",
    "url", "next", "return", "callback", "cb", "ref", "source", "target",
    "file", "path", "dir", "debug", "test", "admin", "action", "cmd",
    "exec", "command", "type", "format", "output", "mode", "view",
    "template", "theme", "style", "config", "key", "token", "api_key",
    "secret", "password", "user", "username", "email", "name", "sort",
    "order", "limit", "offset", "category", "tag", "filter", "status",
    "role", "access", "level", "version", "v", "include", "require",
]


def param_discovery(url: str, wordlist: list[str] | str | None, log: Logger) -> dict:
    """Discover hidden HTTP GET/POST parameters."""
    import requests
    log(f"[*] Parameter discovery: {url}", "cyan")
    result: dict = {"url": url, "found_get": [], "found_post": []}

    # Parse wordlist
    if wordlist and isinstance(wordlist, str):
        path = Path(wordlist)
        if path.is_file():
            params = [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        else:
            params = [p.strip() for p in wordlist.replace(",", "\n").split("\n") if p.strip()]
    elif isinstance(wordlist, list):
        params = wordlist
    else:
        params = COMMON_PARAMS

    log(f"  Testing {len(params)} parameters", "info")

    # Get baseline
    try:
        baseline = requests.get(url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                headers={"User-Agent": random_ua()})
        baseline_size = len(baseline.text)
        baseline_status = baseline.status_code
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return result

    # Test GET parameters
    for param in params:
        if _should_stop():
            break
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{param}=FUZZ_PENETRATOR"
        try:
            resp = requests.get(test_url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                headers={"User-Agent": random_ua()})
            size_diff = abs(len(resp.text) - baseline_size)
            if size_diff > 50 or resp.status_code != baseline_status:
                result["found_get"].append({
                    "param": param, "status": resp.status_code,
                    "size_diff": size_diff,
                })
                log(f"  [+] GET ?{param}= → {resp.status_code} (Δ{size_diff}b)", "ok")
        except requests.RequestException:
            pass

    # Test POST parameters (quick subset)
    for param in params[:20]:
        if _should_stop():
            break
        try:
            resp = requests.post(url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY, data={param: "FUZZ"},
                                 headers={"User-Agent": random_ua()})
            size_diff = abs(len(resp.text) - baseline_size)
            if size_diff > 50 or resp.status_code != baseline_status:
                result["found_post"].append({
                    "param": param, "status": resp.status_code,
                    "size_diff": size_diff,
                })
                log(f"  [+] POST {param}= → {resp.status_code} (Δ{size_diff}b)", "ok")
        except requests.RequestException:
            pass

    total = len(result["found_get"]) + len(result["found_post"])
    log(f"[*] {total} hidden parameter(s) found", "cyan" if total else "muted")
    session_set("last_param_discovery", result)
    return result


# ---------------------------------------------------------------------------
# 40. Technology Fingerprinting (Wappalyzer-style)
# ---------------------------------------------------------------------------
TECH_SIGNATURES = {
    # Headers
    "headers": {
        "x-powered-by": {
            "PHP": r"PHP", "ASP.NET": r"ASP\.NET", "Express": r"Express",
            "Next.js": r"Next\.js",
        },
        "server": {
            "Nginx": r"nginx", "Apache": r"Apache", "IIS": r"Microsoft-IIS",
            "LiteSpeed": r"LiteSpeed", "Caddy": r"Caddy", "Cloudflare": r"cloudflare",
            "Gunicorn": r"gunicorn",
        },
        "x-generator": {
            "WordPress": r"WordPress", "Drupal": r"Drupal", "Joomla": r"Joomla",
            "Hugo": r"Hugo",
        },
    },
    # HTML patterns
    "html": {
        "WordPress": r'wp-content|wp-includes|wp-json',
        "Drupal": r'drupal\.js|Drupal\.settings|sites/default',
        "Joomla": r'joomla|com_content',
        "React": r'react\.production\.min\.js|_react[A-Z]|__NEXT_DATA__',
        "Vue.js": r'vue\.min\.js|v-bind:|v-on:|v-if=',
        "Angular": r'ng-version|angular\.min\.js|ng-app=',
        "jQuery": r'jquery[\.-][\d]+\.[\d]+\.[\d]+\.(?:min\.)?js',
        "Bootstrap": r'bootstrap\.min\.(css|js)',
        "Tailwind": r'tailwindcss',
        "Laravel": r'laravel_session|XSRF-TOKEN',
        "Django": r'csrfmiddlewaretoken|djdt',
        "Ruby on Rails": r'csrf-token.*authenticity_token|action_dispatch',
        "Spring": r'jsessionid|spring',
        "Shopify": r'cdn\.shopify\.com',
        "Wix": r'wix\.com|static\.parastorage\.com',
        "Squarespace": r'squarespace\.com|static1\.squarespace',
    },
    # Cookie names
    "cookies": {
        "PHP": "PHPSESSID",
        "ASP.NET": "ASP.NET_SessionId",
        "Java": "JSESSIONID",
        "Laravel": "laravel_session",
        "Django": "csrftoken",
        "Flask": "session",
        "Express": "connect.sid",
        "Cloudflare": "__cf_bm",
    },
}


def tech_fingerprint(url: str, log: Logger) -> dict:
    """Fingerprint web technologies (Wappalyzer-style)."""
    import requests
    log(f"[*] Technology fingerprinting: {url}", "cyan")
    result: dict = {"url": url, "technologies": [], "details": {}}

    try:
        resp = requests.get(url, timeout=15, verify=TLS_VERIFY,
                            headers={"User-Agent": random_ua()},
                            allow_redirects=True)
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return result

    found: set[str] = set()

    # Check headers
    for header_name, techs in TECH_SIGNATURES["headers"].items():
        header_val = resp.headers.get(header_name, "")
        if header_val:
            for tech, pattern in techs.items():
                if re.search(pattern, header_val, re.IGNORECASE):
                    found.add(tech)
                    result["details"][tech] = f"Header {header_name}: {header_val[:60]}"

    # Check HTML body
    body = resp.text[:200000]  # Cap to avoid OOM
    for tech, pattern in TECH_SIGNATURES["html"].items():
        if re.search(pattern, body, re.IGNORECASE):
            found.add(tech)
            if tech not in result["details"]:
                result["details"][tech] = "HTML pattern match"

    # Check cookies
    cookie_names = {c.name.lower() for c in resp.cookies}
    raw_cookies = resp.headers.get("Set-Cookie", "").lower()
    for tech, cookie in TECH_SIGNATURES["cookies"].items():
        if cookie.lower() in cookie_names or cookie.lower() in raw_cookies:
            found.add(tech)
            if tech not in result["details"]:
                result["details"][tech] = f"Cookie: {cookie}"

    result["technologies"] = sorted(found)
    for tech in sorted(found):
        log(f"  [+] {tech} — {result['details'].get(tech, '')}", "ok")

    if not found:
        log("[-] No technologies fingerprinted", "muted")
    else:
        log(f"[*] {len(found)} technology(ies) identified", "cyan")
    session_set("last_tech_fp", result)
    return result


# ---------------------------------------------------------------------------
# 41. DNS Rebinding Check
# ---------------------------------------------------------------------------
_RFC1918 = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is in RFC1918 / loopback / link-local ranges."""
    try:
        parts = [int(p) for p in ip_str.split(".")]
        ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        for start, end in _RFC1918:
            sp = [int(p) for p in start.split(".")]
            ep = [int(p) for p in end.split(".")]
            s = (sp[0] << 24) + (sp[1] << 16) + (sp[2] << 8) + sp[3]
            e = (ep[0] << 24) + (ep[1] << 16) + (ep[2] << 8) + ep[3]
            if s <= ip_int <= e:
                return True
    except (ValueError, IndexError):
        pass
    return False


def dns_rebinding_check(domain: str, log: Logger) -> dict:
    """Check if a domain resolves to internal/private IPs (DNS rebinding risk)."""
    import socket as _socket
    log(f"[*] DNS rebinding check: {domain}", "cyan")
    result: dict = {"domain": domain, "resolutions": [], "private_ips": [],
                    "vulnerable": False}

    # Resolve multiple times (rebinding flips between public and private)
    for attempt in range(10):
        if _should_stop():
            break
        try:
            ip = _socket.gethostbyname(domain)
            result["resolutions"].append(ip)
            is_priv = _is_private_ip(ip)
            if is_priv:
                result["private_ips"].append(ip)
                result["vulnerable"] = True
                log(f"  [{attempt + 1}] {ip} — PRIVATE!", "err")
            else:
                log(f"  [{attempt + 1}] {ip}", "ok")
        except _socket.gaierror:
            log(f"  [{attempt + 1}] resolution failed", "muted")
        time.sleep(0.3)

    unique = set(result["resolutions"])
    if len(unique) > 1:
        log(f"[!] Domain resolves to multiple IPs: {unique}", "warn")
    if result["vulnerable"]:
        log("[!] DNS REBINDING RISK — domain resolves to private IP", "err")
    else:
        log("[+] No private IP resolutions detected", "ok")
    session_set("last_dns_rebinding", result)
    return result


# ---------------------------------------------------------------------------
# 42. HTTP/2 Smuggling Detector
# ---------------------------------------------------------------------------
def http2_smuggling(url: str, log: Logger) -> dict:
    """Test for HTTP/2 request smuggling (H2.CL / H2.TE desync).

    Note: Uses HTTP/1.1 (requests library). This tests for CL/TE
    desync indicators that are also relevant to HTTP/1.1 servers
    fronted by HTTP/2 reverse proxies.
    """
    import requests
    from urllib.parse import urlparse
    log(f"[*] HTTP/2 smuggling test: {url}", "cyan")
    log("  Note: testing CL/TE desync patterns (HTTP/1.1 probe)", "muted")
    result: dict = {"url": url, "tests": [], "issues": []}
    parsed = urlparse(url)
    host = parsed.hostname or ""

    # Test 1: H2.CL — Content-Length mismatch
    test_payloads = [
        {
            "name": "H2.CL Content-Length mismatch",
            "headers": {"Content-Length": "0", "Transfer-Encoding": "chunked"},
            "body": "0\r\n\r\nSMUGGLED",
        },
        {
            "name": "H2.TE Transfer-Encoding obfuscation",
            "headers": {"Transfer-Encoding": "chunked", "Transfer-encoding": "cow"},
            "body": "5\r\nsmug\r\n0\r\n\r\n",
        },
        {
            "name": "CL.TE with newline",
            "headers": {"Content-Length": "6", "Transfer-Encoding": " chunked"},
            "body": "0\r\n\r\nX",
        },
    ]

    for payload in test_payloads:
        if _should_stop():
            break
        try:
            resp = requests.post(url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                 headers={**payload["headers"],
                                          "Host": host,
                                          "User-Agent": random_ua()},
                                 data=payload["body"])
            # Check for desync indicators
            is_suspicious = resp.status_code in (400, 500, 502, 503)
            test_r = {
                "name": payload["name"],
                "status": resp.status_code,
                "suspicious": is_suspicious,
                "size": len(resp.text),
            }
            result["tests"].append(test_r)
            if is_suspicious:
                result["issues"].append(payload["name"])
                log(f"  [!] {payload['name']}: status {resp.status_code} — SUSPICIOUS", "warn")
            else:
                log(f"  [+] {payload['name']}: status {resp.status_code}", "ok")
        except requests.RequestException as exc:
            result["tests"].append({"name": payload["name"], "error": str(exc)})
            log(f"  [-] {payload['name']}: {exc}", "muted")

    if result["issues"]:
        log(f"[!] {len(result['issues'])} potential smuggling indicator(s)", "err")
    else:
        log("[+] No HTTP/2 smuggling indicators detected", "ok")
    session_set("last_h2_smuggling", result)
    return result


# ---------------------------------------------------------------------------
# 43. Prototype Pollution Scanner
# ---------------------------------------------------------------------------
PROTO_POLLUTION_PAYLOADS = [
    "__proto__[test]=polluted",
    "__proto__.test=polluted",
    "constructor[prototype][test]=polluted",
    "constructor.prototype.test=polluted",
]


def prototype_pollution_scan(url: str, log: Logger) -> dict:
    """Test for client-side and server-side prototype pollution."""
    import requests
    log(f"[*] Prototype pollution scan: {url}", "cyan")
    result: dict = {"url": url, "tests": [], "issues": []}

    for payload in PROTO_POLLUTION_PAYLOADS:
        if _should_stop():
            break
        # Test via query parameter
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{payload}"
        try:
            resp = requests.get(test_url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                headers={"User-Agent": random_ua()})
            reflected = "polluted" in resp.text
            test_r = {"payload": payload, "method": "GET",
                      "reflected": reflected, "status": resp.status_code}
            result["tests"].append(test_r)
            if reflected:
                result["issues"].append(f"GET: {payload}")
                log(f"  [!] GET {payload}: REFLECTED in response!", "err")
            else:
                log(f"  [+] GET {payload}: not reflected", "ok")
        except requests.RequestException:
            pass

        # Test via JSON body — vary the body per payload
        try:
            # Map query-string payload to equivalent JSON structure
            if "constructor" in payload:
                json_body = {"constructor": {"prototype": {"test": "polluted"}}}
                json_label = "JSON constructor.prototype"
            else:
                json_body = {"__proto__": {"test": "polluted"}}
                json_label = "JSON __proto__"
            resp = requests.post(url, json=json_body, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                 headers={"User-Agent": random_ua()})
            reflected = "polluted" in resp.text
            test_r = {"payload": json_label, "method": "POST",
                      "reflected": reflected, "status": resp.status_code}
            result["tests"].append(test_r)
            if reflected:
                result["issues"].append(f"POST {json_label}")
                log(f"  [!] POST {json_label}: REFLECTED!", "err")
        except requests.RequestException:
            pass

    if result["issues"]:
        log(f"[!] {len(result['issues'])} prototype pollution vector(s) found!", "err")
    else:
        log("[+] No prototype pollution detected", "ok")
    session_set("last_proto_pollution", result)
    return result


# ---------------------------------------------------------------------------
# 44. Server-Side Template Injection (SSTI) Scanner
# ---------------------------------------------------------------------------
SSTI_PAYLOADS = [
    # (payload, expected_output, template_engine)
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "FreeMarker/Mako"),
    ("#{7*7}", "49", "Ruby ERB / Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string multiply)"),
    ("${T(java.lang.Runtime)}", "java.lang.Runtime", "Spring SpEL"),
    ("{{config}}", "Config", "Flask/Jinja2 debug"),
    ("{{self}}", "TemplateReference", "Jinja2 self"),
    ("@(1+1)", "2", "Razor"),
    ("#set($x=7*7)${x}", "49", "Velocity"),
]


def ssti_scan(url: str, param: str, log: Logger) -> dict:
    """Test a URL parameter for Server-Side Template Injection."""
    import requests
    log(f"[*] SSTI scan: {url} (param={param})", "cyan")
    result: dict = {"url": url, "param": param, "findings": []}

    for payload, expected, engine in SSTI_PAYLOADS:
        if _should_stop():
            break
        # Inject via GET
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{param}={urllib.parse.quote(payload)}"
        try:
            resp = requests.get(test_url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                headers={"User-Agent": random_ua()})
            if expected.lower() in resp.text.lower():
                result["findings"].append({
                    "payload": payload, "engine": engine,
                    "expected": expected, "found": True,
                })
                log(f"  [!] SSTI detected ({engine}): {payload} → {expected}", "err")
            else:
                log(f"  [+] {engine}: not reflected", "ok")
        except requests.RequestException:
            pass

    if result["findings"]:
        log(f"[!] {len(result['findings'])} SSTI vector(s) confirmed!", "err")
    else:
        log("[+] No SSTI vulnerabilities detected", "ok")
    session_set("last_ssti_result", result)
    return result


# ---------------------------------------------------------------------------
# 45. Insecure Deserialization Tester
# ---------------------------------------------------------------------------
DESER_PAYLOADS = [
    # (name, content_type, body_bytes_hex, detection_pattern)
    ("Java ObjectInputStream", "application/x-java-serialized-object",
     "aced0005", "java|ClassNotFoundException|ObjectInputStream"),
    ("PHP serialize", "application/x-www-form-urlencoded",
     None, "unserialize|Object of class|__wakeup"),
    ("Python pickle", "application/octet-stream",
     "80049505", "pickle|unpickle|module"),
    (".NET ViewState", "application/x-www-form-urlencoded",
     None, "ViewState|MAC validation|serialization"),
    ("Node.js node-serialize", "application/json",
     None, "ERR_ASSERTION|unexpected token|serialize"),
]


def insecure_deser_test(url: str, log: Logger) -> dict:
    """Test for insecure deserialization vulnerabilities."""
    import requests
    log(f"[*] Insecure deserialization test: {url}", "cyan")
    result: dict = {"url": url, "tests": [], "issues": []}

    for name, content_type, hex_body, detection in DESER_PAYLOADS:
        if _should_stop():
            break
        body: bytes
        if hex_body:
            body = bytes.fromhex(hex_body) + b"\x00" * 50
        elif "php" in name.lower():
            body = b'O:8:"stdClass":0:{}'
        elif "node" in name.lower():
            body = b'{"rce":"_$$ND_FUNC$$_function(){return 1}()"}'
        elif "viewstate" in name.lower():
            body = b'__VIEWSTATE=/wEPDwUKLTEwNjczMjQ5Ng=='
        else:
            body = b'\x00' * 20

        try:
            resp = requests.post(url, data=body, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                 headers={"Content-Type": content_type,
                                          "User-Agent": random_ua()})
            # Check if response reveals deserialization processing
            detected = bool(re.search(detection, resp.text, re.IGNORECASE))
            test_r = {
                "name": name, "status": resp.status_code,
                "detected": detected, "size": len(resp.text),
            }
            result["tests"].append(test_r)
            if detected:
                result["issues"].append(name)
                log(f"  [!] {name}: deserialization signatures in response!", "err")
            else:
                log(f"  [+] {name}: no indicators ({resp.status_code})", "ok")
        except requests.RequestException as exc:
            log(f"  [-] {name}: {exc}", "muted")

    if result["issues"]:
        log(f"[!] {len(result['issues'])} deserialization issue(s) detected!", "err")
    else:
        log("[+] No deserialization vulnerabilities detected", "ok")
    session_set("last_deser_test", result)
    return result


