from gui.engine._core import *
from gui.engine.recon import scan_ports, get_service

# crt.sh — Certificate Transparency subdomain enumeration
# ---------------------------------------------------------------------------
def crtsh_subdomains(domain: str, log: Logger) -> list[str]:
    """Query Certificate Transparency logs via crt.sh for SAN entries."""
    import requests
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    log(f"[*] Querying crt.sh for *.{domain}", "cyan")
    try:
        resp = requests.get(url, timeout=30,
                            headers={"User-Agent": random_ua()})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return []
    if resp.status_code != 200:
        log(f"[-] crt.sh returned HTTP {resp.status_code}", "err")
        return []
    try:
        records = resp.json()
    except ValueError:
        log("[-] crt.sh returned non-JSON (rate limited?)", "err")
        return []
    found: set[str] = set()
    for rec in records:
        for name in (rec.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain) and " " not in name:
                found.add(name)
    sorted_names = sorted(found)
    for name in sorted_names:
        log(f"  + {name}", "ok")
    log(f"[*] {len(sorted_names)} unique subdomain(s) from CT logs", "cyan")
    return sorted_names


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------
def grab_banner(host: str, port: int, timeout: float, log: Logger) -> str:
    """Connect to host:port, send a probe, and return the first response chunk."""
    import socket as _s
    probes = {
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        443: b"",  # TLS — handled separately below
        21: b"", 22: b"", 25: b"HELP\r\n", 110: b"QUIT\r\n",
        143: b"a001 LOGOUT\r\n", 3306: b"\x00",
    }
    try:
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            probe = probes.get(port, b"")
            if probe:
                sock.sendall(probe)
            data = sock.recv(2048)
    except OSError as exc:
        log(f"  [{port}] {exc}", "muted")
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    if text:
        first_lines = "\n".join(text.splitlines()[:3])
        log(f"[+] {host}:{port}", "ok")
        for line in first_lines.splitlines():
            log(f"    {line}", "info")
    else:
        log(f"  [{port}] no banner", "muted")
    return text


def scan_with_banners(target: str, start: int, end: int, threads: int,
                      timeout: float, log: Logger) -> dict[int, str]:
    """Port scan + banner grab on each open port."""
    open_ports = scan_ports(target, start, end, threads, timeout, log)
    if not open_ports:
        return {}
    log("[*] Grabbing banners...", "cyan")
    banners: dict[int, str] = {}
    for p in open_ports:
        if _should_stop():
            break
        banners[p] = grab_banner(target, p, timeout * 2, log)
    return banners


# ---------------------------------------------------------------------------
# TLS / SSL scanner
# ---------------------------------------------------------------------------
def tls_scan_last_open_tls(log: Logger) -> list[dict]:
    """Cross-tool chain: pick TLS-likely ports from the last port scan and run
    tls_scan() on each."""
    target = session_get("last_target")
    open_ports = session_get("last_open_ports") or []
    if not target or not open_ports:
        log("[-] No previous port scan in this session. Run a scan first.",
            "err")
        return []
    tls_ports = [p for p in open_ports if p in (443, 465, 587, 636, 993, 995,
                                                8443, 9443, 4443)]
    if not tls_ports:
        log(f"[!] No TLS-likely ports among {open_ports}.", "warn")
        return []
    log(f"[*] Chain: TLS scan on {target} ports {tls_ports}", "cyan")
    out: list[dict] = []
    for p in tls_ports:
        if _should_stop():
            break
        result = tls_scan(target, p, log)
        out.append(result)
    return out


def tls_scan(host: str, port: int, log: Logger) -> dict:
    """Inspect cert chain, expiry, supported TLS versions and weak protocols."""
    import socket as _s
    import ssl
    from datetime import datetime, timezone

    out: dict = {"host": host, "port": port}
    log(f"[*] TLS scan {host}:{port}", "cyan")

    # 1. Cert info via default context
    try:
        ctx = ssl.create_default_context()
        with _s.create_connection((host, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
    except Exception as exc:
        log(f"[-] TLS handshake failed: {exc}", "err")
        return out

    out["tls_version"] = version
    out["cipher"] = cipher
    log(f"[+] Negotiated: {version}  cipher={cipher[0] if cipher else '?'}", "ok")

    # 2. Subject / Issuer / SANs
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    out["subject_cn"] = subject.get("commonName")
    out["issuer_cn"] = issuer.get("commonName")
    out["sans"] = sans
    log(f"  Subject CN  {out['subject_cn']}", "info")
    log(f"  Issuer  CN  {out['issuer_cn']}", "info")
    if sans:
        log(f"  SANs        {', '.join(sans[:8])}"
            + (f" (+{len(sans) - 8} more)" if len(sans) > 8 else ""), "info")

    # 3. Validity window
    try:
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        out["expires"] = cert["notAfter"]
        out["days_left"] = days_left
        tag = "ok" if days_left > 30 else "warn" if days_left > 0 else "err"
        log(f"  Expires     {cert['notAfter']}  ({days_left} days)", tag)
    except (KeyError, ValueError):
        pass

    # 4. Probe legacy protocols (TLS 1.0 / 1.1 / SSLv3)
    legacy_versions = [
        ("SSLv3",    getattr(ssl, "PROTOCOL_SSLv23", None), getattr(ssl.TLSVersion, "SSLv3", None)),
        ("TLSv1.0",  None, ssl.TLSVersion.TLSv1),
        ("TLSv1.1",  None, ssl.TLSVersion.TLSv1_1),
    ]
    legacy_supported: list[str] = []
    for name, _, tlsver in legacy_versions:
        if tlsver is None:
            continue
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ctx2.minimum_version = tlsver
            ctx2.maximum_version = tlsver
            with _s.create_connection((host, port), timeout=4) as s2:
                with ctx2.wrap_socket(s2, server_hostname=host):
                    legacy_supported.append(name)
        except Exception as exc:
            log(f"  [-] {name}: {exc}", "muted")
    out["legacy_supported"] = legacy_supported
    if legacy_supported:
        log(f"[!] Legacy protocols supported: {', '.join(legacy_supported)}", "warn")
    else:
        log("[+] No legacy protocols (SSLv3/TLS1.0/TLS1.1) accepted", "ok")
    return out


# ---------------------------------------------------------------------------
# JWT toolkit
# ---------------------------------------------------------------------------
def _b64url_decode(data: str) -> bytes:
    """Decode a base64url string with auto-padding."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def jwt_decode(token: str, log: Logger) -> dict:
    """Decode and pretty-print a JWT. Does NOT verify signature."""
    import json as _json
    parts = token.strip().split(".")
    if len(parts) != 3:
        log("[-] Not a JWT (need 3 dot-separated parts)", "err")
        return {}
    try:
        header = _json.loads(_b64url_decode(parts[0]))
        payload = _json.loads(_b64url_decode(parts[1]))
    except Exception as exc:
        log(f"[-] Decode failed: {exc}", "err")
        return {}
    out = {"header": header, "payload": payload, "signature_b64": parts[2]}

    log("[+] Header:", "ok")
    for k, v in header.items():
        log(f"    {k}: {v}", "info")
    log("[+] Payload:", "ok")
    for k, v in payload.items():
        log(f"    {k}: {v}", "info")
    log(f"[+] Signature (b64): {parts[2][:50]}{'...' if len(parts[2]) > 50 else ''}", "ok")

    alg = header.get("alg", "").lower()
    if alg == "none":
        log("[!] alg='none' — token can be forged trivially", "warn")
    if alg.startswith("hs"):
        log(f"[i] HMAC algorithm ({alg.upper()}). Try jwt_brute() with a wordlist.",
            "muted")
    return out


def jwt_brute(token: str, wordlist_path: str, log: Logger) -> str | None:
    """Brute-force the HS256/384/512 secret from a wordlist."""
    import hmac as _hmac
    import json as _json
    parts = token.strip().split(".")
    if len(parts) != 3:
        log("[-] Not a JWT", "err"); return None
    try:
        header = _json.loads(_b64url_decode(parts[0]))
    except Exception as exc:
        log(f"[-] Decode failed: {exc}", "err"); return None
    alg = (header.get("alg") or "").upper()
    digest = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}.get(alg)
    if digest is None:
        log(f"[-] Unsupported alg: {alg!r} (need HS256/384/512)", "err")
        return None

    signing_input = (parts[0] + "." + parts[1]).encode()
    expected = _b64url_decode(parts[2])

    path = Path(wordlist_path)
    if not path.is_file():
        log(f"[-] Wordlist not found: {wordlist_path}", "err"); return None

    log(f"[*] Brute-forcing {alg} signature with {path}", "cyan")
    tried = 0; t0 = time.time()
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if _should_stop():
                log("[!] Stop requested - aborting", "warn")
                return None
            secret = line.rstrip("\r\n")
            if not secret:
                continue
            tried += 1
            mac = _hmac.new(secret.encode(), signing_input, digest).digest()
            if _hmac.compare_digest(mac, expected):
                log(f"[+] Secret found after {tried} attempts: {secret!r}", "ok")
                return secret
            if tried % 20000 == 0:
                log(f"    ... tried {tried:,}", "muted")
    log(f"[-] Not found ({tried:,} tried in {time.time() - t0:.2f}s)", "warn")
    return None


# ---------------------------------------------------------------------------
# HIBP — Pwned Password check (k-anonymity API, no key required)
# ---------------------------------------------------------------------------
def hibp_password_check(password: str, log: Logger) -> int:
    """Returns occurrence count in HIBP corpus (0 = not pwned)."""
    import requests
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    log(f"[*] Querying HIBP range API for SHA-1 prefix {prefix}", "cyan")
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": random_ua(),
                     "Add-Padding": "true"},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err"); return -1
    if resp.status_code != 200:
        log(f"[-] HIBP HTTP {resp.status_code}", "err"); return -1
    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        suf, count = line.split(":", 1)
        if suf.strip().upper() == suffix:
            n = int(count.strip())
            log(f"[!] PWNED — seen {n:,} times in known breaches", "err")
            return n
    log("[+] Not found in HIBP — but absence is not a guarantee", "ok")
    return 0


# ---------------------------------------------------------------------------
# Subdomain takeover detector
# ---------------------------------------------------------------------------
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    # service, cname-suffix, body-fingerprint
    ("AWS S3",          "s3.amazonaws.com",          "NoSuchBucket"),
    ("AWS S3",          "s3-website",                "NoSuchBucket"),
    ("GitHub Pages",    "github.io",                 "There isn't a GitHub Pages site here"),
    ("Heroku",          "herokudns.com",             "No such app"),
    ("Heroku",          "herokuapp.com",             "No such app"),
    ("Azure",           "azurewebsites.net",         "404 Web Site not found"),
    ("Azure",           "cloudapp.net",              "404 Web Site not found"),
    ("Azure CDN",       "azureedge.net",             "Web Site not found"),
    ("Fastly",          "fastly.net",                "Fastly error: unknown domain"),
    ("Shopify",         "myshopify.com",             "Sorry, this shop is currently unavailable"),
    ("Tumblr",          "domains.tumblr.com",        "Whatever you were looking for doesn't currently exist"),
    ("Bitbucket",       "bitbucket.io",              "Repository not found"),
    ("Cargo",           "cargocollective.com",       "404 Not Found"),
    ("Pantheon",        "pantheonsite.io",           "The gods are wise"),
    ("Surge",           "surge.sh",                  "project not found"),
    ("Read the Docs",   "readthedocs.io",            "unknown to Read the Docs"),
    ("Unbounce",        "unbouncepages.com",         "The requested URL was not found"),
    ("Zendesk",         "zendesk.com",               "Help Center Closed"),
]


def check_subdomain_takeover(host: str, log: Logger) -> dict:
    """For a given host, resolve CNAME and HTTP body, look for takeover fingerprint."""
    import requests
    out: dict = {"host": host, "cname": None, "vulnerable": False, "service": None}
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(host, "CNAME", lifetime=5)
            cname = str(answers[0]).rstrip(".")
            out["cname"] = cname
            log(f"  CNAME -> {cname}", "info")
        except Exception as exc:
            log(f"  no CNAME ({exc})", "muted")
    except ImportError:
        log("[-] dnspython not installed", "err"); return out

    try:
        resp = requests.get(f"http://{host}", timeout=REQUEST_TIMEOUT, allow_redirects=True,
                            headers={"User-Agent": random_ua()})
        body = resp.text
    except requests.RequestException as exc:
        log(f"  HTTP error: {exc}", "muted")
        body = ""

    cname = (out.get("cname") or "").lower()
    for service, suffix, fingerprint in TAKEOVER_FINGERPRINTS:
        if suffix in cname and fingerprint.lower() in body.lower():
            out["vulnerable"] = True
            out["service"] = service
            log(f"[!] LIKELY TAKEOVER on {host} ({service})", "err")
            return out
    if not out["vulnerable"]:
        log(f"[+] {host} — no takeover fingerprint matched", "ok")
    return out


# ---------------------------------------------------------------------------
# Async helper — safe coroutine execution (handles nested event loops)
# ---------------------------------------------------------------------------
