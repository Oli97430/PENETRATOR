from gui.engine._core import *

# OSINT
# ---------------------------------------------------------------------------
def verify_email(email: str, log: Logger) -> dict:
    """Validate email syntax and check for MX records on the domain."""
    m = EMAIL_REGEX.match(email.strip())
    if not m:
        log("[-] Invalid email syntax", "err")
        return {"valid": False}
    log("[+] Syntax valid", "ok")
    domain = m.group(1)
    out: dict = {"valid": True, "domain": domain, "mx": []}
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        for rdata in answers:
            out["mx"].append(str(rdata))
            log(f"  MX  {rdata}", "info")
    except ImportError:
        log("[!] dnspython not installed", "warn")
    except Exception:
        log("[!] No MX records found", "warn")
    return out


def ip_geolocate(target: str, log: Logger) -> dict:
    """Look up geolocation data for an IP address or domain."""
    import requests
    try:
        resp = requests.get(f"http://ip-api.com/json/{target}", timeout=REQUEST_TIMEOUT)
        data = resp.json()
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return {}
    if data.get("status") != "success":
        log(f"[-] {data.get('message', 'lookup failed')}", "err")
        return {}
    for key in ("query", "country", "regionName", "city", "zip", "lat",
                "lon", "timezone", "isp", "org", "as"):
        if data.get(key):
            log(f"  {key:<12} {data[key]}", "info")
    return data


def username_search(username: str, log: Logger) -> list[tuple[str, str, int]]:
    """Check whether a username exists on popular platforms."""
    import requests
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": random_ua(),
        "Accept-Language": "en-US,en;q=0.9",
    })

    def probe(site: str, tmpl: str) -> tuple[str, str, int]:
        """Check a single site for the username and return (site, url, status)."""
        url = tmpl.format(u=username)
        try:
            r = sess.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            return site, url, r.status_code
        except requests.RequestException:
            return site, url, 0

    log(f"[*] Checking {username} on {len(USERNAME_SITES)} sites", "cyan")
    rows: list[tuple[str, str, int]] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(probe, site, tmpl) for site, tmpl in USERNAME_SITES.items()]
        for fut in as_completed(futures):
            if _should_stop():
                for p in futures:
                    p.cancel()
                break
            site, url, code = fut.result()
            rows.append((site, url, code))
            tag = "ok" if code == 200 else ("muted" if code == 404 else "warn" if code else "err")
            log(f"  [{code or '---'}] {site:<15} {url}", tag)
    sess.close()
    return rows


def phone_info(number: str, log: Logger) -> dict:
    """Parse a phone number and return carrier, region, and timezone info."""
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
    except ImportError:
        log("[-] phonenumbers not installed. Run: pip install phonenumbers", "err")
        return {}
    try:
        parsed = phonenumbers.parse(number, None)
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return {}
    out = {
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "country_code": parsed.country_code,
        "region": geocoder.description_for_number(parsed, "en"),
        "carrier": carrier.name_for_number(parsed, "en"),
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
    }
    for k, v in out.items():
        log(f"  {k:<14} {v}", "info")
    return out


def reverse_dns(ip: str, log: Logger) -> tuple[str, list[str], list[str]] | None:
    """Perform a reverse DNS lookup on an IP address."""
    try:
        name, aliases, addrs = socket.gethostbyaddr(ip)
    except socket.herror as exc:
        log(f"[-] {exc}", "err")
        return None
    log(f"[+] Hostname: {name}", "ok")
    if aliases:
        log(f"  Aliases:  {', '.join(aliases)}", "info")
    log(f"  Addresses:  {', '.join(addrs)}", "info")
    return name, aliases, addrs


# ---------------------------------------------------------------------------
# Wordlist generation
# ---------------------------------------------------------------------------
def cupp_wordlist(values: dict[str, str]) -> set[str]:
    """Generate a CUPP-style targeted wordlist from personal info values."""
    skip_keys = {"birthday", "keywords"}
    base = {v.strip() for k, v in values.items() if k not in skip_keys and v.strip()}
    birthday = values.get("birthday", "").strip()
    base |= {v.strip() for v in (values.get("keywords", "").split(",")) if v.strip()}
    cased: set[str] = set()
    for w in base:
        cased |= {w, w.lower(), w.upper(), w.capitalize()}
    combined = set(cased)
    for a, b in itertools.permutations(cased, 2):
        combined.add(a + b)
    suffixes = ["", "1", "12", "123", "1234", "!", "!!", "!@#"] + [str(y) for y in range(1960, 2031)]
    if birthday and len(birthday) >= 4:
        suffixes += [birthday, birthday[-4:], birthday[-2:]]
    final = set(combined)
    for w in combined:
        for s in suffixes:
            final.add(w + s)
    return final


def combinator(left: list[str], right: list[str]) -> set[str]:
    """Combine every element of left with every element of right."""
    return {a + b for a in left for b in right}


def leet_mutate(words: list[str], per_word: int = 30) -> set[str]:
    """Generate leet-speak mutations of each word."""
    out: set[str] = set()
    for word in words:
        positions = [LEET_MAP.get(ch.lower(), [ch]) for ch in word]
        for i, combo in enumerate(itertools.product(*positions)):
            if i >= per_word:
                break
            out.add("".join(combo))
    return out


def pattern_generate(charset: str, min_len: int, max_len: int) -> Iterable[str]:
    """Yield all combinations of charset characters for lengths min_len..max_len."""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ---------------------------------------------------------------------------
# crt.sh — Certificate Transparency subdomain enumeration
# ---------------------------------------------------------------------------
