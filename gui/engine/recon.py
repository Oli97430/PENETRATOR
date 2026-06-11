from gui.engine._core import *

# ---------------------------------------------------------------------------
# Information Gathering
# ---------------------------------------------------------------------------
def get_service(port: int) -> str:
    """Return the service name for a TCP port number."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def _check_port(target: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to target:port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except OSError:
        return False


def scan_ports(target: str, start: int, end: int, threads: int, timeout: float,
               log: Logger) -> list[int]:
    """Scan a range of TCP ports on target using a thread pool."""
    # Clamp port range to valid values
    start = max(1, min(start, 65535))
    end = max(start, min(end, 65535))
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        log(f"[-] Cannot resolve {target}: {exc}", "err")
        return []
    log(f"[*] Scanning {target} ({ip})  ports {start}-{end}  threads={threads}", "cyan")
    ports = list(range(start, end + 1))
    open_ports: list[int] = []
    t0 = time.time()
    # Look up _check_port via package so tests can mock gui.engine._check_port
    import gui.engine as _eng
    _check_fn = _eng._check_port
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_check_fn, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            if _should_stop():
                log("[!] Stop requested - cancelling scan", "warn")
                for f in futures:
                    f.cancel()
                break
            port = futures[fut]
            if fut.result():
                service = get_service(port)
                open_ports.append(port)
                log(f"[+] {port:>5}/tcp   {service}", "ok")
    log(f"[*] Found {len(open_ports)} open port(s) in {time.time()-t0:.2f}s", "cyan")
    sorted_ports = sorted(open_ports)
    session_set("last_target", target)
    session_set("last_open_ports", sorted_ports)
    return sorted_ports


def resolve_host(host: str, log: Logger) -> list[str]:
    """Resolve a hostname to its IP addresses."""
    try:
        _, _, ips = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        log(f"[-] {exc}", "err")
        return []
    for ip in ips:
        log(f"[+] {host} -> {ip}", "ok")
    return ips


def whois_lookup(domain: str, log: Logger) -> dict:
    """Perform a WHOIS lookup on a domain and return parsed fields."""
    try:
        import whois  # type: ignore
    except ImportError:
        log("[-] python-whois not installed. Run: pip install python-whois", "err")
        return {}
    try:
        data = whois.whois(domain)
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return {}
    out: dict[str, str] = {}
    for key, value in data.items():
        if value is None or value == []:
            continue
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        out[str(key)] = str(value)
        log(f"  {key:<22} {value}", "info")
    return out


def dns_lookup(domain: str, log: Logger) -> dict[str, list[str]]:
    """Query common DNS record types for a domain."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        log("[-] dnspython not installed. Run: pip install dnspython", "err")
        return {}
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            values = [str(rdata) for rdata in answers]
        except Exception as exc:
            log(f"  [-] {rtype}: {exc}", "muted")
            continue
        out[rtype] = values
        for value in values:
            log(f"  {rtype:<6} {value}", "info")
    if not out:
        log("[!] No DNS records found", "warn")
    return out


def find_subdomains(domain: str, threads: int, log: Logger) -> list[tuple[str, str]]:
    """Brute-force common subdomains and return those that resolve."""
    def check(sub: str) -> tuple[str, str] | None:
        """Resolve a single subdomain and return (sub, ip) or None."""
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            return sub, ip
        except socket.gaierror:
            return None

    log(f"[*] Brute-forcing {len(COMMON_SUBDOMAINS)} subdomains of {domain}", "cyan")
    found: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check, s) for s in COMMON_SUBDOMAINS]
        for f in as_completed(futures):
            if _should_stop():
                for pending in futures:
                    pending.cancel()
                break
            result = f.result()
            if result:
                found.append(result)
                log(f"[+] {result[0]}.{domain} -> {result[1]}", "ok")
    if not found:
        log("[!] No subdomains found", "warn")
    session_set("last_subdomains", found)
    return sorted(found)


def fetch_headers(url: str, log: Logger) -> dict:
    """Fetch HTTP response headers from a URL."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                            headers={"User-Agent": random_ua()})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return {}
    log(f"[+] {url}  -> {resp.status_code}  final: {resp.url}", "ok")
    headers = dict(resp.headers)
    for k, v in headers.items():
        log(f"  {k}: {v}", "info")
    return headers


