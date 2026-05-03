"""Web attack tools: directory buster, URL checker, header scanner."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_input,
    pause,
    print_error,
    print_info,
    print_success,
    print_warning,
)

console = Console()

DEFAULT_PATHS = [
    "admin", "administrator", "login", "logout", "wp-admin", "wp-login.php",
    "wp-content", "wp-includes", "config.php", "config.bak", "config.old",
    "backup", "backup.zip", "backup.tar.gz", ".git", ".git/config", ".env",
    ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "phpinfo.php",
    "phpmyadmin", "server-status", "test.php", "info.php", "setup.php",
    "install.php", "shell.php", "upload", "uploads", "images", "assets",
    "api", "api/v1", "api/v2", "users", "user", "profile", "dashboard",
    "console", "manage", "panel", "cpanel", "webmail", "mail", "secret",
    "hidden", "backup.sql", "database.sql", "db.sql", "dump.sql",
    "README.md", "LICENSE", "package.json", "composer.json",
    "debug", "trace", "phpmyadmin/index.php", "adminer.php",
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


def _ensure_scheme(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


def _requests():
    try:
        import requests
        return requests
    except ImportError:
        print_error("requests not installed. Run: pip install requests")
        return None


def dir_buster() -> None:
    requests = _requests()
    if not requests:
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    url = _ensure_scheme(url).rstrip("/") + "/"
    wordlist_path_s = ask_input(t("modules.web_attacks.wordlist_path"),
                                default="(default)")
    threads_s = ask_input(t("ui.threads"), default="30")
    try:
        threads = max(1, min(200, int(threads_s)))
    except ValueError:
        threads = 30

    if wordlist_path_s in ("(default)", ""):
        paths = DEFAULT_PATHS
    else:
        wl_path = Path(wordlist_path_s)
        if not wl_path.is_file():
            print_error(t("ui.required"))
            pause()
            return
        paths = [ln.strip() for ln in wl_path.read_text(
            encoding="utf-8", errors="ignore").splitlines() if ln.strip()]

    session = requests.Session()
    session.headers.update({"User-Agent": "PENETRATOR/1.0"})

    found: list[tuple[int, str]] = []

    def check(path: str) -> tuple[int, str] | None:
        target = urljoin(url, path)
        try:
            resp = session.head(target, timeout=5, allow_redirects=False)
            if resp.status_code == 405:
                resp = session.get(target, timeout=5, allow_redirects=False)
        except requests.RequestException:
            return None
        if resp.status_code in (200, 201, 202, 204, 301, 302, 307, 401, 403):
            return resp.status_code, target
        return None

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task(t("ui.scanning"), total=len(paths))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(check, p) for p in paths]
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    found.append(result)
                progress.update(task, advance=1)

    found.sort()
    for code, target in found:
        print_success(t("modules.web_attacks.found_path", code=code, url=target))
    if not found:
        print_warning(t("ui.no_results"))
    pause()


def url_checker() -> None:
    requests = _requests()
    if not requests:
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    url = _ensure_scheme(url)
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        print_error(str(exc))
        pause()
        return
    table = Table(title=url, border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white", overflow="fold")
    table.add_row("Status", str(resp.status_code))
    table.add_row("Final URL", resp.url)
    table.add_row("Redirect chain", " -> ".join(r.url for r in resp.history) or "(none)")
    table.add_row("Content length", str(len(resp.content)))
    table.add_row("Content-Type", resp.headers.get("Content-Type", ""))
    table.add_row("Server", resp.headers.get("Server", ""))
    console.print(table)
    pause()


def header_scanner() -> None:
    requests = _requests()
    if not requests:
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    url = _ensure_scheme(url)
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        print_error(str(exc))
        pause()
        return
    table = Table(title=f"Security headers: {url}", border_style="green")
    table.add_column("Header", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Value / Purpose", style="dim", overflow="fold")
    for header, purpose in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        if value:
            table.add_row(header, "[green]✓[/]", value)
        else:
            table.add_row(header, "[red]✗[/]", purpose)
    console.print(table)
    pause()


def robots_sitemap() -> None:
    requests = _requests()
    if not requests:
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    url = _ensure_scheme(url).rstrip("/")
    for path in ("robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt"):
        target = f"{url}/{path}"
        try:
            resp = requests.get(target, timeout=8,
                                headers={"User-Agent": "PENETRATOR/1.0"})
        except requests.RequestException:
            continue
        if resp.status_code == 200 and resp.text.strip():
            print_success(f"{target}  [{resp.status_code}]")
            console.print(f"[dim]{resp.text[:2000]}[/]")
            console.print()
        else:
            print_warning(f"{target}  [{resp.status_code}]")
    pause()


def tech_detect() -> None:
    requests = _requests()
    if not requests:
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    url = _ensure_scheme(url)
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        print_error(str(exc))
        pause()
        return

    findings: dict[str, str] = {}
    server = resp.headers.get("Server")
    if server:
        findings["Server"] = server
    powered = resp.headers.get("X-Powered-By")
    if powered:
        findings["X-Powered-By"] = powered
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text, re.I)
    if generator:
        findings["Generator"] = generator.group(1)

    signatures = {
        "WordPress": [r"/wp-content/", r"/wp-includes/"],
        "Drupal": [r"Drupal.settings", r"/sites/default/"],
        "Joomla": [r"/media/jui/", r"Joomla!"],
        "Laravel": [r"laravel_session"],
        "Django": [r"csrftoken", r"__admin__/"],
        "Flask": [r"Werkzeug"],
        "Express": [r"express"],
        "Magento": [r"/static/version", r"Mage\."],
        "Shopify": [r"cdn\.shopify\.com"],
        "React": [r"__REACT_DEVTOOLS"],
        "Vue.js": [r"__VUE"],
        "Angular": [r"ng-version"],
        "jQuery": [r"jquery(?:\.min)?\.js"],
        "Bootstrap": [r"bootstrap(?:\.min)?\.css"],
        "Cloudflare": [r"cloudflare", r"cf-ray"],
    }
    headers_blob = "\n".join(f"{k}:{v}" for k, v in resp.headers.items())
    body = resp.text[:200000]
    for tech, patterns in signatures.items():
        for pattern in patterns:
            if re.search(pattern, body, re.I) or re.search(pattern, headers_blob, re.I):
                findings.setdefault(tech, "detected")
                break

    if findings:
        table = Table(title=f"Tech detection: {url}", border_style="green")
        table.add_column("Technology", style="cyan")
        table.add_column("Detail", style="white")
        for name, detail in findings.items():
            table.add_row(name, detail)
        console.print(table)
    else:
        print_warning(t("ui.no_results"))
    pause()


# ---------------------------------------------------------------------------
# Engine-backed CLI tools (parity with GUI)
# ---------------------------------------------------------------------------
from core.cli_bridge import cli_log  # noqa: E402
from gui import engine as E          # noqa: E402


def http_repeater() -> None:
    method = ask_input(t("modules.web_attacks.method"), default="GET")
    url = ask_input(t("ui.url"))
    if not url:
        return
    headers = ask_input(t("modules.web_attacks.headers"), default="")
    body = ask_input(t("modules.web_attacks.body"), default="")
    E.http_repeat(method, url, headers, body, cli_log)
    pause()


def cors_check() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.cors_test(url, cli_log)
    pause()


def open_redirect_check() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.open_redirect_test(url, cli_log)
    pause()


def waf_detect_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.waf_detect(url, cli_log)
    pause()


def graphql_introspect_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.graphql_introspect(url, cli_log)
    pause()


def graphql_field_enum_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.graphql_field_enum(url, cli_log)
    pause()


def smuggling_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.http_smuggling_detect(url, cli_log)
    pause()


def imds_cli() -> None:
    url = ask_input(t("modules.web_attacks.via_url"))
    if url:
        E.imds_check(url, cli_log)
    pause()


def ssrf_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    param = ask_input(t("modules.web_attacks.ssrf_param"), default="")
    E.ssrf_scan(url, param, cli_log)
    pause()


def xxe_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.xxe_test(url, cli_log)
    pause()


def crlf_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.crlf_test(url, cli_log)
    pause()


def race_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    method = ask_input(t("modules.web_attacks.method"), default="POST")
    body = ask_input(t("modules.web_attacks.body"), default="")
    count = ask_input(t("modules.web_attacks.request_count"), default="50")
    try:
        E.race_condition_test(url, method, body, int(count), cli_log)
    except ValueError:
        print_error(t("ui.invalid_choice"))
    pause()


def ws_fuzz_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.websocket_fuzz(url, cli_log)
    pause()


def lfi_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    param = ask_input(t("modules.web_attacks.lfi_param"), default="")
    E.lfi_scan(url, param, cli_log)
    pause()


def async_buster_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    wl = ask_input(t("ui.wordlist_path"), default="")
    conc_s = ask_input(t("modules.info_gathering.concurrency"), default="100")
    from pathlib import Path
    if wl and Path(wl).is_file():
        paths = [p.strip() for p in Path(wl).read_text(encoding="utf-8",
                errors="ignore").splitlines() if p.strip()]
    else:
        paths = E.DEFAULT_WEB_PATHS
    try:
        E.buster_async(url, paths, int(conc_s), cli_log)
    except ValueError:
        print_error(t("ui.invalid_choice"))
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.web_attacks.title", parent=parent)
    menu.add(MenuItem("modules.web_attacks.dir_buster", dir_buster,
                      "modules.web_attacks.dir_buster_desc"))
    menu.add(MenuItem("modules.web_attacks.async_buster", async_buster_cli,
                      "modules.web_attacks.async_buster_desc"))
    menu.add(MenuItem("modules.web_attacks.url_checker", url_checker,
                      "modules.web_attacks.url_checker_desc"))
    menu.add(MenuItem("modules.web_attacks.header_scanner", header_scanner,
                      "modules.web_attacks.header_scanner_desc"))
    menu.add(MenuItem("modules.web_attacks.robots_sitemap", robots_sitemap,
                      "modules.web_attacks.robots_sitemap_desc"))
    menu.add(MenuItem("modules.web_attacks.tech_detect", tech_detect,
                      "modules.web_attacks.tech_detect_desc"))
    menu.add(MenuItem("modules.web_attacks.repeater", http_repeater,
                      "modules.web_attacks.repeater_desc"))
    menu.add(MenuItem("modules.web_attacks.cors_test", cors_check,
                      "modules.web_attacks.cors_test_desc"))
    menu.add(MenuItem("modules.web_attacks.open_redirect", open_redirect_check,
                      "modules.web_attacks.open_redirect_desc"))
    menu.add(MenuItem("modules.web_attacks.waf_detect", waf_detect_cli,
                      "modules.web_attacks.waf_detect_desc"))
    menu.add(MenuItem("modules.web_attacks.graphql_introspect",
                      graphql_introspect_cli,
                      "modules.web_attacks.graphql_introspect_desc"))
    menu.add(MenuItem("modules.web_attacks.graphql_field_enum",
                      graphql_field_enum_cli,
                      "modules.web_attacks.graphql_field_enum_desc"))
    menu.add(MenuItem("modules.web_attacks.smuggling", smuggling_cli,
                      "modules.web_attacks.smuggling_desc"))
    menu.add(MenuItem("modules.web_attacks.imds_check", imds_cli,
                      "modules.web_attacks.imds_check_desc"))
    menu.add(MenuItem("modules.web_attacks.ssrf_scan", ssrf_cli,
                      "modules.web_attacks.ssrf_scan_desc"))
    menu.add(MenuItem("modules.web_attacks.xxe_test", xxe_cli,
                      "modules.web_attacks.xxe_test_desc"))
    menu.add(MenuItem("modules.web_attacks.crlf_test", crlf_cli,
                      "modules.web_attacks.crlf_test_desc"))
    menu.add(MenuItem("modules.web_attacks.race_condition", race_cli,
                      "modules.web_attacks.race_condition_desc"))
    menu.add(MenuItem("modules.web_attacks.ws_fuzz", ws_fuzz_cli,
                      "modules.web_attacks.ws_fuzz_desc"))
    menu.add(MenuItem("modules.web_attacks.lfi_scan", lfi_cli,
                      "modules.web_attacks.lfi_scan_desc"))
    return menu
