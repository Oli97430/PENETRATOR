"""Information gathering tools: port scan, DNS, WHOIS, subdomains, headers."""
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_input,
    check_command_exists,
    pause,
    print_error,
    print_info,
    print_success,
    print_warning,
    run_command,
)

console = Console()

# A handful of classic service names used when the OS lookup fails.
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "admin", "forum", "blog", "login", "api", "dev", "test", "stage",
    "m", "mobile", "shop", "store", "status", "static", "cdn", "assets", "img",
    "images", "download", "downloads", "docs", "help", "support", "portal",
    "vpn", "remote", "cpanel", "secure", "server", "git", "gitlab", "jenkins",
    "grafana", "kibana", "beta", "demo", "staging", "app", "apps", "intranet",
    "news", "media", "video", "chat", "monitor", "jira", "wiki", "sso",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def _parse_port_range(value: str) -> tuple[int, int]:
    if "-" in value:
        start_s, end_s = value.split("-", 1)
        start, end = int(start_s), int(end_s)
    else:
        start = end = int(value)
    start = max(1, min(65535, start))
    end = max(1, min(65535, end))
    if end < start:
        start, end = end, start
    return start, end


def _check_port(target: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except (socket.gaierror, OSError):
        return False


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def port_scanner() -> None:
    target = ask_input(t("ui.target"))
    if not target:
        return
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        print_error(f"{t('ui.missing_tool', tool=target)}: {exc}")
        pause()
        return
    range_str = ask_input(t("ui.port_range"), default="1-1024")
    try:
        start, end = _parse_port_range(range_str)
    except ValueError:
        print_error(t("ui.invalid_choice"))
        pause()
        return
    threads_s = ask_input(t("ui.threads"), default="200")
    timeout_s = ask_input(t("ui.timeout"), default="0.5")
    try:
        threads = max(1, min(1000, int(threads_s)))
        timeout = max(0.05, float(timeout_s))
    except ValueError:
        print_error(t("ui.invalid_choice"))
        pause()
        return

    print_info(
        t("modules.info_gathering.scanning_ports",
          target=f"{target} ({target_ip})", start=start, end=end)
    )
    ports = list(range(start, end + 1))
    open_ports: list[int] = []
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(t("ui.scanning"), total=len(ports))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_check_port, target_ip, p, timeout): p for p in ports}
            for fut in as_completed(futures):
                port = futures[fut]
                if fut.result():
                    open_ports.append(port)
                progress.update(task, advance=1)

    open_ports.sort()
    if open_ports:
        table = Table(title=t("ui.results"), border_style="green")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service", style="white")
        for port in open_ports:
            table.add_row(str(port), _get_service(port))
        console.print(table)
    else:
        print_warning(t("ui.no_results"))
    print_info(t("modules.info_gathering.total_open", count=len(open_ports)))
    print_info(f"{t('ui.elapsed')}: {time.time() - start_time:.2f}s")
    pause()


def host_to_ip() -> None:
    host = ask_input(t("ui.host"))
    if not host:
        return
    try:
        _, _, ips = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        print_error(str(exc))
        pause()
        return
    for ip in ips:
        print_success(t("modules.info_gathering.resolved", host=host, ip=ip))
    pause()


def whois_lookup() -> None:
    domain = ask_input(t("ui.domain"))
    if not domain:
        return
    try:
        import whois  # type: ignore
    except ImportError:
        print_error("python-whois not installed. Run: pip install python-whois")
        pause()
        return
    try:
        data = whois.whois(domain)
    except Exception as exc:
        print_error(str(exc))
        pause()
        return
    table = Table(title=f"WHOIS: {domain}", border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    for key, value in data.items():
        if value is None or value == []:
            continue
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        table.add_row(str(key), str(value))
    console.print(table)
    pause()


def dns_lookup() -> None:
    domain = ask_input(t("ui.domain"))
    if not domain:
        return
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        print_error("dnspython not installed. Run: pip install dnspython")
        pause()
        return
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
    table = Table(title=f"DNS: {domain}", border_style="green")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="white")
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                table.add_row(rtype, str(rdata))
        except Exception:
            continue
    console.print(table)
    pause()


def subdomain_finder() -> None:
    domain = ask_input(t("ui.domain"))
    if not domain:
        return
    threads_s = ask_input(t("ui.threads"), default="40")
    try:
        threads = max(1, min(200, int(threads_s)))
    except ValueError:
        threads = 40

    def check(sub: str) -> tuple[str, str] | None:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return sub, ip
        except socket.gaierror:
            return None

    found: list[tuple[str, str]] = []
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task(t("ui.scanning"), total=len(COMMON_SUBDOMAINS))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(check, s) for s in COMMON_SUBDOMAINS]
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    found.append(result)
                progress.update(task, advance=1)

    for sub, ip in sorted(found):
        print_success(t("modules.info_gathering.subdomain_found",
                        sub=sub, domain=domain, ip=ip))
    if not found:
        print_warning(t("ui.no_results"))
    pause()


def http_headers() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        import requests
    except ImportError:
        print_error("requests not installed. Run: pip install requests")
        pause()
        return
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "PENETRATOR/1.0"})
    except requests.RequestException as exc:
        print_error(str(exc))
        pause()
        return
    table = Table(title=t("modules.info_gathering.header_info", url=url),
                  border_style="green")
    table.add_column("Header", style="cyan")
    table.add_column("Value", style="white", overflow="fold")
    table.add_row("Status", str(resp.status_code))
    table.add_row("Final URL", resp.url)
    for key, value in resp.headers.items():
        table.add_row(key, value)
    console.print(table)
    pause()


def nmap_wrapper() -> None:
    if not check_command_exists("nmap"):
        print_error(t("ui.missing_tool", tool="nmap"))
        print_warning(t("ui.missing_tool_hint"))
        pause()
        return
    target = ask_input(t("ui.target"))
    if not target:
        return
    options = ask_input("Nmap options", default="-sV -T4 -Pn")
    run_command(f'nmap {options} {target}', shell=True)
    pause()


def traceroute() -> None:
    target = ask_input(t("ui.target"))
    if not target:
        return
    import os as _os
    cmd = "tracert" if _os.name == "nt" else "traceroute"
    run_command(f"{cmd} {target}", shell=True)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.info_gathering.title", parent=parent)
    menu.add(MenuItem("modules.info_gathering.port_scan",
                      port_scanner, "modules.info_gathering.port_scan_desc"))
    menu.add(MenuItem("modules.info_gathering.host_to_ip",
                      host_to_ip, "modules.info_gathering.host_to_ip_desc"))
    menu.add(MenuItem("modules.info_gathering.whois_lookup",
                      whois_lookup, "modules.info_gathering.whois_lookup_desc"))
    menu.add(MenuItem("modules.info_gathering.dns_lookup",
                      dns_lookup, "modules.info_gathering.dns_lookup_desc"))
    menu.add(MenuItem("modules.info_gathering.subdomain_finder",
                      subdomain_finder, "modules.info_gathering.subdomain_finder_desc"))
    menu.add(MenuItem("modules.info_gathering.http_headers",
                      http_headers, "modules.info_gathering.http_headers_desc"))
    menu.add(MenuItem("modules.info_gathering.nmap_wrapper",
                      nmap_wrapper, "modules.info_gathering.nmap_wrapper_desc"))
    menu.add(MenuItem("modules.info_gathering.traceroute",
                      traceroute, "modules.info_gathering.traceroute_desc"))
    return menu
