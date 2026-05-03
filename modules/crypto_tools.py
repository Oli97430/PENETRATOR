"""Crypto & TLS tools: cipher grading, RSA analysis, CT monitoring."""
from __future__ import annotations

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import ask_input, pause, print_error
from core.cli_bridge import cli_log
from gui import engine as E


def cipher_grade_cli() -> None:
    host = ask_input(t("ui.host"))
    if not host:
        return
    port_s = ask_input(t("ui.port"), default="443")
    try:
        E.cipher_suite_grade(host, int(port_s), cli_log)
    except ValueError:
        print_error(t("ui.invalid_choice"))
    pause()


def rsa_analyze_cli() -> None:
    print("Paste RSA public key (PEM), end with empty line:")
    lines: list[str] = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    if lines:
        E.rsa_key_analyze("\n".join(lines), cli_log)
    pause()


def ct_monitor_cli() -> None:
    domain = ask_input(t("ui.domain"))
    if domain:
        E.ct_monitor(domain, cli_log)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.crypto_tools.title", parent=parent)
    menu.add(MenuItem("modules.crypto_tools.cipher_grade", cipher_grade_cli,
                      "modules.crypto_tools.cipher_grade_desc"))
    menu.add(MenuItem("modules.crypto_tools.rsa_analyze", rsa_analyze_cli,
                      "modules.crypto_tools.rsa_analyze_desc"))
    menu.add(MenuItem("modules.crypto_tools.ct_monitor", ct_monitor_cli,
                      "modules.crypto_tools.ct_monitor_desc"))
    return menu
