"""API security tools: Swagger discovery, auth testing, rate limits."""
from __future__ import annotations

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import ask_input, pause, print_error
from core.cli_bridge import cli_log
from gui import engine as E


def swagger_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.swagger_discovery(url, cli_log)
    pause()


def broken_auth_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    token = ask_input(t("modules.api_security.auth_token"), default="")
    E.broken_auth_test(url, token, cli_log)
    pause()


def mass_assign_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    method = ask_input(t("modules.web_attacks.method"), default="POST")
    body = ask_input(t("modules.api_security.base_body"), default="")
    E.mass_assignment_test(url, method, body, cli_log)
    pause()


def rate_limit_cli() -> None:
    url = ask_input(t("ui.url"))
    if not url:
        return
    count = ask_input(t("modules.web_attacks.request_count"), default="100")
    try:
        E.rate_limit_test(url, int(count), cli_log)
    except ValueError:
        print_error(t("ui.invalid_choice"))
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.api_security.title", parent=parent)
    menu.add(MenuItem("modules.api_security.swagger_disc", swagger_cli,
                      "modules.api_security.swagger_disc_desc"))
    menu.add(MenuItem("modules.api_security.broken_auth", broken_auth_cli,
                      "modules.api_security.broken_auth_desc"))
    menu.add(MenuItem("modules.api_security.mass_assign", mass_assign_cli,
                      "modules.api_security.mass_assign_desc"))
    menu.add(MenuItem("modules.api_security.rate_limit", rate_limit_cli,
                      "modules.api_security.rate_limit_desc"))
    return menu
