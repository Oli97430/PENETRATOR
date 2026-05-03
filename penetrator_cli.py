"""PENETRATOR - entry point.

Usage:
    python penetrator.py

A Windows-friendly penetration testing toolkit inspired by Z4nzu/hackingtool.
"""
from __future__ import annotations

import os
import sys

# Ensure the project root is importable when launched from anywhere
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Force UTF-8 on Windows so Chinese/accents render correctly
if os.name == "nt":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.banner import show_banner, VERSION
from core.i18n import I18n, t
from core.menu import Menu, MenuItem
from core.utils import ask_input, pause, print_error, print_info, print_success

from modules import (
    information_gathering,
    wordlist_generator,
    sql_injection,
    web_attacks,
    api_security,
    password_tools,
    crypto_tools,
    cloud_security,
    steganography,
    xss_tools,
    reverse_engineering,
    forensic_tools,
    payload_generator,
    osint_tools,
)

console = Console()


def about_screen() -> None:
    show_banner(console)
    table = Table(border_style="cyan", show_header=False, box=None)
    table.add_column(style="cyan bold", justify="right")
    table.add_column(style="white")
    table.add_row("PENETRATOR", f"v{VERSION}")
    table.add_row("Description", t("modules.about.description"))
    table.add_row("License", t("modules.about.license"))
    table.add_row("Author", t("modules.about.author"))
    console.print(Panel(
        table,
        title=f"[bold red]{t('modules.about.title')}[/]",
        border_style="red",
    ))
    console.print(
        Panel(
            f"[yellow]{t('modules.about.disclaimer')}[/]",
            border_style="yellow",
            title="[bold yellow]!!![/]",
        )
    )
    pause()


def language_menu(parent: Menu) -> None:
    i18n = I18n.get()
    while True:
        show_banner(console)
        table = Table(border_style="cyan", show_header=False, box=None)
        table.add_column(style="cyan bold", justify="right", width=4)
        table.add_column(style="white bold")
        for idx, code in enumerate(("en", "fr", "zh"), start=1):
            marker = " ←" if code == i18n.language else ""
            table.add_row(f"[{idx}]", f"{t(f'menu.language.{code}')}{marker}")
        table.add_row("[0]", f"[red]{t('ui.back')}[/]")
        console.print(Panel(
            table,
            title=f"[bold]{t('menu.language.title')}[/]",
            border_style="cyan",
        ))
        choice = console.input(f"[bold cyan]{t('ui.choose_option')} > [/]").strip()
        if choice == "0":
            return
        mapping = {"1": "en", "2": "fr", "3": "zh"}
        if choice in mapping:
            i18n.save_preferred(mapping[choice])
            print_success(t("menu.language.saved"))
            pause()
            return
        print_error(t("ui.invalid_choice"))
        pause()


def build_settings_menu(parent: Menu) -> Menu:
    menu = Menu(title_key="menu.settings.title", parent=parent)
    menu.add(MenuItem("menu.settings.change_language",
                      lambda: language_menu(menu)))
    return menu


def build_main_menu() -> Menu:
    root = Menu(title_key="menu.main.title")
    root.add(MenuItem(
        "menu.main.info_gathering",
        lambda: information_gathering.build_menu(root).run(),
        "menu.main.info_gathering_desc", color="red"))
    root.add(MenuItem(
        "menu.main.wordlist",
        lambda: wordlist_generator.build_menu(root).run(),
        "menu.main.wordlist_desc", color="red"))
    root.add(MenuItem(
        "menu.main.sql_injection",
        lambda: sql_injection.build_menu(root).run(),
        "menu.main.sql_injection_desc", color="red"))
    root.add(MenuItem(
        "menu.main.web_attacks",
        lambda: web_attacks.build_menu(root).run(),
        "menu.main.web_attacks_desc", color="red"))
    root.add(MenuItem(
        "menu.main.api_security",
        lambda: api_security.build_menu(root).run(),
        "menu.main.api_security_desc", color="red"))
    root.add(MenuItem(
        "menu.main.password_tools",
        lambda: password_tools.build_menu(root).run(),
        "menu.main.password_tools_desc", color="red"))
    root.add(MenuItem(
        "menu.main.crypto_tools",
        lambda: crypto_tools.build_menu(root).run(),
        "menu.main.crypto_tools_desc", color="red"))
    root.add(MenuItem(
        "menu.main.cloud_security",
        lambda: cloud_security.build_menu(root).run(),
        "menu.main.cloud_security_desc", color="red"))
    root.add(MenuItem(
        "menu.main.steganography",
        lambda: steganography.build_menu(root).run(),
        "menu.main.steganography_desc", color="red"))
    root.add(MenuItem(
        "menu.main.xss_tools",
        lambda: xss_tools.build_menu(root).run(),
        "menu.main.xss_tools_desc", color="red"))
    root.add(MenuItem(
        "menu.main.reverse_engineering",
        lambda: reverse_engineering.build_menu(root).run(),
        "menu.main.reverse_engineering_desc", color="red"))
    root.add(MenuItem(
        "menu.main.forensic",
        lambda: forensic_tools.build_menu(root).run(),
        "menu.main.forensic_desc", color="red"))
    root.add(MenuItem(
        "menu.main.payload",
        lambda: payload_generator.build_menu(root).run(),
        "menu.main.payload_desc", color="red"))
    root.add(MenuItem(
        "menu.main.osint",
        lambda: osint_tools.build_menu(root).run(),
        "menu.main.osint_desc", color="red"))
    root.add(MenuItem(
        "menu.main.settings",
        lambda: build_settings_menu(root).run(),
        "menu.main.settings_desc", color="cyan"))
    root.add(MenuItem(
        "menu.main.about", about_screen,
        "menu.main.about_desc", color="cyan"))
    return root


def first_run_language_picker() -> None:
    """If config.json is absent, ask for language right away."""
    i18n = I18n.get()
    if i18n.config_path.exists():
        return
    show_banner(console)
    console.print(Panel(
        "[bold]Select your language[/]  /  [bold]Choisissez votre langue[/]  /  [bold]请选择语言[/]\n\n"
        "[cyan]1[/]  English\n"
        "[cyan]2[/]  Français\n"
        "[cyan]3[/]  中文",
        border_style="cyan",
    ))
    choice = console.input("> ").strip()
    mapping = {"1": "en", "2": "fr", "3": "zh"}
    i18n.save_preferred(mapping.get(choice, "en"))


def main() -> int:
    try:
        first_run_language_picker()
        build_main_menu().run()
    except KeyboardInterrupt:
        console.print(f"\n[yellow]{t('ui.interrupted')}[/]")
    console.print(f"[bold green]{t('ui.finished')}[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
