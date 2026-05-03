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
from gui import engine as _engine

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


def cli_log(msg: str, style: str = "info") -> None:
    """Simple logger for CLI-based engine calls."""
    style_map = {"ok": "green", "err": "red", "warn": "yellow",
                 "cyan": "cyan", "accent": "red", "muted": "dim"}
    rich_style = style_map.get(style, "white")
    console.print(f"[{rich_style}]{msg}[/]")


def _run_cli_automation(root: Menu) -> None:
    menu = Menu(title_key="menu.main.automation", parent=root)
    menu.add(MenuItem("modules.automation.attack_chain", lambda: (
        _engine.attack_chain(
            ask_input(t("ui.target")),
            [s.strip() for s in ask_input(t("modules.automation.chain_steps")).split(",")],
            cli_log) or pause())))
    menu.add(MenuItem("modules.automation.risk_correlator", lambda: (
        _engine.auto_correlate(cli_log) or pause())))
    menu.add(MenuItem("modules.automation.smart_payload", lambda: (
        _engine.smart_payload_gen(
            ask_input(t("ui.payload")),
            ask_input(t("modules.automation.waf_type") + " [cloudflare/modsecurity/aws/generic]"),
            cli_log) or pause())))
    menu.add(MenuItem("modules.automation.executive_report", lambda: (
        _engine.executive_report(ask_input(t("ui.target")), cli_log) or pause())))
    menu.run()


def _run_cli_stealth(root: Menu) -> None:
    menu = Menu(title_key="menu.main.stealth", parent=root)
    menu.add(MenuItem("modules.stealth.proxy_config", lambda: (
        _engine.set_proxy(ask_input(t("modules.stealth.proxy_url")), cli_log) or pause())))
    menu.add(MenuItem("modules.stealth.ua_rotation", lambda: (
        _engine.ua_rotation_demo(
            ask_input(t("ui.url")),
            int(ask_input(t("modules.stealth.count") + " [10]") or "10"),
            cli_log) or pause())))
    menu.add(MenuItem("modules.stealth.throttled_requests", lambda: (
        _engine.throttled_requests(
            ask_input(t("ui.url")),
            int(ask_input(t("modules.stealth.count") + " [20]") or "20"),
            float(ask_input(t("modules.stealth.min_delay") + " [1.0]") or "1.0"),
            float(ask_input(t("modules.stealth.max_delay") + " [3.0]") or "3.0"),
            cli_log) or pause())))
    menu.add(MenuItem("modules.stealth.waf_bypass", lambda: (
        _engine.waf_bypass_test(
            ask_input(t("ui.url")),
            ask_input(t("ui.payload")),
            ask_input(t("modules.stealth.waf_type") + " [generic]") or "generic",
            cli_log) or pause())))
    menu.run()


def _run_cli_integrations(root: Menu) -> None:
    menu = Menu(title_key="menu.main.integrations", parent=root)
    menu.add(MenuItem("modules.integrations.nmap_import", lambda: (
        _engine.nmap_import(ask_input(t("modules.integrations.xml_path")), cli_log) or pause())))
    menu.add(MenuItem("modules.integrations.nuclei_run", lambda: (
        _engine.nuclei_run(
            ask_input(t("ui.target")),
            ask_input(t("modules.integrations.templates_path")),
            cli_log) or pause())))
    menu.add(MenuItem("modules.integrations.shodan_lookup", lambda: (
        _engine.shodan_lookup(
            ask_input(t("ui.target")),
            ask_input(t("modules.integrations.api_key")),
            cli_log) or pause())))
    menu.add(MenuItem("modules.integrations.msf_rpc", lambda: (
        _engine.msf_rpc_check(
            ask_input(t("ui.host")),
            int(ask_input(t("ui.port") + " [55553]") or "55553"),
            ask_input(t("modules.integrations.msf_token")),
            cli_log) or pause())))
    menu.run()


def _run_cli_email_defense(root: Menu) -> None:
    menu = Menu(title_key="menu.main.email_defense", parent=root)
    menu.add(MenuItem("modules.email_defense.spf_dkim_dmarc", lambda: (
        _engine.email_security_check(ask_input(t("ui.domain")), cli_log) or pause())))
    menu.add(MenuItem("modules.email_defense.header_analyzer", lambda: (
        _engine.email_header_analyze(ask_input(t("modules.email_defense.headers")), cli_log) or pause())))
    menu.add(MenuItem("modules.email_defense.homoglyph_detect", lambda: (
        _engine.homoglyph_detect(ask_input(t("ui.domain")), cli_log) or pause())))
    menu.add(MenuItem("modules.email_defense.phishing_url", lambda: (
        _engine.phishing_url_analyze(ask_input(t("ui.url")), cli_log) or pause())))
    menu.run()


def _run_cli_mobile_iot(root: Menu) -> None:
    menu = Menu(title_key="menu.main.mobile_iot", parent=root)
    menu.add(MenuItem("modules.mobile_iot.apk_analyzer", lambda: (
        _engine.apk_analyze(ask_input(t("modules.mobile_iot.apk_path")), cli_log) or pause())))
    menu.add(MenuItem("modules.mobile_iot.mqtt_tester", lambda: (
        _engine.mqtt_test(
            ask_input(t("modules.mobile_iot.broker")),
            int(ask_input(t("ui.port") + " [1883]") or "1883"),
            cli_log) or pause())))
    menu.add(MenuItem("modules.mobile_iot.firmware_strings", lambda: (
        _engine.firmware_strings(
            ask_input(t("ui.file_path")),
            int(ask_input(t("modules.mobile_iot.min_length") + " [6]") or "6"),
            cli_log) or pause())))
    menu.add(MenuItem("modules.mobile_iot.upnp_scanner", lambda: (
        _engine.upnp_scan(cli_log) or pause())))
    menu.run()


def _run_cli_blue_team(root: Menu) -> None:
    menu = Menu(title_key="menu.main.blue_team", parent=root)
    menu.add(MenuItem("modules.blue_team.honeypot_detect", lambda: (
        _engine.honeypot_detect(ask_input(t("ui.host")), [], cli_log) or pause())))
    menu.add(MenuItem("modules.blue_team.log_analyzer", lambda: (
        _engine.log_analyze(ask_input(t("modules.blue_team.log_text")), cli_log) or pause())))
    menu.add(MenuItem("modules.blue_team.yara_scanner", lambda: (
        _engine.yara_scan(
            ask_input(t("ui.file_path")),
            ask_input(t("modules.blue_team.rules_path")),
            cli_log) or pause())))
    menu.add(MenuItem("modules.blue_team.baseline_snapshot", lambda: (
        _engine.baseline_snapshot(cli_log) or pause())))
    menu.run()


def _run_cli_compliance(root: Menu) -> None:
    menu = Menu(title_key="menu.main.compliance", parent=root)
    menu.add(MenuItem("modules.compliance.owasp_map", lambda: (
        _engine.owasp_map([], cli_log) or pause())))
    menu.add(MenuItem("modules.compliance.pci_dss", lambda: (
        _engine.pci_dss_check(ask_input(t("ui.target")), cli_log) or pause())))
    menu.add(MenuItem("modules.compliance.cis_benchmark", lambda: (
        _engine.cis_benchmark(
            ask_input(t("modules.compliance.platform") + " [Windows/Linux]") or "Linux",
            cli_log) or pause())))
    menu.run()


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
        "menu.main.automation",
        lambda: _run_cli_automation(root),
        "menu.main.automation_desc", color="red"))
    root.add(MenuItem(
        "menu.main.stealth",
        lambda: _run_cli_stealth(root),
        "menu.main.stealth_desc", color="red"))
    root.add(MenuItem(
        "menu.main.integrations",
        lambda: _run_cli_integrations(root),
        "menu.main.integrations_desc", color="red"))
    root.add(MenuItem(
        "menu.main.email_defense",
        lambda: _run_cli_email_defense(root),
        "menu.main.email_defense_desc", color="red"))
    root.add(MenuItem(
        "menu.main.mobile_iot",
        lambda: _run_cli_mobile_iot(root),
        "menu.main.mobile_iot_desc", color="red"))
    root.add(MenuItem(
        "menu.main.blue_team",
        lambda: _run_cli_blue_team(root),
        "menu.main.blue_team_desc", color="red"))
    root.add(MenuItem(
        "menu.main.compliance",
        lambda: _run_cli_compliance(root),
        "menu.main.compliance_desc", color="red"))
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
