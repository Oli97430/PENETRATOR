"""Cloud & infrastructure tools: S3, Azure, Git exposure, Firebase, LDAP, SMB, Kerberos."""
from __future__ import annotations

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import ask_input, pause, print_error
from core.cli_bridge import cli_log
from gui import engine as E


def s3_enum_cli() -> None:
    domain = ask_input(t("ui.domain"))
    if domain:
        E.s3_bucket_enum(domain, cli_log)
    pause()


def azure_blob_cli() -> None:
    domain = ask_input(t("ui.domain"))
    if domain:
        E.azure_blob_check(domain, cli_log)
    pause()


def git_exposure_cli() -> None:
    url = ask_input(t("ui.url"))
    if url:
        E.git_exposure_check(url, cli_log)
    pause()


def firebase_cli() -> None:
    target = ask_input(t("ui.target"))
    if target:
        E.firebase_scan(target, cli_log)
    pause()


def ldap_cli() -> None:
    host = ask_input(t("ui.host"))
    if not host:
        return
    port_s = ask_input(t("ui.port"), default="389")
    try:
        E.ldap_anonymous_check(host, int(port_s), cli_log)
    except ValueError:
        print_error(t("ui.invalid_choice"))
    pause()


def smb_cli() -> None:
    host = ask_input(t("ui.host"))
    if host:
        E.smb_enum(host, cli_log)
    pause()


def kerberos_cli() -> None:
    host = ask_input(t("ui.host"))
    if not host:
        return
    domain = ask_input(t("modules.network_attacks.ad_domain"))
    if not domain:
        return
    users_text = ask_input(t("modules.network_attacks.userlist"))
    users = [u.strip() for u in users_text.split(",") if u.strip()] if users_text else []
    if not users:
        users = ["administrator", "admin", "guest", "krbtgt", "user",
                 "test", "service", "backup", "svc_sql", "svc_web"]
    E.kerberos_enum(host, domain, users, cli_log)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.cloud_security.title", parent=parent)
    menu.add(MenuItem("modules.cloud_security.s3_enum", s3_enum_cli,
                      "modules.cloud_security.s3_enum_desc"))
    menu.add(MenuItem("modules.cloud_security.azure_blob", azure_blob_cli,
                      "modules.cloud_security.azure_blob_desc"))
    menu.add(MenuItem("modules.cloud_security.git_exposure", git_exposure_cli,
                      "modules.cloud_security.git_exposure_desc"))
    menu.add(MenuItem("modules.cloud_security.firebase_scan", firebase_cli,
                      "modules.cloud_security.firebase_scan_desc"))
    menu.add(MenuItem("modules.network_attacks.ldap_anon", ldap_cli,
                      "modules.network_attacks.ldap_anon_desc"))
    menu.add(MenuItem("modules.network_attacks.smb_enum", smb_cli,
                      "modules.network_attacks.smb_enum_desc"))
    menu.add(MenuItem("modules.network_attacks.kerberos_enum", kerberos_cli,
                      "modules.network_attacks.kerberos_enum_desc"))
    return menu
