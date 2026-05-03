"""Password analysis and dictionary cracking."""
from __future__ import annotations

import hashlib
import re
import secrets
import string
from pathlib import Path

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


HASH_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("MD5",                re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("SHA-1",              re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("SHA-224",            re.compile(r"^[a-f0-9]{56}$", re.I)),
    ("SHA-256",            re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA-384",            re.compile(r"^[a-f0-9]{96}$", re.I)),
    ("SHA-512",            re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("NTLM",               re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("bcrypt",             re.compile(r"^\$2[abxy]\$\d+\$.{53}$")),
    ("Argon2",             re.compile(r"^\$argon2(id|i|d)\$")),
    ("SHA-512 crypt",      re.compile(r"^\$6\$")),
    ("SHA-256 crypt",      re.compile(r"^\$5\$")),
    ("MD5 crypt",          re.compile(r"^\$1\$")),
    ("MySQL <4.1",         re.compile(r"^[a-f0-9]{16}$", re.I)),
    ("MySQL 4.1+",         re.compile(r"^\*[A-F0-9]{40}$")),
    ("LM hash",            re.compile(r"^[a-f0-9]{32}$", re.I)),
]

SUPPORTED_ALGOS = {
    "md5": lambda b: hashlib.md5(b).hexdigest(),
    "sha1": lambda b: hashlib.sha1(b).hexdigest(),
    "sha224": lambda b: hashlib.sha224(b).hexdigest(),
    "sha256": lambda b: hashlib.sha256(b).hexdigest(),
    "sha384": lambda b: hashlib.sha384(b).hexdigest(),
    "sha512": lambda b: hashlib.sha512(b).hexdigest(),
}


def hash_identifier() -> None:
    value = ask_input(t("modules.password_tools.hash_value")).strip()
    if not value:
        return
    matches = [name for name, pattern in HASH_SIGNATURES if pattern.match(value)]
    # MD5 and NTLM/LM collide on length; flag the collision for the user.
    if "MD5" in matches and "NTLM" in matches and "LM hash" in matches:
        matches = ["MD5 / NTLM / LM (32 hex chars, context-dependent)"]
    if matches:
        print_success(t("modules.password_tools.possible_types", types=", ".join(matches)))
    else:
        print_warning(t("ui.no_results"))
    pause()


def hash_cracker() -> None:
    value = ask_input(t("modules.password_tools.hash_value")).strip().lower()
    if not value:
        return
    algo = ask_input(
        f"{t('modules.password_tools.hash_algo')} ({', '.join(SUPPORTED_ALGOS)})",
        default="md5",
    ).strip().lower()
    if algo not in SUPPORTED_ALGOS:
        print_error(t("ui.invalid_choice"))
        pause()
        return
    wordlist_path = Path(ask_input(t("ui.input_file")))
    if not wordlist_path.is_file():
        print_error(t("ui.required"))
        pause()
        return

    hasher = SUPPORTED_ALGOS[algo]
    found: str | None = None
    tried = 0
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            tried += 1
            if hasher(candidate.encode("utf-8", errors="ignore")) == value:
                found = candidate
                break

    if found is not None:
        print_success(t("modules.password_tools.found_match", password=found))
    else:
        print_warning(t("modules.password_tools.not_found"))
    print_info(f"Tried: {tried}")
    pause()


def _score_password(pw: str) -> tuple[int, str]:
    score = 0
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 12:
        score += 1
    if re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw):
        score += 1
    if re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw):
        score += 1
    label_map = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong"}
    return score, label_map[score]


def strength_meter() -> None:
    pw = ask_input("Password", password=True)
    if not pw:
        return
    score, label = _score_password(pw)
    print_info(t("modules.password_tools.strength_score", score=score, label=label))
    pause()


def gen_secure_password() -> None:
    length_s = ask_input(t("modules.password_tools.length"), default="16")
    try:
        length = max(4, min(128, int(length_s)))
    except ValueError:
        length = 16
    use_upper = ask_confirm(t("modules.password_tools.include_upper"), default=True)
    use_digits = ask_confirm(t("modules.password_tools.include_digits"), default=True)
    use_symbols = ask_confirm(t("modules.password_tools.include_symbols"), default=True)

    alphabet = string.ascii_lowercase
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"

    password = "".join(secrets.choice(alphabet) for _ in range(length))
    score, label = _score_password(password)

    table = Table(border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Password", password)
    table.add_row("Length", str(length))
    table.add_row("Strength", f"{score}/4 ({label})")
    console.print(table)
    pause()


# ---------------------------------------------------------------------------
# Engine-backed CLI tools (parity with GUI)
# ---------------------------------------------------------------------------
from core.cli_bridge import cli_log  # noqa: E402
from gui import engine as E          # noqa: E402


def hibp_check_cli() -> None:
    pw = ask_input(t("ui.password"))
    if pw:
        E.hibp_password_check(pw, cli_log)
    pause()


def jwt_decode_cli() -> None:
    tok = ask_input(t("modules.password_tools.jwt_token"))
    if tok:
        E.jwt_decode(tok, cli_log)
    pause()


def jwt_brute_cli() -> None:
    tok = ask_input(t("modules.password_tools.jwt_token"))
    if not tok:
        return
    wl = ask_input(t("ui.wordlist_path"))
    if wl:
        E.jwt_brute(tok, wl, cli_log)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.password_tools.title", parent=parent)
    menu.add(MenuItem("modules.password_tools.hash_identifier", hash_identifier,
                      "modules.password_tools.hash_identifier_desc"))
    menu.add(MenuItem("modules.password_tools.hash_cracker", hash_cracker,
                      "modules.password_tools.hash_cracker_desc"))
    menu.add(MenuItem("modules.password_tools.strength", strength_meter,
                      "modules.password_tools.strength_desc"))
    menu.add(MenuItem("modules.password_tools.gen_secure", gen_secure_password,
                      "modules.password_tools.gen_secure_desc"))
    menu.add(MenuItem("modules.password_tools.hibp", hibp_check_cli,
                      "modules.password_tools.hibp_desc"))
    menu.add(MenuItem("modules.password_tools.jwt_decode", jwt_decode_cli,
                      "modules.password_tools.jwt_decode_desc"))
    menu.add(MenuItem("modules.password_tools.jwt_brute", jwt_brute_cli,
                      "modules.password_tools.jwt_brute_desc"))
    return menu
