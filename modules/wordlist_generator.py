"""Password wordlist generators."""
from __future__ import annotations

import itertools
from pathlib import Path

from rich.console import Console

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_input,
    pause,
    print_error,
    print_info,
    print_success,
)

console = Console()

LEET_MAP = {
    "a": ["a", "A", "4", "@"],
    "b": ["b", "B", "8"],
    "e": ["e", "E", "3"],
    "g": ["g", "G", "9"],
    "i": ["i", "I", "1", "!"],
    "l": ["l", "L", "1"],
    "o": ["o", "O", "0"],
    "s": ["s", "S", "5", "$"],
    "t": ["t", "T", "7"],
    "z": ["z", "Z", "2"],
}

YEAR_SUFFIXES = [str(y) for y in range(1960, 2031)]
SHORT_SUFFIXES = ["", "1", "12", "123", "1234", "!", "!!", "!@#", "2024", "2025", "2026"]


def _nonempty(prompt: str) -> str:
    value = ask_input(prompt, default="")
    return value.strip()


def _write_wordlist(words: set[str], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(sorted(words)) + "\n", encoding="utf-8")


def cupp_like() -> None:
    first = _nonempty(t("modules.wordlist.cupp_first_name"))
    last = _nonempty(t("modules.wordlist.cupp_last_name"))
    nick = _nonempty(t("modules.wordlist.cupp_nickname"))
    birthday = _nonempty(t("modules.wordlist.cupp_birthday"))
    partner = _nonempty(t("modules.wordlist.cupp_partner"))
    pet = _nonempty(t("modules.wordlist.cupp_pet"))
    company = _nonempty(t("modules.wordlist.cupp_company"))
    keywords = _nonempty(t("modules.wordlist.cupp_keywords"))
    output_path = Path(ask_input(t("ui.output_file"), default="wordlist.txt"))

    base_words = {w for w in [first, last, nick, partner, pet, company] if w}
    for kw in (k.strip() for k in keywords.split(",") if k.strip()):
        base_words.add(kw)

    # Case variants
    cased: set[str] = set()
    for word in base_words:
        cased.update({word, word.lower(), word.upper(), word.capitalize()})

    # Pair combinations (first+last etc.)
    combined: set[str] = set(cased)
    for a, b in itertools.permutations(cased, 2):
        combined.add(a + b)

    # Suffix with birthday parts and years
    final: set[str] = set(combined)
    suffixes = list(SHORT_SUFFIXES)
    if birthday:
        if len(birthday) >= 4:
            suffixes.append(birthday)
            suffixes.append(birthday[-4:])
            suffixes.append(birthday[-2:])
    suffixes.extend(YEAR_SUFFIXES)

    for word in combined:
        for suffix in suffixes:
            final.add(word + suffix)

    _write_wordlist(final, output_path)
    print_success(
        t("modules.wordlist.wordlist_saved", count=len(final), path=output_path)
    )
    pause()


def combinator() -> None:
    left_path = Path(ask_input("Left wordlist"))
    right_path = Path(ask_input("Right wordlist"))
    output_path = Path(ask_input(t("ui.output_file"), default="combined.txt"))
    if not left_path.is_file() or not right_path.is_file():
        print_error(t("ui.required"))
        pause()
        return
    left_words = [w.strip() for w in left_path.read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    right_words = [w.strip() for w in right_path.read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    combined = {a + b for a in left_words for b in right_words}
    _write_wordlist(combined, output_path)
    print_success(
        t("modules.wordlist.wordlist_saved", count=len(combined), path=output_path)
    )
    pause()


def _leet_variants(word: str, limit: int = 200) -> set[str]:
    positions = [LEET_MAP.get(ch.lower(), [ch]) for ch in word]
    out: set[str] = set()
    for combo in itertools.product(*positions):
        out.add("".join(combo))
        if len(out) >= limit:
            break
    return out


def rule_mutator() -> None:
    input_path = Path(ask_input(t("ui.input_file")))
    if not input_path.is_file():
        print_error(t("ui.required"))
        pause()
        return
    output_path = Path(ask_input(t("ui.output_file"), default="mutated.txt"))
    per_word_s = ask_input("Max variants per word", default="50")
    try:
        per_word = max(1, min(500, int(per_word_s)))
    except ValueError:
        per_word = 50
    words = [w.strip() for w in input_path.read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    mutated: set[str] = set()
    for word in words:
        mutated.update(_leet_variants(word, per_word))
        for suffix in SHORT_SUFFIXES:
            mutated.add(word + suffix)
            mutated.add(word.capitalize() + suffix)
    _write_wordlist(mutated, output_path)
    print_success(
        t("modules.wordlist.wordlist_saved", count=len(mutated), path=output_path)
    )
    pause()


def pattern_generator() -> None:
    charset = ask_input(t("modules.wordlist.charset"), default="abcdefghijklmnopqrstuvwxyz0123456789")
    min_s = ask_input(t("modules.wordlist.min_length"), default="3")
    max_s = ask_input(t("modules.wordlist.max_length"), default="4")
    output_path = Path(ask_input(t("ui.output_file"), default="patterns.txt"))
    try:
        min_len = max(1, int(min_s))
        max_len = max(min_len, int(max_s))
    except ValueError:
        print_error(t("ui.invalid_choice"))
        pause()
        return
    if len(charset) ** max_len > 5_000_000:
        print_error("Too many combinations - lower the length or charset size.")
        pause()
        return
    count = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                fh.write("".join(combo) + "\n")
                count += 1
    print_success(
        t("modules.wordlist.wordlist_saved", count=count, path=output_path)
    )
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.wordlist.title", parent=parent)
    menu.add(MenuItem("modules.wordlist.cupp", cupp_like, "modules.wordlist.cupp_desc"))
    menu.add(MenuItem("modules.wordlist.combinator", combinator, "modules.wordlist.combinator_desc"))
    menu.add(MenuItem("modules.wordlist.rule_mutator", rule_mutator, "modules.wordlist.rule_mutator_desc"))
    menu.add(MenuItem("modules.wordlist.crunch_wrapper", pattern_generator, "modules.wordlist.crunch_wrapper_desc"))
    return menu
