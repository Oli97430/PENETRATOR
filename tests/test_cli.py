"""Smoke tests for the classic CLI: banner, menus, i18n."""
from __future__ import annotations

import io

from core.banner import VERSION, show_banner
from core.i18n import I18n, t
from core.menu import Menu, MenuItem


def test_version_format():
    assert isinstance(VERSION, str)
    parts = VERSION.split(".")
    assert len(parts) == 3
    for p in parts:
        assert p.isdigit()


def test_banner_renders():
    """Render the banner to a string buffer to confirm it doesn't crash."""
    from rich.console import Console

    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=False)
    show_banner(console)
    out = buf.getvalue()
    assert "PENETRATOR" in out
    assert VERSION in out


def test_i18n_singleton():
    a = I18n.get()
    b = I18n.get()
    assert a is b
    assert a.language in I18n.SUPPORTED


def test_translate_known_keys():
    for key in ("menu.main.title", "ui.run", "ui.back",
                "modules.info_gathering.port_scan"):
        assert isinstance(t(key), str) and t(key)


def test_translate_unknown_key_returns_key():
    assert t("does.not.exist.anywhere") == "does.not.exist.anywhere"


def test_menu_instantiation():
    menu = Menu(
        title_key="menu.main.title",
        items=[
            MenuItem(label_key="menu.main.info_gathering"),
            MenuItem(label_key="menu.main.about"),
        ],
    )
    assert menu.title_key == "menu.main.title"
    assert len(menu.items) == 2
