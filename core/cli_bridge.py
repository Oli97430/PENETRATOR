"""Adapter so CLI menus can call ``gui.engine.*`` functions.

The engine speaks via a ``log(msg, tag)`` callback. The CLI prints with Rich
colors. This module ships:

- :func:`cli_log` — a Logger-compatible callable.
- :func:`run_engine` — convenience wrapper that prompts via ``ask_input`` then
  calls a one-shot engine function.
"""
from __future__ import annotations

from typing import Any, Callable

from rich.console import Console

console = Console()

# Severity tag → Rich color
_TAG_COLORS = {
    "info": "white",
    "ok": "bold green",
    "warn": "yellow",
    "err": "bold red",
    "accent": "bold magenta",
    "cyan": "cyan",
    "muted": "bright_black",
}


def cli_log(msg: str, tag: str = "info") -> None:
    """Logger-compatible callable: routes engine messages to the Rich console."""
    style = _TAG_COLORS.get(tag, "white")
    try:
        console.print(msg, style=style)
    except Exception:
        # Fallback to plain print if Rich chokes (rare)
        print(msg)


def run_with_log(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Call ``fn(*args, log=cli_log, **kwargs)`` — engine functions take the
    log callback as their last positional argument; pass it explicitly here."""
    return fn(*args, cli_log, **kwargs)
