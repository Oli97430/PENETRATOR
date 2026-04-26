"""Shared helpers: console I/O, command execution, prompts."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Iterable

from rich.console import Console
from rich.prompt import Confirm, Prompt

from core.i18n import t

console = Console()


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    console.print(f"\n[dim]{t('ui.press_enter')}[/]", end="")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def print_success(message: str) -> None:
    console.print(f"[bold green][+][/] {message}")


def print_error(message: str) -> None:
    console.print(f"[bold red][-][/] {message}")


def print_warning(message: str) -> None:
    console.print(f"[bold yellow][!][/] {message}")


def print_info(message: str) -> None:
    console.print(f"[bold cyan][*][/] {message}")


def ask_input(prompt: str, default: str | None = None, password: bool = False) -> str:
    return Prompt.ask(f"[bold cyan]?[/] {prompt}", default=default, password=password)


def ask_confirm(prompt: str, default: bool = False) -> bool:
    return Confirm.ask(f"[bold cyan]?[/] {prompt}", default=default)


def check_command_exists(command: str) -> bool:
    """True if an executable is in ``PATH``."""
    return shutil.which(command) is not None


def run_command(
    command: str | list[str],
    *,
    shell: bool = False,
    capture: bool = False,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess, streaming or capturing output.

    When ``capture`` is False, output streams live to the terminal and a
    ``CompletedProcess`` with empty ``stdout``/``stderr`` is returned.
    """
    if isinstance(command, list) and shell:
        command = " ".join(command)
    return subprocess.run(
        command,
        shell=shell,
        capture_output=capture,
        text=True,
        cwd=cwd,
        env=env,
        check=False,
    )


def require_tools(tools: Iterable[str]) -> list[str]:
    """Return the subset of ``tools`` that is missing from ``PATH``."""
    return [tool for tool in tools if not check_command_exists(tool)]


def open_url(url: str) -> None:
    """Open a URL in the default browser (Windows-friendly)."""
    import webbrowser

    webbrowser.open(url)


def get_python() -> str:
    """Return the current Python executable path (handles venvs)."""
    return sys.executable or "python"
