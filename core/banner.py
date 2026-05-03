"""ASCII banner for PENETRATOR."""
from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.i18n import t

BANNER = r"""
 ____  _____ _   _ _____ _____ ____      _  _____ ___  ____
|  _ \| ____| \ | | ____|_   _|  _ \    / \|_   _/ _ \|  _ \
| |_) |  _| |  \| |  _|   | | | |_) |  / _ \ | || | | | |_) |
|  __/| |___| |\  | |___  | | |  _ <  / ___ \| || |_| |  _ <
|_|   |_____|_| \_|_____| |_| |_| \_\/_/   \_\_| \___/|_| \_\
"""

VERSION = "1.6.0"
AUTHOR = "Tarraw974@gmail.com"


def show_banner(console: Console | None = None) -> None:
    console = console or Console()
    console.clear()
    text = Text(BANNER, style="bold red")
    subtitle = Text.assemble(
        (t("app.tagline"), "bold white"),
        ("  |  ", "dim"),
        (f"v{VERSION}", "cyan"),
        ("  |  ", "dim"),
        (t("app.language_label", lang=t("app.language_name")), "yellow"),
    )
    panel = Panel(
        Align.center(Text.assemble(text, "\n", subtitle)),
        border_style="red",
        title="[bold white]PENETRATOR[/]",
        subtitle=f"[dim]{t('app.subtitle')}[/]",
        padding=(0, 2),
    )
    console.print(panel)
    console.print()
