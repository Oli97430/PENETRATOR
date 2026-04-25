"""Interactive menu system built on top of Rich."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.banner import show_banner
from core.i18n import t

console = Console()


@dataclass
class MenuItem:
    """A single menu entry.

    ``label_key`` is a translation key; ``action`` is a callable to invoke
    when the entry is chosen. A ``None`` action means "exit this menu".
    """

    label_key: str
    action: Callable[[], None] | None = None
    description_key: str | None = None
    color: str = "white"


@dataclass
class Menu:
    title_key: str
    items: list[MenuItem] = field(default_factory=list)
    back_label_key: str = "ui.back"
    parent: "Menu | None" = None
    show_banner_on_render: bool = True

    def add(self, item: MenuItem) -> "Menu":
        self.items.append(item)
        return self

    def render(self) -> None:
        if self.show_banner_on_render:
            show_banner(console)
        table = Table(
            show_header=False,
            show_edge=False,
            box=None,
            padding=(0, 2),
            expand=True,
        )
        table.add_column(justify="right", style="bold cyan", width=4)
        table.add_column(style="bold")
        table.add_column(style="dim")
        for idx, item in enumerate(self.items, start=1):
            label = t(item.label_key)
            desc = t(item.description_key) if item.description_key else ""
            table.add_row(f"[{idx}]", Text(label, style=item.color), desc)
        back_label = t(self.back_label_key) if self.parent else t("ui.exit")
        table.add_row("[0]", Text(back_label, style="bold red"), "")
        panel = Panel(
            table,
            title=f"[bold white]{t(self.title_key)}[/]",
            border_style="cyan",
            padding=(1, 1),
        )
        console.print(panel)

    def prompt(self) -> int | None:
        try:
            raw = console.input(f"[bold cyan]{t('ui.choose_option')} > [/]")
        except (EOFError, KeyboardInterrupt):
            return 0
        raw = raw.strip()
        if not raw.isdigit():
            return None
        value = int(raw)
        if value < 0 or value > len(self.items):
            return None
        return value

    def run(self) -> None:
        while True:
            self.render()
            choice = self.prompt()
            if choice is None:
                from core.utils import print_error, pause

                print_error(t("ui.invalid_choice"))
                pause()
                continue
            if choice == 0:
                return
            item = self.items[choice - 1]
            if item.action is None:
                return
            try:
                item.action()
            except KeyboardInterrupt:
                console.print(f"\n[yellow]{t('ui.interrupted')}[/]")
            except Exception as exc:  # surface unexpected errors, keep running
                from core.utils import print_error, pause

                print_error(f"{t('ui.unexpected_error')}: {exc}")
                pause()
