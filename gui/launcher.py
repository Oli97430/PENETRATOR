"""Ctrl+P quick launcher — fuzzy search over every tool."""
from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from core.i18n import t
from gui import theme as T
from gui.app import BOTTOM_CATEGORIES, CATEGORIES


def _tool_index() -> list[tuple[str, str]]:
    """Return list of (display_label, category_key) — one entry per top-level
    category. The launcher jumps to the category; from there the user types
    in the sidebar filter for finer-grained reach."""
    out: list[tuple[str, str]] = []
    for key, icon, label_k, _ in CATEGORIES + BOTTOM_CATEGORIES:
        out.append((f"{icon}  {t(label_k)}", key))
    return out


def _score(query: str, label: str) -> int:
    """Tiny fuzzy scoring: subsequence + adjacency bonus.
    Returns -1 if not a match."""
    if not query:
        return 1
    q = query.lower()
    s = label.lower()
    if q in s:
        return 1000 - s.index(q)
    # subsequence match
    qi = 0
    last = -2
    score = 0
    for i, c in enumerate(s):
        if qi < len(q) and c == q[qi]:
            score += 5 + (3 if i == last + 1 else 0)
            last = i
            qi += 1
    if qi != len(q):
        return -1
    return score


class QuickLauncher(ctk.CTkToplevel):
    """Modal command-palette."""

    MAX_RESULTS = 12

    def __init__(self, master, on_pick: Callable[[str], None]):
        super().__init__(master)
        self.on_pick = on_pick
        self.title("PENETRATOR — Quick Open")
        self.geometry("520x420")
        self.configure(fg_color=T.BG_DEEP)
        self.resizable(False, False)

        try:
            self.transient(master)
            self.grab_set()
        except Exception:
            pass

        self.entry_var = ctk.StringVar()
        self.entry_var.trace_add("write", lambda *_: self._refresh())

        entry = ctk.CTkEntry(
            self, textvariable=self.entry_var,
            placeholder_text="🔍  type to filter (Enter to open, Esc to close)",
            font=T.FONT_BODY, fg_color=T.BG_SURFACE,
            border_color=T.ACCENT, border_width=1,
            height=42, corner_radius=T.RADIUS_SM,
        )
        entry.pack(fill="x", padx=14, pady=(14, 8))
        entry.focus_set()

        self.list_frame = ctk.CTkScrollableFrame(
            self, fg_color=T.BG_BASE,
            scrollbar_button_color=T.BG_RAISED,
        )
        self.list_frame.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self.results: list[tuple[str, str]] = []
        self.selected = 0

        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Return>", self._activate)
        self.bind("<Down>", lambda _e: self._move(1))
        self.bind("<Up>", lambda _e: self._move(-1))

        self._refresh()

    def _refresh(self) -> None:
        for w in self.list_frame.winfo_children():
            w.destroy()

        q = self.entry_var.get().strip()
        scored = []
        for label, key in _tool_index():
            s = _score(q, label)
            if s >= 0:
                scored.append((s, label, key))
        scored.sort(reverse=True)
        self.results = [(label, key) for _, label, key in scored[:self.MAX_RESULTS]]

        if not self.results:
            ctk.CTkLabel(
                self.list_frame, text="No matches.",
                font=T.FONT_BODY, text_color=T.TEXT_DIM,
            ).pack(pady=20)
            return

        for i, (label, key) in enumerate(self.results):
            row = ctk.CTkButton(
                self.list_frame,
                text=f"   {label}",
                anchor="w",
                fg_color=T.ACCENT if i == self.selected else "transparent",
                hover_color=T.BG_RAISED,
                text_color=T.TEXT,
                font=T.FONT_BODY,
                height=32,
                corner_radius=T.RADIUS_SM,
                command=lambda k=key: self._pick(k),
            )
            row.pack(fill="x", padx=2, pady=1)

    def _move(self, delta: int) -> None:
        if not self.results:
            return
        self.selected = (self.selected + delta) % len(self.results)
        self._refresh()

    def _activate(self, _event=None) -> None:
        if self.results:
            self._pick(self.results[self.selected][1])

    def _pick(self, key: str) -> None:
        self.on_pick(key)
        self.destroy()
