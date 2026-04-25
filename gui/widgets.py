"""Reusable widgets: buttons, cards, input rows, log console."""
from __future__ import annotations

import threading
from typing import Any, Callable

import customtkinter as ctk

from gui import theme as T


# ---------------------------------------------------------------------------
# Basic widgets
# ---------------------------------------------------------------------------
class AccentButton(ctk.CTkButton):
    """Primary action button (brand accent colour)."""

    def __init__(self, master, text: str, command: Callable[[], None] | None = None, **kw):
        super().__init__(
            master,
            text=text,
            command=command,
            fg_color=T.ACCENT,
            hover_color=T.ACCENT_HOV,
            text_color=T.TEXT,
            font=T.FONT_BODY_BOLD,
            corner_radius=T.RADIUS_SM,
            height=36,
            **kw,
        )


class GhostButton(ctk.CTkButton):
    """Secondary button, transparent with a subtle hover."""

    def __init__(self, master, text: str, command: Callable[[], None] | None = None, **kw):
        super().__init__(
            master,
            text=text,
            command=command,
            fg_color="transparent",
            hover_color=T.BG_RAISED,
            border_color=T.BORDER,
            border_width=1,
            text_color=T.TEXT,
            font=T.FONT_BODY,
            corner_radius=T.RADIUS_SM,
            height=34,
            **kw,
        )


class Card(ctk.CTkFrame):
    """A raised card surface with rounded corners."""

    def __init__(self, master, **kw):
        super().__init__(
            master,
            fg_color=T.BG_SURFACE,
            corner_radius=T.RADIUS_MD,
            border_color=T.BORDER,
            border_width=1,
            **kw,
        )


class SectionTitle(ctk.CTkLabel):
    def __init__(self, master, text: str, **kw):
        super().__init__(
            master,
            text=text,
            font=T.FONT_H2,
            text_color=T.TEXT,
            anchor="w",
            **kw,
        )


class MutedLabel(ctk.CTkLabel):
    def __init__(self, master, text: str, **kw):
        super().__init__(
            master,
            text=text,
            font=T.FONT_SMALL,
            text_color=T.TEXT_DIM,
            anchor="w",
            **kw,
        )


# ---------------------------------------------------------------------------
# Input form
# ---------------------------------------------------------------------------
class FormField:
    """Descriptor for an input field in a tool form."""

    def __init__(
        self,
        key: str,
        label: str,
        default: str = "",
        placeholder: str = "",
        kind: str = "entry",          # entry | file | textarea | check | combo | password
        options: list[str] | None = None,
        hint: str = "",
    ) -> None:
        self.key = key
        self.label = label
        self.default = default
        self.placeholder = placeholder
        self.kind = kind
        self.options = options or []
        self.hint = hint


class InputForm(Card):
    """Renders a list of FormField descriptors into an input form."""

    def __init__(self, master, fields: list[FormField]):
        super().__init__(master)
        self.fields = fields
        self.vars: dict[str, Any] = {}
        self._widgets: dict[str, ctk.CTkBaseClass] = {}
        self.grid_columnconfigure(0, weight=1)

        for row, field in enumerate(fields):
            lbl = ctk.CTkLabel(
                self, text=field.label, font=T.FONT_BODY_BOLD,
                text_color=T.TEXT, anchor="w",
            )
            lbl.grid(row=row * 2, column=0, sticky="ew", padx=14, pady=(12 if row else 14, 2))

            widget = self._build_widget(field)
            widget.grid(row=row * 2 + 1, column=0, sticky="ew", padx=14, pady=(0, 0))
            self._widgets[field.key] = widget

            if field.hint:
                hint = MutedLabel(self, field.hint)
                hint.grid(row=row * 2 + 1, column=0, sticky="ew",
                          padx=14, pady=(0, 2))

        # trailing padding row
        ctk.CTkLabel(self, text="").grid(row=len(fields) * 2, column=0, pady=4)

    def _build_widget(self, field: FormField) -> ctk.CTkBaseClass:
        if field.kind == "entry" or field.kind == "password":
            var = ctk.StringVar(value=field.default)
            entry = ctk.CTkEntry(
                self, textvariable=var, placeholder_text=field.placeholder,
                font=T.FONT_BODY, fg_color=T.BG_BASE, border_color=T.BORDER,
                border_width=1, height=34, corner_radius=T.RADIUS_SM,
                show="*" if field.kind == "password" else "",
            )
            self.vars[field.key] = var
            return entry
        if field.kind == "textarea":
            box = ctk.CTkTextbox(
                self, font=T.FONT_BODY, fg_color=T.BG_BASE, border_color=T.BORDER,
                border_width=1, height=80, corner_radius=T.RADIUS_SM,
            )
            if field.default:
                box.insert("1.0", field.default)
            self.vars[field.key] = box
            return box
        if field.kind == "check":
            var = ctk.BooleanVar(value=bool(field.default))
            chk = ctk.CTkCheckBox(
                self, text=field.placeholder or "", variable=var,
                font=T.FONT_BODY, text_color=T.TEXT, fg_color=T.ACCENT,
                hover_color=T.ACCENT_HOV, border_color=T.BORDER,
            )
            self.vars[field.key] = var
            return chk
        if field.kind == "combo":
            var = ctk.StringVar(value=field.default or (field.options[0] if field.options else ""))
            combo = ctk.CTkOptionMenu(
                self, values=field.options, variable=var,
                font=T.FONT_BODY, fg_color=T.BG_BASE, button_color=T.BG_RAISED,
                button_hover_color=T.BG_RAISED, text_color=T.TEXT,
                dropdown_fg_color=T.BG_SURFACE, dropdown_text_color=T.TEXT,
                corner_radius=T.RADIUS_SM, height=34,
            )
            self.vars[field.key] = var
            return combo
        if field.kind == "file":
            frame = ctk.CTkFrame(self, fg_color="transparent")
            frame.grid_columnconfigure(0, weight=1)
            var = ctk.StringVar(value=field.default)
            entry = ctk.CTkEntry(
                frame, textvariable=var, placeholder_text=field.placeholder,
                font=T.FONT_BODY, fg_color=T.BG_BASE, border_color=T.BORDER,
                border_width=1, height=34, corner_radius=T.RADIUS_SM,
            )
            entry.grid(row=0, column=0, sticky="ew")
            browse = GhostButton(frame, text="📁", width=40,
                                 command=lambda v=var: self._pick_file(v))
            browse.grid(row=0, column=1, padx=(6, 0))
            self.vars[field.key] = var
            return frame
        raise ValueError(f"Unknown field kind: {field.kind}")

    def _pick_file(self, var: ctk.StringVar) -> None:
        from tkinter import filedialog
        path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def values(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for field in self.fields:
            widget = self.vars[field.key]
            if field.kind == "textarea":
                out[field.key] = widget.get("1.0", "end").strip()
            elif field.kind == "check":
                out[field.key] = bool(widget.get())
            else:
                out[field.key] = widget.get()
        return out


# ---------------------------------------------------------------------------
# Log console + results panel
# ---------------------------------------------------------------------------
class LogConsole(Card):
    """Console-like scrolled log area with severity tags."""

    TAG_COLORS = {
        "info": T.TEXT,
        "ok": T.GREEN,
        "warn": T.YELLOW,
        "err": T.RED,
        "accent": T.ACCENT,
        "cyan": T.CYAN,
        "muted": T.TEXT_DIM,
    }

    def __init__(self, master):
        super().__init__(master)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
        header.grid_columnconfigure(0, weight=1)
        SectionTitle(header, "📟  Output").grid(row=0, column=0, sticky="w")
        GhostButton(header, "💾 Save", width=80, command=self.save_to_file).grid(
            row=0, column=1, sticky="e", padx=(0, 6))
        GhostButton(header, "Clear", width=70, command=self.clear).grid(
            row=0, column=2, sticky="e")

        self.box = ctk.CTkTextbox(
            self, font=T.FONT_MONO, fg_color=T.BG_DEEP, border_width=0,
            text_color=T.TEXT, wrap="word",
        )
        self.box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(6, 8))
        for tag, color in self.TAG_COLORS.items():
            self.box.tag_config(tag, foreground=color)
        self.box.configure(state="disabled")

    def write(self, text: str, tag: str = "info") -> None:
        self.box.configure(state="normal")
        self.box.insert("end", text + "\n", tag)
        self.box.see("end")
        self.box.configure(state="disabled")

    def clear(self) -> None:
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.configure(state="disabled")

    def save_to_file(self) -> None:
        from tkinter import filedialog
        from datetime import datetime
        import json as _json
        default = f"penetrator_log_{datetime.now():%Y%m%d_%H%M%S}.txt"
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default,
            filetypes=[
                ("Text", "*.txt"),
                ("JSON (structured)", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        content = self.box.get("1.0", "end").rstrip()
        try:
            if path.lower().endswith(".json"):
                # Export as a JSON list of {timestamp, line} entries
                entries = [{"line": line} for line in content.splitlines() if line]
                with open(path, "w", encoding="utf-8") as fh:
                    _json.dump({"version": 1, "entries": entries}, fh,
                               ensure_ascii=False, indent=2)
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(content + "\n")
            self.write(f"[+] Log saved -> {path}", "ok")
        except OSError as exc:
            self.write(f"[-] Cannot save log: {exc}", "err")


# ---------------------------------------------------------------------------
# Threaded runner
# ---------------------------------------------------------------------------
class TaskRunner:
    """Runs a blocking function in a background thread and streams messages.

    The worker function receives a ``log(msg, tag)`` callable that marshals
    messages back onto the Tk main loop via ``after(0, ...)``.

    Cooperative cancellation: a ``threading.Event`` is exposed via
    :attr:`stop_event`. Engine functions can poll it (or use the helper
    :meth:`is_stopping`) and abort early. The GUI's Stop button calls
    :meth:`request_stop`.
    """

    def __init__(self, tk_root: ctk.CTk, log_console: LogConsole):
        self.root = tk_root
        self.log = log_console
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()

    def is_running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def is_stopping(self) -> bool:
        return self.stop_event.is_set()

    def request_stop(self) -> None:
        if self.is_running():
            self.stop_event.set()
            self.log.write("[!] Stop requested - waiting for current step to finish",
                           "warn")

    def run(
        self,
        fn: Callable[[Callable[..., None]], None],
        on_done: Callable[[], None] | None = None,
    ) -> None:
        if self.is_running():
            self.log.write("[!] A task is already running", "warn")
            return

        self.stop_event.clear()

        def log_from_worker(msg: str, tag: str = "info") -> None:
            self.root.after(0, self.log.write, msg, tag)

        def worker() -> None:
            try:
                fn(log_from_worker)
            except StopIteration:
                log_from_worker("[!] Task aborted by user", "warn")
            except Exception as exc:  # keep GUI alive on tool errors
                log_from_worker(f"[-] Error: {exc}", "err")
            finally:
                if on_done is not None:
                    self.root.after(0, on_done)

        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()
