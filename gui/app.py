"""Main PENETRATOR application shell (customtkinter).

Layout:
    +-----------------------------------------------------------+
    |  header: logo / title / language switcher                 |
    +--------+--------------------------------------------------+
    |        |                                                  |
    | side-  |   content area (swaps on category change)        |
    | bar    |                                                  |
    |        +--------------------------------------------------+
    |        |   shared log console                             |
    +--------+--------------------------------------------------+
"""
from __future__ import annotations

import contextlib
from typing import Callable

import customtkinter as ctk

from core.banner import AUTHOR, VERSION
from core.i18n import I18n, t
from gui import theme as T
from gui import tools as tool_frames
from gui.widgets import (
    Card,
    GhostButton,
    LogConsole,
    MutedLabel,
    SectionTitle,
    TaskRunner,
)


class _StatusAwareRunner(TaskRunner):
    """TaskRunner that updates a status label when busy/idle, wires the
    engine cancellation hook, and shows a tray notification when a long task
    completes while the window isn't focused."""

    LONG_TASK_THRESHOLD_SEC = 15  # only notify if task ran > 15s

    def __init__(self, root, log, status_label):
        super().__init__(root, log)
        self.status = status_label
        # Make the engine's _should_stop() return our event state.
        from gui import engine as _engine
        _engine.set_stop_check(self.is_stopping)

    def run(self, fn, on_done=None):
        if self.is_running():
            self.log.write("[!] A task is already running", "warn")
            return
        with contextlib.suppress(Exception):
            self.status.configure(text=f"● {t('ui.running').rstrip('.')}",
                                  text_color=T.YELLOW)

        import time
        start = time.time()

        def wrapped_done():
            with contextlib.suppress(Exception):
                self.status.configure(text=f"● {t('ui.ready')}",
                                      text_color=T.GREEN)
            elapsed = time.time() - start
            if elapsed > self.LONG_TASK_THRESHOLD_SEC:
                self._notify_complete(elapsed)
            if on_done is not None:
                on_done()
        super().run(fn, on_done=wrapped_done)

    def _notify_complete(self, elapsed: float) -> None:
        """Best-effort cross-method completion notification."""
        # If app is focused, no need to nag.
        with contextlib.suppress(Exception):
            if self.root.focus_displayof() is not None:
                return

        # Try Windows toast via win10toast-click (lightweight, optional).
        try:
            from win10toast import ToastNotifier  # type: ignore
            ToastNotifier().show_toast(
                "PENETRATOR",
                t("ui.task_finished_in", sec=f"{elapsed:.1f}"),
                duration=4,
                threaded=True,
            )
            return
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: bell + window attribute flash.
        with contextlib.suppress(Exception):
            self.root.bell()
            self.root.attributes("-topmost", True)
            self.root.after(400,
                            lambda: self.root.attributes("-topmost", False))


CATEGORIES: list[tuple[str, str, str, str]] = [
    # (key, icon, label_key, description_key)
    ("info_gathering",       "🔎", "menu.main.info_gathering",       "menu.main.info_gathering_desc"),
    ("wordlist",             "📝", "menu.main.wordlist",             "menu.main.wordlist_desc"),
    ("sql_injection",        "💉", "menu.main.sql_injection",        "menu.main.sql_injection_desc"),
    ("web_attacks",          "🌐", "menu.main.web_attacks",          "menu.main.web_attacks_desc"),
    ("api_security",         "🔐", "menu.main.api_security",         "menu.main.api_security_desc"),
    ("password_tools",       "🔑", "menu.main.password_tools",       "menu.main.password_tools_desc"),
    ("crypto_tools",         "🔏", "menu.main.crypto_tools",         "menu.main.crypto_tools_desc"),
    ("cloud_security",       "☁️", "menu.main.cloud_security",       "menu.main.cloud_security_desc"),
    ("network_attacks",      "🖧", "menu.main.network_attacks",      "menu.main.network_attacks_desc"),
    ("steganography",        "🖼️", "menu.main.steganography",        "menu.main.steganography_desc"),
    ("xss_tools",            "⚡", "menu.main.xss_tools",            "menu.main.xss_tools_desc"),
    ("reverse_engineering",  "🧩", "menu.main.reverse_engineering",  "menu.main.reverse_engineering_desc"),
    ("forensic",             "🔬", "menu.main.forensic",             "menu.main.forensic_desc"),
    ("payload",              "💣", "menu.main.payload",              "menu.main.payload_desc"),
    ("osint",                "🕵️", "menu.main.osint",                "menu.main.osint_desc"),
]

BOTTOM_CATEGORIES: list[tuple[str, str, str, str]] = [
    ("settings", "⚙️", "menu.main.settings", "menu.main.settings_desc"),
    ("about",    "ℹ️", "menu.main.about",    "menu.main.about_desc"),
]

LANG_LABELS = {
    "en": "English",
    "fr": "Français",
    "zh": "中文",
    "es": "Español",
    "de": "Deutsch",
}


class Sidebar(ctk.CTkFrame):
    """Vertical category list with optional filter."""

    def __init__(self, master, on_select: Callable[[str], None]):
        super().__init__(master, fg_color=T.BG_SURFACE, corner_radius=0,
                         border_color=T.BORDER, border_width=0, width=230)
        self.on_select = on_select
        self.buttons: dict[str, ctk.CTkButton] = {}
        self.current: str | None = None
        self._labels: dict[str, str] = {}

        self.grid_columnconfigure(0, weight=1)

        # title
        title = ctk.CTkLabel(
            self, text="PENETRATOR", font=T.FONT_H1,
            text_color=T.ACCENT, anchor="w",
        )
        title.grid(row=0, column=0, sticky="ew", padx=16, pady=(18, 2))
        sub = MutedLabel(self, t("app.tagline"))
        sub.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        # search bar
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filter())
        search = ctk.CTkEntry(
            self, textvariable=self.search_var,
            placeholder_text=t("ui.filter_placeholder"),
            font=T.FONT_BODY, fg_color=T.BG_BASE, border_color=T.BORDER,
            border_width=1, height=30, corner_radius=T.RADIUS_SM,
        )
        search.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))

        # main category buttons (rows 3..3+N)
        for i, (key, icon, label_k, _) in enumerate(CATEGORIES):
            label = t(label_k)
            self._labels[key] = label
            btn = self._make_btn(key, icon, label)
            btn.grid(row=3 + i, column=0, sticky="ew", padx=8, pady=2)
            self.buttons[key] = btn

        # spacer row
        self.grid_rowconfigure(3 + len(CATEGORIES), weight=1)

        # bottom buttons
        for j, (key, icon, label_k, _) in enumerate(BOTTOM_CATEGORIES):
            label = t(label_k)
            self._labels[key] = label
            btn = self._make_btn(key, icon, label)
            btn.grid(row=4 + len(CATEGORIES) + j, column=0, sticky="ew",
                     padx=8, pady=2)
            self.buttons[key] = btn

        # trailing padding
        ctk.CTkLabel(self, text="", fg_color="transparent").grid(
            row=5 + len(CATEGORIES) + len(BOTTOM_CATEGORIES), column=0, pady=6)

    def _apply_filter(self) -> None:
        query = self.search_var.get().strip().lower()
        for key, btn in self.buttons.items():
            label = self._labels.get(key, "").lower()
            if not query or query in label or query in key:
                btn.grid()
            else:
                btn.grid_remove()

    def _make_btn(self, key: str, icon: str, label: str) -> ctk.CTkButton:
        T.CATEGORY_COLORS.get(key, T.ACCENT)
        return ctk.CTkButton(
            self,
            text=f"  {icon}   {label}",
            anchor="w",
            fg_color="transparent",
            hover_color=T.BG_RAISED,
            text_color=T.TEXT,
            font=T.FONT_BODY,
            corner_radius=T.RADIUS_SM,
            height=36,
            border_width=0,
            command=lambda k=key: self._select(k),
        )

    def _select(self, key: str) -> None:
        self.highlight(key)
        self.on_select(key)

    def highlight(self, key: str) -> None:
        for k, btn in self.buttons.items():
            if k == key:
                color = T.CATEGORY_COLORS.get(k, T.ACCENT)
                btn.configure(fg_color=color, text_color=T.TEXT,
                              hover_color=color)
            else:
                btn.configure(fg_color="transparent", text_color=T.TEXT,
                              hover_color=T.BG_RAISED)
        self.current = key


class Header(ctk.CTkFrame):
    """Top bar with title and language selector."""

    def __init__(self, master, on_language_change: Callable[[str], None]):
        super().__init__(master, fg_color=T.BG_BASE, height=56,
                         corner_radius=0, border_color=T.BORDER,
                         border_width=0)
        self.on_language_change = on_language_change
        self.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(self, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=18, pady=10)
        ctk.CTkLabel(left, text="🗡️", font=("Segoe UI Emoji", 20),
                     text_color=T.ACCENT).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkLabel(left, text=t("app.name"), font=T.FONT_TITLE,
                     text_color=T.TEXT).grid(row=0, column=1)
        ctk.CTkLabel(left, text=f" — {t('app.subtitle')}", font=T.FONT_SMALL,
                     text_color=T.TEXT_DIM).grid(row=0, column=2, padx=(6, 0))

        right = ctk.CTkFrame(self, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e", padx=18, pady=10)
        ctk.CTkLabel(right, text="🌐", font=T.FONT_BODY,
                     text_color=T.TEXT_DIM).grid(row=0, column=0, padx=(0, 6))
        self.lang_var = ctk.StringVar(value=LANG_LABELS[I18n.get().language])
        self.lang_menu = ctk.CTkOptionMenu(
            right,
            values=list(LANG_LABELS.values()),
            variable=self.lang_var,
            command=self._change_lang,
            font=T.FONT_BODY,
            fg_color=T.BG_SURFACE,
            button_color=T.BG_RAISED,
            button_hover_color=T.BG_RAISED,
            text_color=T.TEXT,
            dropdown_fg_color=T.BG_SURFACE,
            dropdown_text_color=T.TEXT,
            corner_radius=T.RADIUS_SM,
            width=130, height=32,
        )
        self.lang_menu.grid(row=0, column=1)

    def _change_lang(self, label: str) -> None:
        for code, lab in LANG_LABELS.items():
            if lab == label:
                self.on_language_change(code)
                return


class SettingsFrame(Card):
    def __init__(self, master, on_language_change: Callable[[str], None],
                 log: LogConsole | None = None):
        super().__init__(master)
        self.log = log
        self.grid_columnconfigure(0, weight=1)
        SectionTitle(self, f"⚙️  {t('menu.settings.title')}").grid(
            row=0, column=0, sticky="ew", padx=18, pady=(16, 4))
        MutedLabel(self, t('menu.language.title')).grid(
            row=1, column=0, sticky="ew", padx=18, pady=(0, 12))

        for i, (code, label) in enumerate(LANG_LABELS.items()):
            btn = GhostButton(self, text=f"  {label}  ({code})",
                              command=lambda c=code: on_language_change(c))
            btn.grid(row=2 + i, column=0, sticky="w", padx=18, pady=4)

        # --- Preferences -----------------------------------------------
        next_row = 2 + len(LANG_LABELS) + 1
        MutedLabel(self, t("menu.settings.preferences")).grid(
            row=next_row, column=0, sticky="ew", padx=18, pady=(20, 8))

        clear_btn = GhostButton(
            self, text=f"  🧹  {t('menu.settings.clear_form_memory')}",
            command=self._clear_form_memory,
        )
        clear_btn.grid(row=next_row + 1, column=0, sticky="w", padx=18, pady=4)

        save_ws_btn = GhostButton(
            self, text=f"  💾  {t('menu.settings.save_workspace')}",
            command=self._save_workspace,
        )
        save_ws_btn.grid(row=next_row + 2, column=0, sticky="w", padx=18, pady=4)

        load_ws_btn = GhostButton(
            self, text=f"  📂  {t('menu.settings.load_workspace')}",
            command=self._load_workspace,
        )
        load_ws_btn.grid(row=next_row + 3, column=0, sticky="w", padx=18, pady=4)

        repo_btn = GhostButton(
            self, text=f"  🔗  {t('menu.settings.open_repo')}",
            command=lambda: __import__("webbrowser").open(
                "https://github.com/Oli97430/PENETRATOR"
            ),
        )
        repo_btn.grid(row=next_row + 4, column=0, sticky="w", padx=18, pady=4)

    def _clear_form_memory(self) -> None:
        try:
            I18n.get().set_config("form_memory", {})
            if self.log is not None:
                self.log.write(f"[+] {t('menu.settings.form_memory_cleared')}",
                               "ok")
        except Exception as exc:
            if self.log is not None:
                self.log.write(f"[-] {exc}", "err")

    def _save_workspace(self) -> None:
        from datetime import datetime
        from tkinter import filedialog
        import json as _json
        from gui import engine as _engine
        from core.banner import VERSION

        default = f"workspace_{datetime.now():%Y%m%d_%H%M%S}.penetrator"
        path = filedialog.asksaveasfilename(
            defaultextension=".penetrator",
            initialfile=default,
            filetypes=[("PENETRATOR workspace", "*.penetrator"),
                       ("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        snapshot = {
            "version": 1,
            "app_version": VERSION,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "session": _engine.session_dump(),
            "log": (self.log.box.get("1.0", "end").rstrip()
                    if self.log is not None else ""),
        }
        try:
            with open(path, "w", encoding="utf-8") as fh:
                _json.dump(snapshot, fh, ensure_ascii=False, indent=2)
            if self.log is not None:
                self.log.write(
                    f"[+] {t('menu.settings.workspace_saved', path=path)}",
                    "ok")
        except OSError as exc:
            if self.log is not None:
                self.log.write(f"[-] {exc}", "err")

    def _load_workspace(self) -> None:
        from tkinter import filedialog
        import json as _json
        from gui import engine as _engine

        path = filedialog.askopenfilename(
            filetypes=[("PENETRATOR workspace", "*.penetrator"),
                       ("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                data = _json.load(fh)
            if not isinstance(data, dict) or data.get("version") != 1:
                raise ValueError("schema mismatch")
            _engine.session_restore(data.get("session", {}))
            if self.log is not None:
                if data.get("log"):
                    self.log.write("──── workspace log ────", "muted")
                    for line in str(data["log"]).splitlines():
                        self.log.write(line, "info")
                self.log.write(
                    f"[+] {t('menu.settings.workspace_loaded', path=path)}",
                    "ok")
        except Exception as exc:
            if self.log is not None:
                self.log.write(
                    f"[-] {t('menu.settings.workspace_invalid')}: {exc}",
                    "err")


class AboutFrame(Card):
    def __init__(self, master):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        SectionTitle(self, f"ℹ️  {t('modules.about.title')}  ·  v{VERSION}").grid(
            row=0, column=0, sticky="ew", padx=18, pady=(16, 4))
        body = ctk.CTkLabel(
            self, text=t("modules.about.description"), font=T.FONT_BODY,
            text_color=T.TEXT, justify="left", anchor="w", wraplength=820,
        )
        body.grid(row=1, column=0, sticky="ew", padx=18, pady=(4, 10))
        MutedLabel(self, t("modules.about.license")).grid(
            row=2, column=0, sticky="ew", padx=18, pady=2)
        author_row = ctk.CTkFrame(self, fg_color="transparent")
        author_row.grid(row=3, column=0, sticky="ew", padx=18, pady=2)
        MutedLabel(author_row, f"{t('modules.about.author')}  ·  ").grid(
            row=0, column=0, sticky="w")
        email_link = ctk.CTkLabel(
            author_row, text=AUTHOR, font=T.FONT_SMALL,
            text_color=T.CYAN, cursor="hand2",
        )
        email_link.grid(row=0, column=1, sticky="w")

        def _open_mail(_event=None):
            import webbrowser
            webbrowser.open(f"mailto:{AUTHOR}")
        email_link.bind("<Button-1>", _open_mail)
        warn = ctk.CTkLabel(
            self, text=f"⚠️  {t('modules.about.disclaimer')}",
            font=T.FONT_SMALL, text_color=T.YELLOW,
            justify="left", anchor="w", wraplength=820,
        )
        warn.grid(row=4, column=0, sticky="ew", padx=18, pady=(14, 16))


class FirstRunLanguageDialog(ctk.CTkToplevel):
    """Modal first-run language picker."""

    def __init__(self, master, on_pick: Callable[[str], None]):
        super().__init__(master)
        self.title(f"PENETRATOR — {t('ui.welcome')}")
        self.geometry("420x320")
        self.configure(fg_color=T.BG_DEEP)
        self.resizable(False, False)
        try:
            self.transient(master)
            self.grab_set()
        except Exception:
            pass

        ctk.CTkLabel(self, text="🗡️", font=("Segoe UI Emoji", 36),
                     text_color=T.ACCENT).pack(pady=(22, 4))
        ctk.CTkLabel(self, text="PENETRATOR", font=T.FONT_TITLE,
                     text_color=T.TEXT).pack()
        ctk.CTkLabel(
            self, text="Choose your language  ·  Choisissez la langue  ·  选择语言",
            font=T.FONT_SMALL, text_color=T.TEXT_DIM,
        ).pack(pady=(2, 16))

        for code, label in LANG_LABELS.items():
            btn = ctk.CTkButton(
                self, text=label, font=T.FONT_BODY_BOLD,
                fg_color=T.BG_SURFACE, hover_color=T.ACCENT,
                text_color=T.TEXT, border_color=T.BORDER, border_width=1,
                corner_radius=T.RADIUS_SM, height=38, width=240,
                command=lambda c=code: (on_pick(c), self.destroy()),
            )
            btn.pack(pady=4)


def _is_first_run() -> bool:
    """True if config.json doesn't yet record a chosen language."""
    import json
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "config.json"
    if not p.exists():
        return True
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True
    return "language" not in data


class App(ctk.CTk):
    """Main PENETRATOR GUI application."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        self.title(f"PENETRATOR v{VERSION}")
        self.geometry("1400x900")
        self.minsize(1100, 720)
        self.configure(fg_color=T.BG_DEEP)

        first_run = _is_first_run()
        self.i18n = I18n.get()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- header -----------------------------------------------------
        self.header = Header(self, on_language_change=self._on_language_change)
        self.header.grid(row=0, column=0, columnspan=2, sticky="ew")
        sep = ctk.CTkFrame(self, height=1, fg_color=T.BORDER)
        sep.grid(row=0, column=0, columnspan=2, sticky="sew")

        # --- sidebar ----------------------------------------------------
        self.sidebar = Sidebar(self, on_select=self._on_category)
        self.sidebar.grid(row=1, column=0, sticky="nsw")

        # --- content + log console -------------------------------------
        self.right = ctk.CTkFrame(self, fg_color=T.BG_BASE)
        self.right.grid(row=1, column=1, sticky="nsew")
        self.right.grid_columnconfigure(0, weight=1)
        self.right.grid_rowconfigure(0, weight=3)
        self.right.grid_rowconfigure(1, weight=2)

        self.content_holder = ctk.CTkFrame(self.right, fg_color=T.BG_BASE)
        self.content_holder.grid(row=0, column=0, sticky="nsew",
                                 padx=16, pady=(16, 8))
        self.content_holder.grid_columnconfigure(0, weight=1)
        self.content_holder.grid_rowconfigure(0, weight=1)

        self.log = LogConsole(self.right)
        self.log.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 4))

        # --- status bar ------------------------------------------------
        self.status_bar = ctk.CTkFrame(self, fg_color=T.BG_SURFACE,
                                       height=28, corner_radius=0)
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.status_bar.grid_columnconfigure(1, weight=1)
        self.status_state = ctk.CTkLabel(
            self.status_bar, text=f"● {t('ui.ready')}", font=T.FONT_SMALL,
            text_color=T.GREEN, anchor="w",
        )
        self.status_state.grid(row=0, column=0, sticky="w", padx=12, pady=4)
        self.status_center = ctk.CTkLabel(
            self.status_bar, text=t("ui.warning_legal"),
            font=T.FONT_SMALL, text_color=T.YELLOW, anchor="center",
        )
        self.status_center.grid(row=0, column=1, sticky="ew", padx=12)
        self.status_right = ctk.CTkLabel(
            self.status_bar,
            text=f"v{VERSION}  •  {LANG_LABELS[I18n.get().language]}  •  {AUTHOR}",
            font=T.FONT_SMALL, text_color=T.TEXT_DIM, anchor="e",
        )
        self.status_right.grid(row=0, column=2, sticky="e", padx=12, pady=4)

        self.runner = _StatusAwareRunner(self, self.log, self.status_state)

        self.current_frame: ctk.CTkBaseClass | None = None

        # default view: restore last-selected category if any
        last_cat = self.i18n.get_config("last_category", "info_gathering")
        valid_keys = {k for k, *_ in CATEGORIES} | {"settings", "about"}
        if last_cat not in valid_keys:
            last_cat = "info_gathering"
        self._on_category(last_cat)
        self.sidebar.highlight(last_cat)

        self.log.write(f"[+] PENETRATOR v{VERSION} ready. {t('ui.warning_legal')}",
                       "accent")
        self.log.write("[i] Shortcuts: Ctrl+P quick open · Ctrl+L clear · "
                       "Ctrl+S save log · F1 about · Ctrl+, settings · Ctrl+Q quit",
                       "muted")

        # --- live clock + window icon + shortcuts + close handler ---
        self._clock_job: str | None = None
        self._tick_clock()
        self._set_window_icon()
        self._bind_shortcuts()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if first_run:
            self.after(150, self._show_first_run_picker)

        # Background update check, 1.5s after launch
        self.after(1500, self._check_for_updates_async)

    # ------------------------------------------------------------------
    # Polish helpers
    # ------------------------------------------------------------------
    def _tick_clock(self) -> None:
        from datetime import datetime
        try:
            now = datetime.now().strftime("%H:%M:%S")
            self.status_right.configure(
                text=f"🕒 {now}  •  v{VERSION}  •  "
                     f"{LANG_LABELS[I18n.get().language]}  •  {AUTHOR}",
            )
        except Exception:
            return
        self._clock_job = self.after(1000, self._tick_clock)

    def _set_window_icon(self) -> None:
        # CustomTkinter doesn't expose iconbitmap cleanly; tk does.
        from pathlib import Path
        ico = Path(__file__).resolve().parent.parent / "assets" / "logo.ico"
        if ico.exists():
            try:
                self.iconbitmap(default=str(ico))
            except Exception:
                pass

    def _bind_shortcuts(self) -> None:
        self.bind_all("<Control-l>", lambda e: self.log.clear())
        self.bind_all("<Control-L>", lambda e: self.log.clear())
        self.bind_all("<Control-s>", lambda e: self.log.save_to_file())
        self.bind_all("<Control-S>", lambda e: self.log.save_to_file())
        self.bind_all("<Control-q>", lambda e: self._on_close())
        self.bind_all("<Control-Q>", lambda e: self._on_close())
        self.bind_all("<F1>",
                      lambda e: (self._on_category("about"),
                                 self.sidebar.highlight("about")))
        self.bind_all("<Control-comma>",
                      lambda e: (self._on_category("settings"),
                                 self.sidebar.highlight("settings")))
        # Quick launcher (VS Code style)
        self.bind_all("<Control-p>", lambda e: self._open_launcher())
        self.bind_all("<Control-P>", lambda e: self._open_launcher())

    def _open_launcher(self) -> None:
        from gui.launcher import QuickLauncher

        def jump(key: str) -> None:
            self._on_category(key)
            self.sidebar.highlight(key)

        QuickLauncher(self, on_pick=jump)

    def _on_close(self) -> None:
        if self.runner.is_running():
            try:
                from CTkMessagebox import CTkMessagebox
                box = CTkMessagebox(
                    title="PENETRATOR",
                    message=t("ui.task_running_quit"),
                    icon="warning",
                    option_1=t("ui.cancel"), option_2=t("ui.quit"),
                )
                if box.get() != t("ui.quit"):
                    return
            except ImportError:
                pass
        if self._clock_job is not None:
            try:
                self.after_cancel(self._clock_job)
            except Exception:
                pass
        self.destroy()

    def _show_first_run_picker(self) -> None:
        FirstRunLanguageDialog(
            self, on_pick=lambda code: self._on_language_change(code),
        )

    def _check_for_updates_async(self) -> None:
        """Background thread to check GitHub releases — non-blocking."""
        import threading
        from core import updater

        def worker():
            result = updater.check_latest(VERSION)
            if result and result.get("newer"):
                self.after(0, self._notify_update, result)

        threading.Thread(target=worker, daemon=True).start()

    def _notify_update(self, info: dict) -> None:
        self.log.write(
            "[★] " + t("ui.update_available", latest=info["latest"], url=info["url"]),
            "accent",
        )
        self.log.write(
            "    " + t("ui.update_current", current=info["current"]),
            "muted",
        )

    # ------------------------------------------------------------------
    def _clear_content(self) -> None:
        if self.current_frame is not None:
            self.current_frame.destroy()
            self.current_frame = None

    def _on_category(self, key: str) -> None:
        self._clear_content()
        try:
            self.i18n.set_config("last_category", key)
        except Exception:
            pass
        if key == "settings":
            self.current_frame = SettingsFrame(
                self.content_holder,
                on_language_change=self._on_language_change,
                log=self.log,
            )
        elif key == "about":
            self.current_frame = AboutFrame(self.content_holder)
        else:
            builder = tool_frames.BUILDERS.get(key)
            if builder is None:
                self.current_frame = Card(self.content_holder)
                MutedLabel(self.current_frame, f"Not available: {key}").grid(
                    padx=24, pady=24)
            else:
                self.current_frame = builder(self.content_holder,
                                             runner=self.runner, log=self.log)
        self.current_frame.grid(row=0, column=0, sticky="nsew")

    def _on_language_change(self, code: str) -> None:
        if code not in I18n.SUPPORTED:
            return
        if code == self.i18n.language:
            return
        self.i18n.save_preferred(code)
        self.log.write(f"[i] {t('menu.language.saved')}: {LANG_LABELS[code]}",
                       "ok")
        self._rebuild()

    def _rebuild(self) -> None:
        """Tear down and re-create everything so labels pick up the new language."""
        current = self.sidebar.current or "info_gathering"
        if self._clock_job is not None:
            try:
                self.after_cancel(self._clock_job)
            except Exception:
                pass
            self._clock_job = None
        for w in (self.header, self.sidebar, self.right, self.status_bar):
            w.destroy()
        # reset state and re-init
        self.header = Header(self, on_language_change=self._on_language_change)
        self.header.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.sidebar = Sidebar(self, on_select=self._on_category)
        self.sidebar.grid(row=1, column=0, sticky="nsw")

        self.right = ctk.CTkFrame(self, fg_color=T.BG_BASE)
        self.right.grid(row=1, column=1, sticky="nsew")
        self.right.grid_columnconfigure(0, weight=1)
        self.right.grid_rowconfigure(0, weight=3)
        self.right.grid_rowconfigure(1, weight=2)

        self.content_holder = ctk.CTkFrame(self.right, fg_color=T.BG_BASE)
        self.content_holder.grid(row=0, column=0, sticky="nsew",
                                 padx=16, pady=(16, 8))
        self.content_holder.grid_columnconfigure(0, weight=1)
        self.content_holder.grid_rowconfigure(0, weight=1)

        self.log = LogConsole(self.right)
        self.log.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 4))

        self.status_bar = ctk.CTkFrame(self, fg_color=T.BG_SURFACE,
                                       height=28, corner_radius=0)
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.status_bar.grid_columnconfigure(1, weight=1)
        self.status_state = ctk.CTkLabel(
            self.status_bar, text=f"● {t('ui.ready')}", font=T.FONT_SMALL,
            text_color=T.GREEN, anchor="w",
        )
        self.status_state.grid(row=0, column=0, sticky="w", padx=12, pady=4)
        self.status_center = ctk.CTkLabel(
            self.status_bar, text=t("ui.warning_legal"),
            font=T.FONT_SMALL, text_color=T.YELLOW, anchor="center",
        )
        self.status_center.grid(row=0, column=1, sticky="ew", padx=12)
        self.status_right = ctk.CTkLabel(
            self.status_bar,
            text=f"v{VERSION}  •  {LANG_LABELS[I18n.get().language]}  •  {AUTHOR}",
            font=T.FONT_SMALL, text_color=T.TEXT_DIM, anchor="e",
        )
        self.status_right.grid(row=0, column=2, sticky="e", padx=12, pady=4)

        self.runner = _StatusAwareRunner(self, self.log, self.status_state)
        self.current_frame = None
        self._on_category(current)
        self.sidebar.highlight(current)
        self._tick_clock()
