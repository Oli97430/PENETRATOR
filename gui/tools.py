"""GUI tool frames.

Each category has one scrollable panel with several tools. A tool is made of
an :class:`InputForm` and a Run button; clicking Run dispatches the matching
``engine.*`` function through a shared :class:`TaskRunner`.
"""
from __future__ import annotations

from typing import Any, Callable

import customtkinter as ctk

from core.i18n import t
from gui import engine as E
from gui import theme as T
from gui.widgets import (
    AccentButton,
    Card,
    FormField,
    GhostButton,
    InputForm,
    LogConsole,
    MutedLabel,
    SectionTitle,
    TaskRunner,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class ToolCard(Card):
    """A single tool with a title, form, and Run button."""

    def __init__(
        self,
        master,
        *,
        icon: str,
        title: str,
        description: str,
        fields: list[FormField],
        on_run: Callable[[dict[str, Any], Callable[..., None]], None],
        runner: TaskRunner,
        log: LogConsole,
        category_color: str,
    ):
        super().__init__(master)
        self.on_run = on_run
        self.runner = runner
        self.log = log
        self._memory_key = f"form_memory.{title}"
        self._fields = fields

        self.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text=icon, font=("Segoe UI Emoji", 18),
                     text_color=category_color).grid(row=0, column=0, padx=(0, 8))
        SectionTitle(header, title).grid(row=0, column=1, sticky="w")
        MutedLabel(self, description).grid(row=1, column=0, sticky="ew",
                                           padx=16, pady=(0, 8))

        self.form = InputForm(self, fields)
        self.form.grid(row=2, column=0, sticky="ew", padx=10, pady=(2, 6))
        self.form.configure(fg_color="transparent", border_width=0)
        self._restore_form_memory()

        run_row = ctk.CTkFrame(self, fg_color="transparent")
        run_row.grid(row=3, column=0, sticky="ew", padx=14, pady=(4, 14))
        run_row.grid_columnconfigure(0, weight=1)
        self.stop_btn = GhostButton(run_row, text=f"⏹  {t('ui.stop')}",
                                    command=self._stop, width=100)
        self.stop_btn.grid(row=0, column=1, sticky="e", padx=(0, 8))
        self.stop_btn.configure(state="disabled")
        self.run_btn = AccentButton(run_row, text=f"▶  {t('ui.run')}",
                                    command=self._dispatch, width=140)
        self.run_btn.grid(row=0, column=2, sticky="e")

    def _dispatch(self) -> None:
        values = self.form.values()
        self._save_form_memory(values)
        self.log.write(f"[*] {t('ui.running')}", "cyan")
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        def worker(log: Callable[..., None]) -> None:
            self.on_run(values, log)

        def done() -> None:
            self.run_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.log.write(f"[*] {t('ui.finished')}", "cyan")

        self.runner.run(worker, on_done=done)

    def _stop(self) -> None:
        self.runner.request_stop()

    # ------------------------------------------------------------------
    # Form-memory: persist per-tool inputs across launches
    # ------------------------------------------------------------------
    def _save_form_memory(self, values: dict[str, Any]) -> None:
        try:
            from core.i18n import I18n
            i18n = I18n.get()
            store = i18n.get_config("form_memory", {}) or {}
            # Don't persist passwords or large textareas
            slim = {}
            for f in self._fields:
                if f.kind in ("password", "textarea"):
                    continue
                v = values.get(f.key)
                if isinstance(v, (str, int, float, bool)):
                    slim[f.key] = v
            if slim:
                store[self._memory_key] = slim
                i18n.set_config("form_memory", store)
        except Exception:
            pass

    def _restore_form_memory(self) -> None:
        try:
            from core.i18n import I18n
            store = I18n.get().get_config("form_memory", {}) or {}
            saved = store.get(self._memory_key)
            if not isinstance(saved, dict):
                return
            for f in self._fields:
                if f.kind in ("password", "textarea"):
                    continue
                if f.key not in saved:
                    continue
                widget = self.form.vars.get(f.key)
                if widget is None:
                    continue
                value = saved[f.key]
                try:
                    if f.kind == "check":
                        widget.set(bool(value))
                    else:
                        widget.set(str(value))
                except Exception:
                    pass
        except Exception:
            pass


class CategoryPanel(ctk.CTkScrollableFrame):
    """Scrollable container that stacks ToolCards vertically."""

    def __init__(self, master, title: str, icon: str, color: str):
        super().__init__(
            master,
            fg_color=T.BG_BASE,
            scrollbar_button_color=T.BG_RAISED,
            scrollbar_button_hover_color=T.BORDER,
            corner_radius=0,
        )
        self.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=4, pady=(2, 12))
        ctk.CTkLabel(header, text=icon, font=("Segoe UI Emoji", 22),
                     text_color=color).grid(row=0, column=0, padx=(0, 10))
        heading = SectionTitle(header, title)
        heading.configure(font=T.FONT_H1)
        heading.grid(row=0, column=1, sticky="w")
        self._next_row = 1

    def add(self, card: ctk.CTkBaseClass) -> None:
        card.grid(row=self._next_row, column=0, sticky="ew", padx=4, pady=(0, 14))
        self._next_row += 1


def _int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _require(values: dict[str, Any], key: str, log: Callable[..., None],
             label: str) -> str | None:
    v = str(values.get(key, "")).strip()
    if not v:
        log(f"[-] {t('ui.required')}: {label}", "err")
        return None
    return v


# ---------------------------------------------------------------------------
# Information Gathering
# ---------------------------------------------------------------------------
def build_info_gathering(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["info_gathering"]
    panel = CategoryPanel(master, t("modules.info_gathering.title"), "🔎", color)

    # Port scanner
    def run_scan(v, lg):
        target = _require(v, "target", lg, t("ui.target"))
        if not target: return
        rng = str(v.get("range", "1-1024")).split("-")
        start = _int(rng[0], 1); end = _int(rng[-1], 1024)
        E.scan_ports(target, start, end, _int(v.get("threads"), 100),
                     _float(v.get("timeout"), 0.6), lg)

    panel.add(ToolCard(
        panel, icon="🔌", title=t("modules.info_gathering.port_scan"),
        description=t("modules.info_gathering.port_scan_desc"),
        fields=[
            FormField("target", t("ui.target"), placeholder="example.com"),
            FormField("range", t("ui.port_range"), default="1-1024"),
            FormField("threads", t("ui.threads"), default="100"),
            FormField("timeout", t("ui.timeout"), default="0.6"),
        ],
        on_run=run_scan, runner=runner, log=log, category_color=color,
    ))

    # Host to IP
    def run_resolve(v, lg):
        host = _require(v, "host", lg, t("ui.host"))
        if host: E.resolve_host(host, lg)

    panel.add(ToolCard(
        panel, icon="🧭", title=t("modules.info_gathering.host_to_ip"),
        description=t("modules.info_gathering.host_to_ip_desc"),
        fields=[FormField("host", t("ui.host"), placeholder="example.com")],
        on_run=run_resolve, runner=runner, log=log, category_color=color,
    ))

    # WHOIS
    def run_whois(v, lg):
        dom = _require(v, "domain", lg, t("ui.domain"))
        if dom: E.whois_lookup(dom, lg)

    panel.add(ToolCard(
        panel, icon="📜", title=t("modules.info_gathering.whois_lookup"),
        description=t("modules.info_gathering.whois_lookup_desc"),
        fields=[FormField("domain", t("ui.domain"), placeholder="example.com")],
        on_run=run_whois, runner=runner, log=log, category_color=color,
    ))

    # DNS
    def run_dns(v, lg):
        dom = _require(v, "domain", lg, t("ui.domain"))
        if dom: E.dns_lookup(dom, lg)

    panel.add(ToolCard(
        panel, icon="📡", title=t("modules.info_gathering.dns_lookup"),
        description=t("modules.info_gathering.dns_lookup_desc"),
        fields=[FormField("domain", t("ui.domain"), placeholder="example.com")],
        on_run=run_dns, runner=runner, log=log, category_color=color,
    ))

    # Subdomains
    def run_sub(v, lg):
        dom = _require(v, "domain", lg, t("ui.domain"))
        if dom: E.find_subdomains(dom, _int(v.get("threads"), 30), lg)

    panel.add(ToolCard(
        panel, icon="🌲", title=t("modules.info_gathering.subdomain_finder"),
        description=t("modules.info_gathering.subdomain_finder_desc"),
        fields=[
            FormField("domain", t("ui.domain"), placeholder="example.com"),
            FormField("threads", t("ui.threads"), default="30"),
        ],
        on_run=run_sub, runner=runner, log=log, category_color=color,
    ))

    # Headers
    def run_headers(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.fetch_headers(url, lg)

    panel.add(ToolCard(
        panel, icon="📄", title=t("modules.info_gathering.http_headers"),
        description=t("modules.info_gathering.http_headers_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com")],
        on_run=run_headers, runner=runner, log=log, category_color=color,
    ))

    # crt.sh subdomain enumeration
    def run_crtsh(v, lg):
        dom = _require(v, "domain", lg, t("ui.domain"))
        if dom: E.crtsh_subdomains(dom, lg)

    panel.add(ToolCard(
        panel, icon="📜", title=t("modules.info_gathering.crtsh"),
        description=t("modules.info_gathering.crtsh_desc"),
        fields=[FormField("domain", t("ui.domain"), placeholder="example.com")],
        on_run=run_crtsh, runner=runner, log=log, category_color=color,
    ))

    # Port scan + banner
    def run_banner_scan(v, lg):
        target = _require(v, "target", lg, t("ui.target"))
        if not target: return
        rng = str(v.get("range", "1-1024")).split("-")
        E.scan_with_banners(target, _int(rng[0], 1), _int(rng[-1], 1024),
                            _int(v.get("threads"), 100),
                            _float(v.get("timeout"), 0.6), lg)

    panel.add(ToolCard(
        panel, icon="🎯", title=t("modules.info_gathering.banner_scan"),
        description=t("modules.info_gathering.banner_scan_desc"),
        fields=[
            FormField("target", t("ui.target"), placeholder="example.com"),
            FormField("range", t("ui.port_range"), default="1-1024"),
            FormField("threads", t("ui.threads"), default="100"),
            FormField("timeout", t("ui.timeout"), default="0.6"),
        ],
        on_run=run_banner_scan, runner=runner, log=log, category_color=color,
    ))

    # Async port scanner
    def run_async_scan(v, lg):
        target = _require(v, "target", lg, t("ui.target"))
        if not target: return
        rng = str(v.get("range", "1-65535")).split("-")
        E.scan_ports_async(target, _int(rng[0], 1), _int(rng[-1], 65535),
                           _int(v.get("concurrency"), 500),
                           _float(v.get("timeout"), 0.5), lg)

    panel.add(ToolCard(
        panel, icon="⚡", title=t("modules.info_gathering.async_scan"),
        description=t("modules.info_gathering.async_scan_desc"),
        fields=[
            FormField("target", t("ui.target"), placeholder="example.com"),
            FormField("range", t("ui.port_range"), default="1-65535"),
            FormField("concurrency", t("modules.info_gathering.concurrency"),
                      default="500"),
            FormField("timeout", t("ui.timeout"), default="0.5"),
        ],
        on_run=run_async_scan, runner=runner, log=log, category_color=color,
    ))

    # TLS / SSL scanner
    def run_tls(v, lg):
        host = _require(v, "host", lg, t("ui.host"))
        if host: E.tls_scan(host, _int(v.get("port"), 443), lg)

    panel.add(ToolCard(
        panel, icon="🔒", title=t("modules.info_gathering.tls_scan"),
        description=t("modules.info_gathering.tls_scan_desc"),
        fields=[
            FormField("host", t("ui.host"), placeholder="example.com"),
            FormField("port", t("ui.port"), default="443"),
        ],
        on_run=run_tls, runner=runner, log=log, category_color=color,
    ))

    # Subdomain takeover
    def run_takeover(v, lg):
        host = _require(v, "host", lg, t("ui.host"))
        if host: E.check_subdomain_takeover(host, lg)

    panel.add(ToolCard(
        panel, icon="⚠️", title=t("modules.info_gathering.takeover"),
        description=t("modules.info_gathering.takeover_desc"),
        fields=[FormField("host", t("ui.host"),
                          placeholder="abandoned.example.com")],
        on_run=run_takeover, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Wordlist generator
# ---------------------------------------------------------------------------
def build_wordlist(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["wordlist"]
    panel = CategoryPanel(master, t("modules.wordlist.title"), "📝", color)

    def _save(words, output, lg):
        from pathlib import Path
        path = Path(output).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(sorted(words)) + "\n", encoding="utf-8")
        lg(f"[+] {t('modules.wordlist.wordlist_saved', count=len(words), path=path)}", "ok")

    def run_cupp(v, lg):
        words = E.cupp_wordlist({
            "first": v.get("first", ""),
            "last": v.get("last", ""),
            "nick": v.get("nick", ""),
            "partner": v.get("partner", ""),
            "pet": v.get("pet", ""),
            "company": v.get("company", ""),
            "birthday": v.get("birthday", ""),
            "keywords": v.get("keywords", ""),
        })
        out = v.get("output", "") or "wordlist_cupp.txt"
        _save(words, out, lg)

    panel.add(ToolCard(
        panel, icon="🎯", title=t("modules.wordlist.cupp"),
        description=t("modules.wordlist.cupp_desc"),
        fields=[
            FormField("first", t("modules.wordlist.cupp_first_name")),
            FormField("last", t("modules.wordlist.cupp_last_name")),
            FormField("nick", t("modules.wordlist.cupp_nickname")),
            FormField("partner", t("modules.wordlist.cupp_partner")),
            FormField("pet", t("modules.wordlist.cupp_pet")),
            FormField("company", t("modules.wordlist.cupp_company")),
            FormField("birthday", t("modules.wordlist.cupp_birthday"),
                      placeholder="DDMMYYYY"),
            FormField("keywords", t("modules.wordlist.cupp_keywords"),
                      kind="textarea"),
            FormField("output", t("ui.output_file"), default="wordlist_cupp.txt"),
        ],
        on_run=run_cupp, runner=runner, log=log, category_color=color,
    ))

    def run_comb(v, lg):
        from pathlib import Path
        a = Path(str(v.get("left", "")))
        b = Path(str(v.get("right", "")))
        if not a.is_file() or not b.is_file():
            lg("[-] Both files required", "err"); return
        left = a.read_text(encoding="utf-8", errors="ignore").splitlines()
        right = b.read_text(encoding="utf-8", errors="ignore").splitlines()
        words = E.combinator([w for w in left if w], [w for w in right if w])
        _save(words, v.get("output", "") or "wordlist_combo.txt", lg)

    panel.add(ToolCard(
        panel, icon="🧬", title=t("modules.wordlist.combinator"),
        description=t("modules.wordlist.combinator_desc"),
        fields=[
            FormField("left", t("ui.list_a"), kind="file"),
            FormField("right", t("ui.list_b"), kind="file"),
            FormField("output", t("ui.output_file"), default="wordlist_combo.txt"),
        ],
        on_run=run_comb, runner=runner, log=log, category_color=color,
    ))

    def run_leet(v, lg):
        words = [w.strip() for w in str(v.get("words", "")).splitlines() if w.strip()]
        if not words:
            lg(f"[-] {t('ui.required')}", "err"); return
        mut = E.leet_mutate(words)
        _save(mut, v.get("output", "") or "wordlist_leet.txt", lg)

    panel.add(ToolCard(
        panel, icon="🔀", title=t("modules.wordlist.rule_mutator"),
        description=t("modules.wordlist.rule_mutator_desc"),
        fields=[
            FormField("words", t("ui.seed_words"), kind="textarea"),
            FormField("output", t("ui.output_file"), default="wordlist_leet.txt"),
        ],
        on_run=run_leet, runner=runner, log=log, category_color=color,
    ))

    def run_pattern(v, lg):
        charset = str(v.get("charset", "")) or "abcdefghijklmnopqrstuvwxyz"
        mn = max(1, _int(v.get("min"), 1)); mx = max(mn, _int(v.get("max"), 4))
        out = v.get("output", "") or "wordlist_pattern.txt"
        from pathlib import Path
        path = Path(out).resolve(); path.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with path.open("w", encoding="utf-8") as fh:
            for w in E.pattern_generate(charset, mn, mx):
                fh.write(w + "\n"); count += 1
                if count >= 1_000_000:
                    lg("[!] Truncated at 1,000,000 words", "warn"); break
        lg(f"[+] {t('modules.wordlist.wordlist_saved', count=count, path=path)}", "ok")

    panel.add(ToolCard(
        panel, icon="🎰", title=t("modules.wordlist.crunch_wrapper"),
        description=t("modules.wordlist.crunch_wrapper_desc"),
        fields=[
            FormField("charset", t("modules.wordlist.charset"),
                      default="abcdefghijklmnopqrstuvwxyz"),
            FormField("min", t("modules.wordlist.min_length"), default="1"),
            FormField("max", t("modules.wordlist.max_length"), default="4"),
            FormField("output", t("ui.output_file"), default="wordlist_pattern.txt"),
        ],
        on_run=run_pattern, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
def build_sql_injection(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["sql_injection"]
    panel = CategoryPanel(master, t("modules.sql_injection.title"), "💉", color)

    def run_detect(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.sqli_detect(url, lg)

    panel.add(ToolCard(
        panel, icon="🔍", title=t("modules.sql_injection.detect"),
        description=t("modules.sql_injection.detect_desc"),
        fields=[FormField("url", t("ui.url"),
                          placeholder="https://site.com/page?id=1")],
        on_run=run_detect, runner=runner, log=log, category_color=color,
    ))

    def run_sqlmap(v, lg):
        import shutil
        import subprocess
        url = _require(v, "url", lg, t("ui.url"))
        if not url: return
        if not shutil.which("sqlmap"):
            lg(t("ui.missing_tool", tool="sqlmap"), "err"); return
        extra = str(v.get("extra", "")).split()
        cmd = ["sqlmap", "-u", url, "--batch"] + extra
        lg(f"[*] {' '.join(cmd)}", "cyan")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="ignore")
            assert proc.stdout is not None
            for line in proc.stdout:
                lg(line.rstrip(), "info")
            proc.wait()
        except OSError as exc:
            lg(f"[-] {exc}", "err")

    panel.add(ToolCard(
        panel, icon="🤖", title=t("modules.sql_injection.sqlmap"),
        description=t("modules.sql_injection.sqlmap_desc"),
        fields=[
            FormField("url", t("ui.url"),
                      placeholder="https://site.com/page?id=1"),
            FormField("extra", t("modules.sql_injection.sqlmap_options"),
                      placeholder="--dbs --risk=1"),
        ],
        on_run=run_sqlmap, runner=runner, log=log, category_color=color,
    ))

    def run_payloads(v, lg):
        for p in E.SQL_PAYLOADS:
            lg(f"  {p}", "info")

    panel.add(ToolCard(
        panel, icon="📋", title=t("modules.sql_injection.payload_list"),
        description=t("modules.sql_injection.payload_list_desc"),
        fields=[],
        on_run=run_payloads, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Web attacks
# ---------------------------------------------------------------------------
def build_web_attacks(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["web_attacks"]
    panel = CategoryPanel(master, t("modules.web_attacks.title"), "🌐", color)

    def run_buster(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if not url: return
        from pathlib import Path
        wl = str(v.get("wordlist", "")).strip()
        if wl and Path(wl).is_file():
            paths = [p.strip() for p in Path(wl).read_text(encoding="utf-8",
                    errors="ignore").splitlines() if p.strip()]
        else:
            paths = E.DEFAULT_WEB_PATHS
        E.buster(url, paths, _int(v.get("threads"), 30), lg)

    panel.add(ToolCard(
        panel, icon="📁", title=t("modules.web_attacks.dir_buster"),
        description=t("modules.web_attacks.dir_buster_desc"),
        fields=[
            FormField("url", t("ui.url"), placeholder="https://example.com"),
            FormField("wordlist", t("modules.web_attacks.wordlist_path"),
                      kind="file"),
            FormField("threads", t("ui.threads"), default="30"),
        ],
        on_run=run_buster, runner=runner, log=log, category_color=color,
    ))

    def run_hdrscan(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.check_security_headers(url, lg)

    panel.add(ToolCard(
        panel, icon="🛡️", title=t("modules.web_attacks.header_scanner"),
        description=t("modules.web_attacks.header_scanner_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com")],
        on_run=run_hdrscan, runner=runner, log=log, category_color=color,
    ))

    def run_robots(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.fetch_discovery_files(url, lg)

    panel.add(ToolCard(
        panel, icon="🤖", title=t("modules.web_attacks.robots_sitemap"),
        description=t("modules.web_attacks.robots_sitemap_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com")],
        on_run=run_robots, runner=runner, log=log, category_color=color,
    ))

    def run_tech(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.detect_tech(url, lg)

    panel.add(ToolCard(
        panel, icon="🧪", title=t("modules.web_attacks.tech_detect"),
        description=t("modules.web_attacks.tech_detect_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com")],
        on_run=run_tech, runner=runner, log=log, category_color=color,
    ))

    def run_url(v, lg):
        import requests
        url = _require(v, "url", lg, t("ui.url"))
        if not url: return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            r = requests.get(url, timeout=10, allow_redirects=True,
                             headers={"User-Agent": "PENETRATOR/1.0"})
            lg(f"[+] {r.status_code}  final: {r.url}", "ok")
            for h in r.history:
                lg(f"  -> {h.status_code}  {h.url}", "muted")
        except requests.RequestException as exc:
            lg(f"[-] {exc}", "err")

    panel.add(ToolCard(
        panel, icon="🔗", title=t("modules.web_attacks.url_checker"),
        description=t("modules.web_attacks.url_checker_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com")],
        on_run=run_url, runner=runner, log=log, category_color=color,
    ))

    # HTTP Repeater
    def run_repeat(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if not url: return
        E.http_repeat(
            str(v.get("method", "GET")), url,
            str(v.get("headers", "")), str(v.get("body", "")),
            lg,
        )

    panel.add(ToolCard(
        panel, icon="🔁", title=t("modules.web_attacks.repeater"),
        description=t("modules.web_attacks.repeater_desc"),
        fields=[
            FormField("method", t("modules.web_attacks.method"),
                      kind="combo", default="GET",
                      options=["GET", "POST", "PUT", "DELETE", "PATCH",
                               "HEAD", "OPTIONS"]),
            FormField("url", t("ui.url"), placeholder="https://example.com/api"),
            FormField("headers", t("modules.web_attacks.headers"),
                      kind="textarea",
                      placeholder="Authorization: Bearer ...\nX-Custom: foo"),
            FormField("body", t("modules.web_attacks.body"), kind="textarea"),
        ],
        on_run=run_repeat, runner=runner, log=log, category_color=color,
    ))

    # CORS misconfig
    def run_cors(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.cors_test(url, lg)

    panel.add(ToolCard(
        panel, icon="🌍", title=t("modules.web_attacks.cors_test"),
        description=t("modules.web_attacks.cors_test_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com/api")],
        on_run=run_cors, runner=runner, log=log, category_color=color,
    ))

    # Open redirect
    def run_redir(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.open_redirect_test(url, lg)

    panel.add(ToolCard(
        panel, icon="↪️", title=t("modules.web_attacks.open_redirect"),
        description=t("modules.web_attacks.open_redirect_desc"),
        fields=[FormField("url", t("ui.url"),
                          placeholder="https://site.com/login?next=https://x")],
        on_run=run_redir, runner=runner, log=log, category_color=color,
    ))

    # WAF detection
    def run_waf(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.waf_detect(url, lg)

    panel.add(ToolCard(
        panel, icon="🛡️", title=t("modules.web_attacks.waf_detect"),
        description=t("modules.web_attacks.waf_detect_desc"),
        fields=[FormField("url", t("ui.url"), placeholder="https://example.com")],
        on_run=run_waf, runner=runner, log=log, category_color=color,
    ))

    # GraphQL introspection
    def run_gql(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.graphql_introspect(url, lg)

    panel.add(ToolCard(
        panel, icon="🟢", title=t("modules.web_attacks.graphql_introspect"),
        description=t("modules.web_attacks.graphql_introspect_desc"),
        fields=[FormField("url", t("ui.url"),
                          placeholder="https://example.com/graphql")],
        on_run=run_gql, runner=runner, log=log, category_color=color,
    ))

    # IMDS probe
    def run_imds(v, lg):
        url = _require(v, "url", lg, t("modules.web_attacks.via_url"))
        if url: E.imds_check(url, lg)

    panel.add(ToolCard(
        panel, icon="☁️", title=t("modules.web_attacks.imds_check"),
        description=t("modules.web_attacks.imds_check_desc"),
        fields=[FormField("url", t("modules.web_attacks.via_url"),
                          placeholder="https://victim/proxy?u={TARGET}")],
        on_run=run_imds, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Password tools
# ---------------------------------------------------------------------------
def build_password_tools(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["password_tools"]
    panel = CategoryPanel(master, t("modules.password_tools.title"), "🔑", color)

    def run_id(v, lg):
        val = _require(v, "hash", lg, t("modules.password_tools.hash_value"))
        if not val: return
        types = E.identify_hash(val)
        if types:
            lg(t("modules.password_tools.possible_types", types=", ".join(types)), "ok")
        else:
            lg("[-] No signature matched", "warn")

    panel.add(ToolCard(
        panel, icon="🆔", title=t("modules.password_tools.hash_identifier"),
        description=t("modules.password_tools.hash_identifier_desc"),
        fields=[FormField("hash", t("modules.password_tools.hash_value"))],
        on_run=run_id, runner=runner, log=log, category_color=color,
    ))

    def run_crack(v, lg):
        val = _require(v, "hash", lg, t("modules.password_tools.hash_value"))
        wl = _require(v, "wordlist", lg, t("modules.web_attacks.wordlist_path"))
        if not val or not wl: return
        result = E.crack_hash(val, str(v.get("algo", "md5")), wl, lg)
        if result:
            lg(t("modules.password_tools.found_match", password=result), "ok")
        else:
            lg(t("modules.password_tools.not_found"), "warn")

    panel.add(ToolCard(
        panel, icon="🔨", title=t("modules.password_tools.hash_cracker"),
        description=t("modules.password_tools.hash_cracker_desc"),
        fields=[
            FormField("hash", t("modules.password_tools.hash_value")),
            FormField("algo", t("modules.password_tools.hash_algo"),
                      kind="combo", default="md5",
                      options=list(E.SUPPORTED_HASH_ALGOS)),
            FormField("wordlist", t("modules.web_attacks.wordlist_path"),
                      kind="file"),
        ],
        on_run=run_crack, runner=runner, log=log, category_color=color,
    ))

    def run_strength(v, lg):
        pw = str(v.get("pw", ""))
        if not pw:
            lg(f"[-] {t('ui.required')}", "err"); return
        score, label = E.password_strength(pw)
        lg(t("modules.password_tools.strength_score", score=score, label=label),
           "ok" if score >= 3 else "warn")

    panel.add(ToolCard(
        panel, icon="📊", title=t("modules.password_tools.strength"),
        description=t("modules.password_tools.strength_desc"),
        fields=[FormField("pw", t("ui.password"), kind="password")],
        on_run=run_strength, runner=runner, log=log, category_color=color,
    ))

    def run_gen(v, lg):
        length = _int(v.get("length"), 16)
        pw = E.generate_password(length, bool(v.get("upper")),
                                 bool(v.get("digits")), bool(v.get("symbols")))
        lg(f"[+] {pw}", "ok")

    panel.add(ToolCard(
        panel, icon="🎲", title=t("modules.password_tools.gen_secure"),
        description=t("modules.password_tools.gen_secure_desc"),
        fields=[
            FormField("length", t("modules.password_tools.length"), default="16"),
            FormField("upper", t("modules.password_tools.include_upper"),
                      kind="check", default="1",
                      placeholder=t("modules.password_tools.include_upper")),
            FormField("digits", t("modules.password_tools.include_digits"),
                      kind="check", default="1",
                      placeholder=t("modules.password_tools.include_digits")),
            FormField("symbols", t("modules.password_tools.include_symbols"),
                      kind="check", default="1",
                      placeholder=t("modules.password_tools.include_symbols")),
        ],
        on_run=run_gen, runner=runner, log=log, category_color=color,
    ))

    # HIBP — pwned password check
    def run_hibp(v, lg):
        pw = str(v.get("pw", ""))
        if not pw:
            lg(f"[-] {t('ui.required')}", "err"); return
        E.hibp_password_check(pw, lg)

    panel.add(ToolCard(
        panel, icon="🛡️", title=t("modules.password_tools.hibp"),
        description=t("modules.password_tools.hibp_desc"),
        fields=[FormField("pw", t("ui.password"), kind="password")],
        on_run=run_hibp, runner=runner, log=log, category_color=color,
    ))

    # JWT decode
    def run_jwt_decode(v, lg):
        tok = _require(v, "token", lg, t("modules.password_tools.jwt_token"))
        if tok: E.jwt_decode(tok, lg)

    panel.add(ToolCard(
        panel, icon="🪪", title=t("modules.password_tools.jwt_decode"),
        description=t("modules.password_tools.jwt_decode_desc"),
        fields=[FormField("token", t("modules.password_tools.jwt_token"),
                          kind="textarea")],
        on_run=run_jwt_decode, runner=runner, log=log, category_color=color,
    ))

    # JWT brute
    def run_jwt_brute(v, lg):
        tok = _require(v, "token", lg, t("modules.password_tools.jwt_token"))
        wl = _require(v, "wordlist", lg, t("ui.wordlist_path"))
        if tok and wl: E.jwt_brute(tok, wl, lg)

    panel.add(ToolCard(
        panel, icon="🔓", title=t("modules.password_tools.jwt_brute"),
        description=t("modules.password_tools.jwt_brute_desc"),
        fields=[
            FormField("token", t("modules.password_tools.jwt_token"),
                      kind="textarea"),
            FormField("wordlist", t("ui.wordlist_path"), kind="file"),
        ],
        on_run=run_jwt_brute, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Steganography
# ---------------------------------------------------------------------------
def build_steganography(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["steganography"]
    panel = CategoryPanel(master, t("modules.steganography.title"), "🖼️", color)

    def run_hide_img(v, lg):
        cov = _require(v, "cover", lg, t("modules.steganography.cover_file"))
        msg = _require(v, "msg", lg, t("modules.steganography.message"))
        out = v.get("out", "") or "stego.png"
        if cov and msg: E.image_hide(cov, msg, out, lg)

    panel.add(ToolCard(
        panel, icon="🖼️", title=t("modules.steganography.image_hide"),
        description=t("modules.steganography.image_hide_desc"),
        fields=[
            FormField("cover", t("modules.steganography.cover_file"), kind="file"),
            FormField("msg", t("modules.steganography.message"), kind="textarea"),
            FormField("out", t("ui.output_file"), default="stego.png"),
        ],
        on_run=run_hide_img, runner=runner, log=log, category_color=color,
    ))

    def run_ext_img(v, lg):
        s = _require(v, "stego", lg, t("modules.steganography.stego_file"))
        if s: E.image_extract(s, lg)

    panel.add(ToolCard(
        panel, icon="📤", title=t("modules.steganography.image_extract"),
        description=t("modules.steganography.image_extract_desc"),
        fields=[FormField("stego", t("modules.steganography.stego_file"), kind="file")],
        on_run=run_ext_img, runner=runner, log=log, category_color=color,
    ))

    def run_hide_ws(v, lg):
        cov = _require(v, "cover", lg, t("modules.steganography.cover_file"))
        msg = _require(v, "msg", lg, t("modules.steganography.message"))
        out = v.get("out", "") or "stego.txt"
        if cov and msg: E.ws_hide(cov, msg, out, lg)

    panel.add(ToolCard(
        panel, icon="⎵", title=t("modules.steganography.whitespace_hide"),
        description=t("modules.steganography.whitespace_hide_desc"),
        fields=[
            FormField("cover", t("modules.steganography.cover_file"), kind="file"),
            FormField("msg", t("modules.steganography.message"), kind="textarea"),
            FormField("out", t("ui.output_file"), default="stego.txt"),
        ],
        on_run=run_hide_ws, runner=runner, log=log, category_color=color,
    ))

    def run_ext_ws(v, lg):
        s = _require(v, "stego", lg, t("modules.steganography.stego_file"))
        if s: E.ws_extract(s, lg)

    panel.add(ToolCard(
        panel, icon="📤", title=t("modules.steganography.whitespace_extract"),
        description=t("modules.steganography.whitespace_extract_desc"),
        fields=[FormField("stego", t("modules.steganography.stego_file"), kind="file")],
        on_run=run_ext_ws, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# XSS tools
# ---------------------------------------------------------------------------
def build_xss_tools(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["xss_tools"]
    panel = CategoryPanel(master, t("modules.xss_tools.title"), "⚡", color)

    def run_payloads(v, lg):
        kind = str(v.get("kind", "basic"))
        payloads = {
            "basic": E.XSS_PAYLOADS_BASIC,
            "polyglot": E.XSS_PAYLOADS_POLYGLOT,
            "waf": E.XSS_PAYLOADS_WAF,
        }.get(kind, E.XSS_PAYLOADS_BASIC)
        for p in payloads:
            lg(f"  {p}", "info")
        lg(t("modules.xss_tools.payload_saved", count=len(payloads)), "ok")

    panel.add(ToolCard(
        panel, icon="📋", title=t("modules.xss_tools.payload_generator"),
        description=t("modules.xss_tools.payload_generator_desc"),
        fields=[FormField("kind", t("modules.xss_tools.payload_type"),
                          kind="combo", default="basic",
                          options=["basic", "polyglot", "waf"])],
        on_run=run_payloads, runner=runner, log=log, category_color=color,
    ))

    def run_refl(v, lg):
        url = _require(v, "url", lg, t("ui.url"))
        if url: E.xss_reflected(url, lg)

    panel.add(ToolCard(
        panel, icon="🪞", title=t("modules.xss_tools.reflected_scanner"),
        description=t("modules.xss_tools.reflected_scanner_desc"),
        fields=[FormField("url", t("ui.url"),
                          placeholder="https://site.com/page?q=test")],
        on_run=run_refl, runner=runner, log=log, category_color=color,
    ))

    def run_encode(v, lg):
        p = str(v.get("payload", ""))
        if not p:
            lg(f"[-] {t('ui.required')}", "err"); return
        for k, val in E.xss_encodings(p).items():
            lg(f"  {k:<16} {val}", "info")

    panel.add(ToolCard(
        panel, icon="🔣", title=t("modules.xss_tools.encoder"),
        description=t("modules.xss_tools.encoder_desc"),
        fields=[FormField("payload", t("ui.payload"), kind="textarea",
                          default="<script>alert(1)</script>")],
        on_run=run_encode, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Reverse engineering
# ---------------------------------------------------------------------------
def build_reverse_engineering(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["reverse_engineering"]
    panel = CategoryPanel(master, t("modules.reverse.title"), "🧩", color)

    def run_str(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p:
            n = _int(v.get("min"), 4)
            results = E.extract_strings(p, n, lg)
            for off, s in results[:500]:
                lg(f"  0x{off:08x}  {s}", "muted")

    panel.add(ToolCard(
        panel, icon="🔤", title=t("modules.reverse.strings"),
        description=t("modules.reverse.strings_desc"),
        fields=[
            FormField("path", t("ui.file_path"), kind="file"),
            FormField("min", t("modules.reverse.min_str_length"), default="4"),
        ],
        on_run=run_str, runner=runner, log=log, category_color=color,
    ))

    def run_pe(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p: E.parse_pe(p, lg)

    panel.add(ToolCard(
        panel, icon="🧬", title=t("modules.reverse.pe_info"),
        description=t("modules.reverse.pe_info_desc"),
        fields=[FormField("path", t("ui.file_path"), kind="file")],
        on_run=run_pe, runner=runner, log=log, category_color=color,
    ))

    def run_hex(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p:
            E.hex_dump(p, _int(v.get("off"), 0), _int(v.get("len"), 256), lg)

    panel.add(ToolCard(
        panel, icon="🔢", title=t("modules.reverse.hex_dump"),
        description=t("modules.reverse.hex_dump_desc"),
        fields=[
            FormField("path", t("ui.file_path"), kind="file"),
            FormField("off", t("modules.reverse.offset"), default="0"),
            FormField("len", t("ui.length"), default="256"),
        ],
        on_run=run_hex, runner=runner, log=log, category_color=color,
    ))

    def run_hash(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p: E.file_hashes(p, lg)

    panel.add(ToolCard(
        panel, icon="🔐", title=t("modules.reverse.hash_file"),
        description=t("modules.reverse.hash_file_desc"),
        fields=[FormField("path", t("ui.file_path"), kind="file")],
        on_run=run_hash, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Forensic tools
# ---------------------------------------------------------------------------
def build_forensic(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["forensic"]
    panel = CategoryPanel(master, t("modules.forensic.title"), "🔬", color)

    def run_exif(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p: E.read_exif(p, lg)

    panel.add(ToolCard(
        panel, icon="🏷️", title=t("modules.forensic.exif_reader"),
        description=t("modules.forensic.exif_reader_desc"),
        fields=[FormField("path", t("ui.file_path"), kind="file")],
        on_run=run_exif, runner=runner, log=log, category_color=color,
    ))

    def run_hex(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p: E.hex_dump(p, _int(v.get("off"), 0), _int(v.get("len"), 256), lg)

    panel.add(ToolCard(
        panel, icon="🔢", title=t("modules.forensic.hex_viewer"),
        description=t("modules.forensic.hex_viewer_desc"),
        fields=[
            FormField("path", t("ui.file_path"), kind="file"),
            FormField("off", t("modules.reverse.offset"), default="0"),
            FormField("len", t("ui.length"), default="256"),
        ],
        on_run=run_hex, runner=runner, log=log, category_color=color,
    ))

    def run_hash(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p: E.file_hashes(p, lg)

    panel.add(ToolCard(
        panel, icon="🔐", title=t("modules.forensic.file_hashes"),
        description=t("modules.forensic.file_hashes_desc"),
        fields=[FormField("path", t("ui.file_path"), kind="file")],
        on_run=run_hash, runner=runner, log=log, category_color=color,
    ))

    def run_magic(v, lg):
        p = _require(v, "path", lg, t("ui.file_path"))
        if p: E.identify_magic(p, lg)

    panel.add(ToolCard(
        panel, icon="✨", title=t("modules.forensic.file_magic"),
        description=t("modules.forensic.file_magic_desc"),
        fields=[FormField("path", t("ui.file_path"), kind="file")],
        on_run=run_magic, runner=runner, log=log, category_color=color,
    ))

    def run_cmp(v, lg):
        a = _require(v, "a", lg, "File A")
        b = _require(v, "b", lg, "File B")
        if a and b: E.compare_files(a, b, lg)

    panel.add(ToolCard(
        panel, icon="🧾", title=t("modules.forensic.compare_files"),
        description=t("modules.forensic.compare_files_desc"),
        fields=[
            FormField("a", t("ui.file_a"), kind="file"),
            FormField("b", t("ui.file_b"), kind="file"),
        ],
        on_run=run_cmp, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Payload generator
# ---------------------------------------------------------------------------
def build_payload(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["payload"]
    panel = CategoryPanel(master, t("modules.payload.title"), "💣", color)

    def run_rev(v, lg):
        choice = str(v.get("kind", ""))
        lhost = _require(v, "lhost", lg, t("modules.payload.lhost"))
        lport = _require(v, "lport", lg, t("modules.payload.lport"))
        if not lhost or not lport: return
        tmpl = E.REVERSE_SHELL_TEMPLATES.get(choice)
        if not tmpl:
            lg(f"[-] Unknown type: {choice}", "err"); return
        lg(t("modules.payload.generated"), "cyan")
        lg(tmpl.format(lhost=lhost, lport=lport), "ok")

    panel.add(ToolCard(
        panel, icon="🔁", title=t("modules.payload.reverse_shell"),
        description=t("modules.payload.reverse_shell_desc"),
        fields=[
            FormField("kind", t("modules.payload.payload_choice"),
                      kind="combo", options=list(E.REVERSE_SHELL_TEMPLATES.keys()),
                      default=next(iter(E.REVERSE_SHELL_TEMPLATES.keys()))),
            FormField("lhost", t("modules.payload.lhost"), placeholder="10.0.0.5"),
            FormField("lport", t("modules.payload.lport"), default="4444"),
        ],
        on_run=run_rev, runner=runner, log=log, category_color=color,
    ))

    def run_bind(v, lg):
        choice = str(v.get("kind", ""))
        lport = _require(v, "lport", lg, t("modules.payload.lport"))
        if not lport: return
        tmpl = E.BIND_SHELL_TEMPLATES.get(choice)
        if not tmpl:
            lg(f"[-] Unknown type: {choice}", "err"); return
        lg(t("modules.payload.generated"), "cyan")
        lg(tmpl.format(lport=lport), "ok")

    panel.add(ToolCard(
        panel, icon="🎧", title=t("modules.payload.bind_shell"),
        description=t("modules.payload.bind_shell_desc"),
        fields=[
            FormField("kind", t("modules.payload.payload_choice"),
                      kind="combo", options=list(E.BIND_SHELL_TEMPLATES.keys()),
                      default=next(iter(E.BIND_SHELL_TEMPLATES.keys()))),
            FormField("lport", t("modules.payload.lport"), default="4444"),
        ],
        on_run=run_bind, runner=runner, log=log, category_color=color,
    ))

    def run_enc(v, lg):
        p = str(v.get("payload", ""))
        if not p:
            lg(f"[-] {t('ui.required')}", "err"); return
        for k, val in E.encode_payload(p).items():
            lg(f"  {k:<24} {val}", "info")

    panel.add(ToolCard(
        panel, icon="🔣", title=t("modules.payload.encoder"),
        description=t("modules.payload.encoder_desc"),
        fields=[FormField("payload", t("ui.text"), kind="textarea")],
        on_run=run_enc, runner=runner, log=log, category_color=color,
    ))

    def run_msfvenom(v, lg):
        import shutil
        import subprocess
        if not shutil.which("msfvenom"):
            lg(t("ui.missing_tool", tool="msfvenom"), "err"); return
        args = str(v.get("args", "")).split()
        if not args:
            lg(f"[-] {t('ui.required')}", "err"); return
        cmd = ["msfvenom"] + args
        lg(f"[*] {' '.join(cmd)}", "cyan")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="ignore")
            assert proc.stdout is not None
            for line in proc.stdout:
                lg(line.rstrip(), "info")
            proc.wait()
        except OSError as exc:
            lg(f"[-] {exc}", "err")

    panel.add(ToolCard(
        panel, icon="🧨", title=t("modules.payload.msfvenom"),
        description=t("modules.payload.msfvenom_desc"),
        fields=[FormField("args", t("ui.msfvenom_args"),
                          placeholder="-p windows/meterpreter/reverse_tcp LHOST=... LPORT=... -f exe -o a.exe")],
        on_run=run_msfvenom, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# OSINT
# ---------------------------------------------------------------------------
def build_osint(master, runner: TaskRunner, log: LogConsole):
    color = T.CATEGORY_COLORS["osint"]
    panel = CategoryPanel(master, t("modules.osint.title"), "🕵️", color)

    def run_email(v, lg):
        e = _require(v, "email", lg, t("ui.email"))
        if e: E.verify_email(e, lg)

    panel.add(ToolCard(
        panel, icon="✉️", title=t("modules.osint.email_verify"),
        description=t("modules.osint.email_verify_desc"),
        fields=[FormField("email", t("ui.email"), placeholder="user@example.com")],
        on_run=run_email, runner=runner, log=log, category_color=color,
    ))

    def run_geo(v, lg):
        ip = _require(v, "ip", lg, t("ui.ip"))
        if ip: E.ip_geolocate(ip, lg)

    panel.add(ToolCard(
        panel, icon="🌍", title=t("modules.osint.ip_geolocate"),
        description=t("modules.osint.ip_geolocate_desc"),
        fields=[FormField("ip", t("ui.ip"), placeholder="8.8.8.8")],
        on_run=run_geo, runner=runner, log=log, category_color=color,
    ))

    def run_user(v, lg):
        u = _require(v, "user", lg, "Username")
        if u: E.username_search(u, lg)

    panel.add(ToolCard(
        panel, icon="👤", title=t("modules.osint.username_search"),
        description=t("modules.osint.username_search_desc"),
        fields=[FormField("user", t("ui.username"))],
        on_run=run_user, runner=runner, log=log, category_color=color,
    ))

    def run_phone(v, lg):
        p = _require(v, "phone", lg, "Phone")
        if p: E.phone_info(p, lg)

    panel.add(ToolCard(
        panel, icon="📞", title=t("modules.osint.phone_info"),
        description=t("modules.osint.phone_info_desc"),
        fields=[FormField("phone", t("ui.phone_e164"), placeholder="+14155552671")],
        on_run=run_phone, runner=runner, log=log, category_color=color,
    ))

    def run_rdns(v, lg):
        ip = _require(v, "ip", lg, t("ui.ip"))
        if ip: E.reverse_dns(ip, lg)

    panel.add(ToolCard(
        panel, icon="↩️", title=t("modules.osint.reverse_dns"),
        description=t("modules.osint.reverse_dns_desc"),
        fields=[FormField("ip", t("ui.ip"), placeholder="8.8.8.8")],
        on_run=run_rdns, runner=runner, log=log, category_color=color,
    ))

    return panel


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
BUILDERS: dict[str, Callable[..., ctk.CTkBaseClass]] = {
    "info_gathering":      build_info_gathering,
    "wordlist":            build_wordlist,
    "sql_injection":       build_sql_injection,
    "web_attacks":         build_web_attacks,
    "password_tools":      build_password_tools,
    "steganography":       build_steganography,
    "xss_tools":           build_xss_tools,
    "reverse_engineering": build_reverse_engineering,
    "forensic":            build_forensic,
    "payload":             build_payload,
    "osint":               build_osint,
}


# ---------------------------------------------------------------------------
# Plugin loading
# ---------------------------------------------------------------------------
def _wrap_with_plugins(category_key: str, original_builder):
    """Return a builder that calls the original then appends matching plugins."""
    def builder(master, runner: TaskRunner, log: LogConsole):
        panel = original_builder(master, runner=runner, log=log)
        try:
            import plugins as _plugins
        except ImportError:
            return panel
        category_color = T.CATEGORY_COLORS.get(category_key, T.ACCENT)
        for spec in _plugins.discover():
            if spec.get("category") != category_key:
                continue
            try:
                panel.add(ToolCard(
                    panel,
                    icon=spec.get("icon", "🧩"),
                    title=spec.get("title", spec.get("name", "Plugin")),
                    description=spec.get("description", ""),
                    fields=spec.get("fields") or [],
                    on_run=spec["run"],
                    runner=runner, log=log,
                    category_color=category_color,
                ))
            except Exception as exc:
                log.write(f"[-] Plugin {spec.get('name')} failed to mount: {exc}",
                          "err")
        return panel
    return builder


# Wrap each builder so plugins can hook in.
BUILDERS = {k: _wrap_with_plugins(k, v) for k, v in BUILDERS.items()}
