# Contributing to PENETRATOR

Thanks for your interest in improving PENETRATOR! This document explains how to
get a working dev environment, the project's coding conventions, and how to
submit changes.

---

## 🛠️  Dev setup

```powershell
# clone
git clone https://github.com/Oli97430/PENETRATOR.git
cd PENETRATOR

# install
install.bat                    # one-click
# or, manually:
pip install -r requirements.txt
pip install ruff pytest pip-audit pre-commit
pre-commit install             # enable git hooks

# run
python penetrator.py           # GUI
python penetrator_cli.py       # classic CLI

# test
python -m pytest tests/ -v
python tests/check_locales.py  # verify locales are complete
```

---

## 🧱 Project layout

```
core/        # CLI helpers (banner, i18n, menu, utils)
gui/         # CustomTkinter GUI
  app.py     # main App shell (sidebar + header + content + log + status bar)
  engine.py  # pure-logic functions, take `log(msg, tag)` callback
  tools.py   # one frame builder per category (assembles InputForms)
  widgets.py # reusable widgets
  theme.py   # palette, fonts, geometry constants
modules/     # CLI tool modules (one per category)
locales/     # en.json / fr.json / zh.json
assets/      # logo.svg, logo.ico, screenshots
tests/       # pytest suite + locale checker
```

---

## ✍️  Adding a new tool

1. Add the **pure-logic function** to `gui/engine.py`. It must accept a
   `log: Callable[..., None]` callback as last argument and call it for output.
   Pure logic = no `print`, no `input`, no `tkinter`.
2. Add **i18n keys** in all three locales (`en.json`, `fr.json`, `zh.json`)
   under the appropriate `modules.<category>.*` section.
3. In `gui/tools.py`, register a `ToolCard` in the category's builder with a
   list of `FormField` and an `on_run` callback that calls your engine function.
4. (Optional) In `modules/<category>.py`, add a CLI menu item that calls the
   same engine function.
5. Add at least one test in `tests/test_engine.py` covering the pure-logic
   function.

---

## 🌍 Adding a new language

1. Copy `locales/en.json` → `locales/<code>.json` (e.g., `es.json`).
2. Translate every string. Run `python tests/check_locales.py` to verify
   no key is missing.
3. Update `core/i18n.py::I18n.SUPPORTED` and `gui/app.py::LANG_LABELS`.
4. Open a PR — the CI will validate completeness.

---

## ✅ Coding conventions

- **Python 3.9+**. We use `from __future__ import annotations` everywhere.
- **Format / lint** via `ruff` (configured in `pyproject.toml`).
- **No new top-level prints**. Engine functions speak only via the `log` callback.
- **No new external binary requirements** unless gracefully degraded with
  `shutil.which` and a clear "missing tool" message.
- **No phishing kits, hidden RATs, keyloggers, spycams, DDoS tools** — these
  categories are intentionally excluded; PRs adding them will be rejected.

---

## 🚀 Pull requests

- **One topic per PR.** Easier to review & revert.
- **Update CHANGELOG.md** under `[Unreleased]`.
- **Pass CI green.** The CI runs compile-check + pytest + locale check on
  Python 3.10, 3.11 and 3.12.
- **Be friendly.** First-time contributors get extra patience.

---

## ⚖️  Legal

By contributing you affirm your code is **your work** (or properly attributed),
that you have the right to license it under MIT, and that you understand
PENETRATOR is a tool for **education / authorized pentest / CTF** — your
contribution must respect that scope.

Thanks for making PENETRATOR better! 🗡️
