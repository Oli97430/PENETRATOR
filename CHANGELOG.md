# Changelog

All notable changes to **PENETRATOR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] — 2026-04-26

### Added — Tools (7 new)
- **crt.sh subdomain enumeration** via Certificate Transparency logs.
- **Banner grabbing** — port scan + grab service banners on open ports.
- **TLS / SSL Scanner** — cert chain, expiry, legacy SSLv3 / TLS 1.0 / 1.1 probe.
- **Subdomain Takeover Detector** — 17 service fingerprints (S3, GitHub Pages,
  Heroku, Azure, Fastly, Shopify, etc.).
- **HIBP Pwned Password check** via k-anonymity API (no key needed).
- **JWT Decoder** + **JWT HMAC brute-force** (HS256/384/512).
- **HTTP Repeater** — Burp-like custom request sender.

### Added — UX
- **Stop button** on every tool — cooperative cancellation via
  `threading.Event` + engine-level `_should_stop()` checks in long loops.
- **Form memory** — every tool remembers its inputs across launches
  (passwords and large textareas excluded).
- **Sidebar search bar** — live-filter categories.
- **JSON export** of the log console alongside `.txt`.
- **Completion toast** — Windows toast or bell+flash when a long task (>15s)
  ends while the window is unfocused.
- **Auto-updater** — checks GitHub Releases on launch and announces newer
  versions in the log.
- **Plugin system** — drop a `.py` file in `plugins/` defining a `PLUGIN`
  dict, and PENETRATOR loads it into the matching category panel.

### Added — i18n
- **Spanish (es)** locale — full translation, 244 keys.
- **German (de)** locale — full translation, 244 keys.
- 5 supported languages: EN / FR / ZH / ES / DE — live switchable.

### Added — Project hygiene
- GitHub Actions CI: compile + pytest + locale check on Win 3.10/3.11/3.12.
- pytest suite (`tests/`) — 21 functional checks of `gui.engine.*`.
- `tests/check_locales.py` — validates every translation key across all locales.
- Dependabot config (weekly pip + monthly actions).
- Issue + PR templates (bug, feature request).
- `CONTRIBUTING.md` and full `pyproject.toml` (ruff + pytest config).
- Pre-commit hooks (ruff format + lint + whitespace).
- Branch protection on `main` (no force-push, no delete).

### Changed
- 12 hardcoded English strings in `gui/tools.py` moved to `ui.*` i18n keys.
- `PENETRATOR.spec` now excludes matplotlib / numpy / scipy / jupyter — exe
  download trimmed by ~30 MB.

## [1.1.0] — 2026-04-25

### Added
- **Modern dark GUI** built on CustomTkinter with sidebar navigation, input forms
  per tool, shared live log console, and bottom status bar.
- **First-run language picker** (modal) — pick EN / FR / 中文 on first launch.
- **Live language switching** — change UI language without restart.
- **Bottom status bar** — live clock, version, language, author, busy/idle indicator.
- **Keyboard shortcuts** — `Ctrl+L` clear log · `Ctrl+S` save log · `Ctrl+Q` quit ·
  `Ctrl+,` settings · `F1` about.
- **Last-category persistence** — re-opens on the previously used category.
- **Save log** button — exports the console to a timestamped `.txt`.
- **Confirm-on-close** when a task is still running.
- **Window icon** (`assets/logo.ico`) — dagger silhouette on dark bg.
- **One-click installer** — `install.bat` / `install.ps1` detects Python, installs
  deps, installs `sqlmap`, drops a desktop shortcut.
- **Standalone `PENETRATOR.exe`** built with PyInstaller (no Python required).
- **42 tools** across 11 categories — info gathering, wordlist, SQLi, web attacks,
  password tools, steganography, XSS, reverse engineering, forensic, payload
  generator, OSINT.

### Changed
- CLI entry point renamed to `penetrator_cli.py` to free `penetrator.py` for the GUI.
- Pure-logic functions extracted to `gui/engine.py`, shared between GUI and CLI.

## [1.0.0] — 2026-04-22

### Added
- Initial Python 3 CLI port — Rich-based menu UI with 11 categories.
- Full i18n support (English / Français / 中文) with JSON locale files.
- Auto-installer (Windows): `install.bat` + `install.ps1`.
