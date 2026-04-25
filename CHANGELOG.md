# Changelog

All notable changes to **PENETRATOR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI: compile + pytest + locale check on every push.
- Test suite (`tests/`) with 19 functional checks of `gui.engine.*`.
- `tests/check_locales.py` — verifies every `t()` / `label_key` / `description_key`
  resolves in EN / FR / ZH.

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
