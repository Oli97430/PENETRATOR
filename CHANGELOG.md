# Changelog

All notable changes to **PENETRATOR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] — 2026-04-26

### Added — Tools (8 new)
- **Async directory buster** — aiohttp-based, ~5× faster on big wordlists.
- **Async subdomain finder** — asyncio DNS resolution.
- **Wayback Machine OSINT** — historical URLs from the Internet Archive,
  highlights `.env` / `.git` / `admin` / `api` / `dump` patterns.
- **GraphQL field enumeration** — brute-force common field names when
  introspection is OFF.
- **HTTP request smuggling detector** — single-pass CL.TE / TE.CL / TE.TE
  desync probes.
- **TLS chain tool** — runs TLS scan on every TLS-likely port from the last
  port scan (cross-tool memory).
- **Save workspace** (Settings) — exports session memory + log to `.penetrator`.
- **Load workspace** (Settings) — restores a saved session.

### Added — UX
- **Ctrl+P quick launcher** — VS Code-style fuzzy command palette
  (Up/Down/Enter/Esc).
- **PDF report export** (via fpdf2) and **Markdown report export**
  alongside HTML / JSON / TXT.
- **Cross-tool session memory** — `last_target` / `last_open_ports` /
  `last_subdomains` accessible to chain tools.

### Added — CLI parity
- 36 menu items now in Info Gathering / Web Attacks / Password Tools
  (was 17 in v1.3.x). The CLI calls the **same engine** as the GUI through
  `core/cli_bridge.py` — every Phase-2/3/7 tool is now reachable from the
  classic terminal UI.

### Added — DevOps
- **Auto-release on tag**: pushing `v*.*.*` builds the exe and creates a
  GitHub Release with notes extracted from CHANGELOG.md (no more manual
  `gh release create`).
- **CodeQL** Python analysis (per-PR + weekly schedule).
- **Bandit** security scan with summary report on every push.
- **pytest-cov + Codecov** badge.
- 5 new badges on README (CI / CodeQL / Security / Codecov / latest release).

### Changed
- 289 i18n keys × 5 languages, 0 missing.
- `Image.getdata()` already replaced in v1.3.1; engine now also writes session
  state on every port scan.

## [1.3.1] — 2026-04-26

### Added
- **Settings panel** gains a *Preferences* section: clear saved form values
  + open project on GitHub.
- **CLI smoke tests** (`tests/test_cli.py`): version format, banner render,
  i18n singleton, menu instantiation. Brings test suite to **27/27**.

### Changed
- Status bar, first-run dialog title, search placeholder, completion toast
  message, close-confirmation popup, and auto-updater banner all now go
  through `t()` — fully translated in EN / FR / ZH / ES / DE.
- Auto-updater message now shows "you have v{current}" on a separate line.
- `Image.getdata()` replaced with the modern `image.load()` pixel-access API
  (Pillow 14 will remove `getdata`).
- Ruff `--fix` pass cleaned 10 issues automatically; remaining warnings are
  documented advisory output (sent to GitHub Step Summary, no error annotations).

### Fixed
- CI no longer floods PRs with red `##[error]` annotations from advisory
  ruff output.
- `tkinterdnd2` is now bundled inside the standalone exe — drag-and-drop
  works out of the box for users on the .exe distribution.

### i18n
- 13 new `ui.*` keys (`ready`, `welcome`, `cancel`, `quit`,
  `task_running_quit`, `update_available`, `update_current`,
  `task_finished_in`, `filter_placeholder`, …).
- 4 new `menu.settings.*` keys (`clear_form_memory`, `form_memory_cleared`,
  `open_repo`, `preferences`).
- **271 keys × 5 languages = 1355 entries**, all resolved.

## [1.3.0] — 2026-04-26

### Added — Tools (6 new)
- **Async port scanner** (`scan_ports_async`) — asyncio rewrite, ~2× faster on
  small ranges and far better on /16-style enumeration.
- **CORS misconfiguration tester** — probes 5 hostile origins and flags risky
  reflection / wildcard + creds combos.
- **Open Redirect tester** — 5 redirect-payload variants on every URL parameter.
- **WAF detection** — 13 fingerprints (Cloudflare, AWS, Akamai, Imperva, F5,
  Barracuda, ModSecurity, Wallarm, StackPath, Fastly, Azure FD, Google Cloud
  Armor) + generic-block heuristic.
- **GraphQL introspection tester** — POSTs `__schema` query, reports if
  introspection is enabled and how many types are exposed.
- **Cloud IMDS probe** — checks AWS / Azure / GCP / Oracle / DigitalOcean /
  Alibaba / Hetzner metadata endpoints, directly or via a `{TARGET}` SSRF URL
  template.

### Added — UX
- **HTML report export** — beautifully styled dark-themed log report
  (`Save → .html`).
- **Drag-and-drop** files into file fields when `tkinterdnd2` is installed.

### Fixed
- CI now installs `pytest` (was missing from the workflow → tests skipped).
- `compileall` scope corrected (was choking on `locales/`).
- Lint step demoted to advisory output and ruff config relaxed for legacy
  modules (no more red CI status from style nits).

### Changed
- 5 locales updated to 258 keys each (full coverage of new tools).

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
