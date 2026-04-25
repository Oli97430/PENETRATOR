"""PENETRATOR — modern GUI entry point.

Run this to start the graphical interface. For the CLI version, use
``penetrator_cli.py``.
"""
from __future__ import annotations

import sys

# Force UTF-8 so Chinese characters render correctly on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main() -> int:
    try:
        from gui import App
    except ImportError as exc:
        print(f"[-] Missing dependencies: {exc}")
        print("    Run install.bat (or install.ps1) once to set things up.")
        return 2

    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
