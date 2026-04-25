"""PENETRATOR plugin system.

Drop a Python file in this directory that defines a top-level ``PLUGIN``
dict, and PENETRATOR will load it on startup. Example:

    # plugins/my_tool.py
    from gui.widgets import FormField
    from gui import engine as E

    def my_tool_logic(target, log):
        log(f"[+] Running my custom tool against {target}", "ok")
        # ...

    PLUGIN = {
        "category": "info_gathering",   # which sidebar entry to attach to
        "icon": "🧪",
        "title": "My Custom Tool",
        "description": "What it does",
        "fields": [FormField("target", "Target")],
        "run": lambda values, log: my_tool_logic(values["target"], log),
    }

The plugin is appended to its category's panel automatically.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


def discover() -> list[dict[str, Any]]:
    """Load every .py file in the plugins/ folder that defines PLUGIN."""
    plugins: list[dict[str, Any]] = []
    base = Path(__file__).resolve().parent
    for path in sorted(base.glob("*.py")):
        if path.name.startswith("_") or path.stem == "__init__":
            continue
        modname = f"plugins.{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[modname] = module
            spec.loader.exec_module(module)
            obj = getattr(module, "PLUGIN", None)
            if isinstance(obj, dict):
                obj.setdefault("name", path.stem)
                plugins.append(obj)
        except Exception as exc:
            print(f"[plugins] Failed to load {path.name}: {exc}")
    return plugins
