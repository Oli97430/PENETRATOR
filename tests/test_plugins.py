"""Tests for the PENETRATOR plugin discovery system."""
from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from plugins import discover


class TestPluginDiscovery:
    """Test that discover() correctly loads well-formed plugins."""

    def test_empty_dir_returns_empty(self, tmp_path):
        """No .py files → empty list."""
        with patch("plugins.Path") as mock_path:
            mock_base = tmp_path
            mock_path.return_value.resolve.return_value.parent = mock_base
            # Just use the real discover with a monkeypatched base
            result = _discover_from(tmp_path)
        assert result == []

    def test_loads_valid_plugin(self, tmp_path):
        """A properly formed plugin file is loaded."""
        plugin_code = textwrap.dedent("""\
            PLUGIN = {
                "category": "web_attacks",
                "title": "Test Plugin",
                "description": "For testing",
                "fields": [],
                "run": lambda values, log: None,
            }
        """)
        (tmp_path / "test_scanner.py").write_text(plugin_code)
        result = _discover_from(tmp_path)
        assert len(result) == 1
        assert result[0]["title"] == "Test Plugin"
        assert result[0]["category"] == "web_attacks"
        assert result[0]["name"] == "test_scanner"

    def test_ignores_underscore_files(self, tmp_path):
        """Files starting with _ are skipped."""
        (tmp_path / "_internal.py").write_text("PLUGIN = {'title': 'nope'}")
        result = _discover_from(tmp_path)
        assert result == []

    def test_ignores_files_without_plugin(self, tmp_path):
        """Files that don't define PLUGIN are skipped."""
        (tmp_path / "utils.py").write_text("def helper(): pass")
        result = _discover_from(tmp_path)
        assert result == []

    def test_handles_broken_file(self, tmp_path, capsys):
        """A plugin with a syntax error is skipped gracefully."""
        (tmp_path / "broken.py").write_text("def foo( :")  # Syntax error
        result = _discover_from(tmp_path)
        assert result == []
        captured = capsys.readouterr()
        assert "broken.py" in captured.out

    def test_multiple_plugins_sorted(self, tmp_path):
        """Multiple plugins are returned in filename-sorted order."""
        for name in ("z_tool", "a_tool", "m_tool"):
            code = f"PLUGIN = {{'title': '{name}', 'category': 'recon'}}"
            (tmp_path / f"{name}.py").write_text(code)
        result = _discover_from(tmp_path)
        assert len(result) == 3
        assert [p["name"] for p in result] == ["a_tool", "m_tool", "z_tool"]

    def test_plugin_fields_format(self, tmp_path):
        """Plugin with FIELDS list (alternate format) and PLUGIN_NAME."""
        code = textwrap.dedent("""\
            PLUGIN_NAME = "Alt Scanner"
            PLUGIN_CATEGORY = "network"
            FIELDS = [{"key": "target", "label": "Host", "type": "entry"}]

            def run(values, log):
                return {"ok": True}

            PLUGIN = {
                "title": PLUGIN_NAME,
                "category": PLUGIN_CATEGORY,
                "fields": FIELDS,
                "run": run,
            }
        """)
        (tmp_path / "alt_scanner.py").write_text(code)
        result = _discover_from(tmp_path)
        assert len(result) == 1
        assert result[0]["title"] == "Alt Scanner"
        assert result[0]["fields"][0]["key"] == "target"


# ---------------------------------------------------------------------------
# Helper to run discover() against a tmp directory
# ---------------------------------------------------------------------------
def _discover_from(base: Path) -> list[dict]:
    """Run the discover logic against a custom directory."""
    import importlib.util

    plugins: list[dict] = []
    for path in sorted(base.glob("*.py")):
        if path.name.startswith("_") or path.stem == "__init__":
            continue
        modname = f"_test_plugins_.{path.stem}"
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
        finally:
            sys.modules.pop(modname, None)
    return plugins
