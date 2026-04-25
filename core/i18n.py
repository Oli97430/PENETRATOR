"""Internationalization (i18n) system for PENETRATOR.

Supports English, French and Chinese. Translations are loaded from JSON files
in the ``locales/`` directory. Keys use dot-notation (e.g. ``menu.main.title``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class I18n:
    """Minimal dot-notation JSON translation loader."""

    SUPPORTED = ("en", "fr", "zh")
    DEFAULT = "en"

    _instance: "I18n | None" = None

    def __init__(self, locales_dir: Path | None = None) -> None:
        base = Path(__file__).resolve().parent.parent
        self.locales_dir = locales_dir or (base / "locales")
        self.config_path = base / "config.json"
        self._cache: dict[str, dict[str, Any]] = {}
        self.language = self._load_preferred()

    # --- language management ---------------------------------------------
    def _load_preferred(self) -> str:
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            lang = data.get("language", self.DEFAULT)
            if lang in self.SUPPORTED:
                return lang
        except (OSError, json.JSONDecodeError):
            pass
        return self.DEFAULT

    def save_preferred(self, language: str) -> None:
        if language not in self.SUPPORTED:
            raise ValueError(f"Unsupported language: {language}")
        self.language = language
        self.set_config("language", language)

    def get_config(self, key: str, default: Any = None) -> Any:
        if not self.config_path.exists():
            return default
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default
        return data.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        data: dict[str, Any] = {}
        if self.config_path.exists():
            try:
                data = json.loads(self.config_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {}
        data[key] = value
        self.config_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def set_language(self, language: str) -> None:
        if language not in self.SUPPORTED:
            raise ValueError(f"Unsupported language: {language}")
        self.language = language

    # --- translation -----------------------------------------------------
    def _load(self, language: str) -> dict[str, Any]:
        if language not in self._cache:
            path = self.locales_dir / f"{language}.json"
            self._cache[language] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[language]

    def translate(self, key: str, **kwargs: Any) -> str:
        """Resolve ``key`` through nested dictionaries with dot-notation.

        Falls back to the default language, then to the key itself if missing.
        ``kwargs`` are substituted with ``str.format``.
        """
        value = self._resolve(self.language, key)
        if value is None and self.language != self.DEFAULT:
            value = self._resolve(self.DEFAULT, key)
        if value is None:
            return key
        if kwargs:
            try:
                return value.format(**kwargs)
            except (KeyError, IndexError):
                return value
        return value

    def _resolve(self, language: str, key: str) -> str | None:
        try:
            data: Any = self._load(language)
        except (OSError, json.JSONDecodeError):
            return None
        for part in key.split("."):
            if isinstance(data, dict) and part in data:
                data = data[part]
            else:
                return None
        return data if isinstance(data, str) else None

    # --- singleton access ------------------------------------------------
    @classmethod
    def get(cls) -> "I18n":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


def t(key: str, **kwargs: Any) -> str:
    """Module-level shortcut: ``t("menu.main.title")``."""
    return I18n.get().translate(key, **kwargs)
