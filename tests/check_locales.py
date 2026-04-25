"""Verify that every t() / label_key= / description_key= literal resolves
in every locale."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOCALES = ROOT / "locales"


def collect_keys() -> set[str]:
    """Walk all .py files under repo, extract translation keys."""
    patterns = [
        re.compile(r"""\bt\(\s*['"]([a-zA-Z0-9_.]+)['"]\s*[\),]"""),
        re.compile(r"""\blabel_key\s*=\s*['"]([a-zA-Z0-9_.]+)['"]"""),
        re.compile(r"""\bdescription_key\s*=\s*['"]([a-zA-Z0-9_.]+)['"]"""),
    ]
    keys: set[str] = set()
    for path in ROOT.rglob("*.py"):
        if any(p.startswith(".") for p in path.parts):
            continue
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in patterns:
            keys.update(pat.findall(text))
    return keys


def resolve(data: dict, key: str) -> bool:
    cur = data
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False
    return isinstance(cur, str)


def main() -> int:
    keys = collect_keys()
    locales = {}
    for lang in ("en", "fr", "zh", "es", "de"):
        path = LOCALES / f"{lang}.json"
        if not path.exists():
            print(f"[!] {lang}.json missing — skipped")
            continue
        locales[lang] = json.loads(path.read_text(encoding="utf-8"))

    missing: dict[str, list[str]] = {lang: [] for lang in locales}
    for k in sorted(keys):
        for lang, data in locales.items():
            if not resolve(data, k):
                missing[lang].append(k)

    failed = False
    for lang, miss in missing.items():
        if miss:
            failed = True
            print(f"[-] {lang}: {len(miss)} missing keys")
            for k in miss[:20]:
                print(f"      {k}")
            if len(miss) > 20:
                print(f"      ... +{len(miss) - 20} more")
        else:
            print(f"[+] {lang}: all {len(keys)} keys resolve")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
