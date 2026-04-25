"""Update checker — queries GitHub Releases API."""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Callable

REPO = "Oli97430/PENETRATOR"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"


def _parse_version(tag: str) -> tuple[int, int, int] | None:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", tag.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def check_latest(current: str, log: Callable[[str, str], None] | None = None
                 ) -> dict | None:
    """Query GitHub for the latest release. Returns:
        {"latest": "1.2.0", "url": "...", "newer": True/False}
    or None if the check failed.
    """
    def _log(msg: str, tag: str = "info") -> None:
        if log is not None:
            log(msg, tag)

    try:
        req = urllib.request.Request(
            API_URL,
            headers={"User-Agent": f"PENETRATOR/{current}",
                     "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        _log(f"[-] Update check failed: {exc}", "muted")
        return None

    tag = (data.get("tag_name") or "").strip()
    parsed = _parse_version(tag)
    if parsed is None:
        return None
    cur = _parse_version(current)
    if cur is None:
        return None

    return {
        "latest": ".".join(str(x) for x in parsed),
        "current": ".".join(str(x) for x in cur),
        "url": data.get("html_url", f"https://github.com/{REPO}/releases/latest"),
        "newer": parsed > cur,
        "name": data.get("name") or tag,
    }
