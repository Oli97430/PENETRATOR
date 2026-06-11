from gui.engine._core import *
from gui.engine.recon import find_subdomains
from gui.engine.web import check_security_headers
from gui.engine.network import tls_scan
from gui.engine.advanced import (
    cors_test, open_redirect_test, waf_detect,
    lfi_scan, ssrf_scan,
)
from gui.engine.automation import attack_chain
from gui.engine.auth import (
    cookie_audit, csrf_analyze, subdomain_permutation,
)
from gui.engine.discovery import (
    tech_fingerprint, ssti_scan, js_endpoint_extract,
)

# ===================================================================
#  Architecture Features: CVSS, Profiles, Scope, DB, SARIF
# ===================================================================

# ---------------------------------------------------------------------------
# CVSS v3.1 Calculator
# ---------------------------------------------------------------------------
_CVSS31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": False, "C": True},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss_calculate(vector: str, log: Logger) -> dict:
    """Calculate CVSS v3.1 base score from a vector string.

    Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    import math as _math
    log(f"[*] CVSS v3.1 calculation: {vector}", "cyan")
    result: dict = {"vector": vector, "score": 0.0, "severity": "None",
                    "metrics": {}}

    # Parse vector
    parts = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    result["metrics"] = metrics

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    for m in required:
        if m not in metrics:
            log(f"[-] Missing metric: {m}", "err")
            return result

    try:
        av = _CVSS31_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS31_WEIGHTS["AC"][metrics["AC"]]
        scope_changed = _CVSS31_WEIGHTS["S"][metrics["S"]]
        pr_scope = "C" if scope_changed else "U"
        pr = _CVSS31_WEIGHTS["PR"][pr_scope][metrics["PR"]]
        ui = _CVSS31_WEIGHTS["UI"][metrics["UI"]]
        c = _CVSS31_WEIGHTS["C"][metrics["C"]]
        i = _CVSS31_WEIGHTS["I"][metrics["I"]]
        a = _CVSS31_WEIGHTS["A"][metrics["A"]]
    except KeyError as exc:
        log(f"[-] Invalid metric value: {exc}", "err")
        return result

    # ISS (Impact Sub-Score)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if iss <= 0:
        result["score"] = 0.0
    else:
        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02) ** 13
        else:
            impact = 6.42 * iss

        if impact <= 0:
            result["score"] = 0.0
        else:
            if scope_changed:
                raw = min(1.08 * (impact + exploitability), 10.0)
            else:
                raw = min(impact + exploitability, 10.0)
            # Round up to nearest 0.1
            result["score"] = _math.ceil(raw * 10) / 10

    score = result["score"]
    if score == 0:
        result["severity"] = "None"
    elif score < 4.0:
        result["severity"] = "Low"
    elif score < 7.0:
        result["severity"] = "Medium"
    elif score < 9.0:
        result["severity"] = "High"
    else:
        result["severity"] = "Critical"

    log(f"  Score: {score} ({result['severity']})", "ok" if score < 4 else ("warn" if score < 7 else "err"))
    log(f"  ISS: {iss:.3f}, Exploitability: {8.22 * av * ac * pr * ui:.3f}", "info")
    return result


# ---------------------------------------------------------------------------
# Scan Profiles
# ---------------------------------------------------------------------------
SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Fast scan: port scan + tech fingerprint + headers",
        "steps": ["port_scan", "tech_fingerprint", "header_check"],
    },
    "standard": {
        "description": "Standard scan: recon + web attacks + TLS",
        "steps": ["port_scan", "subdomain_find", "tech_fingerprint",
                  "cors_test", "header_check", "tls_scan", "cookie_audit"],
    },
    "deep": {
        "description": "Deep scan: full recon + all web tests + OSINT",
        "steps": ["port_scan", "subdomain_find", "subdomain_perm",
                  "buster", "tech_fingerprint", "cors_test",
                  "header_check", "tls_scan", "cookie_audit",
                  "csrf_analyze", "open_redirect", "waf_detect",
                  "ssti_scan", "xss_probe", "lfi_scan", "ssrf_scan",
                  "js_endpoint_extract", "whois_lookup"],
    },
}


def run_profile(name: str, target: str, log: Logger) -> dict:
    """Run a predefined scan profile on a target."""
    profile = SCAN_PROFILES.get(name.lower())
    if not profile:
        log(f"[-] Unknown profile '{name}'. Available: {', '.join(SCAN_PROFILES)}", "err")
        return {"error": f"Unknown profile: {name}"}

    log(f"[*] Running '{name}' profile on {target}", "cyan")
    log(f"  {profile['description']}", "info")
    log(f"  Steps: {', '.join(profile['steps'])}", "info")

    session_set("last_target", target)
    results: dict = {"profile": name, "target": target, "steps": {}}

    # Use attack_chain which already handles step dispatch
    # Late import so mocking gui.engine.attack_chain works in tests
    import gui.engine as _eng
    chain_result = _eng.attack_chain(target, profile["steps"], log)
    results["steps"] = chain_result.get("outputs", {})
    return results


# ---------------------------------------------------------------------------
# Scope Management (engine wrappers)
# ---------------------------------------------------------------------------
def scope_add(target: str, in_scope: bool, log: Logger) -> None:
    """Add a target pattern to the scope."""
    try:
        from gui.db import add_scope as _db_add
    except ImportError:
        log("[-] Database module unavailable (sqlite3 missing?)", "err")
        return
    _db_add(target, in_scope)
    tag = "ok" if in_scope else "warn"
    label = "IN-SCOPE" if in_scope else "OUT-OF-SCOPE"
    log(f"[+] {target} marked as {label}", tag)


def scope_remove(target: str, log: Logger) -> None:
    """Remove a target pattern from the scope."""
    try:
        from gui.db import remove_scope as _db_remove
    except ImportError:
        log("[-] Database module unavailable", "err")
        return
    _db_remove(target)
    log(f"[-] {target} removed from scope", "info")


def scope_check(target: str, log: Logger) -> bool | None:
    """Check if a target is in scope."""
    try:
        from gui.db import check_scope as _db_check
    except ImportError:
        log("[-] Database module unavailable", "err")
        return None
    status = _db_check(target)
    if status is None:
        log(f"  {target}: no scope rules defined (allowed)", "muted")
    elif status:
        log(f"  {target}: IN SCOPE ✓", "ok")
    else:
        log(f"  {target}: OUT OF SCOPE ✗", "err")
    return status


def scope_list(log: Logger) -> list[dict]:
    """List all scope rules."""
    try:
        from gui.db import get_scope as _db_scope
    except ImportError:
        log("[-] Database module unavailable", "err")
        return []
    rules = _db_scope()
    if not rules:
        log("  No scope rules defined", "muted")
    for r in rules:
        tag = "ok" if r["in_scope"] else "warn"
        label = "IN" if r["in_scope"] else "OUT"
        log(f"  [{label}] {r['pattern']}", tag)
    return rules


# ---------------------------------------------------------------------------
# Database wrappers
# ---------------------------------------------------------------------------
def db_init(path: str | None, log: Logger) -> str:
    """Initialize the SQLite database."""
    try:
        from gui.db import init_db
    except ImportError:
        log("[-] Database module unavailable (sqlite3 missing?)", "err")
        return ""
    db_path = init_db(path)
    log(f"[+] Database initialized: {db_path}", "ok")
    return str(db_path)


def db_store(tool: str, target: str, severity: str, data: object,
             log: Logger) -> int:
    """Store a finding in the database."""
    try:
        from gui.db import store_finding
    except ImportError:
        log("[-] Database module unavailable", "err")
        return -1
    fid = store_finding(tool=tool, target=target, severity=severity, data=data)
    log(f"  Stored finding #{fid} ({tool} / {severity})", "muted")
    return fid


def db_query(tool: str | None, target: str | None, severity: str | None,
             log: Logger) -> list[dict]:
    """Query findings from the database."""
    try:
        from gui.db import query_findings
    except ImportError:
        log("[-] Database module unavailable", "err")
        return []
    rows = query_findings(tool=tool, target=target, severity=severity)
    log(f"  {len(rows)} finding(s) returned", "info")
    return rows


# ---------------------------------------------------------------------------
# SARIF Report Export
# ---------------------------------------------------------------------------
def sarif_export(findings: list[dict], output_path: str, log: Logger) -> str:
    """Export findings to SARIF v2.1.0 format (for IDE / GitHub integration)."""
    import json as _json
    log(f"[*] SARIF export → {output_path}", "cyan")

    sarif: dict = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PENETRATOR",
                    "version": "1.7.0",
                    "informationUri": "https://github.com/Oli97430/PENETRATOR",
                    "rules": [],
                }
            },
            "results": [],
        }],
    }

    rules_seen: dict[str, int] = {}
    run = sarif["runs"][0]

    for finding in findings:
        tool = finding.get("tool", "unknown")
        severity = finding.get("severity", "note")
        target = finding.get("target", "")
        detail = finding.get("detail", finding.get("data", ""))

        # Map severity → SARIF level
        level_map = {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "note"}
        level = level_map.get(severity.lower(), "note")

        # Create rule if needed
        if tool not in rules_seen:
            rule_idx = len(rules_seen)
            rules_seen[tool] = rule_idx
            run["tool"]["driver"]["rules"].append({
                "id": tool.replace(" ", "_"),
                "shortDescription": {"text": tool},
            })
        else:
            rule_idx = rules_seen[tool]

        result_obj: dict = {
            "ruleId": tool.replace(" ", "_"),
            "ruleIndex": rule_idx,
            "level": level,
            "message": {"text": str(detail)[:2000] if detail else tool},
        }
        if target:
            result_obj["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                }
            }]
        run["results"].append(result_obj)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"[+] Exported {len(findings)} finding(s) to SARIF", "ok")
    return str(path)
