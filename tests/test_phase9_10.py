"""Tests for Phase 9 + Phase 10 engine functions (no network required)."""
from __future__ import annotations

from pathlib import Path

import pytest

from gui import engine as E


def _log(msg, tag="info"):
    pass


# ===========================================================================
# Phase 10: Pure-logic functions (no network)
# ===========================================================================


class TestSmartPayloadGen:
    def test_returns_original_plus_variants(self):
        result = E.smart_payload_gen("<script>alert(1)</script>", "generic", _log)
        assert isinstance(result, list)
        assert len(result) >= 2
        assert "<script>alert(1)</script>" in result  # original preserved

    def test_cloudflare_variants(self):
        result = E.smart_payload_gen("' OR 1=1", "cloudflare", _log)
        assert any(v != "' OR 1=1" for v in result)

    def test_modsecurity_case_toggle(self):
        result = E.smart_payload_gen("SELECT * FROM users", "modsecurity", _log)
        assert any("SeLeCt" in v for v in result)

    def test_unknown_waf_falls_back_to_generic(self):
        result = E.smart_payload_gen("test", "unknown_waf", _log)
        assert len(result) >= 2


class TestRandomUA:
    def test_returns_string(self):
        ua = E.random_ua()
        assert isinstance(ua, str)
        assert len(ua) > 5

    def test_pool_not_empty(self):
        assert len(E.UA_POOL) >= 10

    def test_randomness(self):
        """Multiple calls should eventually return different values."""
        uas = {E.random_ua() for _ in range(50)}
        assert len(uas) > 1


class TestHomoglyphs:
    def test_homoglyph_table_populated(self):
        assert "a" in E.HOMOGLYPHS
        assert "o" in E.HOMOGLYPHS
        assert len(E.HOMOGLYPHS) >= 10


class TestPhishingURL:
    def test_clean_url_low_score(self):
        result = E.phishing_url_analyze("https://google.com", _log)
        assert result["score"] < 30

    def test_suspicious_url_high_score(self):
        result = E.phishing_url_analyze(
            "http://192.168.1.1/login-verify-secure@evil.com/confirm/update", _log)
        assert result["score"] > 30
        assert len(result["indicators"]) >= 1

    def test_ip_based_url(self):
        result = E.phishing_url_analyze("http://10.0.0.1/login", _log)
        assert any("IP" in i for i in result["indicators"])


class TestOWASPMap:
    def test_empty_findings(self):
        result = E.owasp_map([], _log)
        assert "mapping" in result
        assert result["affected_count"] == 0

    def test_sqli_maps_to_a03(self):
        findings = [{"type": "sqli", "detail": "login page SQLi"}]
        result = E.owasp_map(findings, _log)
        assert len(result["mapping"]["A03"]) == 1
        assert result["affected_count"] >= 1

    def test_multiple_categories(self):
        findings = [
            {"type": "sqli", "detail": "SQLi"},
            {"type": "ssrf", "detail": "SSRF"},
            {"type": "cors", "detail": "CORS"},
        ]
        result = E.owasp_map(findings, _log)
        assert result["affected_count"] >= 3


class TestLogAnalyze:
    def test_empty_log(self):
        result = E.log_analyze("", _log)
        assert result["total_lines"] == 0

    def test_detects_sqli(self):
        log_text = '192.168.1.1 - - "GET /search?q=UNION SELECT * FROM users HTTP/1.1" 200'
        result = E.log_analyze(log_text, _log)
        assert "SQL Injection attempt" in result["attacks"] or any(
            "SQL" in str(v) for v in result.get("summary", []))

    def test_detects_xss(self):
        log_text = '10.0.0.1 - - "GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200'
        result = E.log_analyze(log_text, _log)
        assert len(result["attacks"]) >= 1

    def test_counts_ips(self):
        lines = "\n".join(f'192.168.1.{i % 3} - - "GET / HTTP/1.1" 200' for i in range(9))
        result = E.log_analyze(lines, _log)
        assert result["total_lines"] == 9


class TestBaselineCompare:
    def test_no_diff_identical(self):
        snap = {"ports": [80, 443], "processes": ["sshd", "nginx"]}
        result = E.baseline_compare(snap, snap, _log)
        assert result["new_ports"] == []
        assert result["closed_ports"] == []
        assert result["new_processes"] == []

    def test_detects_new_port(self):
        prev = {"ports": [80], "processes": []}
        curr = {"ports": [80, 3389], "processes": []}
        result = E.baseline_compare(curr, prev, _log)
        assert 3389 in result["new_ports"]

    def test_detects_closed_port(self):
        prev = {"ports": [80, 443], "processes": []}
        curr = {"ports": [80], "processes": []}
        result = E.baseline_compare(curr, prev, _log)
        assert 443 in result["closed_ports"]

    def test_detects_new_process(self):
        prev = {"ports": [], "processes": ["sshd"]}
        curr = {"ports": [], "processes": ["sshd", "cryptominer"]}
        result = E.baseline_compare(curr, prev, _log)
        assert "cryptominer" in result["new_processes"]


class TestScanDiff:
    def test_empty_diffs(self):
        result = E.scan_diff({}, {}, _log)
        assert isinstance(result, dict)
        assert result["new"] == []
        assert result["removed"] == []

    def test_detects_new_ports(self):
        curr = {"ports": [80, 443, 8080]}
        prev = {"ports": [80, 443]}
        result = E.scan_diff(curr, prev, _log)
        assert 8080 in result["new"]
        assert result["removed"] == []

    def test_detects_removed_ports(self):
        curr = {"ports": [80]}
        prev = {"ports": [80, 443]}
        result = E.scan_diff(curr, prev, _log)
        assert 443 in result["removed"]
        assert result["new"] == []


class TestHoneypotDetect:
    def test_no_ports_no_crash(self):
        result = E.honeypot_detect("127.0.0.1", [], _log)
        assert "score" in result
        assert "likely_honeypot" in result

    def test_result_structure(self):
        result = E.honeypot_detect("192.168.1.1", [80], _log)
        assert isinstance(result["score"], int)
        assert isinstance(result["likely_honeypot"], bool)


# ===========================================================================
# Phase 9: Constants & data structures
# ===========================================================================

class TestWAFBypassEncodings:
    def test_all_waf_types_present(self):
        for waf in ("cloudflare", "modsecurity", "aws", "generic"):
            assert waf in E.WAF_BYPASS_ENCODINGS
            assert len(E.WAF_BYPASS_ENCODINGS[waf]) >= 2


class TestOWASPConstants:
    def test_owasp_has_10_categories(self):
        assert len(E.OWASP_2021) == 10

    def test_finding_to_owasp_all_valid(self):
        for _, cat in E.FINDING_TO_OWASP.items():
            assert cat in E.OWASP_2021


class TestHoneypotSignatures:
    def test_signatures_loaded(self):
        assert len(E.HONEYPOT_SIGNATURES) >= 2

    def test_signature_structure(self):
        for name, patterns in E.HONEYPOT_SIGNATURES:
            assert isinstance(name, str)
            assert isinstance(patterns, list)


class TestLogAttackPatterns:
    def test_patterns_loaded(self):
        assert len(E.LOG_ATTACK_PATTERNS) >= 5

    def test_patterns_compile(self):
        import re
        for pattern, desc in E.LOG_ATTACK_PATTERNS:
            re.compile(pattern, re.IGNORECASE)  # should not raise


# ===========================================================================
# Phase 10: firmware_strings with file (no network)
# ===========================================================================

class TestFirmwareStrings:
    def test_file_not_found(self):
        result = E.firmware_strings("/nonexistent/file.bin", 6, _log)
        assert result["total"] == 0

    def test_extracts_strings(self, tmp_path: Path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00password=secret123\x00https://evil.com\x00admin@test.com\x00")
        result = E.firmware_strings(str(f), 4, _log)
        assert result["total"] >= 1
        assert len(result["credentials"]) >= 1
        assert len(result["urls"]) >= 1
        assert len(result["emails"]) >= 1

    def test_small_file_returns_valid_structure(self, tmp_path: Path):
        """Small file should be analyzed and return proper dict structure."""
        f = tmp_path / "small.bin"
        f.write_bytes(b"\x00" * 100)
        result = E.firmware_strings(str(f), 6, _log)
        assert isinstance(result, dict)
        assert "total" in result
        assert "credentials" in result
        assert result["total"] == 0  # no printable strings ≥6 chars in null bytes


# ===========================================================================
# Phase 10: YARA with mock (no yara-python needed)
# ===========================================================================

class TestYaraScan:
    def test_missing_rules_path(self):
        result = E.yara_scan("/some/file", "/nonexistent/rules", _log)
        # Should return empty list if yara not installed OR rules not found
        assert isinstance(result, list)
        assert result == []


# ===========================================================================
# CLI module smoke tests
# ===========================================================================

class TestCLIModules:
    def test_api_security_build_menu(self):
        from modules import api_security
        menu = api_security.build_menu()
        assert len(menu.items) >= 3

    def test_crypto_tools_build_menu(self):
        from modules import crypto_tools
        menu = crypto_tools.build_menu()
        assert len(menu.items) >= 2

    def test_cloud_security_build_menu(self):
        from modules import cloud_security
        menu = cloud_security.build_menu()
        assert len(menu.items) >= 5

    def test_all_module_imports(self):
        """Verify all 14 CLI modules import without error."""
        from modules import (
            information_gathering, wordlist_generator, sql_injection,
            web_attacks, api_security, password_tools, crypto_tools,
            cloud_security, steganography, xss_tools, reverse_engineering,
            forensic_tools, payload_generator, osint_tools,
        )
        modules = [information_gathering, wordlist_generator, sql_injection,
                    web_attacks, api_security, password_tools, crypto_tools,
                    cloud_security, steganography, xss_tools, reverse_engineering,
                    forensic_tools, payload_generator, osint_tools]
        for mod in modules:
            assert hasattr(mod, "build_menu"), f"{mod.__name__} missing build_menu"


# ===========================================================================
# GUI tools BUILDERS completeness
# ===========================================================================

class TestToolBuilders:
    def test_22_builders_registered(self):
        from gui.tools import BUILDERS
        assert len(BUILDERS) == 22

    def test_builder_keys_match_categories(self):
        from gui.tools import BUILDERS
        from gui.app import CATEGORIES
        cat_keys = {k for k, *_ in CATEGORIES}
        builder_keys = set(BUILDERS.keys())
        # Every category should have a builder
        assert cat_keys == builder_keys, f"Mismatch: {cat_keys ^ builder_keys}"


class TestThemeColors:
    def test_22_colors(self):
        from gui.theme import CATEGORY_COLORS
        assert len(CATEGORY_COLORS) >= 22

    def test_all_categories_colored(self):
        from gui.theme import CATEGORY_COLORS
        from gui.app import CATEGORIES
        for key, *_ in CATEGORIES:
            assert key in CATEGORY_COLORS, f"Missing color for {key}"
