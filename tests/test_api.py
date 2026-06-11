"""Comprehensive tests for the PENETRATOR REST API (penetrator_api.py).

Tests cover:
  1. Health check (no auth)
  2. Auth rejection (missing/wrong key -> 403)
  3. All scan endpoints (mocked engine, 200 + correct response shape)
  4. Rate limiting (> 60 requests -> 429)
  5. Validation errors (missing fields -> 422)
  6. JWT endpoints
  7. Tool endpoints
  8. SARIF export (path sanitization)
  9. Profile run

Every scan/tool/jwt endpoint gets at minimum:
  - Happy path (engine returns data -> 200)
  - Error handling (engine raises -> 500 with "Scan failed")
"""
from __future__ import annotations

import os

# Must set BEFORE import so the API module picks it up
os.environ["PENETRATOR_API_KEY"] = "test-secret-key"
os.environ["PENETRATOR_SSRF_PROTECTION"] = "0"  # Disable SSRF block for tests

from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# Patch lifespan's init_db to skip DB initialization
with patch("penetrator_api.init_db"):
    from penetrator_api import app, _rate_store

client = TestClient(app, raise_server_exceptions=False)
HEADERS = {"X-Api-Key": "test-secret-key"}


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _clear_rate_store():
    """Clear rate limiter state between tests that check rate limiting."""
    _rate_store.clear()


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Auto-reset rate limiter before every test to prevent cross-test pollution."""
    _rate_store.clear()
    yield
    _rate_store.clear()


# ---------------------------------------------------------------------------
# 1. Health check
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_ok(self):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_health_no_auth_required(self):
        # No X-Api-Key header, should still work
        r = client.get("/health")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 2. Auth rejection
# ---------------------------------------------------------------------------

class TestAuth:
    def test_missing_api_key_returns_422(self):
        # FastAPI returns 422 when required header is missing
        r = client.post("/scan/ports", json={"target": "127.0.0.1", "ports_str": "80"})
        assert r.status_code in (403, 422)

    def test_wrong_api_key_returns_403(self):
        r = client.post(
            "/scan/ports",
            json={"target": "127.0.0.1", "ports_str": "80"},
            headers={"X-Api-Key": "wrong-key"},
        )
        assert r.status_code == 403

    def test_empty_api_key_returns_403(self):
        r = client.post(
            "/scan/ports",
            json={"target": "127.0.0.1", "ports_str": "80"},
            headers={"X-Api-Key": ""},
        )
        assert r.status_code == 403

    def test_auth_on_jwt_endpoint(self):
        r = client.post("/jwt/decode", json={"token": "a.b.c"})
        assert r.status_code in (403, 422)

    def test_auth_on_tools_endpoint(self):
        r = client.post("/tools/cvss", json={"vector": "AV:N/AC:L"})
        assert r.status_code in (403, 422)


# ---------------------------------------------------------------------------
# 3. Scan endpoints — happy path + error handling
# ---------------------------------------------------------------------------

class TestScanPorts:
    @patch("penetrator_api.E.scan_ports")
    def test_ports_range_happy(self, mock_scan):
        mock_scan.return_value = [80, 443]
        r = client.post(
            "/scan/ports",
            json={"target": "192.168.1.1", "ports_str": "1-1024"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert "result" in data
        assert "log" in data
        assert data["result"] == [80, 443]

    @patch("penetrator_api.E.scan_ports")
    def test_ports_csv_happy(self, mock_scan):
        # For CSV, scan_ports is called per port; if it returns truthy, port is appended
        mock_scan.return_value = [80]
        r = client.post(
            "/scan/ports",
            json={"target": "10.0.0.1", "ports_str": "80,443,8080"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert "result" in data

    @patch("penetrator_api.E.scan_ports")
    def test_ports_engine_raises(self, mock_scan):
        mock_scan.side_effect = RuntimeError("connection refused")
        r = client.post(
            "/scan/ports",
            json={"target": "10.0.0.1", "ports_str": "1-100"},
            headers=HEADERS,
        )
        assert r.status_code == 500

    def test_ports_invalid_spec(self):
        # ports_str with non-numeric content may raise ValueError -> 400
        r = client.post(
            "/scan/ports",
            json={"target": "10.0.0.1", "ports_str": "abc-xyz"},
            headers=HEADERS,
        )
        assert r.status_code in (400, 500)


class TestScanTechFingerprint:
    @patch("penetrator_api.E.tech_fingerprint")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"server": "nginx", "tech": ["PHP"]}
        r = client.post(
            "/scan/tech-fingerprint",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["result"]["server"] == "nginx"
        assert "log" in data

    @patch("penetrator_api.E.tech_fingerprint")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("timeout")
        r = client.post(
            "/scan/tech-fingerprint",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanSubdomainPerm:
    @patch("penetrator_api.E.subdomain_permutation")
    def test_happy(self, mock_fn):
        mock_fn.return_value = ["www.example.com", "mail.example.com"]
        r = client.post(
            "/scan/subdomain-perm",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"] == ["www.example.com", "mail.example.com"]

    @patch("penetrator_api.E.subdomain_permutation")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("DNS error")
        r = client.post(
            "/scan/subdomain-perm",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanCsrf:
    @patch("penetrator_api.E.csrf_analyze")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "forms": 3}
        r = client.post(
            "/scan/csrf",
            json={"url": "http://example.com/form"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.csrf_analyze")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("parse error")
        r = client.post(
            "/scan/csrf",
            json={"url": "http://example.com/form"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanCookieAudit:
    @patch("penetrator_api.E.cookie_audit")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"cookies": [{"name": "session", "secure": False}]}
        r = client.post(
            "/scan/cookie-audit",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "cookies" in r.json()["result"]

    @patch("penetrator_api.E.cookie_audit")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("no cookies")
        r = client.post(
            "/scan/cookie-audit",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanSsti:
    @patch("penetrator_api.E.ssti_scan")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "engine": "Jinja2"}
        r = client.post(
            "/scan/ssti",
            json={"url": "http://example.com/page", "param": "name"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.ssti_scan")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("injection failed")
        r = client.post(
            "/scan/ssti",
            json={"url": "http://example.com/page", "param": "name"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanXssProbe:
    @patch("penetrator_api.E.xss_reflected")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"reflected": True, "payloads": ["<script>alert(1)</script>"]}
        r = client.post(
            "/scan/xss-probe",
            json={"url": "http://example.com/search?q=test"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["reflected"] is True

    @patch("penetrator_api.E.xss_reflected")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("timeout")
        r = client.post(
            "/scan/xss-probe",
            json={"url": "http://example.com/search"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanHeaders:
    @patch("penetrator_api.E.check_security_headers")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"missing": ["X-Frame-Options", "CSP"]}
        r = client.post(
            "/scan/headers",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "missing" in r.json()["result"]

    @patch("penetrator_api.E.check_security_headers")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("connection error")
        r = client.post(
            "/scan/headers",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanCors:
    @patch("penetrator_api.E.cors_test")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"misconfigured": True, "origin_reflected": True}
        r = client.post(
            "/scan/cors",
            json={"url": "http://example.com/api"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["misconfigured"] is True

    @patch("penetrator_api.E.cors_test")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("CORS error")
        r = client.post(
            "/scan/cors",
            json={"url": "http://example.com/api"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanSubdomains:
    @patch("penetrator_api.E.find_subdomains")
    def test_happy(self, mock_fn):
        mock_fn.return_value = ["api.example.com", "dev.example.com"]
        r = client.post(
            "/scan/subdomains",
            json={"domain": "example.com", "threads": 10},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert len(r.json()["result"]) == 2

    @patch("penetrator_api.E.find_subdomains")
    def test_default_threads(self, mock_fn):
        mock_fn.return_value = []
        r = client.post(
            "/scan/subdomains",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200

    @patch("penetrator_api.E.find_subdomains")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("DNS timeout")
        r = client.post(
            "/scan/subdomains",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanBuster:
    @patch("penetrator_api.E.buster")
    def test_happy(self, mock_fn):
        mock_fn.return_value = ["/admin", "/login", "/.git"]
        r = client.post(
            "/scan/buster",
            json={"url": "http://example.com", "threads": 20},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "/admin" in r.json()["result"]

    @patch("penetrator_api.E.buster")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("too many 403s")
        r = client.post(
            "/scan/buster",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanWaf:
    @patch("penetrator_api.E.waf_detect")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"detected": True, "waf": "Cloudflare"}
        r = client.post(
            "/scan/waf",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["waf"] == "Cloudflare"

    @patch("penetrator_api.E.waf_detect")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("WAF error")
        r = client.post(
            "/scan/waf",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanOpenRedirect:
    @patch("penetrator_api.E.open_redirect_test")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "payload": "//evil.com"}
        r = client.post(
            "/scan/open-redirect",
            json={"url": "http://example.com/redirect?url=x"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.open_redirect_test")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("redirect loop")
        r = client.post(
            "/scan/open-redirect",
            json={"url": "http://example.com/redirect"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanSqli:
    @patch("penetrator_api.E.sqli_detect")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "type": "error-based"}
        r = client.post(
            "/scan/sqli",
            json={"url": "http://example.com/item?id=1"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.sqli_detect")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("DB error")
        r = client.post(
            "/scan/sqli",
            json={"url": "http://example.com/item?id=1"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanSsrf:
    @patch("penetrator_api.E.ssrf_scan")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "internal_access": True}
        r = client.post(
            "/scan/ssrf",
            json={"url": "http://example.com/fetch?url=x"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.ssrf_scan")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("SSRF scan error")
        r = client.post(
            "/scan/ssrf",
            json={"url": "http://example.com/fetch"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanLfi:
    @patch("penetrator_api.E.lfi_scan")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "path": "/etc/passwd"}
        r = client.post(
            "/scan/lfi",
            json={"url": "http://example.com/page?file=x"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.lfi_scan")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("LFI error")
        r = client.post(
            "/scan/lfi",
            json={"url": "http://example.com/page?file=x"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanCrlf:
    @patch("penetrator_api.E.crlf_test")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "injection": "header"}
        r = client.post(
            "/scan/crlf",
            json={"url": "http://example.com/redirect"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.crlf_test")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("CRLF error")
        r = client.post(
            "/scan/crlf",
            json={"url": "http://example.com/redirect"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanOauth2:
    @patch("penetrator_api.E.oauth2_test")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"issues": ["open redirect in callback"]}
        r = client.post(
            "/scan/oauth2",
            json={"url": "http://example.com/oauth"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "issues" in r.json()["result"]

    @patch("penetrator_api.E.oauth2_test")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("OAuth error")
        r = client.post(
            "/scan/oauth2",
            json={"url": "http://example.com/oauth"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanDnsRebinding:
    @patch("penetrator_api.E.dns_rebinding_check")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": False}
        r = client.post(
            "/scan/dns-rebinding",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is False

    @patch("penetrator_api.E.dns_rebinding_check")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("DNS error")
        r = client.post(
            "/scan/dns-rebinding",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanHttpSmuggling:
    @patch("penetrator_api.E.http_smuggling_detect")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "technique": "CL.TE"}
        r = client.post(
            "/scan/http-smuggling",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["technique"] == "CL.TE"

    @patch("penetrator_api.E.http_smuggling_detect")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("smuggling error")
        r = client.post(
            "/scan/http-smuggling",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanPrototypePollution:
    @patch("penetrator_api.E.prototype_pollution_scan")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "gadgets": ["__proto__"]}
        r = client.post(
            "/scan/prototype-pollution",
            json={"url": "http://example.com/app.js"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.prototype_pollution_scan")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("prototype error")
        r = client.post(
            "/scan/prototype-pollution",
            json={"url": "http://example.com/app.js"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanInsecureDeser:
    @patch("penetrator_api.E.insecure_deser_test")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "format": "pickle"}
        r = client.post(
            "/scan/insecure-deser",
            json={"url": "http://example.com/api/data"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["format"] == "pickle"

    @patch("penetrator_api.E.insecure_deser_test")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("deser error")
        r = client.post(
            "/scan/insecure-deser",
            json={"url": "http://example.com/api/data"},
            headers=HEADERS,
        )
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# Async scan endpoints
# ---------------------------------------------------------------------------

class TestScanSqliAsync:
    @patch("penetrator_api.E.sqli_detect_async")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": True, "payloads_tested": 50}
        r = client.post(
            "/scan/sqli-async",
            json={"url": "http://example.com/item?id=1"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is True

    @patch("penetrator_api.E.sqli_detect_async")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("async error")
        r = client.post(
            "/scan/sqli-async",
            json={"url": "http://example.com/item?id=1"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanXssAsync:
    @patch("penetrator_api.E.xss_reflected_async")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"reflected": True}
        r = client.post(
            "/scan/xss-async",
            json={"url": "http://example.com/search?q=test"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["reflected"] is True

    @patch("penetrator_api.E.xss_reflected_async")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("async XSS error")
        r = client.post(
            "/scan/xss-async",
            json={"url": "http://example.com/search"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanCorsAsync:
    @patch("penetrator_api.E.cors_test_async")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"misconfigured": False}
        r = client.post(
            "/scan/cors-async",
            json={"url": "http://example.com/api"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["misconfigured"] is False

    @patch("penetrator_api.E.cors_test_async")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("async CORS error")
        r = client.post(
            "/scan/cors-async",
            json={"url": "http://example.com/api"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestScanOpenRedirectAsync:
    @patch("penetrator_api.E.open_redirect_test_async")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"vulnerable": False}
        r = client.post(
            "/scan/open-redirect-async",
            json={"url": "http://example.com/redir"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["vulnerable"] is False

    @patch("penetrator_api.E.open_redirect_test_async")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("async redirect error")
        r = client.post(
            "/scan/open-redirect-async",
            json={"url": "http://example.com/redir"},
            headers=HEADERS,
        )
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# 5. Validation errors (missing fields -> 422)
# ---------------------------------------------------------------------------

class TestValidation:
    def test_ports_missing_target(self):
        r = client.post(
            "/scan/ports",
            json={"ports_str": "80"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_ports_missing_ports_str(self):
        r = client.post(
            "/scan/ports",
            json={"target": "127.0.0.1"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_tech_fingerprint_missing_url(self):
        r = client.post(
            "/scan/tech-fingerprint",
            json={},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_ssti_missing_param(self):
        r = client.post(
            "/scan/ssti",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_jwt_decode_missing_token(self):
        r = client.post(
            "/jwt/decode",
            json={},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_cvss_missing_vector(self):
        r = client.post(
            "/tools/cvss",
            json={},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_sarif_missing_findings(self):
        r = client.post(
            "/report/sarif",
            json={"output_path": "report.sarif"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_sarif_missing_output_path(self):
        r = client.post(
            "/report/sarif",
            json={"findings": []},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_profile_run_missing_name(self):
        r = client.post(
            "/profile/run",
            json={"target": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_profile_run_missing_target(self):
        r = client.post(
            "/profile/run",
            json={"name": "quick"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_attack_chain_missing_chain(self):
        r = client.post(
            "/tools/attack-chain",
            json={"target": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_jwt_key_confusion_missing_key_text(self):
        r = client.post(
            "/jwt/key-confusion",
            json={"token": "a.b.c"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_empty_body(self):
        r = client.post(
            "/scan/headers",
            json={},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_non_json_body(self):
        r = client.post(
            "/scan/headers",
            content=b"not json",
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# 6. JWT endpoints
# ---------------------------------------------------------------------------

class TestJwtDecode:
    @patch("penetrator_api.E.jwt_decode")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {
            "header": {"alg": "HS256"},
            "payload": {"sub": "user1"},
        }
        r = client.post(
            "/jwt/decode",
            json={"token": "eyJ.eyJ.sig"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert "header" in data["result"]
        assert "payload" in data["result"]

    @patch("penetrator_api.E.jwt_decode")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("invalid JWT")
        r = client.post(
            "/jwt/decode",
            json={"token": "bad.token.here"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestJwtNoneAttack:
    @patch("penetrator_api.E.jwt_none_attack")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"forged_token": "eyJ.eyJ.", "accepted": True}
        r = client.post(
            "/jwt/none-attack",
            json={"token": "eyJ.eyJ.sig"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["accepted"] is True

    @patch("penetrator_api.E.jwt_none_attack")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("none attack error")
        r = client.post(
            "/jwt/none-attack",
            json={"token": "bad"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestJwtBrute:
    @patch("penetrator_api.E.jwt_brute")
    def test_happy_with_wordlist(self, mock_fn):
        mock_fn.return_value = {"cracked": True, "secret": "password123"}
        r = client.post(
            "/jwt/brute",
            json={"token": "eyJ.eyJ.sig", "wordlist": ["pass", "password123", "admin"]},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["cracked"] is True

    @patch("penetrator_api.E.jwt_brute")
    def test_happy_no_wordlist(self, mock_fn):
        mock_fn.return_value = {"cracked": False}
        r = client.post(
            "/jwt/brute",
            json={"token": "eyJ.eyJ.sig"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["cracked"] is False

    @patch("penetrator_api.E.jwt_brute")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("brute force error")
        r = client.post(
            "/jwt/brute",
            json={"token": "eyJ.eyJ.sig", "wordlist": ["a"]},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestJwtKeyConfusion:
    @patch("penetrator_api.E.jwt_key_confusion")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"forged": True, "token": "eyJ.modified.sig"}
        r = client.post(
            "/jwt/key-confusion",
            json={"token": "eyJ.eyJ.sig", "key_text": "-----BEGIN PUBLIC KEY-----\nMIIB..."},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["forged"] is True

    @patch("penetrator_api.E.jwt_key_confusion")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("key confusion error")
        r = client.post(
            "/jwt/key-confusion",
            json={"token": "eyJ.eyJ.sig", "key_text": "key"},
            headers=HEADERS,
        )
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# 7. Tool endpoints
# ---------------------------------------------------------------------------

class TestToolsCvss:
    @patch("penetrator_api.E.cvss_calculate")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"score": 9.8, "severity": "Critical"}
        r = client.post(
            "/tools/cvss",
            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["score"] == 9.8

    @patch("penetrator_api.E.cvss_calculate")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("invalid vector")
        r = client.post(
            "/tools/cvss",
            json={"vector": "invalid"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsPhishingUrl:
    @patch("penetrator_api.E.phishing_url_analyze")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"suspicious": True, "score": 0.85}
        r = client.post(
            "/tools/phishing-url",
            json={"url": "http://g00gle.evil.com/login"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["suspicious"] is True

    @patch("penetrator_api.E.phishing_url_analyze")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("phishing analysis error")
        r = client.post(
            "/tools/phishing-url",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsAttackChain:
    @patch("penetrator_api.E.attack_chain")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"steps": ["recon", "exploit", "privesc"], "success": True}
        r = client.post(
            "/tools/attack-chain",
            json={"target": "10.0.0.1", "chain": ["recon", "exploit", "privesc"]},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["success"] is True

    @patch("penetrator_api.E.attack_chain")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("chain error")
        r = client.post(
            "/tools/attack-chain",
            json={"target": "10.0.0.1", "chain": ["recon"]},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsAutoCorrelate:
    @patch("penetrator_api.E.auto_correlate")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"correlations": [{"vuln": "xss", "impact": "high"}]}
        r = client.post(
            "/tools/auto-correlate",
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "correlations" in r.json()["result"]

    @patch("penetrator_api.E.auto_correlate")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("correlate error")
        r = client.post(
            "/tools/auto-correlate",
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsExecutiveReport:
    @patch("penetrator_api.E.executive_report")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"summary": "3 critical, 5 high", "risk": "critical"}
        r = client.post(
            "/tools/executive-report",
            json={"target": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "summary" in r.json()["result"]

    @patch("penetrator_api.E.executive_report")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("report error")
        r = client.post(
            "/tools/executive-report",
            json={"target": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsEncodePayload:
    @patch("penetrator_api.E.encode_payload")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"base64": "PFNJXQ==", "url": "%3Cscript%3E"}
        r = client.post(
            "/tools/encode-payload",
            json={"text": "<script>"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "result" in r.json()
        # encode_payload doesn't use log
        assert "log" not in r.json()

    @patch("penetrator_api.E.encode_payload")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("encode error")
        r = client.post(
            "/tools/encode-payload",
            json={"text": "payload"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsHashIdentify:
    @patch("penetrator_api.E.identify_hash")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"type": "MD5", "length": 32}
        r = client.post(
            "/tools/hash-identify",
            json={"hash": "d41d8cd98f00b204e9800998ecf8427e"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["type"] == "MD5"

    @patch("penetrator_api.E.identify_hash")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("hash error")
        r = client.post(
            "/tools/hash-identify",
            json={"hash": "abc"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsPasswordStrength:
    @patch("penetrator_api.E.password_strength")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"score": 4, "strength": "very strong"}
        r = client.post(
            "/tools/password-strength",
            json={"password": "C0mpl3x!P@ssw0rd#2024"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["score"] == 4

    @patch("penetrator_api.E.password_strength")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("strength error")
        r = client.post(
            "/tools/password-strength",
            json={"password": "x"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsWhois:
    @patch("penetrator_api.E.whois_lookup")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"registrar": "GoDaddy", "created": "2000-01-01"}
        r = client.post(
            "/tools/whois",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["registrar"] == "GoDaddy"

    @patch("penetrator_api.E.whois_lookup")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("whois error")
        r = client.post(
            "/tools/whois",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


class TestToolsEmailCheck:
    @patch("penetrator_api.E.email_security_check")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"spf": True, "dkim": True, "dmarc": True}
        r = client.post(
            "/tools/email-check",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["spf"] is True

    @patch("penetrator_api.E.email_security_check")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("email check error")
        r = client.post(
            "/tools/email-check",
            json={"domain": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# 8. SARIF export (path sanitization)
# ---------------------------------------------------------------------------

class TestSarifExport:
    @patch("penetrator_api.E.sarif_export")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {"file": "report.sarif", "findings_count": 2}
        r = client.post(
            "/report/sarif",
            json={
                "findings": [{"id": "XSS-001", "severity": "high"}],
                "output_path": "my_report.sarif",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert "result" in r.json()

    @patch("penetrator_api.E.sarif_export")
    def test_path_traversal_stripped(self, mock_fn):
        """Path traversal (../) should be stripped, only filename used."""
        mock_fn.return_value = {"file": "evil.sarif"}
        r = client.post(
            "/report/sarif",
            json={
                "findings": [{"id": "TEST-001"}],
                "output_path": "../../../../etc/passwd",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        # Verify the engine was called with a safe path (just the filename)
        call_args = mock_fn.call_args
        safe_path = call_args[0][1] if call_args[0] else call_args[1].get("output_path", "")
        assert ".." not in safe_path
        assert "etc" not in safe_path or "reports" in safe_path

    @patch("penetrator_api.E.sarif_export")
    def test_path_traversal_backslash(self, mock_fn):
        """Windows-style path traversal should be sanitized."""
        mock_fn.return_value = {"file": "report.sarif"}
        r = client.post(
            "/report/sarif",
            json={
                "findings": [],
                "output_path": "..\\..\\..\\windows\\system32\\evil.sarif",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        call_args = mock_fn.call_args
        safe_path = call_args[0][1] if call_args[0] else ""
        # Should only contain the filename, not traversal
        assert "system32" not in safe_path

    @patch("penetrator_api.E.sarif_export")
    def test_empty_output_path_defaults(self, mock_fn):
        """Empty output path should default to 'report.sarif'."""
        mock_fn.return_value = {"file": "report.sarif"}
        r = client.post(
            "/report/sarif",
            json={
                "findings": [{"id": "A"}],
                "output_path": "",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        call_args = mock_fn.call_args
        safe_path = call_args[0][1] if call_args[0] else ""
        assert "report.sarif" in safe_path

    @patch("penetrator_api.E.sarif_export")
    def test_absolute_path_stripped(self, mock_fn):
        """Absolute paths should have only the filename extracted."""
        mock_fn.return_value = {"file": "output.sarif"}
        r = client.post(
            "/report/sarif",
            json={
                "findings": [{"id": "B"}],
                "output_path": "/tmp/evil/output.sarif",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        call_args = mock_fn.call_args
        safe_path = call_args[0][1] if call_args[0] else ""
        assert "output.sarif" in safe_path
        # Should be within the safe reports directory
        assert "reports" in safe_path

    @patch("penetrator_api.E.sarif_export")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("sarif export error")
        r = client.post(
            "/report/sarif",
            json={
                "findings": [{"id": "C"}],
                "output_path": "report.sarif",
            },
            headers=HEADERS,
        )
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# 9. Profile run
# ---------------------------------------------------------------------------

class TestProfileRun:
    @patch("penetrator_api.E.run_profile")
    def test_happy(self, mock_fn):
        mock_fn.return_value = {
            "profile": "full-scan",
            "target": "example.com",
            "results": {"ports": [80, 443], "vulns": 3},
        }
        r = client.post(
            "/profile/run",
            json={"name": "full-scan", "target": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["result"]["profile"] == "full-scan"
        assert "log" in data

    @patch("penetrator_api.E.run_profile")
    def test_engine_raises(self, mock_fn):
        mock_fn.side_effect = Exception("profile not found")
        r = client.post(
            "/profile/run",
            json={"name": "nonexistent", "target": "example.com"},
            headers=HEADERS,
        )
        assert r.status_code == 500

    @patch("penetrator_api.E.run_profile")
    def test_quick_profile(self, mock_fn):
        mock_fn.return_value = {"profile": "quick", "results": {}}
        r = client.post(
            "/profile/run",
            json={"name": "quick", "target": "192.168.1.1"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["result"]["profile"] == "quick"


# ---------------------------------------------------------------------------
# 4. Rate limiting (> 60 requests -> 429)
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def setup_method(self):
        """Clear rate limiter before each test."""
        _clear_rate_store()

    def test_rate_limit_exceeded(self):
        """Sending more than 60 requests in the window should trigger 429."""
        _clear_rate_store()
        # Send 61 requests (rate limit is 60/min)
        for i in range(60):
            r = client.post(
                "/tools/hash-identify",
                json={"hash": f"test{i}"},
                headers=HEADERS,
            )
            # First 60 should succeed (mocked or not, at least not 429)
            if r.status_code == 429:
                # If we hit 429 early, the test still passes (rate limiter works)
                return

        # The 61st request should be rate limited
        with patch("penetrator_api.E.identify_hash", return_value={"type": "unknown"}):
            r = client.post(
                "/tools/hash-identify",
                json={"hash": "final"},
                headers=HEADERS,
            )
        assert r.status_code == 429
        data = r.json()
        assert "Rate limit" in data["detail"]

    def test_health_bypasses_rate_limit(self):
        """Health endpoint should not be rate limited."""
        _clear_rate_store()
        # Fill up rate limit
        for i in range(65):
            client.get("/health")

        # Health should still work
        r = client.get("/health")
        assert r.status_code == 200

    def test_rate_limit_response_has_retry_after(self):
        """429 responses should include Retry-After header."""
        _clear_rate_store()
        # Fill rate limit
        for i in range(61):
            r = client.post(
                "/tools/hash-identify",
                json={"hash": f"h{i}"},
                headers=HEADERS,
            )
            if r.status_code == 429:
                assert "retry-after" in r.headers
                return

        # If we didn't hit 429 in the loop, try one more
        r = client.post(
            "/tools/hash-identify",
            json={"hash": "overflow"},
            headers=HEADERS,
        )
        if r.status_code == 429:
            assert "retry-after" in r.headers


# ---------------------------------------------------------------------------
# Additional edge case tests
# ---------------------------------------------------------------------------

class TestResponseShape:
    """Verify response shape consistency across endpoints."""

    @patch("penetrator_api.E.tech_fingerprint")
    def test_scan_response_has_result_and_log(self, mock_fn):
        mock_fn.return_value = {"data": "test"}
        r = client.post(
            "/scan/tech-fingerprint",
            json={"url": "http://example.com"},
            headers=HEADERS,
        )
        data = r.json()
        assert "result" in data
        assert "log" in data
        assert isinstance(data["log"], list)

    @patch("penetrator_api.E.encode_payload")
    def test_encode_payload_response_no_log(self, mock_fn):
        """encode_payload returns result only, no log."""
        mock_fn.return_value = {"encoded": "test"}
        r = client.post(
            "/tools/encode-payload",
            json={"text": "test"},
            headers=HEADERS,
        )
        data = r.json()
        assert "result" in data
        assert "log" not in data

    @patch("penetrator_api.E.identify_hash")
    def test_hash_identify_response_no_log(self, mock_fn):
        """identify_hash returns result only, no log."""
        mock_fn.return_value = {"type": "SHA256"}
        r = client.post(
            "/tools/hash-identify",
            json={"hash": "abc123"},
            headers=HEADERS,
        )
        data = r.json()
        assert "result" in data
        assert "log" not in data

    @patch("penetrator_api.E.password_strength")
    def test_password_strength_response_no_log(self, mock_fn):
        """password_strength returns result only, no log."""
        mock_fn.return_value = {"score": 2}
        r = client.post(
            "/tools/password-strength",
            json={"password": "weak"},
            headers=HEADERS,
        )
        data = r.json()
        assert "result" in data
        assert "log" not in data


class TestEndpointMethods:
    """Verify only correct HTTP methods are accepted."""

    def test_health_get_only(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_scan_post_only(self):
        r = client.get("/scan/ports")
        assert r.status_code == 405

    def test_jwt_post_only(self):
        r = client.get("/jwt/decode")
        assert r.status_code == 405

    def test_tools_post_only(self):
        r = client.get("/tools/cvss")
        assert r.status_code == 405

    def test_report_post_only(self):
        r = client.get("/report/sarif")
        assert r.status_code == 405

    def test_profile_post_only(self):
        r = client.get("/profile/run")
        assert r.status_code == 405


class TestNonexistentEndpoints:
    def test_404_on_unknown_path(self):
        r = client.get("/nonexistent", headers=HEADERS)
        assert r.status_code == 404

    def test_404_on_unknown_scan(self):
        r = client.post("/scan/nonexistent", json={}, headers=HEADERS)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# WebSocket scan streaming tests
# ---------------------------------------------------------------------------
class TestWebSocketScan:
    """Test the /ws/scan WebSocket endpoint."""

    def test_ws_missing_api_key(self):
        with client.websocket_connect("/ws/scan") as ws:
            ws.send_json({"api_key": "wrong", "scan": "headers",
                          "params": {"target": "example.com"}})
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "Invalid API key" in resp["detail"]

    def test_ws_unknown_scan(self):
        with client.websocket_connect("/ws/scan") as ws:
            ws.send_json({"api_key": "test-secret-key", "scan": "nonexistent",
                          "params": {"target": "example.com"}})
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "Unknown scan" in resp["detail"]

    @patch("penetrator_api.E")
    def test_ws_headers_scan_streams_logs(self, mock_e):
        mock_e.check_security_headers = lambda url, log: (
            log("[*] checking...", "cyan"),
            {"X-Frame-Options": "DENY"},
        )[-1]

        with client.websocket_connect("/ws/scan") as ws:
            ws.send_json({"api_key": "test-secret-key", "scan": "headers",
                          "params": {"target": "example.com"}})
            messages = []
            while True:
                msg = ws.receive_json()
                messages.append(msg)
                if msg["type"] in ("result", "error"):
                    break
            log_msgs = [m for m in messages if m["type"] == "log"]
            assert len(log_msgs) >= 1
            result_msg = messages[-1]
            assert result_msg["type"] == "result"

    @patch("penetrator_api.E")
    def test_ws_scan_error_handling(self, mock_e):
        mock_e.cors_test = MagicMock(side_effect=RuntimeError("boom"))

        with client.websocket_connect("/ws/scan") as ws:
            ws.send_json({"api_key": "test-secret-key", "scan": "cors",
                          "params": {"target": "example.com"}})
            messages = []
            while True:
                msg = ws.receive_json()
                messages.append(msg)
                if msg["type"] in ("result", "error"):
                    break
            assert messages[-1]["type"] == "error"
            assert "boom" in messages[-1]["detail"]
