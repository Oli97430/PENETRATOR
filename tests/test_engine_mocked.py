"""Mock-based tests for Phase 11 engine functions that require network access,
plus pure-logic tests for JWT, CVSS, SARIF, scope, and DB helpers.

Every test is fast (no real I/O, no sleeps). Network-bound functions are tested
with ``unittest.mock.patch`` so that ``requests.get``, ``requests.post``, and
``socket.gethostbyname`` never touch the wire.
"""
from __future__ import annotations

import base64
import json
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gui import engine as E


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _log(msg, tag="info"):
    """Silent logger for tests."""
    pass


def _make_jwt(header: dict | None = None, payload: dict | None = None,
              sig: bytes = b"sig") -> str:
    """Build a minimal JWT string."""
    hdr = header or {"alg": "RS256", "typ": "JWT"}
    pay = payload or {"sub": "1234", "name": "Test User"}
    def _b64(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        ).decode().rstrip("=")
    return f"{_b64(hdr)}.{_b64(pay)}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


class _CIDict(dict):
    """Minimal case-insensitive dict to mimic requests.structures."""

    def __getitem__(self, key):
        return super().__getitem__(key.lower())

    def __setitem__(self, key, value):
        super().__setitem__(key.lower(), value)

    def __contains__(self, key):
        return super().__contains__(key.lower())

    def get(self, key, default=None):
        return super().get(key.lower(), default)


def _mock_response(text="", status_code=200, headers=None, cookies=None,
                   raw_set_cookie_list=None):
    """Create a mock ``requests.Response``-like object."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    ci = _CIDict()
    for k, v in (headers or {}).items():
        ci[k] = v
    resp.headers = ci
    # cookies is iterable and supports .get_dict()
    jar = MagicMock()
    jar.__iter__ = MagicMock(return_value=iter(cookies or []))
    jar.get_dict = MagicMock(return_value={})
    cookie_objs = []
    for c in (cookies or []):
        co = MagicMock()
        co.name = c
        cookie_objs.append(co)
    jar.__iter__ = MagicMock(return_value=iter(cookie_objs))
    resp.cookies = jar
    # raw.headers.getlist for Set-Cookie parsing
    raw = MagicMock()
    if raw_set_cookie_list is not None:
        raw.headers.getlist = MagicMock(return_value=raw_set_cookie_list)
    else:
        raw.headers.getlist = MagicMock(return_value=[])
    resp.raw = raw
    return resp


# ===================================================================
#  CSRF Analyzer
# ===================================================================
class TestCsrfAnalyze:
    @patch("requests.get")
    @patch("requests.post")
    def test_detects_missing_csrf_token(self, mock_post, mock_get):
        resp = _mock_response(
            text="<form action='/submit'><input type='submit'></form>",
            headers={"Set-Cookie": "session=abc"},
        )
        mock_get.return_value = resp
        mock_post.return_value = _mock_response(status_code=200)

        result = E.csrf_analyze("http://test.com", _log)

        assert "No CSRF token found in forms" in result["issues"]
        assert result["score"] < 100

    @patch("requests.get")
    @patch("requests.post")
    def test_detects_csrf_token_present(self, mock_post, mock_get):
        resp = _mock_response(
            text="<form><input name='csrf' value='tok123'></form>",
            headers={"Set-Cookie": "session=abc; SameSite=Strict"},
        )
        mock_get.return_value = resp
        mock_post.return_value = _mock_response(status_code=403)

        result = E.csrf_analyze("http://test.com/form", _log)

        assert "csrf" in result["tokens_found"]
        assert result["score"] >= 80

    @patch("requests.get")
    @patch("requests.post")
    def test_detects_samesite_missing(self, mock_post, mock_get):
        resp = _mock_response(
            text="<form><input name='_token' value='abc'></form>",
            headers={"Set-Cookie": "session=abc"},
        )
        mock_get.return_value = resp
        mock_post.return_value = _mock_response(status_code=200)

        result = E.csrf_analyze("http://target.com", _log)

        assert "No SameSite cookie attribute" in result["issues"]

    @patch("requests.get")
    def test_handles_request_exception(self, mock_get):
        import requests as _req
        mock_get.side_effect = _req.ConnectionError("refused")

        result = E.csrf_analyze("http://down.com", _log)

        assert result["url"] == "http://down.com"
        assert result["tokens_found"] == []


# ===================================================================
#  Cookie Audit
# ===================================================================
class TestCookieAudit:
    @patch("requests.get")
    def test_detects_insecure_cookie(self, mock_get):
        resp = _mock_response(
            headers={"Set-Cookie": "session=abc; Path=/"},
            raw_set_cookie_list=["session=abc; Path=/"],
        )
        mock_get.return_value = resp

        result = E.cookie_audit("http://test.com", _log)

        assert len(result["cookies"]) >= 1
        issues = result["cookies"][0]["issues"]
        assert "Missing Secure flag" in issues
        assert "Missing HttpOnly flag" in issues

    @patch("requests.get")
    def test_detects_secure_cookie(self, mock_get):
        resp = _mock_response(
            headers={"Set-Cookie": "id=x; Secure; HttpOnly; SameSite=Strict"},
            raw_set_cookie_list=["id=x; Secure; HttpOnly; SameSite=Strict"],
        )
        mock_get.return_value = resp

        result = E.cookie_audit("http://test.com", _log)

        assert len(result["cookies"]) >= 1
        cookie = result["cookies"][0]
        assert cookie["secure"] is True
        assert cookie["httponly"] is True
        assert cookie["samesite"] == "strict"
        assert cookie["issues"] == []

    @patch("requests.get")
    def test_no_cookies(self, mock_get):
        resp = _mock_response(headers={})
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([]))
        jar.__bool__ = MagicMock(return_value=False)
        jar.__len__ = MagicMock(return_value=0)
        resp.cookies = jar
        mock_get.return_value = resp

        result = E.cookie_audit("http://test.com", _log)

        assert result["cookies"] == []

    @patch("requests.get")
    def test_handles_connection_error(self, mock_get):
        import requests as _req
        mock_get.side_effect = _req.ConnectionError("timeout")

        result = E.cookie_audit("http://down.com", _log)

        assert result["url"] == "http://down.com"
        assert result["cookies"] == []


# ===================================================================
#  OAuth2 Flow Tester
# ===================================================================
class TestOAuth2Test:
    @patch("requests.get")
    def test_detects_redirect_bypass(self, mock_get):
        # Simulate server accepting evil redirect URI
        def side_effect(url, **kwargs):
            if "evil" in url:
                return _mock_response(
                    status_code=302,
                    headers={"Location": "https://evil.example.com/callback?code=abc"},
                )
            return _mock_response(status_code=400, headers={})

        mock_get.side_effect = side_effect

        result = E.oauth2_test(
            "https://auth.example.com/authorize?client_id=abc",
            "https://example.com/callback",
            _log,
        )

        assert len(result["tests"]) > 0
        assert result["auth_url"] == "https://auth.example.com/authorize?client_id=abc"

    @patch("requests.get")
    def test_all_rejected(self, mock_get):
        mock_get.return_value = _mock_response(status_code=400, headers={})

        result = E.oauth2_test(
            "https://auth.example.com/authorize",
            "https://app.example.com/cb",
            _log,
        )

        assert result["issues"] == []
        for t in result["tests"]:
            if "accepted" in t:
                assert t["accepted"] is False

    @patch("requests.get")
    def test_handles_exception_per_variant(self, mock_get):
        import requests as _req
        mock_get.side_effect = _req.Timeout("slow")

        result = E.oauth2_test(
            "https://auth.example.com/authorize",
            "https://app.example.com/cb",
            _log,
        )

        # Should still return valid structure with error entries
        assert isinstance(result["tests"], list)


# ===================================================================
#  Subdomain Permutation
# ===================================================================
class TestSubdomainPermutation:
    @patch("socket.gethostbyname")
    def test_resolves_permutations(self, mock_dns):
        mock_dns.side_effect = lambda name: (
            "93.184.216.34" if "dev" in name else (_ for _ in ()).throw(
                socket.gaierror("not found"))
        )

        result = E.subdomain_permutation("app.example.com", _log)

        # At least some "dev" variants should resolve
        assert isinstance(result, list)
        assert len(result) > 0, "Expected at least one resolved permutation"
        # Each entry should be a dict with subdomain and ip keys
        assert all(isinstance(r, dict) and "subdomain" in r and "ip" in r for r in result)

    @patch("socket.gethostbyname")
    def test_all_fail_gracefully(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")

        result = E.subdomain_permutation("nope.example.com", _log)

        assert result == []

    @patch("socket.gethostbyname")
    def test_returns_ip_and_subdomain(self, mock_dns):
        mock_dns.return_value = "1.2.3.4"

        result = E.subdomain_permutation("sub.example.com", _log)

        assert len(result) > 0
        assert "subdomain" in result[0]
        assert "ip" in result[0]
        assert result[0]["ip"] == "1.2.3.4"


# ===================================================================
#  VHost Discovery
# ===================================================================
class TestVhostDiscover:
    @patch("requests.get")
    def test_finds_vhost(self, mock_get):
        call_count = [0]

        def side_effect(url, **kwargs):
            call_count[0] += 1
            host = kwargs.get("headers", {}).get("Host", "")
            if host == "nonexistent.invalid":
                return _mock_response(text="default" * 10)
            if host == "admin.target.com":
                return _mock_response(text="A" * 500, status_code=200)
            return _mock_response(text="default" * 10)

        mock_get.side_effect = side_effect

        result = E.vhost_discover("10.0.0.1", ["admin.target.com", "nope.target.com"], _log)

        assert len(result) >= 1
        assert result[0]["hostname"] == "admin.target.com"

    @patch("requests.get")
    def test_no_vhosts_found(self, mock_get):
        mock_get.return_value = _mock_response(text="same", status_code=200)

        result = E.vhost_discover("10.0.0.1", ["a.com", "b.com"], _log)

        # All responses identical to baseline, so nothing stands out
        assert result == []

    @patch("requests.get")
    def test_string_wordlist(self, mock_get):
        mock_get.return_value = _mock_response(text="x" * 100, status_code=200)

        result = E.vhost_discover("10.0.0.1", "host1.com,host2.com", _log)

        # All responses same as baseline → empty, but function must accept string input
        assert isinstance(result, list)
        # Baseline + 2 hosts = at least 3 GET calls
        assert mock_get.call_count >= 3


# ===================================================================
#  JS Endpoint Extractor
# ===================================================================
class TestJsEndpointExtract:
    @patch("requests.get")
    def test_extracts_api_endpoints(self, mock_get):
        html = """
        <html>
        <script src="/static/app.js"></script>
        <script>
          fetch('/api/v1/users');
          var url = "/api/v2/orders";
          const x = '/rest/items';
        </script>
        </html>
        """

        def side_effect(url, **kwargs):
            if url.endswith("app.js"):
                return _mock_response(
                    text='var endpoint = "/api/v1/admin/dashboard";'
                )
            return _mock_response(text=html)

        mock_get.side_effect = side_effect

        result = E.js_endpoint_extract("http://test.com", _log)

        assert len(result["endpoints"]) >= 1
        all_eps = " ".join(result["endpoints"])
        assert "/api/" in all_eps

    @patch("requests.get")
    def test_handles_no_scripts(self, mock_get):
        mock_get.return_value = _mock_response(text="<html><body>No JS</body></html>")

        result = E.js_endpoint_extract("http://test.com", _log)

        assert result["scripts"] == []
        assert result["endpoints"] == []

    @patch("requests.get")
    def test_extracts_full_urls(self, mock_get):
        html = """<script>
        var base = "https://api.example.com/v1/data";
        </script>"""
        mock_get.return_value = _mock_response(text=html)

        result = E.js_endpoint_extract("http://test.com", _log)

        assert any("api.example.com" in u for u in result["full_urls"])


# ===================================================================
#  HTTP Parameter Discovery
# ===================================================================
class TestParamDiscovery:
    @patch("requests.post")
    @patch("requests.get")
    def test_detects_hidden_get_param(self, mock_get, mock_post):
        call_count = [0]

        def get_side_effect(url, **kwargs):
            call_count[0] += 1
            if "debug=" in url:
                return _mock_response(text="DEBUG_OUTPUT " + "x" * 200, status_code=200)
            return _mock_response(text="normal page", status_code=200)

        mock_get.side_effect = get_side_effect
        mock_post.return_value = _mock_response(text="normal page", status_code=200)

        result = E.param_discovery("http://test.com/page", ["id", "debug"], _log)

        assert len(result["found_get"]) >= 1
        found_names = [p["param"] for p in result["found_get"]]
        assert "debug" in found_names

    @patch("requests.post")
    @patch("requests.get")
    def test_detects_hidden_post_param(self, mock_get, mock_post):
        mock_get.return_value = _mock_response(text="baseline", status_code=200)

        def post_side_effect(url, **kwargs):
            data = kwargs.get("data", {})
            if "admin" in data:
                return _mock_response(text="ADMIN_PANEL " + "x" * 200, status_code=200)
            return _mock_response(text="baseline", status_code=200)

        mock_post.side_effect = post_side_effect

        result = E.param_discovery("http://test.com", ["admin", "foo"], _log)

        assert len(result["found_post"]) >= 1

    @patch("requests.post")
    @patch("requests.get")
    def test_no_params_found(self, mock_get, mock_post):
        mock_get.return_value = _mock_response(text="same", status_code=200)
        mock_post.return_value = _mock_response(text="same", status_code=200)

        result = E.param_discovery("http://test.com", ["a", "b"], _log)

        assert result["found_get"] == []
        assert result["found_post"] == []


# ===================================================================
#  Technology Fingerprinting
# ===================================================================
class TestTechFingerprint:
    @patch("requests.get")
    def test_detects_nginx_and_php(self, mock_get):
        resp = _mock_response(
            text="<html>wp-content/themes/foo</html>",
            headers={
                "Server": "nginx/1.21",
                "X-Powered-By": "PHP/8.1",
            },
        )
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([]))
        resp.cookies = jar
        mock_get.return_value = resp

        result = E.tech_fingerprint("http://test.com", _log)

        techs = result["technologies"]
        assert "Nginx" in techs
        assert "PHP" in techs
        assert "WordPress" in techs

    @patch("requests.get")
    def test_detects_cookie_tech(self, mock_get):
        resp = _mock_response(
            text="<html></html>",
            headers={"Set-Cookie": "PHPSESSID=abc123; Path=/"},
        )
        php_cookie = MagicMock()
        php_cookie.name = "PHPSESSID"
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([php_cookie]))
        resp.cookies = jar
        mock_get.return_value = resp

        result = E.tech_fingerprint("http://test.com", _log)

        assert "PHP" in result["technologies"]

    @patch("requests.get")
    def test_no_tech_detected(self, mock_get):
        resp = _mock_response(text="<html></html>", headers={})
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([]))
        resp.cookies = jar
        mock_get.return_value = resp

        result = E.tech_fingerprint("http://test.com", _log)

        assert result["technologies"] == []


# ===================================================================
#  DNS Rebinding Check
# ===================================================================
class TestDnsRebindingCheck:
    @patch("time.sleep", return_value=None)
    @patch("socket.gethostbyname")
    def test_detects_private_ip(self, mock_dns, _sleep):
        # Alternate between public and private IPs
        ips = ["93.184.216.34", "127.0.0.1", "93.184.216.34", "192.168.1.1"]
        mock_dns.side_effect = ips + ips + ips  # enough for 10 iterations

        result = E.dns_rebinding_check("rebind.attacker.com", _log)

        assert result["vulnerable"] is True
        assert "127.0.0.1" in result["private_ips"] or "192.168.1.1" in result["private_ips"]

    @patch("time.sleep", return_value=None)
    @patch("socket.gethostbyname")
    def test_no_rebinding(self, mock_dns, _sleep):
        mock_dns.return_value = "93.184.216.34"

        result = E.dns_rebinding_check("safe.example.com", _log)

        assert result["vulnerable"] is False
        assert result["private_ips"] == []

    @patch("time.sleep", return_value=None)
    @patch("socket.gethostbyname")
    def test_handles_dns_failure(self, mock_dns, _sleep):
        mock_dns.side_effect = socket.gaierror("nxdomain")

        result = E.dns_rebinding_check("nxdomain.test", _log)

        assert result["vulnerable"] is False
        assert result["resolutions"] == []


# ===================================================================
#  HTTP/2 Smuggling Detector
# ===================================================================
class TestHttp2Smuggling:
    @patch("requests.post")
    def test_detects_suspicious_response(self, mock_post):
        # Return 502 for the H2.CL payload, 200 for others
        call_count = [0]

        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(text="Bad Gateway", status_code=502)
            return _mock_response(text="OK", status_code=200)

        mock_post.side_effect = side_effect

        result = E.http2_smuggling("https://target.com/", _log)

        assert len(result["tests"]) >= 1
        assert any(t.get("suspicious") for t in result["tests"])
        assert len(result["issues"]) >= 1

    @patch("requests.post")
    def test_all_clean(self, mock_post):
        mock_post.return_value = _mock_response(text="OK", status_code=200)

        result = E.http2_smuggling("https://clean.com/", _log)

        assert result["issues"] == []
        for t in result["tests"]:
            assert t.get("suspicious") is False

    @patch("requests.post")
    def test_handles_exception(self, mock_post):
        import requests as _req
        mock_post.side_effect = _req.ConnectionError("refused")

        result = E.http2_smuggling("https://down.com/", _log)

        assert isinstance(result["tests"], list)
        for t in result["tests"]:
            assert "error" in t


# ===================================================================
#  Prototype Pollution Scanner
# ===================================================================
class TestPrototypePollutionScan:
    @patch("requests.post")
    @patch("requests.get")
    def test_detects_reflected_pollution(self, mock_get, mock_post):
        def get_side_effect(url, **kwargs):
            if "polluted" in url:
                return _mock_response(text='{"test":"polluted"}', status_code=200)
            return _mock_response(text="clean", status_code=200)

        mock_get.side_effect = get_side_effect
        mock_post.return_value = _mock_response(text="clean", status_code=200)

        result = E.prototype_pollution_scan("http://test.com/api", _log)

        assert len(result["issues"]) >= 1

    @patch("requests.post")
    @patch("requests.get")
    def test_no_pollution(self, mock_get, mock_post):
        mock_get.return_value = _mock_response(text="safe", status_code=200)
        mock_post.return_value = _mock_response(text="safe", status_code=200)

        result = E.prototype_pollution_scan("http://safe.com", _log)

        assert result["issues"] == []


# ===================================================================
#  SSTI Scanner
# ===================================================================
class TestSstiScan:
    @patch("requests.get")
    def test_detects_jinja2_ssti(self, mock_get):
        def side_effect(url, **kwargs):
            if "7*7" in url or "7%2A7" in url:
                return _mock_response(text="Result: 49", status_code=200)
            return _mock_response(text="clean", status_code=200)

        mock_get.side_effect = side_effect

        result = E.ssti_scan("http://test.com/search", "q", _log)

        assert len(result["findings"]) >= 1
        engines = [f["engine"] for f in result["findings"]]
        assert any("Jinja2" in e or "FreeMarker" in e for e in engines)

    @patch("requests.get")
    def test_no_ssti(self, mock_get):
        mock_get.return_value = _mock_response(text="safe output", status_code=200)

        result = E.ssti_scan("http://safe.com", "q", _log)

        assert result["findings"] == []

    @patch("requests.get")
    def test_returns_correct_structure(self, mock_get):
        mock_get.return_value = _mock_response(text="no injection", status_code=200)

        result = E.ssti_scan("http://test.com", "input", _log)

        assert result["url"] == "http://test.com"
        assert result["param"] == "input"
        assert isinstance(result["findings"], list)


# ===================================================================
#  Insecure Deserialization Tester
# ===================================================================
class TestInsecureDeserTest:
    @patch("requests.post")
    def test_detects_java_deser(self, mock_post):
        call_count = [0]

        def side_effect(url, **kwargs):
            call_count[0] += 1
            ct = kwargs.get("headers", {}).get("Content-Type", "")
            if "java" in ct:
                return _mock_response(
                    text="java.lang.ClassNotFoundException: evil",
                    status_code=500,
                )
            return _mock_response(text="OK", status_code=200)

        mock_post.side_effect = side_effect

        result = E.insecure_deser_test("http://test.com/api", _log)

        assert "Java ObjectInputStream" in result["issues"]

    @patch("requests.post")
    def test_no_deser_detected(self, mock_post):
        mock_post.return_value = _mock_response(text="Not Found", status_code=404)

        result = E.insecure_deser_test("http://clean.com/", _log)

        assert result["issues"] == []
        assert len(result["tests"]) > 0

    @patch("requests.post")
    def test_handles_timeout(self, mock_post):
        import requests as _req
        mock_post.side_effect = _req.Timeout("timed out")

        result = E.insecure_deser_test("http://slow.com/", _log)

        assert result["issues"] == []


# ===================================================================
#  JWT none Attack (pure logic, no mocks needed)
# ===================================================================
class TestJwtNoneAttack:
    def test_forges_tokens_with_none_alg(self):
        token = _make_jwt()
        result = E.jwt_none_attack(token, _log)

        assert result["forged"] is True
        assert len(result["forged_tokens"]) >= 4
        algs = [t["alg"] for t in result["forged_tokens"]]
        assert "none" in algs
        assert "None" in algs
        assert "NONE" in algs

    def test_forged_token_has_empty_sig(self):
        token = _make_jwt()
        result = E.jwt_none_attack(token, _log)

        for ft in result["forged_tokens"]:
            if ft["alg"] != "none+sig":
                # Token ends with "." (empty signature)
                assert ft["token"].endswith(".")

    def test_invalid_jwt_format(self):
        result = E.jwt_none_attack("not-a-jwt", _log)
        assert result["forged"] is False

    def test_preserves_original(self):
        token = _make_jwt()
        result = E.jwt_none_attack(token, _log)
        assert result["original"] == token


# ===================================================================
#  JWT Key Confusion (pure logic, no mocks needed)
# ===================================================================
class TestJwtKeyConfusion:
    def test_forges_hs256_token(self):
        token = _make_jwt(header={"alg": "RS256", "typ": "JWT"})
        pubkey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...\n-----END PUBLIC KEY-----"

        result = E.jwt_key_confusion(token, pubkey, _log)

        assert result["forged"] is True
        assert len(result["forged_token"]) > 0
        # Forged token should have 3 parts
        parts = result["forged_token"].split(".")
        assert len(parts) == 3

    def test_forged_header_uses_hs256(self):
        token = _make_jwt(header={"alg": "RS256", "typ": "JWT"})
        pubkey = "test-public-key"

        result = E.jwt_key_confusion(token, pubkey, _log)

        # Decode the forged header
        forged_header_b64 = result["forged_token"].split(".")[0]
        forged_header_b64 += "=" * ((4 - len(forged_header_b64) % 4) % 4)
        forged_header = json.loads(base64.urlsafe_b64decode(forged_header_b64))
        assert forged_header["alg"] == "HS256"

    def test_invalid_jwt(self):
        result = E.jwt_key_confusion("bad", "key", _log)
        assert result["forged"] is False


# ===================================================================
#  CVSS Calculator (pure math, no mocks)
# ===================================================================
class TestCvssCalculate:
    def test_critical_score(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = E.cvss_calculate(vector, _log)

        assert result["score"] == 9.8
        assert result["severity"] == "Critical"

    def test_low_score(self):
        vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        result = E.cvss_calculate(vector, _log)

        assert result["score"] < 4.0
        assert result["severity"] == "Low"

    def test_none_impact(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        result = E.cvss_calculate(vector, _log)

        assert result["score"] == 0.0
        assert result["severity"] == "None"

    def test_medium_score(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
        result = E.cvss_calculate(vector, _log)

        assert 4.0 <= result["score"] < 7.0
        assert result["severity"] == "Medium"

    def test_scope_changed(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        result = E.cvss_calculate(vector, _log)

        assert result["score"] == 10.0
        assert result["severity"] == "Critical"

    def test_missing_metric(self):
        vector = "CVSS:3.1/AV:N/AC:L"
        result = E.cvss_calculate(vector, _log)

        assert result["score"] == 0.0

    def test_metrics_parsed(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = E.cvss_calculate(vector, _log)

        assert result["metrics"]["AV"] == "N"
        assert result["metrics"]["S"] == "U"


# ===================================================================
#  Scan Profiles (run_profile)
# ===================================================================
class TestRunProfile:
    @patch("gui.engine.attack_chain")
    def test_quick_profile(self, mock_chain):
        mock_chain.return_value = {"outputs": {"port_scan": [80, 443]}}

        result = E.run_profile("quick", "example.com", _log)

        assert result["profile"] == "quick"
        assert result["target"] == "example.com"
        mock_chain.assert_called_once()

    @patch("gui.engine.attack_chain")
    def test_unknown_profile(self, mock_chain):
        result = E.run_profile("nonexistent", "example.com", _log)

        assert "error" in result
        mock_chain.assert_not_called()

    @patch("gui.engine.attack_chain")
    def test_deep_profile_calls_chain(self, mock_chain):
        mock_chain.return_value = {"outputs": {}}

        result = E.run_profile("deep", "target.com", _log)

        assert result["profile"] == "deep"
        chain_arg = mock_chain.call_args[0][1]
        assert "ssti_scan" in chain_arg


# ===================================================================
#  SARIF Export (file I/O only, no network)
# ===================================================================
class TestSarifExport:
    def test_writes_valid_sarif(self, tmp_path):
        findings = [
            {"tool": "XSS Scanner", "target": "http://test.com",
             "severity": "high", "data": "reflected XSS in param q"},
            {"tool": "SQL Injection", "target": "http://test.com/login",
             "severity": "critical", "data": "error-based SQLi"},
        ]
        out = tmp_path / "report.sarif"

        result_path = E.sarif_export(findings, str(out), _log)

        assert Path(result_path).exists()
        sarif = json.loads(out.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_severity_mapping(self, tmp_path):
        findings = [
            {"tool": "A", "severity": "critical", "target": "t"},
            {"tool": "B", "severity": "low", "target": "t"},
            {"tool": "C", "severity": "info", "target": "t"},
        ]
        out = tmp_path / "mapped.sarif"
        E.sarif_export(findings, str(out), _log)

        sarif = json.loads(out.read_text(encoding="utf-8"))
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "note", "note"]

    def test_sarif_empty_findings(self, tmp_path):
        out = tmp_path / "empty.sarif"
        E.sarif_export([], str(out), _log)

        sarif = json.loads(out.read_text(encoding="utf-8"))
        assert sarif["runs"][0]["results"] == []

    def test_sarif_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "deep" / "nested" / "report.sarif"
        E.sarif_export([{"tool": "t", "severity": "info", "target": "t"}],
                       str(out), _log)
        assert out.exists()

    def test_sarif_rule_dedup(self, tmp_path):
        findings = [
            {"tool": "XSS", "severity": "high", "target": "a"},
            {"tool": "XSS", "severity": "high", "target": "b"},
            {"tool": "SQLi", "severity": "critical", "target": "c"},
        ]
        out = tmp_path / "dedup.sarif"
        E.sarif_export(findings, str(out), _log)

        sarif = json.loads(out.read_text(encoding="utf-8"))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2  # XSS and SQLi


# ===================================================================
#  Scope Management (uses gui.db)
# ===================================================================
class TestScopeManagement:
    @pytest.fixture(autouse=True)
    def _init_db(self, tmp_path, monkeypatch):
        """Point gui.db to a temporary database for each test."""
        import gui.db as db_mod
        db_file = tmp_path / "test.db"
        monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
        db_mod.init_db(str(db_file))

    def test_add_in_scope(self):
        E.scope_add("*.example.com", True, _log)
        rules = E.scope_list(_log)

        assert len(rules) == 1
        assert rules[0]["pattern"] == "*.example.com"
        assert rules[0]["in_scope"] is True

    def test_add_out_of_scope(self):
        E.scope_add("*.internal.corp", False, _log)
        rules = E.scope_list(_log)

        assert rules[0]["in_scope"] is False

    def test_scope_check_returns_true(self):
        E.scope_add("*.example.com", True, _log)
        assert E.scope_check("www.example.com", _log) is True

    def test_scope_check_returns_false_no_match(self):
        E.scope_add("*.example.com", True, _log)
        assert E.scope_check("evil.com", _log) is False

    def test_scope_check_returns_none_when_empty(self, tmp_path, monkeypatch):
        import gui.db as db_mod
        fresh = tmp_path / "fresh.db"
        monkeypatch.setattr(db_mod, "_DB_PATH", fresh)
        db_mod.init_db(str(fresh))

        assert E.scope_check("anything", _log) is None

    def test_scope_remove(self):
        E.scope_add("target.com", True, _log)
        E.scope_remove("target.com", _log)
        rules = E.scope_list(_log)

        assert len(rules) == 0


# ===================================================================
#  Database Wrappers (uses gui.db)
# ===================================================================
class TestDbWrappers:
    @pytest.fixture(autouse=True)
    def _init_db(self, tmp_path, monkeypatch):
        import gui.db as db_mod
        db_file = tmp_path / "test.db"
        monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
        db_mod.init_db(str(db_file))

    def test_db_init_returns_path(self, tmp_path):
        db_path = E.db_init(str(tmp_path / "new.db"), _log)
        assert "new.db" in db_path

    def test_db_store_and_query(self):
        fid = E.db_store("XSS", "http://t.com", "high", {"payload": "<script>"}, _log)
        assert isinstance(fid, int)
        assert fid > 0

        rows = E.db_query("XSS", None, None, _log)
        assert len(rows) >= 1
        assert rows[0]["tool"] == "XSS"

    def test_db_query_by_severity(self):
        E.db_store("A", "t1", "critical", {}, _log)
        E.db_store("B", "t2", "low", {}, _log)

        critical = E.db_query(None, None, "critical", _log)
        assert all(r["severity"] == "critical" for r in critical)

    def test_db_query_by_target(self):
        E.db_store("scan", "example.com", "info", {}, _log)
        E.db_store("scan", "other.com", "info", {}, _log)

        rows = E.db_query(None, "example", None, _log)
        assert all("example" in r["target"] for r in rows)

    def test_db_store_preserves_data(self):
        data = {"key": "value", "nested": {"a": 1}}
        E.db_store("tool", "target", "info", data, _log)

        rows = E.db_query("tool", None, None, _log)
        assert rows[0]["data"]["key"] == "value"
        assert rows[0]["data"]["nested"]["a"] == 1


# ===================================================================
#  Attack Chain — URL normalization
# ===================================================================
class TestAttackChainNormalization:
    """Verify that attack_chain normalizes the target correctly so that
    socket-based steps get a bare host while web-based steps get a full URL."""

    @patch("gui.engine.check_security_headers")
    @patch("gui.engine.scan_ports")
    def test_plain_host_gets_http_prefix_for_web_steps(self, mock_scan, mock_headers):
        """When target has no scheme, web steps receive 'http://host'."""
        mock_scan.return_value = {"open": []}
        mock_headers.return_value = {"headers": {}}

        E.attack_chain("example.com", ["port_scan", "headers"], _log)

        # socket-based step should receive bare host
        assert mock_scan.call_args[0][0] == "example.com"
        # web-based step should receive URL with scheme
        assert mock_headers.call_args[0][0] == "http://example.com"

    @patch("gui.engine.check_security_headers")
    @patch("gui.engine.scan_ports")
    def test_url_with_scheme_preserves_scheme(self, mock_scan, mock_headers):
        """When target already has a scheme, no double-prefixing occurs."""
        mock_scan.return_value = {"open": []}
        mock_headers.return_value = {"headers": {}}

        E.attack_chain("https://secure.io", ["port_scan", "headers"], _log)

        # socket-based step should get extracted hostname
        assert mock_scan.call_args[0][0] == "secure.io"
        # web-based step should keep the original HTTPS URL
        assert mock_headers.call_args[0][0] == "https://secure.io"

    @patch("gui.engine.find_subdomains")
    def test_http_target_extracts_hostname_for_socket_steps(self, mock_sub):
        """Subdomain step (socket-based) gets just the hostname, not a URL."""
        mock_sub.return_value = []

        E.attack_chain("http://sub.example.org/path", ["subdomain"], _log)

        assert mock_sub.call_args[0][0] == "sub.example.org"

    def test_unknown_step_logged_without_crash(self):
        """Unknown step names should be skipped gracefully, not raise."""
        result = E.attack_chain("example.com", ["nonexistent_step"], _log)
        assert "outputs" in result
        assert "nonexistent_step" not in result["outputs"]

    @patch("gui.engine.scan_ports")
    def test_outputs_key_used_not_results(self, mock_scan):
        """attack_chain returns 'outputs', not 'results'."""
        mock_scan.return_value = {"open": [80]}
        result = E.attack_chain("x.com", ["port_scan"], _log)
        assert "outputs" in result
        assert "results" not in result


# ===================================================================
#  CORS test — session_set called even on early stop
# ===================================================================
class TestCorsSessionSet:
    @patch("requests.get")
    def test_session_set_called_on_normal_run(self, mock_get):
        """cors_test should always set session key, even with 0 findings."""
        mock_get.return_value = _mock_response(
            headers={"Access-Control-Allow-Origin": "*"},
        )
        E._session.pop("last_cors_result", None)

        E.cors_test("http://test.com", _log)

        assert "last_cors_result" in E._session

    @patch("gui.engine._should_stop", side_effect=[True])
    @patch("requests.get")
    def test_session_set_called_when_stopped_early(self, mock_get, mock_stop):
        """Even if _should_stop() fires immediately, session_set must run."""
        E._session.pop("last_cors_result", None)

        E.cors_test("http://test.com", _log)

        # session_set must have been reached via the break path
        assert "last_cors_result" in E._session


# ===================================================================
#  Port Scanner
# ===================================================================
class TestScanPorts:
    @patch("gui.engine._check_port")
    @patch("socket.gethostbyname")
    def test_finds_open_port(self, mock_dns, mock_check):
        mock_dns.return_value = "93.184.216.34"
        mock_check.side_effect = lambda ip, port, timeout: port == 80

        result = E.scan_ports("example.com", 79, 81, 4, 1.0, _log)

        assert 80 in result
        assert 79 not in result

    @patch("socket.gethostbyname")
    def test_dns_failure_returns_empty(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")

        result = E.scan_ports("bad.host", 1, 100, 4, 1.0, _log)

        assert result == []

    @patch("gui.engine._check_port")
    @patch("socket.gethostbyname")
    def test_sets_session_keys(self, mock_dns, mock_check):
        mock_dns.return_value = "1.2.3.4"
        mock_check.return_value = True

        E.scan_ports("target.com", 443, 443, 1, 1.0, _log)

        assert E._session["last_target"] == "target.com"
        assert 443 in E._session["last_open_ports"]


# ===================================================================
#  Security Headers Check
# ===================================================================
class TestCheckSecurityHeaders:
    @patch("requests.get")
    def test_reports_present_headers(self, mock_get):
        mock_get.return_value = _mock_response(headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
        })

        result = E.check_security_headers("http://secure.com", _log)

        assert result["Strict-Transport-Security"] == "max-age=31536000"
        assert result["X-Frame-Options"] == "DENY"

    @patch("requests.get")
    def test_reports_missing_headers(self, mock_get):
        mock_get.return_value = _mock_response(headers={})

        result = E.check_security_headers("http://bare.com", _log)

        assert result["Strict-Transport-Security"] is None
        assert result["Content-Security-Policy"] is None

    @patch("requests.get")
    def test_connection_error_returns_empty(self, mock_get):
        import requests as _req
        mock_get.side_effect = _req.ConnectionError("refused")

        result = E.check_security_headers("http://down.com", _log)

        assert result == {}


# ===================================================================
#  Subdomain Finder
# ===================================================================
class TestFindSubdomains:
    @patch("socket.gethostbyname")
    def test_returns_resolved_subdomains(self, mock_dns):
        def resolver(name):
            if name.startswith("www.") or name.startswith("mail."):
                return "93.184.216.34"
            raise socket.gaierror("nxdomain")

        mock_dns.side_effect = resolver

        result = E.find_subdomains("example.com", 4, _log)

        assert isinstance(result, list)
        assert len(result) >= 1
        # Each entry is a tuple of (subdomain, ip)
        names = [t[0] for t in result]
        assert "www" in names or "mail" in names

    @patch("socket.gethostbyname")
    def test_all_fail_returns_empty(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")

        result = E.find_subdomains("nope.example.com", 4, _log)

        assert result == []

    @patch("socket.gethostbyname")
    def test_sets_session_key(self, mock_dns):
        mock_dns.return_value = "1.2.3.4"

        E.find_subdomains("example.com", 2, _log)

        assert isinstance(E._session.get("last_subdomains"), list)


# ===================================================================
#  Directory Buster
# ===================================================================
class TestBuster:
    @patch("requests.Session")
    def test_finds_existing_paths(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess

        def head_side(url, **kw):
            if "admin" in url:
                return _mock_response(status_code=200)
            return _mock_response(status_code=404)

        sess.head.side_effect = head_side

        result = E.buster("http://test.com", ["admin", "nope"], 2, _log)

        assert len(result) >= 1
        urls = [url for _, url in result]
        assert any("admin" in u for u in urls)

    @patch("requests.Session")
    def test_no_paths_found(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess
        sess.head.return_value = _mock_response(status_code=404)

        result = E.buster("http://test.com", ["x", "y"], 2, _log)

        assert result == []


# ===================================================================
#  SQL Injection Detect
# ===================================================================
class TestSqliDetect:
    @patch("requests.Session")
    def test_detects_sql_error(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess
        sess.get.return_value = _mock_response(
            text="You have an error in your SQL syntax near '\\''",
        )

        result = E.sqli_detect("http://test.com/page?id=1", _log)

        assert len(result) >= 1
        # Each finding is (param, payload, signature)
        assert result[0][0] == "id"

    @patch("requests.Session")
    def test_no_params_returns_empty(self, mock_session_cls):
        result = E.sqli_detect("http://test.com/page", _log)

        assert result == []

    @patch("requests.Session")
    def test_no_errors_returns_empty(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess
        sess.get.return_value = _mock_response(text="normal page content")

        result = E.sqli_detect("http://test.com/?q=hello", _log)

        assert result == []


# ===================================================================
#  XSS Reflected
# ===================================================================
class TestXssReflected:
    @patch("requests.Session")
    def test_detects_reflected_payload(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess

        # Reflect the exact payload back in the body
        def get_side(url, **kw):
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            q_val = params.get("q", [""])[0]
            return _mock_response(text=f"<html>Result: {q_val}</html>")

        sess.get.side_effect = get_side

        result = E.xss_reflected("http://test.com/search?q=test", _log)

        assert len(result) >= 1
        assert result[0][0] == "q"

    @patch("requests.Session")
    def test_no_params_returns_empty(self, mock_session_cls):
        result = E.xss_reflected("http://test.com/page", _log)

        assert result == []


# ===================================================================
#  WAF Detection
# ===================================================================
class TestWafDetect:
    @patch("requests.get")
    def test_detects_cloudflare(self, mock_get):
        resp = _mock_response(headers={"cf-ray": "abc123", "Server": "cloudflare"})
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([]))
        resp.cookies = jar
        mock_get.return_value = resp

        result = E.waf_detect("http://test.com", _log)

        assert "Cloudflare" in result

    @patch("requests.get")
    def test_detects_generic_waf_block(self, mock_get):
        call_count = [0]

        def side_effect(url, **kw):
            call_count[0] += 1
            resp = _mock_response(
                status_code=200 if call_count[0] == 1 else 403,
                headers={},
            )
            jar = MagicMock()
            jar.__iter__ = MagicMock(return_value=iter([]))
            resp.cookies = jar
            return resp

        mock_get.side_effect = side_effect

        result = E.waf_detect("http://test.com", _log)

        assert any("Generic WAF" in r for r in result)

    @patch("requests.get")
    def test_no_waf_detected(self, mock_get):
        resp = _mock_response(headers={})
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([]))
        resp.cookies = jar
        mock_get.return_value = resp

        result = E.waf_detect("http://clean.com", _log)

        assert result == []


# ===================================================================
#  Open Redirect Test
# ===================================================================
class TestOpenRedirectTest:
    @patch("requests.Session")
    def test_detects_redirect_to_evil(self, mock_session_cls):
        sess = MagicMock()
        mock_session_cls.return_value = sess

        def get_side(url, **kw):
            if "evil.example.com" in url:
                return _mock_response(
                    status_code=302,
                    headers={"Location": "https://evil.example.com/pwned"},
                )
            return _mock_response(status_code=200, headers={})

        sess.get.side_effect = get_side

        result = E.open_redirect_test(
            "http://test.com/redirect?url=http://safe.com", _log,
        )

        assert len(result) >= 1
        assert result[0][0] == "url"

    @patch("requests.Session")
    def test_no_params_returns_empty(self, mock_session_cls):
        result = E.open_redirect_test("http://test.com/page", _log)

        assert result == []


# ===================================================================
#  Executive Report
# ===================================================================
class TestExecutiveReport:
    def test_generates_nonempty_report(self):
        E._session["last_open_ports"] = [22, 80, 443]
        E._session["last_subdomains"] = [("www", "1.2.3.4")]
        E._session["last_buster_paths"] = []

        report = E.executive_report("example.com", _log)

        assert isinstance(report, str)
        assert len(report) > 0
        assert "example.com" in report

    def test_includes_port_info(self):
        E._session["last_open_ports"] = [21, 80, 3389]
        E._session["last_subdomains"] = []
        E._session["last_buster_paths"] = []

        report = E.executive_report("target.com", _log)

        assert "CRITICAL" in report or "FTP" in report or "RDP" in report

    def test_empty_session_still_produces_report(self):
        E._session["last_open_ports"] = []
        E._session["last_subdomains"] = []
        E._session["last_buster_paths"] = []

        report = E.executive_report("empty.com", _log)

        assert "empty.com" in report
        assert "PENETRATOR" in report


# ===================================================================
#  Auto Correlate
# ===================================================================
class TestAutoCorrelate:
    def test_high_risk_ports_increase_score(self):
        E._session["last_open_ports"] = [21, 23, 80, 445]
        E._session["last_subdomains"] = []
        E._session["last_buster_paths"] = []

        result = E.auto_correlate(_log)

        assert result["score"] >= 30
        assert any("High-risk" in f for f in result["findings"])

    def test_sensitive_paths_increase_score(self):
        E._session["last_open_ports"] = []
        E._session["last_subdomains"] = []
        E._session["last_buster_paths"] = ["/admin/", "/.git/config"]

        result = E.auto_correlate(_log)

        assert result["score"] >= 25
        assert any("Sensitive" in f for f in result["findings"])

    def test_empty_session_returns_info_grade(self):
        E._session["last_open_ports"] = []
        E._session["last_subdomains"] = []
        E._session["last_buster_paths"] = []

        result = E.auto_correlate(_log)

        assert result["score"] == 0
        assert result["grade"] == "INFO"
        assert result["findings"] == []


# ===================================================================
#  Privilege Escalation Checklist
# ===================================================================
class TestPrivescChecklist:
    @patch("subprocess.run")
    def test_returns_platform_and_checks(self, mock_run):
        mock_run.return_value = MagicMock(stdout="some output", returncode=0)

        result = E.privesc_checklist("linux", _log)

        assert result["platform"] == "linux"
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) >= 1

    @patch("subprocess.run")
    def test_windows_platform(self, mock_run):
        mock_run.return_value = MagicMock(stdout="info", returncode=0)

        result = E.privesc_checklist("windows", _log)

        assert result["platform"] == "windows"
        assert isinstance(result["checks"], list)

    @patch("subprocess.run")
    def test_handles_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="cmd", timeout=15)

        result = E.privesc_checklist("linux", _log)

        assert all(c["status"] == "timeout" for c in result["checks"])


# ===================================================================
#  Payload Encoder (pure function)
# ===================================================================
class TestEncodePayload:
    def test_all_encoding_types_present(self):
        result = E.encode_payload("<script>alert(1)</script>")

        assert "Base64" in result
        assert "Hex" in result
        assert "URL-encoded" in result
        assert "PowerShell UTF16LE B64" in result

    def test_base64_roundtrip(self):
        import base64
        text = "test payload"
        result = E.encode_payload(text)

        decoded = base64.b64decode(result["Base64"]).decode()
        assert decoded == text

    def test_hex_roundtrip(self):
        text = "hello"
        result = E.encode_payload(text)

        decoded = bytes.fromhex(result["Hex"]).decode()
        assert decoded == text


# ===================================================================
#  Homoglyph Detection
# ===================================================================
class TestHomoglyphDetect:
    @patch("socket.gethostbyname")
    def test_finds_registered_variants(self, mock_dns):
        def resolver(name):
            # Pretend one homoglyph variant is registered
            if name.startswith("g") and name != "google.com":
                return "1.2.3.4"
            raise socket.gaierror("nxdomain")

        mock_dns.side_effect = resolver

        result = E.homoglyph_detect("google.com", _log)

        assert isinstance(result, list)
        assert len(result) >= 1

    @patch("socket.gethostbyname")
    def test_no_variants_registered(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")

        result = E.homoglyph_detect("example.com", _log)

        assert result == []


# ===================================================================
#  HTTP Repeater
# ===================================================================
class TestHttpRepeat:
    @patch("requests.request")
    def test_returns_response_structure(self, mock_req):
        mock_req.return_value = _mock_response(
            text="OK response body",
            status_code=200,
            headers={"Content-Type": "text/html"},
        )
        mock_req.return_value.reason = "OK"
        mock_req.return_value.content = b"OK response body"

        result = E.http_repeat("GET", "http://test.com", "", "", _log)

        assert result["status"] == 200
        assert result["reason"] == "OK"
        assert "body" in result
        assert "headers" in result

    @patch("requests.request")
    def test_custom_headers_and_post(self, mock_req):
        mock_req.return_value = _mock_response(
            text="created", status_code=201, headers={},
        )
        mock_req.return_value.reason = "Created"
        mock_req.return_value.content = b"created"

        result = E.http_repeat(
            "POST", "http://test.com/api",
            "Authorization: Bearer tok\nX-Custom: val",
            '{"key":"value"}', _log,
        )

        assert result["status"] == 201
        call_kw = mock_req.call_args
        assert call_kw[1]["headers"]["Authorization"] == "Bearer tok"

    @patch("requests.request")
    def test_connection_error_returns_empty(self, mock_req):
        import requests as _req
        mock_req.side_effect = _req.ConnectionError("refused")

        result = E.http_repeat("GET", "http://down.com", "", "", _log)

        assert result == {}


# ===================================================================
#  TLS Scanner
# ===================================================================
class TestTlsScan:
    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_returns_cert_info(self, mock_ctx_factory, mock_conn):
        # Build the mock chain: context -> wrap_socket -> ssock
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "DigiCert")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "*.example.com")],
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"

        # wrap_socket returns a context-manager yielding ssock
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        # socket.create_connection returns a context-manager yielding raw sock
        mock_raw_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = E.tls_scan("example.com", 443, _log)

        assert result["host"] == "example.com"
        assert result["tls_version"] == "TLSv1.3"
        assert result["subject_cn"] == "example.com"
        assert result["issuer_cn"] == "DigiCert"
        assert "example.com" in result["sans"]

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_handshake_failure(self, mock_ctx_factory, mock_conn):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx

        mock_conn.return_value.__enter__ = MagicMock(side_effect=Exception("handshake failed"))
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = E.tls_scan("bad.host", 443, _log)

        assert result["host"] == "bad.host"
        assert result["port"] == 443
        # Should not have tls_version since handshake failed
        assert "tls_version" not in result


# ===================================================================
#  Async variant tests (with aiohttp mocked out → fall back to sync)
# ===================================================================

class _AiohttpHider:
    """Context manager that hides aiohttp from import machinery."""
    def __init__(self):
        self._saved = None
        self._had_key = False

    def __enter__(self):
        import builtins
        import sys
        self._had_key = "aiohttp" in sys.modules
        self._saved = sys.modules.pop("aiohttp", None)
        self._real_import = builtins.__import__

        def _mock_import(name, *a, **kw):
            if name == "aiohttp":
                raise ImportError("mocked: no aiohttp")
            return self._real_import(name, *a, **kw)

        builtins.__import__ = _mock_import
        return self

    def __exit__(self, *exc):
        import builtins
        import sys
        builtins.__import__ = self._real_import
        if self._had_key and self._saved is not None:
            sys.modules["aiohttp"] = self._saved


class TestSqliDetectAsync:
    """Test sqli_detect_async."""

    def test_fallback_without_aiohttp(self):
        """Without aiohttp, should delegate to sqli_detect."""
        with _AiohttpHider():
            with patch.object(E, "sqli_detect",
                              return_value=[("id", "'", "mysql")]) as m:
                result = E.sqli_detect_async("http://x.com/?id=1", 20, _log)
                m.assert_called_once()
                assert result == [("id", "'", "mysql")]

    def test_no_params_returns_empty(self):
        assert E.sqli_detect_async("http://x.com/", 20, _log) == []


class TestXssReflectedAsync:
    """Test xss_reflected_async."""

    def test_fallback_without_aiohttp(self):
        with _AiohttpHider():
            with patch.object(E, "xss_reflected",
                              return_value=[("q", "<script>")]) as m:
                result = E.xss_reflected_async("http://x.com/?q=1", 20, _log)
                m.assert_called_once()
                assert result == [("q", "<script>")]

    def test_no_params_returns_empty(self):
        assert E.xss_reflected_async("http://x.com/", 20, _log) == []


class TestCorsTestAsync:
    """Test cors_test_async."""

    def test_fallback_without_aiohttp(self):
        with _AiohttpHider():
            with patch.object(E, "cors_test",
                              return_value={"findings": []}) as m:
                result = E.cors_test_async("http://x.com/", 5, _log)
                m.assert_called_once()
                assert result == {"findings": []}


class TestOpenRedirectTestAsync:
    """Test open_redirect_test_async."""

    def test_fallback_without_aiohttp(self):
        with _AiohttpHider():
            with patch.object(E, "open_redirect_test",
                              return_value=[("url", "//evil.example.com")]) as m:
                result = E.open_redirect_test_async(
                    "http://x.com/?url=foo", 20, _log)
                m.assert_called_once()
                assert result == [("url", "//evil.example.com")]

    def test_no_params_returns_empty(self):
        assert E.open_redirect_test_async("http://x.com/", 20, _log) == []
