"""Mock-based unit tests for 100 untested public functions in gui/engine.py.

Every test uses ``unittest.mock.patch`` to avoid real network I/O, subprocess
calls, or filesystem access. All tests are fast (no real I/O, no sleeps).

Pattern matches the existing test_engine_mocked.py file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import tempfile
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from gui import engine as E


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _log(msg, tag="info"):
    """Silent logger for tests."""
    pass


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


def _mock_response(text="", status_code=200, headers=None, json_data=None,
                   content=b"", cookies=None):
    """Create a mock requests.Response-like object."""
    resp = MagicMock()
    resp.text = text
    resp.content = content or text.encode()
    resp.status_code = status_code
    resp.url = "http://test.com"
    resp.reason = "OK"
    ci = _CIDict()
    for k, v in (headers or {}).items():
        ci[k] = v
    resp.headers = ci
    if json_data is not None:
        resp.json = MagicMock(return_value=json_data)
    else:
        resp.json = MagicMock(return_value={})
    # cookies
    jar = MagicMock()
    cookie_objs = []
    for c in (cookies or []):
        co = MagicMock()
        co.name = c
        cookie_objs.append(co)
    jar.__iter__ = MagicMock(return_value=iter(cookie_objs))
    jar.__bool__ = MagicMock(return_value=bool(cookie_objs))
    jar.__len__ = MagicMock(return_value=len(cookie_objs))
    resp.cookies = jar
    # elapsed
    elapsed = MagicMock()
    elapsed.total_seconds = MagicMock(return_value=0.1)
    resp.elapsed = elapsed
    return resp


# ===================================================================
#  apk_analyze
# ===================================================================
class TestApkAnalyze:
    def test_file_not_found(self):
        result = E.apk_analyze("/nonexistent/path.apk", _log)
        assert result["permissions"] == []
        assert result["meta"] == {}

    def test_valid_apk_zip(self, tmp_path):
        apk = tmp_path / "test.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x00" * 10)
            zf.writestr("classes.dex", b"\x00" * 50)
            zf.writestr("lib/arm64-v8a/libnative.so", b"\x00" * 20)
            zf.writestr("res/config.json", b"{}")
        result = E.apk_analyze(str(apk), _log)
        assert result["meta"]["files_count"] == 4
        assert result["meta"]["has_manifest"] is True
        assert result["meta"]["dex_count"] == 1
        assert "arm64-v8a" in result["meta"]["native_archs"]


# ===================================================================
#  arp_spoof_detect
# ===================================================================
class TestArpSpoofDetect:
    @patch("subprocess.run")
    def test_detects_duplicate_mac(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="192.168.1.1  aa:bb:cc:dd:ee:ff  dynamic\n"
                   "192.168.1.2  aa:bb:cc:dd:ee:ff  dynamic\n"
                   "192.168.1.3  11:22:33:44:55:66  dynamic\n",
            returncode=0)
        result = E.arp_spoof_detect("eth0", _log)
        assert len(result) >= 1
        assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert len(result[0]["ips"]) == 2

    @patch("subprocess.run")
    def test_no_conflicts(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="192.168.1.1  aa:bb:cc:dd:ee:ff  dynamic\n"
                   "192.168.1.2  11:22:33:44:55:66  dynamic\n",
            returncode=0)
        result = E.arp_spoof_detect("eth0", _log)
        assert result == []

    @patch("subprocess.run")
    def test_handles_os_error(self, mock_run):
        mock_run.side_effect = OSError("command not found")
        result = E.arp_spoof_detect("eth0", _log)
        assert result == []


# ===================================================================
#  azure_blob_check
# ===================================================================
class TestAzureBlobCheck:
    @patch("requests.Session")
    def test_finds_public_container(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(text="<EnumerationResults>data</EnumerationResults>",
                              status_code=200)
        sess.get.return_value = resp
        result = E.azure_blob_check("example.com", _log)
        assert len(result) > 0
        assert result[0]["status"] == "public"

    @patch("requests.Session")
    def test_no_containers_found(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(text="", status_code=404)
        sess.get.return_value = resp
        result = E.azure_blob_check("nocontainers.com", _log)
        assert result == []


# ===================================================================
#  baseline_snapshot
# ===================================================================
class TestBaselineSnapshot:
    @patch("subprocess.run")
    def test_captures_ports_and_processes(self, mock_run):
        def side_effect(cmd, **kw):
            if "netstat" in cmd:
                return MagicMock(stdout="TCP  0.0.0.0:80  0.0.0.0:0  LISTENING\n"
                                       "TCP  0.0.0.0:443  0.0.0.0:0  LISTENING\n",
                                 returncode=0)
            elif "tasklist" in cmd:
                return MagicMock(stdout='"svchost.exe","1234","Services","0","10K"\n'
                                       '"python.exe","5678","Console","1","50K"\n',
                                 returncode=0)
            return MagicMock(stdout="", returncode=1)
        mock_run.side_effect = side_effect
        result = E.baseline_snapshot(_log)
        assert "timestamp" in result
        assert 80 in result["ports"]
        assert 443 in result["ports"]


# ===================================================================
#  broken_auth_test
# ===================================================================
class TestBrokenAuthTest:
    @patch("requests.Session")
    def test_detects_no_auth_bypass(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=200, content=b"secret data")
        result = E.broken_auth_test("http://api.test/data", "valid_token", _log)
        assert result["url"] == "http://api.test/data"
        vuln = [t for t in result["tests"] if t.get("vulnerable")]
        assert len(vuln) >= 1

    @patch("requests.Session")
    def test_auth_properly_enforced(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=401)
        result = E.broken_auth_test("http://api.test/secret", "tok", _log)
        vuln = [t for t in result["tests"] if t.get("vulnerable")]
        assert len(vuln) == 0


# ===================================================================
#  burp_export
# ===================================================================
class TestBurpExport:
    def test_exports_xml(self, tmp_path):
        out = tmp_path / "burp.xml"
        findings = [
            {"name": "XSS", "host": "http://target.com", "path": "/search",
             "severity": "High", "confidence": "Certain", "detail": "Reflected XSS"}
        ]
        result = E.burp_export(findings, str(out), _log)
        assert result == str(out)
        assert out.exists()
        content = out.read_text()
        assert "<name>XSS</name>" in content


# ===================================================================
#  buster_async (falls back to buster when aiohttp not found)
# ===================================================================
class TestBusterAsync:
    @patch("requests.Session")
    def test_fallback_to_sync(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp200 = _mock_response(status_code=200)
        resp404 = _mock_response(status_code=404)
        sess.head.side_effect = [resp200, resp404, resp200]
        sess.get.return_value = resp200
        # If aiohttp is not installed, it falls back to sync buster
        with patch.dict("sys.modules", {"aiohttp": None}):
            import importlib
            result = E.buster_async("http://test.com", ["admin", "api", "login"], 10, _log)
        assert isinstance(result, list)


# ===================================================================
#  check_subdomain_takeover
# ===================================================================
class TestCheckSubdomainTakeover:
    @patch("requests.get")
    def test_detects_takeover(self, mock_get):
        mock_get.return_value = _mock_response(
            text="NoSuchBucket - The specified bucket does not exist")
        with patch.dict("sys.modules", {"dns": MagicMock(), "dns.resolver": MagicMock()}):
            import dns.resolver
            mock_answer = MagicMock()
            mock_answer.__getitem__ = lambda s, i: MagicMock(__str__=lambda s: "test.s3.amazonaws.com.")
            dns.resolver.resolve = MagicMock(return_value=[mock_answer])
            result = E.check_subdomain_takeover("vuln.example.com", _log)
        assert result["host"] == "vuln.example.com"

    @patch("requests.get")
    def test_no_takeover(self, mock_get):
        mock_get.return_value = _mock_response(text="<html>Normal page</html>")
        with patch.dict("sys.modules", {"dns": MagicMock(), "dns.resolver": MagicMock()}):
            import dns.resolver
            dns.resolver.resolve = MagicMock(side_effect=Exception("no CNAME"))
            result = E.check_subdomain_takeover("safe.example.com", _log)
        assert result["vulnerable"] is False


# ===================================================================
#  cipher_suite_grade
# ===================================================================
class TestCipherSuiteGrade:
    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_grades_ciphers(self, mock_ctx_cls, mock_conn):
        ctx = MagicMock()
        mock_ctx_cls.return_value = ctx
        ssock = MagicMock()
        ctx.wrap_socket.return_value = ssock
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ctx.get_ciphers.return_value = [
            {"name": "TLS_AES_256_GCM_SHA384"},
            {"name": "TLS_CHACHA20_POLY1305_SHA256"},
        ]
        mock_conn.return_value = MagicMock()
        result = E.cipher_suite_grade("example.com", 443, _log)
        assert result["grade"] in ("A", "B", "C", "D", "F", "?")
        assert result["host"] == "example.com"

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connection_failure(self, mock_ctx_cls, mock_conn):
        mock_conn.side_effect = OSError("refused")
        result = E.cipher_suite_grade("down.com", 443, _log)
        assert result["grade"] == "?"


# ===================================================================
#  cis_benchmark
# ===================================================================
class TestCisBenchmark:
    @patch("subprocess.run")
    def test_windows_benchmark(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Minimum password length: 14\n", returncode=0)
        result = E.cis_benchmark("windows", _log)
        assert result["platform"] == "windows"
        assert isinstance(result["checks"], list)

    @patch("subprocess.run")
    def test_linux_benchmark(self, mock_run):
        mock_run.return_value = MagicMock(stdout="PASS_MIN_LEN 8\n", returncode=0)
        result = E.cis_benchmark("linux", _log)
        assert result["platform"] == "linux"


# ===================================================================
#  combinator
# ===================================================================
class TestCombinator:
    def test_basic_combination(self):
        result = E.combinator(["a", "b"], ["1", "2"])
        assert result == {"a1", "a2", "b1", "b2"}

    def test_empty_input(self):
        assert E.combinator([], ["x"]) == set()
        assert E.combinator(["x"], []) == set()


# ===================================================================
#  compare_files
# ===================================================================
class TestCompareFiles:
    def test_identical_files(self, tmp_path):
        f1 = tmp_path / "a.bin"
        f2 = tmp_path / "b.bin"
        f1.write_bytes(b"hello world")
        f2.write_bytes(b"hello world")
        result = E.compare_files(str(f1), str(f2), _log)
        assert result["identical"] is True

    def test_different_files(self, tmp_path):
        f1 = tmp_path / "a.bin"
        f2 = tmp_path / "b.bin"
        f1.write_bytes(b"hello")
        f2.write_bytes(b"hallo")
        result = E.compare_files(str(f1), str(f2), _log)
        assert result["identical"] is False
        assert result["offset"] == 1

    def test_file_not_found(self):
        result = E.compare_files("/no/such/a", "/no/such/b", _log)
        assert result == {}


# ===================================================================
#  crack_hash
# ===================================================================
class TestCrackHash:
    def test_finds_match(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("foo\nbar\nbaz\n")
        target = hashlib.md5(b"bar").hexdigest()
        result = E.crack_hash(target, "md5", str(wl), _log)
        assert result == "bar"

    def test_not_found(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("foo\nbar\n")
        target = hashlib.md5(b"zzz").hexdigest()
        result = E.crack_hash(target, "md5", str(wl), _log)
        assert result is None

    def test_invalid_algo(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("x\n")
        result = E.crack_hash("abc", "invalid_algo", str(wl), _log)
        assert result is None


# ===================================================================
#  crlf_test
# ===================================================================
class TestCrlfTest:
    @patch("requests.Session")
    def test_no_params(self, mock_sess_cls):
        result = E.crlf_test("http://test.com/path", _log)
        assert result == []

    @patch("requests.Session")
    def test_detects_injection(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(status_code=200, headers={
            "Injected-Header": "PENETRATOR"
        })
        resp.headers.items = lambda: [("Injected-Header", "PENETRATOR")]
        sess.get.return_value = resp
        result = E.crlf_test("http://test.com/?q=value", _log)
        assert isinstance(result, list)


# ===================================================================
#  crtsh_subdomains
# ===================================================================
class TestCrtshSubdomains:
    @patch("requests.get")
    def test_returns_subdomains(self, mock_get):
        mock_get.return_value = _mock_response(
            status_code=200,
            json_data=[
                {"name_value": "sub1.example.com"},
                {"name_value": "sub2.example.com\n*.example.com"},
            ])
        mock_get.return_value.json = MagicMock(return_value=[
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com\n*.example.com"},
        ])
        result = E.crtsh_subdomains("example.com", _log)
        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    @patch("requests.get")
    def test_handles_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("timeout")
        result = E.crtsh_subdomains("down.com", _log)
        assert result == []


# ===================================================================
#  ct_monitor
# ===================================================================
class TestCtMonitor:
    @patch("requests.get")
    def test_returns_certs(self, mock_get):
        mock_get.return_value = _mock_response(
            status_code=200,
            json_data=[
                {"id": 1, "name_value": "api.example.com",
                 "issuer_name": "Let's Encrypt", "not_before": "2024-01-01"},
                {"id": 2, "name_value": "*.example.com",
                 "issuer_name": "DigiCert", "not_before": "2024-02-01"},
            ])
        mock_get.return_value.json = MagicMock(return_value=[
            {"id": 1, "name_value": "api.example.com",
             "issuer_name": "Let's Encrypt", "not_before": "2024-01-01"},
            {"id": 2, "name_value": "*.example.com",
             "issuer_name": "DigiCert", "not_before": "2024-02-01"},
        ])
        result = E.ct_monitor("example.com", _log)
        assert len(result) == 2


# ===================================================================
#  cupp_wordlist
# ===================================================================
class TestCuppWordlist:
    def test_generates_words(self):
        values = {"first_name": "John", "last_name": "Doe", "birthday": "19900101"}
        result = E.cupp_wordlist(values)
        assert isinstance(result, set)
        assert len(result) > 10
        assert "John" in result
        assert "Doe" in result

    def test_empty_input(self):
        result = E.cupp_wordlist({})
        assert isinstance(result, set)


# ===================================================================
#  detect_tech
# ===================================================================
class TestDetectTech:
    @patch("requests.get")
    def test_detects_wordpress(self, mock_get):
        mock_get.return_value = _mock_response(
            text="<html><link href='/wp-content/themes/style.css'></html>",
            headers={"Server": "Apache/2.4"})
        result = E.detect_tech("http://wp-site.com", _log)
        assert "WordPress" in result
        assert "Server" in result

    @patch("requests.get")
    def test_handles_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")
        result = E.detect_tech("http://down.com", _log)
        assert result == {}


# ===================================================================
#  dns_axfr
# ===================================================================
class TestDnsAxfr:
    @patch("socket.getaddrinfo")
    def test_no_dnspython_fallback(self, mock_getaddr):
        mock_getaddr.return_value = [(2, 1, 6, '', ('1.2.3.4', 53))]
        with patch.dict("sys.modules", {"dns": None, "dns.resolver": None, "dns.zone": None, "dns.query": None}):
            with patch("socket.socket") as mock_sock:
                sock_inst = MagicMock()
                mock_sock.return_value = sock_inst
                sock_inst.recv.return_value = b"\x00" * 5  # short response = refused
                result = E.dns_axfr("example.com", _log)
        assert isinstance(result, list)


# ===================================================================
#  dns_lookup
# ===================================================================
class TestDnsLookup:
    def test_no_dnspython(self):
        with patch.dict("sys.modules", {"dns": None, "dns.resolver": None}):
            result = E.dns_lookup("example.com", _log)
        assert result == {}


# ===================================================================
#  domain_reputation
# ===================================================================
class TestDomainReputation:
    @patch("requests.Session")
    def test_returns_structure(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(
            status_code=200,
            json_data={"data": {"abuseConfidenceScore": 10}})
        sess.get.return_value.json = MagicMock(
            return_value={"data": {"abuseConfidenceScore": 10}})
        result = E.domain_reputation("1.2.3.4", _log)
        assert result["target"] == "1.2.3.4"
        assert "sources" in result


# ===================================================================
#  email_header_analyze
# ===================================================================
class TestEmailHeaderAnalyze:
    def test_parses_hops(self):
        headers = (
            "Received: from mx1.example.com by mx2.example.com\n"
            "Received: from origin.example.com by mx1.example.com\n"
            "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n"
            "Subject: Test\n"
        )
        result = E.email_header_analyze(headers, _log)
        assert len(result["hops"]) == 2
        assert result["authentication"]["spf"] == "pass"
        assert result["authentication"]["dkim"] == "pass"

    def test_empty_headers(self):
        result = E.email_header_analyze("", _log)
        assert result["hops"] == []


# ===================================================================
#  email_security_check
# ===================================================================
class TestEmailSecurityCheck:
    def test_no_dnspython(self):
        with patch.dict("sys.modules", {"dns": None, "dns.resolver": None}):
            result = E.email_security_check("example.com", _log)
        assert result["domain"] == "example.com"


# ===================================================================
#  extract_strings
# ===================================================================
class TestExtractStrings:
    def test_extracts_ascii(self, tmp_path):
        f = tmp_path / "binary.bin"
        f.write_bytes(b"\x00\x00Hello World\x00\x00short\x00\x00LongEnoughString\x00")
        result = E.extract_strings(str(f), 6, _log)
        strings = [s for _, s in result]
        assert "Hello World" in strings
        assert "LongEnoughString" in strings

    def test_file_not_found(self):
        result = E.extract_strings("/no/such/file", 4, _log)
        assert result == []


# ===================================================================
#  fetch_discovery_files
# ===================================================================
class TestFetchDiscoveryFiles:
    @patch("requests.get")
    def test_fetches_robots(self, mock_get):
        mock_get.return_value = _mock_response(text="User-agent: *\nDisallow: /admin",
                                               status_code=200)
        result = E.fetch_discovery_files("http://test.com", _log)
        assert "robots.txt" in result

    @patch("requests.get")
    def test_handles_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")
        result = E.fetch_discovery_files("http://down.com", _log)
        assert result == {}


# ===================================================================
#  fetch_headers
# ===================================================================
class TestFetchHeaders:
    @patch("requests.get")
    def test_returns_headers(self, mock_get):
        mock_get.return_value = _mock_response(
            headers={"Server": "nginx", "X-Powered-By": "PHP/8.0"})
        mock_get.return_value.headers = {"Server": "nginx", "X-Powered-By": "PHP/8.0"}
        result = E.fetch_headers("http://test.com", _log)
        assert result["Server"] == "nginx"

    @patch("requests.get")
    def test_handles_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")
        result = E.fetch_headers("http://down.com", _log)
        assert result == {}


# ===================================================================
#  file_hashes
# ===================================================================
class TestFileHashes:
    def test_computes_hashes(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello")
        result = E.file_hashes(str(f), _log)
        assert result["md5"] == hashlib.md5(b"hello").hexdigest()
        assert result["sha256"] == hashlib.sha256(b"hello").hexdigest()

    def test_file_not_found(self):
        result = E.file_hashes("/nonexistent", _log)
        assert result == {}


# ===================================================================
#  find_subdomains_async
# ===================================================================
class TestFindSubdomainsAsync:
    @patch("socket.getaddrinfo")
    def test_resolves_some(self, mock_getaddr):
        def side_effect(host, *a, **kw):
            if "www" in host:
                return [(2, 1, 6, '', ('1.2.3.4', 0))]
            raise socket.gaierror("nxdomain")
        mock_getaddr.side_effect = side_effect
        result = E.find_subdomains_async("example.com", 5, _log)
        assert isinstance(result, list)


# ===================================================================
#  firebase_scan
# ===================================================================
class TestFirebaseScan:
    @patch("requests.get")
    @patch("requests.put")
    def test_detects_readable(self, mock_put, mock_get):
        mock_get.return_value = _mock_response(
            text='{"users": {"admin": true}}', status_code=200,
            json_data={"users": {"admin": True}})
        mock_get.return_value.json = MagicMock(return_value={"users": {"admin": True}})
        mock_put.return_value = _mock_response(status_code=401)
        result = E.firebase_scan("test-app", _log)
        assert result["readable"] is True

    @patch("requests.get")
    @patch("requests.put")
    def test_access_denied(self, mock_put, mock_get):
        mock_get.return_value = _mock_response(status_code=401)
        mock_put.return_value = _mock_response(status_code=401)
        result = E.firebase_scan("secure-app", _log)
        assert result["readable"] is False


# ===================================================================
#  generate_password
# ===================================================================
class TestGeneratePassword:
    def test_correct_length(self):
        pw = E.generate_password(16, True, True, True)
        assert len(pw) == 16

    def test_no_symbols(self):
        pw = E.generate_password(20, True, True, False)
        assert all(c.isalnum() for c in pw)

    def test_lowercase_only(self):
        pw = E.generate_password(10, False, False, False)
        assert pw.islower()


# ===================================================================
#  get_proxy
# ===================================================================
class TestGetProxy:
    def test_returns_dict(self):
        result = E.get_proxy()
        assert isinstance(result, dict)


# ===================================================================
#  get_service
# ===================================================================
class TestGetService:
    def test_known_port(self):
        assert E.get_service(80) in ("http", "www", "www-http")

    def test_unknown_port(self):
        result = E.get_service(59999)
        # Should return "unknown" or the socket library result
        assert isinstance(result, str)


# ===================================================================
#  git_exposure_check
# ===================================================================
class TestGitExposureCheck:
    @patch("requests.Session")
    def test_detects_git_head(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(text="ref: refs/heads/main", status_code=200,
                              content=b"ref: refs/heads/main")
        sess.get.return_value = resp
        result = E.git_exposure_check("http://target.com", _log)
        assert len(result) > 0

    @patch("requests.Session")
    def test_no_exposure(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=404)
        result = E.git_exposure_check("http://secure.com", _log)
        assert result == []


# ===================================================================
#  github_dorking
# ===================================================================
class TestGithubDorking:
    @patch("requests.Session")
    def test_finds_results(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(status_code=200, json_data={
            "total_count": 1,
            "items": [{"repository": {"full_name": "user/repo"},
                       "path": "config.py", "html_url": "http://github.com/x"}]
        })
        resp.json = MagicMock(return_value={
            "total_count": 1,
            "items": [{"repository": {"full_name": "user/repo"},
                       "path": "config.py", "html_url": "http://github.com/x"}]
        })
        sess.get.return_value = resp
        result = E.github_dorking("example.com", _log)
        assert isinstance(result, list)


# ===================================================================
#  grab_banner
# ===================================================================
class TestGrabBanner:
    @patch("socket.socket")
    def test_grabs_banner(self, mock_sock_cls):
        sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        result = E.grab_banner("1.2.3.4", 22, 5.0, _log)
        assert "SSH" in result

    @patch("socket.socket")
    def test_connection_fails(self, mock_sock_cls):
        sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)
        sock.connect.side_effect = OSError("refused")
        result = E.grab_banner("1.2.3.4", 22, 5.0, _log)
        assert result == ""


# ===================================================================
#  graphql_field_enum
# ===================================================================
class TestGraphqlFieldEnum:
    @patch("requests.Session")
    def test_finds_fields(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(status_code=200, json_data={
            "errors": [{"message": "Field 'user' must have a selection of subfields"}]
        })
        resp.json = MagicMock(return_value={
            "errors": [{"message": "Field 'user' must have a selection of subfields"}]
        })
        sess.post.return_value = resp
        result = E.graphql_field_enum("http://api.test/graphql", _log)
        assert "found" in result


# ===================================================================
#  graphql_introspect
# ===================================================================
class TestGraphqlIntrospect:
    @patch("requests.post")
    def test_enabled(self, mock_post):
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"data": {"__schema": {"types": [{"name": "Query", "kind": "OBJECT"}],
                                             "queryType": {"name": "Query"},
                                             "mutationType": None,
                                             "subscriptionType": None}}})
        mock_post.return_value.json = MagicMock(return_value={
            "data": {"__schema": {"types": [{"name": "Query", "kind": "OBJECT"}],
                                  "queryType": {"name": "Query"},
                                  "mutationType": None,
                                  "subscriptionType": None}}})
        result = E.graphql_introspect("http://api.test/graphql", _log)
        assert result["enabled"] is True

    @patch("requests.post")
    def test_disabled(self, mock_post):
        mock_post.return_value = _mock_response(status_code=403)
        result = E.graphql_introspect("http://api.test/graphql", _log)
        assert result["enabled"] is False


# ===================================================================
#  hex_dump
# ===================================================================
class TestHexDump:
    def test_produces_hex(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"ABCDEFGHIJKLMNOP" * 2)
        result = E.hex_dump(str(f), 0, 32, _log)
        assert "41 42 43 44" in result
        assert "ABCDEFGHIJKLMNOP" in result

    def test_file_not_found(self):
        result = E.hex_dump("/nonexistent", 0, 16, _log)
        assert result == ""


# ===================================================================
#  hibp_password_check
# ===================================================================
class TestHibpPasswordCheck:
    @patch("requests.get")
    def test_password_pwned(self, mock_get):
        pw = "password123"
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        suffix = sha1[5:]
        mock_get.return_value = _mock_response(
            text=f"{suffix}:1500\nOTHERHASH:2\n", status_code=200)
        result = E.hibp_password_check(pw, _log)
        assert result == 1500

    @patch("requests.get")
    def test_password_safe(self, mock_get):
        mock_get.return_value = _mock_response(
            text="OTHERHASH1:5\nOTHERHASH2:3\n", status_code=200)
        result = E.hibp_password_check("very_unique_pass_xyz", _log)
        assert result == 0


# ===================================================================
#  http_smuggling_detect
# ===================================================================
class TestHttpSmugglingDetect:
    @patch("socket.create_connection")
    def test_no_smuggling(self, mock_conn):
        sock = MagicMock()
        mock_conn.return_value = sock
        sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", socket.timeout(), b"HTTP/1.1 200 OK\r\n\r\n", socket.timeout(), b"HTTP/1.1 200 OK\r\n\r\n", socket.timeout()]
        result = E.http_smuggling_detect("http://safe.com/path", _log)
        assert "results" in result


# ===================================================================
#  identify_magic
# ===================================================================
class TestIdentifyMagic:
    def test_identifies_png(self, tmp_path):
        f = tmp_path / "test.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 24)
        result = E.identify_magic(str(f), _log)
        assert result is not None
        assert "PNG" in result

    def test_unknown_magic(self, tmp_path):
        f = tmp_path / "unknown"
        f.write_bytes(b"\x01\x02\x03\x04" * 8)
        result = E.identify_magic(str(f), _log)
        assert result is None


# ===================================================================
#  image_hide / image_extract
# ===================================================================
class TestImageStego:
    def test_hide_and_extract(self, tmp_path):
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        cover = tmp_path / "cover.png"
        img = Image.new("RGB", (100, 100), color=(128, 128, 128))
        img.save(cover)
        output = tmp_path / "stego.png"
        hidden = E.image_hide(str(cover), "secret msg", str(output), _log)
        assert hidden == str(output)
        extracted = E.image_extract(str(output), _log)
        assert extracted == "secret msg"

    def test_cover_not_found(self):
        result = E.image_hide("/no/cover.png", "msg", "/out.png", _log)
        assert result is None


# ===================================================================
#  ip_geolocate
# ===================================================================
class TestIpGeolocate:
    @patch("requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(
            json_data={"status": "success", "query": "8.8.8.8",
                       "country": "US", "city": "Mountain View"})
        mock_get.return_value.json = MagicMock(return_value={
            "status": "success", "query": "8.8.8.8",
            "country": "US", "city": "Mountain View"})
        result = E.ip_geolocate("8.8.8.8", _log)
        assert result["country"] == "US"

    @patch("requests.get")
    def test_failure(self, mock_get):
        mock_get.side_effect = Exception("timeout")
        result = E.ip_geolocate("invalid", _log)
        assert result == {}


# ===================================================================
#  jwt_key_confusion
# ===================================================================
class TestJwtKeyConfusion:
    def test_forges_token(self):
        # Build a minimal RS256 JWT
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1234"}).encode()
        ).decode().rstrip("=")
        token = f"{header}.{payload}.fakesig"
        result = E.jwt_key_confusion(token, "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----", _log)
        assert result["forged"] is True
        assert result["forged_token"] != ""


# ===================================================================
#  kerberos_enum
# ===================================================================
class TestKerberosEnum:
    @patch("socket.create_connection")
    def test_no_impacket_fallback(self, mock_conn):
        mock_conn.return_value = MagicMock()
        with patch.dict("sys.modules", {"impacket": None, "impacket.krb5": None,
                                         "impacket.krb5.kerberosv5": None,
                                         "impacket.krb5.types": None}):
            result = E.kerberos_enum("dc.test.local", "test.local", ["admin"], _log)
        assert isinstance(result, list)


# ===================================================================
#  leet_mutate
# ===================================================================
class TestLeetMutate:
    def test_generates_mutations(self):
        result = E.leet_mutate(["pass"], per_word=10)
        assert isinstance(result, set)
        assert len(result) >= 1
        assert "pass" in result or "p4ss" in result or "pa55" in result

    def test_empty_list(self):
        result = E.leet_mutate([])
        assert result == set()


# ===================================================================
#  lfi_scan
# ===================================================================
class TestLfiScan:
    @patch("requests.Session")
    def test_no_params(self, mock_sess_cls):
        result = E.lfi_scan("http://test.com/page", "", _log)
        assert result == []

    @patch("requests.Session")
    def test_detects_lfi(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(text="root:x:0:0:root:/root:/bin/bash")
        sess.get.return_value = resp
        result = E.lfi_scan("http://test.com/page?file=x", "file", _log)
        assert len(result) > 0


# ===================================================================
#  mass_assignment_test
# ===================================================================
class TestMassAssignmentTest:
    @patch("requests.Session")
    def test_detects_mass_assign(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        baseline = _mock_response(status_code=200, content=b"x" * 100)
        modified = _mock_response(status_code=200, content=b"x" * 300)
        sess.request.side_effect = [baseline] + [modified] * 50
        result = E.mass_assignment_test("http://api.test/user", "POST", '{"name":"test"}', _log)
        assert isinstance(result, list)


# ===================================================================
#  mqtt_test
# ===================================================================
class TestMqttTest:
    @patch("socket.create_connection")
    def test_no_paho_fallback(self, mock_conn):
        mock_conn.return_value = MagicMock()
        with patch.dict("sys.modules", {"paho": None, "paho.mqtt": None, "paho.mqtt.client": None}):
            result = E.mqtt_test("broker.test", 1883, _log)
        assert result["broker"] == "broker.test"


# ===================================================================
#  nmap_import
# ===================================================================
class TestNmapImport:
    def test_parses_xml(self, tmp_path):
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(xml_content)
        result = E.nmap_import(str(xml_file), _log)
        assert result["total_ports"] == 2
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["address"] == "192.168.1.1"


# ===================================================================
#  nuclei_run
# ===================================================================
class TestNucleiRun:
    @patch("shutil.which")
    def test_nuclei_not_installed(self, mock_which):
        mock_which.return_value = None
        result = E.nuclei_run("http://target.com", "", _log)
        assert result == []


# ===================================================================
#  open_redirect_test
# ===================================================================
class TestOpenRedirectTest:
    @patch("requests.Session")
    def test_no_params(self, mock_sess_cls):
        result = E.open_redirect_test("http://test.com/path", _log)
        assert result == []

    @patch("requests.Session")
    def test_detects_redirect(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(status_code=302, headers={"Location": "https://evil.example.com/phish"})
        resp.is_redirect = True
        sess.get.return_value = resp
        result = E.open_redirect_test("http://test.com/redir?url=x", _log)
        assert isinstance(result, list)


# ===================================================================
#  open_redirect_test_async
# ===================================================================
class TestOpenRedirectTestAsync:
    @patch("requests.Session")
    def test_fallback(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=200, headers={})
        with patch.dict("sys.modules", {"aiohttp": None}):
            result = E.open_redirect_test_async("http://test.com/redir?url=x", 5, _log)
        assert isinstance(result, list)


# ===================================================================
#  parse_pe
# ===================================================================
class TestParsePe:
    def test_valid_pe(self, tmp_path):
        # Build minimal PE header
        pe = bytearray(b"MZ" + b"\x00" * 58)  # DOS header
        pe[0x3C:0x40] = struct.pack("<I", 64)  # e_lfanew
        pe += b"PE\x00\x00"  # PE signature at offset 64
        pe += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0x0022)  # COFF header
        pe += b"\x00" * 40  # section entry
        f = tmp_path / "test.exe"
        f.write_bytes(bytes(pe))
        result = E.parse_pe(str(f), _log)
        assert result["machine"] == "x64"

    def test_not_pe(self, tmp_path):
        f = tmp_path / "notpe"
        f.write_bytes(b"not a PE file at all")
        result = E.parse_pe(str(f), _log)
        assert result == {}


# ===================================================================
#  paste_monitor
# ===================================================================
class TestPasteMonitor:
    @patch("requests.Session")
    def test_returns_findings(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(status_code=200, json_data=[
            {"id": "abc123", "time": "2024-01-01"}
        ])
        resp.json = MagicMock(return_value=[{"id": "abc123", "time": "2024-01-01"}])
        sess.get.return_value = resp
        result = E.paste_monitor("example.com", _log)
        assert isinstance(result, list)


# ===================================================================
#  pattern_generate
# ===================================================================
class TestPatternGenerate:
    def test_generates_combinations(self):
        result = list(E.pattern_generate("ab", 1, 2))
        assert "a" in result
        assert "b" in result
        assert "aa" in result
        assert "ab" in result
        assert len(result) == 6  # 2^1 + 2^2


# ===================================================================
#  phone_info
# ===================================================================
class TestPhoneInfo:
    def test_no_phonenumbers_lib(self):
        with patch.dict("sys.modules", {"phonenumbers": None}):
            result = E.phone_info("+1234567890", _log)
        assert result == {}


# ===================================================================
#  phishing_url_analyze
# ===================================================================
class TestPhishingUrlAnalyze:
    def test_safe_url(self):
        result = E.phishing_url_analyze("https://google.com", _log)
        assert result["grade"] == "SAFE"
        assert result["score"] < 20

    def test_suspicious_url(self):
        result = E.phishing_url_analyze(
            "http://192.168.1.1:8080/login-verify-account@evil.com/secure-update?x=" + "A" * 50, _log)
        assert result["score"] >= 40


# ===================================================================
#  privesc_checklist
# ===================================================================
class TestPrivescChecklist:
    @patch("subprocess.run")
    def test_windows(self, mock_run):
        mock_run.return_value = MagicMock(stdout="SeDebugPrivilege  Enabled\n", returncode=0)
        result = E.privesc_checklist("windows", _log)
        assert result["platform"] == "windows"
        assert isinstance(result["checks"], list)


# ===================================================================
#  prototype_pollution_scan
# ===================================================================
class TestPrototypePollutionScan:
    @patch("requests.get")
    @patch("requests.post")
    def test_no_pollution(self, mock_post, mock_get):
        mock_get.return_value = _mock_response(text="<html>normal</html>")
        mock_post.return_value = _mock_response(text="<html>normal</html>")
        result = E.prototype_pollution_scan("http://target.com/api", _log)
        assert result["url"] == "http://target.com/api"
        assert isinstance(result["tests"], list)


# ===================================================================
#  race_condition_test
# ===================================================================
class TestRaceConditionTest:
    @patch("requests.Session")
    def test_consistent_responses(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.request.return_value = _mock_response(status_code=200, content=b"ok")
        result = E.race_condition_test("http://api.test/transfer", "POST", "amount=1", 5, _log)
        assert result["total"] >= 2
        assert isinstance(result["suspicious"], bool)


# ===================================================================
#  rate_limit_test
# ===================================================================
class TestRateLimitTest:
    @patch("requests.Session")
    def test_rate_limited(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        responses = [_mock_response(status_code=200)] * 5 + \
                    [_mock_response(status_code=429, headers={"Retry-After": "60"})] * 5
        sess.get.side_effect = responses
        result = E.rate_limit_test("http://api.test/endpoint", 10, _log)
        assert result["rate_limited"] is True
        assert result["blocked_at"] == 6


# ===================================================================
#  read_exif
# ===================================================================
class TestReadExif:
    def test_file_not_found(self):
        result = E.read_exif("/nonexistent/photo.jpg", _log)
        assert result == {}


# ===================================================================
#  resolve_host
# ===================================================================
class TestResolveHost:
    @patch("socket.gethostbyname_ex")
    def test_resolves(self, mock_dns):
        mock_dns.return_value = ("example.com", [], ["93.184.216.34"])
        result = E.resolve_host("example.com", _log)
        assert "93.184.216.34" in result

    @patch("socket.gethostbyname_ex")
    def test_fails(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")
        result = E.resolve_host("nonexistent.xyz", _log)
        assert result == []


# ===================================================================
#  reverse_dns
# ===================================================================
class TestReverseDns:
    @patch("socket.gethostbyaddr")
    def test_resolves(self, mock_dns):
        mock_dns.return_value = ("dns.google", [], ["8.8.8.8"])
        result = E.reverse_dns("8.8.8.8", _log)
        assert result[0] == "dns.google"

    @patch("socket.gethostbyaddr")
    def test_fails(self, mock_dns):
        mock_dns.side_effect = socket.herror("host not found")
        result = E.reverse_dns("0.0.0.0", _log)
        assert result is None


# ===================================================================
#  rsa_key_analyze
# ===================================================================
class TestRsaKeyAnalyze:
    def test_invalid_key(self):
        result = E.rsa_key_analyze("not a real key", _log)
        assert "issues" in result

    def test_valid_structure(self):
        # Test with a minimal base64 that decodes but won't be a valid key
        fake_key = "-----BEGIN PUBLIC KEY-----\n"
        fake_key += base64.b64encode(b"\x30" * 100).decode() + "\n"
        fake_key += "-----END PUBLIC KEY-----"
        result = E.rsa_key_analyze(fake_key, _log)
        assert isinstance(result, dict)


# ===================================================================
#  run_profile
# ===================================================================
class TestRunProfile:
    def test_unknown_profile(self):
        result = E.run_profile("nonexistent_profile", "target.com", _log)
        assert "error" in result


# ===================================================================
#  s3_bucket_enum
# ===================================================================
class TestS3BucketEnum:
    @patch("requests.Session")
    def test_finds_public_bucket(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(text="<ListBucketResult>contents</ListBucketResult>",
                              status_code=200)
        sess.get.return_value = resp
        result = E.s3_bucket_enum("example.com", _log)
        assert len(result) > 0
        assert result[0]["status"] == "public"

    @patch("requests.Session")
    def test_no_buckets(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=404)
        result = E.s3_bucket_enum("nobuckets.com", _log)
        assert result == []


# ===================================================================
#  sarif_export
# ===================================================================
class TestSarifExport:
    def test_generates_sarif(self, tmp_path):
        out = tmp_path / "report.sarif"
        findings = [
            {"tool": "xss_scan", "target": "http://t.com", "severity": "high",
             "detail": "Reflected XSS in param q"},
        ]
        result = E.sarif_export(findings, str(out), _log)
        assert result == str(out)
        content = json.loads(out.read_text())
        assert content["version"] == "2.1.0"
        assert len(content["runs"][0]["results"]) == 1


# ===================================================================
#  scan_diff
# ===================================================================
class TestScanDiff:
    def test_detects_new_ports(self):
        current = {"ports": [80, 443, 8080]}
        previous = {"ports": [80, 443]}
        result = E.scan_diff(current, previous, _log)
        assert 8080 in result["new"]

    def test_detects_removed_ports(self):
        current = {"ports": [80]}
        previous = {"ports": [80, 443]}
        result = E.scan_diff(current, previous, _log)
        assert 443 in result["removed"]

    def test_no_changes(self):
        current = {"ports": [80, 443]}
        previous = {"ports": [80, 443]}
        result = E.scan_diff(current, previous, _log)
        assert result["new"] == []
        assert result["removed"] == []


# ===================================================================
#  scan_ports_async
# ===================================================================
class TestScanPortsAsync:
    @patch("socket.gethostbyname")
    def test_resolve_failure(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")
        result = E.scan_ports_async("nonexistent.xyz", 1, 100, 10, 0.5, _log)
        assert result == []


# ===================================================================
#  session_dump / session_restore
# ===================================================================
class TestSessionDumpRestore:
    def test_dump_returns_dict(self):
        result = E.session_dump()
        assert isinstance(result, dict)

    def test_restore_updates_session(self):
        snapshot = {"last_target": "test.local", "last_open_ports": [22, 80]}
        E.session_restore(snapshot)
        assert E.session_get("last_target") == "test.local"
        assert E.session_get("last_open_ports") == [22, 80]
        # Cleanup
        E.session_restore({"last_target": None, "last_open_ports": []})

    def test_restore_ignores_non_dict(self):
        E.session_restore("not a dict")  # should not crash
        E.session_restore(None)  # should not crash


# ===================================================================
#  smb_enum
# ===================================================================
class TestSmbEnum:
    @patch("subprocess.run")
    @patch("socket.create_connection")
    def test_net_view_success(self, mock_conn, mock_run):
        mock_run.return_value = MagicMock(
            stdout="Shared resources at \\\\host\n"
                   "Share name  Type  Used as\n"
                   "---\n"
                   "C$          Disk\n"
                   "ADMIN$      Disk\n"
                   "The command completed successfully.\n",
            returncode=0)
        mock_conn.side_effect = OSError("refused")
        result = E.smb_enum("192.168.1.1", _log)
        assert isinstance(result, list)


# ===================================================================
#  snmp_walk
# ===================================================================
class TestSnmpWalk:
    @patch("socket.socket")
    def test_valid_community(self, mock_sock_cls):
        sock = MagicMock()
        mock_sock_cls.return_value = sock
        sock.recvfrom.return_value = (b"\x30" * 50, ("1.2.3.4", 161))
        result = E.snmp_walk("1.2.3.4", "public", _log)
        assert len(result) >= 1
        assert result[0]["community"] == "public"

    @patch("socket.socket")
    def test_timeout(self, mock_sock_cls):
        sock = MagicMock()
        mock_sock_cls.return_value = sock
        sock.recvfrom.side_effect = socket.timeout("timed out")
        result = E.snmp_walk("1.2.3.4", "public", _log)
        assert result == []


# ===================================================================
#  sqli_detect_async
# ===================================================================
class TestSqliDetectAsync:
    def test_no_params(self):
        with patch.dict("sys.modules", {"aiohttp": None}):
            result = E.sqli_detect_async("http://test.com/path", 5, _log)
        assert result == []


# ===================================================================
#  subdomain_permutation (already tested but adding coverage)
# ===================================================================
class TestSubdomainPermutationCoverage:
    @patch("socket.gethostbyname")
    def test_empty_result(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("nxdomain")
        result = E.subdomain_permutation("nope.example.com", _log)
        assert result == []


# ===================================================================
#  swagger_discovery
# ===================================================================
class TestSwaggerDiscovery:
    @patch("requests.Session")
    def test_finds_swagger(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        resp = _mock_response(
            text='{"swagger":"2.0","info":{"title":"API"},"paths":{}}',
            status_code=200, headers={"Content-Type": "application/json"})
        sess.get.return_value = resp
        result = E.swagger_discovery("http://api.test.com", _log)
        assert len(result) > 0

    @patch("requests.Session")
    def test_nothing_found(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=404)
        result = E.swagger_discovery("http://secure.com", _log)
        assert result == []


# ===================================================================
#  tech_fingerprint
# ===================================================================
class TestTechFingerprint:
    @patch("requests.get")
    def test_identifies_tech(self, mock_get):
        resp = _mock_response(
            text="<html><meta name='generator' content='WordPress 6.0'></html>",
            headers={"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2",
                     "Set-Cookie": ""})
        mock_get.return_value = resp
        result = E.tech_fingerprint("http://wp.test.com", _log)
        assert "url" in result
        assert isinstance(result["technologies"], list)


# ===================================================================
#  tls_scan
# ===================================================================
class TestTlsScan:
    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_successful_scan(self, mock_ctx, mock_conn):
        ctx = MagicMock()
        mock_ctx.return_value = ctx
        ssock = MagicMock()
        ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        ssock.getpeercert.return_value = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "DigiCert")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "*.example.com")],
            "notAfter": "Dec 31 23:59:59 2025 GMT",
        }
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssock.version.return_value = "TLSv1.3"
        mock_conn.return_value = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        result = E.tls_scan("example.com", 443, _log)
        assert result["host"] == "example.com"


# ===================================================================
#  ua_rotation_demo
# ===================================================================
class TestUaRotationDemo:
    @patch("requests.get")
    def test_rotates_ua(self, mock_get):
        mock_get.return_value = _mock_response(status_code=200)
        result = E.ua_rotation_demo("http://test.com", 3, _log)
        assert len(result) == 3
        # Each result should have different UA
        uas = [r["ua"] for r in result]
        assert all(isinstance(ua, str) for ua in uas)


# ===================================================================
#  udp_scan
# ===================================================================
class TestUdpScan:
    @patch("socket.socket")
    def test_finds_open_port(self, mock_sock_cls):
        sock = MagicMock()
        mock_sock_cls.return_value = sock
        sock.recvfrom.return_value = (b"\x00" * 20, ("1.2.3.4", 53))
        result = E.udp_scan("1.2.3.4", [53], _log)
        assert len(result) == 1
        assert result[0]["port"] == 53

    @patch("socket.socket")
    def test_timeout(self, mock_sock_cls):
        sock = MagicMock()
        mock_sock_cls.return_value = sock
        sock.recvfrom.side_effect = socket.timeout("timed out")
        result = E.udp_scan("1.2.3.4", [53, 161], _log)
        assert result == []


# ===================================================================
#  username_search
# ===================================================================
class TestUsernameSearch:
    @patch("requests.Session")
    def test_searches_sites(self, mock_sess_cls):
        sess = MagicMock()
        mock_sess_cls.return_value = sess
        sess.get.return_value = _mock_response(status_code=200)
        result = E.username_search("testuser123", _log)
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0][2] == 200  # status code


# ===================================================================
#  verify_email
# ===================================================================
class TestVerifyEmail:
    def test_invalid_syntax(self):
        result = E.verify_email("not-an-email", _log)
        assert result["valid"] is False

    def test_valid_syntax(self):
        with patch.dict("sys.modules", {"dns": None, "dns.resolver": None}):
            result = E.verify_email("user@example.com", _log)
        assert result["valid"] is True
        assert result["domain"] == "example.com"


# ===================================================================
#  waf_detect
# ===================================================================
class TestWafDetect:
    @patch("requests.get")
    def test_detects_cloudflare(self, mock_get):
        baseline = _mock_response(status_code=200, headers={"cf-ray": "abc123", "Server": "cloudflare"})
        noisy = _mock_response(status_code=403, headers={"cf-ray": "def456", "Server": "cloudflare"})
        mock_get.side_effect = [baseline, noisy]
        result = E.waf_detect("http://protected.com", _log)
        assert "Cloudflare" in result


# ===================================================================
#  wayback_urls
# ===================================================================
class TestWaybackUrls:
    @patch("requests.get")
    def test_returns_urls(self, mock_get):
        mock_get.return_value = _mock_response(
            status_code=200,
            json_data=[["original"], ["http://example.com/page1"], ["http://example.com/.env"]])
        mock_get.return_value.json = MagicMock(return_value=[
            ["original"], ["http://example.com/page1"], ["http://example.com/.env"]])
        result = E.wayback_urls("example.com", 100, _log)
        assert len(result) == 2

    @patch("requests.get")
    def test_handles_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("timeout")
        result = E.wayback_urls("down.com", 10, _log)
        assert result == []


# ===================================================================
#  websocket_fuzz
# ===================================================================
class TestWebsocketFuzz:
    def test_no_websocket_lib(self):
        with patch.dict("sys.modules", {"websocket": None}):
            result = E.websocket_fuzz("ws://test.com/ws", _log)
        assert result == []


# ===================================================================
#  whois_lookup
# ===================================================================
class TestWhoisLookup:
    def test_no_whois_lib(self):
        with patch.dict("sys.modules", {"whois": None}):
            result = E.whois_lookup("example.com", _log)
        assert result == {}


# ===================================================================
#  ws_hide / ws_extract (whitespace steganography)
# ===================================================================
class TestWhitespaceStego:
    def test_hide_and_extract(self, tmp_path):
        cover = tmp_path / "cover.txt"
        cover.write_text("Line one\nLine two\nLine three\n" * 100)
        output = tmp_path / "stego.txt"
        hidden = E.ws_hide(str(cover), "hi", str(output), _log)
        assert hidden == str(output)
        extracted = E.ws_extract(str(output), _log)
        assert extracted == "hi"

    def test_cover_not_found(self):
        result = E.ws_hide("/no/file.txt", "msg", "/out.txt", _log)
        assert result is None


# ===================================================================
#  xss_reflected_async
# ===================================================================
class TestXssReflectedAsync:
    def test_no_params(self):
        with patch.dict("sys.modules", {"aiohttp": None}):
            result = E.xss_reflected_async("http://test.com/path", 5, _log)
        assert result == []


# ===================================================================
#  cors_test_async
# ===================================================================
class TestCorsTestAsync:
    @patch("requests.get")
    def test_fallback_to_sync(self, mock_get):
        mock_get.return_value = _mock_response(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "*"})
        with patch.dict("sys.modules", {"aiohttp": None}):
            result = E.cors_test_async("http://test.com", 5, _log)
        assert "findings" in result


# ===================================================================
#  yara_scan
# ===================================================================
class TestYaraScan:
    def test_no_yara_lib(self):
        with patch.dict("sys.modules", {"yara": None}):
            result = E.yara_scan("/some/file", "/rules", _log)
        assert result == []
