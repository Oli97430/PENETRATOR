"""Functional tests for gui.engine.* — no network required where possible."""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from gui import engine as E


def _log(msg, tag="info"):  # pragma: no cover - swallowed
    pass


# ---------------------------------------------------------------------------
# Hash tools
# ---------------------------------------------------------------------------
def test_identify_hash_md5_and_sha256():
    md5 = hashlib.md5(b"hello").hexdigest()
    sha256 = hashlib.sha256(b"hello").hexdigest()
    assert any("MD5" in s for s in E.identify_hash(md5))
    assert "SHA-256" in E.identify_hash(sha256)


def test_crack_hash_md5(tmp_path: Path):
    md5 = hashlib.md5(b"hello").hexdigest()
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\npassword\nhello\nsecret\n", encoding="utf-8")
    assert E.crack_hash(md5, "md5", str(wl), _log) == "hello"


def test_password_strength_ordering():
    weak = E.password_strength("abc")[0]
    strong = E.password_strength("CorrectHorse!Battery42")[0]
    assert weak < strong


def test_generate_password_length():
    pw = E.generate_password(20, True, True, True)
    assert len(pw) == 20


# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------
def test_cupp_wordlist_grows_with_input():
    words = E.cupp_wordlist({
        "first": "alice", "last": "smith", "nick": "al",
        "partner": "", "pet": "fido", "company": "",
        "birthday": "01011990", "keywords": "london",
    })
    assert len(words) > 100
    assert any("alice" in w.lower() for w in words)


def test_combinator():
    assert E.combinator(["foo", "bar"], ["1", "2"]) == {"foo1", "foo2", "bar1", "bar2"}


def test_leet_mutate_includes_substitution():
    mut = E.leet_mutate(["password"], per_word=200)
    assert "password" in mut
    assert any(c in w for w in mut for c in "4@3150$7")


def test_pattern_generate_exhaustive():
    assert set(E.pattern_generate("ab", 2, 2)) == {"aa", "ab", "ba", "bb"}


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------
def test_xss_encodings():
    enc = E.xss_encodings("<script>")
    assert enc["URL"] == "%3Cscript%3E"
    assert enc["HTML entity"] == "&lt;script&gt;"


def test_encode_payload():
    d = E.encode_payload("abc")
    assert d["Base64"] == "YWJj"
    assert d["Hex"] == "616263"


# ---------------------------------------------------------------------------
# Steganography
# ---------------------------------------------------------------------------
def test_image_stego_round_trip(tmp_path: Path):
    pytest.importorskip("PIL")
    from PIL import Image
    cover = tmp_path / "cover.png"
    stego = tmp_path / "stego.png"
    Image.new("RGB", (64, 64), color=(100, 150, 200)).save(cover)
    msg = "PENETRATOR test 测试 OK"
    E.image_hide(str(cover), msg, str(stego), _log)
    assert E.image_extract(str(stego), _log) == msg


def test_whitespace_stego_round_trip(tmp_path: Path):
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    cover.write_text("lorem\nipsum\ndolor\nsit\namet\n" * 20, encoding="utf-8")
    E.ws_hide(str(cover), "hidden", str(stego), _log)
    assert E.ws_extract(str(stego), _log) == "hidden"


# ---------------------------------------------------------------------------
# Forensic / RE
# ---------------------------------------------------------------------------
def test_file_hashes_match_reference(tmp_path: Path):
    f = tmp_path / "t.bin"
    f.write_bytes(b"hello")
    h = E.file_hashes(str(f), _log)
    assert h["md5"] == hashlib.md5(b"hello").hexdigest()
    assert h["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_extract_strings(tmp_path: Path):
    f = tmp_path / "t.bin"
    f.write_bytes(b"\x00\x00HelloWorld\x00\xff\xffABCDEF\x00\x00")
    found = [s for _, s in E.extract_strings(str(f), 4, _log)]
    assert "HelloWorld" in found and "ABCDEF" in found


def test_identify_magic_png(tmp_path: Path):
    f = tmp_path / "t.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    result = E.identify_magic(str(f), _log)
    assert result and "PNG" in result


def test_compare_files_diff_offset(tmp_path: Path):
    a = tmp_path / "a.bin"; b = tmp_path / "b.bin"
    a.write_bytes(b"AAAA"); b.write_bytes(b"AABB")
    result = E.compare_files(str(a), str(b), _log)
    assert result["offset"] == 2
    assert not result["identical"]


# ---------------------------------------------------------------------------
# OSINT
# ---------------------------------------------------------------------------
def test_verify_email_rejects_bad_syntax():
    assert not E.verify_email("bad..", _log).get("valid")


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------
def test_reverse_shell_template_renders():
    assert "Bash" in E.REVERSE_SHELL_TEMPLATES
    rendered = E.REVERSE_SHELL_TEMPLATES["Bash"].format(lhost="1.2.3.4", lport="4444")
    assert "1.2.3.4" in rendered and "4444" in rendered


# ---------------------------------------------------------------------------
# JWT toolkit
# ---------------------------------------------------------------------------
def test_jwt_decode():
    # eyJ... = header {"alg":"HS256","typ":"JWT"}
    # payload {"sub":"1234","name":"alice"}
    # signed with secret "key"
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0IiwibmFtZSI6ImFsaWNlIn0."
        "wsCt3uM-EFr9SLrYy_x0XZX46hYQbQXtKPYRMM10qNk"
    )
    out = E.jwt_decode(token, _log)
    assert out["header"]["alg"] == "HS256"
    assert out["payload"]["sub"] == "1234"
    assert out["payload"]["name"] == "alice"


def test_jwt_brute_finds_secret(tmp_path: Path):
    import hmac as _hmac
    import json as _json
    import base64 as _b64

    def _b64u(b: bytes) -> str:
        return _b64.urlsafe_b64encode(b).decode().rstrip("=")

    header = _b64u(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64u(_json.dumps({"x": 1}).encode())
    signing_input = (header + "." + payload).encode()
    secret = "letmein"
    sig = _hmac.new(secret.encode(), signing_input, "sha256").digest()
    token = f"{header}.{payload}.{_b64u(sig)}"

    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nletmein\nfoo\n", encoding="utf-8")
    assert E.jwt_brute(token, str(wl), _log) == secret


# ---------------------------------------------------------------------------
# Banner / TLS / takeover — smoke tests (no network required)
# ---------------------------------------------------------------------------
def test_takeover_fingerprints_loaded():
    assert len(E.TAKEOVER_FINGERPRINTS) >= 10
    # spot-check structure
    for service, suffix, fingerprint in E.TAKEOVER_FINGERPRINTS:
        assert isinstance(service, str) and service
        assert isinstance(suffix, str) and suffix
        assert isinstance(fingerprint, str) and fingerprint
