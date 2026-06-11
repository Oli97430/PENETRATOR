"""PENETRATOR REST API — headless interface to the engine.

Run: uvicorn penetrator_api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hmac
import os
import sys
from pathlib import Path

# Add project root to path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from contextlib import asynccontextmanager

import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from gui import engine as E
from gui.db import init_db


import json as _json
import logging

# Structured JSON log formatter for production deployments
class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return _json.dumps(payload, ensure_ascii=False)


_logger = logging.getLogger("penetrator")
_handler = logging.StreamHandler()
_handler.setFormatter(_JsonFormatter())
_logger.addHandler(_handler)
_logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if API_KEY == "changeme":
        _logger.critical(
            "⚠  PENETRATOR_API_KEY is set to the default 'changeme'. "
            "Set a strong key via environment variable before exposing this service."
        )
        raise RuntimeError(
            "Refusing to start with default API key 'changeme'. "
            "Set PENETRATOR_API_KEY environment variable."
        )
    db_path = os.environ.get("PENETRATOR_DB_PATH")
    init_db(db_path)
    yield


app = FastAPI(
    title="PENETRATOR API",
    version="1.9.0",
    description="Penetration testing toolkit API",
    lifespan=lifespan,
)

# CORS — configurable origins for dashboard/integration use
from fastapi.middleware.cors import CORSMiddleware

_CORS_ORIGINS = os.environ.get("PENETRATOR_CORS_ORIGINS", "").split(",")
_CORS_ORIGINS = [o.strip() for o in _CORS_ORIGINS if o.strip()]
if _CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["X-Api-Key", "Content-Type", "X-Request-Id"],
    )

# Allowed directory for SARIF export (restrict file writes)
_SAFE_REPORT_DIR = _HERE / "data" / "reports"


# ---------------------------------------------------------------------------
# API key authentication
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("PENETRATOR_API_KEY", "changeme")


def verify_key(x_api_key: str = Header(...)):
    if not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(403, "Invalid API key")


# ---------------------------------------------------------------------------
# Request-ID middleware — adds X-Request-Id to every response for tracing
# ---------------------------------------------------------------------------
import uuid as _uuid
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers and X-Request-Id to every response."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id", str(_uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(_SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (no extra dependency)
# ---------------------------------------------------------------------------
import asyncio as _asyncio
import time as _time
from collections import defaultdict

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = _asyncio.Lock()
_RATE_LIMIT = int(os.environ.get("PENETRATOR_RATE_LIMIT", "60"))  # req/min
_RATE_WINDOW = 60.0  # seconds
_RATE_MAX_IPS = 10_000  # cap tracked IPs to prevent memory exhaustion


@app.middleware("http")
async def _rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    if not request.client:
        return JSONResponse(status_code=400, content={"detail": "Unknown client"})
    client_ip = request.client.host
    now = _time.time()
    async with _rate_lock:
        # Prune old entries for this IP (only if it exists)
        if client_ip in _rate_store:
            recent = [t for t in _rate_store[client_ip] if now - t < _RATE_WINDOW]
            if recent:
                _rate_store[client_ip] = recent
            else:
                del _rate_store[client_ip]
        # Hard cap on tracked IPs to prevent memory exhaustion via IP cycling
        # Only reject truly NEW IPs — returning IPs were either kept or just pruned above
        if client_ip not in _rate_store and len(_rate_store) >= _RATE_MAX_IPS:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(int(_RATE_WINDOW))},
            )
        if len(_rate_store.get(client_ip, [])) >= _RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(int(_RATE_WINDOW))},
            )
        _rate_store[client_ip].append(now)
    return await call_next(request)


# ---------------------------------------------------------------------------
# Log collector — captures engine log() calls into a list
# ---------------------------------------------------------------------------
class LogCollector:
    def __init__(self):
        self.entries: list[dict] = []

    def __call__(self, msg: str, tag: str = "info"):
        self.entries.append({"msg": msg, "tag": tag})


# ---------------------------------------------------------------------------
# Global exception handlers — wrap errors into clean JSON responses
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


@app.exception_handler(Exception)
async def _global_exception_handler(request, exc):
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    # Don't leak internal details (file paths, SQL errors) to clients
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# ===== SSRF Protection =====================================================
_SSRF_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_internal_target(host: str) -> bool:
    """Return True if the target resolves to an internal/loopback IP."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # It's a hostname — resolve it
        try:
            resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
            ips = {ipaddress.ip_address(r[4][0]) for r in resolved}
        except (socket.gaierror, OSError):
            return False
        return any(
            ip_ in net for ip_ in ips for net in _SSRF_BLOCKED_NETS
        )
    return any(ip in net for net in _SSRF_BLOCKED_NETS)


_SSRF_PROTECTION = os.environ.get("PENETRATOR_SSRF_PROTECTION", "1") not in ("0", "false", "no")


def _check_ssrf(target: str) -> None:
    """Raise HTTPException(400) if target resolves to an internal IP."""
    if not _SSRF_PROTECTION:
        return
    # Extract host from URL or use raw target
    parsed = urlparse(target)
    host = parsed.hostname if parsed.hostname else target.split(":")[0].split("/")[0]
    if _is_internal_target(host):
        raise HTTPException(400, "Target resolves to a private/internal IP. SSRF blocked.")


# ===== Input Validators ====================================================
def _validate_url(v: str) -> str:
    """Ensure URL has a scheme and valid structure."""
    if not v or not v.strip():
        raise ValueError("URL cannot be empty")
    v = v.strip()
    if not v.startswith(("http://", "https://")):
        v = "http://" + v
    parsed = urlparse(v)
    if not parsed.hostname:
        raise ValueError("Invalid URL: no hostname found")
    return v


def _validate_domain(v: str) -> str:
    """Ensure domain is a valid FQDN-like string."""
    if not v or not v.strip():
        raise ValueError("Domain cannot be empty")
    v = v.strip().lower().rstrip(".")
    if len(v) > 253:
        raise ValueError("Domain name too long (max 253 chars)")
    labels = v.split(".")
    if len(labels) < 2:
        raise ValueError("Domain must have at least two labels (e.g. example.com)")
    import re
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"Invalid domain label: '{label}'")
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label):
            raise ValueError(f"Invalid domain label: '{label}'")
    return v


def _validate_ports_str(v: str) -> str:
    """Validate port specification string."""
    v = v.strip().replace(" ", "")
    if not v:
        raise ValueError("Ports string cannot be empty")
    # Check range format
    if "-" in v and "," not in v:
        parts = v.split("-", 1)
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            raise ValueError("Port range must be like '1-1024'")
        lo, hi = int(parts[0]), int(parts[1])
        if lo < 1 or hi > 65535 or lo > hi:
            raise ValueError("Port range must be within 1-65535 and start<=end")
    else:
        # Comma-separated
        for p in v.split(","):
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                raise ValueError(f"Invalid port: {p} (must be 1-65535)")
    return v


# ===== Request / Response models ==========================================

# --- Scan models ---
class PortScanRequest(BaseModel):
    target: str
    ports_str: str  # e.g. "1-1024" or "80,443,8080"

    @field_validator("ports_str")
    @classmethod
    def check_ports(cls, v):
        return _validate_ports_str(v)


class _UrlModel(BaseModel):
    """Base for models with a validated url field."""
    url: str

    @field_validator("url")
    @classmethod
    def check_url(cls, v):
        return _validate_url(v)


class _DomainModel(BaseModel):
    """Base for models with a validated domain field."""
    domain: str

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v):
        return _validate_domain(v)


class TechFingerprintRequest(_UrlModel):
    pass


class SubdomainPermRequest(_DomainModel):
    pass


class CsrfRequest(_UrlModel):
    pass


class CookieAuditRequest(_UrlModel):
    pass


class SstiRequest(_UrlModel):
    param: str


class XssProbeRequest(_UrlModel):
    pass


# --- JWT models ---
class JwtDecodeRequest(BaseModel):
    token: str


class JwtNoneAttackRequest(BaseModel):
    token: str


# --- Tool models ---
class CvssRequest(BaseModel):
    vector: str


class PhishingUrlRequest(_UrlModel):
    pass


# --- Scan models (new) ---
class HeadersRequest(_UrlModel):
    pass


class CorsRequest(_UrlModel):
    pass


class SubdomainFindRequest(_DomainModel):
    threads: int = 50

    @field_validator("threads")
    @classmethod
    def clamp_threads(cls, v):
        return max(1, min(200, v))


class BusterRequest(_UrlModel):
    threads: int = 50

    @field_validator("threads")
    @classmethod
    def clamp_threads(cls, v):
        return max(1, min(200, v))


class WafRequest(_UrlModel):
    pass


class OpenRedirectRequest(_UrlModel):
    pass


class SqliRequest(_UrlModel):
    pass


class SsrfRequest(_UrlModel):
    pass


class LfiRequest(_UrlModel):
    pass


class CrlfRequest(_UrlModel):
    pass


class Oauth2Request(_UrlModel):
    pass


class DnsRebindingRequest(_DomainModel):
    pass


class HttpSmugglingRequest(_UrlModel):
    pass


class PrototypePollutionRequest(_UrlModel):
    pass


class InsecureDeserRequest(_UrlModel):
    pass


# --- JWT models (new) ---
class JwtBruteRequest(BaseModel):
    token: str
    wordlist: list[str] = []


class JwtKeyConfusionRequest(BaseModel):
    token: str
    key_text: str


# --- Tool models (new) ---
class AttackChainRequest(BaseModel):
    target: str
    chain: list[str]


class EncodePayloadRequest(BaseModel):
    text: str


class HashIdentifyRequest(BaseModel):
    hash: str


class PasswordStrengthRequest(BaseModel):
    password: str


class WhoisRequest(_DomainModel):
    pass


class EmailCheckRequest(_DomainModel):
    pass


class ExecutiveReportRequest(BaseModel):
    target: str


# --- Report models ---
class SarifExportRequest(BaseModel):
    findings: list[dict]
    output_path: str


# --- Profile models ---
class ProfileRunRequest(BaseModel):
    name: str
    target: str


# ===== Endpoints ==========================================================

# ---------------------------------------------------------------------------
# Health check (no auth required)
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------
@app.post("/scan/ports")
def scan_ports(req: PortScanRequest, _=Depends(verify_key)):
    _check_ssrf(req.target)
    log = LogCollector()
    try:
        # Parse port range from string like "1-1024" or "80,443"
        parts = req.ports_str.replace(" ", "")
        if "-" in parts and "," not in parts:
            lo, hi = parts.split("-", 1)
            start, end = int(lo), int(hi)
            result = E.scan_ports(req.target, start, end, threads=50, timeout=1.0, log=log)
        else:
            # Comma-separated list — scan only the specified ports
            port_list = sorted({int(p) for p in parts.split(",")})
            # Scan each port individually using range(port, port)
            result = []
            for port in port_list:
                if E.scan_ports(req.target, port, port, threads=1, timeout=1.0, log=log):
                    result.append(port)
        return {"result": result, "log": log.entries}
    except ValueError as exc:
        raise HTTPException(400, f"Invalid port specification: {exc}")
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/tech-fingerprint")
def scan_tech_fingerprint(req: TechFingerprintRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.tech_fingerprint(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/subdomain-perm")
def scan_subdomain_perm(req: SubdomainPermRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.subdomain_permutation(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/csrf")
def scan_csrf(req: CsrfRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.csrf_analyze(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/cookie-audit")
def scan_cookie_audit(req: CookieAuditRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.cookie_audit(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/ssti")
def scan_ssti(req: SstiRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.ssti_scan(req.url, req.param, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/xss-probe")
def scan_xss_probe(req: XssProbeRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.xss_reflected(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/headers")
def scan_headers(req: HeadersRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.check_security_headers(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/cors")
def scan_cors(req: CorsRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.cors_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/subdomains")
def scan_subdomains(req: SubdomainFindRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.find_subdomains(req.domain, req.threads, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/buster")
def scan_buster(req: BusterRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.buster(req.url, E.DEFAULT_WEB_PATHS, req.threads, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/waf")
def scan_waf(req: WafRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.waf_detect(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/open-redirect")
def scan_open_redirect(req: OpenRedirectRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.open_redirect_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/sqli")
def scan_sqli(req: SqliRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.sqli_detect(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/ssrf")
def scan_ssrf(req: SsrfRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.ssrf_scan(req.url, "", log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/lfi")
def scan_lfi(req: LfiRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.lfi_scan(req.url, "", log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/crlf")
def scan_crlf(req: CrlfRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.crlf_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/oauth2")
def scan_oauth2(req: Oauth2Request, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.oauth2_test(req.url, "", log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/dns-rebinding")
def scan_dns_rebinding(req: DnsRebindingRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.dns_rebinding_check(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/http-smuggling")
def scan_http_smuggling(req: HttpSmugglingRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.http_smuggling_detect(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/prototype-pollution")
def scan_prototype_pollution(req: PrototypePollutionRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.prototype_pollution_scan(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/insecure-deser")
def scan_insecure_deser(req: InsecureDeserRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.insecure_deser_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# Async scan endpoints (faster, uses aiohttp when available)
# ---------------------------------------------------------------------------
@app.post("/scan/sqli-async")
def scan_sqli_async(req: SqliRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.sqli_detect_async(req.url, concurrency=30, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/xss-async")
def scan_xss_async(req: XssProbeRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.xss_reflected_async(req.url, concurrency=30, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/cors-async")
def scan_cors_async(req: CorsRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.cors_test_async(req.url, concurrency=10, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/open-redirect-async")
def scan_open_redirect_async(req: OpenRedirectRequest, _=Depends(verify_key)):
    _check_ssrf(req.url)
    log = LogCollector()
    try:
        result = E.open_redirect_test_async(req.url, concurrency=20, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# JWT endpoints
# ---------------------------------------------------------------------------
@app.post("/jwt/decode")
def jwt_decode(req: JwtDecodeRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.jwt_decode(req.token, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/jwt/none-attack")
def jwt_none_attack(req: JwtNoneAttackRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.jwt_none_attack(req.token, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/jwt/brute")
def jwt_brute(req: JwtBruteRequest, _=Depends(verify_key)):
    log = LogCollector()
    wordlist_path = ""
    try:
        # Write the wordlist to a temp file if provided, else use empty path
        if req.wordlist:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
            tmp.write("\n".join(req.wordlist))
            tmp.close()
            wordlist_path = tmp.name
        result = E.jwt_brute(req.token, wordlist_path, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")
    finally:
        if wordlist_path:
            os.unlink(wordlist_path)


@app.post("/jwt/key-confusion")
def jwt_key_confusion(req: JwtKeyConfusionRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.jwt_key_confusion(req.token, req.key_text, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# Tool endpoints
# ---------------------------------------------------------------------------
@app.post("/tools/cvss")
def tools_cvss(req: CvssRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.cvss_calculate(req.vector, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/phishing-url")
def tools_phishing_url(req: PhishingUrlRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.phishing_url_analyze(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/attack-chain")
def tools_attack_chain(req: AttackChainRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.attack_chain(req.target, req.chain, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/auto-correlate")
def tools_auto_correlate(_=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.auto_correlate(log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/executive-report")
def tools_executive_report(req: ExecutiveReportRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.executive_report(req.target, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/encode-payload")
def tools_encode_payload(req: EncodePayloadRequest, _=Depends(verify_key)):
    result = E.encode_payload(req.text)
    return {"result": result}


@app.post("/tools/hash-identify")
def tools_hash_identify(req: HashIdentifyRequest, _=Depends(verify_key)):
    result = E.identify_hash(req.hash)
    return {"result": result}


@app.post("/tools/password-strength")
def tools_password_strength(req: PasswordStrengthRequest, _=Depends(verify_key)):
    result = E.password_strength(req.password)
    return {"result": result}


@app.post("/tools/whois")
def tools_whois(req: WhoisRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.whois_lookup(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/email-check")
def tools_email_check(req: EmailCheckRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.email_security_check(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# Report endpoints
# ---------------------------------------------------------------------------
@app.post("/report/sarif")
def report_sarif(req: SarifExportRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        # Restrict output to safe report directory (prevent arbitrary file write)
        _SAFE_REPORT_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = Path(req.output_path).name  # strip any path traversal
        if not safe_name:
            safe_name = "report.sarif"
        safe_path = str(_SAFE_REPORT_DIR / safe_name)
        result = E.sarif_export(req.findings, safe_path, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# Profile endpoints
# ---------------------------------------------------------------------------
@app.post("/profile/run")
def profile_run(req: ProfileRunRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.run_profile(req.name, req.target, log=log)
        return {"result": result, "log": log.entries}
    except Exception:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# WebSocket — live scan streaming
# ---------------------------------------------------------------------------
import threading as _ws_threading
import queue as _ws_queue


_SCAN_REGISTRY: dict[str, callable] = {
    "ports": lambda p, log: E.scan_ports(p["target"], int(p.get("start", 1)),
                                          int(p.get("end", 1024)),
                                          int(p.get("threads", 50)),
                                          float(p.get("timeout", 1)), log),
    "headers": lambda p, log: E.check_security_headers(p["target"], log),
    "cors": lambda p, log: E.cors_test(p["target"], log),
    "sqli": lambda p, log: E.sqli_detect(p["target"], log),
    "xss": lambda p, log: E.xss_reflected(p["target"], log),
    "subdomains": lambda p, log: E.find_subdomains(p["target"],
                                                     int(p.get("threads", 10)), log),
    "tech": lambda p, log: E.tech_fingerprint(p["target"], log),
    "whois": lambda p, log: E.whois_lookup(p["target"], log),
    "waf": lambda p, log: E.waf_detect(p["target"], log),
}


@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    """Stream scan results in real-time over WebSocket.

    Protocol:
      1. Client sends: {"api_key": "...", "scan": "ports", "params": {"target": "..."}}
      2. Server streams: {"type": "log", "msg": "...", "tag": "..."} for each log line
      3. Server sends:   {"type": "result", "data": ...} when the scan finishes
      4. Server sends:   {"type": "error", "detail": "..."} on failure
      5. Connection closes after the scan completes.
    """
    await ws.accept()
    try:
        payload = await ws.receive_json()
    except Exception:
        await ws.close(code=1008, reason="Invalid JSON")
        return

    key = payload.get("api_key", "")
    if not hmac.compare_digest(key, API_KEY):
        await ws.send_json({"type": "error", "detail": "Invalid API key"})
        await ws.close(code=1008, reason="Unauthorized")
        return

    scan_name = payload.get("scan", "")
    params = payload.get("params", {})

    if scan_name not in _SCAN_REGISTRY:
        await ws.send_json({"type": "error",
                            "detail": f"Unknown scan '{scan_name}'. "
                                      f"Available: {', '.join(sorted(_SCAN_REGISTRY))}"})
        await ws.close(code=1003)
        return

    target = params.get("target", "")
    if target and _SSRF_PROTECTION and _is_internal_target(target):
        await ws.send_json({"type": "error", "detail": "SSRF blocked: internal target"})
        await ws.close(code=1003)
        return

    log_q: _ws_queue.Queue = _ws_queue.Queue()

    def log_callback(msg: str, tag: str = "info"):
        log_q.put({"type": "log", "msg": msg, "tag": tag})

    result_holder: list = []
    error_holder: list = []

    def run_scan():
        try:
            result = _SCAN_REGISTRY[scan_name](params, log_callback)
            result_holder.append(result)
        except Exception as exc:
            error_holder.append(str(exc))
        finally:
            log_q.put(None)

    thread = _ws_threading.Thread(target=run_scan, daemon=True)
    thread.start()

    try:
        while True:
            try:
                item = log_q.get(timeout=0.1)
            except _ws_queue.Empty:
                continue
            if item is None:
                break
            await ws.send_json(item)

        if error_holder:
            await ws.send_json({"type": "error", "detail": error_holder[0]})
        else:
            data = result_holder[0] if result_holder else None
            await ws.send_json({"type": "result", "data": _serialize(data)})
    except WebSocketDisconnect:
        pass
    finally:
        await ws.close()


def _serialize(obj):
    """Make scan results JSON-serializable."""
    if isinstance(obj, (list, tuple)):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return obj
