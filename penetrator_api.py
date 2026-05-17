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

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from gui import engine as E
from gui.db import init_db


import logging

_logger = logging.getLogger("penetrator")


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
    version="1.8.1",
    description="Penetration testing toolkit API",
    lifespan=lifespan,
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
# Simple in-memory rate limiter (no extra dependency)
# ---------------------------------------------------------------------------
import time as _time
from collections import defaultdict
from fastapi import Request

_rate_store: dict[str, list[float]] = defaultdict(list)
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
    # Prune old entries for this IP
    _rate_store[client_ip] = [
        t for t in _rate_store[client_ip] if now - t < _RATE_WINDOW
    ]
    # Evict key entirely if no recent requests (prevents unbounded growth)
    if not _rate_store[client_ip]:
        del _rate_store[client_ip]
    # Hard cap on tracked IPs to prevent memory exhaustion via IP cycling
    if client_ip not in _rate_store and len(_rate_store) >= _RATE_MAX_IPS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again later."},
            headers={"Retry-After": str(int(_RATE_WINDOW))},
        )
    if len(_rate_store[client_ip]) >= _RATE_LIMIT:
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


# ===== Request / Response models ==========================================

# --- Scan models ---
class PortScanRequest(BaseModel):
    target: str
    ports_str: str  # e.g. "1-1024" or "80,443,8080"


class TechFingerprintRequest(BaseModel):
    url: str


class SubdomainPermRequest(BaseModel):
    domain: str


class CsrfRequest(BaseModel):
    url: str


class CookieAuditRequest(BaseModel):
    url: str


class SstiRequest(BaseModel):
    url: str
    param: str


class XssProbeRequest(BaseModel):
    url: str


# --- JWT models ---
class JwtDecodeRequest(BaseModel):
    token: str


class JwtNoneAttackRequest(BaseModel):
    token: str


# --- Tool models ---
class CvssRequest(BaseModel):
    vector: str


class PhishingUrlRequest(BaseModel):
    url: str


# --- Scan models (new) ---
class HeadersRequest(BaseModel):
    url: str


class CorsRequest(BaseModel):
    url: str


class SubdomainFindRequest(BaseModel):
    domain: str
    threads: int = 50


class BusterRequest(BaseModel):
    url: str
    threads: int = 50


class WafRequest(BaseModel):
    url: str


class OpenRedirectRequest(BaseModel):
    url: str


class SqliRequest(BaseModel):
    url: str


class SsrfRequest(BaseModel):
    url: str


class LfiRequest(BaseModel):
    url: str


class CrlfRequest(BaseModel):
    url: str


class Oauth2Request(BaseModel):
    url: str


class DnsRebindingRequest(BaseModel):
    domain: str


class HttpSmugglingRequest(BaseModel):
    url: str


class PrototypePollutionRequest(BaseModel):
    url: str


class InsecureDeserRequest(BaseModel):
    url: str


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


class WhoisRequest(BaseModel):
    domain: str


class EmailCheckRequest(BaseModel):
    domain: str


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
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/tech-fingerprint")
def scan_tech_fingerprint(req: TechFingerprintRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.tech_fingerprint(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/subdomain-perm")
def scan_subdomain_perm(req: SubdomainPermRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.subdomain_permutation(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/csrf")
def scan_csrf(req: CsrfRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.csrf_analyze(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/cookie-audit")
def scan_cookie_audit(req: CookieAuditRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.cookie_audit(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/ssti")
def scan_ssti(req: SstiRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.ssti_scan(req.url, req.param, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/xss-probe")
def scan_xss_probe(req: XssProbeRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.xss_reflected(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/headers")
def scan_headers(req: HeadersRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.check_security_headers(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/cors")
def scan_cors(req: CorsRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.cors_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/subdomains")
def scan_subdomains(req: SubdomainFindRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.find_subdomains(req.domain, req.threads, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/buster")
def scan_buster(req: BusterRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.buster(req.url, E.DEFAULT_WEB_PATHS, req.threads, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/waf")
def scan_waf(req: WafRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.waf_detect(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/open-redirect")
def scan_open_redirect(req: OpenRedirectRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.open_redirect_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/sqli")
def scan_sqli(req: SqliRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.sqli_detect(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/ssrf")
def scan_ssrf(req: SsrfRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.ssrf_scan(req.url, "", log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/lfi")
def scan_lfi(req: LfiRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.lfi_scan(req.url, "", log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/crlf")
def scan_crlf(req: CrlfRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.crlf_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/oauth2")
def scan_oauth2(req: Oauth2Request, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.oauth2_test(req.url, "", log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/dns-rebinding")
def scan_dns_rebinding(req: DnsRebindingRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.dns_rebinding_check(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/http-smuggling")
def scan_http_smuggling(req: HttpSmugglingRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.http_smuggling_detect(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/prototype-pollution")
def scan_prototype_pollution(req: PrototypePollutionRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.prototype_pollution_scan(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/insecure-deser")
def scan_insecure_deser(req: InsecureDeserRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.insecure_deser_test(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


# ---------------------------------------------------------------------------
# Async scan endpoints (faster, uses aiohttp when available)
# ---------------------------------------------------------------------------
@app.post("/scan/sqli-async")
def scan_sqli_async(req: SqliRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.sqli_detect_async(req.url, concurrency=30, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/xss-async")
def scan_xss_async(req: XssProbeRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.xss_reflected_async(req.url, concurrency=30, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/cors-async")
def scan_cors_async(req: CorsRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.cors_test_async(req.url, concurrency=10, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/scan/open-redirect-async")
def scan_open_redirect_async(req: OpenRedirectRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.open_redirect_test_async(req.url, concurrency=20, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
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
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/jwt/none-attack")
def jwt_none_attack(req: JwtNoneAttackRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.jwt_none_attack(req.token, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
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
    except Exception as exc:
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
    except Exception as exc:
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
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/phishing-url")
def tools_phishing_url(req: PhishingUrlRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.phishing_url_analyze(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/attack-chain")
def tools_attack_chain(req: AttackChainRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.attack_chain(req.target, req.chain, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/auto-correlate")
def tools_auto_correlate(_=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.auto_correlate(log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/executive-report")
def tools_executive_report(req: ExecutiveReportRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.executive_report(req.target, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
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
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")


@app.post("/tools/email-check")
def tools_email_check(req: EmailCheckRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.email_security_check(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
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
    except Exception as exc:
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
    except Exception as exc:
        _logger.exception("Endpoint error")
        raise HTTPException(500, "Scan failed")
