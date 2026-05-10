"""PENETRATOR REST API — headless interface to the engine.

Run: uvicorn penetrator_api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root to path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from gui import engine as E
from gui.db import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="PENETRATOR API",
    version="1.7.0",
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
    if x_api_key != API_KEY:
        raise HTTPException(403, "Invalid API key")


# ---------------------------------------------------------------------------
# Log collector — captures engine log() calls into a list
# ---------------------------------------------------------------------------
class LogCollector:
    def __init__(self):
        self.entries: list[dict] = []

    def __call__(self, msg: str, tag: str = "info"):
        self.entries.append({"msg": msg, "tag": tag})


# ---------------------------------------------------------------------------
# Global exception handler — wrap engine errors into clean JSON responses
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exception_handler(request, exc):
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "type": type(exc).__name__},
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
            # Comma-separated list — scan min..max then filter to requested
            port_list = sorted({int(p) for p in parts.split(",")})
            start, end = min(port_list), max(port_list)
            all_open = E.scan_ports(req.target, start, end, threads=50, timeout=1.0, log=log)
            result = [p for p in all_open if p in port_list]
        return {"result": result, "log": log.entries}
    except ValueError as exc:
        raise HTTPException(400, f"Invalid port specification: {exc}")
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/scan/tech-fingerprint")
def scan_tech_fingerprint(req: TechFingerprintRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.tech_fingerprint(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/scan/subdomain-perm")
def scan_subdomain_perm(req: SubdomainPermRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.subdomain_permutation(req.domain, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/scan/csrf")
def scan_csrf(req: CsrfRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.csrf_analyze(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/scan/cookie-audit")
def scan_cookie_audit(req: CookieAuditRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.cookie_audit(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/scan/ssti")
def scan_ssti(req: SstiRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.ssti_scan(req.url, req.param, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/scan/xss-probe")
def scan_xss_probe(req: XssProbeRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.xss_reflected(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


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
        raise HTTPException(500, str(exc))


@app.post("/jwt/none-attack")
def jwt_none_attack(req: JwtNoneAttackRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.jwt_none_attack(req.token, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


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
        raise HTTPException(500, str(exc))


@app.post("/tools/phishing-url")
def tools_phishing_url(req: PhishingUrlRequest, _=Depends(verify_key)):
    log = LogCollector()
    try:
        result = E.phishing_url_analyze(req.url, log=log)
        return {"result": result, "log": log.entries}
    except Exception as exc:
        raise HTTPException(500, str(exc))


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
        raise HTTPException(500, str(exc))


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
        raise HTTPException(500, str(exc))
