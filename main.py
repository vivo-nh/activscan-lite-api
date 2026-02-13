import os
import re
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr
from publicsuffix2 import get_sld

from scanner import run_scan, normalize_domain
from store import init_db, upsert_otp, verify_otp, create_session, validate_session, ratelimit_hit
from emailer import send_otp_email

app = FastAPI()

API_KEY = os.getenv("ACTIVSCAN_API_KEY", "").strip() or "dev-change-me"
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "600"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))
RATE_WINDOW_SECONDS = int(os.getenv("RATE_WINDOW_SECONDS", "60"))
RATE_MAX_REQUESTS = int(os.getenv("RATE_MAX_REQUESTS", "10"))

init_db()

def _auth(req: Request):
    auth = req.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    token = auth.split(" ", 1)[1].strip()
    if token != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")

def _client_key(req: Request, suffix: str):
    ip = req.client.host if req.client else "unknown"
    return f"{suffix}:{ip}"

def _registrable(domain: str) -> str:
    sld = get_sld(domain)
    if not sld:
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain
    return sld

def _permission_check(email: str, target_domain: str) -> None:
    email_domain = email.split("@", 1)[1].lower().strip(".")
    if _registrable(email_domain) != _registrable(target_domain):
        raise HTTPException(status_code=403, detail="email_domain_mismatch")

class OtpRequest(BaseModel):
    email: EmailStr
    target: str

class OtpVerify(BaseModel):
    email: EmailStr
    target: str
    code: str

class ScanRequest(BaseModel):
    email: EmailStr
    target: str
    session_token: str

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/otp/request")
async def otp_request(req: Request, payload: OtpRequest):
    _auth(req)

    if ratelimit_hit(_client_key(req, "otp_request"), RATE_WINDOW_SECONDS, RATE_MAX_REQUESTS):
        raise HTTPException(status_code=429, detail="rate_limited")

    target_domain = normalize_domain(payload.target)
    _permission_check(payload.email, target_domain)

    import secrets
    code = f"{secrets.randbelow(1000000):06d}"

    upsert_otp(payload.email.lower(), target_domain, code, ttl_seconds=OTP_TTL_SECONDS)

    try:
        send_otp_email(payload.email, code, target_domain)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"sent": True, "expires_in_seconds": OTP_TTL_SECONDS}

@app.post("/otp/verify")
async def otp_verify(req: Request, payload: OtpVerify):
    _auth(req)

    if ratelimit_hit(_client_key(req, "otp_verify"), RATE_WINDOW_SECONDS, RATE_MAX_REQUESTS):
        raise HTTPException(status_code=429, detail="rate_limited")

    target_domain = normalize_domain(payload.target)
    _permission_check(payload.email, target_domain)

    code = (payload.code or "").strip()
    if not re.match(r"^\d{6}$", code):
        raise HTTPException(status_code=400, detail="invalid_code_format")

    ok = verify_otp(payload.email.lower(), target_domain, code)
    if not ok:
        raise HTTPException(status_code=400, detail="invalid_or_expired_code")

    token = create_session(payload.email.lower(), target_domain, ttl_seconds=SESSION_TTL_SECONDS)
    return {"verified": True, "session_token": token, "expires_in_seconds": SESSION_TTL_SECONDS}

@app.post("/scan")
async def scan(req: Request, payload: ScanRequest):
    _auth(req)

    if ratelimit_hit(_client_key(req, "scan"), RATE_WINDOW_SECONDS, RATE_MAX_REQUESTS):
        raise HTTPException(status_code=429, detail="rate_limited")

    target_domain = normalize_domain(payload.target)
    _permission_check(payload.email, target_domain)

    token = (payload.session_token or "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing_session_token")

    if not validate_session(token, payload.email.lower(), target_domain):
        raise HTTPException(status_code=401, detail="invalid_or_expired_session")

    try:
        result = run_scan(target_domain)
        return {"target": target_domain, "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="scan_failed")
