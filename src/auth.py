import hashlib
import hmac
import re
import time

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from .config import get_settings
from .deps import get_store
from .signing import compute_signature

# auto_error=False: we return our own generic 401. Declaring the scheme gives Swagger its "Authorize" button.
_bearer = HTTPBearer(auto_error=False, bearerFormat="API key",
                     description="Paste your API key (starts with fgk_). Enter it once; Swagger sends it on every request.")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_DUMMY_SECRET = b"\x00" * 32  # unknown clients cost the same work as known ones


def _deny() -> HTTPException:
    # One generic message for every authentication failure: no oracle for attackers.
    return HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})


def _client_for_api_key(presented: str, settings):
    digest = hashlib.sha256(presented.encode()).hexdigest()
    match = None
    for client_id, cfg in settings.clients.items():  # no early exit: same work for every outcome
        if cfg.key_sha256 and hmac.compare_digest(digest, cfg.key_sha256):
            match = client_id
    return match


def _verify_signature(request: Request, body: bytes, settings):
    h = request.headers
    client_id, timestamp = h.get("x-client-id", ""), h.get("x-timestamp", "")
    nonce, signature = h.get("x-nonce", ""), h.get("x-signature", "")
    client = settings.clients.get(client_id)
    secret = client.secret if client and client.secret else _DUMMY_SECRET
    expected = compute_signature(secret, request.method, request.url.path, timestamp, nonce, body)
    signature_ok = hmac.compare_digest(expected.encode(), signature.encode())
    fresh = (timestamp.isascii() and timestamp.isdigit() and len(timestamp) <= 12
             and abs(time.time() - int(timestamp)) <= settings.clock_skew_s)
    if client and client.secret and signature_ok and fresh and _NONCE_RE.match(nonce):
        return client_id, nonce
    return None, None


def require_role(role: str):
    async def dependency(
        request: Request,
        store=Depends(get_store),
        credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    ) -> str:
        settings = get_settings()

        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > settings.max_body_bytes:
            raise HTTPException(status_code=413, detail="Payload too large")
        body = await request.body()
        if len(body) > settings.max_body_bytes:
            raise HTTPException(status_code=413, detail="Payload too large")

        nonce = None
        if settings.auth_mode == "signed":
            client_id, nonce = _verify_signature(request, body, settings)
        elif credentials is not None and credentials.scheme.lower() == "bearer":
            client_id = _client_for_api_key(credentials.credentials, settings)
        else:
            client_id = None
        if client_id is None:
            raise _deny()
        if settings.clients[client_id].role != role:
            raise HTTPException(status_code=403, detail="Forbidden")

        try:
            if nonce is not None:  # signed mode: nonce is recorded only AFTER the signature is proven valid
                if not await run_in_threadpool(store.claim_nonce, f"nonce:{client_id}:{nonce}",
                                               settings.clock_skew_s * 2):
                    raise _deny()  # replay
            calls = await run_in_threadpool(store.hit, f"rate:{client_id}", 60)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=503, detail="Service unavailable")
        if calls > settings.client_rate_limit:
            raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": "60"})
        return client_id

    return dependency