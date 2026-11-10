"""HMAC request signing shared by the server (verification) and clients (signing).

signature = HMAC-SHA256(secret, METHOD \\n PATH \\n TIMESTAMP \\n NONCE \\n SHA256(body))
Binding method, path, timestamp, nonce and body means a captured request cannot be
modified, redirected to another endpoint, or replayed (timestamp window + one-time nonce).
"""
import hashlib
import hmac
import secrets
import time


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def compute_signature(secret: bytes, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    message = "\n".join([method.upper(), path, timestamp, nonce, body_digest(body)]).encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def sign_headers(client_id: str, secret, method: str, path: str, body: bytes,
                 timestamp: str | None = None, nonce: str | None = None) -> dict:
    secret_b = secret.encode() if isinstance(secret, str) else secret
    timestamp = timestamp if timestamp is not None else str(int(time.time()))
    nonce = nonce if nonce is not None else secrets.token_hex(16)
    return {
        "X-Client-Id": client_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": compute_signature(secret_b, method, path, timestamp, nonce, body),
    }