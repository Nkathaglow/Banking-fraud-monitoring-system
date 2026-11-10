import json
import os
import re
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache

ROLES = frozenset({"txn", "telco"})
AUTH_MODES = frozenset({"apikey", "signed"})
MIN_SECRET_LEN = 32
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ClientConfig:
    role: str
    key_sha256: str | None = None   # AUTH_MODE=apikey: SHA-256 of the client's API key (the key itself is never stored)
    secret: bytes | None = None     # AUTH_MODE=signed: shared HMAC secret
    verbose: bool = False           # True = response includes score and reason (developer / sandbox clients only)


@dataclass(frozen=True)
class Settings:
    database_url: str
    audit_key: bytes
    manifest_key: bytes
    auth_mode: str
    clients: dict
    models_dir: str
    redis_url: str | None
    enable_docs: bool
    require_https: bool
    client_rate_limit: int
    velocity_limit: int
    velocity_window_s: int
    sim_swap_window_hours: int
    sim_swap_amount: Decimal
    cumulative_limit: Decimal
    cumulative_window_s: int
    review_threshold: float
    block_threshold: float
    max_body_bytes: int
    clock_skew_s: int


def _require(name: str, min_len: int = 1) -> str:
    value = os.environ.get(name, "")
    if len(value) < min_len:
        raise RuntimeError(f"Missing or too-short environment variable {name} (min {min_len} chars)")
    return value


def _flag(name: str) -> bool:
    return os.environ.get(name, "false").lower() == "true"


def _parse_clients(raw: str, auth_mode: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GATEWAY_CLIENTS must be valid JSON") from exc
    clients = {}
    for client_id, cfg in data.items():
        role = cfg.get("role", "")
        key_sha256, secret = cfg.get("key_sha256"), cfg.get("secret")
        if role not in ROLES:
            raise RuntimeError(f"Client '{client_id}' has invalid role '{role}' (allowed: {sorted(ROLES)})")
        if key_sha256 is not None and not _SHA256_HEX.match(key_sha256):
            raise RuntimeError(f"Client '{client_id}': key_sha256 must be 64 lowercase hex characters")
        if secret is not None and len(secret) < MIN_SECRET_LEN:
            raise RuntimeError(f"Client '{client_id}': secret must be >= {MIN_SECRET_LEN} chars")
        if auth_mode == "apikey" and not key_sha256:
            raise RuntimeError(f"Client '{client_id}' has no key_sha256. Create one with: "
                               f"python3 -m scripts.create_client {client_id} --role {role} --add-to-env .env")
        if auth_mode == "signed" and not secret:
            raise RuntimeError(f"Client '{client_id}' has no signing secret (AUTH_MODE=signed). "
                               f"Add one with: python3 -m scripts.create_client {client_id} --role {role} "
                               f"--with-signing-secret --add-to-env .env")
        clients[client_id] = ClientConfig(role=role, key_sha256=key_sha256,
                                          secret=secret.encode() if secret else None,
                                          verbose=bool(cfg.get("verbose", False)))
    if not clients:
        raise RuntimeError("GATEWAY_CLIENTS defines no clients. Create one with: "
                           "python3 -m scripts.create_client mobile-app --role txn --add-to-env .env")
    return clients


@lru_cache
def get_settings() -> Settings:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    auth_mode = os.environ.get("AUTH_MODE", "apikey")
    if auth_mode not in AUTH_MODES:
        raise RuntimeError(f"AUTH_MODE must be one of {sorted(AUTH_MODES)}")
    s = Settings(
        database_url=_require("DATABASE_URL"),
        audit_key=_require("AUDIT_HMAC_KEY", MIN_SECRET_LEN).encode(),
        manifest_key=_require("MODEL_MANIFEST_KEY", MIN_SECRET_LEN).encode(),
        auth_mode=auth_mode,
        clients=_parse_clients(os.environ.get("GATEWAY_CLIENTS", ""), auth_mode),
        models_dir=os.environ.get("MODELS_DIR", os.path.join(base_dir, "models")),
        redis_url=os.environ.get("REDIS_URL") or None,
        enable_docs=_flag("ENABLE_DOCS"),
        require_https=_flag("REQUIRE_HTTPS"),
        client_rate_limit=int(os.environ.get("CLIENT_RATE_LIMIT", "600")),
        velocity_limit=int(os.environ.get("VELOCITY_LIMIT", "10")),
        velocity_window_s=int(os.environ.get("VELOCITY_WINDOW_S", "60")),
        sim_swap_window_hours=int(os.environ.get("SIM_SWAP_WINDOW_HOURS", "24")),
        sim_swap_amount=Decimal(os.environ.get("SIM_SWAP_AMOUNT", "50000")),
        cumulative_limit=Decimal(os.environ.get("CUMULATIVE_LIMIT", "200000")),
        cumulative_window_s=int(os.environ.get("CUMULATIVE_WINDOW_S", "86400")),
        review_threshold=float(os.environ.get("REVIEW_THRESHOLD", "0.30")),
        block_threshold=float(os.environ.get("BLOCK_THRESHOLD", "0.80")),
        max_body_bytes=int(os.environ.get("MAX_BODY_BYTES", "16384")),
        clock_skew_s=int(os.environ.get("CLOCK_SKEW_S", "300")),
    )
    if not 0 < s.review_threshold < s.block_threshold <= 1:
        raise RuntimeError("Require 0 < REVIEW_THRESHOLD < BLOCK_THRESHOLD <= 1")
    return s