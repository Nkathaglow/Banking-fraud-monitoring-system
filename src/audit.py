import hashlib
import hmac
import json
import threading
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import select, text

from .config import get_settings
from .database import AuditLogModel

GENESIS = "GENESIS"
_ADVISORY_LOCK_KEY = 727001
_local_lock = threading.Lock()  # used only for non-PostgreSQL (tests)

HASHED_FIELDS = (
    "timestamp", "request_id", "client_id", "account_hash", "step", "transaction_type",
    "amount", "old_balance_org", "new_balance_org", "old_balance_dest", "new_balance_dest",
    "decision", "risk_level", "fraud_detected", "decision_source", "ml_probability",
    "ledger_anomaly_detected", "security_threat", "message", "model_sha256",
)
_QUANT = {
    "amount": Decimal("0.01"), "old_balance_org": Decimal("0.01"), "new_balance_org": Decimal("0.01"),
    "old_balance_dest": Decimal("0.01"), "new_balance_dest": Decimal("0.01"),
    "ml_probability": Decimal("0.000001"),
}


def _norm(field: str, value):
    """Canonical form so insert-time and verify-time serialisation are identical."""
    if value is None:
        return None
    if field == "timestamp":
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if field in _QUANT:
        return str(Decimal(str(value)).quantize(_QUANT[field]))
    return value


def canonical_json(row) -> str:
    data = {f: _norm(f, getattr(row, f)) for f in HASHED_FIELDS}
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def chain_hash(row, prev_hash: str) -> str:
    key = get_settings().audit_key
    return hmac.new(key, f"{prev_hash}|{canonical_json(row)}".encode(), hashlib.sha256).hexdigest()


def pseudonymize(account_id: str) -> str:
    """Keyed hash so raw account identifiers never reach logs, Redis or the audit table."""
    return hmac.new(get_settings().audit_key, b"acct:" + account_id.encode(), hashlib.sha256).hexdigest()[:32]


def append_audit(db, **fields) -> AuditLogModel:
    """Insert one chained row and commit. On PostgreSQL a transaction-scoped advisory
    lock serialises writers so concurrent requests cannot fork the chain."""
    is_pg = db.get_bind().dialect.name == "postgresql"
    with (nullcontext() if is_pg else _local_lock):
        try:
            if is_pg:
                db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
            last = db.execute(
                select(AuditLogModel.row_hash).order_by(AuditLogModel.id.desc()).limit(1)
            ).scalar_one_or_none()
            prev = last or GENESIS
            entry = AuditLogModel(timestamp=datetime.now(timezone.utc),
                                  previous_row_hash=prev, row_hash="", **fields)
            entry.row_hash = chain_hash(entry, prev)
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry
        except Exception:
            db.rollback()
            raise


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    head_id: int | None
    head_hash: str | None
    bad_id: int | None = None
    error: str | None = None


def verify_chain(db, batch: int = 1000) -> VerifyResult:
    key = get_settings().audit_key  # noqa: F841 (fails early if key missing)
    prev, checked, head_id = GENESIS, 0, None
    rows = db.scalars(select(AuditLogModel).order_by(AuditLogModel.id).execution_options(yield_per=batch))
    for row in rows:
        if row.previous_row_hash != prev:
            return VerifyResult(False, checked, head_id, prev, row.id,
                                "previous_row_hash does not match preceding row (row deleted, inserted or reordered)")
        expected = chain_hash(row, prev)
        if not hmac.compare_digest(expected.encode(), row.row_hash.encode()):
            return VerifyResult(False, checked, head_id, prev, row.id, "row content does not match its row_hash")
        prev, checked, head_id = row.row_hash, checked + 1, row.id
    return VerifyResult(True, checked, head_id, prev if checked else None)


def write_anchor(path: str, result: VerifyResult) -> None:
    """Record the chain head. Keep this file OFF the database host (email it, commit it
    elsewhere, ship it to object storage) - it is what makes tail-truncation detectable."""
    with open(path, "w") as f:
        json.dump({"head_id": result.head_id, "head_hash": result.head_hash,
                   "written_at": datetime.now(timezone.utc).isoformat()}, f)


def check_anchor(db, path: str) -> tuple[bool, str]:
    with open(path) as f:
        anchor = json.load(f)
    if anchor["head_id"] is None:
        return True, "anchor was taken on an empty log"
    row = db.get(AuditLogModel, anchor["head_id"])
    if row is None:
        return False, f"anchored row id={anchor['head_id']} is missing (log truncated?)"
    if not hmac.compare_digest(row.row_hash.encode(), anchor["head_hash"].encode()):
        return False, f"anchored row id={anchor['head_id']} has a different hash (history rewritten)"
    return True, "anchored head still present and unchanged"