import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from .audit import append_audit, pseudonymize
from .auth import require_role
from .config import get_settings
from .database import SimEventModel, check_db, get_db
from .decision import Signals, evaluate
from .deps import get_bundle, get_store
from .model_service import load_verified_bundle
from .schemas import (SIM_EVENT_EXAMPLES, TRANSACTION_EXAMPLES, DecisionResponse,
                      SimEventInput, TransactionInput)
from .signals import recent_sim_change
from .store import build_store

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fraud.gateway")


def log_event(event: str, **details):
    """Structured logs. Only request ids, pseudonyms and decisions - never raw PII."""
    logger.info(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "event": event, **details}))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    check_db()                                                    # DB down  -> refuse to start
    app.state.bundle = load_verified_bundle(settings.models_dir, settings.manifest_key)  # bad model -> refuse
    app.state.store = build_store(settings.redis_url)             # Redis down -> refuse
    log_event("STARTUP_OK", model_sha256=app.state.bundle.model_sha256)
    yield


_settings = get_settings()
app = FastAPI(
    title="Banking Fraud Monitoring Gateway",
    description=("Prototype fraud-decision gateway: ML + rules, tamper-evident audit log.\n\n"
                 "**To test here:** click **Authorize**, paste your API key once, then pick a dummy transaction "
                 "from the *Examples* dropdown on `POST /predict` and press Execute."),
    version="3.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _settings.enable_docs else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_middleware(request, call_next):
    s = get_settings()
    if s.require_https and request.url.path != "/health":
        if request.headers.get("x-forwarded-proto", request.url.scheme) != "https":
            return JSONResponse({"detail": "HTTPS required"}, status_code=400)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    if s.require_https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/audit-logs")
def get_audit_logs(
    client_id: str = Depends(require_role("txn")),
    db: Session = Depends(get_db),
):
    """Fetches persistent audit records from the database for the Bank Fraud Ops dashboard."""
    try:
        rows = db.execute(
            text(
                "SELECT id, request_id, account_hash, transaction_type, amount, "
                "decision, risk_level, decision_source, ml_probability, security_threat, "
                "message, timestamp FROM audit_logs ORDER BY id DESC LIMIT 100"
            )
        ).mappings().all()
        return [
            {
                "audit_id": r["id"],
                "request_id": r["request_id"],
                "account_hash": r["account_hash"],
                "type": r["transaction_type"],
                "amount": float(r["amount"]) if r["amount"] is not None else 0.0,
                "decision": r["decision"],
                "risk_level": r["risk_level"],
                "decision_source": r["decision_source"],
                "fraud_probability": float(r["ml_probability"]) if r["ml_probability"] is not None else 0.0,
                "security_threat": r["security_threat"],
                "reason": r["message"],
                "timestamp": r["timestamp"].isoformat() if hasattr(r["timestamp"], "isoformat") else str(r["timestamp"]),
            }
            for r in rows
        ]
    except Exception:
        logger.exception("Failed to query audit_logs table")
        return []


@app.post("/predict", response_model=DecisionResponse, response_model_exclude_none=True)
def predict(
    tx: TransactionInput = Body(openapi_examples=TRANSACTION_EXAMPLES),
    client_id: str = Depends(require_role("txn")),
    db: Session = Depends(get_db),
    store=Depends(get_store),
    bundle=Depends(get_bundle),
):
    request_id = str(uuid.uuid4())
    s = get_settings()
    try:
        acct = pseudonymize(tx.account_id)
        signals = Signals(
            velocity=store.hit(f"vel:{acct}", s.velocity_window_s),
            cumulative_amount=store.add_amount(f"cum:{acct}", tx.amount, s.cumulative_window_s),
            sim_recently_changed=recent_sim_change(db, acct, s.sim_swap_window_hours),
        )
        ml_p = bundle.score({
            "step": tx.step, "amount": float(tx.amount),
            "oldbalanceOrg": float(tx.oldbalanceOrg), "newbalanceOrig": float(tx.newbalanceOrig),
            "oldbalanceDest": float(tx.oldbalanceDest), "newbalanceDest": float(tx.newbalanceDest),
            "type": tx.type,
        })
        ev = evaluate(tx, signals, ml_p, s)
        entry = append_audit(
            db,
            request_id=request_id, client_id=client_id, account_hash=acct,
            step=tx.step, transaction_type=tx.type, amount=tx.amount,
            old_balance_org=tx.oldbalanceOrg, new_balance_org=tx.newbalanceOrig,
            old_balance_dest=tx.oldbalanceDest, new_balance_dest=tx.newbalanceDest,
            decision=ev.decision, risk_level=ev.risk_level,
            fraud_detected=ev.decision != "APPROVE", decision_source=ev.decision_source,
            ml_probability=Decimal(str(round(ev.ml_probability, 6))),
            ledger_anomaly_detected=ev.ledger_anomaly, security_threat=ev.security_threat,
            message=ev.message, model_sha256=bundle.model_sha256,
        )
    except Exception:
        logger.exception("predict failed request_id=%s", request_id)
        raise HTTPException(status_code=503, detail={"error": "service_unavailable", "request_id": request_id})

    log_event("TRANSACTION_EVALUATED", request_id=request_id, audit_id=entry.id,
              decision=ev.decision, threat=ev.security_threat, source=ev.decision_source)
    out = dict(request_id=request_id, audit_id=entry.id, decision=ev.decision, timestamp=entry.timestamp)
    if s.clients[client_id].verbose:
        out.update(fraud_probability=round(ev.ml_probability, 4), risk_level=ev.risk_level,
                   decision_source=ev.decision_source, security_threat=ev.security_threat, reason=ev.message)
    return DecisionResponse(**out)


@app.post("/telco/sim-events", status_code=201)
def record_sim_event(
    event: SimEventInput = Body(openapi_examples=SIM_EVENT_EXAMPLES),
    client_id: str = Depends(require_role("telco")),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    occurred = (event.occurred_at or now).astimezone(timezone.utc)
    db.add(SimEventModel(account_hash=pseudonymize(event.account_id),
                         event_type=event.event_type, occurred_at=occurred, received_at=now))
    db.commit()
    log_event("SIM_EVENT_RECORDED", client_id=client_id, event_type=event.event_type)
    return {"status": "recorded"}