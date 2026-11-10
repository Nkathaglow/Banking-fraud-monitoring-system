from datetime import datetime, timezone

from sqlalchemy import (Boolean, Column, DateTime, Integer, Numeric, String,
                        create_engine, text)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings


def _make_engine(url: str):
    if url.startswith("sqlite"):  # tests only
        return create_engine(url, connect_args={"check_same_thread": False},
                             poolclass=StaticPool, hide_parameters=True)
    # hide_parameters keeps bound values out of exception messages/logs
    return create_engine(url, pool_pre_ping=True, hide_parameters=True)


engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _utcnow():
    return datetime.now(timezone.utc)


class AuditLogModel(Base):
    """Append-only, HMAC hash-chained decision log. Every column except id and the
    two hash columns is covered by row_hash (see src/audit.py)."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    request_id = Column(String(36), nullable=False, unique=True)
    client_id = Column(String(64), nullable=False)
    account_hash = Column(String(64), nullable=False, index=True)  # pseudonymised, never the raw account id
    step = Column(Integer, nullable=False)
    transaction_type = Column(String(20), nullable=False)
    amount = Column(Numeric(18, 2), nullable=False)
    old_balance_org = Column(Numeric(18, 2), nullable=False)
    new_balance_org = Column(Numeric(18, 2), nullable=False)
    old_balance_dest = Column(Numeric(18, 2), nullable=False)
    new_balance_dest = Column(Numeric(18, 2), nullable=False)
    decision = Column(String(10), nullable=False, index=True)       # APPROVE | REVIEW | BLOCK
    risk_level = Column(String(10), nullable=False)
    fraud_detected = Column(Boolean, nullable=False)
    decision_source = Column(String(10), nullable=False)            # RULE | ML | RULE+ML
    ml_probability = Column(Numeric(8, 6), nullable=True)           # real model score only, never a placeholder
    ledger_anomaly_detected = Column(Boolean, nullable=False)
    security_threat = Column(String(64), nullable=False, index=True)
    message = Column(String(255), nullable=False)
    model_sha256 = Column(String(64), nullable=False)
    previous_row_hash = Column(String(64), nullable=False)
    row_hash = Column(String(64), nullable=False, unique=True)


class SimEventModel(Base):
    """Simulated telco feed: SIM-swap / device-change events per (pseudonymised) account."""
    __tablename__ = "sim_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_hash = Column(String(64), nullable=False, index=True)
    event_type = Column(String(20), nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False, index=True)
    received_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


APPEND_ONLY_DDL = [
    """CREATE OR REPLACE FUNCTION audit_logs_forbid_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs",
    """CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION audit_logs_forbid_mutation()""",
    "DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs",
    """CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_forbid_mutation()""",
]


def init_db():
    """Create tables (+ append-only triggers on PostgreSQL). Run with the OWNER role
    via `python -m scripts.init_db`, not with the restricted runtime role."""
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            for stmt in APPEND_ONLY_DDL:
                conn.exec_driver_sql(stmt)


def check_db():
    """Fail fast at startup if the database is unreachable."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()