from sqlalchemy import select

from src.database import AuditLogModel, SessionLocal


def tx(**over):
    base = {"account_id": "ACC-1001", "step": 1, "amount": 100.0,
            "oldbalanceOrg": 1000.0, "newbalanceOrig": 900.0,
            "oldbalanceDest": 500.0, "newbalanceDest": 600.0, "type": "TRANSFER"}
    base.update(over)
    return base


def audit_rows():
    with SessionLocal() as db:
        return list(db.scalars(select(AuditLogModel).order_by(AuditLogModel.id)))