from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, select

from .database import SimEventModel


def recent_sim_change(db, account_hash: str, window_hours: int) -> bool:
    """Server-side SIM-swap signal from the (simulated) telco feed."""
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    stmt = select(exists().where(SimEventModel.account_hash == account_hash,
                                 SimEventModel.occurred_at >= since))
    return bool(db.execute(stmt).scalar())