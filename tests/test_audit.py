import hashlib
import json

import pytest
from sqlalchemy import text

from src.audit import check_anchor, verify_chain, write_anchor
from src.database import SessionLocal, engine
from tests.helpers import audit_rows, tx


def _fill(api, n=5):
    for i in range(n):
        assert api.post("/predict", tx(step=i + 1, account_id=f"ACC-{i:04d}")).status_code == 200


def _verify():
    with SessionLocal() as db:
        return verify_chain(db)


def test_chain_valid_and_linked(api):
    _fill(api)
    res = _verify()
    assert res.ok and res.checked == 5
    rows = audit_rows()
    assert rows[0].previous_row_hash == "GENESIS"
    assert all(rows[i].previous_row_hash == rows[i - 1].row_hash for i in range(1, 5))


@pytest.mark.parametrize("column,value", [
    ("amount", "1"), ("message", "'edited'"), ("decision", "'BLOCK'"),
    ("ml_probability", "0.5"), ("old_balance_dest", "7"), ("client_id", "'attacker'"),
    ("timestamp", "'2020-01-01 00:00:00'"), ("security_threat", "'Forged'"),
])
def test_edit_of_any_field_is_detected(api, column, value):
    _fill(api)
    with engine.begin() as c:
        c.execute(text(f"UPDATE audit_logs SET {column} = {value} WHERE id = 3"))
    res = _verify()
    assert not res.ok and res.bad_id == 3


def test_middle_row_deletion_detected(api):
    _fill(api)
    with engine.begin() as c:
        c.execute(text("DELETE FROM audit_logs WHERE id = 3"))
    res = _verify()
    assert not res.ok and res.bad_id == 4


def test_attacker_without_key_cannot_recompute_chain(api):
    _fill(api)
    with engine.begin() as c:  # edit row 2, then "fix" its hash with plain SHA-256
        c.execute(text("UPDATE audit_logs SET amount = 1 WHERE id = 2"))
        forged = hashlib.sha256(json.dumps({"x": 1}).encode()).hexdigest()
        c.execute(text("UPDATE audit_logs SET row_hash = :h WHERE id = 2"), {"h": forged})
    res = _verify()
    assert not res.ok and res.bad_id == 2


def test_tail_truncation_caught_by_anchor(api, tmp_path):
    _fill(api)
    anchor = str(tmp_path / "anchor.json")
    with SessionLocal() as db:
        write_anchor(anchor, verify_chain(db))
        assert check_anchor(db, anchor)[0]
    with engine.begin() as c:
        c.execute(text("DELETE FROM audit_logs WHERE id = 5"))
    assert _verify().ok  # chain alone cannot see tail truncation...
    with SessionLocal() as db:
        ok, why = check_anchor(db, anchor)
    assert not ok and "missing" in why  # ...the external anchor can


def test_no_pii_in_audit_row(api):
    api.post("/predict", tx(account_id="ACC-SECRET-77"))
    row = audit_rows()[-1]
    assert "ACC-SECRET-77" not in json.dumps({c.name: str(getattr(row, c.name)) for c in row.__table__.columns})