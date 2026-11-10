import hashlib
import json
from decimal import Decimal as D
from types import SimpleNamespace

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from src.decision import ledger_violations
from src.model_service import (ARTIFACTS, ModelBundle, ModelIntegrityError,
                               read_verified_artifacts, write_manifest)

KEY = b"k" * 48


@pytest.fixture
def models(tmp_path):
    for name in ARTIFACTS:
        (tmp_path / name).write_bytes(name.encode() * 10)
    write_manifest(str(tmp_path), KEY)
    return tmp_path


def test_valid_manifest_loads(models):
    assert set(read_verified_artifacts(str(models), KEY)) == set(ARTIFACTS)


def test_swapped_model_file_refused(models):
    (models / "fraud_model.pkl").write_bytes(b"malicious pickle")
    with pytest.raises(ModelIntegrityError, match="Hash mismatch"):
        read_verified_artifacts(str(models), KEY)


def test_manifest_rewritten_by_attacker_refused(models):
    (models / "fraud_model.pkl").write_bytes(b"malicious pickle")
    m = json.loads((models / "manifest.json").read_text())
    m["files"]["fraud_model.pkl"] = hashlib.sha256(b"malicious pickle").hexdigest()  # attacker fixes the hash...
    (models / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(ModelIntegrityError, match="signature"):                      # ...but cannot forge the HMAC
        read_verified_artifacts(str(models), KEY)


def test_wrong_key_and_missing_manifest_refused(models, tmp_path_factory):
    with pytest.raises(ModelIntegrityError):
        read_verified_artifacts(str(models), b"w" * 48)
    with pytest.raises(ModelIntegrityError):
        read_verified_artifacts(str(tmp_path_factory.mktemp("empty")), KEY)


def test_bundle_scores_with_real_sklearn_objects():
    cols = ["step", "amount", "oldbalanceOrg", "newbalanceOrig", "oldbalanceDest", "newbalanceDest",
            "errorBalanceOrig", "errorBalanceDest", "type_TRANSFER", "type_PAYMENT"]
    rng = np.random.default_rng(0)
    X = rng.random((200, len(cols)))
    y = (X[:, 1] > 0.8).astype(int)
    scaler = StandardScaler().fit(X)
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(scaler.transform(X), y)
    bundle = ModelBundle(model, scaler, cols, "0" * 64)
    p = bundle.score({"step": 1, "amount": 10.0, "oldbalanceOrg": 100.0, "newbalanceOrig": 90.0,
                      "oldbalanceDest": 0.0, "newbalanceDest": 10.0, "type": "TRANSFER"})
    assert 0.0 <= p <= 1.0


def test_unknown_model_feature_fails_loudly():
    with pytest.raises(ValueError, match="cannot derive"):
        ModelBundle(None, None, ["step", "mystery_feature"], "0" * 64)


def test_cash_in_ledger_direction():
    ok = SimpleNamespace(type="CASH_IN", amount=D("50"), oldbalanceOrg=D("100"), newbalanceOrig=D("150"),
                         oldbalanceDest=D("0"), newbalanceDest=D("0"))
    bad = SimpleNamespace(**{**ok.__dict__, "newbalanceOrig": D("50")})
    assert ledger_violations(ok) == [] and ledger_violations(bad) == ["origin"]