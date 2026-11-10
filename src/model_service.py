"""Verified model loading + feature building.

Integrity: manifest.json holds the SHA-256 of every artifact and an HMAC over that
list (key = MODEL_MANIFEST_KEY, kept outside the models directory). Files are read
into memory ONCE, verified, and deserialised from those same bytes (no check/use race).
Residual risk: pickle is still code-execution-on-load for anyone holding the manifest
key. Moving to ONNX / skops removes that class of risk.
"""
import hashlib
import hmac
import io
import json
import os

import joblib
import pandas as pd

ARTIFACTS = ("fraud_model.pkl", "scaler.pkl", "feature_columns.pkl")
MANIFEST = "manifest.json"
BASE_FEATURES = {"step", "amount", "oldbalanceOrg", "newbalanceOrig",
                 "oldbalanceDest", "newbalanceDest", "errorBalanceOrig", "errorBalanceDest",
                 "is_transfer"}


class ModelIntegrityError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(files: dict, key: bytes) -> str:
    payload = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def write_manifest(models_dir: str, key: bytes) -> dict:
    """Run once, right after training (scripts/sign_models.py)."""
    files = {}
    for name in ARTIFACTS:
        with open(os.path.join(models_dir, name), "rb") as f:
            files[name] = _sha256(f.read())
    manifest = {"files": files, "signature": _sign(files, key)}
    with open(os.path.join(models_dir, MANIFEST), "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def read_verified_artifacts(models_dir: str, key: bytes) -> dict:
    """Return {name: bytes} only if the signed manifest and every file hash check out."""
    try:
        with open(os.path.join(models_dir, MANIFEST)) as f:
            manifest = json.load(f)
        files, signature = manifest["files"], manifest["signature"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise ModelIntegrityError("Model manifest missing or unreadable") from exc
    if not hmac.compare_digest(_sign(files, key).encode(), str(signature).encode()):
        raise ModelIntegrityError("Model manifest signature invalid")
    if set(files) != set(ARTIFACTS):
        raise ModelIntegrityError("Model manifest does not list the expected artifacts")
    blobs = {}
    for name in ARTIFACTS:
        with open(os.path.join(models_dir, name), "rb") as f:
            data = f.read()
        if not hmac.compare_digest(_sha256(data).encode(), files[name].encode()):
            raise ModelIntegrityError(f"Hash mismatch for {name}: refusing to load")
        blobs[name] = data
    return blobs


class ModelBundle:
    def __init__(self, model, scaler, feature_columns, model_sha256: str):
        unsupported = [c for c in feature_columns if c not in BASE_FEATURES and not c.startswith("type_")]
        if unsupported:  # fail loudly instead of silently zero-filling
            raise ValueError(f"Model expects features the gateway cannot derive: {unsupported}")
        self.model, self.scaler = model, scaler
        self.feature_columns = list(feature_columns)
        self.model_sha256 = model_sha256

    def score(self, tx: dict) -> float:
        """tx: step, amount, balances (floats) and type (str)."""
        row = {}
        for col in self.feature_columns:
            if col.startswith("type_"):
                row[col] = 1.0 if tx["type"] == col[5:].upper() else 0.0
            elif col == "errorBalanceOrig":
                row[col] = tx["newbalanceOrig"] + tx["amount"] - tx["oldbalanceOrg"]
            elif col == "errorBalanceDest":
                row[col] = tx["newbalanceDest"] + tx["amount"] - tx["oldbalanceDest"]
            elif col == "is_transfer":
                row[col] = 1.0 if tx["type"] == "TRANSFER" else 0.0
            else:
                row[col] = tx[col]
        frame = pd.DataFrame([row], columns=self.feature_columns)
        scaled = self.scaler.transform(frame)
        return float(self.model.predict_proba(scaled)[0][1])


def load_verified_bundle(models_dir: str, key: bytes) -> ModelBundle:
    blobs = read_verified_artifacts(models_dir, key)
    return ModelBundle(
        model=joblib.load(io.BytesIO(blobs["fraud_model.pkl"])),
        scaler=joblib.load(io.BytesIO(blobs["scaler.pkl"])),
        feature_columns=joblib.load(io.BytesIO(blobs["feature_columns.pkl"])),
        model_sha256=_sha256(blobs["fraud_model.pkl"]),
    )