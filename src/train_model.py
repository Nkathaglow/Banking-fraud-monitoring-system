import argparse
import json
import time
from pathlib import Path
 
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
 
from features import FEATURE_COLUMNS, build_features
 
RANDOM_STATE = 42
BASE_DIR = Path(__file__).resolve().parent.parent
 
 
def load_and_sample(path: Path, sample_size: int) -> pd.DataFrame:
    """Keep only TRANSFER/CASH_OUT rows, then draw a stratified sample."""
    df = pd.read_csv(path)
    df = df[df["type"].isin(["TRANSFER", "CASH_OUT"])].copy()
    print(f"TRANSFER + CASH_OUT rows: {len(df):,} | frauds: {int(df['isFraud'].sum()):,} "
          f"({df['isFraud'].mean():.4%})")
 
    if sample_size and sample_size < len(df):
        df, _ = train_test_split(
            df, train_size=sample_size, stratify=df["isFraud"], random_state=RANDOM_STATE
        )
        print(f"Stratified sample: {len(df):,} rows | frauds: {int(df['isFraud'].sum()):,}")
    return df
 
 
def evaluate(name, model, X_test, y_test):
    """Return metrics for one model on the held-out test set."""
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
 
    # Single-transaction latency (measured with n_jobs=1 for fair inference comparison)
    if hasattr(model, "n_jobs"):
        original_n_jobs = getattr(model, "n_jobs", None)
        model.n_jobs = 1

    n = min(200, len(X_test))
    start = time.perf_counter()
    for i in range(n):
        model.predict_proba(X_test[i:i + 1])
    latency_ms = (time.perf_counter() - start) / n * 1000

    # Restore n_jobs if applicable
    if hasattr(model, "n_jobs") and original_n_jobs is not None:
        model.n_jobs = original_n_jobs
 
    print(f"\n===== {name} =====")
    print(classification_report(y_test, pred, digits=4, zero_division=0))
    print(f"Confusion matrix  TN={tn} FP={fp} FN={fn} TP={tp}")
 
    return {
        "model": name,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0,
        "roc_auc": roc_auc_score(y_test, proba),
        "pr_auc": average_precision_score(y_test, proba),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "latency_ms_per_request": latency_ms,
        "trained_model_object": model  # Kept temporarily to extract the winner
    }
 
 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(BASE_DIR / "data" / "transactions.csv"))
    parser.add_argument("--sample", type=int, default=500_000,
                        help="rows to sample (0 = use all)")
    args = parser.parse_args()
 
    # 1. Load + sample ---------------------------------------------------------
    df = load_and_sample(Path(args.data), args.sample)
    X = build_features(df)
    y = df["isFraud"].astype(int)
 
    # 2. Stratified train/test split (before scaling, to avoid leakage) ----------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
 
    # 3. Scale: fit on TRAIN only ------------------------------------------------
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
 
    # 4. Class-imbalance handling -----------------------------------------------
    neg, pos = int((y_train == 0).sum()), int((y_train == 1).sum())
    scale_pos_weight = neg / pos
    print(f"\nTrain: {neg:,} legit / {pos:,} fraud | scale_pos_weight = {scale_pos_weight:.1f}")
 
    # 5. Models -------------------------------------------------------------------
    rf = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="aucpr",
        tree_method="hist",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
        weights=[1, 1],
    )
 
    # 6. Train + evaluate all three on the SAME split -----------------------------
    results_raw = []
    for name, model in [("RandomForest", rf), ("XGBoost", xgb), ("Ensemble (soft voting)", ensemble)]:
        t0 = time.perf_counter()
        model.fit(X_train_s, y_train)
        print(f"\nTrained {name} in {time.perf_counter() - t0:.1f}s")
        results_raw.append(evaluate(name, model, X_test_s, y_test))
 
    # Identify the best model based on PR-AUC
    best_result = max(results_raw, key=lambda x: x["pr_auc"])
    best_model_name = best_result["model"]
    best_model_obj = best_result["trained_model_object"]
    print(f"\n🏆 Best Model Selected for Production: {best_model_name} (PR-AUC: {best_result['pr_auc']:.4f})")

    # Clean results for export (remove raw python objects from dict)
    results_export = []
    for r in results_raw:
        r_clean = r.copy()
        r_clean.pop("trained_model_object", None)
        results_export.append(r_clean)

    summary = pd.DataFrame(results_export).set_index("model")
    print("\n===== SUMMARY =====")
    print(summary[["precision", "recall", "f1", "roc_auc", "pr_auc",
                   "latency_ms_per_request"]].round(4))
 
    # 7. Feature importance (Random Forest) ---------------------------------------
    importances = pd.Series(rf.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print("\nRandom Forest feature importance:\n", importances.round(4))
 
    # 8. Save artefacts -----------------------------------------------------------
    models_dir = BASE_DIR / "models"
    models_dir.mkdir(exist_ok=True)
    
    # Automatically save the best model as fraud_model.pkl for FastAPI
    joblib.dump(best_model_obj, models_dir / "fraud_model.pkl")   
    joblib.dump(scaler, models_dir / "scaler.pkl")
    joblib.dump(rf, models_dir / "rf_model.pkl")
    joblib.dump(xgb, models_dir / "xgb_model.pkl")
    joblib.dump(FEATURE_COLUMNS, models_dir / "feature_columns.pkl")
    
    summary.to_csv(models_dir / "evaluation_summary.csv")
    with open(models_dir / "evaluation_summary.json", "w") as f:
        json.dump(results_export, f, indent=2)
    print(f"\nSaved models, scaler and metrics to {models_dir}")
 
 
if __name__ == "__main__":
    main()