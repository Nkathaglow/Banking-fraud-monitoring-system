import pandas as pd
 
FEATURE_COLUMNS = [
    "is_transfer",        # 1 = TRANSFER, 0 = CASH_OUT
    "amount",
    "oldbalanceOrg",
    "newbalanceOrig",
    "oldbalanceDest",
    "newbalanceDest",
    "errorBalanceOrig",   # balance inconsistency on the sender side
    "errorBalanceDest",   # balance inconsistency on the receiver side
]
 
 
def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Turn raw PaySim-style columns into the model's feature matrix."""
    out = pd.DataFrame(index=df.index)
    out["is_transfer"] = (df["type"] == "TRANSFER").astype(int)
    out["amount"] = df["amount"]
    out["oldbalanceOrg"] = df["oldbalanceOrg"]
    out["newbalanceOrig"] = df["newbalanceOrig"]
    out["oldbalanceDest"] = df["oldbalanceDest"]
    out["newbalanceDest"] = df["newbalanceDest"]
    out["errorBalanceOrig"] = df["newbalanceOrig"] + df["amount"] - df["oldbalanceOrg"]
    out["errorBalanceDest"] = df["oldbalanceDest"] + df["amount"] - df["newbalanceDest"]
    return out[FEATURE_COLUMNS]