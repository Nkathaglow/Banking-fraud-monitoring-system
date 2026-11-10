import argparse
import json
import os
import secrets
import sys

import httpx

ap = argparse.ArgumentParser()
ap.add_argument("--type", default="TRANSFER", choices=["PAYMENT", "TRANSFER", "CASH_OUT", "CASH_IN", "DEBIT"])
ap.add_argument("--amount", type=float, required=True)
ap.add_argument("--old-org", type=float, required=True, help="sender balance before")
ap.add_argument("--new-org", type=float, help="sender balance after (default: consistent)")
ap.add_argument("--old-dest", type=float, default=0.0, help="receiver balance before")
ap.add_argument("--new-dest", type=float, help="receiver balance after (default: consistent)")
ap.add_argument("--account", default=None, help="account id (default: a fresh random one)")
ap.add_argument("--step", type=int, default=1)
ap.add_argument("--url", default="http://127.0.0.1:8000")
ap.add_argument("--client", default="mobile-app", help="client name (signed mode only)")
a = ap.parse_args()

new_org = a.new_org if a.new_org is not None else (
    a.old_org + a.amount if a.type == "CASH_IN" else a.old_org - a.amount)
new_dest = a.new_dest if a.new_dest is not None else (
    a.old_dest + a.amount if a.type == "TRANSFER" else a.old_dest)
payload = {"account_id": a.account or "ACC-" + secrets.token_hex(4), "step": a.step, "amount": a.amount,
           "oldbalanceOrg": a.old_org, "newbalanceOrig": round(new_org, 2),
           "oldbalanceDest": a.old_dest, "newbalanceDest": round(new_dest, 2), "type": a.type}
body = json.dumps(payload).encode()
headers = {"Content-Type": "application/json"}

if os.environ.get("FRAUD_API_KEY"):
    headers["Authorization"] = f"Bearer {os.environ['FRAUD_API_KEY']}"
else:
    from src.signing import sign_headers
    try:
        secret = json.loads(os.environ["GATEWAY_CLIENTS"])[a.client]["secret"]
    except KeyError:
        sys.exit("Set your key first:  export FRAUD_API_KEY=fgk_...")
    headers.update(sign_headers(a.client, secret, "POST", "/predict", body))

try:
    r = httpx.post(f"{a.url}/predict", content=body, headers=headers, timeout=10)
except httpx.ConnectError:
    sys.exit(f"Cannot reach {a.url} - is uvicorn running?")
if r.status_code != 200:
    sys.exit(f"HTTP {r.status_code}: {r.text}")

res = r.json()
print(f"\n  Decision : {res['decision']}")
if "fraud_probability" in res:
    print(f"  Fraud probability (ML) : {res['fraud_probability']:.4f}   Risk: {res['risk_level']}")
    print(f"  Decided by : {res['decision_source']}   Threat: {res['security_threat']}")
    print(f"  Reason : {res['reason']}")
else:
    print("  (this key is not 'verbose', so score and reason are only in the audit log;"
          " use a --verbose client for testing)")
print(f"  Audit id : {res['audit_id']}\n")