import argparse
import json
import os
import secrets
import sys

from src.signing import sign_headers

SCENARIOS = {
    "normal":      ("Ordinary transfer, consistent books", dict(type="TRANSFER", amount=5000, oldbalanceOrg=20000, newbalanceOrig=15000, oldbalanceDest=1000, newbalanceDest=6000)),
    "payment":     ("Small payment that empties the account", dict(type="PAYMENT", amount=181, oldbalanceOrg=181, newbalanceOrig=0, oldbalanceDest=0, newbalanceDest=0)),
    "drain":       ("Cash-out of the entire balance (ML decides)", dict(type="CASH_OUT", amount=90000, oldbalanceOrg=90000, newbalanceOrig=0, oldbalanceDest=0, newbalanceDest=0)),
    "ledger":      ("Sender balance did not drop -> BLOCK (ledger rule)", dict(type="TRANSFER", amount=5000, oldbalanceOrg=20000, newbalanceOrig=20000, oldbalanceDest=1000, newbalanceDest=6000)),
    "dest-ledger": ("Receiver balance did not rise -> BLOCK (ledger rule)", dict(type="TRANSFER", amount=5000, oldbalanceOrg=20000, newbalanceOrig=15000, oldbalanceDest=1000, newbalanceDest=1000)),
    "big":         ("250k in one go -> REVIEW (cumulative volume rule)", dict(type="TRANSFER", amount=250000, oldbalanceOrg=1000000, newbalanceOrig=750000, oldbalanceDest=0, newbalanceDest=250000)),
    "simswap":     ("75k transfer; BLOCK if --telco was run for the SAME --account", dict(type="TRANSFER", amount=75000, oldbalanceOrg=100000, newbalanceOrig=25000, oldbalanceDest=0, newbalanceDest=75000)),
}

ap = argparse.ArgumentParser()
ap.add_argument("scenario", nargs="?", default="normal", choices=list(SCENARIOS))
ap.add_argument("--list", action="store_true")
ap.add_argument("--account", default=None, help="account id (default: fresh random; use the same one for simswap)")
ap.add_argument("--telco", metavar="ACCOUNT", help="generate a SIM_SWAP event for ACCOUNT (telco endpoint)")
a = ap.parse_args()

if a.list:
    for name, (desc, _) in SCENARIOS.items():
        print(f"  {name:12} {desc}")
    sys.exit(0)

clients = json.loads(os.environ.get("GATEWAY_CLIENTS", "{}"))
if not clients:
    sys.exit("Load your env first:  set -a; source .env; set +a")

if a.telco:
    path, client_id = "/telco/sim-events", "telco-feed"
    payload = {"account_id": a.telco, "event_type": "SIM_SWAP"}
else:
    path, client_id = "/predict", "mobile-app"
    payload = {"account_id": a.account or "ACC-" + secrets.token_hex(4), "step": 1, **SCENARIOS[a.scenario][1]}

body = json.dumps(payload, separators=(",", ":"))
h = sign_headers(client_id, clients[client_id]["secret"], "POST", path, body.encode())

print(f"\nIn Swagger, open  POST {path}  ->  Try it out\n")
print("1) Request body (paste exactly, one line):\n")
print(body)
print("\n2) Header fields:\n")
for k in ("X-Client-Id", "X-Timestamp", "X-Nonce", "X-Signature"):
    print(f"{k}: {h[k]}")
print("\nValid 5 minutes, single use. Click Execute now.\n")