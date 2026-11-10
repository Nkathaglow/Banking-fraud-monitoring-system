"""Demo client. Sends a signed transaction; --replay re-sends the identical request.
    CLIENT_ID=mobile-app CLIENT_SECRET=... python3 -m scripts.send_signed --url http://127.0.0.1:8000 --replay"""
import argparse
import json
import os

import httpx

from src.signing import sign_headers

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="https://localhost:8443")
ap.add_argument("--insecure", action="store_true", help="accept Caddy's internal CA (demo only)")
ap.add_argument("--replay", action="store_true")
args = ap.parse_args()

payload = {"account_id": "ACC-1001", "step": 1, "amount": 100.0, "oldbalanceOrg": 1000.0,
           "newbalanceOrig": 900.0, "oldbalanceDest": 500.0, "newbalanceDest": 600.0, "type": "TRANSFER"}
body = json.dumps(payload).encode()
headers = sign_headers(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"], "POST", "/predict", body)
headers["Content-Type"] = "application/json"

with httpx.Client(verify=not args.insecure) as c:
    r = c.post(f"{args.url}/predict", content=body, headers=headers)
    print("first :", r.status_code, r.text)
    if args.replay:
        r = c.post(f"{args.url}/predict", content=body, headers=headers)  # identical nonce
        print("replay:", r.status_code, r.text, "<- expected 401")
