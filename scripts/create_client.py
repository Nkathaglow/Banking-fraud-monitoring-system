import argparse
import hashlib
import json
import os
import secrets
import sys

ap = argparse.ArgumentParser()
ap.add_argument("name")
ap.add_argument("--role", required=True, choices=["txn", "telco"])
ap.add_argument("--verbose", action="store_true")
ap.add_argument("--with-signing-secret", action="store_true")
ap.add_argument("--add-to-env", metavar="FILE")
a = ap.parse_args()

key = "fgk_" + secrets.token_urlsafe(32)
entry = {"role": a.role, "key_sha256": hashlib.sha256(key.encode()).hexdigest()}
if a.verbose:
    entry["verbose"] = True
if a.with_signing_secret:
    entry["secret"] = secrets.token_urlsafe(48)


def update_env(path: str, name: str, entry: dict) -> bool:
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    idx = next((i for i, l in enumerate(lines) if l.startswith("GATEWAY_CLIENTS=")), None)
    clients = {}
    if idx is not None:
        raw = lines[idx].split("=", 1)[1].strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
            raw = raw[1:-1]
        clients = json.loads(raw or "{}")
    rotated = name in clients
    clients[name] = {**clients.get(name, {}), **entry}   # keep existing fields (e.g. verbose, secret) on rotation
    line = "GATEWAY_CLIENTS='" + json.dumps(clients, separators=(",", ":")) + "'"
    if idx is None:
        lines.append(line)
    else:
        lines[idx] = line
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    return rotated


if a.add_to_env:
    rotated = update_env(a.add_to_env, a.name, entry)
    print(f"{'Rotated' if rotated else 'Added'} client '{a.name}' in {a.add_to_env}")
else:
    print("Add this to GATEWAY_CLIENTS yourself:")
    print(json.dumps({a.name: entry}, separators=(",", ":")))

print(f"\n  API key for '{a.name}' (shown ONCE - store it in a password manager):\n\n    {key}\n")
print("  Use it as:   Authorization: Bearer <key>")
print("  In Swagger:  click Authorize, paste the key, press Authorize.")
print("  Restart the server for the change to take effect.", file=sys.stderr)