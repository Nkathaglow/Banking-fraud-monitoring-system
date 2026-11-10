"""Verify the audit chain (and optionally an external anchor).
    python -m scripts.verify_audit
    python -m scripts.verify_audit --write-anchor anchor.json   # store this file OFF the DB host
    python -m scripts.verify_audit --check-anchor anchor.json
Exit code 0 = intact, 1 = tampering detected."""
import argparse
import sys

from src.audit import check_anchor, verify_chain, write_anchor
from src.database import SessionLocal

ap = argparse.ArgumentParser()
ap.add_argument("--write-anchor")
ap.add_argument("--check-anchor")
args = ap.parse_args()

with SessionLocal() as db:
    res = verify_chain(db)
    if not res.ok:
        print(f"TAMPERING DETECTED at audit id={res.bad_id}: {res.error}")
        sys.exit(1)
    print(f"Chain intact: {res.checked} rows, head id={res.head_id}")
    if args.check_anchor:
        ok, why = check_anchor(db, args.check_anchor)
        print(("ANCHOR OK: " if ok else "ANCHOR FAILED: ") + why)
        if not ok:
            sys.exit(1)
    if args.write_anchor:
        write_anchor(args.write_anchor, res)
        print(f"Anchor written to {args.write_anchor}")
