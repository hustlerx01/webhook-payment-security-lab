"""Send signed and forged test events to a running receiver.

Usage: WEBHOOK_SECRET=whsec_test_only python scripts/send_events.py [http://127.0.0.1:8000]
"""
import json
import os
import sys
import time
import uuid

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security import sign_header  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
SECRET = os.environ.get("WEBHOOK_SECRET", "whsec_test_only")


def body(eid):
    return json.dumps({"id": eid, "type": "payment_intent.succeeded",
                       "data": {"amount": 500, "currency": "inr"}}).encode()


def send(name, b, header):
    r = httpx.post(f"{BASE}/webhooks/payments", content=b,
                   headers={"X-Signature": header, "Content-Type": "application/json"})
    print(f"{name:<22} -> {r.status_code} {r.text}")


eid = f"evt_{uuid.uuid4().hex[:10]}"
good = body(eid)
send("valid", good, sign_header(SECRET, good))
send("replay (same event)", good, sign_header(SECRET, good))
send("forged (wrong key)", body("evt_forged"), sign_header("attacker_key", body("evt_forged")))
send("tampered body", good.replace(b"500", b"99999"), sign_header(SECRET, good))
send("stale timestamp", body("evt_old"), sign_header(SECRET, body("evt_old"), int(time.time()) - 3600))
send("no header", body("evt_none"), "")
