import json
import logging
import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.security import SignatureError, sign_header, verify_signature

SECRET = "whsec_test_only"


@pytest.fixture
def client():
    return TestClient(create_app(secret=SECRET))


def event(eid="evt_1", etype="payment_intent.succeeded"):
    return json.dumps({"id": eid, "type": etype, "data": {"amount": 500}}).encode()


def post(client, body, header):
    return client.post("/webhooks/payments", content=body,
                       headers={"X-Signature": header, "Content-Type": "application/json"})


def test_valid_signature_accepted(client):
    body = event()
    r = post(client, body, sign_header(SECRET, body))
    assert r.status_code == 200
    assert r.json() == {"received": True, "duplicate": False}


def test_bad_signature_rejected(client, caplog):
    body = event()
    with caplog.at_level(logging.WARNING, logger="webhook"):
        r = post(client, body, sign_header("wrong_secret", body))
    assert r.status_code == 400 and r.json()["error"] == "bad_signature"
    assert any("webhook_rejected" in m for m in caplog.messages)


def test_tampered_body_rejected(client):
    body = event()
    header = sign_header(SECRET, body)
    r = post(client, body.replace(b"500", b"50000"), header)
    assert r.json()["error"] == "bad_signature"


def test_missing_header_rejected(client):
    r = post(client, event(), "")
    assert r.status_code == 400 and r.json()["error"] == "missing_header"


def test_stale_timestamp_rejected(client):
    body = event()
    old = int(time.time()) - 301
    r = post(client, body, sign_header(SECRET, body, timestamp=old))
    assert r.status_code == 400 and r.json()["error"] == "stale_timestamp"


def test_future_timestamp_rejected():
    body = event()
    future = 1_000_000 + 400
    with pytest.raises(SignatureError) as e:
        verify_signature(sign_header(SECRET, body, future), body, SECRET, 300, now=1_000_000)
    assert e.value.reason == "stale_timestamp"


def test_replayed_event_not_processed_twice(client):
    body = event("evt_replay")
    h = sign_header(SECRET, body)
    assert post(client, body, h).json()["duplicate"] is False
    r2 = post(client, body, h)
    assert r2.status_code == 200 and r2.json()["duplicate"] is True
    assert client.app.state.store.count("processed_events") == 1


def test_malformed_event_rejected(client):
    body = b'{"no_id": true}'
    r = post(client, body, sign_header(SECRET, body))
    assert r.json()["error"] == "malformed_event"


def test_idempotency_same_key_same_body_returns_same_payment(client):
    h = {"Idempotency-Key": "order-12345678"}
    r1 = client.post("/payments", json={"amount": 500, "currency": "inr"}, headers=h)
    r2 = client.post("/payments", json={"amount": 500, "currency": "inr"}, headers=h)
    assert r1.status_code == 201 and r2.status_code == 200
    assert r1.json()["id"] == r2.json()["id"]
    assert r2.headers["Idempotent-Replayed"] == "true"
    assert client.app.state.store.count("payments") == 1


def test_idempotency_same_key_different_body_rejected(client):
    h = {"Idempotency-Key": "order-abcdefgh"}
    client.post("/payments", json={"amount": 500, "currency": "inr"}, headers=h)
    r = client.post("/payments", json={"amount": 999, "currency": "inr"}, headers=h)
    assert r.status_code == 422


def test_missing_idempotency_key_rejected(client):
    r = client.post("/payments", json={"amount": 500, "currency": "inr"})
    assert r.status_code == 400
