"""Test-mode payment webhook receiver. No real money, no real provider."""
import hashlib
import json
import logging
import os
import re
import uuid

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.security import SignatureError, verify_signature
from app.store import Store

MAX_BODY_BYTES = 64 * 1024
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        base = {"level": record.levelname, "msg": record.getMessage()}
        base.update(getattr(record, "extra_fields", {}))
        return json.dumps(base)


log = logging.getLogger("webhook")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    log.addHandler(h)
log.setLevel(logging.INFO)


def log_reject(reason: str, request: Request, **fields):
    """Structured reject log. Never logs the secret, the signature or the body."""
    log.warning("webhook_rejected", extra={"extra_fields": {
        "event": "webhook_rejected", "reason": reason,
        "client_ip": request.client.host if request.client else None,
        **fields}})


class PaymentIn(BaseModel):
    amount: int = Field(gt=0, le=10_000_000)
    currency: str = Field(pattern=r"^[a-z]{3}$")


def create_app(secret: str | None = None, db_path: str = ":memory:",
               tolerance_s: int = 300) -> FastAPI:
    secret = secret or os.environ.get("WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError("WEBHOOK_SECRET is not set")
    store = Store(db_path)
    app = FastAPI(title="webhook-payment-security-lab")
    app.state.store = store

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/webhooks/payments")
    async def receive_webhook(request: Request,
                              x_signature: str = Header(default="")):
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            log_reject("body_too_large", request, size=len(body))
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        try:
            verify_signature(x_signature, body, secret, tolerance_s)
        except SignatureError as e:
            log_reject(e.reason, request)
            return JSONResponse({"error": e.reason}, status_code=400)
        try:
            event = json.loads(body)
            event_id, event_type = str(event["id"]), str(event["type"])
        except (ValueError, KeyError, TypeError):
            log_reject("malformed_event", request)
            return JSONResponse({"error": "malformed_event"}, status_code=400)
        if not store.record_event(event_id, event_type):
            log_reject("duplicate_event", request, event_id=event_id)
            # 200 so the sender stops retrying, but we do no work.
            return {"received": True, "duplicate": True}
        log.info("webhook_accepted", extra={"extra_fields": {
            "event": "webhook_accepted", "event_id": event_id, "type": event_type}})
        return {"received": True, "duplicate": False}

    @app.post("/payments", status_code=201)
    def create_payment(payload: PaymentIn, request: Request,
                       idempotency_key: str = Header(default="")):
        if not IDEMPOTENCY_KEY_RE.match(idempotency_key):
            log_reject("bad_idempotency_key", request)
            return JSONResponse({"error": "idempotency_key_required"}, status_code=400)
        req_hash = hashlib.sha256(payload.model_dump_json().encode()).hexdigest()
        existing = store.get_idempotent(idempotency_key)
        if existing:
            prev_hash, prev_resp = existing
            if prev_hash != req_hash:
                log_reject("idempotency_key_reused", request, key=idempotency_key)
                return JSONResponse({"error": "idempotency_key_reused_with_different_body"},
                                    status_code=422)
            return JSONResponse(prev_resp, status_code=200,
                                headers={"Idempotent-Replayed": "true"})
        resp = store.create_payment(f"pay_{uuid.uuid4().hex[:16]}",
                                    payload.amount, payload.currency)
        store.save_idempotent(idempotency_key, req_hash, resp)
        return resp

    return app


def get_app() -> FastAPI:  # uvicorn --factory app.main:get_app
    return create_app(db_path=os.environ.get("DB_PATH", "lab.db"))
