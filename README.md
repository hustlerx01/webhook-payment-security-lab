# webhook-payment-security-lab

![ci](https://github.com/hustlerx01/webhook-payment-security-lab/actions/workflows/ci.yml/badge.svg)

A test-mode payment webhook receiver. I built it to practise the checks payment providers expect you to do on your end. Nothing here touches real money or real API keys.

What it does:
- Verifies a Stripe-style `X-Signature: t=<timestamp>,v1=<hmac-sha256>` header with a constant-time compare.
- Rejects events whose timestamp is more than 5 minutes off, so captured requests can't be replayed later.
- Stores each event id in SQLite and skips events it has already seen (providers retry, attackers replay).
- Requires an `Idempotency-Key` on `POST /payments`, so a retried request returns the same payment instead of creating a second one.
- Logs every rejected request as one JSON line with the reason. The secret and body are never logged.

The threats and which function handles each one are in [THREAT_MODEL.md](THREAT_MODEL.md).

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q

export WEBHOOK_SECRET=whsec_test_only
uvicorn --factory app.main:get_app --port 8000
# in another terminal
python scripts/send_events.py http://127.0.0.1:8000
```

Expected output:
```
valid                  -> 200 {"received":true,"duplicate":false}
replay (same event)    -> 200 {"received":true,"duplicate":true}
forged (wrong key)     -> 400 {"error":"bad_signature"}
tampered body          -> 400 {"error":"bad_signature"}
stale timestamp        -> 400 {"error":"stale_timestamp"}
no header              -> 400 {"error":"missing_header"}
```

## Demo

![demo](docs/demo.gif) <!-- TODO: record with asciinema/peek -->

## CI

Each push runs pytest, bandit (static security checks) and pip-audit (known-vulnerable dependencies).

## Results

- Tests: [CONFIRM] passing
- Forged/tampered/stale/replayed requests rejected in the demo run: [CONFIRM] of [CONFIRM]
- Duplicate events processed under [CONFIRM] concurrent retries: [CONFIRM] (should be 0)

## What I'd add next
- Rate limiting at the proxy (threat #8 in the threat model)
- Rotating the signing secret without downtime
- Postgres instead of SQLite for more than one instance

## Resume bullet (fill in after running)
> Blocked [CONFIRM: 5 of 5] forged, tampered, stale and replayed payment webhooks with zero duplicate payments across [CONFIRM: N] concurrent retries, by building a FastAPI receiver with HMAC-SHA256 verification, a 5-minute replay window, SQLite event dedupe and idempotency keys, tested by [CONFIRM: 11] pytest cases in CI with bandit and pip-audit.
