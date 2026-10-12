# Threat model: webhook-payment-security-lab

Scope: one FastAPI service with two endpoints. `POST /webhooks/payments` receives events from a payment provider. `POST /payments` is called by our own frontend to create a payment. Test mode only, with no real provider and no real money.

## Assets
- The webhook signing secret (`WEBHOOK_SECRET`)
- Payment state (rows in `payments` and `processed_events`)
- Order/fulfilment logic that runs when an event is accepted

## Trust boundaries
1. Internet -> webhook endpoint (anyone can send a request here)
2. Frontend -> `/payments` (clients retry on timeouts)
3. App -> SQLite file

## STRIDE

| # | STRIDE | Threat | Mitigation | Where in code | OWASP API Top 10 (2023) |
|---|--------|--------|------------|---------------|--------------------------|
| 1 | Spoofing | Attacker posts a fake `payment_intent.succeeded` to get goods without paying | HMAC-SHA256 over `t.body` with a shared secret; reject when it doesn't match | `app/security.py` `verify_signature()` L45, compare at L55 | API2 Broken Authentication |
| 2 | Tampering | Attacker changes the amount in a real, signed event | The signature covers the raw body, so any change breaks it | `compute_signature()`; test `test_tampered_body_rejected` | API8 Security Misconfiguration |
| 3 | Info disclosure (timing) | Byte-by-byte timing attack on signature compare | `hmac.compare_digest` (constant time) | `app/security.py` L55 | API2 |
| 4 | Tampering / Replay | A captured valid request is resent later | Timestamp is inside the signed payload; reject if more than 300 s off (past or future) | `app/security.py` L59; tests `test_stale_timestamp_rejected`, `test_future_timestamp_rejected` | API2 |
| 5 | Replay within window / provider retries | The same event arrives twice inside 5 min, so fulfilment runs twice | `event_id` PRIMARY KEY + `INSERT OR IGNORE` (atomic); duplicate returns 200 and does no work | `app/store.py` `record_event()` L34; test `test_replayed_event_not_processed_twice` | API6 Unrestricted Access to Sensitive Business Flows |
| 6 | Tampering (business) | Client retries create-payment, which double-charges | Required `Idempotency-Key`; same key + same body replays the stored response; same key + different body gets 422 | `app/main.py` `create_payment()` L88, L97; `store.save_idempotent()` L56 | API6 |
| 7 | Repudiation | No record of who sent forged or rejected traffic | Structured JSON reject log with reason + client IP; secret, signature and body are never logged | `app/main.py` `log_reject()` L35 | API9 Improper Inventory / logging gap (general) |
| 8 | Denial of service | Huge bodies or a flood of requests | 64 KB body cap (L16, L65); amount bounds (L44). **Rate limiting is not done, so put it at the proxy/WAF** | `app/main.py` | API4 Unrestricted Resource Consumption |
| 9 | Elevation / misconfig | App boots with an empty secret, so every signature "matches" | Startup fails if `WEBHOOK_SECRET` is unset | `app/main.py` L52 | API8 |
| 10 | Injection | SQL injection through event id or table name | Parameterised queries throughout; the one f-string uses an allow-listed table name (bandit B608 suppressed with reason) | `app/store.py` L76 | API8 / (OWASP Top 10 A03) |

## Out of scope / accepted
- Secret rotation (Stripe allows several `v1=` values; the parser already accepts a list, but there is no rotation tooling).
- Rate limiting and WAF: belongs at the reverse proxy (see hardened-aws-web-tier).
- SQLite works for one instance only; production would need Postgres with the same unique constraints.
- The idempotency key isn't scoped per user because this lab has no auth.
