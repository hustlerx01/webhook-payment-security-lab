# SPEC: webhook-payment-security-lab

## Goal
Show that I can build an API endpoint that handles untrusted, money-moving input safely: verify signatures, block replays, ignore duplicates, and stop double charges. The point is a small repo a security or backend reviewer can read in 10 minutes.

## Scope (1-3 days)
In: one FastAPI service, SQLite, pytest, a sender script, CI with bandit + pip-audit, a threat model.
Out: real Stripe/Razorpay keys, a UI, auth, deployment, rate limiting (documented as a gap).

## Architecture
```
sender script / provider ──HTTP POST + X-Signature: t=..,v1=..──► FastAPI
                                                                     │ verify_signature (HMAC, compare_digest, ±300 s)
                                                                     │ record_event (SQLite PK on event_id)
                                                                     ▼
                                                               processed_events
frontend ──POST /payments + Idempotency-Key──► FastAPI ──► idempotency_keys, payments
all rejects ──► JSON log line {event, reason, client_ip}
```

## Threat model
See THREAT_MODEL.md (STRIDE table, mitigations mapped to functions and lines, OWASP API Top 10 references).

## Day-by-day
- Day 1: run the scaffold and read every line. Rename anything that doesn't read like my own code. Run `scripts/send_events.py` against the local server and save the output and log lines for the README. Push the repo and get CI green.
- Day 2: add one thing I chose myself, e.g. (a) secret rotation with two active secrets, (b) a Razorpay-style `X-Razorpay-Signature` variant, or (c) a load test with `hey`/`locust` that counts duplicates under concurrency. Record a GIF of the sender script plus the logs.
- Day 3 (optional): Dockerfile, run behind Nginx with `limit_req`, and close threat #8.

## Acceptance checks
- [ ] `pytest -q` passes all tests (11 at scaffold time)
- [ ] `bandit -r app scripts -ll` reports no issues
- [ ] `pip-audit -r requirements.txt` reports no known vulns
- [ ] `send_events.py` output: valid=200, replay=200 duplicate:true, forged/tampered/stale/no-header=400
- [ ] Each reject produces exactly one JSON log line with a `reason`
- [ ] GitHub Actions green on main

## Recruiter can verify in 30s
1. **README top**: CI badge is green (it links to the Actions run that shows pytest + bandit + pip-audit).
2. **README "Demo" section**: GIF/screenshot of the sender script showing 1 accepted and 5 rejected requests. Placeholder until recorded: `docs/demo.gif`.
3. **THREAT_MODEL.md**: a single table with each threat → the function that stops it.
4. **tests/test_webhooks.py**: test names read as a checklist (valid, bad sig, stale, replay, idempotency).
