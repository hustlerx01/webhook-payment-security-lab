"""Signature verification for Stripe-style webhook headers.

Header format:  X-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
Signed payload: f"{t}.{raw_body}"
"""
import hashlib
import hmac
import time


class SignatureError(Exception):
    """Raised with a short machine-readable reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def parse_header(header: str) -> tuple[int, list[str]]:
    if not header:
        raise SignatureError("missing_header")
    ts = None
    sigs: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                ts = int(value)
            except ValueError:
                raise SignatureError("bad_timestamp")
        elif key == "v1" and value:
            sigs.append(value)
    if ts is None:
        raise SignatureError("missing_timestamp")
    if not sigs:
        raise SignatureError("missing_signature")
    return ts, sigs


def compute_signature(secret: str, timestamp: int, body: bytes) -> str:
    signed = str(timestamp).encode() + b"." + body
    return hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


def verify_signature(header: str, body: bytes, secret: str,
                     tolerance_s: int = 300, now: int | None = None) -> int:
    """Return the verified timestamp or raise SignatureError.

    Order matters: check the HMAC first so an attacker learns nothing about
    the tolerance window from an unsigned request.
    """
    ts, sigs = parse_header(header)
    expected = compute_signature(secret, ts, body)
    # constant-time comparison (T: tampering / S: spoofing)
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise SignatureError("bad_signature")
    now = int(time.time()) if now is None else now
    # replay window (R/T: replay of captured requests)
    if abs(now - ts) > tolerance_s:
        raise SignatureError("stale_timestamp")
    return ts


def sign_header(secret: str, body: bytes, timestamp: int | None = None) -> str:
    ts = int(time.time()) if timestamp is None else timestamp
    return f"t={ts},v1={compute_signature(secret, ts, body)}"
