"""SQLite stores for webhook event dedupe and idempotency keys."""
import json
import sqlite3
import threading
import time


class Store:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                received_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                key TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                amount INTEGER NOT NULL,
                currency TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )

    def record_event(self, event_id: str, event_type: str) -> bool:
        """Insert event id; return False if it was already processed.

        PRIMARY KEY + INSERT OR IGNORE makes this atomic, so two concurrent
        deliveries of the same event can't both be processed.
        """
        with self._lock, self.db:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO processed_events VALUES (?, ?, ?)",
                (event_id, event_type, int(time.time())),
            )
            return cur.rowcount == 1

    def get_idempotent(self, key: str):
        row = self.db.execute(
            "SELECT request_hash, response_json FROM idempotency_keys WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        return row[0], json.loads(row[1])

    def save_idempotent(self, key: str, request_hash: str, response: dict) -> bool:
        with self._lock, self.db:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO idempotency_keys VALUES (?, ?, ?, ?)",
                (key, request_hash, json.dumps(response), int(time.time())),
            )
            return cur.rowcount == 1

    def create_payment(self, pid: str, amount: int, currency: str) -> dict:
        with self._lock, self.db:
            self.db.execute(
                "INSERT INTO payments VALUES (?, ?, ?, ?)",
                (pid, amount, currency, "requires_confirmation"),
            )
        return {"id": pid, "amount": amount, "currency": currency,
                "status": "requires_confirmation"}

    def count(self, table: str) -> int:
        if table not in {"processed_events", "idempotency_keys", "payments"}:
            raise ValueError("unknown table")
        return self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608
