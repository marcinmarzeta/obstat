"""Two-phase approval (§4).

Phase 1: the call arrives, policy says `approve`, and the tool returns an
approval id instead of doing anything. Phase 2: a human decides, the agent calls
again with the id, and the call proceeds.

The agent is never blocked waiting on a human, because most agents are not
sitting at a terminal. That is the only reason this is a state machine in SQLite
rather than an `input()` call.

An approval is bound to the exact call it was granted for — tool, subject,
resource and argument digest — and is single-use. Approving "send the email"
must not authorise sending a different one.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass

from . import paths

TTL_SECONDS = 900  # 15 minutes: long enough to reach a human, short enough to expire

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,
    created      REAL NOT NULL,
    expires      REAL NOT NULL,
    tool         TEXT NOT NULL,
    subject      TEXT NOT NULL,
    resource     TEXT NOT NULL,
    args_digest  TEXT NOT NULL,
    record_id    TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('pending','approved','denied','consumed')),
    decided_by   TEXT,
    decided_at   REAL
);
"""


@dataclass(frozen=True)
class Pending:
    id: str
    tool: str
    subject: str
    resource: str
    created: float
    expires: float


def _connect() -> sqlite3.Connection:
    path = paths.db()
    path.parent.mkdir(parents=True, exist_ok=True)
    # isolation_level=None: explicit BEGIN IMMEDIATE where it matters, autocommit
    # elsewhere. WAL so a human running the CLI cannot block a serving process.
    conn = sqlite3.connect(path, isolation_level=None, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_SCHEMA)
    return conn


def request(
    *, tool: str, subject: str, resource: str, args_digest: str, record_id: str
) -> tuple[str, int]:
    """Open a pending approval. Returns its id and how long it is valid for."""
    approval_id = uuid.uuid4().hex[:12]  # short enough to read out loud over a call
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO approvals (id, created, expires, tool, subject, resource,"
            " args_digest, record_id, state) VALUES (?,?,?,?,?,?,?,?,'pending')",
            (approval_id, now, now + TTL_SECONDS, tool, subject, resource, args_digest, record_id),
        )
    return approval_id, TTL_SECONDS


def resolve(approval_id: str, *, approved: bool, by: str) -> bool:
    """A human decides. Returns False if there was no pending approval by that id."""
    state = "approved" if approved else "denied"
    with _connect() as conn:
        cursor = conn.execute(
            "UPDATE approvals SET state=?, decided_by=?, decided_at=?"
            " WHERE id=? AND state='pending'",
            (state, by, time.time(), approval_id),
        )
        return cursor.rowcount == 1


def consume(
    approval_id: str, *, tool: str, subject: str, resource: str, args_digest: str
) -> tuple[bool, str]:
    """Spend an approval on exactly the call it was granted for.

    Returns (ok, reason). The check and the state change happen inside one
    IMMEDIATE transaction, so two concurrent retries cannot both win.
    """
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None:
                return False, "unknown approval"
            if row["state"] == "consumed":
                return False, "approval already used"
            if row["state"] != "approved":
                return False, f"approval is {row['state']}"
            if row["expires"] < time.time():
                return False, "approval expired"
            # The binding check. Each of these being wrong means the agent is
            # retrying with an approval granted for a different call.
            for field, actual in (
                ("tool", tool),
                ("subject", subject),
                ("resource", resource),
                ("args_digest", args_digest),
            ):
                if row[field] != actual:
                    return False, f"approval was granted for a different {field}"
            conn.execute("UPDATE approvals SET state='consumed' WHERE id=?", (approval_id,))
            conn.execute("COMMIT")
            return True, "approved"
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def pending() -> list[Pending]:
    """Everything still waiting on a human, oldest first. Expired entries are hidden."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, tool, subject, resource, created, expires FROM approvals"
            " WHERE state='pending' AND expires > ? ORDER BY created",
            (time.time(),),
        ).fetchall()
    return [Pending(**dict(row)) for row in rows]
