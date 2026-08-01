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

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass

from . import paths

DEFAULT_TTL_SECONDS = 900  # 15 minutes: long enough to reach a human, short enough to expire


def ttl() -> int:
    """How long an approval stays usable, from `OBSTAT_APPROVAL_TTL` (§7).

    Read at call time rather than frozen at import, like every path beside it.
    A value that is not a positive number raises instead of falling back to the
    default: an approval that expires before anyone reads it turns every
    `approve` rule into a call that can never succeed, and a silent fallback is
    how that gets diagnosed as obstat being broken.
    """
    raw = os.environ.get("OBSTAT_APPROVAL_TTL") or DEFAULT_TTL_SECONDS
    try:
        seconds = int(raw)
    except ValueError:
        # int()'s own message quotes the value but not where it came from, and
        # the variable is the half an operator needs to fix it.
        raise ValueError(f"OBSTAT_APPROVAL_TTL is not a number: {raw!r}") from None
    if seconds <= 0:
        raise ValueError(f"OBSTAT_APPROVAL_TTL must be positive, got {seconds}")
    return seconds


# Stable codes (§6.4). `guard` branches on PENDING — a retry that arrives before
# anyone has answered is not a failure — so these are load-bearing, not labels.
UNKNOWN = "approval_unknown"
MISMATCH = "approval_mismatch"
USED = "approval_used"
DENIED = "approval_denied"
PENDING = "approval_pending"
EXPIRED = "approval_expired"

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
    record_id: str  # what an approver reads the call's details off (§5.1)
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


def identifier(*, tool: str, subject: str, resource: str, args_digest: str) -> str:
    """The id for this exact call, derived rather than invented.

    Deterministic so that an agent retrying while a human thinks rejoins the
    approval already waiting instead of opening another one. A random id turns a
    slow approver into a queue of duplicates, and whoever is deciding then has to
    work out which of eight identical requests to press.

    Twelve hex characters: short enough to read out over a call, and the input is
    not secret, so collision resistance rather than preimage resistance is what
    is being asked of it.
    """
    material = "|".join((tool, subject, resource, args_digest))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def request(
    approval_id: str, *, tool: str, subject: str, resource: str, args_digest: str, record_id: str
) -> tuple[int, bool]:
    """Open an approval, or rejoin the one this call already has.

    Returns (seconds remaining, rejoined). A row still `pending` or `approved` is
    reused; anything terminal or expired is replaced, because the same call being
    made twice legitimately is not the same request.
    """
    now = time.time()
    # Before the transaction: a bad TTL should fail where nothing has been
    # written, not between the INSERT and the COMMIT.
    window = ttl()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT state, expires FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()
            if row is not None and row["state"] in ("pending", "approved") and row["expires"] > now:
                conn.execute("COMMIT")
                return int(row["expires"] - now), True
            conn.execute(
                "INSERT INTO approvals (id, created, expires, tool, subject, resource,"
                " args_digest, record_id, state) VALUES (?,?,?,?,?,?,?,?,'pending')"
                " ON CONFLICT(id) DO UPDATE SET created=excluded.created,"
                " expires=excluded.expires, record_id=excluded.record_id,"
                " state='pending', decided_by=NULL, decided_at=NULL",
                (
                    approval_id,
                    now,
                    now + window,
                    tool,
                    subject,
                    resource,
                    args_digest,
                    record_id,
                ),
            )
            conn.execute("COMMIT")
            return window, False
        except BaseException:
            conn.execute("ROLLBACK")
            raise


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
) -> tuple[bool, str, str]:
    """Spend an approval on exactly the call it was granted for.

    Returns (ok, code, reason): the code is the contract, the reason is the prose
    that goes in the record and carries the detail the code cannot. The check and
    the state change happen inside one IMMEDIATE transaction, so two concurrent
    retries cannot both win.
    """
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None:
                return False, UNKNOWN, "unknown approval"
            # The binding check comes first. Each of these being wrong means the
            # agent is retrying with an approval granted for a different call, and
            # answering that before saying anything about state keeps this from
            # reporting on approvals the caller has no business asking about.
            for field, actual in (
                ("tool", tool),
                ("subject", subject),
                ("resource", resource),
                ("args_digest", args_digest),
            ):
                if row[field] != actual:
                    # One code, and the prose names which field: an examiner wants
                    # to know it was the resource, a caller is told nothing at all.
                    return False, MISMATCH, f"approval was granted for a different {field}"
            if row["state"] == "consumed":
                return False, USED, "approval already used"
            if row["state"] != "approved":
                code = PENDING if row["state"] == "pending" else DENIED
                return False, code, f"approval is {row['state']}"
            if row["expires"] < time.time():
                return False, EXPIRED, "approval expired"
            conn.execute("UPDATE approvals SET state='consumed' WHERE id=?", (approval_id,))
            conn.execute("COMMIT")
            # No constant: nothing branches on the code once `ok` is True, and
            # §5.3 records the policy's `rule_matched` on the call that follows.
            return True, "approval_spent", "approved"
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def pending() -> list[Pending]:
    """Everything still waiting on a human, oldest first. Expired entries are hidden."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, tool, subject, resource, record_id, created, expires FROM approvals"
            " WHERE state='pending' AND expires > ? ORDER BY created",
            (time.time(),),
        ).fetchall()
    return [Pending(**dict(row)) for row in rows]
