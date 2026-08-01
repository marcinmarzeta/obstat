"""The decision record (§5), and the one ordering that is a security property.

`decision()` returns only after the record is on disk — written, flushed, and
fsynced. Everything else in this library is a convenience; this is the part an
examiner relies on. A log written after the call is a story about what happened.
A record written before it is evidence of what was authorised.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from . import paths

SCHEMA = 1


def digest(args: dict[str, Any]) -> str:
    """A stable fingerprint of the call arguments.

    The values themselves are deliberately not recorded: tool arguments carry
    credentials, personal data and free text, and a governance log that leaks
    them is a liability rather than a control. The digest is enough to prove
    that the call executed is the call that was approved.

    ponytail: no per-key allowlist yet. Add `record_args=("issue_key",)` to
    @guard when someone needs the values in the record itself.
    """
    canonical = json.dumps(args, sort_keys=True, default=repr, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _append(entry: dict[str, Any], *, durable: bool) -> None:
    path = paths.log()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, separators=(",", ":"), default=str) + "\n"
    # Append mode, one write, one line: concurrent writers interleave records but
    # never split one. O_APPEND makes the offset kernel-side, so no lock is needed.
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        if durable:
            handle.flush()
            os.fsync(handle.fileno())


def decision(
    *,
    tool: str,
    subject: str,
    resource: str,
    effect: str,
    reason: str,
    rule: int | None,
    args_digest: str,
    approval_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Write the decision. Returns the record id, which is also the deny reference.

    Durable before the caller continues — that is the whole point, and
    `tests/test_guard.py::test_record_is_durable_before_the_body_runs` fails if
    this is ever relaxed for speed.
    """
    record_id = uuid.uuid4().hex
    _append(
        {
            "schema": SCHEMA,
            "id": record_id,
            "ts": time.time(),
            "phase": "decision",
            "tool": tool,
            "subject": subject,
            "resource": resource,
            "effect": effect,
            "reason": reason,
            "rule": rule,
            "args": args_digest,
            "approval_id": approval_id,
            **(extra or {}),
        },
        durable=True,
    )
    return record_id


def outcome(record_id: str, *, ok: bool, error: str | None = None) -> None:
    """Best effort, and deliberately not durable.

    If the process dies mid-call the decision record still stands alone, which
    reads as "authorised, outcome unknown" — the honest state. Blocking the
    caller on a second fsync to record something that is only informative would
    be paying the cost twice for half the value.
    """
    # A full disk must not turn a completed call into a failed one.
    with contextlib.suppress(OSError):
        _append(
            {
                "schema": SCHEMA,
                "id": record_id,
                "ts": time.time(),
                "phase": "outcome",
                "ok": ok,
                "error": error,
            },
            durable=False,
        )


def read(path: Path | None = None) -> list[dict[str, Any]]:
    """Every record, oldest first. For tests and for `obstat log`."""
    path = path or paths.log()
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
