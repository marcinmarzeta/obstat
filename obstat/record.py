"""The decision record (§5), and the one ordering that is a security property.

`decision()` returns only after the record is on disk — written and fsynced.
Everything else in this library is a convenience; this is the part an examiner
relies on. A log written after the call is a story about what happened. A record
written before it is evidence of what was authorised.

Each record also carries the hash of the one before it (§6.3), so a line that was
edited or removed shows up in `obstat verify`. That makes the log tamper-evident,
not tamper-proof: see §8 for what it still does not prove.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from . import paths

SCHEMA = 4

# (log path, hash of the last record this process wrote). Re-read when the path
# changes, the way policy re-reads its file.
_chain: tuple[str, str | None] | None = None

# ponytail: one lock for the whole process, so records are hashed and appended in
# the same order. Per-writer chains would let concurrent calls fsync in parallel;
# worth it only if a server ever makes enough guarded calls for one fsync at a
# time to be the thing that hurts.
_chain_lock = threading.Lock()


def digest(args: dict[str, Any]) -> str:
    """A stable fingerprint of the call arguments.

    The values themselves are deliberately not recorded: tool arguments carry
    credentials, personal data and free text, and a governance log that leaks
    them is a liability rather than a control. The digest is enough to prove
    that the call executed is the call that was approved.

    The digest covers **every** argument, including any the tool named in
    `record_args` (§6.1). Those are written beside it, not instead of it.
    """
    canonical = json.dumps(args, sort_keys=True, default=repr, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _chain_hash(entry: dict[str, Any]) -> str:
    """A record's own hash, over every field except that hash (§6.3).

    Sorted keys, so a record verifies the same whatever order it was written in.
    """
    canonical = json.dumps(
        {key: value for key, value in entry.items() if key != "hash"},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _tail_hash(path: Path) -> str | None:
    """The `hash` of the log's last record, or None when there isn't one.

    Read once per log path, so a restarted process continues the chain instead of
    starting a second one beside it.

    ponytail: reads the whole file to reach its last line. Once per process, that
    beats the twenty lines of backwards seeking it replaced — but the log has no
    rotation (§8), so seek backwards from the end if a long-lived log ever makes
    the first guarded call of a process feel slow.

    A last line that does not parse — a torn write, or an edit — yields None
    rather than raising. Refusing to serve because the log is damaged would hand
    anyone who can append one byte a denial of service for every guarded tool,
    and the damage is already reported by the thing built to report it,
    `obstat verify`.
    """
    try:
        with path.open("rb") as handle:
            last = deque(handle, maxlen=1)
    except FileNotFoundError:
        return None
    try:
        return json.loads(last[0]).get("hash")
    except (IndexError, AttributeError, json.JSONDecodeError):
        return None


def _append(entry: dict[str, Any], *, durable: bool) -> None:
    global _chain
    path = paths.log()
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    with _chain_lock:
        if _chain is None or _chain[0] != str(path):
            _chain = (str(path), _tail_hash(path))
        chained = {**entry, "prev": _chain[1]}
        chained["hash"] = _chain_hash(chained)
        line = (json.dumps(chained, separators=(",", ":"), default=str) + "\n").encode("utf-8")
        # One record, one write() syscall: concurrent writers interleave records
        # but never split one, and O_APPEND keeps the offset kernel-side so no
        # *inter-process* lock is needed. Unbuffered because a buffered text write
        # splits a record larger than its buffer across several syscalls, and only
        # one syscall is atomic — record size is caller-influenced, since resource
        # ids are built from the arguments.
        with path.open("a+b", buffering=0) as handle:
            # A write cut short by a full disk leaves a fragment with no newline on
            # the end. Starting on a fresh line keeps *this* record readable rather
            # than splicing it onto that fragment and losing both; `obstat verify`
            # still reports the fragment. One read() costs nothing beside the fsync.
            end = handle.seek(0, os.SEEK_END)
            if end:
                handle.seek(end - 1)
                if handle.read(1) != b"\n":
                    line = b"\n" + line
            view = memoryview(line)
            while view:
                # In practice a short write means the disk filled. Finishing the
                # line surfaces that as OSError instead of leaving half a record.
                view = view[handle.write(view) :]
            if durable:
                os.fsync(handle.fileno())
        # Only after the write, so a record that failed to land is not the one the
        # next record claims to follow.
        _chain = (str(path), chained["hash"])
    if durable and created:
        # fsync on the file does not make its directory entry durable, so the very
        # first record could survive as data with nothing pointing at it. Only the
        # write that creates the log needs this; every later one reuses the entry.
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def decision(
    *,
    tool: str,
    subject: str,
    resource: str,
    effect: str,
    code: str,
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
            "code": code,
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


def verify(path: Path | None = None) -> list[str]:
    """Recompute the chain (§6.3). Returns the problems found; empty means intact.

    Catches a record that was edited and a record that was cut out of the middle.
    It cannot catch records cut from the *end* — nothing points at them — and it
    cannot stop someone who can write the file from recomputing the whole chain.
    Both limits are in §8; this is tamper-evidence, not non-repudiation.

    Parses line by line rather than through `read()`, because a damaged log is
    exactly the input this is for.
    """
    path = path or paths.log()
    if not path.exists():
        return []
    problems: list[str] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"line {number}: not a record")
                continue
            stored = entry.get("hash")
            if stored is None:
                continue  # written before the chain existed; unverifiable, not wrong
            if stored != _chain_hash(entry):
                problems.append(f"line {number}: record {entry.get('id')} has been altered")
            prev = entry.get("prev")
            if prev is not None and prev not in seen:
                problems.append(
                    f"line {number}: record {entry.get('id')} follows a record"
                    " that is no longer in the log"
                )
            # Recorded even when it failed a check above, so one tampered record
            # produces one problem rather than one for every record after it.
            seen.add(stored)
    return problems


def read(path: Path | None = None) -> list[dict[str, Any]]:
    """Every record, oldest first. For tests and for `obstat log`."""
    path = path or paths.log()
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
