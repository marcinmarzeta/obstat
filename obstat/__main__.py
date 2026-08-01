"""`obstat` — the operator's side: what is waiting, and what happened.

obstat init
obstat check <tool> [resource] [--subject]
obstat pending
obstat approve <id>
obstat deny <id>
obstat log [-n 20]
obstat verify
obstat stop | resume
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time

from . import approval, paths, policy, record

# `obstat.guard` the name is the decorator, so the module's own default resource
# has to be reached directly.
from .guard import _resource_for

# Every rule commented out and one live deny (§2.3). A starter policy that grants
# something is a starter policy somebody ships unread, and the rules here are
# shapes to copy rather than defaults to inherit.
_STARTER = """\
# obstat policy. Rules are tried in file order, the first match wins, and
# nothing matching is a deny — so this file permits nothing until you edit it.
# It is re-read when it changes; no restart.

# Tools whose name begins with read_ may run without asking.
# [[rule]]
# tool = "read_*"
# effect = "allow"

# Deleting waits for a human: `obstat pending`, then `obstat approve <id>`.
# [[rule]]
# tool = "delete_*"
# effect = "approve"

# One principal, one family of resources. `subject` is "kind:id", or "anonymous".
# [[rule]]
# subject = "human:ana"
# resource = "jira_issue:ACME-*"
# effect = "allow"

# Deny the rest out loud. An absent rule denies too, but this puts a rule number
# in the record, which reads as a decision rather than as an omission.
[[rule]]
effect = "deny"
"""


def _init(_: argparse.Namespace) -> int:
    path = paths.policy()
    if path.exists():
        # Never clobber a policy. The file this would overwrite is the only thing
        # standing between an agent and every guarded tool.
        print(f"{path} already exists, leaving it alone", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_STARTER, encoding="utf-8")
    # Resolved, because the default path is relative to the working directory and
    # a policy written beside the wrong one is the quietest way to edit nothing.
    print(f"wrote {path.resolve()} — everything is denied until you uncomment a rule")
    return 0


def _check(args: argparse.Namespace) -> int:
    """What the policy would decide, without a call to make it decide it (§2.3)."""
    # Through the guard's own resolver, so the default cannot drift from §3.3 and
    # leave `check` answering about a resource no call would ever produce.
    resource = args.resource or _resource_for(None, args.tool, {})
    try:
        verdict = policy.decide(tool=args.tool, subject=args.subject, resource=resource)
    except policy.PolicyError as exc:
        # The reason this reads a file at all: a typo'd key or broken TOML is
        # otherwise found by the next real call, in front of a real agent.
        print(exc, file=sys.stderr)
        return 1
    print(f"{verdict.effect} ({verdict.reason})  {args.tool}  {args.subject}  {resource}")
    return 0 if verdict.effect == "allow" else 1


def _pending(_: argparse.Namespace) -> int:
    rows = approval.pending()
    if not rows:
        print("nothing waiting")
        return 0
    # What the call was actually for lives on the record the approval was opened
    # with, not in the approvals table (§5.1).
    #
    # ponytail: reads the whole log to find a handful of ids. Affordable in a
    # human command in a way it would not be in front of every guarded call; if
    # a long log ever makes this pause, stop at the oldest pending row's record.
    recorded = {
        entry["id"]: entry["args_recorded"] for entry in record.read() if entry.get("args_recorded")
    }
    for row in rows:
        left = int(row.expires - time.time())
        print(f"{row.id}  {row.tool:24}  {row.subject:20}  {row.resource:30}  {left}s left")
        for key, value in recorded.get(row.record_id, {}).items():
            print(f"      {key} = {value!r}")
    return 0


def _decide(args: argparse.Namespace) -> int:
    who = args.by or getpass.getuser()
    if approval.resolve(args.id, approved=args.approved, by=who):
        print(f"{args.id} {'approved' if args.approved else 'denied'} by {who}")
        return 0
    # Already decided, already used, or never existed — all the same to the operator.
    print(f"{args.id}: no pending approval by that id", file=sys.stderr)
    return 1


def _log(args: argparse.Namespace) -> int:
    entries = record.read()
    for entry in entries[-args.n :]:
        print(json.dumps(entry))
    return 0


def _verify(_: argparse.Namespace) -> int:
    if problems := record.verify():
        print(*problems, sep="\n", file=sys.stderr)
        return 1
    print("chain intact")
    return 0


def _stop(_: argparse.Namespace) -> int:
    path = paths.halt()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"stopped by {getpass.getuser()} at {time.time()}\n", encoding="utf-8")
    print(f"stopped. Every guarded call is denied until `obstat resume`. ({path})")
    return 0


def _resume(_: argparse.Namespace) -> int:
    paths.halt().unlink(missing_ok=True)
    print("resumed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="obstat", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="write a starter policy file").set_defaults(run=_init)

    check = sub.add_parser("check", help="what the policy would decide, without calling anything")
    check.add_argument("tool")
    check.add_argument("resource", nargs="?", help="default: tool:<tool>, as @guard uses")
    check.add_argument("--subject", default=policy.ANONYMOUS, help="default: anonymous")
    check.set_defaults(run=_check)

    sub.add_parser("pending", help="approvals waiting on a human").set_defaults(run=_pending)

    for verb, approved in (("approve", True), ("deny", False)):
        cmd = sub.add_parser(verb, help=f"{verb} a pending approval")
        cmd.add_argument("id")
        cmd.add_argument("--by", help="who decided (default: the shell user)")
        cmd.set_defaults(run=_decide, approved=approved)

    log = sub.add_parser("log", help="the decision record, oldest first")
    log.add_argument("-n", type=int, default=20, help="how many entries (default 20)")
    log.set_defaults(run=_log)

    sub.add_parser("verify", help="recompute the record chain").set_defaults(run=_verify)

    sub.add_parser("stop", help="deny every guarded call").set_defaults(run=_stop)
    sub.add_parser("resume", help="undo stop").set_defaults(run=_resume)

    args = parser.parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    raise SystemExit(main())
