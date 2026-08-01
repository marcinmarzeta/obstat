"""`obstat` — the operator's side: what is waiting, and what happened.

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

from . import approval, paths, record


def _pending(_: argparse.Namespace) -> int:
    rows = approval.pending()
    if not rows:
        print("nothing waiting")
        return 0
    for row in rows:
        left = int(row.expires - time.time())
        print(f"{row.id}  {row.tool:24}  {row.subject:20}  {row.resource:30}  {left}s left")
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
