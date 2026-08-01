"""`@guard` — the decorator, and the order it does things in (§3).

    1  reject a caller-supplied subject
    2  stop file
    3  resolve the resource from the arguments
    4  policy
    5  approval, if policy asked for one
    6  write the decision record — durable
    7  run the body
    8  write the outcome — best effort

Step 6 is before step 7 and that is not a stylistic choice. Everything a reader
needs to trust the record depends on it.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from . import approval, paths, policy, record

ANONYMOUS = policy.ANONYMOUS
APPROVAL_ARG = "obstat_approval_id"


class Denied(Exception):
    """Refused. Carries the record id and nothing else.

    A denial that explains itself teaches a caller which rule to work around, so
    the detail lives in the record, where the operator can read it and the agent
    cannot.
    """

    def __init__(self, record_id: str) -> None:
        super().__init__(f"Not permitted. Do not retry. Reference: {record_id}")
        self.record_id = record_id


class _Pending(Exception):
    """Not an error: an approval was opened and the agent should come back.

    Raised only because it unwinds the same path a denial does; the wrapper turns
    it into a return value, because a call that needs a human has not failed.
    """

    def __init__(self, approval_id: str, ttl: int, record_id: str, *, rejoined: bool) -> None:
        super().__init__(approval_id)
        self.approval_id = approval_id
        self.ttl = ttl
        self.record_id = record_id
        self.rejoined = rejoined

    def payload(self) -> dict[str, Any]:
        return {
            "obstat": "approval_required",
            "approval_id": self.approval_id,
            "expires_in_seconds": self.ttl,
            "record": self.record_id,
            "waiting": self.rejoined,  # already asked; nobody has answered yet
            "retry": (
                "A human must approve this call. Once approved, call the same tool "
                f"again with identical arguments plus {APPROVAL_ARG}='{self.approval_id}'."
            ),
        }


@dataclass(frozen=True)
class Subject:
    """Who is calling, as far as the host application can tell.

    `verified` is the honest flag: False means the identity came from somewhere a
    caller could have influenced — a header, an argument, a config file.

    ponytail: policy matches on `kind:id` and ignores `verified`, which is
    recorded but not enforced. Gate on it in your resolver (return None rather
    than an unverified Subject) until there is a reason for a rule to say so.
    """

    id: str
    kind: Literal["human", "agent", "service"] = "agent"
    via: tuple[str, ...] = ()  # delegation chain, most recent first
    verified: bool = False

    def __str__(self) -> str:
        return f"{self.kind}:{self.id}"


def _no_subject() -> Subject | None:
    return None


_resolver: Callable[[], Subject | None] = _no_subject


def set_subject_resolver(resolver: Callable[[], Subject | None]) -> None:
    """Tell obstat how to find out who is calling.

    Called with no arguments on every guarded call; return None when there is no
    identity, which is the normal case for a stdio MCP server on a laptop. An
    anonymous call is a legitimate call — it is recorded as `anonymous`, and the
    policy decides what that may do.
    """
    global _resolver
    _resolver = resolver


@dataclass(frozen=True)
class _Checked:
    """What steps 1-5 established, handed to step 6."""

    subject: Subject | None
    subject_name: str
    resource: str
    args_digest: str
    verdict: policy.Decision
    approval_id: str | None


def _public_signature(fn: Callable[..., Any]) -> inspect.Signature:
    """The signature callers see: `subject` removed, `obstat_approval_id` added.

    `subject` is injected by obstat, so leaving it in the advertised schema would
    invite a client to supply its own. The approval id is the opposite — the
    retry protocol needs the caller to send it, so it has to be advertised.
    """
    original = inspect.signature(fn)
    kept = [p for name, p in original.parameters.items() if name != "subject"]
    var_keyword = [p for p in kept if p.kind is inspect.Parameter.VAR_KEYWORD]
    positional = [p for p in kept if p.kind is not inspect.Parameter.VAR_KEYWORD]
    approval_param = inspect.Parameter(
        APPROVAL_ARG,
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation="str | None",
    )
    return original.replace(parameters=[*positional, approval_param, *var_keyword])


def _resource_for(
    spec: str | Callable[[dict[str, Any]], str] | None, tool: str, args: dict[str, Any]
) -> str:
    if spec is None:
        return f"tool:{tool}"
    if callable(spec):
        return spec(args)
    return spec.format(**args)


def guard(
    *,
    resource: str | Callable[[dict[str, Any]], str] | None = None,
    tool: str | None = None,
):
    """Wrap a tool so that no call happens without a written decision.

        @guard(resource="jira_issue:{issue_key}")
        def transition_issue(issue_key: str, transition: str) -> str:
            ...

    `resource` is a format template over the call arguments, or a callable that
    takes them. Omit it and the resource is `tool:<name>`, which is enough when
    the tool is the only thing policy needs to distinguish.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = tool or fn.__name__
        wants_subject = "subject" in inspect.signature(fn).parameters
        public = _public_signature(fn)
        # Arguments are bound against the public signature minus the approval id,
        # so the digest covers what the tool will actually receive and nothing else.
        bind_against = public.replace(
            parameters=[p for p in public.parameters.values() if p.name != APPROVAL_ARG]
        )

        def refuse(
            reason: str,
            *,
            subject: str = ANONYMOUS,
            resource_id: str | None = None,
            args_digest: str | None = None,
            rule: int | None = None,
            approval_id: str | None = None,
        ) -> Denied:
            return Denied(
                record.decision(
                    tool=name,
                    subject=subject,
                    resource=resource_id or f"tool:{name}",
                    effect="deny",
                    reason=reason,
                    rule=rule,
                    args_digest=args_digest or record.digest({}),
                    approval_id=approval_id,
                )
            )

        def check(args: tuple, kwargs: dict) -> _Checked:
            """Steps 1-5. Raises Denied, raises _Pending, or returns."""
            approval_id = kwargs.pop(APPROVAL_ARG, None)

            # 1. `subject` is not advertised, so its presence is a caller trying to
            #    say who it is. Denied before anything reads it — including the
            #    record, which would otherwise quote an attacker's string.
            if "subject" in kwargs:
                raise refuse("caller supplied a subject")

            try:
                bound = bind_against.bind_partial(*args, **kwargs)
            except TypeError as exc:
                raise refuse(f"arguments do not fit the tool: {exc}") from exc
            bound.apply_defaults()
            call_args = dict(bound.arguments)
            args_digest = record.digest(call_args)

            who = _resolver()
            subject = str(who) if who is not None else ANONYMOUS

            # 2. The stop file, before policy: stopping must not depend on the
            #    policy file still being parseable.
            if paths.halt().exists():
                raise refuse("halted", subject=subject, args_digest=args_digest)

            # 3. Resource.
            try:
                target = _resource_for(resource, name, call_args)
            except (KeyError, IndexError, AttributeError, TypeError) as exc:
                raise refuse(
                    f"resource template did not resolve: {exc!r}",
                    subject=subject,
                    resource_id="unresolved",
                    args_digest=args_digest,
                ) from exc

            # 4. Policy. Evaluated once; step 6 records this verdict, not a re-read.
            verdict = policy.decide(tool=name, subject=subject, resource=target)
            refusal = functools.partial(
                refuse, subject=subject, resource_id=target, args_digest=args_digest
            )
            if verdict.effect == "deny":
                raise refusal(verdict.reason, rule=verdict.rule)

            # 5. Approval.
            if verdict.effect == "approve":
                spent = False
                if approval_id is not None:
                    ok, why = approval.consume(
                        approval_id,
                        tool=name,
                        subject=subject,
                        resource=target,
                        args_digest=args_digest,
                    )
                    # A retry that arrives before anyone has answered is not a
                    # denial. Telling an agent "do not retry" because a human is
                    # slow turns a working control into a failed call, and makes
                    # the approval useless by the time it arrives.
                    if not ok and why != approval.STILL_PENDING:
                        raise refusal(why, rule=verdict.rule, approval_id=approval_id)
                    spent = ok

                if not spent:
                    # Derived from this call, so a retry rejoins the approval
                    # already waiting rather than opening another one.
                    wanted = approval.identifier(
                        tool=name, subject=subject, resource=target, args_digest=args_digest
                    )
                    record_id = record.decision(
                        tool=name,
                        subject=subject,
                        resource=target,
                        effect="approval_required",
                        reason=verdict.reason,
                        rule=verdict.rule,
                        args_digest=args_digest,
                        approval_id=wanted,
                    )
                    ttl, rejoined = approval.request(
                        wanted,
                        tool=name,
                        subject=subject,
                        resource=target,
                        args_digest=args_digest,
                        record_id=record_id,
                    )
                    raise _Pending(wanted, ttl, record_id, rejoined=rejoined)

            return _Checked(who, subject, target, args_digest, verdict, approval_id)

        def authorise(args: tuple, kwargs: dict) -> tuple[str, dict]:
            """Steps 1-6. Returns the record id and the kwargs the body will get."""
            checked = check(args, kwargs)
            record_id = record.decision(
                tool=name,
                subject=checked.subject_name,
                resource=checked.resource,
                effect="allow",
                reason=checked.verdict.reason,
                rule=checked.verdict.rule,
                args_digest=checked.args_digest,
                approval_id=checked.approval_id,
                extra={"subject_verified": bool(checked.subject and checked.subject.verified)},
            )
            if wants_subject:
                kwargs = {**kwargs, "subject": checked.subject}
            return record_id, kwargs

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    record_id, kwargs = authorise(args, dict(kwargs))
                except _Pending as pending:
                    return pending.payload()
                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:
                    record.outcome(record_id, ok=False, error=type(exc).__name__)
                    raise
                record.outcome(record_id, ok=True)
                return result

        else:

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    record_id, kwargs = authorise(args, dict(kwargs))
                except _Pending as pending:
                    return pending.payload()
                try:
                    result = fn(*args, **kwargs)
                except Exception as exc:
                    record.outcome(record_id, ok=False, error=type(exc).__name__)
                    raise
                record.outcome(record_id, ok=True)
                return result

        wrapper.__signature__ = public  # type: ignore[attr-defined]
        return wrapper

    return decorate
