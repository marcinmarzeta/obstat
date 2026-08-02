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

APPROVAL_ARG = "obstat_approval_id"
# Namespaced, and for the same reason the approval id is: `subject` is an
# ordinary word a tool may need for itself — an email's subject line was the
# case that proved it — and a library that takes one silently takes it from
# every tool that had a use for it.
SUBJECT_ARG = "obstat_subject"

# Stable codes for the refusals `guard` raises itself (§6.4).
SUBJECT_SUPPLIED = "subject_supplied"
ARGUMENTS_REJECTED = "arguments_rejected"
HALTED = "halted"
RESOURCE_UNRESOLVED = "resource_unresolved"


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
    shown: dict[str, Any]
    verdict: policy.Decision
    approval_id: str | None  # only when actually spent — never a caller's unchecked claim
    approved_by: str | None


def _widened_return(returns: Any) -> Any:
    """The advertised return: what the body promises, or the §5.1 payload.

    A server validates a tool's result against this. A tool annotated `-> str`
    therefore fails when policy sends the call to a human and obstat returns the
    approval payload instead — the control reaches the client as a protocol
    error, which is the opposite of what §5.1 returns rather than raises for.
    """
    if returns is inspect.Signature.empty:
        return returns  # nothing declared, so nothing to validate against
    try:
        return returns | dict[str, Any]
    except TypeError:
        # `from __future__ import annotations` leaves the annotation a string,
        # and a string has no `|`. Servers resolve either form the same way.
        return f"{returns} | dict[str, Any]"


def _public_signature(original: inspect.Signature) -> inspect.Signature:
    """The signature callers see: `obstat_subject` removed, `obstat_approval_id`
    added, and the return widened to admit the approval payload.

    The subject is injected by obstat, so leaving it in the advertised schema
    would invite a client to supply its own. The approval id is the opposite —
    the retry protocol needs the caller to send it, so it has to be advertised.
    The return is widened for the same reason both of those are true: this
    signature describes what the wrapper does, not what the body does.
    """
    kept = [p for name, p in original.parameters.items() if name != SUBJECT_ARG]
    var_keyword = [p for p in kept if p.kind is inspect.Parameter.VAR_KEYWORD]
    positional = [p for p in kept if p.kind is not inspect.Parameter.VAR_KEYWORD]
    approval_param = inspect.Parameter(
        APPROVAL_ARG,
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation="str | None",
    )
    return original.replace(
        parameters=[*positional, approval_param, *var_keyword],
        return_annotation=_widened_return(original.return_annotation),
    )


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
    record_args: tuple[str, ...] = (),
):
    """Wrap a tool so that no call happens without a written decision.

        @guard(resource="jira_issue:{issue_key}")
        def transition_issue(issue_key: str, transition: str) -> str:
            ...

    `resource` is a format template over the call arguments, or a callable that
    takes them. Omit it and the resource is `tool:<name>`, which is enough when
    the tool is the only thing policy needs to distinguish.

    `record_args` names the parameters whose **values** go into the record; every
    other argument stays a digest and nothing else (§6.1). Name identifiers, not
    payloads — the point is that an approver can tell which issue, which
    document, which recipient, not that the log holds a copy of the message.

    To record what the call *did* rather than what it was allowed to do, call
    `obstat.note(...)` from inside the body (§6.2). Arguments naming a set say
    nothing about how big the set turned out to be.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = tool or fn.__name__
        original = inspect.signature(fn)
        params = list(original.parameters.values())
        # Until 0.4.0 the caller was injected into a parameter called `subject`.
        # A tool that still declares one would now be handed nothing at all, and
        # would carry on with `None` as though nobody were calling — so it is
        # refused here rather than discovered from a record that says `anonymous`
        # about a caller obstat knew.
        legacy = original.parameters.get("subject")
        if legacy is not None and "Subject" in str(legacy.annotation):
            raise TypeError(
                f"{name}: the caller is injected into `{SUBJECT_ARG}` since 0.4.0, not "
                "`subject`. Rename the parameter — left as it is, it would receive None "
                "on every call."
            )
        wants_subject = SUBJECT_ARG in original.parameters
        if wants_subject:
            # Injected by keyword while positional arguments pass through
            # unchanged, so a parameter fillable by position after it would
            # receive the caller's value for something else (§4.1). Raised at
            # decoration rather than at call time, where the `allow` record is
            # already on disk and the failure reads as a call that broke after
            # being authorised.
            after = params[[p.name for p in params].index(SUBJECT_ARG) + 1 :]
            by_keyword = (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.VAR_KEYWORD)
            if original.parameters[SUBJECT_ARG].kind is inspect.Parameter.POSITIONAL_ONLY or any(
                p.kind not in by_keyword for p in after
            ):
                raise TypeError(
                    f"{name}: obstat injects `{SUBJECT_ARG}` by keyword, so it must come "
                    f"last or be keyword-only (`*, {SUBJECT_ARG}: Subject | None = None`)"
                )
        public = _public_signature(original)
        # Arguments are bound against the public signature minus the approval id,
        # so the digest covers what the tool will actually receive and nothing else.
        bind_against = public.replace(
            parameters=[p for p in public.parameters.values() if p.name != APPROVAL_ARG]
        )
        unknown = set(record_args) - set(bind_against.parameters)
        if unknown:
            # A name that matches no parameter would record nothing and say
            # nothing about it — the same quiet, widening failure §2 refuses to
            # accept from a typo'd policy key.
            raise TypeError(
                f"{name}: record_args names no such parameter: {', '.join(sorted(unknown))}"
            )

        def refuse(
            code: str,
            reason: str,
            *,
            subject: str = policy.ANONYMOUS,
            resource_id: str | None = None,
            args_digest: str | None = None,
            rule: int | None = None,
            policy_digest: str | None = None,
            approval_id: str | None = None,
            extra: dict[str, Any] | None = None,
        ) -> Denied:
            return Denied(
                record.decision(
                    tool=name,
                    subject=subject,
                    resource=resource_id or f"tool:{name}",
                    effect="deny",
                    code=code,
                    reason=reason,
                    rule=rule,
                    args_digest=args_digest or record.digest({}),
                    policy_digest=policy_digest,
                    approval_id=approval_id,
                    extra=extra,
                )
            )

        def check(args: tuple, kwargs: dict) -> _Checked:
            """Steps 1-5. Raises Denied, raises _Pending, or returns."""
            approval_id = kwargs.pop(APPROVAL_ARG, None)

            # 1. `obstat_subject` is not advertised, so its presence is a caller
            #    trying to say who it is. Denied before anything reads it —
            #    including the record, which would otherwise quote an attacker's
            #    string. A plain `subject` is now the tool's own business.
            if SUBJECT_ARG in kwargs:
                raise refuse(SUBJECT_SUPPLIED, "caller supplied a subject")

            # Full bind, not partial: a call missing a required argument cannot
            # run, and binding it partially wrote `allow` for it and left the
            # TypeError to the body — a record claiming a call was authorised
            # when it was never executable. Refused here instead, which is what
            # §3.1 step 1b says happens.
            try:
                bound = bind_against.bind(*args, **kwargs)
            except TypeError as exc:
                raise refuse(ARGUMENTS_REJECTED, f"arguments do not fit the tool: {exc}") from exc
            bound.apply_defaults()
            call_args = dict(bound.arguments)
            args_digest = record.digest(call_args)
            # Only what the tool opted in to (§6.1). `in call_args` still guards
            # it: a **kwargs parameter is absent until something fills it.
            #
            # ponytail: values go in whole. Cap or elide them if someone
            # allowlists a parameter big enough to matter to a log that fsyncs.
            shown = {key: call_args[key] for key in record_args if key in call_args}
            # Built once: every record written from here down carries it, and a
            # site that quietly did not would be a record missing what the one
            # beside it has.
            recorded = {"args_recorded": shown} if shown else None

            who = _resolver()
            subject = str(who) if who is not None else policy.ANONYMOUS

            # 2. The stop file, before policy: stopping must not depend on the
            #    policy file still being parseable.
            if paths.halt().exists():
                raise refuse(
                    HALTED, "halted", subject=subject, args_digest=args_digest, extra=recorded
                )

            # 3. Resource. Everything, not a curated list: the callable is where
            #    §3.3 sends validation, so what it raises is a verdict to record,
            #    not a crash to propagate — an unrecorded refusal is half a control.
            try:
                target = _resource_for(resource, name, call_args)
            except Exception as exc:
                raise refuse(
                    RESOURCE_UNRESOLVED,
                    f"resource template did not resolve: {exc!r}",
                    subject=subject,
                    resource_id="unresolved",
                    args_digest=args_digest,
                    extra=recorded,
                ) from exc

            # 4. Policy. Evaluated once; step 6 records this verdict, not a re-read.
            verdict = policy.decide(tool=name, subject=subject, resource=target)
            refusal = functools.partial(
                refuse,
                subject=subject,
                resource_id=target,
                args_digest=args_digest,
                policy_digest=verdict.policy,
                extra=recorded,
            )
            if verdict.effect == "deny":
                raise refusal(verdict.code, verdict.reason, rule=verdict.rule)

            # 5. Approval.
            spent = False
            approver: str | None = None
            if verdict.effect == "approve":
                if approval_id is not None:
                    ok, code, why, approver = approval.consume(
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
                    if not ok and code != approval.PENDING:
                        raise refusal(code, why, rule=verdict.rule, approval_id=approval_id)
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
                        code=verdict.code,
                        reason=verdict.reason,
                        rule=verdict.rule,
                        args_digest=args_digest,
                        policy_digest=verdict.policy,
                        approval_id=wanted,
                        # The approver reads these off this record (§5.1): the
                        # approvals table holds a digest, and a human cannot
                        # decide about a digest.
                        extra=recorded,
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

            # `approval_id if spent`: on an outright allow the id was never
            # checked against anything, and recording it would repeat a caller's
            # claim that an approval existed — §1.2's rule, different field.
            return _Checked(
                who,
                subject,
                target,
                args_digest,
                shown,
                verdict,
                approval_id if spent else None,
                approver,
            )

        def authorise(args: tuple, kwargs: dict) -> tuple[str, dict]:
            """Steps 1-6. Returns the record id and the kwargs the body will get."""
            checked = check(args, kwargs)
            extra: dict[str, Any] = {
                "subject_verified": bool(checked.subject and checked.subject.verified)
            }
            # Omitted rather than empty (§6): a field on every record of every
            # deployment that never delegates is noise in the thing being read.
            if checked.subject and checked.subject.via:
                extra["via"] = list(checked.subject.via)
            if checked.shown:
                extra["args_recorded"] = checked.shown
            # Who said yes, into the chained log — the approvals database also
            # holds it, but that file is the one store here anyone can UPDATE.
            if checked.approved_by:
                extra["approved_by"] = checked.approved_by
            record_id = record.decision(
                tool=name,
                subject=checked.subject_name,
                resource=checked.resource,
                effect="allow",
                code=checked.verdict.code,
                reason=checked.verdict.reason,
                rule=checked.verdict.rule,
                args_digest=checked.args_digest,
                policy_digest=checked.verdict.policy,
                approval_id=checked.approval_id,
                extra=extra,
            )
            if wants_subject:
                kwargs = {**kwargs, SUBJECT_ARG: checked.subject}
            return record_id, kwargs

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    record_id, kwargs = authorise(args, dict(kwargs))
                except _Pending as pending:
                    return pending.payload()
                with record.noting() as noted:
                    try:
                        result = await fn(*args, **kwargs)
                    except Exception as exc:
                        # `__qualname__`, because a nested exception class has a
                        # `__name__` that identifies nothing: `imaplib.IMAP4.error`
                        # records as "error". Same leak-nothing property, one more
                        # dotted component.
                        record.outcome(
                            record_id, ok=False, error=type(exc).__qualname__, noted=noted
                        )
                        raise
                    # A body that failed half way still noted what it managed to
                    # do, and that half is the part a reader needs most.
                    record.outcome(record_id, ok=True, noted=noted)
                return result

        else:

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    record_id, kwargs = authorise(args, dict(kwargs))
                except _Pending as pending:
                    return pending.payload()
                with record.noting() as noted:
                    try:
                        result = fn(*args, **kwargs)
                    except Exception as exc:
                        record.outcome(
                            record_id, ok=False, error=type(exc).__qualname__, noted=noted
                        )
                        raise
                    record.outcome(record_id, ok=True, noted=noted)
                return result

        wrapper.__signature__ = public  # type: ignore[attr-defined]
        return wrapper

    return decorate
