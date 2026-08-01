# obstat — specification

Normative. Where this document and the code disagree, one of them is a bug; say
which in an issue.

The claim obstat makes is narrow: **a tool call leaves a written decision before
it runs.** Everything below exists to make that claim true without an identity
provider, a policy service or a cloud account standing behind it.

---

## 1. Subject

Identity is optional and it is the host application's business. obstat asks for
it through one resolver and never goes looking on its own.

```python
@dataclass(frozen=True)
class Subject:
    id: str
    kind: Literal["human", "agent", "service"] = "agent"
    via: tuple[str, ...] = ()
    verified: bool = False
```

| field | meaning |
|---|---|
| `id` | opaque, whatever the host calls this principal |
| `kind` | what sort of thing it is; policy can match on it |
| `via` | delegation chain, most recent first — who asked this principal to act |
| `verified` | whether the host authenticated it, or merely received a claim |

`str(subject)` is `"{kind}:{id}"`, and that string is what policy matches and what
the record stores. Absent identity is the string `anonymous`.

```python
set_subject_resolver(lambda: Subject(id=user(), kind="human", verified=True))
```

The resolver is called once per guarded call, with no arguments. Returning `None`
is legal and normal: a stdio MCP server on a laptop has no token, and demanding
one before obstat will run is how a governance library goes uninstalled. **An
anonymous call is a legitimate call.** It is recorded as such and the policy
decides what `anonymous` may do.

### 1.1 `verified` is a record field, not a gate

`verified=False` means the identity came from somewhere the caller could
influence — a header, an argument, a config file. obstat records it on every
decision and enforces nothing on it.

This is deliberate, and it is the weaker of the two available choices. The
alternative — refusing to match rules against unverified subjects — would push
every host without an IdP back to `anonymous`, which is the state the flag exists
to distinguish from. A reader of the record can tell "Ana did this" from
"something claimed to be Ana did this", which is the honest minimum. Gate on it
in your resolver by returning `None` instead of an unverified `Subject`.

### 1.2 A caller may not name itself

`subject` is removed from the wrapped function's advertised signature (§4.2), so
a client cannot supply one. If one arrives anyway the call is denied at step 1,
before anything reads the value — including the record, which would otherwise
quote an attacker's string back into the audit trail.

---

## 2. Policy

A TOML file. Rules are evaluated in file order and **the first match wins**.

```toml
[[rule]]
tool = "read_*"
effect = "allow"

[[rule]]
tool = "transition_issue"
resource = "jira_issue:*"
effect = "approve"
```

| key | matched against | default |
|---|---|---|
| `tool` | the function name, or the decorator's `tool=` | `*` |
| `subject` | `str(subject)`, or `anonymous` | `*` |
| `resource` | the resolved resource id (§4.3) | `*` |
| `effect` | one of `allow`, `deny`, `approve` | **required** |

Patterns are `fnmatch` globs, matched case-sensitively. An unknown key in a rule
is an error rather than a warning: a typo'd `resources = "..."` would otherwise
leave the rule matching every resource, which is the widest possible failure and
the quietest.

### 2.1 Nothing matching is a deny

An absent rule is not permission. A file that parses but matches nothing denies
with reason `no rule matched`.

A **missing policy file raises `PolicyError`** on the first guarded call. It is
not an implicit allow and not an implicit deny — the difference matters, because
an implicit deny looks like a working installation with a strict policy, and the
operator finds out otherwise only when they read the record.

### 2.2 Reloading

The file is re-read when its `(mtime, size)` changes, so editing policy takes
effect on the next call rather than the next restart. The cost is one `stat()`
per call, which is cheaper than the class of incident where someone tightened a
rule, saw no change, and concluded the tightening was wrong.

---

## 3. `@guard`

```python
def guard(
    *,
    resource: str | Callable[[dict[str, Any]], str] | None = None,
    tool: str | None = None,
) -> Callable[[F], F]: ...
```

Supports `def` and `async def`. Composes beneath the MCP decorator, which must be
outermost so that what the server advertises is the guarded signature:

```python
@mcp.tool()
@guard(resource="jira_issue:{issue_key}")
async def transition_issue(issue_key: str, transition: str) -> str: ...
```

### 3.1 Enforcement order

Normative. Each step's failure is terminal.

| # | Step | Deny reason |
|---|---|---|
| 1 | Reject a caller-supplied `subject` argument | `caller supplied a subject` |
| 1b | Bind arguments to the tool's signature | `arguments do not fit the tool: …` |
| 2 | Stop file present (§3.4) | `halted` |
| 3 | Resolve the resource id from the arguments | `resource template did not resolve: …` |
| 4 | Policy decision (§2) | `no rule matched` · `rule {n}` |
| 5 | Approval, if policy said `approve` (§5) | — returns `approval_required`, or a §5.3 reason |
| 6 | **Write the decision record — durable** (§6) | propagates |
| 7 | Execute the tool body | — |
| 8 | Write the outcome record, best effort | — never denies |

**Step 6 before step 7 is the whole point.** `record.decision()` returns only
after `write`, `flush` and `fsync`. If the process dies between 6 and 7, the
record says `allow` and no outcome follows, which reads as "authorised, did not
complete" — a state an examiner can act on. The reverse ordering produces
"executed, no idea whether it was allowed", which is the state that costs an
audit.

Step 2 precedes policy so that stopping never depends on the policy file still
being parseable. Step 1 precedes argument binding so that a forged `subject`
cannot reach the record even as a rejected value.

Denials at every step write a record before raising. A denial nobody can read is
half a control.

### 3.2 Denial response

`Denied` is raised, carrying exactly:

```
Not permitted. Do not retry. Reference: {record_id}
```

No resource name, no rule number, no reason, and no distinction between "does
not exist" and "not allowed" — otherwise the tool becomes an existence oracle for
anything the caller can name. The reason goes to the record, where an operator
reads it and the agent does not. "Do not retry" is load-bearing: agents loop on
ambiguous errors.

`record_id` is on the exception as `.record_id` as well as in the message.

### 3.3 Resource resolution

`resource` is a format template over the bound call arguments, or a callable
taking them:

```python
@guard(resource="doc:{doc_id}")
@guard(resource=lambda a: f"doc:{a['doc_id'].lower()}")
```

Omitted, the resource is `tool:{name}` — enough when the tool is the only thing
policy needs to distinguish. A template that raises (`KeyError`, `IndexError`,
`AttributeError`, `TypeError`) denies with the resource recorded as `unresolved`.
It never falls back to a wildcard.

### 3.4 The stop file

Every other control answers "may this call proceed". This one answers "is
anything allowed to proceed at all" — the question asked at 04:00 by someone who
does not yet know what is wrong.

```console
obstat stop      # creates .obstat/halt
obstat resume    # removes it
```

Presence denies every guarded call in every process reading that path. It is a
file rather than a config value so that pressing it needs no deploy, no restart
and no credentials beyond write access to a directory.

**Granularity is deliberately absent here.** Airlock's equivalent matches
patterns per subject and per tool; obstat's is all-or-nothing. An all-or-nothing
button is one people hesitate to press, and hesitation is the failure it exists
to prevent — so this is a known weakness, listed in §8, not a settled design.

---

## 4. What callers see

### 4.1 Injected `subject`

Declare a `subject` parameter and obstat passes the resolved `Subject` (or
`None`). Omit it and nothing is injected. Either way the parameter is stripped
from the advertised signature.

### 4.2 The advertised signature

The wrapper's `__signature__` is the wrapped function's, minus `subject`, plus:

```python
obstat_approval_id: str | None = None   # keyword-only
```

MCP servers generate their tool schema from that signature, so a client sees the
approval argument — it needs to, for §5.2 — and cannot see `subject`. Verified
against the MCP SDK in the example server: `delete_document` advertises
`['doc_id', 'obstat_approval_id']`.

---

## 5. Approval protocol

An MCP call cannot block for a human. Approval is therefore a two-phase exchange
across two tool calls, and the agent is never left waiting on a person.

### 5.1 Phase 1 — request

Policy said `approve` and no approval id was supplied. obstat:

1. Writes a decision record with `effect: "approval_required"`.
2. Inserts a `pending` row bound to `(tool, subject, resource, args_digest)`,
   with `expires = now + 900s`.
3. Returns — **does not raise** — this value:

```python
{"obstat": "approval_required",
 "approval_id": "d41b88f29a43",
 "expires_in_seconds": 900,
 "record": "814e0978bd10…",
 "retry": "A human must approve this call. …"}
```

A return rather than an error, so the agent can reason about it and tell the user
what it is waiting for instead of treating a working control as a failure.

### 5.2 Phase 2 — retry

The agent calls the same tool with the same arguments plus
`obstat_approval_id=…`. The approval is spent only if **all** of these hold:

- state is `approved`
- `expires` is in the future
- `tool` matches
- `subject` matches
- `resource` matches
- `args_digest` matches

The last four are the security property. Without them an approval for
`delete q3-report` is replayable as `delete everything-else`, and an approval
granted to one principal is usable by another.

The check and the state transition to `consumed` happen inside one
`BEGIN IMMEDIATE` transaction, so two concurrent retries cannot both win.
**Approvals are single-use.**

### 5.3 State machine

```
pending ──approve──► approved ──use──► consumed
   │                     │
   └──deny────────► denied
```

| state at retry | result | reason recorded |
|---|---|---|
| absent | deny | `unknown approval` |
| `pending` | deny | `approval is pending` |
| `denied` | deny | `approval is denied` |
| `consumed` | deny | `approval already used` |
| `approved`, past `expires` | deny | `approval expired` |
| `approved`, binding mismatch | deny | `approval was granted for a different {field}` |
| `approved`, all checks pass | allow | — |

Expiry is not a state; it is `expires < now` evaluated at use, and `obstat
pending` hides rows past it. **A TTL elapsing denies** — never approve on
timeout.

`approval is pending` being a hard deny is a **known divergence from Airlock**,
which returns the phase-1 payload again so that an agent polling ahead of a slow
human is not told "do not retry". See §8.

### 5.4 Who approves

`obstat approve <id> --by <name>` records `decided_by` and `decided_at`. That is
the entire authority model: anyone who can run the CLI against the database can
decide, and `--by` is unauthenticated self-assertion.

This is honest for a single-operator local deployment and inadequate for anything
else. Segregation of duties — that the approver is entitled to approve, and is
not the requester — is what an ITGC walkthrough tests, and obstat does not
implement it. §8.

---

## 6. The decision record

JSONL, one object per line, appended with `O_APPEND` so concurrent writers
interleave records but never split one.

```json
{"schema": 1,
 "id": "6430f1a38f8e470a898ca9a116dfb4cc",
 "ts": 1785545412.241792,
 "phase": "decision",
 "tool": "delete_document",
 "subject": "anonymous",
 "resource": "doc:q3-report",
 "effect": "allow",
 "reason": "rule 1",
 "rule": 1,
 "args": "sha256:ae32e699…",
 "approval_id": "d41b88f29a43",
 "subject_verified": false}
```

`effect` is one of `allow`, `deny`, `approval_required`. `rule` is the index into
the policy file, so a record points at the line that decided it.

### 6.1 Arguments are fingerprinted, not stored

`args` is `sha256:` over the canonical JSON of the bound arguments. The values
are deliberately absent: tool arguments carry credentials, personal data and free
text, and a governance log that leaks them is a liability rather than a control.
The digest is enough to prove the call that executed is the call that was
approved, which is what the record is for.

### 6.2 Outcome records

```json
{"schema": 1, "id": "<same id>", "ts": …, "phase": "outcome", "ok": true, "error": null}
```

`error` is the exception class name, never its message — messages carry the same
data the arguments do.

Written after execution, **not** durable, and never able to fail a call: `OSError`
here is suppressed. If the process dies between the body and this line, the
decision record stands alone and reads as "authorised, outcome unknown", which is
the honest state. A second `fsync` for something merely informative is paying
twice for half the value.

---

## 7. Configuration

Read at call time, never at import. A library that raises `ConfigError` on import
is a library nobody can try.

| variable | default |
|---|---|
| `OBSTAT_POLICY` | `obstat.toml` |
| `OBSTAT_LOG` | `.obstat/decisions.jsonl` |
| `OBSTAT_DB` | `.obstat/approvals.db` |
| `OBSTAT_HALT` | `.obstat/halt` |

---

## 8. Still open

Ranked by how much they weaken the claim in the first paragraph.

**Phase-1 requests are not deduplicated.** Each retry without an approval id
opens a *new* pending approval, so an agent polling a slow human produces a queue
of duplicates. Airlock solved this by deriving the approval id deterministically
from `subject | tool | args`, so a retry rejoins the approval already waiting.
obstat should do the same, and `pending` should then return the phase-1 payload
rather than denying (§5.3).

**No approver authority.** §5.4. Anything beyond a single operator needs the
approver to be authenticated and distinct from the requester.

**The stop file is all-or-nothing.** §3.4.

**Deny reasons are prose, not codes.** They are stable enough to assert on in
tests and unstable enough that no one should parse them. They want to be an enum
with the prose as a separate field.

**No retention, rotation or integrity protection on the log.** An append-only
file that anyone can rewrite proves less than it appears to. Append-only storage
and per-record hash chaining are the obvious answers; neither is here.

**No egress control.** Nothing asks where a result is allowed to go, which is the
control that matters for tools that send mail or post to channels.

**Approval channels are the CLI only.** Slack and webhook belong at the edges as
adapters, not dependencies.

---

## 9. Required tests

These encode the claims above; `tests/test_guard.py` is the current
implementation of them.

| Property | Test |
|---|---|
| the record is durable before the body runs | reads the log from inside the body and asserts its own decision is already there |
| an outcome follows a decision, sharing its id | `test_outcome_is_recorded_after` |
| a failing body still leaves both records | `test_a_failing_body_still_leaves_both_records` |
| nothing matching denies | `test_no_rule_is_a_deny` |
| a missing policy is not an implicit allow | `test_missing_policy_is_not_an_implicit_allow` |
| a caller cannot name itself | `test_a_caller_cannot_supply_its_own_subject` |
| `subject` unadvertised, approval id advertised | `test_injected_subject_is_not_advertised…` |
| the resource comes from the arguments | `test_resource_comes_from_the_arguments` |
| an unresolvable resource denies | `test_an_unresolvable_resource_denies` |
| arguments are fingerprinted, not stored | `test_arguments_are_fingerprinted_not_stored` |
| the stop file denies, and lifting it restores | `test_the_stop_file_denies_everything` |
| approval is two-phase and does not run early | `TestApproval::test_first_call_asks_and_does_not_run` |
| approval is single-use | `TestApproval::test_retry_after_approval_runs_once` |
| approval does not travel to another call | `TestApproval::test_an_approval_does_not_travel_to_another_call` |
| a denied or invented approval denies | `TestApproval::test_a_denied_approval_denies`, `…invented_approval_id…` |
| async tools take the same path | `test_async_tools_go_through_the_same_gate` |
