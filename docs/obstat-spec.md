# obstat — specification

Normative, §10 excepted. Where this document and the code disagree, one of them
is a bug; say which in an issue.

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
| `via` | delegation chain, most recent first — who asked this principal to act; recorded when non-empty (§6) |
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

### 2.3 Writing one, and asking what it would do

```console
obstat init                                    # a starter obstat.toml
obstat check delete_document doc:q3-report     # deny (rule 0)
obstat check read_doc --subject human:ana      # allow (rule 1)
```

`init` writes every rule commented out and one live `deny`, so a policy nobody
finished editing permits nothing. It refuses to overwrite an existing file: that
file is the only thing standing between an agent and every guarded tool.

`check` evaluates §2 against the file on disk and prints the effect with the rule
that produced it. The resource argument is optional and defaults to
`tool:<name>`, the same default §3.3 applies. Exit status is 0 for `allow` and 1
for anything else, including a policy that does not parse — which is otherwise
discovered by the next real call, in front of a real agent.

It writes no record, resolves no resource and touches no approval. It answers
what the policy *would* say, which is the question §2.2's reload leaves a reader
unable to ask.

---

## 3. `@guard`

```python
def guard(
    *,
    resource: str | Callable[[dict[str, Any]], str] | None = None,
    tool: str | None = None,
    record_args: tuple[str, ...] = (),
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

| # | Step | Code (§6.4) | Prose reason |
|---|---|---|---|
| 1 | Reject a caller-supplied `subject` argument | `subject_supplied` | `caller supplied a subject` |
| 1b | Bind arguments to the tool's signature | `arguments_rejected` | `arguments do not fit the tool: …` |
| 2 | Stop file present (§3.4) | `halted` | `halted` |
| 3 | Resolve the resource id from the arguments | `resource_unresolved` | `resource template did not resolve: …` |
| 4 | Policy decision (§2) | `no_rule_matched` · `rule_matched` | `no rule matched` · `rule {n}` |
| 5 | Approval, if policy said `approve` (§5) | §5.3 | — returns `approval_required`, or a §5.3 reason |
| 6 | **Write the decision record — durable** (§6) | — | propagates |
| 7 | Execute the tool body | — | — |
| 8 | Write the outcome record, best effort | — | never denies |

**Step 6 before step 7 is the whole point.** `record.decision()` returns only
after `write` and `fsync` — and, on the write that creates the log file, an
`fsync` of the containing directory too, since a synced file whose directory
entry is not synced can survive a crash with nothing pointing at it. That
directory sync opens a directory as a file descriptor, which POSIX allows and
Windows does not — §8. If the
process dies between 6 and 7, the
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

It must be **keyword-only, or the last parameter**:

```python
def delete_document(doc_id: str, *, subject: Subject | None = None) -> str: ...
```

obstat injects it by keyword and passes the caller's positional arguments
through unchanged, against a signature that no longer contains `subject` — so
any parameter fillable by position *after* `subject` would receive the caller's
value for something else. `@guard` raises `TypeError` at decoration rather than
at call time, because at call time the `allow` record is already on disk and the
failure reads as a call that was authorised and then broke.

### 4.2 The advertised signature

The wrapper's `__signature__` is the wrapped function's, minus `subject`, plus:

```python
obstat_approval_id: str | None = None  # keyword-only
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

Policy said `approve` and no usable approval was supplied. obstat:

1. Derives the approval id: `sha256(tool | subject | resource | args_digest)[:12]`.
2. Writes a decision record with `effect: "approval_required"`, naming that id.
3. Inserts a `pending` row bound to `(tool, subject, resource, args_digest)` with
   `expires = now + 900s` — **or rejoins** the row already there, if one is still
   `pending` or `approved` and unexpired.
4. Returns — **does not raise** — this value:

```python
{
    "obstat": "approval_required",
    "approval_id": "d41b88f29a43",
    "expires_in_seconds": 900,
    "record": "814e0978bd10…",
    "waiting": False,
    "retry": "A human must approve this call. …",
}
```

A return rather than an error, so the agent can reason about it and tell the user
what it is waiting for instead of treating a working control as a failure.
`waiting` is `True` when this rejoined an existing request, which is how an agent
distinguishes "asked" from "asked again".

The approvals table holds the argument *digest*, so `obstat pending` reads what
the call was for off the record named in step 2 — anything the tool recorded
under §6.1 is printed beneath the row:

```console
$ obstat pending
d41b88f29a43  send_email  human:ana  tool:send_email  871s left
      to = 'board@example.com'
```

**The id is derived, not invented.** A random id would mean every retry opens
another approval, so an agent polling a slow human produces a queue of identical
requests for that human to sort out — and the pile-up is worst exactly when
someone is already too busy to answer. Deriving it from the call makes a retry
rejoin the request already waiting.

A row that is terminal (`consumed`, `denied`) or expired is *replaced* rather
than rejoined. The same call made twice on purpose is not a replay, and must be
able to get its own approval.

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

| state at retry | result | code recorded | prose reason |
|---|---|---|---|
| binding mismatch | deny | `approval_mismatch` | `approval was granted for a different {field}` |
| absent | deny | `approval_unknown` | `unknown approval` |
| `pending` | **§5.1 payload again** | — | — |
| `denied` | deny | `approval_denied` | `approval is denied` |
| `consumed` | deny | `approval_used` | `approval already used` |
| past `expires` | deny | `approval_expired` | `approval expired` |
| `approved`, all checks pass | allow | `rule_matched` | `rule {n}` |

`approval_pending` is the one code the guard **branches on** rather than merely
records: it is what distinguishes "come back later" from a denial. Before codes
existed that branch compared an interpolated sentence, so renaming a SQLite state
would have turned every slow approval into a failed call.

The binding check runs **before** anything is said about state, so a caller
holding someone else's id learns that it does not match this call rather than
what is happening to that approval.

Expiry is not a state; it is `expires < now` evaluated at use, and `obstat
pending` hides rows past it. **A TTL elapsing denies** — never approve on
timeout.

A retry against a `pending` approval is not a denial. It returns §5.1's payload
with `waiting: True`, because telling an agent "do not retry" while the
notification is still on somebody's phone turns a slow approver into a failed
call and makes the eventual approval worthless. `denied`, `consumed` and expired
remain hard denials.

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
interleave records but never split one. Each record is a single unbuffered
`write()`, which is what makes that true — a buffered text write splits anything
past its buffer into several syscalls, and only one syscall is atomic. Within a
process one lock covers hashing and appending together (§6.3); across processes
there is still no lock.

A write cut short by a full disk leaves a fragment with no closing newline. The
next record starts on a fresh line rather than splicing itself onto that
fragment, so one failed write costs one record instead of two — `obstat verify`
reports the fragment and everything after it still reads.

```json
{"schema": 4,
 "id": "6430f1a38f8e470a898ca9a116dfb4cc",
 "ts": 1785545412.241792,
 "phase": "decision",
 "tool": "delete_document",
 "subject": "anonymous",
 "resource": "doc:q3-report",
 "effect": "allow",
 "code": "rule_matched",
 "reason": "rule 1",
 "rule": 1,
 "args": "sha256:ae32e699…",
 "approval_id": "d41b88f29a43",
 "subject_verified": false,
 "prev": "sha256:1f0c4b7d…",
 "hash": "sha256:9d2ae410…"}
```

`effect` is one of `allow`, `deny`, `approval_required`. `rule` is the index into
the policy file, so a record points at the line that decided it. `prev` and
`hash` are the chain (§6.3).

Schema 2 added `prev` and `hash`; schema 3 added `code`; schema 4 added
`args_recorded` (§6.1). Records written at schema 1 have no chain fields and
verify as *unverifiable* rather than as damaged — a log that predates the chain is
not evidence of tampering.

`via` (§1) is present on an `allow` record only when the subject carries a
delegation chain: `"via": ["human:ana"]`. It is omitted rather than written empty,
because `"via": []` on every record of every deployment that never delegates is
noise in the thing an examiner has to read. `args_recorded` is omitted on the
same grounds.

### 6.1 Arguments are fingerprinted, and named values are recorded

`args` is `sha256:` over the canonical JSON of the bound arguments. The values
are absent by default: tool arguments carry credentials, personal data and free
text, and a governance log that leaks them is a liability rather than a control.
The digest is enough to prove the call that executed is the call that was
approved, which is what the record is for.

A digest is not enough for the *other* reader. An approver deciding about
`sha256:ae32e6…` is deciding about nothing, and the resource id only sometimes
carries the answer — `doc:q3-report` does, `tool:send_email` does not. So a tool
may name parameters whose values are recorded:

```python
@guard(record_args=("to", "issue_key"))
```

```json
"args_recorded": {"to": "ana@example.com", "issue_key": "ACME-14"}
```

Normative:

- The allowlist is **explicit and per tool**. There is no wildcard and no
  "record everything" switch — the absent default is the safe one, and a
  deployment that wants values names them.
- Naming a parameter the tool does not have is a `TypeError` **at decoration**.
  A name that matched nothing would record nothing and say nothing about it,
  which is the same quiet widening §2 refuses from a typo'd policy key.
- `args` still covers **every** argument. Recorded values are written beside the
  digest, never instead of it, so the binding an approval rests on (§5.2) is
  unchanged by what anyone chose to display.
- The field is omitted when nothing was named, on the §6 grounds `via` is.
- It appears on `allow`, `deny` and `approval_required` records alike: an
  examiner asking what was refused deserves the same answer as an approver
  asking what is waiting.

Name identifiers, not payloads. The point is that a human can tell which issue,
which document, which recipient — not that the log holds a copy of the message.

### 6.2 Outcome records

```json
{"schema": 4, "id": "<same id>", "ts": …, "phase": "outcome", "ok": true, "error": null,
 "prev": "…", "hash": "…"}
```

`error` is the exception class name, never its message — messages carry the same
data the arguments do.

Written after execution, **not** durable, and never able to fail a call: `OSError`
here is suppressed. If the process dies between the body and this line, the
decision record stands alone and reads as "authorised, outcome unknown", which is
the honest state. A second `fsync` for something merely informative is paying
twice for half the value.

Outcome records are in the chain even though they are not durable. `ok` and
`error` are worth as much to a reader as the decision itself, and a record left
out of the chain is a record anyone may rewrite freely.

### 6.3 The chain

Every record carries `hash`, the SHA-256 of its own remaining fields serialised
with sorted keys, and `prev`, the `hash` of the record before it. `obstat verify`
recomputes both for every line.

```console
$ obstat verify
chain intact

$ obstat verify
line 3: record cd53f9db… follows a record that is no longer in the log
```

Exit status is 1 when anything is reported.

The predecessor is read from the file once per process, so restarting a server
continues the chain rather than starting a second one beside it. Within a process
the read and the append happen under one lock, so records are hashed in the order
they land.

**Concurrent processes fork the chain**, and that is accepted rather than
prevented. Two servers appending to one log both chain from the record they last
saw, so the file holds interleaved strands instead of one line. Verification does
not care: it checks that each `prev` names a record still present earlier in the
file, which holds for a forked chain and fails for a removed one. The alternative
— an inter-process lock around every decision — would put a file lock on the path
that exists to be fast enough to sit in front of every tool call.

#### What this catches, and what it does not

Caught:

- a record whose contents were edited, whether or not its `hash` was recomputed
- a record removed from anywhere but the end
- a line that no longer parses

Not caught, and neither is an oversight:

- **records removed from the end.** Nothing points at them. Detecting a truncated
  tail needs a counter-signed head published somewhere the log's owner does not
  control.
- **a wholesale rewrite.** The chain is unkeyed, so anyone who can write the file
  can recompute every hash in it. This is tamper-*evidence* — it raises the cost
  of a quiet edit from `sed` to a deliberate forgery, and it makes an accidental
  edit obvious. It is not non-repudiation, and §8 says so.

A damaged log does not stop a guarded call. The new record chains from `null` and
`obstat verify` reports the break, because refusing to serve on a corrupt log
would let anyone who can append one byte turn every guarded tool off.

### 6.4 Codes and prose

Every decision record carries both:

| field | for | stability |
|---|---|---|
| `code` | filtering a log, branching in code, asserting in tests | **stable**; a change is a schema change |
| `reason` | the operator reading one record | free text, may be reworded at any time |

The full set of codes is the §3.1 and §5.3 tables. They are lower-case snake, the
same shape as `effect`.

The split exists because the two jobs conflict. `approval was granted for a
different resource` tells an examiner exactly what happened and is useless to
`jq`; `approval_mismatch` is the reverse. Carrying one field and asking it to do
both is how a log ends up with code branching on an interpolated sentence — which
is what obstat did until schema 3, in the one place it mattered most (§5.3).

Prose still carries detail no code should: which binding failed, which exception a
resource template raised. Assert on the code; read the reason.

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

**No approver authority.** §5.4. Anything beyond a single operator needs the
approver to be authenticated and distinct from the requester.

**An approver sees only what the tool chose to show.** §6.1 gives a tool
`record_args`, and `obstat pending` prints it — but a tool that names nothing
still sends a human a digest and a resource id to decide on. Nothing warns an
operator that a rule with `effect = "approve"` sits in front of a tool that
records no values, which is the configuration where the approval is a rubber
stamp.

**The chain is unkeyed, and nothing anchors its head.** §6.3 makes an edit or a
deletion visible, which is where most of the value is — but anyone who can write
the log can recompute every hash in it, and a truncated tail leaves nothing
dangling. The answers are a head published where the log's owner cannot reach it,
or append-only storage. Neither is here, so this is tamper-evidence and not proof
against the operator.

**The stop file is all-or-nothing.** §3.4.

**The approval TTL is fixed.** 900 seconds, a module constant, absent from §7
while every path beside it is configurable. A request raised after hours expires
unanswered, and §5.3 is explicit that expiry denies.

**No retention or rotation on the log.** It grows without bound, and nothing says
how long a record must be kept. Rotation has to carry the chain across files as
well, or every new file begins at `prev: null` and a deletion at the seam is
indistinguishable from a rollover.

**POSIX only, without saying so.** The directory sync in §3.1 opens a directory
as a file descriptor, which Windows refuses, so the write that *creates* the log
fails there; every write after it would be fine, which makes this a first-run
failure rather than a degradation. Either that sync is skipped where it cannot be
done — losing the guarantee it exists for — or the package declares POSIX. It
currently does neither.

**No egress control.** Nothing asks where a result is allowed to go, which is the
control that matters for tools that send mail or post to channels.

**Approval channels are the CLI only.** Slack and webhook belong at the edges as
adapters, not dependencies.

---

## 9. Required tests

These encode the claims above; `tests/test_guard.py` is the current
implementation of them, with §2.3's two commands in `tests/test_cli.py`.

| Property | Test |
|---|---|
| a starter policy parses and permits nothing | `test_init_writes_a_policy_that_permits_nothing` |
| `init` does not overwrite a policy | `test_init_will_not_overwrite_a_policy` |
| `check` names the rule that decided | `test_check_names_the_rule_that_decided` |
| a broken policy is reported, not raised | `test_check_reports_a_broken_policy_instead_of_raising` |
| the record is durable before the body runs | reads the log from inside the body and asserts its own decision is already there |
| an outcome follows a decision, sharing its id | `test_outcome_is_recorded_after` |
| a failing body still leaves both records | `test_a_failing_body_still_leaves_both_records` |
| nothing matching denies | `test_no_rule_is_a_deny` |
| a missing policy is not an implicit allow | `test_missing_policy_is_not_an_implicit_allow` |
| a caller cannot name itself | `test_a_caller_cannot_supply_its_own_subject` |
| a colliding `subject` parameter is refused at decoration | `test_a_subject_that_would_collide_is_refused_at_decoration` |
| a delegation chain reaches the record | `test_a_delegation_chain_reaches_the_record` |
| an edited record is caught | `TestChain::test_an_edited_record_is_caught` |
| a removed record is caught | `TestChain::test_a_removed_record_is_caught` |
| recomputing one hash does not hide the edit | `TestChain::test_a_reused_hash_does_not_hide_an_edit` |
| a torn line does not swallow the next record | `TestChain::test_a_torn_line_does_not_swallow_the_next_record` |
| `subject` unadvertised, approval id advertised | `test_injected_subject_is_not_advertised…` |
| the resource comes from the arguments | `test_resource_comes_from_the_arguments` |
| an unresolvable resource denies | `test_an_unresolvable_resource_denies` |
| arguments are fingerprinted, not stored | `test_arguments_are_fingerprinted_not_stored` |
| only the named arguments are recorded | `test_only_the_named_arguments_are_recorded` |
| nothing is recorded unless it was named | `test_nothing_is_recorded_unless_it_was_named` |
| an argument that does not exist is refused at decoration | `test_recording_an_argument_that_does_not_exist_is_refused_at_decoration` |
| a denial records the named arguments | `test_a_denial_records_the_named_arguments` |
| an approver can see what they are approving | `test_pending_shows_what_is_being_approved` |
| the stop file denies, and lifting it restores | `test_the_stop_file_denies_everything` |
| approval is two-phase and does not run early | `TestApproval::test_first_call_asks_and_does_not_run` |
| approval is single-use | `TestApproval::test_retry_after_approval_runs_once` |
| asking twice rejoins one approval | `TestApproval::test_asking_twice_rejoins_one_approval` |
| retrying before a human answers is not a denial | `TestApproval::test_retrying_before_a_human_answers…` |
| the same call can be approved again later | `TestApproval::test_the_same_call_can_be_approved_again_later` |
| approval does not travel to another call | `TestApproval::test_an_approval_does_not_travel_to_another_call` |
| a denied or invented approval denies | `TestApproval::test_a_denied_approval_denies`, `…invented_approval_id…` |
| async tools take the same path | `test_async_tools_go_through_the_same_gate` |

---

## 10. Direction

**Not normative. Nothing in this section is implemented**, and code that
disagrees with it is not a bug. It is here so a reader can tell a missing feature
from an undecided one: §8 is what is weak, this is what is next.

**Shadow mode, and a policy written from traffic.** Decisions recorded without
being enforced, so obstat can be installed in front of a live server for a week
before it denies anything — then `obstat suggest` reads the log back and emits
candidate rules. Policy authoring is the barrier to adoption, and an empty file
is not a starting point.

**Counterfactual replay.** `obstat check --policy new.toml --against
decisions.jsonl`: run decisions already recorded through a proposed policy and
print only what changes. Answers "I tightened a rule, what breaks" from real
traffic rather than from imagination, and needs nothing that §2 and §6 do not
already provide.

**An evidence pack.** One command producing what a controls walkthrough asks
for over a period: every call that required an approval, who decided it and
when, every denial, and the result of §6.3 across the same range. The log is
already the input; what is missing is the deliverable.

**An anchored head.** §8. Counter-signing the chain head somewhere the log's
owner cannot reach is the difference between tamper-evidence and
non-repudiation, and it is the only item here that changes what obstat can
*claim*.

**Result digests.** §6.1 fingerprints the arguments, which proves the call that
ran is the call that was approved. The same over the return value would say
something about what came back, and is the groundwork any egress rule needs.

**Break-glass with a retrospective.** The stop file's opposite: one call
permitted against policy, recorded as an override, and listed as outstanding
until somebody signs it off. That it is visible matters more than that it is
rare.

**The record as a format rather than a library.** §6 is language-agnostic. A
second implementation writing the same lines, verified by the same rules, would
make this document the product and the Python package one implementation of it.

Also wanted and unremarkable: approval channels beyond the CLI (§8), per-subject
call budgets as a rule key, and a trace id on the record so it joins traces a
host already collects.
