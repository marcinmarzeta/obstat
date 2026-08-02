# obstat

[![PyPI](https://img.shields.io/pypi/v/obstat)](https://pypi.org/project/obstat/)
[![Python](https://img.shields.io/pypi/pyversions/obstat)](https://pypi.org/project/obstat/)
[![CI](https://github.com/marcinmarzeta/obstat/actions/workflows/ci.yml/badge.svg)](https://github.com/marcinmarzeta/obstat/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/obstat)](LICENSE)

**An auditable decision record for agent tool calls.** The clearance is written
down before the call runs — not reconstructed from logs afterwards.

*Nihil obstat*: nothing stands in the way. It was the formal clearance a censor
granted **in writing, before publication**. That is the whole idea here. An agent
asks to do something, a rule decides, and the decision goes to disk *before* the
tool body executes. If the process dies mid-call, the record still says what was
authorised and why.

```bash
pip install obstat
```

No dependencies. Not AWS, not an identity provider, not a policy service — the
decorator, `tomllib`, `sqlite3` and a file.

[`docs/obstat-spec.md`](docs/obstat-spec.md) is normative, and its §8 lists what
is still weak.

## 60 seconds

```console
$ obstat init
wrote obstat.toml — everything is denied until you uncomment a rule
```

`obstat.toml`:

```toml
[[rule]]
tool = "read_*"
effect = "allow"

[[rule]]
tool = "delete_*"
effect = "approve"
```

Your tool:

```python
from obstat import guard


@guard(resource="doc:{doc_id}")
def delete_document(doc_id: str) -> str: ...  # obstat has already decided this may happen
```

First call returns instead of running:

```python
>>> delete_document("q3-report")
{'obstat': 'approval_required',
 'approval_id': '4f1c2a9b8e07',
 'expires_in_seconds': 900,
 'record': '814e0978bd10…',
 'waiting': False,
 'retry': "A human must approve this call. Once approved, call the same tool
           again with identical arguments plus obstat_approval_id='4f1c2a9b8e07'."}
```

A human decides:

```console
$ obstat pending
4f1c2a9b8e07  delete_document  anonymous  doc:q3-report  871s left
$ obstat approve 4f1c2a9b8e07
4f1c2a9b8e07 approved by ana
```

The agent retries with the id, the call runs, and `.obstat/decisions.jsonl` holds
the whole story.

## What it is not

There are several good libraries that gate MCP tool calls. This one is built
around a narrower claim: **the record is the product.** Four things follow from
that, and they are the reason to pick this over a permission wrapper.

**The decision is durable before the body runs.** Not flushed after, not written
in a `finally`, not batched. `record.decision()` returns only after `fsync`. A log
written after the fact is a story about what happened; a record written before it
is evidence of what was authorised. There is a test that runs inside a tool body,
reads the log off disk, and fails if its own decision record is not already there.

**Authorisation is per resource, not per tool.** A tier — READ, WRITE,
DESTRUCTIVE — cannot say "may edit their own ticket, not yours". obstat resolves
the resource from the call arguments and matches rules against it:

```python
@guard(resource="jira_issue:{issue_key}")
```

```toml
[[rule]]
subject = "human:ana"
resource = "jira_issue:ACME-*"
effect = "allow"
```

**An approval is bound to one call.** It carries the tool, the subject, the
resource and a digest of the arguments, and it is single-use. Approving "delete
q3-report" cannot be spent on deleting something else, and cannot be spent twice.
This is enforced in one `BEGIN IMMEDIATE` transaction, so two concurrent retries
cannot both win.

**The record says when it has been edited.** Every record carries the hash of the
one before it, and `obstat verify` recomputes the chain:

```console
$ obstat verify
line 3: record cd53f9db… follows a record that is no longer in the log
```

An edited line and a deleted line both show up. A truncated tail does not, and
anyone who can write the file can recompute the whole chain — this is
tamper-evidence, not non-repudiation, and
[§8](docs/obstat-spec.md#8-still-open) says so in those words.

**And the record covers the gate, not the resource.** Anything reaching the same
system by another path — its own client, a shell, the credential this process is
holding — leaves nothing behind, and the log does not read as incomplete. It
reads as quiet. Absence is evidence only over the calls that came through
`@guard`, which is a boundary to design your deployment around rather than a bug
to wait on: it is the first entry in §8.

## Identity is optional

Most MCP servers today have no token at all: stdio, one local user, or a gateway
that already terminated auth. Demanding an identity provider before you can try a
governance library is why governance libraries go untried. An anonymous call is a
legitimate call here — it is recorded as `anonymous`, and the policy decides what
`anonymous` may do.

When you *do* have identity, hand it over:

```python
from obstat import Subject, set_subject_resolver

set_subject_resolver(lambda: Subject(id=current_user(), kind="human", verified=True))
```

`verified=False` is the honest flag for identity that came from somewhere a caller
could influence — a header, an argument. It is recorded, so a reader can tell the
difference between "Ana did this" and "something claimed to be Ana did this".

## Policy

First matching rule wins. Nothing matching is a deny — an absent rule is not
permission, and a missing policy file is an error rather than an implicit allow.

| key | matches | default |
|---|---|---|
| `tool` | the function name, or `tool=` on the decorator | `*` |
| `subject` | `human:ana`, `agent:planner`, `service:etl`, `anonymous` | `*` |
| `resource` | whatever the resource template produced | `*` |
| `effect` | `allow`, `deny`, `approve` | required |

Patterns are globs. The file is re-read when it changes, so editing policy does
not need a restart.

They are matched **case-sensitively**, against an id built from arguments the
caller sent. If your namespace is not case-sensitive — Jira keys, most
filesystems — a rule written for `jira_issue:SEC-*` will not cover `sec-1`, and
nothing will tell you. Normalise the id where you build it:

```python
@guard(resource=lambda a: f"jira_issue:{a['issue_key'].upper()}")
```

That is what the callable form is for; [§3.3](docs/obstat-spec.md#33-resource-resolution)
has the whole story, including why obstat does not fold case for you.

## The order

```
1  reject a caller-supplied obstat_subject
2  stop file
3  resolve the resource from the arguments
4  policy
5  approval, if policy asked for one
6  write the decision record — durable      <-- before, not after
7  run the body
8  write the outcome — best effort
```

Step 1 exists because `obstat_subject` is stripped from the tool's advertised
signature. A client that sends one anyway is trying to name itself, and that is a
denial before anything reads the value. `obstat_` is the only prefix reserved —
every other parameter name, `subject` included, stays the tool's own.

Step 8 is deliberately not durable. If the process dies between 7 and 8 the record
reads "authorised, outcome unknown", which is the honest state; paying for a second
`fsync` to say something merely informative is the wrong trade.

## Operator commands

```console
obstat init                 # a starter policy; refuses to overwrite one
obstat check <tool> [res]   # what the policy would decide, without a call
obstat pending              # approvals waiting on a human
obstat approve <id> [--by]  # decide
obstat deny <id> [--by]
obstat log -n 50            # the decision record
obstat verify               # recompute the chain; exit 1 if anything was edited
obstat stop                 # deny every guarded call
obstat resume
```

`obstat stop` is checked before policy, so stopping never depends on the policy
file still being parseable.

`obstat check` exits 0 for an allow and 1 for anything else, so a policy can be
tested in CI — and a policy that does not parse is reported there rather than by
the next real call.

## Arguments

Fingerprinted by default, never stored: tool arguments carry credentials and
personal data, and a governance log that leaks them is a liability rather than a
control. Name the ones a human needs and those values are recorded too —

```python
@guard(resource="tool:send_email", record_args=("to",))
def send_email(to: str, body: str) -> str: ...
```

```console
$ obstat pending
d41b88f29a43  send_email  human:ana  tool:send_email  871s left
      to = 'board@example.com'
```

— because an approver deciding about `sha256:ae32e6…` is deciding about nothing.
The digest still covers every argument; `body` is in it and nowhere else. Name
identifiers, not payloads.

Arguments say what a call was *allowed* to do. Where they name a set rather than
one thing, only the body knows what it then touched — so the body says:

```python
@guard(record_args=("sender",))
def delete_by_sender(sender: str) -> str:
    ...
    obstat.note(deleted=len(gone), matched=len(found))
```

```json
{"phase": "outcome", "ok": true, "noted": {"deleted": 154, "matched": 158}}
```

Written on failure too, since half a bulk delete is the case a reader most needs
a number for. Outside a guarded call `note()` does nothing, so a tool body stays
callable without obstat.

## What is not here yet

Deliberately absent: retention and rotation of the log, Slack and webhook
approval channels, a policy for where a result may be *sent*, and anything that
talks to a cloud. Those belong at the edges, and the edges should be adapters
rather than dependencies.

## Configuration

| variable | default |
|---|---|
| `OBSTAT_POLICY` | `obstat.toml` |
| `OBSTAT_LOG` | `.obstat/decisions.jsonl` |
| `OBSTAT_DB` | `.obstat/approvals.db` |
| `OBSTAT_HALT` | `.obstat/halt` |
| `OBSTAT_APPROVAL_TTL` | `900` (seconds) |

Read at call time, never at import. A library that raises on import is a library
you cannot try.

## License

Apache-2.0. Copyright 2026 Marcin Marzęta.
