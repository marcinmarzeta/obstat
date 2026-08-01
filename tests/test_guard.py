"""What must stay true.

The first test is the one that matters: if the decision record stops being
durable before the body runs, obstat is a logging library and the README is a
lie. It asserts the property from inside the tool body, which is the only place
that can tell the difference.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
import threading
import time

import pytest

from obstat import Denied, Subject, guard, policy, record, set_subject_resolver
from obstat import approval as approval_module

# `obstat.guard` the name is the decorator, so reach the module's codes directly.
from obstat.guard import HALTED, RESOURCE_UNRESOLVED, SUBJECT_SUPPLIED

ALLOW_ALL = '[[rule]]\neffect = "allow"\n'


def test_record_is_durable_before_the_body_runs(workspace):
    workspace(ALLOW_ALL)
    seen: dict[str, list] = {}

    @guard()
    def read_thing(what: str) -> str:
        # Read the log off disk from inside the body. Anything buffered, deferred
        # or written afterwards is invisible here, which is the point.
        seen["records"] = record.read()
        return f"read {what}"

    assert read_thing("a-file") == "read a-file"

    decisions = [r for r in seen["records"] if r["phase"] == "decision"]
    assert len(decisions) == 1
    assert decisions[0]["effect"] == "allow"
    assert decisions[0]["tool"] == "read_thing"


def test_outcome_is_recorded_after(workspace):
    workspace(ALLOW_ALL)

    @guard()
    def works() -> str:
        return "fine"

    works()
    entries = record.read()
    assert [e["phase"] for e in entries] == ["decision", "outcome"]
    assert entries[1]["ok"] is True
    assert entries[1]["id"] == entries[0]["id"]


def test_a_failing_body_still_leaves_both_records(workspace):
    workspace(ALLOW_ALL)

    @guard()
    def explodes() -> str:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        explodes()
    entries = record.read()
    assert entries[0]["effect"] == "allow"
    assert entries[1] == {**entries[1], "phase": "outcome", "ok": False, "error": "ValueError"}


def test_an_unknown_effect_is_refused(workspace):
    """`policy.EFFECTS` is derived from the `Effect` literal; this is what fails
    if the two ever come apart."""
    workspace('[[rule]]\neffect = "permit"\n')

    with pytest.raises(policy.PolicyError, match="allow, deny, approve"):
        policy.decide(tool="t", subject="anonymous", resource="r")


def test_no_rule_is_a_deny(workspace):
    workspace('[[rule]]\ntool = "something_else"\neffect = "allow"\n')

    @guard()
    def unlisted() -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran despite no matching rule")

    with pytest.raises(Denied) as caught:
        unlisted()

    entries = record.read()
    assert entries[0]["effect"] == "deny"
    assert entries[0]["code"] == policy.NO_RULE_MATCHED
    # The reference in the message is the record, so an operator can find it.
    assert entries[0]["id"] == caught.value.record_id
    assert entries[0]["id"] in str(caught.value)


def test_missing_policy_is_not_an_implicit_allow(workspace):
    # The `workspace` fixture points at a tmp dir; no policy file is written there.
    @guard()
    def anything() -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran with no policy at all")

    with pytest.raises(policy.PolicyError):
        anything()


def test_a_caller_cannot_supply_its_own_subject(workspace):
    workspace(ALLOW_ALL)
    set_subject_resolver(lambda: Subject(id="ana", kind="human", verified=True))

    @guard()
    def whoami(subject: Subject | None = None) -> str:
        return str(subject)

    assert whoami() == "human:ana"

    with pytest.raises(Denied):
        whoami(subject=Subject(id="root", kind="human", verified=True))

    assert record.read()[-1]["code"] == SUBJECT_SUPPLIED


def test_a_subject_that_would_collide_is_refused_at_decoration():
    # A `doc_id` after `subject` would be filled from the caller's first positional
    # argument, because the advertised signature no longer has `subject` in it.
    with pytest.raises(TypeError, match="keyword"):

        @guard()
        def wrong(subject: Subject | None, doc_id: str) -> str:  # pragma: no cover
            raise AssertionError("decorating this should have failed")

    # Last, or keyword-only: nothing positional follows, so neither can collide.
    @guard()
    def trailing(doc_id: str, subject: Subject | None = None) -> str:  # pragma: no cover
        return doc_id

    @guard()
    def keyword_only(doc_id: str, *, subject: Subject | None = None) -> str:  # pragma: no cover
        return doc_id


def test_a_delegation_chain_reaches_the_record(workspace):
    workspace(ALLOW_ALL)
    set_subject_resolver(lambda: Subject(id="planner", kind="agent", via=("human:ana",)))

    @guard()
    def act() -> str:
        return "done"

    act()
    set_subject_resolver(lambda: Subject(id="planner", kind="agent"))
    act()

    delegated, direct = [e for e in record.read() if e["phase"] == "decision"]
    assert delegated["via"] == ["human:ana"]
    assert "via" not in direct  # omitted rather than empty


def test_injected_subject_is_not_advertised_but_the_approval_id_is(workspace):
    workspace(ALLOW_ALL)

    @guard()
    def tool(issue: str, subject: Subject | None = None) -> str:  # pragma: no cover
        return issue

    params = inspect.signature(tool).parameters
    assert "subject" not in params
    assert params["obstat_approval_id"].default is None


def test_resource_comes_from_the_arguments(workspace):
    workspace(
        '[[rule]]\nresource = "jira_issue:ACME-*"\neffect = "allow"\n[[rule]]\neffect = "deny"\n'
    )

    @guard(resource="jira_issue:{key}")
    def touch(key: str) -> str:
        return key

    assert touch("ACME-1") == "ACME-1"
    assert record.read()[0]["resource"] == "jira_issue:ACME-1"

    with pytest.raises(Denied):
        touch("OTHER-1")


def test_a_template_matches_only_the_spelling_it_was_given(workspace):
    """The hazard §3.3 documents, pinned so it cannot be fixed by accident.

    A glob is case-sensitive and a template interpolates whatever the caller
    sent, so a deny rule covers one spelling of an id and not another — even
    where the system behind the tool resolves both to one object.
    """
    workspace(
        '[[rule]]\nresource = "jira_issue:SEC-*"\neffect = "deny"\n[[rule]]\neffect = "allow"\n'
    )

    @guard(resource="jira_issue:{key}")
    def touch(key: str) -> str:
        return key

    with pytest.raises(Denied):
        touch("SEC-1")
    assert touch("sec-1") == "sec-1"


def test_a_callable_resource_normalises_what_policy_matches(workspace):
    """And the fix §3.3 prescribes, which is why `resource` takes a callable."""
    workspace(
        '[[rule]]\nresource = "jira_issue:SEC-*"\neffect = "deny"\n[[rule]]\neffect = "allow"\n'
    )

    @guard(resource=lambda a: f"jira_issue:{a['key'].upper()}")
    def touch(key: str) -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran for a resource the policy denies")

    for spelling in ("SEC-1", "sec-1", "Sec-1"):
        with pytest.raises(Denied):
            touch(spelling)
    assert {r["resource"] for r in record.read()} == {"jira_issue:SEC-1"}


def test_an_unresolvable_resource_denies(workspace):
    workspace(ALLOW_ALL)

    @guard(resource="doc:{missing}")
    def touch(key: str) -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran without a resolvable resource")

    with pytest.raises(Denied):
        touch("x")
    assert record.read()[0]["resource"] == "unresolved"
    assert record.read()[0]["code"] == RESOURCE_UNRESOLVED


def test_arguments_are_fingerprinted_not_stored(workspace):
    workspace(ALLOW_ALL)

    @guard()
    def send(to: str, secret: str) -> str:
        return "sent"

    send("ana@example.com", secret="hunter2")
    written = record.read()[0]
    assert written["args"].startswith("sha256:")
    assert "hunter2" not in str(written)


def test_only_the_named_arguments_are_recorded(workspace):
    workspace(ALLOW_ALL)

    @guard(record_args=("to",))
    def send(to: str, secret: str) -> str:
        return "sent"

    send("ana@example.com", secret="hunter2")
    written = record.read()[0]
    assert written["args_recorded"] == {"to": "ana@example.com"}
    # Naming one argument does not opt the others in, and the digest still
    # covers all of them — the values are written beside it, not instead of it.
    assert "hunter2" not in str(written)
    assert written["args"] == record.digest({"to": "ana@example.com", "secret": "hunter2"})


def test_nothing_is_recorded_unless_it_was_named(workspace):
    workspace(ALLOW_ALL)

    @guard()
    def send(to: str) -> str:
        return "sent"

    send("ana@example.com")
    assert "args_recorded" not in record.read()[0]


def test_recording_an_argument_that_does_not_exist_is_refused_at_decoration(workspace):
    workspace(ALLOW_ALL)

    with pytest.raises(TypeError, match="record_args names no such parameter: recipient"):

        @guard(record_args=("recipient",))
        def send(to: str) -> str:
            return "sent"


def test_a_denial_records_the_named_arguments(workspace):
    workspace('[[rule]]\neffect = "deny"\n')

    @guard(record_args=("doc_id",))
    def delete(doc_id: str) -> str:
        return "gone"

    with pytest.raises(Denied):
        delete("q3-report")
    # An examiner asking what was refused gets an answer, not a digest.
    assert record.read()[0]["args_recorded"] == {"doc_id": "q3-report"}

    # Every step that denies after the arguments are bound, not just policy: a
    # record missing what the one beside it carries is the gap being closed.
    (workspace.path / "halt").write_text("stopped\n", encoding="utf-8")
    with pytest.raises(Denied):
        delete("q4-report")
    halted = record.read()[-1]
    assert halted["code"] == HALTED
    assert halted["args_recorded"] == {"doc_id": "q4-report"}


def test_the_stop_file_denies_everything(workspace):
    workspace(ALLOW_ALL)
    halt = workspace.path / "halt"

    @guard()
    def anything() -> str:
        return "ran"

    assert anything() == "ran"
    halt.write_text("stopped")
    with pytest.raises(Denied):
        anything()
    assert record.read()[-1]["code"] == HALTED
    halt.unlink()
    assert anything() == "ran"


def test_the_approval_window_is_configurable(workspace, monkeypatch):
    workspace('[[rule]]\neffect = "approve"\n')
    monkeypatch.setenv("OBSTAT_APPROVAL_TTL", "60")

    @guard()
    def sensitive() -> str:
        return "ran"

    assert sensitive()["expires_in_seconds"] == 60

    # A window that cannot work is not quietly replaced by one that can: every
    # call would ask, expire, and ask again, and nothing would say why.
    monkeypatch.setenv("OBSTAT_APPROVAL_TTL", "0")
    with pytest.raises(ValueError, match="must be positive"):
        sensitive()


class TestApproval:
    POLICY = '[[rule]]\ntool = "transition"\neffect = "approve"\n'

    @staticmethod
    def tool():
        @guard(resource="jira_issue:{key}")
        def transition(key: str, to: str) -> str:
            return f"{key} -> {to}"

        return transition

    def test_first_call_asks_and_does_not_run(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()

        answer = transition("ACME-1", to="Done")

        assert answer["obstat"] == "approval_required"
        assert record.read()[0]["effect"] == "approval_required"
        assert [p.id for p in approval_module.pending()] == [answer["approval_id"]]

    def test_retry_after_approval_runs_once(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()
        approval_id = transition("ACME-1", to="Done")["approval_id"]

        approval_module.resolve(approval_id, approved=True, by="ana")
        assert transition("ACME-1", to="Done", obstat_approval_id=approval_id) == "ACME-1 -> Done"

        # Single use: the same id a second time is a denial, not a second run.
        with pytest.raises(Denied):
            transition("ACME-1", to="Done", obstat_approval_id=approval_id)
        assert record.read()[-1]["code"] == approval_module.USED

    def test_an_approval_does_not_travel_to_another_call(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()
        approval_id = transition("ACME-1", to="Done")["approval_id"]
        approval_module.resolve(approval_id, approved=True, by="ana")

        # Approved for ACME-1. Retrying against a different issue must fail.
        with pytest.raises(Denied):
            transition("OTHER-9", to="Done", obstat_approval_id=approval_id)
        written = record.read()[-1]
        # The code is the contract; the prose is asserted only because *which*
        # binding failed is detail the code deliberately does not carry.
        assert written["code"] == approval_module.MISMATCH
        assert "different resource" in written["reason"]

        # And approved for "Done", so a different transition must fail too.
        with pytest.raises(Denied):
            transition("ACME-1", to="Deleted", obstat_approval_id=approval_id)
        written = record.read()[-1]
        assert written["code"] == approval_module.MISMATCH
        assert "different args_digest" in written["reason"]

    def test_asking_twice_rejoins_one_approval(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()

        first = transition("ACME-1", to="Done")
        second = transition("ACME-1", to="Done")

        # Same call, same approval. An agent polling a slow human must not queue
        # up duplicates for that human to sort out.
        assert first["approval_id"] == second["approval_id"]
        assert first["waiting"] is False
        assert second["waiting"] is True
        assert len(approval_module.pending()) == 1

        # A different call is a different approval.
        other = transition("ACME-2", to="Done")
        assert other["approval_id"] != first["approval_id"]
        assert len(approval_module.pending()) == 2

    def test_retrying_before_a_human_answers_is_not_a_denial(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()
        approval_id = transition("ACME-1", to="Done")["approval_id"]

        again = transition("ACME-1", to="Done", obstat_approval_id=approval_id)

        assert again["obstat"] == "approval_required"
        assert again["approval_id"] == approval_id
        assert again["waiting"] is True
        assert len(approval_module.pending()) == 1

    def test_the_same_call_can_be_approved_again_later(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()

        first = transition("ACME-1", to="Done")["approval_id"]
        approval_module.resolve(first, approved=True, by="ana")
        transition("ACME-1", to="Done", obstat_approval_id=first)

        # Consumed. Asking again opens a fresh approval under the same derived id,
        # because doing the same thing twice on purpose is not a replay.
        second = transition("ACME-1", to="Done")
        assert second["obstat"] == "approval_required"
        assert second["approval_id"] == first
        assert second["waiting"] is False
        assert len(approval_module.pending()) == 1

        approval_module.resolve(second["approval_id"], approved=True, by="ana")
        assert transition("ACME-1", to="Done", obstat_approval_id=first) == "ACME-1 -> Done"

    def test_a_denied_approval_denies(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()
        approval_id = transition("ACME-1", to="Done")["approval_id"]
        approval_module.resolve(approval_id, approved=False, by="ana")

        with pytest.raises(Denied):
            transition("ACME-1", to="Done", obstat_approval_id=approval_id)
        assert record.read()[-1]["code"] == approval_module.DENIED

    def test_an_invented_approval_id_denies(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()

        with pytest.raises(Denied):
            transition("ACME-1", to="Done", obstat_approval_id="deadbeef")
        assert record.read()[-1]["code"] == approval_module.UNKNOWN


class TestChain:
    """A log anyone can rewrite proves less than it looks like it does (§6.3)."""

    @staticmethod
    def two_calls(workspace):
        workspace(ALLOW_ALL)

        @guard()
        def act(what: str) -> str:
            return what

        act("one")
        act("two")
        log = workspace.path / "decisions.jsonl"
        assert record.verify(log) == []  # nothing touched it yet
        return log

    @staticmethod
    def rewrite(log, lines: list[str]) -> None:
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_an_edited_record_is_caught(self, workspace):
        log = self.two_calls(workspace)
        lines = log.read_text(encoding="utf-8").splitlines()

        # Rewriting history so the call reads as one that was refused.
        edited = json.loads(lines[0])
        edited["effect"] = "deny"
        lines[0] = json.dumps(edited, separators=(",", ":"))
        self.rewrite(log, lines)

        assert "has been altered" in " ".join(record.verify(log))

    def test_a_removed_record_is_caught(self, workspace):
        log = self.two_calls(workspace)
        lines = log.read_text(encoding="utf-8").splitlines()

        # Deleting the record of the call outright. Its outcome still points at it.
        del lines[0]
        self.rewrite(log, lines)

        assert "no longer in the log" in " ".join(record.verify(log))

    def test_a_reused_hash_does_not_hide_an_edit(self, workspace):
        log = self.two_calls(workspace)
        lines = log.read_text(encoding="utf-8").splitlines()

        # Editing a record and leaving its stored hash alone is the lazy forgery;
        # recomputing the hash but not the successor's `prev` is the other one.
        edited = json.loads(lines[0])
        edited["effect"] = "deny"
        edited["hash"] = record._chain_hash(edited)
        lines[0] = json.dumps(edited, separators=(",", ":"))
        self.rewrite(log, lines)

        assert "no longer in the log" in " ".join(record.verify(log))

    def test_a_torn_line_does_not_swallow_the_next_record(self, workspace):
        log = self.two_calls(workspace)
        # What a write cut short by a full disk leaves behind: no trailing newline.
        with log.open("a", encoding="utf-8") as handle:
            handle.write('{"schema":2,"id":"torn"')

        @guard()
        def act(what: str) -> str:
            return what

        act("three")

        # Exactly one problem, and it is the fragment. Anything less readable than
        # that — a spliced decision record, a dangling outcome — shows up here too.
        assert record.verify(log) == ["line 5: not a record"]


CHILD = """
import pathlib, sys, time
from obstat import guard


@guard()
def touch(n: int) -> int:
    return n


pathlib.Path(sys.argv[1]).write_text("ready")
go = pathlib.Path(sys.argv[2])
while not go.exists():
    time.sleep(0.005)
for i in range({calls}):
    touch(i)
"""


class TestConcurrency:
    """Two writers, one log. §6 says records interleave but never split; §6.3
    says the chain forks across processes and verification tolerates it.

    Both are claims about what happens when nothing is coordinating the writers,
    which is the state a served tool is in and the state no other test puts it
    in.
    """

    CALLS = 15

    def test_threads_do_not_split_a_record(self, workspace):
        """One process, one lock: every record whole, and the chain still a line."""
        workspace(ALLOW_ALL)

        @guard()
        def touch(n: int) -> int:
            return n

        threads = [
            threading.Thread(target=lambda: [touch(i) for i in range(self.CALLS)]) for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # read() parses every line, so a split record fails here before anything
        # is asserted about it.
        entries = record.read()
        assert len(entries) == 4 * self.CALLS * 2  # a decision and an outcome each

        # `_chain_lock` covers hashing and appending together, so within one
        # process the result is a line: one root, and no record followed twice.
        prevs = [entry["prev"] for entry in entries]
        assert prevs.count(None) == 1
        assert len(prevs) == len(set(prevs))
        assert record.verify() == []

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows append is a seek and a write, so concurrent processes lose records (§8)",
    )
    def test_two_processes_write_one_log(self, workspace, tmp_path):
        """No inter-process lock, so this is O_APPEND and one write() syscall
        doing the work (§6). Released together, because two writers that happen
        to take turns prove nothing.

        POSIX only, and the skip above is the honest form of that: this once
        failed on Windows at 57 of 60 records, which is the platform telling the
        truth about an atomicity obstat does not have there.
        """
        workspace(ALLOW_ALL)
        script = tmp_path / "child.py"
        script.write_text(CHILD.format(calls=self.CALLS), encoding="utf-8")

        go = tmp_path / "go"
        children = []
        for name in ("a", "b"):
            ready = tmp_path / f"ready-{name}"
            children.append(
                (
                    ready,
                    subprocess.Popen([sys.executable, str(script), str(ready), str(go)]),
                )
            )
        deadline = time.time() + 30
        while not all(ready.exists() for ready, _ in children):
            assert time.time() < deadline, "a child never started"
            time.sleep(0.01)
        go.write_text("go")

        for _, child in children:
            assert child.wait(timeout=60) == 0

        entries = record.read()
        assert len(entries) == 2 * self.CALLS * 2
        assert record.verify() == []

    def test_a_forked_chain_still_verifies(self, workspace):
        """What a second process does, done deliberately: carry on from the
        record you last saw, not from the one that is now on the end.

        Reproduced in-process because two real processes might take turns and
        never fork at all, and a test that only sometimes tests the thing is
        worse than no test.
        """
        workspace(ALLOW_ALL)

        @guard()
        def touch(what: str) -> str:
            return what

        touch("first")
        branch = record._chain  # what another process would still be holding
        touch("second")
        record._chain = branch
        touch("third")

        prevs = [entry["prev"] for entry in record.read()]
        assert len(prevs) != len(set(prevs)), "nothing forked, so nothing was tested"
        # Every `prev` still names a record earlier in the file, which is all
        # verification asks of it — a fork is not damage.
        assert record.verify() == []


async def test_an_approval_survives_a_real_mcp_server(workspace):
    """Through the SDK, not past it (§4.2).

    Every other test calls the decorated function directly, which is exactly how
    a server validating the tool's result against its return annotation went
    unnoticed: a tool declaring `-> str` raised at the client the moment policy
    sent a call to a human, turning the control §5.1 designed as a return value
    into a protocol error.
    """
    server = pytest.importorskip("mcp.server", reason="mcp is an optional extra")
    workspace('[[rule]]\ntool = "read_*"\neffect = "allow"\n[[rule]]\neffect = "approve"\n')

    mcp = server.MCPServer("test")

    @mcp.tool()
    @guard()
    def read_thing(doc_id: str) -> str:
        return f"contents of {doc_id}"

    @mcp.tool()
    @guard()
    def delete_thing(doc_id: str) -> str:  # pragma: no cover - waits for a human
        return f"{doc_id} deleted"

    advertised = await mcp.list_tools()
    assert {tool.name for tool in advertised} == {"read_thing", "delete_thing"}

    allowed = await mcp.call_tool("read_thing", {"doc_id": "q3"})
    assert allowed.is_error is False
    assert allowed.content[0].text == "contents of q3"

    # The one that used to raise.
    asked = await mcp.call_tool("delete_thing", {"doc_id": "q3"})
    assert asked.is_error is False
    assert json.loads(asked.content[0].text)["obstat"] == "approval_required"

    assert [entry["effect"] for entry in record.read() if entry["phase"] == "decision"] == [
        "allow",
        "approval_required",
    ]


async def test_async_tools_go_through_the_same_gate(workspace):
    workspace('[[rule]]\ntool = "fetch"\neffect = "allow"\n[[rule]]\neffect = "deny"\n')

    @guard()
    async def fetch(url: str) -> str:
        return f"got {url}"

    @guard()
    async def nope() -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran despite a deny")

    assert await fetch("https://example.com") == "got https://example.com"
    with pytest.raises(Denied):
        await nope()
