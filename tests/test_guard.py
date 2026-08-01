"""What must stay true.

The first test is the one that matters: if the decision record stops being
durable before the body runs, obstat is a logging library and the README is a
lie. It asserts the property from inside the tool body, which is the only place
that can tell the difference.
"""

from __future__ import annotations

import inspect

import pytest

from obstat import Denied, Subject, guard, policy, record, set_subject_resolver
from obstat import approval as approval_module

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


def test_no_rule_is_a_deny(workspace):
    workspace('[[rule]]\ntool = "something_else"\neffect = "allow"\n')

    @guard()
    def unlisted() -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran despite no matching rule")

    with pytest.raises(Denied) as caught:
        unlisted()

    entries = record.read()
    assert entries[0]["effect"] == "deny"
    assert entries[0]["reason"] == "no rule matched"
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

    assert record.read()[-1]["reason"] == "caller supplied a subject"


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


def test_an_unresolvable_resource_denies(workspace):
    workspace(ALLOW_ALL)

    @guard(resource="doc:{missing}")
    def touch(key: str) -> str:  # pragma: no cover - must never run
        raise AssertionError("body ran without a resolvable resource")

    with pytest.raises(Denied):
        touch("x")
    assert record.read()[0]["resource"] == "unresolved"


def test_arguments_are_fingerprinted_not_stored(workspace):
    workspace(ALLOW_ALL)

    @guard()
    def send(to: str, secret: str) -> str:
        return "sent"

    send("ana@example.com", secret="hunter2")
    written = record.read()[0]
    assert written["args"].startswith("sha256:")
    assert "hunter2" not in str(written)


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
    assert record.read()[-1]["reason"] == "halted"
    halt.unlink()
    assert anything() == "ran"


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
        assert record.read()[-1]["reason"] == "approval already used"

    def test_an_approval_does_not_travel_to_another_call(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()
        approval_id = transition("ACME-1", to="Done")["approval_id"]
        approval_module.resolve(approval_id, approved=True, by="ana")

        # Approved for ACME-1. Retrying against a different issue must fail.
        with pytest.raises(Denied):
            transition("OTHER-9", to="Done", obstat_approval_id=approval_id)
        assert "different resource" in record.read()[-1]["reason"]

        # And approved for "Done", so a different transition must fail too.
        with pytest.raises(Denied):
            transition("ACME-1", to="Deleted", obstat_approval_id=approval_id)
        assert "different args_digest" in record.read()[-1]["reason"]

    def test_a_denied_approval_denies(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()
        approval_id = transition("ACME-1", to="Done")["approval_id"]
        approval_module.resolve(approval_id, approved=False, by="ana")

        with pytest.raises(Denied):
            transition("ACME-1", to="Done", obstat_approval_id=approval_id)
        assert record.read()[-1]["reason"] == "approval is denied"

    def test_an_invented_approval_id_denies(self, workspace):
        workspace(self.POLICY)
        transition = self.tool()

        with pytest.raises(Denied):
            transition("ACME-1", to="Done", obstat_approval_id="deadbeef")
        assert record.read()[-1]["reason"] == "unknown approval"


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
