"""The two commands an operator meets before anything is guarded (§2.3).

`init` has to produce a file the parser accepts — a broken template is a broken
install — and `check` has to answer for a policy without a call to make it
answer.
"""

from __future__ import annotations

from obstat import guard, policy
from obstat.__main__ import main


def test_init_writes_a_policy_that_permits_nothing(workspace, capsys):
    path = workspace.path / "obstat.toml"

    assert main(["init"]) == 0
    assert path.exists()

    # Parsed rather than pattern-matched: the point is that policy.load accepts
    # what init wrote, whatever the comments around it say.
    assert policy.decide(tool="anything", subject="human:ana", resource="doc:x").effect == "deny"
    assert "denied until" in capsys.readouterr().out


def test_init_will_not_overwrite_a_policy(workspace, capsys):
    workspace('[[rule]]\neffect = "allow"\n')

    assert main(["init"]) == 1
    assert "already exists" in capsys.readouterr().err
    # The rule that was there is still there.
    assert policy.decide(tool="t", subject="anonymous", resource="r").effect == "allow"


def test_check_names_the_rule_that_decided(workspace, capsys):
    workspace(
        '[[rule]]\ntool = "read_*"\neffect = "allow"\n'
        '[[rule]]\nresource = "doc:secret"\neffect = "deny"\n'
    )

    assert main(["check", "read_thing"]) == 0
    assert capsys.readouterr().out.startswith("allow (rule 0)")

    # Exit 1 for anything that is not an allow, so a policy can be tested in CI.
    assert main(["check", "write_thing", "doc:secret"]) == 1
    assert capsys.readouterr().out.startswith("deny (rule 1)")

    assert main(["check", "write_thing", "doc:other"]) == 1
    assert capsys.readouterr().out.startswith("deny (no rule matched)")


def test_pending_shows_what_is_being_approved(workspace, capsys):
    """An approver deciding about a digest is an approver deciding about nothing."""
    workspace('[[rule]]\neffect = "approve"\n')

    @guard(record_args=("to",))
    def send(to: str, body: str) -> str:
        return "sent"

    send("ana@example.com", body="the whole quarterly report")

    assert main(["pending"]) == 0
    out = capsys.readouterr().out
    assert "to = 'ana@example.com'" in out
    # Only what the tool named. The body is in the digest and nowhere else.
    assert "quarterly" not in out


def test_check_reports_a_broken_policy_instead_of_raising(workspace, capsys):
    # The typo §2 worries about: `resources` would otherwise leave the rule
    # matching every resource, which is the widest failure and the quietest.
    workspace('[[rule]]\nresources = "doc:*"\neffect = "allow"\n')

    assert main(["check", "read_thing"]) == 1
    assert "unknown key" in capsys.readouterr().err
