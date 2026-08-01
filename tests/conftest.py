from __future__ import annotations

import pytest

from obstat import policy

# `obstat.guard` the name is the decorator, so reach the module's internals directly.
from obstat.guard import _no_subject, set_subject_resolver


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A policy file, a log and an approvals db, all under tmp_path.

    Returns a callable that writes the policy, so each test states the rules it
    is actually testing rather than sharing a fixture nobody reads.
    """
    monkeypatch.setenv("OBSTAT_POLICY", str(tmp_path / "obstat.toml"))
    monkeypatch.setenv("OBSTAT_LOG", str(tmp_path / "decisions.jsonl"))
    monkeypatch.setenv("OBSTAT_DB", str(tmp_path / "approvals.db"))
    monkeypatch.setenv("OBSTAT_HALT", str(tmp_path / "halt"))
    policy._cache = None
    set_subject_resolver(_no_subject)

    def write_policy(text: str) -> None:
        (tmp_path / "obstat.toml").write_text(text, encoding="utf-8")
        policy._cache = None

    write_policy.path = tmp_path  # type: ignore[attr-defined]
    return write_policy
