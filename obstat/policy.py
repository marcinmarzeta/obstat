"""Rules, and the decision they produce (§2).

A rule matches on three things — who, which tool, which object — and says one of
`allow`, `deny`, `approve`. First match wins. Nothing matching is a deny: an
absent rule is not permission.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal, get_args

from . import paths

Effect = Literal["allow", "deny", "approve"]
# Derived, so the set a rule is validated against cannot drift from the type.
EFFECTS: tuple[Effect, ...] = get_args(Effect)

ANONYMOUS = "anonymous"

# Stable codes (§6.4). The prose beside them is for whoever reads the record; only
# the code is safe to branch on or to filter a log by.
NO_RULE_MATCHED = "no_rule_matched"
RULE_MATCHED = "rule_matched"


class PolicyError(RuntimeError):
    """The policy file is missing or malformed. Raised on the first guarded call."""


@dataclass(frozen=True)
class Rule:
    effect: Effect
    tool: str = "*"
    subject: str = "*"
    resource: str = "*"

    def matches(self, *, tool: str, subject: str, resource: str) -> bool:
        return (
            fnmatchcase(tool, self.tool)
            and fnmatchcase(subject, self.subject)
            and fnmatchcase(resource, self.resource)
        )


@dataclass(frozen=True)
class Decision:
    effect: Effect
    code: str
    reason: str
    rule: int | None  # index into the file, so a record points at the line that decided
    policy: str  # digest of the file it indexes into (§6.4)


# (path, mtime, size) -> rules, digest. Editing the policy takes effect on the
# next call rather than the next restart; a stat() per call is cheaper than the
# confusion.
_cache: tuple[tuple[str, float, int], list[Rule], str] | None = None


def _parse(raw: dict) -> list[Rule]:
    rules: list[Rule] = []
    for index, entry in enumerate(raw.get("rule", [])):
        if not isinstance(entry, dict):
            raise PolicyError(f"rule {index}: expected a table")
        effect = entry.get("effect")
        if effect not in EFFECTS:
            raise PolicyError(f"rule {index}: effect must be one of {', '.join(EFFECTS)}")
        unknown = set(entry) - {"effect", "tool", "subject", "resource"}
        if unknown:
            # A typo'd key would otherwise silently widen the rule to match everything.
            raise PolicyError(f"rule {index}: unknown key(s) {', '.join(sorted(unknown))}")
        rules.append(
            Rule(
                effect=effect,
                tool=str(entry.get("tool", "*")),
                subject=str(entry.get("subject", "*")),
                resource=str(entry.get("resource", "*")),
            )
        )
    return rules


def _loaded(path: Path | None = None) -> tuple[list[Rule], str]:
    """The rules, and a digest of the exact bytes they were parsed from.

    The digest is what makes `rule {n}` mean anything later: the index points
    into a file §2.2 re-reads whenever it changes, so without it an edit
    silently repoints every record written before it (§6.4).
    """
    global _cache
    path = path or paths.policy()
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise PolicyError(
            f"no policy at {path}. Write one (see README) or set OBSTAT_POLICY. "
            "obstat has no implicit allow."
        ) from exc

    key = (str(path), stat.st_mtime, stat.st_size)
    if _cache is not None and _cache[0] == key:
        return _cache[1], _cache[2]

    text = path.read_text(encoding="utf-8")
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: {exc}") from exc

    rules = _parse(raw)
    # Over the file, not over the parsed rules: two files that parse the same are
    # still two files, and a reader chasing a decision wants the one on disk.
    digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    _cache = (key, rules, digest)
    return rules, digest


def load(path: Path | None = None) -> list[Rule]:
    return _loaded(path)[0]


def decide(*, tool: str, subject: str, resource: str, path: Path | None = None) -> Decision:
    rules, digest = _loaded(path)
    for index, rule in enumerate(rules):
        if rule.matches(tool=tool, subject=subject, resource=resource):
            return Decision(rule.effect, RULE_MATCHED, f"rule {index}", index, digest)
    return Decision("deny", NO_RULE_MATCHED, "no rule matched", None, digest)
