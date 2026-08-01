"""Rules, and the decision they produce (§2).

A rule matches on three things — who, which tool, which object — and says one of
`allow`, `deny`, `approve`. First match wins. Nothing matching is a deny: an
absent rule is not permission.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal

from . import paths

Effect = Literal["allow", "deny", "approve"]
EFFECTS: tuple[Effect, ...] = ("allow", "deny", "approve")

ANONYMOUS = "anonymous"


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
    reason: str
    rule: int | None  # index into the file, so a record points at the line that decided


_DENY_UNMATCHED = Decision("deny", "no rule matched", None)

# (path, mtime, size) -> rules. Editing the policy takes effect on the next call
# rather than the next restart; a stat() per call is cheaper than the confusion.
_cache: tuple[tuple[str, float, int], list[Rule]] | None = None


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


def load(path: Path | None = None) -> list[Rule]:
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
        return _cache[1]

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: {exc}") from exc

    rules = _parse(raw)
    _cache = (key, rules)
    return rules


def decide(*, tool: str, subject: str, resource: str, path: Path | None = None) -> Decision:
    for index, rule in enumerate(load(path)):
        if rule.matches(tool=tool, subject=subject, resource=resource):
            return Decision(rule.effect, f"rule {index}", index)
    return _DENY_UNMATCHED
