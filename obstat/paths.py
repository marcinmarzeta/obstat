"""Where obstat keeps things.

Read at call time, never at import. A governance library that raises
`ConfigError` on import is one you cannot try, and a library you cannot try is
one nobody adopts — which is worse for security than a permissive default.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_DIR = ".obstat"


def _env(name: str, default: str) -> Path:
    return Path(os.environ.get(name) or default).expanduser()


def policy() -> Path:
    return _env("OBSTAT_POLICY", "obstat.toml")


def log() -> Path:
    return _env("OBSTAT_LOG", f"{DEFAULT_DIR}/decisions.jsonl")


def db() -> Path:
    return _env("OBSTAT_DB", f"{DEFAULT_DIR}/approvals.db")


def halt() -> Path:
    """Presence of this file stops every guarded call. Deleting it resumes."""
    return _env("OBSTAT_HALT", f"{DEFAULT_DIR}/halt")
