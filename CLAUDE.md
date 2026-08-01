# obstat

An auditable decision record for agent tool calls. The one claim the project
makes: **the decision is on disk, fsynced, before the tool body runs.** Anything
that weakens that ordering is a bug, not an optimisation.

## Commands

```bash
uv run pytest -q          # 42 tests, ~0.9s (TestConcurrency spawns two children)
uv run ruff check .
uv run ruff format .
```

## Rules that are not negotiable

- **No runtime dependencies.** `tomllib`, `sqlite3`, `hashlib`, `json` are
  stdlib. `mcp` is an optional extra for `examples/server.py` only. A governance
  library nobody can try on a laptop is one nobody adopts.
- **`docs/obstat-spec.md` is normative.** Behaviour changes update the spec in
  the same commit. Where spec and code disagree, one of them is a bug.
- **Nothing matching the policy is a deny**, and a missing policy file is an
  error — never an implicit allow.
- **Denials reach the caller with a record id and nothing else.** The reason goes
  to the record. A denial that explains itself teaches a caller what to work
  around.

## Conventions

Comments say *why*, not what, and name the alternative that was rejected. A
`ponytail:` comment marks a deliberate shortcut and its upgrade path — those are
debts, not decoration.

Spec section numbers (`§5.1`) are referenced from docstrings; keep them in step
when the spec is renumbered.

## Releasing

1. Bump `version` in `pyproject.toml` **and** `__version__` in
   `obstat/__init__.py` — two places, no single source yet.
2. `git tag vX.Y.Z && git push --tags`

`.github/workflows/publish.yml` runs the tests against the tag, builds, and
uploads via PyPI trusted publishing (OIDC — there is no token anywhere). **A PyPI
version is immutable**: a bad build can be superseded, never withdrawn.

**A green publish does not mean a green CI.** The two workflows run
independently, and `publish.yml` builds on ubuntu only — 0.3.1 went to PyPI while
`ci.yml` was failing on the Windows leg. Check both, and prefer pushing the
commit and letting CI finish before pushing the tag.

## Gotchas

`uv run --with /path/to/obstat` serves a **cached wheel** and will happily run
code you edited minutes ago as if you hadn't. `--reinstall-package` does not
dislodge it; `--refresh` does. Two verification runs were wasted on this — if a
local install seems to ignore your change, that is why. To exercise uncommitted
work, `--with-editable` sidesteps the question entirely.

**PyPI lags its own publish.** Minutes after `publish.yml` goes green,
`uv pip install obstat==X` can still fail with *"there is no version of
obstat==X"* while `https://pypi.org/pypi/obstat/json` reports X as latest — or
the reverse; 0.2.0 and 0.3.0 each showed one. It cleared inside a minute both
times. The symptom impersonates a failed upload, and every tempting response
(re-tag, re-run, `force`) is wrong, one of them irreversibly. **The publish job
log is authoritative**: it prints the `https://pypi.org/project/obstat/X/` that
upload.pythonhosted.org returned, which means the file was accepted. Poll the
install until it succeeds rather than diagnosing it.
