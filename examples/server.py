"""An MCP server with obstat in front of its tools.

    uv run --with 'obstat[mcp]' examples/server.py

`@mcp.tool()` goes outside `@guard(...)`, so what FastMCP advertises is the
guarded signature: no `subject`, plus an optional `obstat_approval_id`.

The policy this reads is `obstat.toml` in the working directory.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from obstat import Subject, guard, set_subject_resolver

mcp = FastMCP("documents")

# Where identity comes from is the host application's business. Over stdio there
# is usually none, and None is a valid answer — the call is recorded as
# `anonymous` and the policy decides what anonymous may do. Swap this for your
# own resolver when you have a token to read.
set_subject_resolver(lambda: Subject(id="local", kind="human", verified=False))


@mcp.tool()
@guard(resource="doc:{doc_id}")
def read_document(doc_id: str) -> str:
    """Read a document."""
    return f"the contents of {doc_id}"


@mcp.tool()
@guard(resource="doc:{doc_id}")
def delete_document(doc_id: str, subject: Subject | None = None) -> str:
    """Delete a document. Policy sends this one to a human first.

    Declaring `subject` is optional — obstat injects it when the parameter is
    there, and strips it from what clients see either way.
    """
    return f"{doc_id} deleted by {subject}"


if __name__ == "__main__":
    mcp.run()
