"""Execute the code examples in `docs/` and check their documented output.

Every `#>` comment in the documentation is a claim about what zttp does. This
module runs the examples and holds them to it, so a change to an error message
or a repr cannot silently leave the docs behind. (It has: two `LocalProtocolError`
messages drifted before this existed.)

There are exactly two shapes of claim:

* **Printed output** - one or more `#>` lines after a `print(...)`. Every `#>`
  payload in the block, in order, must equal the block's stdout.
* **A raised exception** - a `#>` line of the form `zttp.SomeError: message`
  directly after the statement that raises it.

A page's examples share one namespace and run in document order, the way a reader
meets them, so a later block may build on an earlier one. Blocks with no `#>`
claim are executed on a best-effort basis to populate that namespace and are
allowed to fail: they are illustrative fragments (`await writer.drain()`,
`transport.close()`) with nothing to verify. Nothing is masked by this - a
skipped block that some `#>` block genuinely needed shows up as a `NameError` in
the block that made the claim.
"""

from __future__ import annotations

import contextlib
import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import zttp

DOCS = Path(__file__).parent.parent / "docs"

FENCE = re.compile(r"^(?P<indent> *)```+ *python\b[^\n]*\n(?P<source>.*?)^(?P=indent)```+ *$", re.M | re.S)
OUTPUT = re.compile(r"^\s*#>[ ]?(.*)$")
# `#> zttp.RemoteProtocolError: malformed header field`
RAISES = re.compile(r"^\s*#>[ ]?(zttp\.\w*Error): (.*)$")


@dataclass(frozen=True)
class Example:
    """One ```python fenced block in a documentation page."""

    path: Path
    line: int
    source: str

    @property
    def claims(self) -> list[str]:
        """The `#>` payloads in this block, in order."""
        return [m.group(1) for line in self.source.split("\n") if (m := OUTPUT.match(line))]

    @property
    def raises(self) -> tuple[int, str, str] | None:
        """The (line index, exception name, message) of a documented exception."""
        for index, line in enumerate(self.source.split("\n")):
            if m := RAISES.match(line):
                return index, m.group(1), m.group(2)
        return None


def find_examples(root: Path) -> list[Example]:
    """Every ```python block under `root`, in file then document order."""
    examples = []
    for path in sorted(root.rglob("*.md")):
        text = path.read_text()
        for match in FENCE.finditer(text):
            line = text[: match.start()].count("\n") + 2
            examples.append(Example(path, line, match.group("source")))
    return examples


def http2_request_bytes() -> bytes:
    """The `incoming_bytes` that docs/usage/http2.md's read side reads off the socket.

    The page introduces reading before it introduces the client that produces the
    bytes, so this supplies what the prose describes: one `GET /` on the first
    client-initiated stream.
    """
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)
    stream = client.send_request(b"GET", b"/", b"2", [(b"host", b"example.com")])
    stream.end_message()
    return client.data_to_send()


# Placeholder names a page's prose describes but does not construct in a block.
PAGE_CONTEXT = {"http2.md": http2_request_bytes}


def check_raises(example: Example, namespace: dict[str, Any]) -> None:
    """The documented exception must be the one the final statement actually raises."""
    found = example.raises
    assert found is not None
    index, name, message = found
    lines = example.source.split("\n")

    with pytest.raises(zttp.ProtocolError) as excinfo:
        exec("\n".join(lines[:index]), namespace)

    actual = f"zttp.{type(excinfo.value).__name__}: {excinfo.value}"
    assert actual == f"{name}: {message}", (
        f"{example.path.name}:{example.line + index} documents a different exception\n"
        f"  documented: {name}: {message}\n"
        f"  actual:     {actual}"
    )

    # The rest of the block still runs, so later blocks can build on it.
    with contextlib.suppress(Exception):
        exec("\n".join(lines[index + 1 :]), namespace)


def check_output(example: Example, namespace: dict[str, Any]) -> None:
    """The block's stdout must equal its `#>` payloads, in order."""
    source = "\n".join(line for line in example.source.split("\n") if not OUTPUT.match(line))
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exec(source, namespace)

    actual = stdout.getvalue().splitlines()
    assert actual == example.claims, (
        f"{example.path.name}:{example.line} printed output does not match its `#>` comments\n"
        f"  documented: {example.claims}\n"
        f"  actual:     {actual}"
    )


def pages() -> list[str]:
    return sorted({example.path.name for example in find_examples(DOCS)})


@pytest.mark.parametrize("page", pages())
def test_documented_output_is_accurate(page: str) -> None:
    """Run a page's examples in order and verify every `#>` claim it makes."""
    context = PAGE_CONTEXT.get(page)
    namespace: dict[str, Any] = {"incoming_bytes": context()} if context else {}

    for example in find_examples(DOCS):
        if example.path.name != page:
            continue
        if not example.claims:
            # An illustrative fragment: run it to populate the namespace, but it
            # asserts nothing, so let it fail.
            with contextlib.suppress(Exception):
                exec(example.source, namespace)
        elif example.raises:
            check_raises(example, namespace)
        else:
            check_output(example, namespace)


def test_the_docs_make_checkable_claims() -> None:
    """Guard the convention itself: `#>` markers must still be found and parsed."""
    examples = find_examples(DOCS)
    assert len(examples) > 40, "the ```python fence scanner stopped matching"

    with_claims = [e for e in examples if e.claims]
    assert len(with_claims) > 15, "no documented output found - has the `#>` convention changed?"
    assert {e.path.name for e in with_claims} <= set(pages())


def test_inline_output_markers_are_not_used() -> None:
    """`#>` must start its own line, or the checker above silently skips it.

    A trailing `value  #> repr` reads fine but is invisible to the parser, so it
    can drift exactly like the messages this module exists to pin down.
    """
    stray = [
        f"{path.relative_to(DOCS)}:{number}"
        for path in sorted(DOCS.rglob("*.md"))
        for number, line in enumerate(path.read_text().split("\n"), 1)
        if "#>" in line and not OUTPUT.match(line)
    ]
    assert not stray, f"`#>` must be on its own line, found trailing markers at: {stray}"
