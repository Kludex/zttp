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
import json
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
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
        """The (line index, exception name, message) of a documented exception.

        A block documents at most one: execution stops at the first raise, so a
        second marker could never be reached and would be silently ignored.
        """
        found = [
            (index, m.group(1), m.group(2))
            for index, line in enumerate(self.source.split("\n"))
            if (m := RAISES.match(line))
        ]
        assert len(found) <= 1, (
            f"{self.path.name}:{self.line} documents {len(found)} exceptions in one block. "
            f"Execution stops at the first, so the rest can never be checked - split the block."
        )
        return found[0] if found else None


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

# Names an example deliberately leaves to the reader ("the bytes off your socket").
# Anything undefined and *not* listed here is a broken example: either define it in
# the block, or add it here to say it is the reader's to supply.
PLACEHOLDERS = {
    "architecture.md": {"raw", "udp_payload"},
    "errors.md": {"conn"},
    "first-steps.md": {"request", "transport"},
    "http2.md": {"bytes_from_socket", "incoming_bytes", "very_large_body"},
    "http3.md": {"cert", "key", "peer_address", "recv_with_timeout", "sock", "ticket_id", "ticket_psk", "udp_payload"},
}


def check_raises(example: Example, namespace: dict[str, Any]) -> None:
    """The documented exception must be the one the final statement actually raises."""
    found = example.raises
    assert found is not None
    index, name, message = found
    lines = example.source.split("\n")
    assert len(example.claims) == 1, (
        f"{example.path.name}:{example.line} documents an exception alongside other output. "
        f"Nothing after the raise runs, so put the printed output in its own block."
    )

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


def undefined_names(source: str) -> set[str]:
    """The names `source` uses but never defines, via ruff's F821."""
    with tempfile.TemporaryDirectory() as directory:
        # A real file in a temp directory, not NamedTemporaryFile: Windows holds
        # that one open exclusively, so ruff could not read it.
        path = Path(directory) / "example.py"
        path.write_text(source)
        result = subprocess.run(
            ["ruff", "check", "--select", "F821", "--no-cache", "--output-format", "json", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode not in (0, 1):  # 0 = clean, 1 = violations found
        raise RuntimeError(f"ruff could not inspect the example: {result.stderr.strip()}")  # pragma: no cover
    return {m.group(1) for d in json.loads(result.stdout) if (m := re.search(r"`(.+)`", d["message"]))}


@pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff is not installed")
def test_examples_only_reference_documented_placeholders() -> None:
    """An example may not silently depend on a name that nobody defines.

    A reader copies a block and runs it. If it calls `now_us()` and the page never
    says what that is, the example is broken - which is how this test came to be.
    Concatenating a page's blocks mirrors reading it top to bottom, so a block may
    still build on an earlier one.
    """
    blocks = defaultdict(list)
    for example in find_examples(DOCS):
        blocks[example.path.name].append(example.source)

    seen = set()
    for page, sources in sorted(blocks.items()):
        undefined = undefined_names("\n".join(sources))
        seen |= undefined
        unexpected = undefined - PLACEHOLDERS.get(page, set())
        assert not unexpected, (
            f"{page} uses {sorted(unexpected)} without defining them. Define them in "
            f"the example, or add them to PLACEHOLDERS to declare that they are the "
            f"reader's to supply."
        )

    # The pages above genuinely leave names to the reader, so finding none at all
    # means ruff never really ran and this test passed vacuously.
    assert seen, "ruff reported no undefined names anywhere - did it actually inspect the examples?"
