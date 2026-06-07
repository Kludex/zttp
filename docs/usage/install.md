---
icon: lucide/download
---

# Installation

zttp ships as a wheel with the Zig core already compiled, so installing it is just:

```console
pip install zttp
```

That's all you need. There's nothing else to configure. ✨

!!! note "Requirements"
    zttp needs **CPython 3.12+** and runs on **Linux**, **macOS**, and **Windows**.

## With uv

If you use [uv](https://docs.astral.sh/uv/) (we do):

```console
uv add zttp
```

## Building from source

Wheels cover the common platforms, so most people never compile anything. But the
source distribution builds the Zig extension on install - you only need a Zig
toolchain, and even that comes along automatically:

```console
pip install --no-binary zttp zttp
```

The build pulls in the [`ziglang`](https://pypi.org/project/ziglang/) wheel as a
build dependency, so there's **no system Zig to install**. The whole thing
compiles in an isolated build environment.

!!! info "Why is there a Zig compiler involved?"
    zttp's parsing engine is written in Zig and exposed to Python as a C
    extension. A wheel ships that engine already built for your platform; the
    sdist ships the Zig sources and compiles them for you. Either way, you just
    `import zttp`.

## Verify it

```python
import zttp

conn = zttp.Connection(zttp.SERVER)
conn.receive_data(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
assert type(conn.next_event()).__name__ == "Request"
print("zttp works 🎉")
```
