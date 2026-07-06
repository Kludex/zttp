"""HTTP/2 SETTINGS parameter identifiers.

A `Settings` event carries `params` as raw `(id, value)` integer pairs. This enum
names the ids (RFC 9113 6.5.2) so they can be read without magic numbers:

    values = dict(settings.params)
    values.get(H2Settings.MAX_CONCURRENT_STREAMS)
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["H2Settings"]


class H2Settings(IntEnum):
    """The HTTP/2 SETTINGS parameter identifiers (RFC 9113 6.5.2).

    Names the integer ids carried in a [`Settings`][zttp.Settings] event's `params`,
    so they can be read without magic numbers.
    """

    HEADER_TABLE_SIZE = 0x01
    ENABLE_PUSH = 0x02
    MAX_CONCURRENT_STREAMS = 0x03
    INITIAL_WINDOW_SIZE = 0x04
    MAX_FRAME_SIZE = 0x05
    MAX_HEADER_LIST_SIZE = 0x06
