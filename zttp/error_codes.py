"""HTTP/2 error codes from RFC 9113.

`RstStream` and `GoAway` events carry `error_code` as a raw integer, and
`Stream.reset()` and `H2Connection.close()` take one. This enum names the codes
(RFC 9113 7) so they can be used without magic numbers:

    stream.reset(H2ErrorCode.PROTOCOL_ERROR)
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["H2ErrorCode"]


class H2ErrorCode(IntEnum):
    """The HTTP/2 error codes (RFC 9113 7).

    Names the integer codes carried by [`RstStream`][zttp.RstStream] and
    [`GoAway`][zttp.GoAway] events, and accepted by `Stream.reset()` and
    `H2Connection.close()`.
    """

    NO_ERROR = 0x00
    PROTOCOL_ERROR = 0x01
    INTERNAL_ERROR = 0x02
    FLOW_CONTROL_ERROR = 0x03
    SETTINGS_TIMEOUT = 0x04
    STREAM_CLOSED = 0x05
    FRAME_SIZE_ERROR = 0x06
    REFUSED_STREAM = 0x07
    CANCEL = 0x08
    COMPRESSION_ERROR = 0x09
    CONNECT_ERROR = 0x0A
    ENHANCE_YOUR_CALM = 0x0B
    INADEQUATE_SECURITY = 0x0C
    HTTP_1_1_REQUIRED = 0x0D
