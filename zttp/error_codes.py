"""HTTP/2 error codes from RFC 9113 7.

`RstStream` and `GoAway` events carry `error_code` as a raw integer, and
`Stream.reset()` and `H2Connection.close()` take one. These constants name the
codes so they can be used without magic numbers:

    from zttp import error_codes

    stream.reset(error_codes.PROTOCOL_ERROR)
"""

from __future__ import annotations

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
