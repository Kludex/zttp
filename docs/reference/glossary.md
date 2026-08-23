---
icon: lucide/list-ordered
---

# Glossary

## ACK

An acknowledgement. A QUIC endpoint sends ACK frames to report which packets it
received. The sender uses them to detect loss and measure round-trip time.

## AEAD

Authenticated Encryption with Associated Data. QUIC uses AEAD algorithms to
encrypt packet contents and detect modification. The packet header remains
available for routing, but it is authenticated with the encrypted payload.

## ALPN

Application-Layer Protocol Negotiation. A TLS handshake uses ALPN to select the
protocol carried by a connection, such as `h2` for HTTP/2 or `h3` for HTTP/3.
zttp starts after that selection because it does not perform socket or TLS I/O
for HTTP/1.1 and HTTP/2.

## Connection ID

A QUIC identifier that routes packets to a connection. It is independent of the
peer's IP address and port, which lets a connection survive network changes.

## Datagram

One message sent over UDP. Datagram boundaries matter to QUIC, so you pass each
UDP payload to `receive_datagram` separately and send each item returned by
`data_to_send()` as a separate datagram.

## FIN

The QUIC stream flag that says the sender has no more bytes for that stream. A
FIN fixes the stream's final byte offset. It does not close other streams or the
QUIC connection.

## Flow control

A limit on how much data a sender may have in flight for a receiver. HTTP/2 and
QUIC maintain both connection-level and stream-level credit. The receiver grants
more credit as it consumes data.

## Frame

A typed protocol unit inside a connection or stream. For example, HTTP/2 uses
`HEADERS`, `DATA`, and `SETTINGS` frames. QUIC has its own frames for stream data,
acknowledgements, flow control, and connection management.

## Head-of-line blocking

A delay where one missing or slow item prevents later independent work from
progressing. HTTP/2 removes HTTP/1.1 response ordering, but TCP can still block
all HTTP/2 streams behind one lost segment. QUIC orders each HTTP/3 stream
independently.

## HPACK

The HTTP/2 header compression format defined by
[RFC 7541](https://www.rfc-editor.org/rfc/rfc7541). It replaces repeated header
fields with references to shared static and dynamic tables. See
[Header compression](../usage/http2.md#header-compression-hpack).

## Multiplexing

Interleaving several independent streams on one connection. Each frame carries a
stream identifier, so the receiver can route it without waiting for another
stream to finish.

## QPACK

The HTTP/3 header compression format defined by
[RFC 9204](https://www.rfc-editor.org/rfc/rfc9204). It adapts HPACK's table-based
compression to QUIC streams without requiring every header block to arrive in
one global order.

## QUIC

The encrypted transport protocol defined by
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000). It runs over UDP and provides
reliability, congestion control, flow control, connection migration, and
independent streams. HTTP/3 runs over QUIC instead of TCP.

## Sans-IO

A protocol implementation that does not read sockets, write sockets, or choose
an event loop. You feed received data into zttp, pull events, and send the bytes
or datagrams that zttp produces.

## Stream

One ordered flow inside a multiplexed connection. HTTP/2 and HTTP/3 assign each
request and response to a stream, and zttp exposes its identifier as
`stream_id`.

## TLS

Transport Layer Security. It authenticates peers and protects traffic. HTTP/3
integrates the TLS 1.3 handshake into QUIC. HTTP/1.1 and HTTP/2 leave TLS to your
I/O layer because zttp receives the decrypted TCP byte stream.

## 0-RTT

Application data sent during a resumed QUIC handshake, before a new handshake
round trip completes. It reduces latency, but an attacker can replay it. Use it
only for operations that are safe to repeat.
