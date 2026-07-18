---
icon: lucide/radio
---

# HTTP/3

HTTP/3 is the same zttp API again: opt in with one argument, pull the same
events. The difference is the wire. HTTP/3 runs over **QUIC** on UDP, so instead
of feeding a byte stream you feed whole datagrams:

```python
import zttp

server = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
client = zttp.Connection(
    zttp.CLIENT,
    protocol=zttp.HTTP3,
    server_name=b"example.com",
    trust=ca_certificates,  # PEM or DER; see "Verifying the server" below
)
```

As with HTTP/2, the `protocol` argument picks the subtype, so construction
returns an `H3Connection` and the surface you get matches the wire you chose.
zttp provides the QUIC transport defaults internally; constructor fields such as
transport parameters, connection IDs, and handshake entropy are advanced
overrides for deterministic tests and interoperability work, not the normal user
API.

The handshake's two same-typed `bytes` pairs - a server's certificate and key,
and a resumption ticket's identity and PSK - are passed as **value objects** so
they cannot be transposed. A swap is a type error, not a handshake failure:

```python
server = zttp.Connection(
    zttp.SERVER, zttp.HTTP3,
    credentials=zttp.TlsCredentials(certificate=cert, private_key=key),
)
client = zttp.Connection(
    zttp.CLIENT, zttp.HTTP3,
    server_name=b"example.com",
    resumption=zttp.SessionResumption(identity=ticket_id, psk=ticket_psk),
)
```

Omit `credentials` and the server uses an ephemeral self-signed identity for
`localhost` (development only).

## Verifying the server

The HTTP/3 client authenticates the server: it checks the certificate chain
against trust anchors **you** provide, that it is in date, and that a
SubjectAltName matches `server_name`. Verification is **on by default and
fail-closed** - a client with no anchors raises rather than trusting silently:

```python
client = zttp.Connection(
    zttp.CLIENT, zttp.HTTP3,
    server_name=b"example.com",
    trust=ca_certificates,  # bytes: one DER cert, or a PEM bundle of them
)
```

Staying sans-IO, zttp never reads the system trust store or a clock itself - you
load the CAs at your own I/O layer and pass the bytes, and the clock defaults to
`time.time()` (override with `now_sec=`). To verify against the OS trust store,
hand it in:

```python
import ssl

der_certs = b"".join(ssl.create_default_context().get_ca_certs(binary_form=True))
client = zttp.Connection(zttp.CLIENT, zttp.HTTP3, server_name=b"example.com", trust=der_certs)
```

Two escape hatches:

- **Pinning.** Pass the exact server certificate as `trust=` - handy for a
  self-signed dev server. `zttp.generate_self_signed(dns_name, private_key,
  not_before, not_after)` mints one (the same DER goes to the server as
  `credentials` and to the client as `trust`).
- **Opt out.** `verify=False` disables authentication entirely. It is explicit
  and dangerous - only for local testing over a trusted link.

!!! note "Signature algorithms"
    Chain verification covers the real-world set: ECDSA P-256/P-384 and RSA
    (PKCS#1 v1.5 and PSS) with SHA-256/384/512 - so an ordinary chain (an ECDSA or
    RSA leaf under RSA certificate authorities) verifies. The certificate the
    *server presents as its own leaf* is still limited to ECDSA P-256 by the
    handshake's `CertificateVerify` (RFC 9001), independent of this - so a
    verifying client talks to servers with an ECDSA P-256 leaf, whatever CAs sign
    it.

!!! warning "Scope"
    HTTP/3 support is still experimental. The public surface is intentionally
    the same event model as HTTP/1.1 and HTTP/2, but the transport underneath is
    new code: QUIC packet protection, loss recovery, flow control, connection
    migration, TLS 1.3, and QPACK all live inside zttp's core. The convenience
    server constructor generates an ephemeral TLS identity for each connection;
    it is suitable for local experiments, not for production server identity.

## How HTTP/3 works

You just learned HTTP/2: many requests share one connection, each on its own
stream, all interleaved. **Multiplexing.** That part HTTP/3 keeps. So you
already have the right mental model, and there is really only one new idea to
add.

That idea is the transport underneath.

### The leftover problem

HTTP/2 multiplexes streams, but it still rides on a single TCP connection, and
TCP delivers exactly one ordered byte stream. So when a single TCP segment is
lost, TCP holds back *everything* that came after it until the retransmission
arrives, even bytes that belong to completely unrelated streams. Your streams
are independent to HTTP/2, but they are not independent to TCP.

That is **head-of-line blocking**, and this time it lives at the transport
layer, below anything HTTP/2 can fix.

!!! note "HTTP/2 didn't have *no* head-of-line blocking"

    You often hear "HTTP/2 fixed head-of-line blocking." It fixed it at the
    *application* layer: no more waiting in line inside the HTTP framing. But the
    single ordered TCP stream brings it right back at the *transport* layer. One
    lost segment, every stream waits. HTTP/3's whole reason to exist is to remove
    that.

So HTTP/3 does the one thing HTTP/2 couldn't: it changes the transport.

### QUIC: a new transport on UDP

HTTP/3 runs over **QUIC**, a general-purpose transport protocol that sits on top
of UDP. UDP on its own gives you almost nothing - just "here is a datagram for
this port." Everything that makes a transport trustworthy, QUIC provides itself:
connection setup, reliability (it detects loss and retransmits), congestion
control, and flow control. The same jobs TCP did, now done in QUIC.

Here is the one change that matters. TCP orders the *whole connection*. QUIC
orders *each stream on its own*.

So when a packet is lost, QUIC only holds back the stream or streams whose bytes
were in that packet. Every other stream keeps flowing, delivered, not waiting on
anybody. That is the entire payoff.

```mermaid
flowchart TB
    subgraph H2["HTTP/2 over TCP - one ordered byte stream"]
        direction TB
        L2["Segment for stream 1 is LOST"]
        L2 --> B2["TCP must wait for retransmission"]
        B2 --> S1x["stream 1 - blocked"]
        B2 --> S3x["stream 3 - blocked too (it was just waiting in line)"]
    end

    subgraph H3["HTTP/3 over QUIC - independent streams"]
        direction TB
        L3["Packet carrying stream 1 is LOST"]
        L3 --> Q1x["stream 1 - blocked, waits for its retransmission"]
        L3 --> Q3ok["stream 3 - delivered now, it never needed those bytes"]
    end
```

The difference is the second column. On TCP, losing stream 1's data freezes
stream 3 for no reason. On QUIC, stream 3 sails right past. Same lost packet,
completely different outcome.

!!! info "Within one stream, order still matters"

    QUIC removes head-of-line blocking *across* streams, not *inside* one. A
    single stream is still an ordered byte stream, so a gap early in stream 1
    still holds back the later bytes of stream 1. That is fine - it is exactly
    what you want. The win is that stream 1's gap is stream 1's problem, and
    nobody else's.

This is why, just like HTTP/2, every HTTP/3 event carries a `stream_id`: each
request lives on its own client-initiated bidirectional QUIC stream, and those
streams really are independent all the way down.

### Encryption is built in (TLS 1.3)

QUIC doesn't run TLS *on top* of itself the way HTTPS runs TLS on top of TCP.
The TLS 1.3 handshake and the transport handshake are a single combined
exchange: TLS messages travel inside QUIC `CRYPTO` frames, and TLS hands QUIC
the keys it uses to protect every packet. Encryption is **mandatory** - there is
no plaintext mode - and a fresh connection is ready in one round trip, or zero
when you resume an earlier session.

!!! warning "0-RTT is replayable"

    Sending data in that first 0-RTT flight is delightful for latency, but that
    data is not forward-secret and an attacker can replay it. So only replay-safe
    requests (think idempotent ones) belong in 0-RTT. A performance treat with a
    real security string attached.

### Connection migration

Here is my favorite part.

A TCP connection *is* its four-tuple: source IP, source port, destination IP,
destination port. Change any of them - walk out of Wi-Fi range and onto cellular
- and TCP sees a different connection. The old one is gone, and you start over.

QUIC doesn't identify a connection by the address at all. It identifies it by a
**Connection ID** the endpoints chose. So when your phone switches networks and
your IP changes, the Connection ID is still the same, and the connection just...
keeps going. The download doesn't restart. The handshake doesn't repeat.

It just works.

### QPACK

HTTP/2 compressed headers with HPACK. HTTP/3 uses **QPACK**, its successor.
Same good ideas - a static table, a dynamic table, Huffman coding - redesigned
for one specific reason: HPACK assumed a single, totally ordered stream of
header blocks, and over QUIC's independent streams that assumption breaks. QPACK
is built so that compressing headers does not quietly reintroduce the very
head-of-line blocking you came here to escape. zttp advertises a bounded dynamic
table and blocked-stream limit, resumes streams that wait for encoder updates,
and falls back to static/literal encoding when the peer disables dynamic QPACK.

### Why this changes zttp's job

For HTTP/1.1 and HTTP/2, the kernel's TCP did the hard transport work and handed
zttp a clean, ordered, reliable byte stream. The core only had to **parse**.

For HTTP/3, there is no TCP to lean on. So the core has to *be* the transport:
packet protection, loss recovery, congestion control, stream reassembly - all of
it. That is also why HTTP/3 takes whole UDP datagrams instead of a byte stream:
the transport has to see real packet boundaries to do its job.

And the sans-IO line still holds: the core does all of this without ever
touching a socket.

## Datagrams in, events out

TCP hands you an ordered byte stream, so HTTP/1.1 and HTTP/2 take
`receive_data(bytes)`. QUIC is packet-oriented and the transport must see
datagram boundaries, so HTTP/3 takes `receive_datagram` instead. Pass one UDP
payload per call, exactly as it came off the socket; the QUIC layer underneath
decrypts the packets, tracks acks, and reassembles the stream bytes for you. The
event side is unchanged:

```python title="server_read.py"
import zttp

conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP3)
conn.receive_datagram(udp_payload)

while (event := conn.next_event()) is not zttp.NEED_DATA:
    if isinstance(event, zttp.Request):
        print(event.method, event.path, event.stream_id)
```

You get the same `Request` / `Data` / `EndOfMessage` events, now tagged with the
QUIC `stream_id`. An HTTP/3 request collapses its pseudo-headers into the same
shape the other protocols use, and `http_version` is `b"3"`.

## The transport is inside

For HTTP/1.1 and HTTP/2, the kernel's TCP gives zttp an ordered, reliable byte
stream and the core only parses it. For HTTP/3, the core also *is* the
transport: packet protection, loss recovery, congestion control, flow control,
and stream reassembly all live in the Zig core, written from scratch on
`std.crypto`. The sans-IO line holds: the core never touches a socket; your I/O
layer moves the datagrams.

Read [Architecture](../architecture.md) for the layering and the QUIC-as-transport
tour, including the security posture (amplification limits, AEAD packet
protection, and the QPACK bomb defenses).

## Where to go next

<div class="grid cards" markdown>

-   :material-transit-connection-variant: **[HTTP/2](http2.md)**

    ---

    The same multiplexed event model over TCP, with the full write side.

-   :material-sitemap: **[Architecture](../architecture.md)**

    ---

    How the from-scratch QUIC transport is built, layer by layer.

</div>
