"""Compare zttp's HTTP/3 path against aioquic on request/response throughput.

aioquic is the reference Python HTTP/3 stack: a pure-Python QUIC transport with
QPACK accelerated by the `pylsqpack` C extension. It is the only mainstream Python
HTTP/3 implementation, so this pits zttp's Zig core against the fastest Python
option there is, not against a C/Rust peer (none exists). Read the ratios with
that in mind.

Unlike the HTTP/1 and HTTP/2 benchmarks, this is not a pure parse: HTTP/3 has no
plaintext mode, so every request and response also pays QUIC packet protection.
Both stacks run in memory (no sockets) over one established connection, and the
timed unit is a full request -> response **round-trip** (client sends a request,
server parses it and answers, client parses the response). msg/s counts those
round-trips.

Methodology mirrors http1.py / http2.py: many short batches interleaved
round-robin so thermal drift hits both stacks equally, GC disabled while a batch
is timed, and the median batch reported with its p25-p75 quartiles and stdev.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gc
import ssl
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import zttp

AUTHORITY = b"bench.test"


@dataclass(frozen=True)
class Workload:
    name: str
    method: bytes
    path: bytes
    request_headers: list[tuple[bytes, bytes]]
    request_body: bytes = b""
    response_headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    response_body: bytes = b""
    scale: float = 1.0  # batch-size multiplier for heavier round-trips


JSON_BODY = b'{"username": "alice", "password": "correcthorsebattery"}'
RESP_JSON = b'{"message": "Hello, World!"}'

WORKLOADS = [
    Workload("bare GET", b"GET", b"/", [], response_headers=[(b"content-length", b"0")]),
    Workload(
        "small API GET",
        b"GET",
        b"/api/v1/users/12345?include=profile",
        [
            (b"user-agent", b"bench/1.0"),
            (b"accept", b"application/json"),
            (b"accept-encoding", b"gzip, deflate, br"),
            (b"authorization", b"Bearer abcdef0123456789"),
        ],
        response_headers=[
            (b"content-type", b"application/json"),
            (b"content-length", str(len(RESP_JSON)).encode()),
        ],
        response_body=RESP_JSON,
    ),
    Workload(
        "POST JSON body",
        b"POST",
        b"/api/v1/login",
        [(b"content-type", b"application/json"), (b"content-length", str(len(JSON_BODY)).encode())],
        request_body=JSON_BODY,
        response_headers=[(b"content-length", b"0")],
    ),
]


Runner = Callable[[int], None]


# -- certificate for aioquic's TLS handshake (generated once) -----------------

_TMP = tempfile.TemporaryDirectory()


def _make_cert() -> tuple[str, str, bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, AUTHORITY.decode())])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(AUTHORITY.decode())]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = Path(_TMP.name) / "cert.pem"
    key_path = Path(_TMP.name) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    private_scalar = key.private_numbers().private_value.to_bytes(32, "big")
    return str(cert_path), str(key_path), cert.public_bytes(serialization.Encoding.DER), private_scalar


# -- zttp ---------------------------------------------------------------------


def make_zttp(w: Workload) -> Runner:
    _cert_path, _key_path, certificate, private_key = _make_cert()
    client = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        server_name=AUTHORITY,
        server_certificate=certificate,
    )
    server = zttp.Connection(
        zttp.SERVER,
        protocol=zttp.HTTP3,
        credentials=zttp.TlsCredentials(certificate=certificate, private_key_scalar=private_key),
    )
    now = [1000]

    def transfer(src: zttp.H3Connection, dst: zttp.H3Connection) -> None:
        for datagram in src.data_to_send():
            dst.receive_datagram(datagram, now[0])

    for _ in range(6):  # drive the handshake to completion
        transfer(client, server)
        transfer(server, client)
        now[0] += 1000

    request_headers = [(b"host", AUTHORITY), *w.request_headers]

    def run(n: int) -> None:
        for _ in range(n):
            now[0] += 100
            stream = client.send_request(w.method, w.path, b"3", request_headers)
            if w.request_body:
                stream.send_data(w.request_body)
            stream.end_message()
            transfer(client, server)
            while (event := server.next_event()) is not zttp.NEED_DATA:
                if isinstance(event, zttp.Request):
                    response = server.stream(event.stream_id)
                    response.send_response(200, w.response_headers)
                    if w.response_body:
                        response.send_data(w.response_body)
                    response.end_message()
            transfer(server, client)
            saw_response = False
            while (event := client.next_event()) is not zttp.NEED_DATA:
                if isinstance(event, zttp.Response):
                    saw_response = event.status_code == 200
            if not saw_response:
                raise RuntimeError(f"zttp did not complete the {w.name} round-trip")

    return run


def make_zttp_multiplexed(active_streams: int) -> Runner:
    _cert_path, _key_path, certificate, private_key = _make_cert()
    transport_params = zttp.QuicTransportParameters(initial_max_streams_bidi=256)
    client = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        server_name=AUTHORITY,
        server_certificate=certificate,
        transport_params=transport_params,
    )
    server = zttp.Connection(
        zttp.SERVER,
        protocol=zttp.HTTP3,
        credentials=zttp.TlsCredentials(certificate=certificate, private_key_scalar=private_key),
        transport_params=transport_params,
    )
    now = [1000]

    def transfer(src: zttp.H3Connection, dst: zttp.H3Connection) -> None:
        for datagram in src.data_to_send():
            dst.receive_datagram(datagram, now[0])

    for _ in range(6):
        transfer(client, server)
        transfer(server, client)
        now[0] += 1000

    requests = 0
    for _ in range(active_streams - 1):
        client.send_request(
            b"POST",
            b"/",
            b"3",
            [(b"host", AUTHORITY)],
        )
        transfer(client, server)
        while (event := server.next_event()) is not zttp.NEED_DATA:
            if isinstance(event, zttp.Request):
                requests += 1
        transfer(server, client)
    if requests != active_streams - 1:
        raise RuntimeError(f"zttp opened {requests}/{active_streams - 1} held request streams")

    def run(n: int) -> None:
        received = 0
        for _ in range(n):
            now[0] += 100
            stream = client.send_request(
                b"GET",
                b"/",
                b"3",
                [(b"host", AUTHORITY)],
            )
            stream.end_message()
            transfer(client, server)
            while (event := server.next_event()) is not zttp.NEED_DATA:
                if isinstance(event, zttp.Request):
                    received += 1
            transfer(server, client)
        if received != n:
            raise RuntimeError(f"zttp delivered {received}/{n} multiplexed requests")

    return run


# -- aioquic ------------------------------------------------------------------


def make_aioquic(w: Workload) -> Runner:
    cert_path, key_path, _certificate, _private_key = _make_cert()
    server_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    server_config.load_cert_chain(cert_path, key_path)
    client_config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    client_config.verify_mode = ssl.CERT_NONE

    clock = [0.0]
    client = QuicConnection(configuration=client_config)
    client.connect(("server", 4433), now=clock[0])
    initial = client.datagrams_to_send(now=clock[0])
    header = pull_quic_header(Buffer(data=initial[0][0]), host_cid_length=8)
    server = QuicConnection(configuration=server_config, original_destination_connection_id=header.destination_cid)
    client_addr, server_addr = ("client", 1), ("server", 2)
    for datagram, _addr in initial:
        server.receive_datagram(datagram, client_addr, now=clock[0])

    client_h3, server_h3 = H3Connection(client), H3Connection(server)
    request_headers = [
        (b":method", w.method),
        (b":scheme", b"https"),
        (b":authority", AUTHORITY),
        (b":path", w.path),
        *w.request_headers,
    ]
    response_headers = [(b":status", b"200"), *w.response_headers]
    counters = {"responses": 0}

    def drive_server() -> None:
        for event in iter(server.next_event, None):
            for h3_event in server_h3.handle_event(event):
                # Answer once the request stream ends - via HEADERS (bodyless) or the
                # final DATA (a request with a body).
                if isinstance(h3_event, (HeadersReceived, DataReceived)) and h3_event.stream_ended:
                    server_h3.send_headers(h3_event.stream_id, response_headers, end_stream=not w.response_body)
                    if w.response_body:
                        server_h3.send_data(h3_event.stream_id, w.response_body, end_stream=True)

    def drive_client() -> None:
        for event in iter(client.next_event, None):
            for h3_event in client_h3.handle_event(event):
                if isinstance(h3_event, HeadersReceived) and h3_event.stream_ended:
                    counters["responses"] += 1
                elif isinstance(h3_event, DataReceived) and h3_event.stream_ended:
                    counters["responses"] += 1

    def pump() -> None:
        for _ in range(12):
            clock[0] += 0.001
            moved = False
            for datagram, _addr in client.datagrams_to_send(now=clock[0]):
                server.receive_datagram(datagram, client_addr, now=clock[0])
                moved = True
            drive_server()
            for datagram, _addr in server.datagrams_to_send(now=clock[0]):
                client.receive_datagram(datagram, server_addr, now=clock[0])
                moved = True
            drive_client()
            if not moved:
                return

    pump()  # finish the handshake

    def run(n: int) -> None:
        target = counters["responses"] + n
        for _ in range(n):
            stream_id = client.get_next_available_stream_id()
            client_h3.send_headers(stream_id, request_headers, end_stream=not w.request_body)
            if w.request_body:
                client_h3.send_data(stream_id, w.request_body, end_stream=True)
            pump()
        if counters["responses"] != target:
            raise RuntimeError(f"aioquic completed {counters['responses'] - target + n}/{n} {w.name} round-trips")

    return run


RUNNERS: list[tuple[str, Callable[[Workload], Runner]]] = [
    ("zttp", make_zttp),
    ("aioquic", make_aioquic),
]


def verify(w: Workload) -> None:
    for _, make in RUNNERS:
        make(w)(1)  # a single round-trip; the runners raise if it does not complete


def timed(fn: Runner, n: int) -> float:
    gc.collect()
    gc.disable()
    try:
        start = time.perf_counter()
        fn(n)
        return time.perf_counter() - start
    finally:
        gc.enable()


# workload -> (ratio median, p25, p75), filled by bench() for the summary.
dispersion: dict[str, tuple[float, float, float]] = {}


def _quartiles(values: list[float]) -> tuple[float, float, float]:
    if len(values) < 2:
        v = values[0]
        return (v, v, v)
    q1, median, q3 = statistics.quantiles(values, n=4)
    return (q1, median, q3)


def bench(w: Workload, batch: int, repeats: int) -> dict[str, float]:
    verify(w)
    batch = max(1, int(batch * w.scale))
    runners = [(label, make(w)) for label, make in RUNNERS]
    print(f"\n== {w.name} ({repeats} batches of {batch:,} round-trips) ==")

    for _, fn in runners:
        fn(max(1, batch // 10))  # warmup

    samples: dict[str, list[float]] = {label: [] for label, _ in runners}
    for _ in range(repeats):
        for label, fn in runners:
            samples[label].append(timed(fn, batch))

    per_batch = {label: [batch / dt for dt in batches] for label, batches in samples.items()}
    rates: dict[str, float] = {}
    for label, values in per_batch.items():
        p25, median, p75 = _quartiles(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0.0
        rates[label] = median
        print(
            f"  {label:>10}: {median:12,.0f} req/s  "
            f"(median of {repeats}, p25-p75 {p25:,.0f}-{p75:,.0f}, stdev {stdev / median * 100:4.1f}%)"
        )

    ratios = [z / a for z, a in zip(per_batch["zttp"], per_batch["aioquic"], strict=True)]
    r25, rmed, r75 = _quartiles(ratios)
    dispersion[w.name] = (rmed, r25, r75)
    print(f"  -> zttp is {rmed:.1f}x aioquic (p25-p75 {r25:.1f}-{r75:.1f})")
    return rates


def bench_active_stream_scaling(batch: int, repeats: int) -> None:
    print(f"\n== one changed stream by active stream count ({repeats} batches of {batch:,} requests) ==")
    for active_streams in (1, 16, 64):
        run = make_zttp_multiplexed(active_streams)
        run(max(1, batch // 10))
        samples = [batch / timed(run, batch) for _ in range(repeats)]
        p25, median, p75 = _quartiles(samples)
        print(f"  {active_streams:>3} active: {median:12,.0f} requests/s  (p25-p75 {p25:,.0f}-{p75:,.0f})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=int, default=2_000, help="round-trips per timed batch")
    parser.add_argument("--repeats", type=int, default=15, help="timed batches per stack")
    parser.add_argument("--only", type=str, default=None, help="substring filter on workload names")
    parser.add_argument(
        "--active-stream-scaling",
        action="store_true",
        help="measure one changed stream with 1, 16, and 64 active streams",
    )
    args = parser.parse_args()

    print(
        f"CPython {sys.version.split()[0]}, zttp {version('zttp')}, aioquic {version('aioquic')} (Python QUIC, C QPACK)"
    )
    if args.active_stream_scaling:
        bench_active_stream_scaling(args.batch, args.repeats)
        return
    selected = [w for w in WORKLOADS if args.only is None or args.only.lower() in w.name.lower()]
    results = {w.name: bench(w, args.batch, args.repeats) for w in selected}

    print(f"\n{'workload':<24} {'zttp':>12} {'aioquic':>12} {'ratio':>7} {'p25-p75':>12}")
    for name, rates in results.items():
        rmed, r25, r75 = dispersion[name]
        print(
            f"{name:<24} {rates['zttp']:>12,.0f} {rates['aioquic']:>12,.0f} {rmed:>5.1f}x {f'{r25:.1f}-{r75:.1f}':>12}"
        )


if __name__ == "__main__":
    main()
