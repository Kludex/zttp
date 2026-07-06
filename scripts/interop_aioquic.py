from __future__ import annotations

import datetime as dt
import importlib
import os
import select
import ssl
import socket
import tempfile
import time
from pathlib import Path

import zttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


QUIC_BACKEND = os.environ.get("ZTTP_INTEROP_BACKEND", "aioquic")
if QUIC_BACKEND not in {"aioquic", "qh3"}:
    raise SystemExit(f"unsupported QUIC interop backend: {QUIC_BACKEND}")

_packet_mod = importlib.import_module(f"{QUIC_BACKEND}.quic.packet")
if QUIC_BACKEND == "aioquic":
    Buffer = importlib.import_module("aioquic.buffer").Buffer
else:
    Buffer = _packet_mod.Buffer
_h3_conn_mod = importlib.import_module(f"{QUIC_BACKEND}.h3.connection")
_h3_events_mod = importlib.import_module(f"{QUIC_BACKEND}.h3.events")
_quic_config_mod = importlib.import_module(f"{QUIC_BACKEND}.quic.configuration")
_quic_conn_mod = importlib.import_module(f"{QUIC_BACKEND}.quic.connection")
_quic_events_mod = importlib.import_module(f"{QUIC_BACKEND}.quic.events")

H3Connection = _h3_conn_mod.H3Connection
FrameType = _h3_conn_mod.FrameType
encode_frame = _h3_conn_mod.encode_frame
encode_uint_var = _h3_conn_mod.encode_uint_var
DataReceived = _h3_events_mod.DataReceived
HeadersReceived = _h3_events_mod.HeadersReceived
QuicConfiguration = _quic_config_mod.QuicConfiguration
MAX_EARLY_DATA = _quic_conn_mod.MAX_EARLY_DATA
QuicConnection = _quic_conn_mod.QuicConnection
ConnectionTerminated = _quic_events_mod.ConnectionTerminated
pull_quic_header = _packet_mod.pull_quic_header


CLIENT_TP = (
    b"\x04\x04\x80\x01\x00\x00"  # initial_max_data = 65536
    b"\x05\x04\x80\x04\x00\x00"  # initial_max_stream_data_bidi_local = 262144
    b"\x06\x04\x80\x04\x00\x00"  # initial_max_stream_data_bidi_remote = 262144
    b"\x07\x04\x80\x04\x00\x00"  # initial_max_stream_data_uni = 262144
    b"\x08\x01\x10"  # initial_max_streams_bidi = 16
    b"\x09\x01\x10"  # initial_max_streams_uni = 16
)
ZTTP_SERVER_TP = (
    b"\x04\x04\x80\x10\x00\x00"  # initial_max_data = 1048576
    b"\x08\x01\x08"  # initial_max_streams_bidi = 8
    b"\x09\x01\x08"  # initial_max_streams_uni = 8
    b"\x06\x04\x80\x04\x00\x00"  # initial_max_stream_data_bidi_remote = 262144
    b"\x07\x04\x80\x04\x00\x00"  # initial_max_stream_data_uni = 262144
)
ZTTP_SERVER_TICKET_EXTENSIONS = b"\x00\x39" + len(ZTTP_SERVER_TP).to_bytes(2, "big") + ZTTP_SERVER_TP
ZTTP_SERVER_PUBLIC_KEY_SEC1 = bytes.fromhex(
    "042ca00e33928e5b66cc63a70e91c78f5d9e0db34711f9108778151912d389c589"
    "c6c886572fd6dad9d01e0b98c5fec3276e9a2e4b89705140f564f7eb65016b95"
)


def make_cert_chain(tmp: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp / "cert.pem"
    key_path = tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def make_zttp_server_cert_der() -> bytes:
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ZTTP_SERVER_PUBLIC_KEY_SEC1)
    signing_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(signing_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def drain_quic_to_h3(server: QuicConnection, h3: H3Connection) -> list[object]:
    events: list[object] = []
    while True:
        event = server.next_event()
        if event is None:
            return events
        events.extend(h3.handle_event(event))


def obfuscated_ticket_age(age_add: int, issued_at: int, now: int) -> int:
    return ((now - issued_at) // 1000 + age_add) & 0xFFFFFFFF


def assert_zttp_client_to_aioquic_server(tmp: Path) -> None:
    cert_path, key_path = make_cert_chain(tmp)
    server_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    server_config.load_cert_chain(str(cert_path), str(key_path))
    issued_tickets: list[object] = []

    dcid = b"\x11\x22\x33\x44"
    client = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        transport_params=CLIENT_TP,
        random=b"\x44" * 32,
        ephemeral_seed=b"\x55" * 32,
        connection_id=dcid,
        alpn=b"h3",
        server_name=b"localhost",
    )

    client_initial = client.data_to_send()[0]
    header = pull_quic_header(Buffer(data=client_initial), host_cid_length=None)
    server = QuicConnection(
        configuration=server_config,
        original_destination_connection_id=header.destination_cid,
        session_ticket_handler=issued_tickets.append,
    )
    h3 = H3Connection(server)

    server.receive_datagram(client_initial, ("client", 1234), 0.0)
    for datagram, _addr in server.datagrams_to_send(0.001):
        client.receive_datagram(datagram, 1_000)
    for datagram in client.data_to_send():
        server.receive_datagram(datagram, ("client", 1234), 0.002)
    drain_quic_to_h3(server, h3)
    for datagram, _addr in server.datagrams_to_send(0.003):
        client.receive_datagram(datagram, 3_000)
    tickets = client.session_tickets()
    if (
        len(issued_tickets) != 1
        or len(tickets) != 1
        or tickets[0].ticket != issued_tickets[0].ticket
        or tickets[0].max_early_data_size != MAX_EARLY_DATA
    ):
        raise SystemExit(
            "zttp did not receive aioquic's NewSessionTicket: "
            f"issued={issued_tickets!r} stored={tickets!r}"
        )
    ticket = tickets[0]
    if ticket.psk != issued_tickets[0].resumption_secret:
        raise SystemExit("zttp derived a different PSK for aioquic's NewSessionTicket")

    resumed = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        transport_params=CLIENT_TP,
        random=b"\x66" * 32,
        ephemeral_seed=b"\x77" * 32,
        connection_id=b"\x11\x22\x33\x45",
        alpn=b"h3",
        server_name=b"localhost",
        resumption=zttp.SessionResumption(identity=ticket.ticket, psk=ticket.psk),
        obfuscated_ticket_age=obfuscated_ticket_age(ticket.age_add, 3_000, 10_000),
        early_data=True,
        remembered_transport_params=ZTTP_SERVER_TP,
    )
    early_stream = resumed.send_request(
        b"GET",
        b"/early-interop",
        b"3",
        [(b"host", b"localhost"), (b"content-length", b"0")],
    )
    early_stream.end_message()
    resumed_datagrams = resumed.data_to_send()
    if len(resumed_datagrams) < 2:
        raise SystemExit("zttp did not emit a 0-RTT datagram for the resumed request")

    resumed_header = pull_quic_header(Buffer(data=resumed_datagrams[0]), host_cid_length=None)
    resumed_server = QuicConnection(
        configuration=server_config,
        original_destination_connection_id=resumed_header.destination_cid,
        session_ticket_fetcher=lambda identity: issued_tickets[0] if identity == ticket.ticket else None,
    )
    resumed_h3 = H3Connection(resumed_server)
    early_events: list[object] = []
    for datagram in resumed_datagrams:
        resumed_server.receive_datagram(datagram, ("client-early", 1234), 0.010)
        early_events.extend(drain_quic_to_h3(resumed_server, resumed_h3))
    early_headers = [event for event in early_events if isinstance(event, HeadersReceived)]
    early_data = [event for event in early_events if isinstance(event, DataReceived)]
    if (
        not early_headers
        or (b":method", b"GET") not in early_headers[0].headers
        or (b":path", b"/early-interop") not in early_headers[0].headers
        or not early_data
        or early_data[-1].data != b""
        or not early_data[-1].stream_ended
        or not resumed_server.tls.early_data_accepted
        or resumed_server._handshake_complete
    ):
        raise SystemExit(f"aioquic did not receive zttp's 0-RTT request before handshake completion: {early_events!r}")

    stream = client.send_request(
        b"POST",
        b"/interop",
        b"3",
        [(b"host", b"localhost"), (b"content-length", b"4")],
    )
    stream.send_data(b"body")
    stream.end_message([(b"x-zttp-trailer", b"done")])
    received: list[object] = []
    migrated_client = ("client-migrated", 1234)
    for datagram in client.data_to_send():
        server.receive_datagram(datagram, migrated_client, 0.004)
        received.extend(drain_quic_to_h3(server, h3))
    challenges = server.datagrams_to_send(0.0045)
    if not challenges:
        raise SystemExit("aioquic did not challenge zttp's migrated client path")
    if any(addr != migrated_client for _datagram, addr in challenges):
        raise SystemExit(f"aioquic challenged the wrong migrated zttp client path: {challenges!r}")
    for datagram, _addr in challenges:
        client.receive_datagram(datagram, 4_500)
    responses = client.data_to_send()
    if not responses:
        raise SystemExit("zttp did not answer aioquic's migrated-path challenge")
    for datagram in responses:
        server.receive_datagram(datagram, migrated_client, 0.0047)
    drain_quic_to_h3(server, h3)

    headers = [event for event in received if isinstance(event, HeadersReceived)]
    data = [event for event in received if isinstance(event, DataReceived)]
    if not headers:
        raise SystemExit("aioquic did not receive an HTTP/3 HEADERS frame from zttp")
    if (b":method", b"POST") not in headers[0].headers or (b":path", b"/interop") not in headers[0].headers:
        raise SystemExit(f"aioquic received unexpected headers: {headers[0].headers!r}")
    if not data or data[0].data != b"body":
        raise SystemExit(f"aioquic did not receive the zttp request body: {received!r}")
    if len(headers) < 2 or (b"x-zttp-trailer", b"done") not in headers[-1].headers or not headers[-1].stream_ended:
        raise SystemExit(f"aioquic did not receive zttp request trailers/end: {received!r}")

    interim = h3._encode_headers(headers[0].stream_id, [(b":status", b"103"), (b"link", b"</style.css>; rel=preload")])
    server.send_stream_data(headers[0].stream_id, encode_frame(FrameType.HEADERS, interim))
    h3.send_headers(headers[0].stream_id, [(b":status", b"200"), (b"content-length", b"2")])
    h3.send_data(headers[0].stream_id, b"ok", end_stream=False)
    h3.send_headers(headers[0].stream_id, [(b"x-aioquic-trailer", b"done")], end_stream=True)
    for datagram, addr in server.datagrams_to_send(0.005):
        if addr != migrated_client:
            raise SystemExit(f"aioquic response was not routed to zttp's validated migrated path: {addr!r}")
        client.receive_datagram(datagram, 5_000)

    response_events = []
    while True:
        event = client.next_event()
        if event is zttp.NEED_DATA:
            break
        response_events.append(event)
    responses = [event for event in response_events if event.__class__.__name__ == "Response"]
    bodies = [event for event in response_events if event.__class__.__name__ == "Data"]
    if [response.status_code for response in responses[:2]] != [103, 200]:
        raise SystemExit(f"zttp did not receive the aioquic response: {response_events!r}")
    if not bodies or bodies[0].data != b"ok":
        raise SystemExit(f"zttp did not receive the aioquic response body: {response_events!r}")
    eoms = [event for event in response_events if event.__class__.__name__ == "EndOfMessage"]
    if not eoms or eoms[-1].trailers != [(b"x-aioquic-trailer", b"done")]:
        raise SystemExit(f"zttp did not receive the aioquic response trailers/end: {response_events!r}")

    for datagram in client.data_to_send():
        server.receive_datagram(datagram, migrated_client, 0.0051)
        drain_quic_to_h3(server, h3)
    client.request_key_update()
    key_update_stream = client.send_request(
        b"GET",
        b"/key-update",
        b"3",
        [(b"host", b"localhost"), (b"content-length", b"0")],
    )
    key_update_stream.end_message()
    key_update_received: list[object] = []
    key_update_datagrams = client.data_to_send()
    for datagram in key_update_datagrams:
        server.receive_datagram(datagram, migrated_client, 0.0052)
        key_update_received.extend(drain_quic_to_h3(server, h3))
    key_update_headers = [event for event in key_update_received if isinstance(event, HeadersReceived)]
    key_update_data = [event for event in key_update_received if isinstance(event, DataReceived)]
    if (
        not key_update_headers
        or (b":method", b"GET") not in key_update_headers[0].headers
        or (b":path", b"/key-update") not in key_update_headers[0].headers
        or not key_update_data
        or key_update_data[-1].data != b""
        or not key_update_data[-1].stream_ended
    ):
        close_event = getattr(server, "_close_event", None)
        raise SystemExit(
            "aioquic did not receive zttp's post-key-update request: "
            f"datagrams={len(key_update_datagrams)} events={key_update_received!r} close={close_event!r}"
        )

    server.send_stream_data(h3._local_control_stream_id, encode_frame(FrameType.GOAWAY, encode_uint_var(8)))
    for datagram, addr in server.datagrams_to_send(0.0055):
        if addr != migrated_client:
            raise SystemExit(f"aioquic GOAWAY was not routed to zttp's validated migrated path: {addr!r}")
        client.receive_datagram(datagram, 5_500)

    goaway_events = []
    while True:
        event = client.next_event()
        if event is zttp.NEED_DATA:
            break
        goaway_events.append(event)
    goaways = [event for event in goaway_events if event.__class__.__name__ == "Goaway"]
    if not goaways or goaways[-1].last_stream_id != 8 or client.goaway_received() != 8:
        raise SystemExit(f"zttp did not receive aioquic's GOAWAY: {goaway_events!r}")

    client.close(error_code=0x0100, reason=b"zttp-close")
    close_datagrams = client.data_to_send()
    if not close_datagrams:
        raise SystemExit("zttp did not emit a CONNECTION_CLOSE datagram")
    for datagram in close_datagrams:
        server.receive_datagram(datagram, migrated_client, 0.006)
    close_event = getattr(server, "_close_event", None)
    if (
        not isinstance(close_event, ConnectionTerminated)
        or close_event.error_code != 0x0100
        or close_event.reason_phrase != "zttp-close"
    ):
        raise SystemExit(f"aioquic did not receive zttp's CONNECTION_CLOSE: {close_event!r}")


def assert_aioquic_client_to_zttp_server() -> None:
    server = zttp.Connection(
        zttp.SERVER,
        protocol=zttp.HTTP3,
        credentials=zttp.TlsCredentials(certificate=make_zttp_server_cert_der(), private_key=b"\x42" * 32),
        transport_params=ZTTP_SERVER_TP,
        random=b"\xab" * 32,
        ephemeral_seed=b"\x33" * 32,
        alpn=b"h3",
    )
    client_config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        server_name="localhost",
        verify_mode=ssl.CERT_NONE,
    )
    received_tokens: list[bytes] = []
    received_tickets: list[object] = []
    client_kwargs = {
        "configuration": client_config,
        "session_ticket_handler": received_tickets.append,
    }
    if QUIC_BACKEND == "aioquic":
        client_kwargs["token_handler"] = received_tokens.append
    client = QuicConnection(**client_kwargs)
    h3 = H3Connection(client)
    client.connect(("server", 4433), now=0.0)

    for round_idx in range(10):
        progressed = False
        now = round_idx / 1000
        for datagram, _addr in client.datagrams_to_send(now):
            progressed = True
            server.receive_datagram(datagram, round_idx * 1000, b"client")
        for datagram, _addr in server.data_to_send_with_addresses():
            progressed = True
            client.receive_datagram(datagram, ("server", 4433), now + 0.0005)
        while True:
            event = client.next_event()
            if event is None:
                break
            progressed = True
            h3.handle_event(event)
        if not progressed:
            break

    server.issue_connection_id(1, b"server-cid-1", b"\x5a" * 16)
    for datagram, _addr in server.data_to_send_with_addresses():
        client.receive_datagram(datagram, ("server", 4433), 0.011)
        drain_quic_to_h3(client, h3)
    if not any(
        cid.sequence_number == 1 and cid.cid == b"server-cid-1"
        for cid in getattr(client, "_peer_cid_available", [])
    ):
        raise SystemExit("aioquic did not receive zttp's NEW_CONNECTION_ID")
    client.change_connection_id()
    active_cid = getattr(client, "_peer_cid", None)
    if active_cid is None or active_cid.sequence_number != 1 or active_cid.cid != b"server-cid-1":
        raise SystemExit(f"aioquic did not switch to zttp's issued CID: {active_cid!r}")

    stream_id = client.get_next_available_stream_id()
    h3.send_headers(
        stream_id,
        [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/interop-server"),
            (b"content-length", b"4"),
        ],
    )
    h3.send_data(stream_id, b"body", end_stream=False)
    h3.send_headers(
        stream_id,
        [(b"x-aioquic-trailer", b"done")],
        end_stream=True,
    )
    migrated_client = b"client-migrated"
    for datagram, _addr in client.datagrams_to_send(0.02):
        server.receive_datagram(datagram, 20_000, migrated_client)
    challenges = server.data_to_send_with_addresses()
    if not challenges:
        raise SystemExit("zttp did not challenge the migrated aioquic client path")
    if any(addr != migrated_client for _datagram, addr in challenges):
        raise SystemExit(f"zttp challenged the wrong migrated path: {challenges!r}")
    for datagram, _addr in challenges:
        client.receive_datagram(datagram, ("server", 4433), 0.021)
        drain_quic_to_h3(client, h3)
    responses = client.datagrams_to_send(0.022)
    if not responses:
        raise SystemExit("aioquic did not answer zttp's migrated-path challenge")
    for datagram, _addr in responses:
        server.receive_datagram(datagram, 22_000, migrated_client)
    server.data_to_send_with_addresses()

    events = []
    while True:
        event = server.next_event()
        if event is zttp.NEED_DATA:
            break
        events.append(event)
    requests = [event for event in events if event.__class__.__name__ == "Request"]
    if not requests:
        raise SystemExit("zttp did not receive an HTTP/3 request from aioquic")
    if requests[0].method != b"POST" or requests[0].path != b"/interop-server":
        raise SystemExit(f"zttp received unexpected request: {requests[0]!r}")
    bodies = [event for event in events if event.__class__.__name__ == "Data"]
    if not bodies or bodies[0].data != b"body":
        raise SystemExit(f"zttp did not receive the aioquic request body: {events!r}")
    eoms = [event for event in events if event.__class__.__name__ == "EndOfMessage"]
    if not eoms or eoms[-1].trailers != [(b"x-aioquic-trailer", b"done")]:
        raise SystemExit(f"zttp did not receive the aioquic request trailers/end: {events!r}")

    stream = server.stream(requests[0].stream_id)
    stream.send_response(200, [(b"content-length", b"2")])
    stream.send_data(b"ok")
    stream.end_message([(b"x-zttp-trailer", b"done")])
    response_events: list[object] = []
    for datagram, addr in server.data_to_send_with_addresses():
        if addr != migrated_client:
            raise SystemExit(f"zttp response was not routed to the validated migrated path: {addr!r}")
        client.receive_datagram(datagram, ("server", 4433), 0.03)
        response_events.extend(drain_quic_to_h3(client, h3))

    response_headers = [event for event in response_events if isinstance(event, HeadersReceived)]
    response_data = [event for event in response_events if isinstance(event, DataReceived)]
    if not response_headers or (b":status", b"200") not in response_headers[0].headers:
        raise SystemExit(f"aioquic did not receive the zttp response headers: {response_events!r}")
    if not response_data or response_data[0].data != b"ok":
        raise SystemExit(f"aioquic did not receive the zttp response body: {response_events!r}")
    if len(response_headers) < 2 or (b"x-zttp-trailer", b"done") not in response_headers[-1].headers or not response_headers[-1].stream_ended:
        raise SystemExit(f"aioquic did not receive the zttp response trailers/end: {response_events!r}")

    issued_zttp_psk = server.send_session_ticket(
        b"zttp-session-ticket",
        7200,
        0x01020304,
        b"\x01",
        ZTTP_SERVER_TICKET_EXTENSIONS,
        MAX_EARLY_DATA,
    )
    for datagram, addr in server.data_to_send_with_addresses():
        if addr != migrated_client:
            raise SystemExit(f"zttp NewSessionTicket was not routed to the validated migrated path: {addr!r}")
        client.receive_datagram(datagram, ("server", 4433), 0.0303)
        drain_quic_to_h3(client, h3)
    if (
        len(received_tickets) != 1
        or received_tickets[0].ticket != b"zttp-session-ticket"
        or received_tickets[0].age_add != 0x01020304
        or received_tickets[0].max_early_data_size != MAX_EARLY_DATA
        or received_tickets[0].resumption_secret != issued_zttp_psk
    ):
        raise SystemExit(f"aioquic did not receive zttp's NewSessionTicket: {received_tickets!r}")

    resumed_server = zttp.Connection(
        zttp.SERVER,
        protocol=zttp.HTTP3,
        credentials=zttp.TlsCredentials(certificate=make_zttp_server_cert_der(), private_key=b"\x42" * 32),
        transport_params=ZTTP_SERVER_TP,
        random=b"\xac" * 32,
        ephemeral_seed=b"\x34" * 32,
        alpn=b"h3",
    )
    resumed_client_config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        server_name="localhost",
        verify_mode=ssl.CERT_NONE,
        session_ticket=received_tickets[0],
    )
    resumed_client = QuicConnection(configuration=resumed_client_config)
    resumed_client.connect(("server", 4433), now=0.050)
    resumed_h3 = H3Connection(resumed_client)
    early_stream_id = resumed_client.get_next_available_stream_id()
    resumed_h3.send_headers(
        early_stream_id,
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/aioquic-early"),
            (b"content-length", b"0"),
        ],
        end_stream=True,
    )
    early_datagrams = resumed_client.datagrams_to_send(0.050)
    if not early_datagrams:
        raise SystemExit("aioquic did not emit datagrams for the resumed 0-RTT request")
    for datagram, _addr in early_datagrams:
        try:
            resumed_server.receive_datagram(datagram, 50_000, b"aioquic-early-client")
        except zttp.RemoteProtocolError as exc:
            raise SystemExit(
                "zttp rejected aioquic's resumed 0-RTT datagram: "
                f"close={resumed_server.close_info()!r} exc={exc}"
            ) from exc
    early_events = []
    while True:
        event = resumed_server.next_event()
        if event is zttp.NEED_DATA:
            break
        early_events.append(event)
    early_requests = [event for event in early_events if event.__class__.__name__ == "Request"]
    early_eoms = [event for event in early_events if event.__class__.__name__ == "EndOfMessage"]
    if not early_requests or early_requests[0].path != b"/aioquic-early" or not early_eoms:
        raise SystemExit(f"zttp did not receive aioquic's 0-RTT request before handshake completion: {early_events!r}")

    server.send_new_token(b"zttp-validation-token")
    for datagram, addr in server.data_to_send_with_addresses():
        if addr != migrated_client:
            raise SystemExit(f"zttp NEW_TOKEN was not routed to the validated migrated path: {addr!r}")
        client.receive_datagram(datagram, ("server", 4433), 0.0305)
        drain_quic_to_h3(client, h3)
    peer_token = getattr(client, "_peer_token", None)
    if QUIC_BACKEND == "aioquic":
        if received_tokens != [b"zttp-validation-token"]:
            raise SystemExit(f"aioquic did not receive zttp's NEW_TOKEN: {received_tokens!r}")
    elif peer_token not in (None, b"", b"zttp-validation-token"):
        raise SystemExit(f"qh3 stored an unexpected NEW_TOKEN value: {peer_token!r}")

    for datagram, _addr in client.datagrams_to_send(0.031):
        server.receive_datagram(datagram, 31_000, migrated_client)
    server.data_to_send_with_addresses()
    client.request_key_update()
    key_update_stream_id = client.get_next_available_stream_id()
    h3.send_headers(
        key_update_stream_id,
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/peer-key-update"),
            (b"content-length", b"0"),
        ],
        end_stream=True,
    )
    for datagram, _addr in client.datagrams_to_send(0.032):
        server.receive_datagram(datagram, 32_000, migrated_client)

    key_update_events = []
    while True:
        event = server.next_event()
        if event is zttp.NEED_DATA:
            break
        key_update_events.append(event)
    key_update_requests = [event for event in key_update_events if event.__class__.__name__ == "Request"]
    if not key_update_requests or key_update_requests[0].path != b"/peer-key-update":
        raise SystemExit(f"zttp did not receive aioquic's post-key-update request: {key_update_events!r}")
    key_update_eoms = [event for event in key_update_events if event.__class__.__name__ == "EndOfMessage"]
    if not key_update_eoms:
        raise SystemExit(f"zttp did not receive aioquic's post-key-update request end: {key_update_events!r}")

    client.close(error_code=0x0100, reason_phrase="aioquic-close")
    for datagram, _addr in client.datagrams_to_send(0.04):
        server.receive_datagram(datagram, 40_000, migrated_client)
    if server.close_info() != zttp.CloseInfo(0x0100, b"aioquic-close", True):
        raise SystemExit(f"zttp did not receive aioquic's CONNECTION_CLOSE: {server.close_info()!r}")
    if server.next_event() is not zttp.CONNECTION_CLOSED:
        raise SystemExit("zttp did not surface CONNECTION_CLOSED after aioquic close")


def assert_udp_loopback_zttp_client_to_aioquic_server(tmp: Path, drop_first_server_datagram: bool = False) -> None:
    cert_path, key_path = make_cert_chain(tmp)
    server_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    server_config.load_cert_chain(str(cert_path), str(key_path))

    client = zttp.Connection(
        zttp.CLIENT,
        protocol=zttp.HTTP3,
        transport_params=CLIENT_TP,
        random=b"\xae" * 32,
        ephemeral_seed=b"\x36" * 32,
        connection_id=b"\x11\x22\x33\x46",
        alpn=b"h3",
        server_name=b"localhost",
    )

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    migrated_client_sock: socket.socket | None = None
    try:
        server_sock.bind(("127.0.0.1", 0))
        client_sock.bind(("127.0.0.1", 0))
        server_sock.setblocking(False)
        client_sock.setblocking(False)
        server_addr = server_sock.getsockname()

        started = time.monotonic()
        server: QuicConnection | None = None
        h3: H3Connection | None = None
        request_sent = False
        request_seen = False
        response_events: list[object] = []
        dropped_server_datagram = False

        def now_s() -> float:
            return time.monotonic() - started

        def now_us() -> int:
            return int(now_s() * 1_000_000)

        def flush_client() -> None:
            for datagram in client.data_to_send():
                client_sock.sendto(datagram, server_addr)

        def flush_server() -> None:
            nonlocal dropped_server_datagram
            if server is None:
                return
            for datagram, addr in server.datagrams_to_send(now_s()):
                if drop_first_server_datagram and not dropped_server_datagram:
                    dropped_server_datagram = True
                    continue
                client_sock_addr = addr
                server_sock.sendto(datagram, client_sock_addr)

        def pump_client_events() -> None:
            while True:
                event = client.next_event()
                if event is zttp.NEED_DATA:
                    return
                response_events.append(event)

        def pump_server_events() -> None:
            nonlocal request_seen
            assert server is not None
            assert h3 is not None
            for event in drain_quic_to_h3(server, h3):
                if isinstance(event, HeadersReceived):
                    request_seen = True
                    if (b":method", b"GET") not in event.headers or (b":path", b"/udp-loopback-zttp") not in event.headers:
                        raise SystemExit(f"aioquic UDP loopback received unexpected headers: {event.headers!r}")
                    h3.send_headers(event.stream_id, [(b":status", b"200"), (b"content-length", b"2")])
                    h3.send_data(event.stream_id, b"ok", end_stream=True)

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            client_timeout = client.next_timeout()
            now = now_us()
            if client_timeout is not None and now >= client_timeout:
                client.handle_timeout(now)
            if server is not None:
                server_timeout = server.get_timer()
                now = now_s()
                if server_timeout is not None and now >= server_timeout:
                    server.handle_timer(now)
            if not request_sent and client.peer_settings() is not None:
                stream = client.send_request(
                    b"GET",
                    b"/udp-loopback-zttp",
                    b"3",
                    [(b"host", b"localhost"), (b"content-length", b"0")],
                )
                stream.end_message()
                request_sent = True

            flush_client()
            flush_server()
            readable, _, _ = select.select([server_sock, client_sock], [], [], 0.01)
            for sock in readable:
                while True:
                    try:
                        datagram, addr = sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    if sock is server_sock:
                        if server is None:
                            header = pull_quic_header(Buffer(data=datagram), host_cid_length=None)
                            server = QuicConnection(
                                configuration=server_config,
                                original_destination_connection_id=header.destination_cid,
                            )
                            h3 = H3Connection(server)
                        server.receive_datagram(datagram, addr, now_s())
                        pump_server_events()
                    else:
                        client.receive_datagram(datagram, now_us())
                        pump_client_events()

            responses = [event for event in response_events if event.__class__.__name__ == "Response"]
            bodies = [event for event in response_events if event.__class__.__name__ == "Data"]
            ends = [event for event in response_events if event.__class__.__name__ == "EndOfMessage"]
            if (
                request_sent
                and request_seen
                and (not drop_first_server_datagram or dropped_server_datagram)
                and responses
                and responses[0].status_code == 200
                and bodies
                and any(body.data == b"ok" for body in bodies)
                and ends
            ):
                return

        raise SystemExit(
            "UDP loopback zttp client <-> aioquic server smoke timed out: "
            f"request_sent={request_sent} request_seen={request_seen} "
            f"dropped_server_datagram={dropped_server_datagram} events={response_events!r}"
        )
    finally:
        server_sock.close()
        client_sock.close()


def assert_udp_loopback_aioquic_client_to_zttp_server(drop_first_server_datagram: bool = False) -> None:
    server = zttp.Connection(
        zttp.SERVER,
        protocol=zttp.HTTP3,
        credentials=zttp.TlsCredentials(certificate=make_zttp_server_cert_der(), private_key=b"\x42" * 32),
        transport_params=ZTTP_SERVER_TP,
        random=b"\xad" * 32,
        ephemeral_seed=b"\x35" * 32,
        alpn=b"h3",
    )
    client_config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        server_name="localhost",
        verify_mode=ssl.CERT_NONE,
    )
    client = QuicConnection(configuration=client_config)
    h3 = H3Connection(client)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    migrated_client_sock: socket.socket | None = None
    try:
        server_sock.bind(("127.0.0.1", 0))
        client_sock.bind(("127.0.0.1", 0))
        server_sock.setblocking(False)
        client_sock.setblocking(False)
        server_addr = server_sock.getsockname()
        client.connect(server_addr, now=0.0)

        stream_id = client.get_next_available_stream_id()
        h3.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/udp-loopback"),
                (b"content-length", b"0"),
            ],
            end_stream=True,
        )

        started = time.monotonic()
        peer_by_key: dict[bytes, tuple[str, int]] = {}
        client_events: list[object] = []
        request_seen = False
        response_sent = False
        migrated_request_seen = False
        migrated_response_sent = False
        migration_started = False
        migrated_path_response_seen = False
        migrated_request_sent = False
        migrated_stream_id: int | None = None
        migrated_response_received = False
        dropped_server_datagram = False
        send_sock = client_sock

        def now_s() -> float:
            return time.monotonic() - started

        def now_us() -> int:
            return int(now_s() * 1_000_000)

        def addr_key(addr: tuple[str, int]) -> bytes:
            return f"{addr[0]}:{addr[1]}".encode("ascii")

        def flush_client() -> None:
            for datagram, addr in client.datagrams_to_send(now_s()):
                send_sock.sendto(datagram, addr)

        def flush_server() -> None:
            nonlocal dropped_server_datagram
            for datagram, key in server.data_to_send_with_addresses():
                if key is None:
                    if len(peer_by_key) != 1:
                        raise SystemExit("zttp UDP loopback emitted an unroutable datagram")
                    addr = next(iter(peer_by_key.values()))
                else:
                    addr = peer_by_key.get(key)
                    if addr is None:
                        raise SystemExit(f"zttp UDP loopback emitted a datagram for an unknown peer key: {key!r}")
                if drop_first_server_datagram and not dropped_server_datagram:
                    dropped_server_datagram = True
                    continue
                server_sock.sendto(datagram, addr)

        def pump_server_events() -> None:
            nonlocal request_seen, response_sent, migrated_request_seen, migrated_response_sent
            while True:
                event = server.next_event()
                if event is zttp.NEED_DATA:
                    return
                if event.__class__.__name__ == "Request":
                    if event.method != b"GET" or event.path not in (b"/udp-loopback", b"/udp-loopback-migrated"):
                        raise SystemExit(f"zttp UDP loopback received an unexpected request: {event!r}")
                    if event.path == b"/udp-loopback":
                        request_seen = True
                    else:
                        migrated_request_seen = True
                    stream = server.stream(event.stream_id)
                    stream.send_response(200, [(b"content-length", b"2")])
                    stream.send_data(b"ok")
                    stream.end_message()
                    if event.path == b"/udp-loopback":
                        response_sent = True
                    else:
                        migrated_response_sent = True

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            timeout = server.next_timeout()
            now = now_us()
            if timeout is not None and now >= timeout:
                server.handle_timeout(now)
            flush_client()
            flush_server()
            readable_socks = [server_sock, client_sock]
            if migrated_client_sock is not None:
                readable_socks.append(migrated_client_sock)
            readable, _, _ = select.select(readable_socks, [], [], 0.01)
            for sock in readable:
                while True:
                    try:
                        datagram, addr = sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    if sock is server_sock:
                        key = addr_key(addr)
                        peer_by_key[key] = addr
                        server.receive_datagram(datagram, now_us(), key)
                        if (
                            migration_started
                            and migrated_client_sock is not None
                            and addr == migrated_client_sock.getsockname()
                            and migrated_response_received
                        ):
                            migrated_path_response_seen = True
                        pump_server_events()
                    else:
                        client.receive_datagram(datagram, addr, now_s())
                        if migrated_client_sock is not None and sock is migrated_client_sock:
                            migrated_response_received = True
                        client_events.extend(drain_quic_to_h3(client, h3))
            responses = [event for event in client_events if isinstance(event, HeadersReceived)]
            bodies = [event for event in client_events if isinstance(event, DataReceived)]
            migrated_responses = [
                event
                for event in responses
                if migrated_stream_id is not None and event.stream_id == migrated_stream_id
            ]
            migrated_bodies = [
                event
                for event in bodies
                if migrated_stream_id is not None and event.stream_id == migrated_stream_id
            ]
            first_done = (
                request_seen
                and response_sent
                and (not drop_first_server_datagram or dropped_server_datagram)
                and responses
                and (b":status", b"200") in responses[0].headers
                and bodies
                and any(body.data == b"ok" for body in bodies)
                and bodies[-1].stream_ended
            )
            if first_done and not migration_started:
                migrated_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                migrated_client_sock.bind(("127.0.0.1", 0))
                migrated_client_sock.setblocking(False)
                send_sock = migrated_client_sock
                client.send_ping(0x6D696772)
                migration_started = True
                continue
            if migration_started and migrated_path_response_seen and not migrated_request_sent:
                migrated_stream_id = client.get_next_available_stream_id()
                h3.send_headers(
                    migrated_stream_id,
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/udp-loopback-migrated"),
                        (b"content-length", b"0"),
                    ],
                    end_stream=True,
                )
                migrated_request_sent = True
                continue
            migrated_done = (
                migration_started
                and migrated_request_sent
                and migrated_path_response_seen
                and migrated_request_seen
                and migrated_response_sent
                and migrated_responses
                and (b":status", b"200") in migrated_responses[0].headers
                and migrated_bodies
                and any(body.data == b"ok" for body in migrated_bodies)
                and migrated_bodies[-1].stream_ended
            )
            if (
                first_done
                and migrated_done
            ):
                return

        raise SystemExit(
            "UDP loopback aioquic client <-> zttp server smoke timed out: "
            f"request_seen={request_seen} response_sent={response_sent} "
            f"migrated_request_seen={migrated_request_seen} migrated_response_sent={migrated_response_sent} "
            f"migrated_path_response_seen={migrated_path_response_seen} "
            f"migrated_request_sent={migrated_request_sent} migrated_response_received={migrated_response_received} "
            f"dropped_server_datagram={dropped_server_datagram} events={client_events!r}"
        )
    finally:
        server_sock.close()
        client_sock.close()
        if migrated_client_sock is not None:
            migrated_client_sock.close()


def main() -> None:
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        if QUIC_BACKEND == "qh3":
            assert_zttp_client_to_aioquic_server(tmp)
            assert_aioquic_client_to_zttp_server()
            assert_udp_loopback_zttp_client_to_aioquic_server(tmp, drop_first_server_datagram=True)
            assert_udp_loopback_aioquic_client_to_zttp_server(drop_first_server_datagram=True)
            print(
                "zttp <-> qh3 HTTP/3 request/response/trailers + "
                "1xx/goaway + bidirectional NewSessionTicket/0-RTT + key update + "
                "migration/CID rotation + close + bidirectional UDP loopback/loss interop smoke passed"
            )
            return

        assert_zttp_client_to_aioquic_server(tmp)
        assert_aioquic_client_to_zttp_server()
        assert_udp_loopback_zttp_client_to_aioquic_server(tmp, drop_first_server_datagram=True)
        assert_udp_loopback_aioquic_client_to_zttp_server(drop_first_server_datagram=True)
        print(
            "zttp <-> aioquic HTTP/3 request/response/trailers + "
            "1xx/goaway + bidirectional NewSessionTicket/0-RTT + NEW_TOKEN + key update + "
            "migration/CID rotation + close + bidirectional UDP loopback/loss interop smoke passed"
        )


if __name__ == "__main__":
    main()
