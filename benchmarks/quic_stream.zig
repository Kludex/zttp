const std = @import("std");
const stream = @import("quic_stream");

const TRANSFER_SIZE: usize = 4 * 1024 * 1024;
const PACKET_PAYLOAD: usize = 1200;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const data = try gpa.alloc(u8, TRANSFER_SIZE);
    defer gpa.free(data);
    @memset(data, 'x');

    var send = stream.SendStream.init(gpa);
    defer send.deinit();
    try send.write(data, true);
    while (send.peek(PACKET_PAYLOAD)) |chunk| send.commit(chunk.offset, chunk.data.len, chunk.fin);

    const ack_start = std.Io.Clock.awake.now(init.io);
    var offset: u64 = 0;
    while (offset < TRANSFER_SIZE) {
        const len = @min(@as(u64, PACKET_PAYLOAD), TRANSFER_SIZE - offset);
        try send.onAck(offset, len, offset + len == TRANSFER_SIZE);
        offset += len;
    }
    const ack_ns = ack_start.untilNow(init.io, .awake).toNanoseconds();

    var recv = stream.RecvStream.init(gpa);
    defer recv.deinit();
    _ = try recv.push(0, data, true);
    const consume_start = std.Io.Clock.awake.now(init.io);
    while (recv.readable().len > 0) recv.consume(@min(PACKET_PAYLOAD, recv.readable().len));
    const consume_ns = consume_start.untilNow(init.io, .awake).toNanoseconds();

    std.debug.print(
        "{d} MiB in {d}-byte chunks: sequential ACKs {d:.2} ms, receives {d:.2} ms\n",
        .{
            TRANSFER_SIZE / (1024 * 1024),
            PACKET_PAYLOAD,
            @as(f64, @floatFromInt(ack_ns)) / std.time.ns_per_ms,
            @as(f64, @floatFromInt(consume_ns)) / std.time.ns_per_ms,
        },
    );
}
