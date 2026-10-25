// Mirrors `decodePacketNumber` in src/core/quic/packet.zig (RFC 9000 appendix A.3).

const U64_LIMIT: int := 0x1_0000_0000_0000_0000
const PN_LIMIT: int := 0x4000_0000_0000_0000

newtype u64 = x: int | 0 <= x < U64_LIMIT

// Zig traps on u64 overflow; these preconditions make Dafny prove it never happens.
function Add(a: u64, b: u64): u64
  requires a as int + b as int < U64_LIMIT
{
  a + b
}

function Sub(a: u64, b: u64): u64
  requires a >= b
{
  a - b
}

function Window(pn_len: nat): u64
  requires 1 <= pn_len <= 4
{
  match pn_len
  case 1 => 0x100
  case 2 => 0x1_0000
  case 3 => 0x100_0000
  case 4 => 0x1_0000_0000
}

// `(x & ~(win - 1)) | low` in the Zig source; MaskIsArithmetic proves the two agree.
function ClearLowBitsOr(x: u64, win: u64, low: u64): u64
  requires 0 < win <= 0x1_0000_0000 && low < win
  requires x as int < PN_LIMIT
{
  (x as int - x as int % win as int + low as int) as u64
}

function DecodePacketNumber(largest_acked: u64, truncated: u64, pn_len: nat): u64
  requires largest_acked as int < PN_LIMIT - 1
  requires 1 <= pn_len <= 4
  requires truncated < Window(pn_len)
{
  var pn_win := Window(pn_len);
  var pn_hwin := pn_win / 2;
  var expected := Add(largest_acked, 1);
  var candidate := ClearLowBitsOr(expected, pn_win, truncated);
  if Add(candidate, pn_hwin) <= expected && Add(candidate, pn_win) as int <= PN_LIMIT - 1 then
    Add(candidate, pn_win)
  else if candidate > Add(expected, pn_hwin) && candidate >= pn_win then
    Sub(candidate, pn_win)
  else
    candidate
}

// The sender picks pn_len so the real packet number lies in the half-window around
// `expected` (RFC 9000 17.1); then the decoder recovers it exactly.
lemma DecodeRecoversPacketNumber(largest_acked: u64, truncated: u64, pn_len: nat, pn: u64)
  requires largest_acked as int < PN_LIMIT - 1
  requires 1 <= pn_len <= 4
  requires truncated < Window(pn_len)
  requires pn as int < PN_LIMIT
  requires pn % Window(pn_len) == truncated
  requires largest_acked + 1 < pn + Window(pn_len) / 2
  requires pn <= largest_acked + 1 + Window(pn_len) / 2
  ensures DecodePacketNumber(largest_acked, truncated, pn_len) == pn
{
}

lemma DecodeStaysInRange(largest_acked: u64, truncated: u64, pn_len: nat)
  requires largest_acked as int < PN_LIMIT - 1
  requires 1 <= pn_len <= 4
  requires truncated < Window(pn_len)
  ensures DecodePacketNumber(largest_acked, truncated, pn_len) as int < PN_LIMIT
  ensures DecodePacketNumber(largest_acked, truncated, pn_len) % Window(pn_len) == truncated
{
}

lemma MaskIsArithmetic(x: bv64, low: bv64)
  requires low < 0x1_0000_0000
  ensures low < 0x100 ==> (x & !0xFF) | low == x - x % 0x100 + low
  ensures low < 0x1_0000 ==> (x & !0xFFFF) | low == x - x % 0x1_0000 + low
  ensures low < 0x100_0000 ==> (x & !0xFF_FFFF) | low == x - x % 0x100_0000 + low
  ensures (x & !0xFFFF_FFFF) | low == x - x % 0x1_0000_0000 + low
{
}
