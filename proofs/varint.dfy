// Mirrors `decode`, `len` and `encode` in src/core/quic/varint.zig (RFC 9000 section 16).

import opened Std.Arithmetic.DivMod
import opened Std.Arithmetic.Mul

const MAX: nat := 0x3FFF_FFFF_FFFF_FFFF

newtype u8 = x: int | 0 <= x < 0x100

datatype Decoded = Decoded(value: nat, len: nat) | NeedData

function Decode(buf: seq<u8>): Decoded
{
  if |buf| == 0 then NeedData
  else
    var n := match buf[0] / 0x40 case 0 => 1 case 1 => 2 case 2 => 4 case _ => 8;
    if |buf| < n then NeedData
    else Decoded(BigEndian([buf[0] % 0x40] + buf[1..n]), n)
}

function Len(value: nat): nat
  requires value <= MAX
{
  if value <= 0x3F then 1
  else if value <= 0x3FFF then 2
  else if value <= 0x3FFF_FFFF then 4
  else 8
}

function Encode(value: nat): seq<u8>
  requires value <= MAX
{
  var n := Len(value);
  var bytes := BigEndianBytes(value, n);
  LengthBitsAreClear(value, n);
  [bytes[0] + Tag(n)] + bytes[1..]
}

lemma EncodeRoundTrips(value: nat)
  requires value <= MAX
  ensures Decode(Encode(value)) == Decoded(value, Len(value))
{
  var n := Len(value);
  var bytes := BigEndianBytes(value, n);
  LengthBitsAreClear(value, n);
  PowValues();
  BigEndianInverts(value, n);
  var buf := Encode(value);
  assert buf[0] / 0x40 == Tag(n) / 0x40 && buf[0] % 0x40 == bytes[0];
  assert [buf[0] % 0x40] + buf[1..n] == bytes;
}

lemma DecodeIsBounded(buf: seq<u8>)
  ensures Decode(buf).Decoded? ==> Decode(buf).len <= |buf| && Decode(buf).value <= MAX
{
  if Decode(buf).Decoded? {
    var n := Decode(buf).len;
    BigEndianIsBounded([buf[0] % 0x40] + buf[1..n]);
    PowValues();
  }
}

// `buf[0] >> 6`, `buf[0] & 0x3F` and `out[0] |= tag` in the Zig source.
lemma BitOpsAreArithmetic(b: bv8, tag: bv8)
  ensures b >> 6 == b / 0x40
  ensures b & 0x3F == b % 0x40
  ensures b < 0x40 && tag % 0x40 == 0 ==> b | tag == b + tag
{
}

function Tag(n: nat): u8
{
  match n case 1 => 0x00 case 2 => 0x40 case 4 => 0x80 case _ => 0xC0
}

function Pow256(k: nat): nat
  ensures Pow256(k) > 0
{
  if k == 0 then 1 else 0x100 * Pow256(k - 1)
}

function BigEndian(bytes: seq<u8>): nat
{
  if |bytes| == 0 then 0 else BigEndian(bytes[..|bytes| - 1]) * 0x100 + bytes[|bytes| - 1] as nat
}

function BigEndianBytes(value: nat, n: nat): seq<u8>
  ensures |BigEndianBytes(value, n)| == n
{
  if n == 0 then [] else BigEndianBytes(value / 0x100, n - 1) + [(value % 0x100) as u8]
}

lemma BigEndianInverts(value: nat, n: nat)
  requires value < Pow256(n)
  ensures BigEndian(BigEndianBytes(value, n)) == value
{
  if n > 0 {
    BigEndianInverts(value / 0x100, n - 1);
    assert BigEndianBytes(value, n)[..n - 1] == BigEndianBytes(value / 0x100, n - 1);
  }
}

lemma FirstByte(value: nat, n: nat)
  requires n >= 1 && value < Pow256(n)
  ensures BigEndianBytes(value, n)[0] as nat == value / Pow256(n - 1)
{
  if n > 1 {
    FirstByte(value / 0x100, n - 1);
    LemmaDivDenominator(value, 0x100, Pow256(n - 2));
  }
}

lemma LengthBitsAreClear(value: nat, n: nat)
  requires value <= MAX && n == Len(value)
  ensures BigEndianBytes(value, n)[0] < 0x40
{
  PowValues();
  FirstByte(value, n);
  var p := Pow256(n - 1);
  assert value < 0x40 * p;
  LemmaFundamentalDivMod(value, p);
  if value / p >= 0x40 {
    LemmaMulInequality(0x40, value / p, p);
  }
}

lemma BigEndianIsBounded(bytes: seq<u8>)
  requires |bytes| >= 1 && bytes[0] < 0x40
  ensures BigEndian(bytes) < 0x40 * Pow256(|bytes| - 1)
{
  if |bytes| > 1 {
    BigEndianIsBounded(bytes[..|bytes| - 1]);
  }
}

lemma PowValues()
  ensures Pow256(1) == 0x100 && Pow256(2) == 0x1_0000 && Pow256(3) == 0x100_0000
  ensures Pow256(4) == 0x1_0000_0000 && Pow256(7) == 0x100_0000_0000_0000 && Pow256(8) == 0x1_0000_0000_0000_0000
{
  assert Pow256(5) == 0x100 * Pow256(4);
  assert Pow256(6) == 0x100 * Pow256(5);
  assert Pow256(7) == 0x100 * Pow256(6);
  assert Pow256(8) == 0x100 * Pow256(7);
}
