// Mirrors `ChunkDecoder.next` in src/core/h1/chunked.zig and `Scanner.line` in
// src/core/scanner.zig. The main theorem: however the peer fragments a chunked body
// across reads, the decoder yields the same body, trailers, and message boundary as
// decoding the complete byte stream at once.

datatype Config = Config(max_line: nat, strict: bool)

datatype State = Size | Data(remaining: nat) | DataCrlf | Trailer | Done

datatype Output = OData(bytes: string) | OTrailerLine(line: string) | ODone | ONeedData

datatype StepResult = Step(out: Output, consumed: nat, next: State) | InvalidChunk

datatype Verdict = Incomplete | Error | Complete(rest: string)

datatype Decoding = Decoding(body: string, trailers: seq<string>, verdict: Verdict)

datatype Option<T> = Some(value: T) | Nothing

// -- the Zig implementation -------------------------------------------------------

function Rank(st: State): nat
{
  match st
  case Data(r) => if r == 0 then 5 else 1
  case DataCrlf => 4
  case Size => 3
  case Trailer => 1
  case Done => 0
}

function Next(st: State, avail: string, cfg: Config): StepResult
  decreases Rank(st)
{
  match st
  case Size =>
    (match Line(avail, cfg)
     case LineNone => Step(ONeedData, 0, Size)
     case LineError => InvalidChunk
     case LineOk(l, n) =>
       match ParseChunkSize(l)
       case Nothing => InvalidChunk
       case Some(size) => Shift(n, if size == 0 then Next(Trailer, avail[n..], cfg) else Next(Data(size), avail[n..], cfg)))
  case Data(remaining) =>
    if remaining == 0 then Next(DataCrlf, avail, cfg)
    else if |avail| == 0 then Step(ONeedData, 0, st)
    else
      var take := if |avail| < remaining then |avail| else remaining;
      Step(OData(avail[..take]), take, Data(remaining - take))
  case DataCrlf =>
    (match Crlf(avail, cfg)
     case CrlfNone => Step(ONeedData, 0, DataCrlf)
     case CrlfError => InvalidChunk
     case CrlfOk(n) => Shift(n, Next(Size, avail[n..], cfg)))
  case Trailer =>
    (match Line(avail, cfg)
     case LineNone => Step(ONeedData, 0, Trailer)
     case LineError => InvalidChunk
     case LineOk(l, n) => if |l| == 0 then Step(ODone, n, Done) else Step(OTrailerLine(l), n, Trailer))
  case Done => Step(ODone, 0, Done)
}

function Shift(n: nat, r: StepResult): StepResult
{
  match r
  case InvalidChunk => InvalidChunk
  case Step(out, consumed, next) => Step(out, n + consumed, next)
}

datatype LineResult = LineOk(line: string, consumed: nat) | LineNone | LineError

// `Scanner.line`: MessageTooLong and BareLf both surface as InvalidChunk.
function Line(avail: string, cfg: Config): LineResult
{
  match IndexOfLf(avail, 0)
  case Nothing => if |avail| > cfg.max_line then LineError else LineNone
  case Some(lf) =>
    if lf > cfg.max_line then LineError
    else
      var has_cr := lf > 0 && avail[lf - 1] == '\r';
      if cfg.strict && !has_cr then LineError
      else LineOk(avail[..if has_cr then lf - 1 else lf], lf + 1)
}

function IndexOfLf(s: string, i: nat): Option<nat>
  requires i <= |s|
  ensures IndexOfLf(s, i).Some? ==> i <= IndexOfLf(s, i).value < |s| && s[IndexOfLf(s, i).value] == '\n'
  ensures IndexOfLf(s, i).Some? ==> forall k :: i <= k < IndexOfLf(s, i).value ==> s[k] != '\n'
  ensures IndexOfLf(s, i).Nothing? ==> forall k :: i <= k < |s| ==> s[k] != '\n'
  decreases |s| - i
{
  if i == |s| then Nothing else if s[i] == '\n' then Some(i) else IndexOfLf(s, i + 1)
}

datatype CrlfResult = CrlfOk(consumed: nat) | CrlfNone | CrlfError

function Crlf(avail: string, cfg: Config): CrlfResult
{
  if |avail| == 0 then CrlfNone
  else if avail[0] == '\n' then (if cfg.strict then CrlfError else CrlfOk(1))
  else if avail[0] == '\r' then
    if |avail| < 2 then CrlfNone else if avail[1] != '\n' then CrlfError else CrlfOk(2)
  else CrlfError
}

function ParseChunkSize(line: string): Option<nat>
{
  ParseChunkSizeFrom(line, 0, 0)
}

// `n = (n << 4) | v` after the 16-digit check, so n never leaves u64.
function ParseChunkSizeFrom(line: string, i: nat, n: nat): Option<nat>
  requires i <= |line| && i <= 16 && n < Pow16(i)
  ensures ParseChunkSizeFrom(line, i, n).Some? ==> ParseChunkSizeFrom(line, i, n).value < 0x1_0000_0000_0000_0000
  decreases |line| - i
{
  if i == |line| then (if i == 0 then Nothing else Pow16Bound(i); Some(n))
  else if line[i] == ';' then
    if i == 0 || !ValidChunkExtension(line[i + 1..]) then Nothing else Pow16Bound(i); Some(n)
  else if HexValue(line[i]) == 0xFF then Nothing
  else if i >= 16 then Nothing
  else ParseChunkSizeFrom(line, i + 1, n * 16 + HexValue(line[i]))
}

predicate ValidChunkExtension(ext: string)
{
  forall i :: 0 <= i < |ext| ==> IsFieldVchar(ext[i])
}

predicate IsFieldVchar(c: char)
{
  c == '\t' || c == ' ' || (0x21 <= c as int <= 0xFF && c as int != 0x7F)
}

function HexValue(c: char): nat
{
  if '0' <= c <= '9' then c as nat - '0' as nat
  else if 'a' <= c <= 'f' then c as nat - 'a' as nat + 10
  else if 'A' <= c <= 'F' then c as nat - 'A' as nat + 10
  else 0xFF
}

function Pow16(k: nat): nat
  ensures Pow16(k) > 0
{
  if k == 0 then 1 else 16 * Pow16(k - 1)
}

lemma Pow16Bound(k: nat)
  requires k <= 16
  ensures Pow16(k) <= 0x1_0000_0000_0000_0000
  decreases 16 - k
{
  if k < 16 {
    Pow16Bound(k + 1);
  } else {
    assert Pow16(4) == 0x1_0000;
    assert Pow16(8) == 0x1_0000 * Pow16(4) by { assert Pow16(8) == 16 * 16 * 16 * 16 * Pow16(4); }
    assert Pow16(12) == 0x1_0000 * Pow16(8) by { assert Pow16(12) == 16 * 16 * 16 * 16 * Pow16(8); }
    assert Pow16(16) == 0x1_0000 * Pow16(12) by { assert Pow16(16) == 16 * 16 * 16 * 16 * Pow16(12); }
  }
}

// -- decoding the complete stream ---------------------------------------------------

function Spec(st: State, s: string, cfg: Config): Decoding
  decreases |s|, Rank(st)
{
  match st
  case Size =>
    (match Line(s, cfg)
     case LineNone => Decoding([], [], Incomplete)
     case LineError => Decoding([], [], Error)
     case LineOk(l, n) =>
       match ParseChunkSize(l)
       case Nothing => Decoding([], [], Error)
       case Some(size) => if size == 0 then Spec(Trailer, s[n..], cfg) else Spec(Data(size), s[n..], cfg))
  case Data(k) =>
    if k == 0 then Spec(DataCrlf, s, cfg)
    else if |s| < k then Decoding(s, [], Incomplete)
    else WithBody(s[..k], Spec(DataCrlf, s[k..], cfg))
  case DataCrlf =>
    (match Crlf(s, cfg)
     case CrlfNone => Decoding([], [], Incomplete)
     case CrlfError => Decoding([], [], Error)
     case CrlfOk(n) => Spec(Size, s[n..], cfg))
  case Trailer =>
    (match Line(s, cfg)
     case LineNone => Decoding([], [], Incomplete)
     case LineError => Decoding([], [], Error)
     case LineOk(l, n) => if |l| == 0 then Decoding([], [], Complete(s[n..])) else WithTrailer(l, Spec(Trailer, s[n..], cfg)))
  case Done => Decoding([], [], Complete(s))
}

function WithBody(bytes: string, d: Decoding): Decoding
{
  d.(body := bytes + d.body)
}

function WithTrailer(line: string, d: Decoding): Decoding
{
  d.(trailers := [line] + d.trailers)
}

// -- the reader loop: call `next` until need_data, then wait for the next feed ------

function Collect(st: State, buffered: string, feeds: seq<string>, cfg: Config): Decoding
  decreases |feeds|, |buffered|
{
  match Next(st, buffered, cfg)
  case InvalidChunk => Decoding([], [], Error)
  case Step(out, n, st') =>
    NextConsumes(st, buffered, cfg);
    match out
    case ONeedData => if |feeds| == 0 then Decoding([], [], Incomplete) else Collect(st', buffered[n..] + feeds[0], feeds[1..], cfg)
    case OData(bytes) => WithBody(bytes, Collect(st', buffered[n..], feeds, cfg))
    case OTrailerLine(l) => WithTrailer(l, Collect(st', buffered[n..], feeds, cfg))
    case ODone => Decoding([], [], Complete(buffered[n..] + Concat(feeds)))
}

function Concat(feeds: seq<string>): string
{
  if |feeds| == 0 then [] else feeds[0] + Concat(feeds[1..])
}

lemma FragmentationIsInvisible(feeds: seq<string>, cfg: Config)
  ensures Collect(Size, [], feeds, cfg) == Spec(Size, Concat(feeds), cfg)
{
  CollectIsSpec(Size, [], feeds, cfg);
  assert [] + Concat(feeds) == Concat(feeds);
}

lemma CollectIsSpec(st: State, buffered: string, feeds: seq<string>, cfg: Config)
  ensures Collect(st, buffered, feeds, cfg) == Spec(st, buffered + Concat(feeds), cfg)
  decreases |feeds|, |buffered|
{
  var rest := Concat(feeds);
  NextIsSound(st, buffered, rest, cfg);
  match Next(st, buffered, cfg)
  case InvalidChunk =>
  case Step(out, n, st') =>
    NextConsumes(st, buffered, cfg);
    match out
    case ONeedData =>
      if |feeds| == 0 {
        NextIsSound(st, buffered, [], cfg);
        assert buffered + [] == buffered;
        assert buffered[n..] + [] == buffered[n..];
      } else {
        CollectIsSpec(st', buffered[n..] + feeds[0], feeds[1..], cfg);
        assert buffered[n..] + feeds[0] + Concat(feeds[1..]) == buffered[n..] + rest;
      }
    case OData(_) => CollectIsSpec(st', buffered[n..], feeds, cfg);
    case OTrailerLine(_) => CollectIsSpec(st', buffered[n..], feeds, cfg);
    case ODone =>
}

lemma NextConsumes(st: State, avail: string, cfg: Config)
  ensures Next(st, avail, cfg).Step? ==> Next(st, avail, cfg).consumed <= |avail|
  ensures Next(st, avail, cfg).Step? && (Next(st, avail, cfg).out.OData? || Next(st, avail, cfg).out.OTrailerLine?) ==>
    Next(st, avail, cfg).consumed > 0
  decreases Rank(st)
{
  match st
  case Size =>
    if Line(avail, cfg).LineOk? {
      var n := Line(avail, cfg).consumed;
      NextConsumes(Trailer, avail[n..], cfg);
      if ParseChunkSize(Line(avail, cfg).line).Some? && ParseChunkSize(Line(avail, cfg).line).value > 0 {
        NextConsumes(Data(ParseChunkSize(Line(avail, cfg).line).value), avail[n..], cfg);
      }
    }
  case Data(r) => if r == 0 { NextConsumes(DataCrlf, avail, cfg); }
  case DataCrlf => if Crlf(avail, cfg).CrlfOk? { NextConsumes(Size, avail[Crlf(avail, cfg).consumed..], cfg); }
  case Trailer =>
  case Done =>
}

// One `next` call on the bytes buffered so far commits to nothing that more bytes
// could change.
lemma NextIsSound(st: State, a: string, b: string, cfg: Config)
  ensures match Next(st, a, cfg)
    case InvalidChunk => Spec(st, a + b, cfg) == Decoding([], [], Error)
    case Step(out, n, st') =>
      n <= |a| &&
      (a + b)[n..] == a[n..] + b &&
      match out
      case ONeedData => Spec(st, a + b, cfg) == Spec(st', a[n..] + b, cfg) && Spec(st', a[n..], cfg) == Decoding([], [], Incomplete)
      case OData(bytes) => Spec(st, a + b, cfg) == WithBody(bytes, Spec(st', a[n..] + b, cfg))
      case OTrailerLine(l) => Spec(st, a + b, cfg) == WithTrailer(l, Spec(st', a[n..] + b, cfg))
      case ODone => Spec(st, a + b, cfg) == Decoding([], [], Complete(a[n..] + b))
  decreases Rank(st)
{
  NextConsumes(st, a, cfg);
  match st
  case Size =>
    LineExtends(a, b, cfg);
    if Line(a, cfg).LineOk? {
      var n := Line(a, cfg).consumed;
      assert (a + b)[n..] == a[n..] + b;
      var size := ParseChunkSize(Line(a, cfg).line);
      if size.Some? {
        if size.value == 0 { NextIsSound(Trailer, a[n..], b, cfg); } else { NextIsSound(Data(size.value), a[n..], b, cfg); }
        NextConsumes(Trailer, a[n..], cfg);
        if size.value > 0 { NextConsumes(Data(size.value), a[n..], cfg); }
        var r := Next(st, a, cfg);
        if r.Step? { assert a[n..][r.consumed - n..] == a[r.consumed..]; }
      }
    }
  case Data(r) =>
    if r == 0 {
      NextIsSound(DataCrlf, a, b, cfg);
    } else if |a| > 0 {
      var take := if |a| < r then |a| else r;
      assert (a + b)[..take] == a[..take];
      assert (a + b)[take..] == a[take..] + b;
      if take == |a| && take < r {
        assert a[take..] + b == b;
        assert a[..take] + b == a + b;
      } else {
        assert (a + b)[..r] == a[..r];
      }
    } else {
      assert a + b == b;
    }
  case DataCrlf =>
    CrlfExtends(a, b, cfg);
    if Crlf(a, cfg).CrlfOk? {
      var n := Crlf(a, cfg).consumed;
      assert (a + b)[n..] == a[n..] + b;
      NextIsSound(Size, a[n..], b, cfg);
      NextConsumes(Size, a[n..], cfg);
      var r := Next(st, a, cfg);
      if r.Step? { assert a[n..][r.consumed - n..] == a[r.consumed..]; }
    }
  case Trailer =>
    LineExtends(a, b, cfg);
    if Line(a, cfg).LineOk? {
      var n := Line(a, cfg).consumed;
      assert (a + b)[n..] == a[n..] + b;
    }
  case Done =>
}

lemma LineExtends(a: string, b: string, cfg: Config)
  ensures Line(a, cfg).LineOk? ==> Line(a + b, cfg) == Line(a, cfg) && Line(a, cfg).consumed <= |a|
  ensures Line(a, cfg).LineError? ==> Line(a + b, cfg).LineError?
{
  IndexOfLfExtends(a, b, 0);
  match IndexOfLf(a, 0)
  case Some(lf) =>
    var has_cr := lf > 0 && a[lf - 1] == '\r';
    assert (a + b)[..if has_cr then lf - 1 else lf] == a[..if has_cr then lf - 1 else lf];
  case Nothing =>
}

lemma IndexOfLfExtends(a: string, b: string, i: nat)
  requires i <= |a|
  ensures IndexOfLf(a, i).Some? ==> IndexOfLf(a + b, i) == IndexOfLf(a, i)
  ensures IndexOfLf(a, i).Nothing? ==> IndexOfLf(a + b, i).Nothing? || IndexOfLf(a + b, i).value >= |a|
  decreases |a| - i
{
  if i < |a| {
    assert (a + b)[i] == a[i];
    IndexOfLfExtends(a, b, i + 1);
  }
}

lemma CrlfExtends(a: string, b: string, cfg: Config)
  ensures Crlf(a, cfg).CrlfOk? ==> Crlf(a + b, cfg) == Crlf(a, cfg) && Crlf(a, cfg).consumed <= |a|
  ensures Crlf(a, cfg).CrlfError? ==> Crlf(a + b, cfg).CrlfError?
{
  if |a| > 0 { assert (a + b)[0] == a[0]; }
  if |a| > 1 { assert (a + b)[1] == a[1]; }
}

// -- the chunk-size line grammar (RFC 9112 7.1) -------------------------------------

// chunk-size = 1*HEXDIG, capped at 16 digits so it fits u64, then an optional
// chunk extension whose bytes must be field-vchar.
predicate IsChunkSizeLine(line: string, digits: nat)
{
  1 <= digits <= 16 && digits <= |line|
  && (forall i :: 0 <= i < digits ==> HexValue(line[i]) != 0xFF)
  && (digits == |line| || (line[digits] == ';' && ValidChunkExtension(line[digits + 1..])))
}

function HexNumber(s: string): nat
{
  if |s| == 0 then 0 else HexNumber(s[..|s| - 1]) * 16 + (if HexValue(s[|s| - 1]) == 0xFF then 0 else HexValue(s[|s| - 1]))
}

lemma ChunkSizeMatchesGrammar(line: string)
  ensures ParseChunkSize(line).Some? <==> exists digits: nat :: IsChunkSizeLine(line, digits)
  ensures forall digits: nat :: IsChunkSizeLine(line, digits) ==> ParseChunkSize(line) == Some(HexNumber(line[..digits]))
{
  ParseFromMatchesGrammar(line, 0, 0);
}

lemma ParseFromMatchesGrammar(line: string, i: nat, n: nat)
  requires i <= |line| && i <= 16 && n < Pow16(i)
  requires n == HexNumber(line[..i]) && forall k :: 0 <= k < i ==> HexValue(line[k]) != 0xFF
  ensures ParseChunkSizeFrom(line, i, n).Some? <==> exists digits: nat :: digits >= i && IsChunkSizeLine(line, digits)
  ensures forall digits: nat :: digits >= i && IsChunkSizeLine(line, digits) ==>
    ParseChunkSizeFrom(line, i, n) == Some(HexNumber(line[..digits]))
  decreases |line| - i
{
  if i < |line| && line[i] != ';' && HexValue(line[i]) != 0xFF && i < 16 {
    assert line[..i + 1][..i] == line[..i];
    ParseFromMatchesGrammar(line, i + 1, n * 16 + HexValue(line[i]));
    forall digits: nat | digits >= i && IsChunkSizeLine(line, digits) ensures digits >= i + 1 {}
  } else {
    forall digits: nat | digits >= i && IsChunkSizeLine(line, digits) ensures digits == i {
      if digits > i { assert HexValue(line[i]) != 0xFF; }
    }
    if i < |line| && line[i] == ';' && i > 0 && ValidChunkExtension(line[i + 1..]) {
      assert IsChunkSizeLine(line, i);
    }
    if i == |line| && i > 0 {
      assert IsChunkSizeLine(line, i);
    }
  }
}
