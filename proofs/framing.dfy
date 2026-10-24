// Mirrors `determine` in src/core/h1/framing.zig and proves it equals the RFC 9112 6
// framing rules, stated over the whole header list instead of the streaming accumulator.

datatype Header = Header(name: string, value: string)

datatype Options = Options(bodyless: bool, forbid_transfer_encoding: bool, until_close_default: bool)

datatype Framing = None | ContentLength(n: nat) | Chunked | UntilClose

datatype Result = Ok(framing: Framing) | InvalidFraming

const U64_LIMIT: nat := 0x1_0000_0000_0000_0000

// -- the Zig implementation -------------------------------------------------------

datatype TransferEncoding = TransferEncoding(saw_chunked: bool, coding_after_chunked: bool)

datatype Analyzer = Analyzer(
  te: TransferEncoding,
  has_transfer_encoding: bool,
  content_length: Option<nat>,
  content_length_value: Option<string>)

datatype Option<T> = Some(value: T) | Nothing

function TeAdd(te: TransferEncoding, codings: seq<string>): TransferEncoding
  decreases |codings|
{
  if |codings| == 0 then te else TeAdd(TeStep(te, codings[0]), codings[1..])
}

function TeStep(te: TransferEncoding, coding: string): TransferEncoding
{
  if |coding| == 0 then te
  else TransferEncoding(te.saw_chunked || EqIgnoreCase(coding, "chunked"), te.coding_after_chunked || te.saw_chunked)
}

function AnalyzerAdd(a: Analyzer, h: Header): Option<Analyzer>
{
  if EqIgnoreCase(h.name, "transfer-encoding") then
    Some(a.(has_transfer_encoding := true, te := TeAdd(a.te, Codings(h.value))))
  else if EqIgnoreCase(h.name, "content-length") then
    match ParseDecimal(TrimOws(h.value))
    case Nothing => Nothing
    case Some(n) =>
      if a.content_length_value.Some? && a.content_length_value.value != h.value then Nothing
      else Some(a.(content_length := Some(n), content_length_value := Some(h.value)))
  else Some(a)
}

function Finish(a: Analyzer, opts: Options): Result
{
  if a.has_transfer_encoding && a.content_length.Some? then InvalidFraming
  else if a.has_transfer_encoding && opts.forbid_transfer_encoding then InvalidFraming
  else if opts.bodyless then Ok(None)
  else if a.has_transfer_encoding then
    if !a.te.saw_chunked || a.te.coding_after_chunked then InvalidFraming else Ok(Chunked)
  else if a.content_length.Some? then
    if a.content_length.value == 0 then Ok(None) else Ok(ContentLength(a.content_length.value))
  else if opts.until_close_default then Ok(UntilClose)
  else Ok(None)
}

function AddAll(a: Analyzer, headers: seq<Header>): Option<Analyzer>
  decreases |headers|
{
  if |headers| == 0 then Some(a)
  else match AnalyzerAdd(a, headers[0])
    case Nothing => Nothing
    case Some(a') => AddAll(a', headers[1..])
}

function Determine(headers: seq<Header>, opts: Options): Result
{
  match AddAll(Analyzer(TransferEncoding(false, false), false, Nothing, Nothing), headers)
  case Nothing => InvalidFraming
  case Some(a) => Finish(a, opts)
}

// -- the RFC 9112 rules -------------------------------------------------------------

function TeValues(headers: seq<Header>): seq<string>
{
  if |headers| == 0 then []
  else (if EqIgnoreCase(headers[0].name, "transfer-encoding") then [headers[0].value] else []) + TeValues(headers[1..])
}

function ClValues(headers: seq<Header>): seq<string>
{
  if |headers| == 0 then []
  else (if EqIgnoreCase(headers[0].name, "content-length") then [headers[0].value] else []) + ClValues(headers[1..])
}

// RFC 9112 6.1: all Transfer-Encoding lines form one ordered list of codings.
function AllCodings(values: seq<string>): seq<string>
{
  if |values| == 0 then [] else NonEmpty(Codings(values[0])) + AllCodings(values[1..])
}

predicate IsChunked(coding: string)
{
  EqIgnoreCase(coding, "chunked")
}

// RFC 9112 6.3: `chunked` must be the final coding, and may be applied only once.
predicate ChunkedIsFinalAndUnique(codings: seq<string>)
{
  |codings| > 0 && IsChunked(codings[|codings| - 1]) && forall i :: 0 <= i < |codings| - 1 ==> !IsChunked(codings[i])
}

// RFC 9110 8.6: Content-Length = 1*DIGIT.
predicate IsDecimal(s: string)
{
  |s| > 0 && forall i :: 0 <= i < |s| ==> '0' <= s[i] <= '9'
}

function Spec(headers: seq<Header>, opts: Options): Result
{
  var te := TeValues(headers);
  var cl := ClValues(headers);
  if exists v :: v in cl && !(IsDecimal(TrimOws(v)) && DecimalValue(TrimOws(v)) < U64_LIMIT) then InvalidFraming
  else if exists i, j :: 0 <= i < j < |cl| && cl[i] != cl[j] then InvalidFraming
  else if |te| > 0 && |cl| > 0 then InvalidFraming
  else if |te| > 0 && opts.forbid_transfer_encoding then InvalidFraming
  else if opts.bodyless then Ok(None)
  else if |te| > 0 then
    if ChunkedIsFinalAndUnique(AllCodings(te)) then Ok(Chunked) else InvalidFraming
  else if |cl| > 0 then
    var n := DecimalValue(TrimOws(cl[0]));
    if n == 0 then Ok(None) else Ok(ContentLength(n))
  else if opts.until_close_default then Ok(UntilClose)
  else Ok(None)
}

lemma DetermineMatchesSpec(headers: seq<Header>, opts: Options)
  ensures Determine(headers, opts) == Spec(headers, opts)
{
  var cl := ClValues(headers);
  var codings := AllCodings(TeValues(headers));
  Invariant(headers);
  NonEmptyIsNonEmpty(TeValues(headers));
  TeAddCharacterization(TransferEncoding(false, false), codings);
  if AddAll(INIT, headers).Some? {
    var a := AddAll(INIT, headers).value;
    if a.has_transfer_encoding && !a.content_length.Some? && !opts.forbid_transfer_encoding && !opts.bodyless {
      ChunkedRule(codings);
    }
  }
}

const INIT := Analyzer(TransferEncoding(false, false), false, Nothing, Nothing)

predicate ClValid(cl: seq<string>)
{
  (forall v :: v in cl ==> IsDecimal(TrimOws(v)) && DecimalValue(TrimOws(v)) < U64_LIMIT)
  && (forall i, j :: 0 <= i < j < |cl| ==> cl[i] == cl[j])
}

lemma Invariant(headers: seq<Header>)
  ensures AddAll(INIT, headers).Some? <==> ClValid(ClValues(headers))
  ensures AddAll(INIT, headers).Some? ==>
    var a := AddAll(INIT, headers).value;
    var cl := ClValues(headers);
    && a.has_transfer_encoding == (|TeValues(headers)| > 0)
    && a.te == TeAdd(TransferEncoding(false, false), AllCodings(TeValues(headers)))
    && a.content_length == (if |cl| > 0 then Some(DecimalValue(TrimOws(cl[0]))) else Nothing)
    && a.content_length_value == (if |cl| > 0 then Some(cl[|cl| - 1]) else Nothing)
  decreases |headers|
{
  if |headers| > 0 {
    var hs, h := headers[..|headers| - 1], headers[|headers| - 1];
    assert headers == hs + [h];
    Invariant(hs);
    AddAllSnoc(INIT, hs, h);
    ValuesSnoc(hs, h);
    var cl := ClValues(hs);
    if EqIgnoreCase(h.name, "transfer-encoding") {
      assert !EqIgnoreCase(h.name, "content-length");
      assert ClValues(headers) == cl;
      assert TeValues(headers) == TeValues(hs) + [h.value];
      if AddAll(INIT, hs).Some? {
        AllCodingsSnoc(TeValues(hs), h.value);
        TeAddAppend(TransferEncoding(false, false), AllCodings(TeValues(hs)), NonEmpty(Codings(h.value)));
        TeAddSkipsEmpty(AddAll(INIT, hs).value.te, Codings(h.value));
      }
    } else if !EqIgnoreCase(h.name, "content-length") {
      assert ClValues(headers) == cl;
      assert TeValues(headers) == TeValues(hs);
    }
    if EqIgnoreCase(h.name, "content-length") {
      ParseDecimalIsSpec(TrimOws(h.value));
      assert !EqIgnoreCase(h.name, "transfer-encoding");
      var cl' := cl + [h.value];
      assert ClValues(headers) == cl';
      assert TeValues(headers) == TeValues(hs);
      if ClValid(cl') {
        forall i, j | 0 <= i < j < |cl| ensures cl[i] == cl[j] { assert cl'[i] == cl[i] && cl'[j] == cl[j]; }
        assert ClValid(cl);
        if |cl| > 0 { assert cl'[|cl| - 1] == cl'[|cl|]; }
        assert cl'[|cl'| - 1] == h.value;
        if |cl| > 0 { assert cl'[0] == cl[0]; } else { assert cl'[0] == h.value; }
      } else if ClValid(cl) && (|cl| == 0 || cl[|cl| - 1] == h.value) && ParseDecimal(TrimOws(h.value)).Some? {
        forall i, j | 0 <= i < j < |cl'| ensures cl'[i] == cl'[j] {
          if j == |cl| { assert cl[i] == cl[|cl| - 1]; }
        }
        assert false;
      }
    }
  } else {
    assert headers == [];
  }
}

lemma TeAddCharacterization(te: TransferEncoding, codings: seq<string>)
  requires forall c :: c in codings ==> |c| > 0
  ensures TeAdd(te, codings) == TransferEncoding(
    te.saw_chunked || (exists i :: 0 <= i < |codings| && IsChunked(codings[i])),
    te.coding_after_chunked || (te.saw_chunked && |codings| > 0)
      || (exists i :: 0 <= i < |codings| - 1 && IsChunked(codings[i])))
  decreases |codings|
{
  if |codings| > 0 {
    TeAddCharacterization(TeStep(te, codings[0]), codings[1..]);
    var rest := codings[1..];
    if exists i :: 0 <= i < |rest| && IsChunked(rest[i]) {
      var i :| 0 <= i < |rest| && IsChunked(rest[i]);
      assert IsChunked(codings[i + 1]);
    }
    if exists i :: 0 <= i < |rest| - 1 && IsChunked(rest[i]) {
      var i :| 0 <= i < |rest| - 1 && IsChunked(rest[i]);
      assert IsChunked(codings[i + 1]);
    }
    if exists i :: 0 <= i < |codings| - 1 && IsChunked(codings[i]) {
      var i :| 0 <= i < |codings| - 1 && IsChunked(codings[i]);
      if i > 0 { assert IsChunked(rest[i - 1]); }
    }
    if exists i :: 0 <= i < |codings| && IsChunked(codings[i]) {
      var i :| 0 <= i < |codings| && IsChunked(codings[i]);
      if i > 0 { assert IsChunked(rest[i - 1]); }
    }
  }
}

lemma ChunkedRule(codings: seq<string>)
  ensures ((exists i :: 0 <= i < |codings| && IsChunked(codings[i]))
    && !(exists i :: 0 <= i < |codings| - 1 && IsChunked(codings[i])))
    <==> ChunkedIsFinalAndUnique(codings)
{
  if ChunkedIsFinalAndUnique(codings) {
    assert IsChunked(codings[|codings| - 1]);
  }
}

lemma TeAddSkipsEmpty(te: TransferEncoding, codings: seq<string>)
  ensures TeAdd(te, codings) == TeAdd(te, NonEmpty(codings))
  decreases |codings|
{
  if |codings| > 0 {
    TeAddSkipsEmpty(TeStep(te, codings[0]), codings[1..]);
    if |codings[0]| == 0 {
      assert NonEmpty(codings) == NonEmpty(codings[1..]);
    } else {
      var ne := NonEmpty(codings);
      assert ne == [codings[0]] + NonEmpty(codings[1..]);
      assert ne[1..] == NonEmpty(codings[1..]);
    }
  }
}

lemma TeAddAppend(te: TransferEncoding, xs: seq<string>, ys: seq<string>)
  ensures TeAdd(te, xs + ys) == TeAdd(TeAdd(te, xs), ys)
  decreases |xs|
{
  if |xs| > 0 {
    assert (xs + ys)[1..] == xs[1..] + ys;
    assert (xs + ys)[0] == xs[0];
    TeAddAppend(TeStep(te, xs[0]), xs[1..], ys);
  } else {
    assert xs + ys == ys;
  }
}

lemma NonEmptyIsNonEmpty(values: seq<string>)
  ensures forall c :: c in AllCodings(values) ==> |c| > 0
  decreases |values|
{
  if |values| > 0 {
    NonEmptyFilters(Codings(values[0]));
    NonEmptyIsNonEmpty(values[1..]);
  }
}

lemma NonEmptyFilters(codings: seq<string>)
  ensures forall c :: c in NonEmpty(codings) ==> |c| > 0
  decreases |codings|
{
  if |codings| > 0 { NonEmptyFilters(codings[1..]); }
}

lemma AllCodingsSnoc(values: seq<string>, v: string)
  ensures AllCodings(values + [v]) == AllCodings(values) + NonEmpty(Codings(v))
  decreases |values|
{
  if |values| > 0 {
    assert (values + [v])[1..] == values[1..] + [v];
    AllCodingsSnoc(values[1..], v);
  } else {
    assert values + [v] == [v];
  }
}

lemma ValuesSnoc(hs: seq<Header>, h: Header)
  ensures TeValues(hs + [h]) == TeValues(hs) + (if EqIgnoreCase(h.name, "transfer-encoding") then [h.value] else [])
  ensures ClValues(hs + [h]) == ClValues(hs) + (if EqIgnoreCase(h.name, "content-length") then [h.value] else [])
  decreases |hs|
{
  if |hs| > 0 {
    assert (hs + [h])[1..] == hs[1..] + [h];
    ValuesSnoc(hs[1..], h);
  } else {
    assert hs + [h] == [h];
  }
}

lemma AddAllSnoc(a: Analyzer, hs: seq<Header>, h: Header)
  ensures AddAll(a, hs + [h]) == match AddAll(a, hs) case Nothing => Nothing case Some(a') => AnalyzerAdd(a', h)
  decreases |hs|
{
  if |hs| > 0 {
    assert (hs + [h])[1..] == hs[1..] + [h];
    if AnalyzerAdd(a, hs[0]).Some? {
      AddAllSnoc(AnalyzerAdd(a, hs[0]).value, hs[1..], h);
    }
  } else {
    assert hs + [h] == [h];
  }
}

lemma ParseDecimalIsSpec(s: string)
  ensures ParseDecimal(s).Some? <==> IsDecimal(s) && DecimalValue(s) < U64_LIMIT
  ensures ParseDecimal(s).Some? ==> ParseDecimal(s).value == DecimalValue(s)
{
  if |s| > 0 {
    ParseDecimalFromIsSpec(s, 0, 0);
  }
}

lemma ParseDecimalFromIsSpec(s: string, i: nat, n: nat)
  requires i <= |s| && n < U64_LIMIT
  requires n == DecimalValue(s[..i]) && forall k :: 0 <= k < i ==> '0' <= s[k] <= '9'
  ensures ParseDecimalFrom(s, i, n).Some? <==> IsDigits(s[i..]) && DecimalValue(s) < U64_LIMIT
  ensures ParseDecimalFrom(s, i, n).Some? ==> ParseDecimalFrom(s, i, n).value == DecimalValue(s)
  decreases |s| - i
{
  assert s[..|s|] == s;
  if i < |s| {
    assert s[..i + 1][..i] == s[..i];
    if '0' <= s[i] <= '9' {
      var n' := n * 10 + (s[i] as int - '0' as int);
      assert DecimalValue(s[..i + 1]) == n';
      if n' < U64_LIMIT {
        ParseDecimalFromIsSpec(s, i + 1, n');
      } else {
        PrefixBoundsValue(s, i + 1);
      }
      assert s[i..] == [s[i]] + s[i + 1..];
    } else {
      assert s[i..][0] == s[i];
    }
  }
}

predicate IsDigits(s: string)
{
  forall i :: 0 <= i < |s| ==> '0' <= s[i] <= '9'
}

lemma PrefixBoundsValue(s: string, i: nat)
  requires i <= |s|
  ensures DecimalValue(s[..i]) <= DecimalValue(s)
  decreases |s| - i
{
  if i < |s| {
    assert s[..i + 1][..i] == s[..i];
    PrefixBoundsValue(s, i + 1);
  } else {
    assert s[..i] == s;
  }
}

// -- string helpers, mirroring src/core/ascii.zig -----------------------------------

function Lower(c: char): char
{
  if 'A' <= c <= 'Z' then (c as int - 'A' as int + 'a' as int) as char else c
}

predicate EqIgnoreCase(a: string, b: string)
{
  |a| == |b| && forall i :: 0 <= i < |a| ==> Lower(a[i]) == Lower(b[i])
}

predicate IsOws(c: char)
{
  c == ' ' || c == '\t'
}

function TrimOws(s: string): string
{
  if |s| > 0 && IsOws(s[0]) then TrimOws(s[1..])
  else if |s| > 0 && IsOws(s[|s| - 1]) then TrimOws(s[..|s| - 1])
  else s
}

// `std.mem.splitScalar(u8, value, ',')`, each piece trimmed of SP / HTAB.
function Codings(value: string): seq<string>
{
  Split(value, 0, 0)
}

function Split(value: string, start: nat, i: nat): seq<string>
  requires start <= i <= |value|
  decreases |value| - i
{
  if i == |value| then [TrimOws(value[start..])]
  else if value[i] == ',' then [TrimOws(value[start..i])] + Split(value, i + 1, i + 1)
  else Split(value, start, i + 1)
}

function NonEmpty(codings: seq<string>): seq<string>
{
  if |codings| == 0 then [] else (if |codings[0]| == 0 then [] else [codings[0]]) + NonEmpty(codings[1..])
}

function ParseDecimal(s: string): Option<nat>
{
  if |s| == 0 then Nothing else ParseDecimalFrom(s, 0, 0)
}

// `std.math.mul` and `std.math.add` on u64 return null on overflow.
function ParseDecimalFrom(s: string, i: nat, n: nat): Option<nat>
  requires i <= |s| && n < U64_LIMIT
  decreases |s| - i
{
  if i == |s| then Some(n)
  else if s[i] < '0' || s[i] > '9' then Nothing
  else if n * 10 >= U64_LIMIT then Nothing
  else if n * 10 + (s[i] as int - '0' as int) >= U64_LIMIT then Nothing
  else ParseDecimalFrom(s, i + 1, n * 10 + (s[i] as int - '0' as int))
}

function DecimalValue(s: string): nat
{
  if |s| == 0 then 0 else DecimalValue(s[..|s| - 1]) * 10 + (if '0' <= s[|s| - 1] <= '9' then s[|s| - 1] as int - '0' as int else 0)
}
