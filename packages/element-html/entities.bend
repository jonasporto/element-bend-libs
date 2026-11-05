import Base
import ./entity_table.bend as Tab

# HTML character references (WHATWG 13.2.5.72-80), in text and attribute
# values:
# - named: the longest name in the table (entity_table.bend, all 2231) that
#   the text after '&' starts with, so "&notit;" is "¬it;" (legacy names work
#   without ';'). In an attribute, a legacy match followed by an alphanumeric
#   or '=' stays as written ("?a=1&copy=2" keeps its "&copy").
# - numeric: "&#" digits or "&#x" hex digits, ';' optional; no digits leaves
#   the text as written. 0, surrogates and values past U+10FFFF become
#   U+FFFD; 0x80-0x9F map through the windows-1252 table, as the spec says.
# Anything else keeps its '&'.

def rev_str(cs: List<&2, Char>) -> String:
  String.from_list(List.reverse(&2, Char, cs))

def is_alnum(+c: Char) -> Bool:
  Char.is_alpha(c) || Char.is_digit(c)

def hex_digit(+c: Char) -> Bool:
  +u = Char.to_u32(Char.to_lower(c))
  Char.is_digit(c) || ((u >= 97 : U32) && (u <= 102 : U32))

def hex_val(+c: U32) -> U32:
  Bool.pick(U32, (c >= 97 : U32), (c - 87 : U32), Bool.pick(U32, (c >= 65 : U32), (c - 55 : U32), (c - 48 : U32)))

# The leading run of s whose characters satisfy the test (hex or decimal
# digits, or letters and digits), at most `n` long.
def digits_go(n: Nat, s: String, +hex: Bool) -> String:
  match n:
    case 0n:
      SNil{}
    case 1n+r:
      match s:
        case SNil{}:
          SNil{}
        case SCon{+c, t}:
          Bool.pick(String, Bool.pick(Bool, hex, hex_digit(c), Char.is_digit(c)), SCon{c, digits_go(r, t, hex)}, SNil{})

def alnum_go(n: Nat, s: String) -> String:
  match n:
    case 0n:
      SNil{}
    case 1n+r:
      match s:
        case SNil{}:
          SNil{}
        case SCon{+c, t}:
          Bool.pick(String, is_alnum(c), SCon{c, alnum_go(r, t)}, SNil{})

# Digits to a value, saturating just past U+10FFFF (no U32 overflow).
def value_go(s: String, +base: U32, +acc: U32) -> U32:
  match s:
    case SNil{}:
      acc
    case SCon{+c, t}:
      value_go(t, base, U32.min(((acc * base : U32) + hex_val(Char.to_u32(c)) : U32), 1114112))

# windows-1252 for 0x80-0x9F (the spec's numeric reference table); others as is.
def nth_or(xs: List<&2, U32>, n: Nat, +d: U32) -> U32:
  match xs:
    case Nil{}:
      d
    case Con{h, t}:
      match n:
        case 0n:
          h
        case 1n+r:
          nth_or(t, r, d)

def c1_map(+v: U32) -> U32:
  Bool.pick(U32, (v >= 128 : U32) && (v <= 159 : U32),
    nth_or([8364, 129, 8218, 402, 8222, 8230, 8224, 8225, 710, 8240, 352, 8249, 338, 141, 381, 143,
            144, 8216, 8217, 8220, 8221, 8226, 8211, 8212, 732, 8482, 353, 8250, 339, 157, 382, 376], U32.to_nat((v - 128 : U32)), v),
    v)

def code_point(+v: U32) -> U32:
  Bool.pick(U32, U32.is_zero(v) || (v > 1114111 : U32) || ((v >= 55296 : U32) && (v <= 57343 : U32)), 65533, c1_map(v))

# What a reference turned into (reversed, to prepend to the output) and the
# text after it.
type Step is Data:
  Step{out: List<&2, Char>, rest: String}

def literal(+rest: String) -> Step:
  Step{['&'], rest}

# t is the text after "&#".
def numeric(+t: String) -> Step:
  +x = String.starts_with(t, "x") || String.starts_with(t, "X")
  +body = String.drop(t, Bool.pick(Nat, x, 1n, 0n))
  +ds = digits_go(12n, body, x)
  +after = String.drop(body, String.length(ds))
  +semi = String.starts_with(after, ";")
  Bool.pick(Step, String.is_empty(ds), Step{['#', '&'], t},
    Step{[Char.from_u32(code_point(value_go(ds, Bool.pick(U32, x, 16, 10), 0)))], String.drop(after, Bool.pick(Nat, semi, 1n, 0n))})

def letter_index(+c: U32) -> Nat:
  U32.to_nat(Bool.pick(U32, (c >= 97 : U32), (c - 71 : U32), (c - 65 : U32)))

type Named is Data:
  Named{name: String, cps: List<&2, U32>}

def nth0(xs: List<&2, U32>, n: Nat) -> U32:
  nth_or(xs, n, 0)

# 6-bit code (entity_table.bend) to a character.
def sym(+v: U32) -> Char:
  Char.from_u32(Bool.pick(U32, (v <= 10 : U32), (v + 47 : U32),
    Bool.pick(U32, (v <= 36 : U32), (v + 54 : U32), Bool.pick(U32, (v <= 62 : U32), (v + 60 : U32), 59))))

def unpack(k: Nat, +w: U32) -> List<&2, Char>:
  match k:
    case 0n:
      Nil{}
    case 1n+r:
      sym((w % 64 : U32)) <> unpack(r, (w / 64 : U32))

# The characters in a name's words after the first; `left` still to read.
def more_chars(ws: List<&2, U32>, +left: U32) -> List<&2, Char>:
  match ws:
    case Nil{}:
      Nil{}
    case Con{w, t}:
      List.append(&2, Char, unpack(U32.to_nat(U32.min(left, 5)), w), more_chars(t, (left - U32.min(left, 5) : U32)))

# One packed record at the head of ws: its name, code points, and the rest.
type Rec is Data:
  Rec{name: String, cps: List<&2, U32>, rest: List<&2, U32>}

def rec_of(+ws: List<&2, U32>) -> Rec:
  +first = nth0(ws, 0n)
  +len = (first % 64 : U32)
  +more = (len - U32.min(len, 4) : U32)
  +nw = U32.to_nat(((more + 4 : U32) / 5 : U32))
  +name = String.from_list(List.append(&2, Char, unpack(U32.to_nat(U32.min(len, 4)), (first / 64 : U32)),
    more_chars(List.take(&2, U32, List.drop(&2, U32, ws, 1n), nw), more)))
  +at = List.drop(&2, U32, ws, Nat.add(nw, 1n))
  +w0 = nth0(at, 0n)
  +one = (w0 >= 16777216 : U32)
  Rec{name, Bool.pick(List<&2, U32>, one, [(w0 - 16777216 : U32)], [w0, (nth0(at, 1n) - 16777216 : U32)]),
    List.drop(&2, U32, at, Bool.pick(Nat, one, 1n, 2n))}

# The 6-bit code of a character (0 if it cannot be in a name).
def code6(+c: U32) -> U32:
  Bool.pick(U32, (c >= 48 : U32) && (c <= 57 : U32), (c - 47 : U32),
    Bool.pick(U32, (c >= 65 : U32) && (c <= 90 : U32), (c - 54 : U32),
      Bool.pick(U32, (c >= 97 : U32) && (c <= 122 : U32), (c - 60 : U32), Bool.pick(U32, U32.is_eq(c, 59), 63, 0))))

def pack4(k: Nat, s: String) -> U32:
  match k:
    case 0n:
      0
    case 1n+r:
      match s:
        case SNil{}:
          0
        case SCon{c, t}:
          (code6(Char.to_u32(c)) + (pack4(r, t) * 64 : U32) : U32)

# Words a record takes: its first, the rest of its name, its code points.
def rec_words(+ws: List<&2, U32>) -> Nat:
  +len = (nth0(ws, 0n) % 64 : U32)
  +nw = U32.to_nat((((len - U32.min(len, 4) : U32) + 4 : U32) / 5 : U32))
  Nat.add(Nat.add(nw, 1n), Bool.pick(Nat, (nth0(ws, Nat.add(nw, 1n)) >= 16777216 : U32), 1n, 2n))

type RS is Data:
  RHit{}
  RNext{}
  REnd{}

def rec_name(r: Rec) -> String:
  match r:
    case Rec{name, cps, rest}:
      name

# The full name is read only when the first four characters already match.
def rs_long(pre: Bool, +ws: List<&2, U32>, +run: String) -> RS:
  match pre:
    case False{}:
      RNext{}
    case True{}:
      Bool.pick(RS, String.starts_with(run, rec_name(rec_of(ws))), RHit{}, RNext{})

def rs_of(+ws: List<&2, U32>, +run: String, +runpack: U32) -> RS:
  +first = nth0(ws, 0n)
  +len = (first % 64 : U32)
  +mask = (U32.shln(1, U32.to_nat((U32.min(len, 4) * 6 : U32))) - 1 : U32)
  +pre = U32.is_eq(U32.and((first / 64 : U32), mask), U32.and(runpack, mask))
  Bool.pick(RS, List.is_empty(&2, U32, ws) || U32.is_zero(len), REnd{},
    Bool.pick(RS, (len <= 4 : U32), Bool.pick(RS, pre, RHit{}, RNext{}), rs_long(pre, ws, run)))

def rec_named(r: Rec) -> Named:
  match r:
    case Rec{name, cps, rest}:
      Named{name, cps}

# Walk the bucket's records: the first name `run` starts with is the longest
# (records are longest first). `k` classifies the record at the head of ws,
# computed by the caller.
def find(fuel: Nat, +run: String, +runpack: U32, +ws: List<&2, U32>, k: RS) -> Maybe<&2, Named>:
  match fuel:
    case 0n:
      None{}
    case 1n+f:
      match k:
        case RHit{}:
          Some{rec_named(rec_of(ws))}
        case REnd{}:
          None{}
        case RNext{}:
          +nx = List.drop(&2, U32, ws, rec_words(ws))
          find(f, run, runpack, nx, rs_of(nx, run, runpack))

def longest_in(+ws: List<&2, U32>, +run: String) -> Maybe<&2, Named>:
  +rp = pack4(4n, run)
  find(List.length(&2, U32, ws), run, rp, ws, rs_of(ws, run, rp))

def cps_chars(cps: List<&2, U32>) -> List<&2, Char>:
  match cps:
    case Nil{}:
      Nil{}
    case Con{c, t}:
      Char.from_u32(c) <> cps_chars(t)

def first_char(s: String) -> Char:
  match s:
    case SNil{}:
      ' '
    case SCon{c, t}:
      c

def named_hit(m: Maybe<&2, Named>, +t: String, +attr: Bool) -> Step:
  match m:
    case None{}:
      literal(t)
    case Some{value}:
      match value:
        case Named{+name, cps}:
          +after = String.drop(t, String.length(name))
          +nx = first_char(after)
          Bool.pick(Step, attr && Bool.not(String.ends_with(name, ";")) && (is_alnum(nx) || Char.is_eq(nx, '=')),
            literal(t), Step{List.reverse(&2, Char, cps_chars(cps)), after})

# t is the text after '&', starting with a letter.
def named(+t: String, +attr: Bool) -> Step:
  +run = alnum_go(40n, t)
  +semi = String.starts_with(String.drop(t, String.length(run)), ";")
  +key = run ++ Bool.pick(String, semi, ";", "")
  named_hit(longest_in(Tab.bucket(letter_index(Char.to_u32(first_char(t)))), key), t, attr)

type RK is Data:
  RNum{}
  RName{}
  RNone{}

def kind_of(+t: String) -> RK:
  +c = first_char(t)
  Bool.pick(RK, Char.is_eq(c, '#') && Bool.not(String.is_empty(t)), RNum{}, Bool.pick(RK, Char.is_alpha(c) && Bool.not(String.is_empty(t)), RName{}, RNone{}))

def reference(k: RK, +t: String, +attr: Bool) -> Step:
  match k:
    case RNum{}:
      numeric(String.drop(t, 1n))
    case RName{}:
      named(t, attr)
    case RNone{}:
      literal(t)

def step(amp: Bool, +c: Char, +t: String, +attr: Bool) -> Step:
  match amp:
    case False{}:
      Step{[c], t}
    case True{}:
      reference(kind_of(t), t, attr)

def step_out(s: Step) -> List<&2, Char>:
  match s:
    case Step{out, rest}:
      out

def step_rest(s: Step) -> String:
  match s:
    case Step{out, rest}:
      rest

# One pass; `fuel` bounds it (every step consumes at least one character).
def dec(fuel: Nat, s: String, +attr: Bool, +out: List<&2, Char>) -> List<&2, Char>:
  match fuel:
    case 0n:
      out
    case 1n+f:
      match s:
        case SNil{}:
          out
        case SCon{+c, +t}:
          +st = step(Char.is_eq(c, '&'), c, t, attr)
          dec(f, step_rest(st), attr, List.append(&2, Char, step_out(st), out))

def has_amp(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{c, t}:
      Char.is_eq(c, '&') || has_amp(t)

def decode_if(amp: Bool, +s: String, +attr: Bool) -> String:
  match amp:
    case False{}:
      s
    case True{}:
      rev_str(dec(String.length(s), s, attr, Nil{}))

# Most text has no '&': one scan, and it comes back unchanged.
def decode_in(+s: String, +attr: Bool) -> String:
  decode_if(has_amp(s), s, attr)

# Character references in text.
def decode(+s: String) -> String:
  decode_in(s, False{})

# Character references in an attribute value.
def decode_attr(+s: String) -> String:
  decode_in(s, True{})
