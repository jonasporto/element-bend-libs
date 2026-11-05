import Base

# ASN.1 DER (ITU-T X.690) reading: enough for X.509. A value is a TLV: one
# tag byte (low-tag-number form; X.509 never needs the high form), a length
# (short form, or long form with up to 3 length bytes; indefinite lengths are
# not DER and are refused), and the contents. `raw` keeps the whole encoding,
# because signatures cover exact bytes (tbsCertificate) and names compare
# byte for byte. Malformed input reads as End or as an empty Tlv, never a crash.

type Tlv is Data:
  Tlv{tag: U32, body: List<&2, U32>, raw: List<&2, U32>}

type Next is Data:
  Got{tlv: Tlv, rest: List<&2, U32>}
  End{}

def or0(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{value}:
      value

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  or0(List.get(&2, U32, xs, n))

def zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      0 <> zeros(r)

def empty() -> Tlv:
  Tlv{0, Nil{}, Nil{}}

def got_if(ok: Bool, +bs: List<&2, U32>, +head: Nat, +len: Nat) -> Next:
  match ok:
    case False{}:
      End{}
    case True{}:
      +raw = List.take(&2, U32, bs, Nat.add(head, len))
      Got{Tlv{nth(bs, 0n), List.drop(&2, U32, raw, head), raw}, List.drop(&2, U32, bs, Nat.add(head, len))}

# The header size and contents length from the first length byte.
def head_of(+l0: U32) -> Nat:
  Bool.pick(Nat, (l0 < 128 : U32), 2n, U32.to_nat((l0 - 126 : U32)))

def len_of(+bs: List<&2, U32>, +l0: U32) -> U32:
  Bool.pick(U32, (l0 < 128 : U32), l0,
    Bool.pick(U32, U32.is_eq(l0, 129), nth(bs, 2n),
      Bool.pick(U32, U32.is_eq(l0, 130), ((nth(bs, 2n) * 256 : U32) + nth(bs, 3n) : U32),
        (((nth(bs, 2n) * 65536 : U32) + (nth(bs, 3n) * 256 : U32) : U32) + nth(bs, 4n) : U32))))

# The first TLV of bs and what follows it.
def read(+bs: List<&2, U32>) -> Next:
  +l0 = nth(bs, 1n)
  +head = head_of(l0)
  +len = U32.to_nat(len_of(bs, l0))
  got_if(Bool.not(U32.is_eq(l0, 128)) && (l0 <= 131 : U32) && Nat.is_ge(List.length(&2, U32, bs), Nat.add(head, len)), bs, head, len)

def one(n: Next) -> Tlv:
  match n:
    case End{}:
      empty()
    case Got{tlv, rest}:
      tlv

# Exactly one TLV filling bs (a certificate, an extension value).
def decode(+bs: List<&2, U32>) -> Tlv:
  one(read(bs))

# Every TLV in a row; `fuel` bounds the count (each TLV takes at least 2 bytes).
def items_go(fuel: Nat, n: Next) -> List<&2, Tlv>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+r:
      match n:
        case End{}:
          Nil{}
        case Got{tlv, rest}:
          tlv <> items_go(r, read(rest))

def items(+bs: List<&2, U32>) -> List<&2, Tlv>:
  items_go(List.length(&2, U32, bs), read(bs))

def tag(t: Tlv) -> U32:
  match t:
    case Tlv{g, b, r}:
      g

def body(t: Tlv) -> List<&2, U32>:
  match t:
    case Tlv{g, b, r}:
      b

def raw(t: Tlv) -> List<&2, U32>:
  match t:
    case Tlv{g, b, r}:
      r

# The children of a constructed value (SEQUENCE, SET, [n] EXPLICIT).
def kids(+t: Tlv) -> List<&2, Tlv>:
  items(body(t))

def or_empty(m: Maybe<&2, Tlv>) -> Tlv:
  match m:
    case None{}:
      empty()
    case Some{value}:
      value

def at(+ts: List<&2, Tlv>, +i: Nat) -> Tlv:
  or_empty(List.get(&2, Tlv, ts, i))

def kid(+t: Tlv, +i: Nat) -> Tlv:
  at(kids(t), i)

def count(+t: Tlv) -> Nat:
  List.length(&2, Tlv, kids(t))

def same(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{x, xt} Con{y, yt}:
      U32.is_eq(x, y) && same(xt, yt)
    case _ _:
      False{}

# An OBJECT IDENTIFIER's contents equal to `oid` (its DER contents bytes).
def is_oid(+t: Tlv, +oid: List<&2, U32>) -> Bool:
  U32.is_eq(tag(t), 6) && same(body(t), oid)

# A BIT STRING's bits as bytes (the leading unused-bits count dropped).
def bits(+t: Tlv) -> List<&2, U32>:
  List.drop(&2, U32, body(t), 1n)

# ---- time ----------------------------------------------------------------------------

# A byte that is not a digit reads as 0. It used to wrap (b - 48 below '0'
# is near 2^32), and a certificate's time arrives before the certificate is
# verified: one malformed date grew past Bend's largest Nat (2^48 - 1) in
# the date arithmetic and stopped the whole process. Fields are 2 or 4
# bytes, so every value now stays below 10^4.
def digit(+b: U32) -> U32:
  Bool.pick(U32, ((b >= 48 : U32) && (b <= 57 : U32)), (b - 48 : U32), 0)

def digits(bs: List<&2, U32>, +acc: Nat) -> Nat:
  match bs:
    case Nil{}:
      acc
    case Con{b, t}:
      digits(t, Nat.add(Nat.mul(acc, 10n), U32.to_nat(digit(b))))

def field(+bs: List<&2, U32>, +at: Nat, +n: Nat) -> Nat:
  digits(List.take(&2, U32, List.drop(&2, U32, bs, at), n), 0n)

# Days from 1970-01-01 to y-m-d (Howard Hinnant's days_from_civil), clamped
# at zero for dates before 1970.
def days_from_civil(+y0: Nat, +m: Nat, +d: Nat) -> Nat:
  +y = Bool.pick(Nat, Nat.is_le(m, 2n), Nat.sub(y0, 1n), y0)
  +era = Nat.div(y, 400n)
  +yoe = Nat.sub(y, Nat.mul(era, 400n))
  +mp = Bool.pick(Nat, Nat.is_gt(m, 2n), Nat.sub(m, 3n), Nat.add(m, 9n))
  +doy = Nat.add(Nat.div(Nat.add(Nat.mul(153n, mp), 2n), 5n), Nat.sub(d, 1n))
  +doe = Nat.add(Nat.sub(Nat.add(Nat.mul(yoe, 365n), Nat.div(yoe, 4n)), Nat.div(yoe, 100n)), doy)
  Nat.sub(Nat.add(Nat.mul(era, 146097n), doe), 719468n)

# UTCTime (YYMMDDHHMMSSZ; YY < 50 is 20YY) or GeneralizedTime
# (YYYYMMDDHHMMSSZ) as seconds since 1970-01-01 UTC.
def seconds(+y: Nat, +bs: List<&2, U32>, +at: Nat) -> Nat:
  +days = days_from_civil(y, field(bs, at, 2n), field(bs, Nat.add(at, 2n), 2n))
  Nat.add(Nat.mul(days, 86400n),
    Nat.add(Nat.mul(field(bs, Nat.add(at, 4n), 2n), 3600n),
      Nat.add(Nat.mul(field(bs, Nat.add(at, 6n), 2n), 60n), field(bs, Nat.add(at, 8n), 2n))))

def time(+t: Tlv) -> Nat:
  +bs = body(t)
  +yy = field(bs, 0n, 2n)
  Bool.pick(Nat, U32.is_eq(tag(t), 23),
    seconds(Bool.pick(Nat, Nat.is_lt(yy, 50n), Nat.add(yy, 2000n), Nat.add(yy, 1900n)), bs, 2n),
    seconds(field(bs, 0n, 4n), bs, 4n))
