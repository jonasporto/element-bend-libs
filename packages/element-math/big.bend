import Base

# Natural numbers of any size, for public-key cryptography (RSA, ECDSA).
# A number is a list of 16-bit limbs, least significant first, held in U32:
# Bend has no 64-bit integers, and a limb product plus a limb plus a carry,
# (2^16-1)^2 + 2 (2^16-1), is exactly 2^32 - 1, so it never wraps.
#
# Modular multiplication is Montgomery's (CIOS form, as in BearSSL's
# i31 code and the Handbook of Applied Cryptography 14.36): a Mod carries the
# modulus n (odd), its limb count k, -n^-1 mod 2^16 and R^2 mod n with
# R = 2^(16k). All numbers handed to a Mod are k limbs and below n.

def zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      0 <> zeros(r)

def or0(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{value}:
      value

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  or0(List.get(&2, U32, xs, n))

def tail(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# Exactly k limbs: truncated, or padded with zeros on the high side.
def fit(k: Nat, xs: List<&2, U32>) -> List<&2, U32>:
  match k:
    case 0n:
      Nil{}
    case 1n+r:
      match xs:
        case Nil{}:
          0 <> fit(r, Nil{})
        case Con{h, t}:
          h <> fit(r, t)

# ---- bytes -----------------------------------------------------------------------

# Little-endian bytes to limbs.
def pairs(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{a, t}:
      match t:
        case Nil{}:
          [a]
        case Con{b, t2}:
          (a + (b * 256 : U32) : U32) <> pairs(t2)

# Big-endian bytes (the form in certificates and signatures) to a number.
def from_bytes(bs: List<&2, U32>) -> List<&2, U32>:
  pairs(List.reverse(&2, U32, bs))

def unpair(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+h, t}:
      (h % 256 : U32) <> ((h / 256 : U32) <> unpair(t))

# A number as exactly `n` big-endian bytes.
def to_bytes(x: List<&2, U32>, n: Nat) -> List<&2, U32>:
  List.reverse(&2, U32, fit(n, unpair(x)))

def byte_bits(c: Nat, +b: U32) -> List<&2, Bool>:
  match c:
    case 0n:
      Nil{}
    case 1n+(+r):
      U32.is_eq(U32.and((b / U32.shln(1, r) : U32), 1), 1) <> byte_bits(r, b)

# Bits of big-endian bytes, most significant first.
def bits_of_bytes(bs: List<&2, U32>) -> List<&2, Bool>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{b, t}:
      List.append(&2, Bool, byte_bits(8n, b), bits_of_bytes(t))

def is_zero(xs: List<&2, U32>) -> Bool:
  match xs:
    case Nil{}:
      True{}
    case Con{h, t}:
      U32.is_zero(h) && is_zero(t)

def eq(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{x, xt} Con{y, yt}:
      U32.is_eq(x, y) && eq(xt, yt)
    case _ _:
      False{}

# ---- add and subtract ------------------------------------------------------------

# a + b over a's length, the final carry appended as one more limb.
def add_go(a: List<&2, U32>, +b: List<&2, U32>, +c: U32) -> List<&2, U32>:
  match a:
    case Nil{}:
      [c]
    case Con{x, at}:
      +s = (x + nth(b, 0n) + c : U32)
      (s % 65536 : U32) <> add_go(at, tail(b), (s / 65536 : U32))

# a - b over a's length, the final borrow (0 or 1) appended.
def sub_go(a: List<&2, U32>, +b: List<&2, U32>, +br: U32) -> List<&2, U32>:
  match a:
    case Nil{}:
      [br]
    case Con{x, at}:
      +d = (x + 65536 - nth(b, 0n) - br : U32)
      (d % 65536 : U32) <> sub_go(at, tail(b), (1 - (d / 65536 : U32) : U32))

# The borrow of a - b: a < b.
def lt(+a: List<&2, U32>, +b: List<&2, U32>) -> Bool:
  U32.is_eq(nth(sub_go(a, b, 0), List.length(&2, U32, a)), 1)

def pick(c: Bool, a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  Bool.pick(List<&2, U32>, c, a, b)

# ---- Montgomery ------------------------------------------------------------------

type Mod is Data:
  Mod{k: Nat, n: List<&2, U32>, ninv: U32, r2: List<&2, U32>}

# (a + b) mod n, a and b below n.
def add_mod(+k: Nat, +n: List<&2, U32>, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  +s = add_go(a, b, 0)
  +d = sub_go(s, n, 0)
  pick(U32.is_zero(nth(d, 1n+k)), fit(k, d), fit(k, s))

# (a - b) mod n, a and b below n.
def sub_mod(+k: Nat, +n: List<&2, U32>, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  +d = sub_go(a, b, 0)
  pick(U32.is_zero(nth(d, k)), fit(k, d), fit(k, add_go(fit(k, d), n, 0)))

# 2^c x mod n, doubling c times.
def doublings(c: Nat, +k: Nat, +n: List<&2, U32>, +x: List<&2, U32>) -> List<&2, U32>:
  match c:
    case 0n:
      x
    case 1n+r:
      doublings(r, k, n, add_mod(k, n, x, x))

# -n0^-1 mod 2^16 by Newton's iteration; x = n0 is right to 3 bits for odd n0,
# and each step doubles the correct bits (U32 products wrap mod 2^32, which
# keeps the low 16 bits exact).
def newton(+n0: U32, +x: U32) -> U32:
  (x * (2 - (n0 * x : U32) : U32) : U32)

def ninv_of(+n0: U32) -> U32:
  ((65536 - (newton(n0, newton(n0, newton(n0, newton(n0, n0)))) % 65536 : U32) : U32) % 65536 : U32)

# R mod n: when n's top bit is set, R - n (that is, -n mod R) is below n;
# otherwise 1 doubled 16k times.
def r_mod(top: Bool, +k: Nat, +n: List<&2, U32>) -> List<&2, U32>:
  match top:
    case True{}:
      fit(k, sub_go(zeros(k), n, 0))
    case False{}:
      doublings(Nat.mul(k, 16n), k, n, fit(k, [1]))

# The number of times 2 divides x, up to `c`.
def twos(c: Nat, +x: Nat) -> Nat:
  match c:
    case 0n:
      0n
    case 1n+r:
      Bool.pick(Nat, Nat.is_eq(Nat.mod(x, 2n), 0n), Nat.add(twos(r, Nat.div(x, 2n)), 1n), 0n)

# One CIOS row, fused: t + a_i b + m n in a single pass with two carries
# (each partial sum stays below 2^32), where m = (t_0 + a_i b_0) ninv mod 2^16
# makes the low limb zero. t has k + 1 limbs; the row yields k + 2, the first
# of them zero.
def row(t: List<&2, U32>, bs: List<&2, U32>, ns: List<&2, U32>, +a: U32, +m: U32, +c1: U32, +c2: U32) -> List<&2, U32>:
  match t:
    case Nil{}:
      [((c1 + c2 : U32) % 65536 : U32)]
    case Con{tv, tt}:
      match bs ns:
        case Con{b, bt} Con{n, nt}:
          +s1 = (tv + (a * b : U32) + c1 : U32)
          +s2 = ((s1 % 65536 : U32) + (m * n : U32) + c2 : U32)
          (s2 % 65536 : U32) <> row(tt, bt, nt, a, m, (s1 / 65536 : U32), (s2 / 65536 : U32))
        case _ _:
          +s1 = (tv + c1 : U32)
          +s2 = ((s1 % 65536 : U32) + c2 : U32)
          (s2 % 65536 : U32) <> row(tt, Nil{}, Nil{}, a, m, (s1 / 65536 : U32), (s2 / 65536 : U32))

def mont_go(a: List<&2, U32>, +b: List<&2, U32>, +n: List<&2, U32>, +ninv: U32, +t: List<&2, U32>) -> List<&2, U32>:
  match a:
    case Nil{}:
      t
    case Con{+ai, at}:
      +m = ((((nth(t, 0n) + (ai * nth(b, 0n) : U32) : U32) % 65536 : U32) * ninv : U32) % 65536 : U32)
      mont_go(at, b, n, ninv, tail(row(t, b, n, ai, m, 0, 0)))

# a b R^-1 mod n.
def mmul(m: Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  match m:
    case Mod{+k, +n, +ninv, r2}:
      +t = mont_go(a, b, n, ninv, zeros(1n+k))
      +d = sub_go(t, n, 0)
      pick(U32.is_zero(nth(d, 1n+k)), fit(k, d), fit(k, t))

# Montgomery squaring doubles the exponent: x = 2^e R becomes 2^(2e) R.
def squarings(c: Nat, +m: Mod, +x: List<&2, U32>) -> List<&2, U32>:
  match c:
    case 0n:
      x
    case 1n+r:
      squarings(r, m, mmul(m, x, x))

def k_of(m: Mod) -> Nat:
  match m:
    case Mod{k, n, ninv, r2}:
      k

def n_of(m: Mod) -> List<&2, U32>:
  match m:
    case Mod{k, n, ninv, r2}:
      n

# R^2 mod n = 2^(16k) R: with 16k = 2^v s (s odd), double R mod n s times to
# get 2^s R, then square v times.
def r2_of_mod(+m: Mod) -> List<&2, U32>:
  +k = k_of(m)
  +n = n_of(m)
  +v = twos(16n, Nat.mul(k, 16n))
  +s = Nat.div(Nat.mul(k, 16n), Nat.pow(2n, v))
  squarings(v, m, doublings(s, k, n, r_mod((nth(n, Nat.sub(k, 1n)) >= 32768 : U32), k, n)))

def with_r2(m: Mod) -> Mod:
  match m:
    case Mod{+k, +n, +ninv, r2}:
      Mod{k, n, ninv, r2_of_mod(Mod{k, n, ninv, Nil{}})}

# A modulus from its limbs (odd, above 1, top limb nonzero).
def modulus(+n: List<&2, U32>) -> Mod:
  with_r2(Mod{List.length(&2, U32, n), n, ninv_of(nth(n, 0n)), Nil{}})

def modulus_of_bytes(+bs: List<&2, U32>) -> Mod:
  modulus(fit(Nat.div(Nat.add(List.length(&2, U32, bs), 1n), 2n), from_bytes(bs)))

def r2_of(m: Mod) -> List<&2, U32>:
  match m:
    case Mod{k, n, ninv, r2}:
      r2

def one(+m: Mod) -> List<&2, U32>:
  fit(k_of(m), [1])

# Into and out of the Montgomery form x R mod n.
def to_mont(+m: Mod, +x: List<&2, U32>) -> List<&2, U32>:
  mmul(m, fit(k_of(m), x), r2_of(m))

def from_mont(+m: Mod, +x: List<&2, U32>) -> List<&2, U32>:
  mmul(m, x, one(m))

# a b mod n for plain (not Montgomery) a, b below n.
def mul(+m: Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  mmul(m, mmul(m, a, b), r2_of(m))

def add(+m: Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  add_mod(k_of(m), n_of(m), a, b)

def sub(+m: Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  sub_mod(k_of(m), n_of(m), a, b)

def pick_mul(b: Bool, +m: Mod, +acc: List<&2, U32>, +x: List<&2, U32>) -> List<&2, U32>:
  match b:
    case True{}:
      mmul(m, acc, x)
    case False{}:
      acc

# Square and multiply in Montgomery form, exponent bits most significant first.
def exp_go(bits: List<&2, Bool>, +m: Mod, +x: List<&2, U32>, +acc: List<&2, U32>) -> List<&2, U32>:
  match bits:
    case Nil{}:
      acc
    case Con{b, t}:
      exp_go(t, m, x, pick_mul(b, m, mmul(m, acc, acc), x))

# x^e mod n, x plain and below n, e as big-endian bytes.
def pow(+m: Mod, +x: List<&2, U32>, +e: List<&2, U32>) -> List<&2, U32>:
  from_mont(m, exp_go(bits_of_bytes(e), m, to_mont(m, x), to_mont(m, one(m))))

# x^-1 mod a prime p, as x^(p-2) (Fermat); 0 for 0.
def inv(+m: Mod, +x: List<&2, U32>) -> List<&2, U32>:
  pow(m, x, to_bytes(fit(k_of(m), sub_go(n_of(m), [2], 0)), Nat.mul(k_of(m), 2n)))
