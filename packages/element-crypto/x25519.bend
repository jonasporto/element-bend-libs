import Base

# X25519 (RFC 7748 section 5): Diffie-Hellman on Curve25519, the key
# exchange of TLS 1.3. Scalars and u-coordinates are 32 bytes, little-endian.
#
# Field arithmetic mod p = 2^255 - 19 with 32 limbs of 8 bits and U32
# accumulators (Bend has no 64-bit integers). Products of two 32-limb numbers
# reach 63 columns of at most 32 * 255 * 255; the upper 31 fold down times 38
# (2^256 = 2 * 2^255 = 2 * 19 mod p), which still fits in 32 bits.
# Subtraction adds 4p in a non-canonical form whose limbs are all >= 436, so
# no limb goes negative. The Montgomery ladder follows RFC 7748 section 5.

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

# ---- carries -----------------------------------------------------------------

# Carry limbs to 8 bits; returns the limbs with the final carry appended.
def carry_go(xs: List<&2, U32>, +c: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      [c]
    case Con{x, t}:
      +s = (x + c : U32)
      (s % 256 : U32) <> carry_go(t, (s / 256 : U32))

def add_low(xs: List<&2, U32>, +v: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      (x + v : U32) <> t

# Reduce 32 limbs of any size to 32 limbs < 256 (value mod p, maybe >= p):
# carry, fold the overflow above 2^256 back times 38, twice.
def reduce(+xs: List<&2, U32>) -> List<&2, U32>:
  +a = carry_go(xs, 0)
  +b = carry_go(add_low(List.take(&2, U32, a, 32n), (nth(a, 32n) * 38 : U32)), 0)
  List.take(&2, U32, carry_go(add_low(List.take(&2, U32, b, 32n), (nth(b, 32n) * 38 : U32)), 0), 32n)

# ---- field operations ----------------------------------------------------------

def zip_add(xs: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  match xs ys:
    case Con{x, xt} Con{y, yt}:
      (x + y : U32) <> zip_add(xt, yt)
    case _ _:
      Nil{}

def zip_sub(xs: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  match xs ys:
    case Con{x, xt} Con{y, yt}:
      (x - y : U32) <> zip_sub(xt, yt)
    case _ _:
      Nil{}

def add(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  reduce(zip_add(a, b))

# 4p = 2^257 - 76 with limbs 436, 510, ..., 510 (each above any reduced limb).
def four_p() -> List<&2, U32>:
  436 <> List.concat(&2, U32, [[510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510], [510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510, 510]])

def sub(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  reduce(zip_sub(zip_add(a, four_p()), b))

def scale(xs: List<&2, U32>, +k: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      (x * k : U32) <> scale(t, k)

# Like zip_add, but keeps the tail of the longer first list.
def zip_add_long(xs: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, xt}:
      match ys:
        case Nil{}:
          Con{x, xt}
        case Con{y, yt}:
          (x + y : U32) <> zip_add_long(xt, yt)

# acc + (ys shifted by `off` limbs)
def add_at(off: Nat, acc: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  match off:
    case 0n:
      zip_add_long(acc, ys)
    case 1n+k:
      match acc:
        case Nil{}:
          Nil{}
        case Con{a, t}:
          a <> add_at(k, t, ys)

# Schoolbook product into 63 columns.
def mul_cols(as: List<&2, U32>, +b: List<&2, U32>, acc: List<&2, U32>, +off: Nat) -> List<&2, U32>:
  match as:
    case Nil{}:
      acc
    case Con{a, t}:
      mul_cols(t, b, add_at(off, acc, scale(b, a)), Nat.add(off, 1n))

def mul(+a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  +cols = mul_cols(a, b, zeros(63n), 0n)
  reduce(zip_add_long(List.take(&2, U32, cols, 32n), scale(List.drop(&2, U32, cols, 32n), 38)))

def sq(+a: List<&2, U32>) -> List<&2, U32>:
  mul(a, a)

def mul_small(+a: List<&2, U32>, +k: U32) -> List<&2, U32>:
  reduce(scale(a, k))

# a^(p-2) = a^-1: p - 2 = 2^255 - 21, whose bits from 254 down are all 1
# except bits 4 and 2 (TweetNaCl's inv25519).
def inv_go(n: Nat, +a: List<&2, U32>, +c: List<&2, U32>, +bit: U32) -> List<&2, U32>:
  match n:
    case 0n:
      c
    case 1n+r:
      +s = sq(c)
      inv_go(r, a, Bool.pick(List<&2, U32>, U32.is_eq(bit, 2) || U32.is_eq(bit, 4), s, mul(s, a)), (bit - 1 : U32))

def invert(+a: List<&2, U32>) -> List<&2, U32>:
  inv_go(254n, a, a, 253)

# Canonical form: subtract p while the value is >= p (at most twice).
def p_limbs() -> List<&2, U32>:
  237 <> List.concat(&2, U32, [[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], [127]])

# a - p with borrow; the borrow out tells whether a < p.
def sub_p_go(xs: List<&2, U32>, ps: List<&2, U32>, +borrow: U32) -> List<&2, U32>:
  match xs ps:
    case Con{x, xt} Con{p, pt}:
      +d = ((x + 256 : U32) - (p + borrow : U32) : U32)
      (d % 256 : U32) <> sub_p_go(xt, pt, Bool.pick(U32, (d < 256 : U32), 1, 0))
    case _ _:
      [borrow]

def minus_p_once(+a: List<&2, U32>) -> List<&2, U32>:
  +d = sub_p_go(a, p_limbs(), 0)
  Bool.pick(List<&2, U32>, U32.is_eq(nth(d, 32n), 1), a, List.take(&2, U32, d, 32n))

def freeze(+a: List<&2, U32>) -> List<&2, U32>:
  minus_p_once(minus_p_once(a))

# ---- the ladder ------------------------------------------------------------------

def clamp(+k: List<&2, U32>) -> List<&2, U32>:
  List.concat(&2, U32, [[U32.and(nth(k, 0n), 248)], List.take(&2, U32, List.drop(&2, U32, k, 1n), 30n), [U32.or(U32.and(nth(k, 31n), 127), 64)]])

def bit_at(+k: List<&2, U32>, +t: U32) -> U32:
  (nth(k, U32.to_nat((t / 8 : U32))) / U32.pow(2, U32.to_nat((t % 8 : U32))) % 2 : U32)

type L4 is Data:
  L4{x2: +List<U32>, z2: +List<U32>, x3: +List<U32>, z3: +List<U32>}

def cswap(+swap: U32, st: L4) -> L4:
  match st:
    case L4{+x2, +z2, +x3, +z3}:
      Bool.pick(L4, U32.is_eq(swap, 1), L4{x3, z3, x2, z2}, L4{x2, z2, x3, z3})

# One rung (RFC 7748 section 5, after the conditional swap).
def rung(st: L4, +x1: List<&2, U32>) -> L4:
  match st:
    case L4{+x2, +z2, +x3, +z3}:
      +a = add(x2, z2)
      +aa = sq(a)
      +b = sub(x2, z2)
      +bb = sq(b)
      +e = sub(aa, bb)
      +c = add(x3, z3)
      +d = sub(x3, z3)
      +da = mul(d, a)
      +cb = mul(c, b)
      L4{mul(aa, bb), mul(e, add(aa, mul_small(e, 121665))), sq(add(da, cb)), mul(x1, sq(sub(da, cb)))}

def ladder(n: Nat, +k: List<&2, U32>, +x1: List<&2, U32>, +t: U32, +swap: U32, st: L4) -> L4:
  match n:
    case 0n:
      cswap(swap, st)
    case 1n+r:
      +kt = bit_at(k, t)
      ladder(r, k, x1, (t - 1 : U32), kt, rung(cswap(U32.xor(swap, kt), st), x1))

def one() -> List<&2, U32>:
  1 <> zeros(31n)

def result(st: L4) -> List<&2, U32>:
  match st:
    case L4{x2, +z2, x3, z3}:
      freeze(mul(x2, invert(z2)))

# X25519(k, u): both 32 bytes little-endian; the top bit of u is ignored.
def x25519(+k: List<&2, U32>, +u: List<&2, U32>) -> List<&2, U32>:
  +x1 = List.append(&2, U32, List.take(&2, U32, u, 31n), [U32.and(nth(u, 31n), 127)])
  result(ladder(255n, clamp(k), x1, 254, 0, L4{one(), zeros(32n), x1, one()}))

def base_point() -> List<&2, U32>:
  9 <> zeros(31n)

def public_key(+k: List<&2, U32>) -> List<&2, U32>:
  x25519(k, base_point())

# An all-zero result means the peer sent a low-order point. RFC 7748 §6.1
# lets a protocol check it; TLS (RFC 8446 §7.4.2, RFC 8422 §5.11) MUST
# abort. The result is public at this point, so the check needs no constant
# time.
def is_all_zero(bs: List<&2, U32>) -> Bool:
  match bs:
    case Nil{}:
      True{}
    case Con{b, t}:
      U32.is_zero(b) && is_all_zero(t)

def shared_or_none(zero: Bool, +s: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match zero:
    case True{}:
      None{}
    case False{}:
      Some{s}

# The shared secret for a key exchange, or None for an all-zero one.
def shared(+k: List<&2, U32>, +u: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  +s = x25519(k, u)
  shared_or_none(is_all_zero(s), s)
