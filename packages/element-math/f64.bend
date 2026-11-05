import Base
import element-ints@0.1.0.0/signed.bend as S

# IEEE 754 binary64 in software (Bend has U32 and F32, no F64), for
# JavaScript numbers. A number is its 64 bits as two U32 (F{hi, lo}).
#
# Every operation is exact then rounded once: operands are unpacked to
# m * 2^e (m a natural, e a signed U32), the exact result is computed with
# natural numbers of any size, and `round_pack` rounds it to nearest, ties to
# even, with subnormals, infinities and signed zeros. Division keeps a sticky
# bit below the quotient, which is enough for a correct rounding. Text: the
# shortest digits that read back to the same number (ES Number::toString),
# found by trying 1..17 digits, each rounded exactly; reading a decimal is
# exact too (a big quotient and a sticky bit). Finite binary64 division uses
# two U32 words per significand/quotient; wider power/decimal operands keep
# the general natural-number path and the same single rounding boundary.

type F is Data:
  F{hi: U32, lo: U32}

type Dec is Data:
  DNaN{}
  DInf{neg: Bool}
  DZero{neg: Bool}
  DFin{neg: Bool, m: +List<U32>, e: U32}

type QR is Data:
  QR{q: +List<U32>, r: +List<U32>}

type Digits is Data:
  Digits{d: +List<U32>, k: U32}

type Lit is Data:
  Lit{d: +List<U32>, s: U32, ok: Bool}

type Ex is Data:
  Ex{v: U32, ok: Bool}

# Unpacked: value = (-1)^neg * m * 2^e.

# ---- naturals: 16-bit limbs, least significant first -------------------------------------------

def lo16(+x: U32) -> U32:
  U32.and(x, 65535)

def hi16(+x: U32) -> U32:
  U32.shrn(x, 16n)

def head0(xs: List<&2, U32>) -> U32:
  match xs:
    case Nil{}:
      0
    case Con{x, t}:
      x

def tail0(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      t

def carry_go(b: List<&2, U32>, +c: U32) -> List<&2, U32>:
  match b:
    case Nil{}:
      Bool.pick(List<&2, U32>, U32.is_zero(c), Nil{}, [c])
    case Con{x, t}:
      +s = (x + c : U32)
      lo16(s) <> carry_go(t, hi16(s))

def add_go(a: List<&2, U32>, +b: List<&2, U32>, +c: U32) -> List<&2, U32>:
  match a:
    case Nil{}:
      carry_go(b, c)
    case Con{x, t}:
      # Bound before the annotation: from Bend 2.0.21 a bare name inside
      # `( ... : U32)` is looked for in the U32 namespace first. This shape
      # compiles on every version.
      +hb = head0(b)
      +s = ((x + hb : U32) + c : U32)
      lo16(s) <> add_go(t, tail0(b), hi16(s))

def n_add(+a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  add_go(a, b, 0)

# a - b for a >= b.
def sub_go(a: List<&2, U32>, +b: List<&2, U32>, +br: U32) -> List<&2, U32>:
  match a:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      +y = (head0(b) + br : U32)
      +borrow = (x < y : U32)
      Bool.pick(U32, borrow, ((x + 65536 : U32) - y : U32), (x - y : U32)) <> sub_go(t, tail0(b), Bool.pick(U32, borrow, 1, 0))

def drop_zeros(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+x, +t}:
      Bool.pick(List<&2, U32>, U32.is_zero(x), drop_zeros(t), x <> t)

# Without zero limbs on the high side.
def norm(+xs: List<&2, U32>) -> List<&2, U32>:
  List.reverse(&2, U32, drop_zeros(List.reverse(&2, U32, xs)))

def n_sub(+a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  norm(sub_go(a, b, 0))

def is_zero(xs: List<&2, U32>) -> Bool:
  match xs:
    case Nil{}:
      True{}
    case Con{x, t}:
      U32.is_zero(x) && is_zero(t)

# 0: a < b, 1: a = b, 2: a > b.
# Compare in the stored order. A difference in the remaining (higher)
# limbs wins; missing limbs are zero. No normalization or reversed copies.
def n_cmp(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a:
    case Nil{}:
      Bool.pick(U32, is_zero(b), 1, 0)
    case Con{+x, t}:
      match b:
        case Nil{}:
          Bool.pick(U32, U32.is_zero(x) && is_zero(t), 1, 2)
        case Con{+y, u}:
          +higher = n_cmp(t, u)
          Bool.pick(U32, U32.is_eq(higher, 1), Bool.pick(U32, U32.is_eq(x, y), 1, Bool.pick(U32, (x < y : U32), 0, 2)), higher)

def n_ge(+a: List<&2, U32>, +b: List<&2, U32>) -> Bool:
  (n_cmp(a, b) >= 1 : U32)

def mul_small(b: List<&2, U32>, +x: U32, +c: U32) -> List<&2, U32>:
  match b:
    case Nil{}:
      Bool.pick(List<&2, U32>, U32.is_zero(c), Nil{}, [c])
    case Con{y, t}:
      +p = ((x * y : U32) + c : U32)
      lo16(p) <> mul_small(t, x, hi16(p))

def n_mul(a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  match a:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      n_add(mul_small(b, x, 0), 0 <> n_mul(t, b))

def zeros_then(k: Nat, +xs: List<&2, U32>) -> List<&2, U32>:
  match k:
    case 0n:
      xs
    case 1n+r:
      0 <> zeros_then(r, xs)

def shl_bits(a: List<&2, U32>, +r: U32, +c: U32) -> List<&2, U32>:
  match a:
    case Nil{}:
      Bool.pick(List<&2, U32>, U32.is_zero(c), Nil{}, [c])
    case Con{x, t}:
      +v = U32.or(U32.shln(x, U32.to_nat(r)), c)
      lo16(v) <> shl_bits(t, r, hi16(v))

# a * 2^s.
def n_shl(+a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  zeros_then(U32.to_nat((s / 16 : U32)), shl_bits(a, (s % 16 : U32), 0))

def shr_bits(a: List<&2, U32>, +r: U32) -> List<&2, U32>:
  match a:
    case Nil{}:
      Nil{}
    case Con{x, +t}:
      U32.or(U32.shrn(x, U32.to_nat(r)), lo16(U32.shln(head0(t), U32.to_nat((16 - r : U32))))) <> shr_bits(t, r)

# floor(a / 2^s).
def n_shr(+a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  norm(shr_bits(List.drop(&2, U32, a, U32.to_nat((s / 16 : U32))), (s % 16 : U32)))

# a mod 2^s.
def n_low(+a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  +whole = U32.to_nat((s / 16 : U32))
  +part = (s % 16 : U32)
  norm(List.append(&2, U32, List.take(&2, U32, a, whole),
    [U32.and(head0(List.drop(&2, U32, a, whole)), (U32.shln(1, U32.to_nat(part)) - 1 : U32))]))

def bits32(+x: U32) -> U32:
  +s16 = Bool.pick(U32, (x >= 65536 : U32), 16, 0)
  +x16 = U32.shrn(x, U32.to_nat(s16))
  +s8 = Bool.pick(U32, (x16 >= 256 : U32), 8, 0)
  +x8 = U32.shrn(x16, U32.to_nat(s8))
  +s4 = Bool.pick(U32, (x8 >= 16 : U32), 4, 0)
  +x4 = U32.shrn(x8, U32.to_nat(s4))
  +s2 = Bool.pick(U32, (x4 >= 4 : U32), 2, 0)
  +x2 = U32.shrn(x4, U32.to_nat(s2))
  (s16 + s8 + s4 + s2 + Bool.pick(U32, (x2 >= 2 : U32), 2, Bool.pick(U32, U32.is_zero(x2), 0, 1)) : U32)

def bitlen_go(a: List<&2, U32>, +offset: U32, +seen: U32) -> U32:
  match a:
    case Nil{}:
      seen
    case Con{+x, t}:
      +width = bits32(x)
      bitlen_go(t, (offset + 16 : U32), Bool.pick(U32, U32.is_zero(x), seen, (offset + width : U32)))

def bitlen(a: List<&2, U32>) -> U32:
  bitlen_go(a, 0, 0)

def odd(xs: List<&2, U32>) -> Bool:
  U32.is_eq(U32.and(head0(xs), 1), 1)

def n_of(+x: U32) -> List<&2, U32>:
  norm([lo16(x), hi16(x)])

def one() -> List<&2, U32>:
  [1]

# Long division by shift and subtract: `i` from the top bit down.
def subtract_if(fits: Bool, a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  match fits:
    case True{}:
      n_sub(a, b)
    case False{}:
      a

def div_go(k: Nat, +q: List<&2, U32>, +r: List<&2, U32>, +bs: List<&2, U32>) -> QR:
  match k:
    case 0n:
      QR{norm(q), norm(r)}
    case 1n+s:
      +fits = n_ge(r, bs)
      # Shift and append the quotient bit in one pass. Subtract only when
      # the trial divisor fits; Bool.pick would compute a discarded borrow.
      div_go(s, shl_bits(q, 1, Bool.pick(U32, fits, 1, 0)), subtract_if(fits, r, bs), n_shr(bs, 1))

def n_divmod(+a: List<&2, U32>, +b: List<&2, U32>) -> QR:
  +la = bitlen(a)
  +lb = bitlen(b)
  +span = Bool.pick(U32, (la >= lb : U32), (la - lb : U32), 0)
  div_go(U32.to_nat((span + 1 : U32)), Nil{}, norm(a), n_shl(b, span))

def pow10(k: Nat) -> List<&2, U32>:
  match k:
    case 0n:
      one()
    case 1n+r:
      mul_small(pow10(r), 10, 0)

# ---- signed exponents ----------------------------------------------------------------------------

def smax(+a: U32, +b: U32) -> U32:
  Bool.pick(U32, S.s_ge(a, b), a, b)

def smin(+a: U32, +b: U32) -> U32:
  Bool.pick(U32, S.s_le(a, b), a, b)

def spos(+a: U32) -> Bool:
  S.s_gt(a, 0)

# ---- packing ---------------------------------------------------------------------------------

def nth16(xs: List<&2, U32>, n: Nat) -> U32:
  head0(List.drop(&2, U32, xs, n))

def pack(+neg: Bool, +biased: U32, +frac: List<&2, U32>) -> F:
  F{U32.or(U32.or(Bool.pick(U32, neg, 2147483648, 0), U32.shln(biased, 20n)), U32.or(nth16(frac, 2n), U32.shln(U32.and(nth16(frac, 3n), 15), 16n))),
    U32.or(nth16(frac, 0n), U32.shln(nth16(frac, 1n), 16n))}

def inf(+neg: Bool) -> F:
  F{Bool.pick(U32, neg, 4293918720, 2146435072), 0}

def nan() -> F:
  F{2146959360, 0}

def zero(+neg: Bool) -> F:
  F{Bool.pick(U32, neg, 2147483648, 0), 0}

# m * 2^lsb with m < 2^53 (after rounding): a subnormal when m < 2^52.
def pack_rounded(+neg: Bool, +m: List<&2, U32>, +lsb: U32) -> F:
  +normal = (bitlen(m) >= 53 : U32)
  +biased = (lsb + 1075 : U32)
  Bool.pick(F, Bool.not(normal), pack(neg, 0, m),
    # pack masks the implicit leading bit, so subtracting 2^52 is redundant.
    Bool.pick(F, S.s_ge(biased, 2047), inf(neg), pack(neg, biased, m)))

# m >> s, rounded to nearest, ties to even (s > 0).
def round_shr(+m: List<&2, U32>, +s: U32) -> List<&2, U32>:
  +q = n_shr(m, s)
  +c = n_cmp(n_low(m, s), n_shl(one(), (s - 1 : U32)))
  Bool.pick(List<&2, U32>, U32.is_eq(c, 2) || (U32.is_eq(c, 1) && odd(q)), n_add(q, one()), q)

def shift_to(right: Bool, +m: List<&2, U32>, +sh: U32) -> List<&2, U32>:
  match right:
    case True{}:
      round_shr(m, sh)
    case False{}:
      n_shl(m, (0 - sh : U32))

def carry_fix(over: Bool, +neg: Bool, +q: List<&2, U32>, +lsb: U32) -> F:
  match over:
    case True{}:
      pack_rounded(neg, n_shr(q, 1), (lsb + 1 : U32))
    case False{}:
      pack_rounded(neg, q, lsb)

# The nearest binary64 to (-1)^neg * m * 2^e, m > 0.
def round_pack(+neg: Bool, +m: List<&2, U32>, +e: U32) -> F:
  +b = bitlen(m)
  +lsb = smax(((e + b : U32) - 53 : U32), 4294966222)
  +sh = (lsb - e : U32)
  +q = shift_to(spos(sh), m, sh)
  carry_fix(U32.is_eq(bitlen(q), 54), neg, q, lsb)

def pack_zero(z: Bool, +neg: Bool, +m: List<&2, U32>, +e: U32) -> F:
  match z:
    case True{}:
      zero(neg)
    case False{}:
      round_pack(neg, m, e)

def exact(+neg: Bool, +m: List<&2, U32>, +e: U32) -> F:
  pack_zero(is_zero(m), neg, m, e)

# ---- unpacking -------------------------------------------------------------------------------

def frac_of(+hi: U32, +lo: U32) -> List<&2, U32>:
  [lo16(lo), hi16(lo), lo16(hi), U32.and(hi16(hi), 15)]

def dec_finite(normal: Bool, +neg: Bool, +hi: U32, +lo: U32, biased: U32) -> Dec:
  match normal:
    case True{}:
      # The hidden bit makes the fourth limb nonzero: already normalized.
      DFin{neg, [lo16(lo), hi16(lo), lo16(hi), U32.or(U32.and(hi16(hi), 15), 16)], (biased - 1075 : U32)}
    case False{}:
      +fr = norm(frac_of(hi, lo))
      Bool.pick(Dec, is_zero(fr), DZero{neg}, DFin{neg, fr, 4294966222})

def dec_kind(special: Bool, +neg: Bool, +hi: U32, +lo: U32, +biased: U32) -> Dec:
  match special:
    case True{}:
      Bool.pick(Dec, U32.is_zero(U32.or(U32.and(hi, 1048575), lo)), DInf{neg}, DNaN{})
    case False{}:
      dec_finite(Bool.not(U32.is_zero(biased)), neg, hi, lo, biased)

def dec(f: F) -> Dec:
  match f:
    case F{+hi, +lo}:
      +neg = (hi >= 2147483648 : U32)
      +biased = U32.and(U32.shrn(hi, 20n), 2047)
      dec_kind(U32.is_eq(biased, 2047), neg, hi, lo, biased)

def negate(f: F) -> F:
  match f:
    case F{hi, lo}:
      F{U32.xor(hi, 2147483648), lo}

# ---- arithmetic --------------------------------------------------------------------------------

def is_nan(f: F) -> Bool:
  match f:
    case F{+hi, lo}:
      (U32.and(hi, 2147483647) > 2146435072 : U32) || (U32.is_eq(U32.and(hi, 2147483647), 2146435072) && Bool.not(U32.is_zero(lo)))

def diff_go(c: Nat, +na: Bool, +nb: Bool, +a: List<&2, U32>, +b: List<&2, U32>, +e: U32) -> F:
  match c:
    case 0n:
      round_pack(nb, n_sub(b, a), e)
    case 1n:
      zero(False{})
    case 2n+r:
      round_pack(na, n_sub(a, b), e)

def diff(+c: U32, +na: Bool, +nb: Bool, +a: List<&2, U32>, +b: List<&2, U32>, +e: U32) -> F:
  diff_go(U32.to_nat(c), na, nb, a, b, e)

def add_signs(same: Bool, +na: Bool, +nb: Bool, +a: List<&2, U32>, +b: List<&2, U32>, +e: U32) -> F:
  match same:
    case True{}:
      round_pack(na, n_add(a, b), e)
    case False{}:
      diff(n_cmp(a, b), na, nb, a, b, e)

# Both finite: x + y exactly, then rounded.
def add_fin(+na: Bool, +ma: List<&2, U32>, +ea: U32, +nb: Bool, +mb: List<&2, U32>, +eb: U32) -> F:
  +e = smin(ea, eb)
  +a = n_shl(ma, (ea - e : U32))
  +b = n_shl(mb, (eb - e : U32))
  add_signs(Bool.pick(Bool, na, nb, Bool.not(nb)), na, nb, a, b, e)

def add_dec(x: Dec, y: Dec, +fx: F, +fy: F) -> F:
  match x:
    case DNaN{}:
      nan()
    case DInf{nx}:
      match y:
        case DNaN{}:
          nan()
        case DInf{+ny}:
          Bool.pick(F, Bool.pick(Bool, nx, ny, Bool.not(ny)), fx, nan())
        case DZero{ny}:
          fx
        case DFin{ny, my, ey}:
          fx
    case DZero{nx}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          fy
        case DZero{ny}:
          zero(nx && ny)
        case DFin{ny, my, ey}:
          fy
    case DFin{+nx, +mx, +ex}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          fy
        case DZero{ny}:
          fx
        case DFin{ny, my, ey}:
          add_fin(nx, mx, ex, ny, my, ey)

def add(+a: F, +b: F) -> F:
  add_dec(dec(a), dec(b), a, b)

def sub(+a: F, +b: F) -> F:
  add(a, negate(b))

def xor_b(+a: Bool, +b: Bool) -> Bool:
  Bool.pick(Bool, a, Bool.not(b), b)

# Exact 53x53-bit significand product, least-significant 16-bit limb first.
# Called only from mul_dec(dec(a), dec(b)); the top input limbs are <=31.
# Each partial product fits U32 and each split column sum is <2^19.
# Preserve all 106 bits for the existing round_pack; general n_mul stays
# available to wide power/decimal arithmetic. No intermediate row lists.
def mul53_words(+a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  +a0 = nth16(a, 0n)
  +b0 = nth16(b, 0n)
  +a1 = nth16(a, 1n)
  +b1 = nth16(b, 1n)
  +a2 = nth16(a, 2n)
  +b2 = nth16(b, 2n)
  +a3 = nth16(a, 3n)
  +b3 = nth16(b, 3n)
  +p00 = (a0 * b0 : U32)
  +p01 = (a0 * b1 : U32)
  +p02 = (a0 * b2 : U32)
  +p03 = (a0 * b3 : U32)
  +p10 = (a1 * b0 : U32)
  +p11 = (a1 * b1 : U32)
  +p12 = (a1 * b2 : U32)
  +p13 = (a1 * b3 : U32)
  +p20 = (a2 * b0 : U32)
  +p21 = (a2 * b1 : U32)
  +p22 = (a2 * b2 : U32)
  +p23 = (a2 * b3 : U32)
  +p30 = (a3 * b0 : U32)
  +p31 = (a3 * b1 : U32)
  +p32 = (a3 * b2 : U32)
  +p33 = (a3 * b3 : U32)
  +c0_0 = lo16(p00)
  +c0 = (c0_0 : U32)
  +c1_0 = hi16(c0)
  +c1_1 = hi16(p00)
  +c1_2 = lo16(p01)
  +c1_3 = lo16(p10)
  +c1 = (c1_0 + c1_1 + c1_2 + c1_3 : U32)
  +c2_0 = hi16(c1)
  +c2_1 = hi16(p01)
  +c2_2 = lo16(p02)
  +c2_3 = hi16(p10)
  +c2_4 = lo16(p11)
  +c2_5 = lo16(p20)
  +c2 = (c2_0 + c2_1 + c2_2 + c2_3 + c2_4 + c2_5 : U32)
  +c3_0 = hi16(c2)
  +c3_1 = hi16(p02)
  +c3_2 = lo16(p03)
  +c3_3 = hi16(p11)
  +c3_4 = lo16(p12)
  +c3_5 = hi16(p20)
  +c3_6 = lo16(p21)
  +c3_7 = lo16(p30)
  +c3 = (c3_0 + c3_1 + c3_2 + c3_3 + c3_4 + c3_5 + c3_6 + c3_7 : U32)
  +c4_0 = hi16(c3)
  +c4_1 = hi16(p03)
  +c4_2 = hi16(p12)
  +c4_3 = lo16(p13)
  +c4_4 = hi16(p21)
  +c4_5 = lo16(p22)
  +c4_6 = hi16(p30)
  +c4_7 = lo16(p31)
  +c4 = (c4_0 + c4_1 + c4_2 + c4_3 + c4_4 + c4_5 + c4_6 + c4_7 : U32)
  +c5_0 = hi16(c4)
  +c5_1 = hi16(p13)
  +c5_2 = hi16(p22)
  +c5_3 = lo16(p23)
  +c5_4 = hi16(p31)
  +c5_5 = lo16(p32)
  +c5 = (c5_0 + c5_1 + c5_2 + c5_3 + c5_4 + c5_5 : U32)
  +c6_0 = hi16(c5)
  +c6_1 = hi16(p23)
  +c6_2 = hi16(p32)
  +c6_3 = lo16(p33)
  +c6 = (c6_0 + c6_1 + c6_2 + c6_3 : U32)
  [lo16(c0), lo16(c1), lo16(c2), lo16(c3), lo16(c4), lo16(c5), lo16(c6)]

def mul_dec(x: Dec, y: Dec) -> F:
  match x:
    case DNaN{}:
      nan()
    case DInf{nx}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          inf(xor_b(nx, ny))
        case DZero{ny}:
          nan()
        case DFin{ny, my, ey}:
          inf(xor_b(nx, ny))
    case DZero{nx}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          nan()
        case DZero{ny}:
          zero(xor_b(nx, ny))
        case DFin{ny, my, ey}:
          zero(xor_b(nx, ny))
    case DFin{+nx, +mx, +ex}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          inf(xor_b(nx, ny))
        case DZero{ny}:
          zero(xor_b(nx, ny))
        case DFin{ny, my, ey}:
          round_pack(xor_b(nx, ny), mul53_words(mx, my), (ex + ey : U32))

def mul(+a: F, +b: F) -> F:
  mul_dec(dec(a), dec(b))

def div_qr(qr: QR, +neg: Bool, +e: U32) -> F:
  match qr:
    case QR{q, r}:
      round_pack(neg, n_add(n_shl(q, 1), Bool.pick(List<&2, U32>, is_zero(r), Nil{}, one())), e)

# A bounded, allocation-free quotient loop for binary64 significands.
# Normalize both operands to 53 bits. Then a/b is in [1/2, 2), so 57
# restoring steps yield floor(a * 2^56 / b). Each remainder is < 2*b < 2^54;
# quotient and remainder therefore fit two U32 words without lost bits.
# The final remainder is doubled, which preserves the only fact rounding needs:
# whether any discarded bit is nonzero. Keep div_qr/round_pack unchanged.
type Q53 is Data:
  Q53{hi: U32, lo: U32, sticky: Bool}

def div53_loop(n: Nat, +qh: U32, +ql: U32, +rh: U32, +rl: U32, +bh: U32, +bl: U32) -> Q53:
  match n:
    case 0n:
      Q53{qh, ql, Bool.not(U32.is_zero(U32.or(rh, rl)))}
    case 1n+rest:
      +fits = (rh > bh : U32) || (U32.is_eq(rh, bh) && (rl >= bl : U32))
      +borrow = Bool.pick(U32, (rl < bl : U32), 1, 0)
      +sh = Bool.pick(U32, fits, ((rh - bh : U32) - borrow : U32), rh)
      +sl = Bool.pick(U32, fits, (rl - bl : U32), rl)
      +bit = Bool.pick(U32, fits, 1, 0)
      div53_loop(rest,
        U32.or(U32.shln(qh, 1n), U32.shrn(ql, 31n)), U32.or(U32.shln(ql, 1n), bit),
        U32.or(U32.shln(sh, 1n), U32.shrn(sl, 31n)), U32.shln(sl, 1n), bh, bl)

def div53_words(+a: List<&2, U32>, +b: List<&2, U32>) -> Q53:
  div53_loop(57n, 0, 0,
    U32.or(nth16(a, 2n), U32.shln(nth16(a, 3n), 16n)),
    U32.or(nth16(a, 0n), U32.shln(nth16(a, 1n), 16n)),
    U32.or(nth16(b, 2n), U32.shln(nth16(b, 3n), 16n)),
    U32.or(nth16(b, 0n), U32.shln(nth16(b, 1n), 16n)))

def div53_finish(q: Q53, +neg: Bool, +e: U32) -> F:
  match q:
    case Q53{+hi, +lo, sticky}:
      div_qr(QR{norm([lo16(lo), hi16(lo), lo16(hi), hi16(hi)]),
        Bool.pick(List<&2, U32>, sticky, [1], Nil{})}, neg, e)

def div_widths(small: Bool, +neg: Bool, +ma: List<&2, U32>, +mb: List<&2, U32>, +la: U32, +lb: U32, +k: U32, +e: U32) -> F:
  match small:
    case True{}:
      div53_finish(div53_words(n_shl(ma, (53 - la : U32)), n_shl(mb, (53 - lb : U32))), neg, e)
    case False{}:
      # pow_fin can pass a denominator much wider than a binary64 mantissa.
      # Decimal conversion also retains its independent general division path.
      div_qr(n_divmod(n_shl(ma, k), mb), neg, e)

# m_a / m_b with a quotient of 56 bits or more and a sticky bit below it.
def div_fin(+neg: Bool, +ma: List<&2, U32>, +ea: U32, +mb: List<&2, U32>, +eb: U32) -> F:
  +la = bitlen(ma)
  +lb = bitlen(mb)
  +k = smax(((56 + lb : U32) - la : U32), 0)
  +small = (la > 0 : U32) && (la <= 53 : U32) && (lb > 0 : U32) && (lb <= 53 : U32)
  div_widths(small, neg, ma, mb, la, lb, k, ((ea - eb : U32) - (k + 1 : U32) : U32))

def div_dec(x: Dec, y: Dec) -> F:
  match x:
    case DNaN{}:
      nan()
    case DInf{nx}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          nan()
        case DZero{ny}:
          inf(xor_b(nx, ny))
        case DFin{ny, my, ey}:
          inf(xor_b(nx, ny))
    case DZero{nx}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          zero(xor_b(nx, ny))
        case DZero{ny}:
          nan()
        case DFin{ny, my, ey}:
          zero(xor_b(nx, ny))
    case DFin{+nx, +mx, +ex}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          zero(xor_b(nx, ny))
        case DZero{ny}:
          inf(xor_b(nx, ny))
        case DFin{ny, my, ey}:
          div_fin(xor_b(nx, ny), mx, ex, my, ey)

def div(+a: F, +b: F) -> F:
  div_dec(dec(a), dec(b))

def rem_qr(qr: QR, +neg: Bool, +e: U32) -> F:
  match qr:
    case QR{q, r}:
      exact(neg, r, e)

# JavaScript %: the remainder of truncated division, exact, with a's sign.
def rem_fin(+na: Bool, +ma: List<&2, U32>, +ea: U32, +mb: List<&2, U32>, +eb: U32) -> F:
  +e = smin(ea, eb)
  rem_qr(n_divmod(n_shl(ma, (ea - e : U32)), n_shl(mb, (eb - e : U32))), na, e)

def rem_dec(x: Dec, y: Dec, +fx: F) -> F:
  match x:
    case DNaN{}:
      nan()
    case DInf{nx}:
      nan()
    case DZero{nx}:
      match y:
        case DNaN{}:
          nan()
        case DZero{ny}:
          nan()
        case DInf{ny}:
          fx
        case DFin{ny, my, ey}:
          fx
    case DFin{+nx, +mx, +ex}:
      match y:
        case DNaN{}:
          nan()
        case DInf{ny}:
          fx
        case DZero{ny}:
          nan()
        case DFin{ny, my, ey}:
          rem_fin(nx, mx, ex, my, ey)

def rem(+a: F, +b: F) -> F:
  rem_dec(dec(a), dec(b), a)

# ---- powers --------------------------------------------------------------------------------------

def n_pow(k: Nat, +m: List<&2, U32>, +acc: List<&2, U32>) -> List<&2, U32>:
  match k:
    case 0n:
      acc
    case 1n+r:
      n_pow(r, m, n_mul(acc, m))

# x ** n for an integer n, exact then rounded once: (m 2^e)^n = m^n 2^(e n);
# a negative n is 1 / x^|n| (a quotient with a sticky bit). |n| is capped
# at 2100 (beyond it every finite x != 1 over- or underflows anyway).
def pow_fin(+neg: Bool, +m: List<&2, U32>, +e: U32, +n: U32) -> F:
  +an = Bool.pick(U32, S.is_neg(n), (0 - n : U32), n)
  +k = U32.min(an, 2100)
  +mn = n_pow(U32.to_nat(k), m, one())
  +sign = neg && U32.is_eq(U32.and(an, 1), 1)
  Bool.pick(F, S.is_neg(n), div_fin(sign, one(), 0, mn, (e * k : U32)), round_pack(sign, mn, (e * k : U32)))

# ---- integers ------------------------------------------------------------------------------------

def from_i32(+n: U32) -> F:
  exact(S.is_neg(n), n_of(Bool.pick(U32, S.is_neg(n), (0 - n : U32), n)), 0)

# x ** n for an int32 n. n = 0 is 1 whatever x is, NaN too (ES 6.1.6.1.3,
# step 1: NaN ** 0 was NaN, m4c-pow-special).
def pow_dec(d: Dec, +f: F, +n: U32) -> F:
  match d:
    case DNaN{}:
      Bool.pick(F, U32.is_zero(n), from_i32(1), nan())
    case DZero{+neg}:
      Bool.pick(F, U32.is_zero(n), from_i32(1), Bool.pick(F, S.is_neg(n), inf(neg && U32.is_eq(U32.and(n, 1), 1)), zero(neg && U32.is_eq(U32.and(n, 1), 1))))
    case DInf{+neg}:
      Bool.pick(F, U32.is_zero(n), from_i32(1), Bool.pick(F, S.is_neg(n), zero(neg && U32.is_eq(U32.and(n, 1), 1)), inf(neg && U32.is_eq(U32.and(n, 1), 1))))
    case DFin{+neg, +m, +e}:
      Bool.pick(F, U32.is_zero(n), from_i32(1), pow_fin(neg, m, e, n))

def pow_int(+f: F, +n: U32) -> F:
  pow_dec(dec(f), f, n)

# ---- square root ------------------------------------------------------------------------------

# floor(sqrt(a)) by the digit-by-digit method, two bits at a time from the
# top; the remainder says whether it was exact.
def isqrt_go(k: Nat, +a: List<&2, U32>, +r: List<&2, U32>, +rem: List<&2, U32>, +shift: U32) -> QR:
  match k:
    case 0n:
      QR{norm(r), norm(rem)}
    case 1n+s:
      +rem2 = n_add(n_shl(rem, 2), n_low(n_shr(a, shift), 2))
      +trial = n_add(n_shl(r, 2), one())
      +fits = n_ge(rem2, trial)
      isqrt_go(s, a, n_add(n_shl(r, 1), Bool.pick(List<&2, U32>, fits, one(), Nil{})), Bool.pick(List<&2, U32>, fits, n_sub(rem2, trial), rem2), (shift - 2 : U32))

def isqrt(+a: List<&2, U32>) -> QR:
  +pairs = ((bitlen(a) + 1 : U32) / 2 : U32)
  isqrt_go(U32.to_nat(pairs), a, Nil{}, Nil{}, ((pairs * 2 : U32) - 2 : U32))

def S_half(+e: U32) -> U32:
  Bool.pick(U32, S.is_neg(e), (0 - ((0 - e : U32) / 2 : U32) : U32), (e / 2 : U32))

def sqrt_qr(qr: QR, +e: U32) -> F:
  match qr:
    case QR{q, r}:
      round_pack(False{}, n_add(n_shl(q, 1), Bool.pick(List<&2, U32>, is_zero(r), Nil{}, one())), e)

# sqrt(m 2^e): e made even, m widened to 112 bits or more, the integer root
# taken with a sticky bit from its remainder, then rounded once.
def sqrt_fin(+m: List<&2, U32>, +e: U32) -> F:
  +odd_e = U32.is_eq(U32.and(e, 1), 1)
  +m1 = Bool.pick(List<&2, U32>, odd_e, n_shl(m, 1), m)
  +e1 = Bool.pick(U32, odd_e, (e - 1 : U32), e)
  +w = smax(((112 - bitlen(m1) : U32) + 1 : U32), 0)
  +w2 = (w + U32.and(w, 1) : U32)
  +qr = isqrt(n_shl(m1, w2))
  sqrt_qr(qr, (S_half((e1 - w2 : U32)) - 1 : U32))

def sqrt_dec(d: Dec, +f: F) -> F:
  match d:
    case DNaN{}:
      nan()
    case DZero{neg}:
      f
    case DInf{neg}:
      Bool.pick(F, neg, nan(), f)
    case DFin{+neg, +m, +e}:
      Bool.pick(F, neg, nan(), sqrt_fin(m, e))

# Math.sqrt, correctly rounded.
def sqrt(+f: F) -> F:
  sqrt_dec(dec(f), f)

# ---- comparison ----------------------------------------------------------------------------------

# 0: a < b, 1: a = b, 2: a > b, 3: unordered (a NaN). -0 equals +0.
def mag_cmp(+ma: List<&2, U32>, +ea: U32, +mb: List<&2, U32>, +eb: U32) -> U32:
  +e = smin(ea, eb)
  n_cmp(n_shl(ma, (ea - e : U32)), n_shl(mb, (eb - e : U32)))

def flip(+c: U32) -> U32:
  (2 - c : U32)

def signed_cmp(+neg: Bool, +c: U32) -> U32:
  Bool.pick(U32, neg, flip(c), c)

def fin_cmp(same: Bool, +nx: Bool, +mx: List<&2, U32>, +ex: U32, +my: List<&2, U32>, +ey: U32) -> U32:
  match same:
    case True{}:
      signed_cmp(nx, mag_cmp(mx, ex, my, ey))
    case False{}:
      Bool.pick(U32, nx, 0, 2)

def cmp_dec(x: Dec, y: Dec) -> U32:
  match x:
    case DNaN{}:
      3
    case DInf{+nx}:
      match y:
        case DNaN{}:
          3
        case DInf{+ny}:
          Bool.pick(U32, Bool.pick(Bool, nx, ny, Bool.not(ny)), 1, Bool.pick(U32, nx, 0, 2))
        case DZero{ny}:
          Bool.pick(U32, nx, 0, 2)
        case DFin{ny, my, ey}:
          Bool.pick(U32, nx, 0, 2)
    case DZero{nx}:
      match y:
        case DNaN{}:
          3
        case DInf{ny}:
          Bool.pick(U32, ny, 2, 0)
        case DZero{ny}:
          1
        case DFin{ny, my, ey}:
          Bool.pick(U32, ny, 2, 0)
    case DFin{+nx, mx, ex}:
      match y:
        case DNaN{}:
          3
        case DInf{ny}:
          Bool.pick(U32, ny, 2, 0)
        case DZero{ny}:
          Bool.pick(U32, nx, 0, 2)
        case DFin{+ny, my, ey}:
          fin_cmp(Bool.pick(Bool, nx, ny, Bool.not(ny)), nx, mx, ex, my, ey)

def cmp(+a: F, +b: F) -> U32:
  cmp_dec(dec(a), dec(b))

def from_u32(+n: U32) -> F:
  exact(False{}, n_of(n), 0)

def limbs32(+xs: List<&2, U32>) -> U32:
  U32.or(head0(xs), U32.shln(head0(tail0(xs)), 16n))

# The integer part toward zero, modulo 2^32 (ES ToInt32 / ToUint32 before
# the sign is read).
# m * 2^e toward zero (a right shift for e < 0, a left shift otherwise),
# with the left shift stopped at 64 bits (only the low 32 are read).
def whole_part(neg_e: Bool, +m: List<&2, U32>, +e: U32) -> List<&2, U32>:
  match neg_e:
    case True{}:
      n_shr(m, (0 - e : U32))
    case False{}:
      n_shl(m, U32.min(e, 64))

def int_bits(d: Dec) -> U32:
  match d:
    case DNaN{}:
      0
    case DInf{n}:
      0
    case DZero{n}:
      0
    case DFin{+neg, +m, +e}:
      +mag = limbs32(n_low(whole_part(S.is_neg(e), m, e), 32))
      Bool.pick(U32, neg, (0 - mag : U32), mag)

def to_int32(+f: F) -> U32:
  int_bits(dec(f))

# The value as an exact int32, when it is one (-0 is not: 1/-0 is -Infinity).
def frac_zero(neg_e: Bool, +m: List<&2, U32>, +e: U32) -> Bool:
  match neg_e:
    case True{}:
      is_zero(n_low(m, (0 - e : U32)))
    case False{}:
      True{}

def exact_i32(d: Dec) -> Maybe<&2, U32>:
  match d:
    case DZero{neg}:
      Bool.pick(Maybe<&2, U32>, neg, None{}, Some{0})
    case DNaN{}:
      None{}
    case DInf{n}:
      None{}
    case DFin{+neg, +m, +e}:
      +v = whole_part(S.is_neg(e), m, e)
      +fits = frac_zero(S.is_neg(e), m, e) && S.s_lt(e, 32) && Bool.pick(Bool, neg, Bool.not(n_ge(v, n_of(2147483649))), Bool.not(n_ge(v, n_of(2147483648))))
      Bool.pick(Maybe<&2, U32>, fits, Some{Bool.pick(U32, neg, (0 - limbs32(v) : U32), limbs32(v))}, None{})

def as_i32(+f: F) -> Maybe<&2, U32>:
  exact_i32(dec(f))

# ---- decimal text ----------------------------------------------------------------------------------

# floor(t * log10(2)) for |t| < 4096 (78913 / 2^18 ~ 0.30103).
def log10_2(+t: U32) -> U32:
  Bool.pick(U32, S.is_neg(t), (0 - U32.shrn(((((0 - t : U32) * 78913 : U32) + 262143 : U32)), 18n) : U32), U32.shrn((t * 78913 : U32), 18n))

def round_div(qr: QR, +den: List<&2, U32>) -> List<&2, U32>:
  match qr:
    case QR{+q, r}:
      +c = n_cmp(n_shl(r, 1), den)
      Bool.pick(List<&2, U32>, U32.is_eq(c, 2) || (U32.is_eq(c, 1) && odd(q)), n_add(q, one()), q)

# m * 2^e / 10^s, rounded to nearest (ties to even).
def scaled(+m: List<&2, U32>, +e: U32, +s: U32) -> List<&2, U32>:
  +num = n_mul(n_shl(m, smax(e, 0)), pow10(U32.to_nat(smax((0 - s : U32), 0))))
  +den = n_mul(n_shl(one(), smax((0 - e : U32), 0)), pow10(U32.to_nat(smax(s, 0))))
  round_div(n_divmod(num, den), den)

# Digits of a natural, most significant first.
def q_of(qr: QR) -> List<&2, U32>:
  match qr:
    case QR{q, r}:
      q

def r_of(qr: QR) -> List<&2, U32>:
  match qr:
    case QR{q, r}:
      r

# Decimal digits of x, most significant first; `stop` says x is zero.
def digits_go(k: Nat, +x: List<&2, U32>, stop: Bool, +acc: List<&2, Char>) -> List<&2, Char>:
  match k:
    case 0n:
      acc
    case 1n+r:
      match stop:
        case True{}:
          acc
        case False{}:
          +qr = n_divmod(x, [10])
          digits_go(r, q_of(qr), is_zero(q_of(qr)), Char.from_u32((48 + head0(r_of(qr)) : U32)) <> acc)

def n_text(+x: List<&2, U32>) -> String:
  Bool.pick(String, is_zero(x), "0", String.from_list(digits_go(400n, x, is_zero(x), Nil{})))

# p significant digits of m * 2^e and the decimal exponent of the first:
# the estimate k is corrected when the digits come out one too many or few.

# 0: d has p digits; 1: one too many (k too small); 2: too few.
def fit_code(+d: List<&2, U32>, +p: U32) -> Nat:
  Bool.pick(Nat, n_ge(d, pow10(U32.to_nat(p))), 1n, Bool.pick(Nat, n_ge(d, pow10(U32.to_nat((p - 1 : U32)))), 0n, 2n))

def digits_try(fuel: Nat, code: Nat, +m: List<&2, U32>, +e: U32, +p: U32, +k: U32, +d: List<&2, U32>) -> Digits:
  match fuel:
    case 0n:
      Digits{d, k}
    case 1n+f:
      match code:
        case 0n:
          Digits{d, k}
        case 1n:
          +d2 = scaled(m, e, (((k + 1 : U32) - p : U32) + 1 : U32))
          digits_try(f, fit_code(d2, p), m, e, p, (k + 1 : U32), d2)
        case 2n+r:
          +d3 = scaled(m, e, (((k - 1 : U32) - p : U32) + 1 : U32))
          digits_try(f, fit_code(d3, p), m, e, p, (k - 1 : U32), d3)

def digits_at(+m: List<&2, U32>, +e: U32, +p: U32, +k: U32) -> Digits:
  +d = scaled(m, e, ((k - p : U32) + 1 : U32))
  digits_try(3n, fit_code(d, p), m, e, p, k, d)

def from_dec_go(frac: Bool, +d: List<&2, U32>, +s: U32) -> F:
  match frac:
    case False{}:
      exact(False{}, n_mul(d, pow10(U32.to_nat(s))), 0)
    case True{}:
      +den = pow10(U32.to_nat((0 - s : U32)))
      +k = smax(((56 + bitlen(den) : U32) - bitlen(d) : U32), 0)
      div_qr(n_divmod(n_shl(d, k), den), False{}, (0 - (k + 1 : U32) : U32))

def from_dec(+d: List<&2, U32>, +s: U32) -> F:
  from_dec_go(S.is_neg(s), d, s)

def same_bits(a: F, b: F) -> Bool:
  match a:
    case F{ah, al}:
      match b:
        case F{bh, bl}:
          U32.is_eq(ah, bh) && U32.is_eq(al, bl)

# The fewest digits (1..17) that read back to |f|.
def k_of(+m: List<&2, U32>, +e: U32) -> U32:
  log10_2(((bitlen(m) - 1 : U32) + e : U32))

def digits_back(dg: Digits, +p: U32, +target: F) -> Bool:
  match dg:
    case Digits{d, k}:
      same_bits(from_dec(d, ((k - p : U32) + 1 : U32)), target)

# The fewest digits (1..17) that read back to |f|: `dg` holds p digits and
# `ok` whether they read back.
def shortest(fuel: Nat, ok: Bool, +dg: Digits, +m: List<&2, U32>, +e: U32, +p: U32, +target: F) -> Digits:
  match fuel:
    case 0n:
      dg
    case 1n+f:
      match ok:
        case True{}:
          dg
        case False{}:
          +dg2 = digits_at(m, e, (p + 1 : U32), k_of(m, e))
          shortest(f, digits_back(dg2, (p + 1 : U32), target), dg2, m, e, (p + 1 : U32), target)

def zeros_text(k: Nat) -> String:
  String.repeat("0", k)

def drop_c0(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, +t}:
      Bool.pick(String, U32.is_eq(Char.to_u32(c), 48), drop_c0(t), SCon{c, t})

def strip0(s: String) -> String:
  String.reverse(drop_c0(String.reverse(s)))

def layout_go(code: Nat, +ds: String, +n: U32, +p: U32) -> String:
  match code:
    case 0n:
      ds ++ zeros_text(U32.to_nat((n - p : U32)))
    case 1n:
      String.take(ds, U32.to_nat(n)) ++ "." ++ String.drop(ds, U32.to_nat(n))
    case 2n:
      "0." ++ zeros_text(U32.to_nat((0 - n : U32))) ++ ds
    case 3n+r:
      Bool.pick(String, U32.is_eq(p, 1), ds, String.take(ds, 1n) ++ "." ++ String.drop(ds, 1n)) ++ "e" ++
        Bool.pick(String, S.is_neg((n - 1 : U32)), "-", "+") ++ S.show_i(Bool.pick(U32, S.is_neg((n - 1 : U32)), (1 - n : U32), (n - 1 : U32)))

# ES 9.8.1 Number::toString with digits `ds` and n = k + 1.
def layout(+ds: String, +n: U32) -> String:
  +p = U32.from_nat(String.length(ds))
  layout_go(Bool.pick(Nat, S.s_le(p, n) && S.s_le(n, 21), 0n, Bool.pick(Nat, S.s_gt(n, 0) && S.s_le(n, 21), 1n,
    Bool.pick(Nat, S.s_gt(n, 4294967290) && S.s_le(n, 0), 2n, 3n))), ds, n, p)

def digits_text(dg: Digits) -> String:
  match dg:
    case Digits{d, k}:
      layout(strip0(n_text(d)), (k + 1 : U32))

def abs(f: F) -> F:
  match f:
    case F{hi, lo}:
      F{U32.and(hi, 2147483647), lo}

def f_hi(f: F) -> U32:
  match f:
    case F{hi, lo}:
      hi

def f_lo(f: F) -> U32:
  match f:
    case F{hi, lo}:
      lo

def show_dec(d: Dec, +f: F) -> String:
  match d:
    case DNaN{}:
      "NaN"
    case DInf{neg}:
      Bool.pick(String, neg, "-Infinity", "Infinity")
    case DZero{neg}:
      "0"
    case DFin{+neg, +m, +e}:
      +t = abs(f)
      +dg = digits_at(m, e, 1, k_of(m, e))
      Bool.pick(String, neg, "-", "") ++ digits_text(shortest(17n, digits_back(dg, 1, t), dg, m, e, 1, t))

def show(+f: F) -> String:
  show_dec(dec(f), f)

# As show, but -0 is "-0" (CDP's unserializableValue).
def show_signed(+f: F) -> String:
  Bool.pick(String, U32.is_eq(cmp(f, zero(False{})), 1) && (f_hi(f) >= 2147483648 : U32), "-0", show(f))

# ---- reading numbers ---------------------------------------------------------------------------------

# A decimal literal's parts: its significant digits as a natural and the
# power of ten they are scaled by.

def dig(+c: Char) -> U32:
  (Char.to_u32(c) - 48 : U32)

# Integer digits, then fraction digits (each lowers the exponent), then the
# exponent part.
# 0 digit, 1 point, 2 exponent mark, 3 anything else.
def lit_class(+c: Char, +frac: Bool, +any: Bool) -> Nat:
  Bool.pick(Nat, Char.is_digit(c), 0n, Bool.pick(Nat, U32.is_eq(Char.to_u32(c), 46) && Bool.not(frac), 1n,
    Bool.pick(Nat, (U32.is_eq(Char.to_u32(c), 101) || U32.is_eq(Char.to_u32(c), 69)) && any, 2n, 3n)))

def exp_digits(s: String, +acc: U32, +any: Bool) -> Ex:
  match s:
    case SNil{}:
      Ex{acc, any}
    case SCon{+c, t}:
      Bool.pick(Ex, Char.is_digit(c), exp_digits(t, U32.min(((acc * 10 : U32) + dig(c) : U32), 100000), True{}), Ex{acc, False{}})

def neg_ex(x: Ex, +minus: Bool) -> Ex:
  match x:
    case Ex{+v, ok}:
      Ex{Bool.pick(U32, minus, (0 - v : U32), v), ok}

def read_exp(+s: String) -> Ex:
  +minus = String.starts_with(s, "-")
  +body = Bool.pick(String, minus || String.starts_with(s, "+"), String.drop(s, 1n), s)
  neg_ex(exp_digits(body, 0, False{}), minus)

def with_exp(x: Ex, +acc: List<&2, U32>, +sc: U32) -> Lit:
  match x:
    case Ex{v, ok}:
      Lit{acc, (sc + v : U32), ok}

def head_class(s: String, +frac: Bool, +any: Bool) -> Nat:
  match s:
    case SNil{}:
      3n
    case SCon{c, t}:
      lit_class(c, frac, any)

# `code` is the class of s's first character (lit_class).
def read_int(s: String, code: Nat, +acc: List<&2, U32>, +sc: U32, +frac: Bool, +any: Bool) -> Lit:
  match s:
    case SNil{}:
      Lit{acc, sc, any}
    case SCon{+c, +t}:
      match code:
        case 0n:
          read_int(t, head_class(t, frac, True{}), mul_small(acc, 10, dig(c)), Bool.pick(U32, frac, (sc - 1 : U32), sc), frac, True{})
        case 1n:
          read_int(t, head_class(t, True{}, any), acc, sc, True{}, any)
        case 2n:
          with_exp(read_exp(t), acc, sc)
        case 3n+r:
          Lit{acc, sc, False{}}

def hex_val(+c: Char) -> U32:
  +k = Char.to_u32(c)
  Bool.pick(U32, Char.is_digit(c), (k - 48 : U32), Bool.pick(U32, (k >= 97 : U32) && (k <= 102 : U32), (k - 87 : U32),
    Bool.pick(U32, (k >= 65 : U32) && (k <= 70 : U32), (k - 55 : U32), 99)))

# The digits of an integer in `base` (16 for 0x, 8 for 0o, 2 for 0b).
def read_hex(s: String, +base: U32, +acc: List<&2, U32>, +any: Bool) -> Lit:
  match s:
    case SNil{}:
      Lit{acc, 0, any}
    case SCon{+c, t}:
      Bool.pick(Lit, (hex_val(c) < base : U32), read_hex(t, base, mul_small(acc, base, hex_val(c)), True{}), Lit{acc, 0, False{}})

def apply_sign(+neg: Bool, +f: F) -> F:
  Bool.pick(F, neg, negate(f), f)

def lit_value(l: Lit, +neg: Bool, +hex: Bool) -> Maybe<&2, F>:
  match l:
    case Lit{+d, +s, ok}:
      match ok:
        case False{}:
          None{}
        case True{}:
          Some{Bool.pick(F, is_zero(d), zero(neg), apply_sign(neg, Bool.pick(F, hex, exact(False{}, d, 0), from_dec(norm(d), smax(smin(s, 400), 4294966496)))))}

# The numeric value of a decimal, hexadecimal, octal or binary literal
# ("12", "1.5e-3", ".5", "0x1F", "0o17", "0b101", "Infinity"), signed when
# `signed`; None when it is not one.
def read(+text: String) -> Maybe<&2, F>:
  +neg = String.starts_with(text, "-")
  +body = Bool.pick(String, neg || String.starts_with(text, "+"), String.drop(text, 1n), text)
  +p2 = String.to_lower(String.take(body, 2n))
  +base = Bool.pick(U32, String.eq(p2, "0x"), 16, Bool.pick(U32, String.eq(p2, "0o"), 8, Bool.pick(U32, String.eq(p2, "0b"), 2, 0)))
  +hex = Bool.not(U32.is_zero(base))
  Bool.pick(Maybe<&2, F>, String.eq(body, "Infinity"), Some{inf(neg)},
    lit_value(Bool.pick(Lit, hex, read_hex(String.drop(body, 2n), base, Nil{}, False{}), read_int(body, head_class(body, False{}, False{}), Nil{}, 0, False{}, False{})), neg, hex))

def bits_text(f: F) -> String:
  match f:
    case F{hi, lo}:
      U32.show(hi) ++ " " ++ U32.show(lo)
