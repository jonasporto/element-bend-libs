import Base
import element-math@0.1.0.0/big.bend as Big
import ./hash.bend as Hash
import ./hmac.bend as Hmac

# ECDSA signature verification (FIPS 186-5 6.4.2, SEC 1 4.1.4) on the NIST
# curves P-256 and P-384, y^2 = x^3 - 3x + b over GF(p). Field elements live
# in Montgomery form; points in Jacobian coordinates (X, Y, Z) with the point
# at infinity as Z = 0, doubling by dbl-2001-b and addition by add-2007-bl
# from the Explicit-Formulas Database. u1 G + u2 Q is one joint
# double-and-add pass (Shamir's trick). Verification only: no secret ever
# enters this file, so nothing here needs to be constant time.

type Curve is Data:
  Curve{f: Big.Mod, q: Big.Mod, b: List<&2, U32>, gx: List<&2, U32>, gy: List<&2, U32>, size: Nat}

type Pt is Data:
  Pt{x: List<&2, U32>, y: List<&2, U32>, z: List<&2, U32>}

def num(+s: String) -> List<&2, U32>:
  Big.from_bytes(Hmac.unhex(s))

def curve(+p: String, +b: String, +n: String, +gx: String, +gy: String, +size: Nat) -> Curve:
  +f = Big.modulus_of_bytes(Hmac.unhex(p))
  Curve{f, Big.modulus_of_bytes(Hmac.unhex(n)), Big.to_mont(f, num(b)), Big.to_mont(f, num(gx)), Big.to_mont(f, num(gy)), size}

def p256() -> Curve:
  curve(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    32n)

def p384() -> Curve:
  curve(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    48n)

def pt(+x: List<&2, U32>, +y: List<&2, U32>, +z: List<&2, U32>) -> Pt:
  Pt{x, y, z}

# ---- points ------------------------------------------------------------------------

def mm(+f: Big.Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  Big.mmul(f, a, b)

def fa(+f: Big.Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  Big.add(f, a, b)

def fs(+f: Big.Mod, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  Big.sub(f, a, b)

def times8(+f: Big.Mod, +a: List<&2, U32>) -> List<&2, U32>:
  +a2 = fa(f, a, a)
  +a4 = fa(f, a2, a2)
  fa(f, a4, a4)

def infinity(+f: Big.Mod) -> Pt:
  +one = Big.to_mont(f, Big.one(f))
  Pt{one, one, Big.zeros(Big.k_of(f))}

# dbl-2001-b (a = -3). Infinity (Z = 0) and Y = 0 both give Z3 = 0.
def dbl(+f: Big.Mod, p: Pt) -> Pt:
  match p:
    case Pt{+x, +y, +z}:
      +delta = mm(f, z, z)
      +gamma = mm(f, y, y)
      +beta = mm(f, x, gamma)
      +t = fs(f, x, delta)
      +alpha = mm(f, fa(f, fa(f, t, t), t), fa(f, x, delta))
      +beta2 = fa(f, beta, beta)
      +beta4 = fa(f, beta2, beta2)
      +x3 = fs(f, mm(f, alpha, alpha), fa(f, beta4, beta4))
      +yz = fa(f, y, z)
      +z3 = fs(f, fs(f, mm(f, yz, yz), gamma), delta)
      +y3 = fs(f, mm(f, alpha, fs(f, beta4, x3)), times8(f, mm(f, gamma, gamma)))
      Pt{x3, y3, z3}

# add-2007-bl, general case (P != +-Q, neither at infinity).
def add_general(+f: Big.Mod, p: Pt, q: Pt, +u1: List<&2, U32>, +s1: List<&2, U32>, +h: List<&2, U32>, +r0: List<&2, U32>, +z1z1: List<&2, U32>, +z2z2: List<&2, U32>) -> Pt:
  match p q:
    case Pt{x1, y1, +z1} Pt{x2, y2, +z2}:
      +h2 = fa(f, h, h)
      +i = mm(f, h2, h2)
      +j = mm(f, h, i)
      +r = fa(f, r0, r0)
      +v = mm(f, u1, i)
      +x3 = fs(f, fs(f, fs(f, mm(f, r, r), j), v), v)
      +sj = mm(f, s1, j)
      +y3 = fs(f, mm(f, r, fs(f, v, x3)), fa(f, sj, sj))
      +zz = fa(f, z1, z2)
      +z3 = mm(f, fs(f, fs(f, mm(f, zz, zz), z1z1), z2z2), h)
      Pt{x3, y3, z3}

def add_case(inf1: Bool, inf2: Bool, hz: Bool, rz: Bool, +f: Big.Mod, +p: Pt, +q: Pt, +u1: List<&2, U32>, +s1: List<&2, U32>, +h: List<&2, U32>, +r0: List<&2, U32>, +z1z1: List<&2, U32>, +z2z2: List<&2, U32>) -> Pt:
  match inf1:
    case True{}:
      q
    case False{}:
      match inf2:
        case True{}:
          p
        case False{}:
          match hz:
            case False{}:
              add_general(f, p, q, u1, s1, h, r0, z1z1, z2z2)
            case True{}:
              match rz:
                case True{}:
                  dbl(f, p)
                case False{}:
                  infinity(f)

def add(+f: Big.Mod, p: Pt, q: Pt) -> Pt:
  match p q:
    case Pt{+x1, +y1, +z1} Pt{+x2, +y2, +z2}:
      +z1z1 = mm(f, z1, z1)
      +z2z2 = mm(f, z2, z2)
      +u1 = mm(f, x1, z2z2)
      +s1 = mm(f, mm(f, y1, z2), z2z2)
      +h = fs(f, mm(f, x2, z1z1), u1)
      +r0 = fs(f, mm(f, mm(f, y2, z1), z1z1), s1)
      add_case(Big.is_zero(z1), Big.is_zero(z2), Big.is_zero(h), Big.is_zero(r0), f, Pt{x1, y1, z1}, Pt{x2, y2, z2}, u1, s1, h, r0, z1z1, z2z2)

def pick_add(b1: Bool, b2: Bool, +f: Big.Mod, +d: Pt, +g: Pt, +q: Pt, +gq: Pt) -> Pt:
  match b1:
    case True{}:
      match b2:
        case True{}:
          add(f, d, gq)
        case False{}:
          add(f, d, g)
    case False{}:
      match b2:
        case True{}:
          add(f, d, q)
        case False{}:
          d

# u1 G + u2 Q from both scalars' bits, most significant first.
def joint(b1s: List<&2, Bool>, b2s: List<&2, Bool>, +f: Big.Mod, +g: Pt, +q: Pt, +gq: Pt, +acc: Pt) -> Pt:
  match b1s:
    case Nil{}:
      acc
    case Con{b1, t1}:
      match b2s:
        case Nil{}:
          acc
        case Con{b2, t2}:
          joint(t1, t2, f, g, q, gq, pick_add(b1, b2, f, dbl(f, acc), g, q, gq))

# ---- verification ----------------------------------------------------------------

def drop_zeros(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{+h, +t}:
      Bool.pick(List<&2, U32>, U32.is_zero(h), drop_zeros(t), h <> t)

# x mod m for x below 2m.
def reduce_once(+m: Big.Mod, +x: List<&2, U32>) -> List<&2, U32>:
  Big.pick(Big.lt(x, Big.n_of(m)), x, Big.fit(Big.k_of(m), Big.sub_go(x, Big.n_of(m), 0)))

# A big-endian integer of at most `size` bytes, as k limbs; `ok` says it fit.
def fits(+size: Nat, +bs: List<&2, U32>) -> Bool:
  Nat.is_le(List.length(&2, U32, drop_zeros(bs)), size)

def limbs(+m: Big.Mod, +bs: List<&2, U32>) -> List<&2, U32>:
  Big.fit(Big.k_of(m), Big.from_bytes(drop_zeros(bs)))

def in_range(+m: Big.Mod, +x: List<&2, U32>) -> Bool:
  Bool.not(Big.is_zero(x)) && Big.lt(x, Big.n_of(m))

def on_curve(+f: Big.Mod, +b: List<&2, U32>, +x: List<&2, U32>, +y: List<&2, U32>) -> Bool:
  Big.eq(mm(f, y, y), fa(f, fs(f, mm(f, mm(f, x, x), x), fa(f, fa(f, x, x), x)), b))

def x_of(+f: Big.Mod, p: Pt) -> List<&2, U32>:
  match p:
    case Pt{x, y, +z}:
      +zp = Big.from_mont(f, z)
      Big.mul(f, Big.from_mont(f, x), Big.inv(f, Big.mul(f, zp, zp)))

def is_inf(p: Pt) -> Bool:
  match p:
    case Pt{x, y, z}:
      Big.is_zero(z)

# Verify (r, s) over msg with the public point (qx, qy); all big-endian bytes.
def verify(c: Curve, +h: Hash.Hash, +qx: List<&2, U32>, +qy: List<&2, U32>, +r_b: List<&2, U32>, +s_b: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match c:
    case Curve{+f, +q, +b, +gx, +gy, +size}:
      +r = limbs(q, r_b)
      +s = limbs(q, s_b)
      +x = limbs(f, qx)
      +y = limbs(f, qy)
      +w = Big.inv(q, s)
      +e = reduce_once(q, limbs(q, List.take(&2, U32, Hash.digest(h, msg), size)))
      +u1 = Big.mul(q, e, w)
      +u2 = Big.mul(q, r, w)
      +one = Big.to_mont(f, Big.one(f))
      +xm = Big.to_mont(f, x)
      +ym = Big.to_mont(f, y)
      +g = pt(gx, gy, one)
      +pq = pt(xm, ym, one)
      +bits1 = Big.bits_of_bytes(Big.to_bytes(u1, size))
      +bits2 = Big.bits_of_bytes(Big.to_bytes(u2, size))
      +sum = joint(bits1, bits2, f, g, pq, add(f, g, pq), infinity(f))
      fits(size, r_b) && fits(size, s_b) && fits(size, qx) && fits(size, qy) &&
        in_range(q, r) && in_range(q, s) && Big.lt(x, Big.n_of(f)) && Big.lt(y, Big.n_of(f)) &&
        on_curve(f, b, xm, ym) && Bool.not(is_inf(sum)) && Big.eq(reduce_once(q, x_of(f, sum)), r)

def curve_size(c: Curve) -> Nat:
  match c:
    case Curve{f, q, b, gx, gy, size}:
      size

# The public key as an uncompressed SEC 1 point: 04 || X || Y.
def verify_point(+c: Curve, +h: Hash.Hash, +point: List<&2, U32>, +r: List<&2, U32>, +s: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  +size = curve_size(c)
  U32.is_eq(Big.nth(point, 0n), 4) && Nat.is_eq(List.length(&2, U32, point), Nat.add(Nat.mul(size, 2n), 1n)) &&
    verify(c, h, List.take(&2, U32, List.drop(&2, U32, point, 1n), size), List.drop(&2, U32, point, Nat.add(size, 1n)), r, s, msg)
