import Base
import element-math@0.1.0.0/big.bend as Big
import ./hash.bend as Hash
import ./hmac.bend as Hmac
import ./ecp256.bend as E256
import ./ecp384.bend as E384

# ECDSA signature verification (FIPS 186-5 6.4.2, SEC 1 4.1.4) on the NIST
# curves P-256 and P-384, y^2 = x^3 - 3x + b over GF(p). It runs in
# ./ecp256.bend and ./ecp384.bend, made by Element's field generator over
# generated Montgomery fields (13-bit limbs in a record of U32): the point
# arithmetic mod p (Jacobian, dbl-2001-b and add-2007-bl, u1 G + u2 Q in one
# joint pass, Shamir's trick) and the scalars mod n (s^-1, e s^-1, r s^-1).
# This file checks lengths, truncates the digest and picks the curve.
# Verification only: no secret ever enters this file, so nothing here needs
# to be constant time.
#
# The list-limb point code below (BigCurve, verify_big) is what this
# replaced on 2026-11-06, kept for the differential test in crypto_vectors
# until the generated one has run in Element for a while.

type Field is Data:
  FP256{}
  FP384{}

type Curve is Data:
  Curve{fld: Field, size: Nat}

def p256() -> Curve:
  Curve{FP256{}, 32n}

def p384() -> Curve:
  Curve{FP384{}, 48n}

def verify_rs(fld: Field, +qx: List<&2, U32>, +qy: List<&2, U32>, +r: List<&2, U32>, +s: List<&2, U32>, +e: List<&2, U32>) -> Bool:
  match fld:
    case FP256{}:
      E256.verify_rs(qx, qy, r, s, e)
    case FP384{}:
      E384.verify_rs(qx, qy, r, s, e)

# ---- the list-limb curve (verify_big) -----------------------------------------------

type BigCurve is Data:
  BigCurve{f: Big.Mod, q: Big.Mod, b: List<&2, U32>, gx: List<&2, U32>, gy: List<&2, U32>, size: Nat}

type Pt is Data:
  Pt{x: List<&2, U32>, y: List<&2, U32>, z: List<&2, U32>}

def num(+s: String) -> List<&2, U32>:
  Big.from_bytes(Hmac.unhex(s))

def curve(+p: String, +b: String, +n: String, +gx: String, +gy: String, +size: Nat) -> BigCurve:
  +f = Big.modulus_of_bytes(Hmac.unhex(p))
  BigCurve{f, Big.modulus_of_bytes(Hmac.unhex(n)), Big.to_mont(f, num(b)), Big.to_mont(f, num(gx)), Big.to_mont(f, num(gy)), size}

def p256_big() -> BigCurve:
  curve(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    32n)

def p384_big() -> BigCurve:
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

# ---- shared by both ------------------------------------------------------------

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

# ---- verification on the generated fields ---------------------------------------

# Verify (r, s) over msg with the public point (qx, qy); all big-endian bytes.
def verify(c: Curve, +h: Hash.Hash, +qx: List<&2, U32>, +qy: List<&2, U32>, +r_b: List<&2, U32>, +s_b: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match c:
    case Curve{+fld, +size}:
      +e = List.take(&2, U32, Hash.digest(h, msg), size)
      fits(size, r_b) && fits(size, s_b) && fits(size, qx) && fits(size, qy) && verify_rs(fld, qx, qy, r_b, s_b, e)

def curve_size(c: Curve) -> Nat:
  match c:
    case Curve{fld, size}:
      size

# The public key as an uncompressed SEC 1 point: 04 || X || Y.
def verify_point(+c: Curve, +h: Hash.Hash, +point: List<&2, U32>, +r: List<&2, U32>, +s: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  +size = curve_size(c)
  U32.is_eq(Big.nth(point, 0n), 4) && Nat.is_eq(List.length(&2, U32, point), Nat.add(Nat.mul(size, 2n), 1n)) &&
    verify(c, h, List.take(&2, U32, List.drop(&2, U32, point, 1n), size), List.drop(&2, U32, point, Nat.add(size, 1n)), r, s, msg)

# ---- verification on the list-limb curve ----------------------------------------

# Verify (r, s) over msg with the public point (qx, qy); all big-endian bytes.
def verify_big(c: BigCurve, +h: Hash.Hash, +qx: List<&2, U32>, +qy: List<&2, U32>, +r_b: List<&2, U32>, +s_b: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match c:
    case BigCurve{+f, +q, +b, +gx, +gy, +size}:
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

def big_curve_size(c: BigCurve) -> Nat:
  match c:
    case BigCurve{f, q, b, gx, gy, size}:
      size

def verify_point_big(+c: BigCurve, +h: Hash.Hash, +point: List<&2, U32>, +r: List<&2, U32>, +s: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  +size = big_curve_size(c)
  U32.is_eq(Big.nth(point, 0n), 4) && Nat.is_eq(List.length(&2, U32, point), Nat.add(Nat.mul(size, 2n), 1n)) &&
    verify_big(c, h, List.take(&2, U32, List.drop(&2, U32, point, 1n), size), List.drop(&2, U32, point, Nat.add(size, 1n)), r, s, msg)

# ---- the signature in DER ---------------------------------------------------------

def len(+bs: List<&2, U32>) -> Nat:
  List.length(&2, U32, bs)

# A DER INTEGER's content is minimal and non-negative (X.690 8.3.2): at least
# one byte, the first below 0x80, and no leading 00 unless the next byte needs it.
def der_int_ok(+v: List<&2, U32>) -> Bool:
  +b0 = Big.nth(v, 0n)
  +b1 = Big.nth(v, 1n)
  Nat.is_ge(len(v), 1n) && (b0 < 128 : U32) && Bool.not(U32.is_zero(b0) && Nat.is_ge(len(v), 2n) && (b1 < 128 : U32))

# ECDSA-Sig-Value (RFC 5480 2.2.3, SEC 1 C.5) in strict DER: SEQUENCE {
# INTEGER r, INTEGER s } and nothing after it, every length in short form (a
# P-256 or P-384 signature is under 128 bytes, so a long form is never
# minimal), both integers minimal. BER, extra bytes and other tags are
# refused, as Wycheproof's ecdsa_*_test.json requires.
def der_sig_ok(+sig: List<&2, U32>, +r: List<&2, U32>, +t: List<&2, U32>, +s: List<&2, U32>) -> Bool:
  +l = Big.nth(sig, 1n)
  +lr = Big.nth(sig, 3n)
  +ls = Big.nth(t, 1n)
  U32.is_eq(Big.nth(sig, 0n), 48) && (l < 128 : U32) && Nat.is_eq(len(sig), Nat.add(U32.to_nat(l), 2n)) &&
    U32.is_eq(Big.nth(sig, 2n), 2) && (lr < 128 : U32) && Nat.is_eq(len(r), U32.to_nat(lr)) &&
    U32.is_eq(Big.nth(t, 0n), 2) && (ls < 128 : U32) && Nat.is_eq(len(s), U32.to_nat(ls)) &&
    der_int_ok(r) && der_int_ok(s)

# verify_point with (r, s) as a DER ECDSA-Sig-Value (X.509 and TLS signatures).
def verify_der(+c: Curve, +h: Hash.Hash, +point: List<&2, U32>, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  +lr = U32.to_nat(Big.nth(sig, 3n))
  +r = List.take(&2, U32, List.drop(&2, U32, sig, 4n), lr)
  +t = List.drop(&2, U32, sig, Nat.add(4n, lr))
  +s = List.drop(&2, U32, t, 2n)
  der_sig_ok(sig, r, t, s) && verify_point(c, h, point, r, s, msg)
