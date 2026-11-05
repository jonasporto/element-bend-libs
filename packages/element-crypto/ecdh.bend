import Base
import element-math@0.1.0.0/big.bend as Big
import ./ecdsa.bend as Ec
import ./sha256.bend as Sha256

# ECDH on P-256 (SEC 1 3.3.1), the TLS 1.2 key exchange of servers that
# offer no x25519 (RFC 8422; arstechnica.com and craigslist.org). Points are
# uncompressed SEC 1 (04 || X || Y, 65 bytes); the shared secret is X alone,
# 32 bytes (RFC 8422 5.10). Checked against RFC 5903 8.1.
#
# Timing. ecdsa.bend holds no secret; this file does: an ephemeral scalar,
# used for one handshake and dropped. The scalar multiplication runs the
# same sequence for every bit (a doubling and an addition, both computed,
# the result picked), but Big's field arithmetic is not constant time. That
# is accepted for an ephemeral key only: a timing attack must recover it
# from one handshake. Never hold a long-term key here.

def curve() -> Ec.Curve:
  Ec.p256()

# k P, most significant bit first: every bit doubles and adds, and the bit
# picks which of the two goes on (both were computed).
def ladder(bits: List<&2, Bool>, +f: Big.Mod, +p: Ec.Pt, +acc: Ec.Pt) -> Ec.Pt:
  match bits:
    case Nil{}:
      acc
    case Con{b, t}:
      +d = Ec.dbl(f, acc)
      +s = Ec.add(f, d, p)
      ladder(t, f, p, Bool.pick(Ec.Pt, b, s, d))

# The affine point as 64 bytes, X then Y (Jacobian: x = X/Z^2, y = Y/Z^3).
def affine_bytes(+f: Big.Mod, p: Ec.Pt) -> List<&2, U32>:
  match p:
    case Ec.Pt{x, y, +z}:
      +zi = Big.inv(f, Big.from_mont(f, z))
      +zi2 = Big.mul(f, zi, zi)
      List.append(&2, U32, Big.to_bytes(Big.mul(f, Big.from_mont(f, x), zi2), 32n), Big.to_bytes(Big.mul(f, Big.from_mont(f, y), Big.mul(f, zi2, zi)), 32n))

def times(+f: Big.Mod, +k: List<&2, U32>, +p: Ec.Pt) -> Ec.Pt:
  ladder(Big.bits_of_bytes(Big.to_bytes(k, 32n)), f, p, Ec.infinity(f))

# The scalar from 32 secret bytes: SHA-256 under a label (so it is not the
# x25519 key made from the same bytes), reduced into [1, n-1].
def scalar_in(c: Ec.Curve, +secret: List<&2, U32>) -> List<&2, U32>:
  match c:
    case Ec.Curve{f, +q, b, gx, gy, size}:
      +h = Sha256.digest(List.append(&2, U32, Sha256.bytes_of("element p-256 ecdhe "), secret))
      +k = Ec.reduce_once(q, Ec.limbs(q, h))
      Big.pick(Big.is_zero(k), Big.one(q), k)

def scalar(+secret: List<&2, U32>) -> List<&2, U32>:
  scalar_in(curve(), secret)

# 04 || X || Y of k G, for a scalar k
def public_in(c: Ec.Curve, +k: List<&2, U32>) -> List<&2, U32>:
  match c:
    case Ec.Curve{+f, q, b, gx, gy, size}:
      +one = Big.to_mont(f, Big.one(f))
      4 <> affine_bytes(f, times(f, k, Ec.pt(gx, gy, one)))

def public_key_of_scalar(+k: List<&2, U32>) -> List<&2, U32>:
  public_in(curve(), k)

def public_key(+secret: List<&2, U32>) -> List<&2, U32>:
  public_in(curve(), scalar(secret))

# The peer's point must be uncompressed, in range and on the curve (an
# invalid point would leak the scalar, RFC 8422 5.11); the result must not
# be the point at infinity. X of k P, or None.
def valid(+f: Big.Mod, +b: List<&2, U32>, +point: List<&2, U32>, +x: List<&2, U32>, +y: List<&2, U32>) -> Bool:
  U32.is_eq(Big.nth(point, 0n), 4) && Nat.is_eq(List.length(&2, U32, point), 65n) &&
    Big.lt(x, Big.n_of(f)) && Big.lt(y, Big.n_of(f)) && Ec.on_curve(f, b, Big.to_mont(f, x), Big.to_mont(f, y))

def finite(inf: Bool, +f: Big.Mod, r: Ec.Pt) -> Maybe<&2, List<&2, U32>>:
  match inf:
    case True{}:
      None{}
    case False{}:
      Some{List.take(&2, U32, affine_bytes(f, r), 32n)}

def shared_if(ok: Bool, +f: Big.Mod, +k: List<&2, U32>, +x: List<&2, U32>, +y: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      +one = Big.to_mont(f, Big.one(f))
      +r = times(f, k, Ec.pt(Big.to_mont(f, x), Big.to_mont(f, y), one))
      finite(Ec.is_inf(r), f, r)

def shared_in(c: Ec.Curve, +k: List<&2, U32>, +point: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match c:
    case Ec.Curve{+f, q, +b, gx, gy, size}:
      +x = Ec.limbs(f, List.take(&2, U32, List.drop(&2, U32, point, 1n), 32n))
      +y = Ec.limbs(f, List.drop(&2, U32, point, 33n))
      shared_if(valid(f, b, point, x, y), f, k, x, y)

def scalar_bytes_in(c: Ec.Curve, +bs: List<&2, U32>) -> List<&2, U32>:
  match c:
    case Ec.Curve{f, +q, b, gx, gy, size}:
      Ec.limbs(q, bs)

# A scalar given as 32 big-endian bytes (test vectors name the scalar).
def scalar_of_bytes(+bs: List<&2, U32>) -> List<&2, U32>:
  scalar_bytes_in(curve(), bs)

# X of k P for a scalar k
def shared_of_scalar(+k: List<&2, U32>, +point: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  shared_in(curve(), k, point)

def shared(+secret: List<&2, U32>, +point: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  shared_in(curve(), scalar(secret), point)
