import Base
import element-math@0.1.0.0/big.bend as Big
import ./ecdsa.bend as Ec
import ./ecp256.bend as E
import ./sha256.bend as Sha256

# ECDH on P-256 (SEC 1 3.3.1), the TLS 1.2 key exchange of servers that
# offer no x25519 (RFC 8422; arstechnica.com and craigslist.org). Points are
# uncompressed SEC 1 (04 || X || Y, 65 bytes); the shared secret is X alone,
# 32 bytes (RFC 8422 5.10). Checked against RFC 5903 8.1.
#
# The point arithmetic is ./ecp256.bend over the generated Montgomery field
# ./fep256.bend (both generated); the scalar stays a math/big number
# mod n, the curve's order.
#
# Timing. ecdsa.bend holds no secret; this file does: an ephemeral scalar,
# used for one handshake and dropped. The scalar multiplication runs the
# same sequence for every bit (a doubling and an addition, both computed,
# the result picked by a mask), and the field is straight-line code with no
# branch on a limb, but the point addition branches on infinity and on
# equal points, so it is not constant time. That is accepted for an
# ephemeral key only: a timing attack must recover it from one handshake.
# Never hold a long-term key here.

# n, the order of P-256's base point.
def order() -> Big.Mod:
  Big.modulus_of_bytes([255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173, 167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81])

def times(+k: List<&2, U32>, +p: E.Pt) -> E.Pt:
  E.times(Big.to_bytes(k, 32n), p)

# The scalar from 32 secret bytes: SHA-256 under a label (so it is not the
# x25519 key made from the same bytes), reduced into [1, n-1].
def scalar(+secret: List<&2, U32>) -> List<&2, U32>:
  +q = order()
  +h = Sha256.digest(List.append(&2, U32, Sha256.bytes_of("element p-256 ecdhe "), secret))
  +k = Ec.reduce_once(q, Ec.limbs(q, h))
  Big.pick(Big.is_zero(k), Big.one(q), k)

# 04 || X || Y of k G, for a scalar k
def public_key_of_scalar(+k: List<&2, U32>) -> List<&2, U32>:
  4 <> E.affine(times(k, E.base()))

def public_key(+secret: List<&2, U32>) -> List<&2, U32>:
  public_key_of_scalar(scalar(secret))

# The peer's point must be uncompressed, in range and on the curve (an
# invalid point would leak the scalar, RFC 8422 5.11); the result must not
# be the point at infinity. X of k P, or None.
def valid(+point: List<&2, U32>, +x: List<&2, U32>, +y: List<&2, U32>) -> Bool:
  U32.is_eq(Big.nth(point, 0n), 4) && Nat.is_eq(List.length(&2, U32, point), 65n) && E.point_ok(x, y)

def shared_if(ok: Bool, +k: List<&2, U32>, +x: List<&2, U32>, +y: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      +r = times(k, E.point_of(x, y))
      E.finite_x(E.is_inf(r), r)

# X of k P for a scalar k
def shared_of_scalar(+k: List<&2, U32>, +point: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  +x = List.take(&2, U32, List.drop(&2, U32, point, 1n), 32n)
  +y = List.drop(&2, U32, point, 33n)
  shared_if(valid(point, x, y), k, x, y)

# A scalar given as 32 big-endian bytes (test vectors name the scalar).
def scalar_of_bytes(+bs: List<&2, U32>) -> List<&2, U32>:
  Ec.limbs(order(), bs)

def shared(+secret: List<&2, U32>, +point: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  shared_of_scalar(scalar(secret), point)
