import Base
import ./sha256.bend as Sha256
import ./hmac.bend as Hmac
import ./poly1305.bend as Poly
import ./gcm.bend as Gcm
import ./x25519.bend as X

# The TLS primitives from Element's own crypto (one implementation behind
# crypto/suite.bend; suite_bc.bend is the other).

def digest(+bs: List<&2, U32>) -> List<&2, U32>:
  Sha256.digest(bs)

def hmac(key: List<&2, U32>, msg: List<&2, U32>) -> List<&2, U32>:
  Hmac.hmac(key, msg)

def extract(salt: List<&2, U32>, ikm: List<&2, U32>) -> List<&2, U32>:
  Hmac.extract(salt, ikm)

def expand(+prk: List<&2, U32>, +info: List<&2, U32>, +len: U32) -> List<&2, U32>:
  Hmac.expand(prk, info, len)

def chacha_seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  Poly.seal(key, nonce, aad, pt)

def chacha_open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Poly.open(key, nonce, aad, sealed)

def gcm_seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  Gcm.seal(key, nonce, aad, pt)

def gcm_open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Gcm.open(key, nonce, aad, sealed)

def x25519_public(+k: List<&2, U32>) -> List<&2, U32>:
  X.public_key(k)

def x25519_shared(+k: List<&2, U32>, +u: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  X.shared(k, u)

def eq_bytes(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  Poly.eq_bytes(xs, ys)
