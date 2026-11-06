import Base
import ./suite_ours.bend as Impl

# The seam for the TLS primitives (decision own-libraries-and-hub-packages-
# side-by-side): Element's TLS calls these, and the line above picks the
# implementation. ./suite_ours.bend is crypto; ./suite_bc.bend is
# bend-collections@1.0.0.0 by hash. Switching is that one line; both stay
# buildable, so the A/B can be re-run.

def digest(+bs: List<&2, U32>) -> List<&2, U32>:
  Impl.digest(bs)

def hmac(key: List<&2, U32>, msg: List<&2, U32>) -> List<&2, U32>:
  Impl.hmac(key, msg)

def extract(salt: List<&2, U32>, ikm: List<&2, U32>) -> List<&2, U32>:
  Impl.extract(salt, ikm)

def expand(+prk: List<&2, U32>, +info: List<&2, U32>, +len: U32) -> List<&2, U32>:
  Impl.expand(prk, info, len)

def chacha_seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  Impl.chacha_seal(key, nonce, aad, pt)

def chacha_open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Impl.chacha_open(key, nonce, aad, sealed)

def gcm_seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  Impl.gcm_seal(key, nonce, aad, pt)

def gcm_open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Impl.gcm_open(key, nonce, aad, sealed)

def x25519_public(+k: List<&2, U32>) -> List<&2, U32>:
  Impl.x25519_public(k)

def x25519_shared(+k: List<&2, U32>, +u: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Impl.x25519_shared(k, u)

def eq_bytes(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  Impl.eq_bytes(xs, ys)
