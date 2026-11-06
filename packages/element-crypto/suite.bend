import Base
import ./suite_ours.bend as Ours

# The seam for TLS's primitives (decision own-libraries-and-hub-packages-side-
# by-side): Element's TLS calls these, and each one names the implementation
# that is better today, measured the same way on both sides
# (a TLS-shaped benchmark and the crypto vectors). Switching one primitive is
# one word; both implementations stay buildable for the A/B.
#   Bc:   bend-collections@1.0.0.0: laws for every input, constant-time by construction; as fast or faster (AES-GCM ~2x)
#   Ours: crypto/fe25519 (2026-11-05): 600 X25519 in 0.21 s against 39.8 s for bend-collections@1.0.0.0, same output

def digest(+bs: List<&2, U32>) -> List<&2, U32>:
  Ours.digest(bs)

def hmac(key: List<&2, U32>, msg: List<&2, U32>) -> List<&2, U32>:
  Ours.hmac(key, msg)

def extract(salt: List<&2, U32>, ikm: List<&2, U32>) -> List<&2, U32>:
  Ours.extract(salt, ikm)

def expand(+prk: List<&2, U32>, +info: List<&2, U32>, +len: U32) -> List<&2, U32>:
  Ours.expand(prk, info, len)

def chacha_seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  Ours.chacha_seal(key, nonce, aad, pt)

def chacha_open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Ours.chacha_open(key, nonce, aad, sealed)

def gcm_seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  Ours.gcm_seal(key, nonce, aad, pt)

def gcm_open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Ours.gcm_open(key, nonce, aad, sealed)

def x25519_public(+k: List<&2, U32>) -> List<&2, U32>:
  Ours.x25519_public(k)

def x25519_shared(+k: List<&2, U32>, +u: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Ours.x25519_shared(k, u)

def eq_bytes(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  Ours.eq_bytes(xs, ys)
