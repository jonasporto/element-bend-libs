import Base
import element-crypto@0.1.0.0/hmac.bend as Hmac
import element-crypto@0.1.0.0/sha256.bend as Sha256
import element-crypto@0.1.0.0/poly1305.bend as Poly
import element-crypto@0.1.0.0/gcm.bend as Gcm
import ./tls13.bend as T

# TLS 1.2 (RFC 5246), the pure half, for servers that do not speak TLS 1.3:
# the PRF, the key schedule with the extended master secret (RFC 7627),
# ECDHE over x25519 or P-256 (RFC 8422; P-256 in lib/crypto/ecdh.bend), and record protection for the two AEADs
# Element has: AES-128-GCM (RFC 5288, an 8-byte explicit nonce in each
# record) and ChaCha20-Poly1305 (RFC 7905, the nonce as in TLS 1.3). As in
# tls13.bend, the AEAD follows the key length: 16 bytes is GCM.
#
# Suites, all SHA-256: ECDHE_ECDSA/RSA_WITH_AES_128_GCM_SHA256 0xC02B/0xC02F,
# ECDHE_RSA/ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA8/0xCCA9.

def is_suite(+s: U32) -> Bool:
  U32.is_eq(s, 49195) || U32.is_eq(s, 49199) || U32.is_eq(s, 52392) || U32.is_eq(s, 52393)

def is_gcm(+s: U32) -> Bool:
  U32.is_eq(s, 49195) || U32.is_eq(s, 49199)

def key_len(+s: U32) -> U32:
  Bool.pick(U32, is_gcm(s), 16, 32)

# GCM's implicit nonce part is 4 bytes; ChaCha20's whole nonce is 12
def iv_len(+s: U32) -> U32:
  Bool.pick(U32, is_gcm(s), 4, 12)

# ---- PRF (5) ------------------------------------------------------------------------

# P_SHA256: HMAC(secret, A(i) | seed) for A(i) = HMAC(secret, A(i-1)), A(0) = seed
def p_hash(n: Nat, +secret: List<&2, U32>, +seed: List<&2, U32>, +a: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+k:
      +a1 = Hmac.hmac(secret, a)
      List.append(&2, U32, Hmac.hmac(secret, List.append(&2, U32, a1, seed)), p_hash(k, secret, seed, a1))

def prf(+secret: List<&2, U32>, +label: String, +seed: List<&2, U32>, +n: U32) -> List<&2, U32>:
  +ls = List.append(&2, U32, T.ascii(label), seed)
  List.take(&2, U32, p_hash(U32.to_nat(((n + 31 : U32) / 32 : U32)), secret, ls, ls), U32.to_nat(n))

# 8.1, or RFC 7627 4 when the server echoed extended_master_secret: the
# session hash covers every handshake message through ClientKeyExchange.
def master_secret(ems: Bool, +pms: List<&2, U32>, +cr: List<&2, U32>, +sr: List<&2, U32>, +transcript: List<&2, U32>) -> List<&2, U32>:
  match ems:
    case True{}:
      prf(pms, "extended master secret", Sha256.digest(transcript), 48)
    case False{}:
      prf(pms, "master secret", List.append(&2, U32, cr, sr), 48)

# 6.3: client key, server key, client IV, server IV (AEAD suites have no MAC keys)
def key_block(+ms: List<&2, U32>, +cr: List<&2, U32>, +sr: List<&2, U32>, +suite: U32) -> List<&2, U32>:
  +k = key_len(suite)
  +i = iv_len(suite)
  prf(ms, "key expansion", List.append(&2, U32, sr, cr), ((k + k : U32) + (i + i : U32) : U32))

def client_key(+kb: List<&2, U32>, +suite: U32) -> List<&2, U32>:
  T.slice(kb, 0, key_len(suite))

def server_key(+kb: List<&2, U32>, +suite: U32) -> List<&2, U32>:
  T.slice(kb, key_len(suite), key_len(suite))

def client_iv(+kb: List<&2, U32>, +suite: U32) -> List<&2, U32>:
  +k = key_len(suite)
  T.slice(kb, (k + k : U32), iv_len(suite))

def server_iv(+kb: List<&2, U32>, +suite: U32) -> List<&2, U32>:
  +k = key_len(suite)
  +i = iv_len(suite)
  T.slice(kb, ((k + k : U32) + i : U32), i)

# 7.4.9: Finished is PRF(master, label, Hash(handshake messages))[0..12]
def verify_data(+ms: List<&2, U32>, +label: String, +transcript: List<&2, U32>) -> List<&2, U32>:
  prf(ms, label, Sha256.digest(transcript), 12)

# ---- handshake messages ----------------------------------------------------------------

# 7.4.2: certificate_list<0..2^24-1> of ASN.1Cert<1..2^24-1>, leaf first
def entries(fuel: Nat, +bs: List<&2, U32>) -> List<&2, List<&2, U32>>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+r:
      +n = T.get24(bs, 0n)
      Bool.pick(List<&2, List<&2, U32>>, (T.len(bs) < 3 : U32), Nil{},
        T.slice(bs, 3, n) <> entries(r, List.drop(&2, U32, bs, U32.to_nat((3 + n : U32)))))

def cert_ders(+m: List<&2, U32>) -> List<&2, List<&2, U32>>:
  entries(16n, T.slice(m, 7, T.get24(m, 4n)))

# ServerKeyExchange for ECDHE (RFC 8422 5.4): curve_type 3 (named_curve),
# the curve, the public point<1..255>, then the signature scheme and the
# signature<0..2^16-1>. Offsets are into the whole message (4-byte header).
def ske_curve(+m: List<&2, U32>) -> U32:
  T.get16(m, 5n)

def ske_named(+m: List<&2, U32>) -> Bool:
  U32.is_eq(T.nth(m, 4n), 3)

# x25519 (29) with a 32-byte key, or secp256r1 (23) with a 65-byte
# uncompressed point; the point itself is checked when it is used.
def ske_group_ok(+m: List<&2, U32>) -> Bool:
  +curve = ske_curve(m)
  +n = T.nth(m, 7n)
  ske_named(m) && ((U32.is_eq(curve, 29) && U32.is_eq(n, 32)) || (U32.is_eq(curve, 23) && U32.is_eq(n, 65)))

def ske_public(+m: List<&2, U32>) -> List<&2, U32>:
  T.slice(m, 8, T.nth(m, 7n))

def ske_params(+m: List<&2, U32>) -> List<&2, U32>:
  T.slice(m, 4, (4 + T.nth(m, 7n) : U32))

def ske_sig_at(+m: List<&2, U32>) -> U32:
  (8 + T.nth(m, 7n) : U32)

def ske_scheme(+m: List<&2, U32>) -> U32:
  T.get16(m, U32.to_nat(ske_sig_at(m)))

def ske_sig(+m: List<&2, U32>) -> List<&2, U32>:
  +at = ske_sig_at(m)
  T.slice(m, (at + 4 : U32), T.get16(m, U32.to_nat((at + 2 : U32))))

# what the server signed: client_random | server_random | params
def ske_signed(+cr: List<&2, U32>, +sr: List<&2, U32>, +m: List<&2, U32>) -> List<&2, U32>:
  T.cat([cr, sr, ske_params(m)])

# ClientKeyExchange (RFC 8422 5.7): the client's public point<1..255>
def client_key_exchange(+pub: List<&2, U32>) -> List<&2, U32>:
  T.handshake(16, T.vec8(pub))

# RFC 8446 4.1.3: a TLS 1.3 client that is answered with TLS 1.2 must check
# that the server random does not end in "DOWNGRD" 01 (a downgrade attack).
def downgraded(+sr: List<&2, U32>) -> Bool:
  Poly.eq_bytes(T.slice(sr, 24, 8), Hmac.unhex("444f574e47524401"))

# ---- records (6.2.3.3) ----------------------------------------------------------------

def seq64(+seq: U32) -> List<&2, U32>:
  List.append(&2, U32, Hmac.zeros(4n), [(seq / 16777216 : U32), (seq / 65536 % 256 : U32), (seq / 256 % 256 : U32), (seq % 256 : U32)])

# additional_data = seq_num | type | version | length (of the plaintext)
def aad(+seq: U32, +typ: U32, +n: U32) -> List<&2, U32>:
  T.cat([seq64(seq), [typ, 3, 3], T.u16(n)])

def seal_go(gcm: Bool, +key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +typ: U32, +content: List<&2, U32>) -> List<&2, U32>:
  match gcm:
    case True{}:
      +explicit = seq64(seq)
      List.append(&2, U32, explicit, Gcm.seal(key, List.append(&2, U32, iv, explicit), aad(seq, typ, T.len(content)), content))
    case False{}:
      Poly.seal(key, T.nonce(iv, seq), aad(seq, typ, T.len(content)), content)

# A whole protected record of type `typ` (the type stays visible in 1.2).
def protect(+key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +typ: U32, +content: List<&2, U32>) -> List<&2, U32>:
  T.record(typ, seal_go(U32.is_eq(T.len(key), 16), key, iv, seq, typ, content))

def inner(+typ: U32, m: Maybe<&2, List<&2, U32>>) -> Maybe<&2, T.Inner>:
  match m:
    case None{}:
      None{}
    case Some{value}:
      Some{T.Inner{typ, value}}

def open_go(gcm: Bool, +key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +typ: U32, +body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match gcm:
    case True{}:
      +ct = List.drop(&2, U32, body, 8n)
      Gcm.open(key, List.append(&2, U32, iv, List.take(&2, U32, body, 8n)), aad(seq, typ, (T.len(ct) - 16 : U32)), ct)
    case False{}:
      Poly.open(key, T.nonce(iv, seq), aad(seq, typ, (T.len(body) - 16 : U32)), body)

def opened_if(long: Bool, gcm: Bool, +key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +typ: U32, +body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match long:
    case False{}:
      None{}
    case True{}:
      open_go(gcm, key, iv, seq, typ, body)

# The fragment of a protected record (after its 5-byte header); None when it
# is too short or its tag does not verify.
def unprotect(+key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +typ: U32, +body: List<&2, U32>) -> Maybe<&2, T.Inner>:
  +gcm = U32.is_eq(T.len(key), 16)
  +least = Bool.pick(U32, gcm, 24, 16)
  inner(typ, opened_if((T.len(body) >= least : U32), gcm, key, iv, seq, typ, body))
