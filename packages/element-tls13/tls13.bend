import Base
import element-crypto@0.1.0.0/suite.bend as Suite
import element-crypto@0.1.0.0/sha256.bend as Sha256
import element-crypto@0.1.0.0/hmac.bend as Hmac
import element-crypto@0.1.0.0/chacha20.bend as ChaCha
import element-crypto@0.1.0.0/poly1305.bend as Poly
import element-crypto@0.1.0.0/gcm.bend as Gcm
import element-crypto@0.1.0.0/x25519.bend as X

# TLS 1.3 (RFC 8446), the pure half: wire encoding, the key schedule, the
# ClientHello, ServerHello parsing, record protection and Finished.
# Two TLS 1.3 suites, both SHA-256: TLS_AES_128_GCM_SHA256 (0x1301, which RFC 8446
# 9.1 requires a client to offer; five real sites refused
# a hello without it) offered first, as Chrome does, and also the faster in
# Bend (bench aead_gcm: 40 ms per 100 KB against 90 for ChaCha20-Poly1305),
# then TLS_CHACHA20_POLY1305_SHA256 (0x1303). x25519 only.
# The key schedule is checked against the RFC 8448 "Simple 1-RTT" trace.

# ---- bytes -------------------------------------------------------------------

def u8(+n: U32) -> List<&2, U32>:
  [(n % 256 : U32)]

def u16(+n: U32) -> List<&2, U32>:
  [(n / 256 % 256 : U32), (n % 256 : U32)]

def u24(+n: U32) -> List<&2, U32>:
  [(n / 65536 % 256 : U32), (n / 256 % 256 : U32), (n % 256 : U32)]

def len(xs: List<&2, U32>) -> U32:
  U32.from_nat(List.length(&2, U32, xs))

def vec8(+xs: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, u8(len(xs)), xs)

def vec16(+xs: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, u16(len(xs)), xs)

def vec24(+xs: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, u24(len(xs)), xs)

def cat(xss: List<&2, List<&2, U32>>) -> List<&2, U32>:
  List.concat(&2, U32, xss)

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  ChaCha.nth(xs, n)

def get16(+xs: List<&2, U32>, +i: Nat) -> U32:
  ((nth(xs, i) * 256 : U32) + nth(xs, Nat.add(i, 1n)) : U32)

def get24(+xs: List<&2, U32>, +i: Nat) -> U32:
  ((nth(xs, i) * 65536 : U32) + (nth(xs, Nat.add(i, 1n)) * 256 : U32) + nth(xs, Nat.add(i, 2n)) : U32)

def slice(+xs: List<&2, U32>, +from: U32, +n: U32) -> List<&2, U32>:
  List.take(&2, U32, List.drop(&2, U32, xs, U32.to_nat(from)), U32.to_nat(n))

def zeros(n: Nat) -> List<&2, U32>:
  Hmac.zeros(n)

def ascii(s: String) -> List<&2, U32>:
  Sha256.bytes_of(s)

def hash(+xs: List<&2, U32>) -> List<&2, U32>:
  Suite.digest(xs)

# ---- key schedule (7.1) ----------------------------------------------------------

def expand_label(+secret: List<&2, U32>, +label: String, +ctx: List<&2, U32>, +n: U32) -> List<&2, U32>:
  Suite.expand(secret, cat([u16(n), vec8(ascii("tls13 " ++ label)), vec8(ctx)]), n)

def derive_secret(+secret: List<&2, U32>, +label: String, +transcript: List<&2, U32>) -> List<&2, U32>:
  expand_label(secret, label, hash(transcript), 32)

def early_secret() -> List<&2, U32>:
  Suite.extract(zeros(32n), zeros(32n))

def handshake_secret(+ecdhe: List<&2, U32>) -> List<&2, U32>:
  Suite.extract(derive_secret(early_secret(), "derived", Nil{}), ecdhe)

def master_secret(+hs: List<&2, U32>) -> List<&2, U32>:
  Suite.extract(derive_secret(hs, "derived", Nil{}), zeros(32n))

def traffic_key(+secret: List<&2, U32>, +n: U32) -> List<&2, U32>:
  expand_label(secret, "key", Nil{}, n)

def traffic_iv(+secret: List<&2, U32>) -> List<&2, U32>:
  expand_label(secret, "iv", Nil{}, 12)

# Finished (4.4.4): HMAC over the transcript hash with the "finished" key.
def verify_data(+base: List<&2, U32>, +transcript: List<&2, U32>) -> List<&2, U32>:
  Suite.hmac(expand_label(base, "finished", Nil{}, 32), hash(transcript))

# ---- handshake messages ------------------------------------------------------------

def handshake(+typ: U32, +body: List<&2, U32>) -> List<&2, U32>:
  cat([u8(typ), vec24(body)])

def ext(+typ: U32, +body: List<&2, U32>) -> List<&2, U32>:
  cat([u16(typ), vec16(body)])

# ClientHello (4.1.2) offering TLS 1.3, then TLS 1.2 for servers that speak
# nothing newer (tls/tls12.bend), x25519 only. Suites: AES-128-GCM then
# ChaCha20-Poly1305 for 1.3; ECDHE with the same two AEADs for 1.2.
# Signature algorithms are the ones x509 verifies: ecdsa_secp256r1_sha256,
# ecdsa_secp384r1_sha384, rsa_pss_rsae_sha256/384/512, and
# rsa_pkcs1_sha256/384/512 (certificates, and TLS 1.2 ServerKeyExchange).
# For 1.2 also ec_point_formats (uncompressed), extended_master_secret and an
# empty renegotiation_info, as Chrome sends them. supported_groups lists
# secp256r1 and secp384r1 after x25519: a TLS 1.2 server may present an
# ECDSA certificate only on a curve the client lists (RFC 8422 5.1), and
# TLS 1.2 ECDHE runs on x25519 or P-256. The 1.3 key share is x25519.
def client_hello(+host: String, +random: List<&2, U32>, +session: List<&2, U32>, +pub: List<&2, U32>) -> List<&2, U32>:
  handshake(1, cat([
    u16(771), random, vec8(session),
    vec16(cat([u16(4865), u16(4867), u16(49195), u16(49199), u16(52393), u16(52392)])), vec8([0]),
    vec16(cat([
      ext(0, vec16(cat([u8(0), vec16(ascii(host))]))),
      ext(23, Nil{}),
      ext(65281, vec8(Nil{})),
      ext(10, vec16(cat([u16(29), u16(23), u16(24)]))),
      ext(11, vec8([0])),
      ext(13, vec16(cat([u16(1027), u16(1283), u16(2052), u16(2053), u16(2054), u16(1025), u16(1281), u16(1537)]))),
      ext(43, vec8(cat([u16(772), u16(771)]))),
      ext(51, vec16(cat([u16(29), vec16(pub)]))),
      ext(16, vec16(vec8(ascii("http/1.1"))))
    ]))
  ]))

# ServerHello: find the x25519 key_share (extension 51) and the chosen
# version (43). Returns the server's public key, or Nil if absent.
def find_ext(fuel: Nat, +exts: List<&2, U32>, +want: U32) -> List<&2, U32>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+k:
      Bool.pick(List<&2, U32>, (len(exts) < 4 : U32), Nil{},
        Bool.pick(List<&2, U32>, U32.is_eq(get16(exts, 0n), want),
          slice(exts, 4, get16(exts, 2n)),
          find_ext(k, List.drop(&2, U32, exts, U32.to_nat((4 + get16(exts, 2n) : U32))), want)))

# ServerHello body offsets: version 2, random 32, session_id vec8,
# cipher 2, compression 1, extensions vec16.
def sh_extensions(+sh: List<&2, U32>) -> List<&2, U32>:
  +body = List.drop(&2, U32, sh, 4n)
  +sid = nth(body, 34n)
  +at = (35 + sid + 3 : U32)
  slice(body, (at + 2 : U32), get16(body, U32.to_nat(at)))

def sh_cipher(+sh: List<&2, U32>) -> U32:
  +body = List.drop(&2, U32, sh, 4n)
  get16(body, U32.to_nat((35 + nth(body, 34n) : U32)))

def sh_key_share(+sh: List<&2, U32>) -> List<&2, U32>:
  +ks = find_ext(32n, sh_extensions(sh), 51)
  slice(ks, 4, get16(ks, 2n))

def sh_version(+sh: List<&2, U32>) -> U32:
  get16(find_ext(32n, sh_extensions(sh), 43), 0n)

# ServerHello's legacy_version (0x0303 for both 1.2 and 1.3) and random.
def sh_legacy(+sh: List<&2, U32>) -> U32:
  get16(sh, 4n)

def sh_random(+sh: List<&2, U32>) -> List<&2, U32>:
  slice(sh, 6, 32)

def ext_present(fuel: Nat, +exts: List<&2, U32>, +want: U32) -> Bool:
  match fuel:
    case 0n:
      False{}
    case 1n+k:
      +n = len(exts)
      +size = get16(exts, 2n)
      Bool.pick(Bool, (n < 4 : U32), False{},
        Bool.pick(Bool, U32.is_eq(get16(exts, 0n), want), True{},
          ext_present(k, List.drop(&2, U32, exts, U32.to_nat((4 + size : U32))), want)))

# extended_master_secret (RFC 7627) echoed by a TLS 1.2 server
def sh_ems(+sh: List<&2, U32>) -> Bool:
  +exts = sh_extensions(sh)
  ext_present(32n, exts, 23)

# HelloRetryRequest has this fixed "random" (4.1.3).
def is_hrr(+sh: List<&2, U32>) -> Bool:
  Suite.eq_bytes(slice(sh, 6, 32), Hmac.unhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"))

# ---- records (5) -----------------------------------------------------------------

# nonce = iv XOR (64-bit sequence number, left-padded to 12 bytes)
def nonce(+iv: List<&2, U32>, +seq: U32) -> List<&2, U32>:
  ChaCha.xor_with(iv, List.append(&2, U32, zeros(8n), [(seq / 16777216 : U32), (seq / 65536 % 256 : U32), (seq / 256 % 256 : U32), (seq % 256 : U32)]))

def record(+typ: U32, +body: List<&2, U32>) -> List<&2, U32>:
  cat([u8(typ), u16(771), vec16(body)])

# The suite's traffic key length: 16 for AES-128-GCM, 32 for ChaCha20.
def key_len(+suite: U32) -> U32:
  Bool.pick(U32, U32.is_eq(suite, 4865), 16, 32)

def is_suite(+suite: U32) -> Bool:
  U32.is_eq(suite, 4865) || U32.is_eq(suite, 4867)

# The AEAD follows the key: a 16-byte key is AES-128-GCM, else ChaCha20-
# Poly1305. Keys carry the suite, so no record state has to.
def seal_go(gcm: Bool, +key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  match gcm:
    case True{}:
      Suite.gcm_seal(key, nonce, aad, pt)
    case False{}:
      Suite.chacha_seal(key, nonce, aad, pt)

def open_go(gcm: Bool, +key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ct: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match gcm:
    case True{}:
      Suite.gcm_open(key, nonce, aad, ct)
    case False{}:
      Suite.chacha_open(key, nonce, aad, ct)

def seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  seal_go(U32.is_eq(len(key), 16), key, nonce, aad, pt)

def open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ct: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  open_go(U32.is_eq(len(key), 16), key, nonce, aad, ct)

# 5.2: the inner plaintext is content | type; the record header is the AAD.
def protect(+key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +typ: U32, +content: List<&2, U32>) -> List<&2, U32>:
  +inner = List.append(&2, U32, content, [typ])
  +hdr = cat([[23], u16(771), u16((len(inner) + 16 : U32))])
  List.append(&2, U32, hdr, seal(key, nonce(iv, seq), hdr, inner))

# Strip the zero padding and the content type from a decrypted record.
type Inner is Data:
  Inner{typ: U32, content: +List<U32>}

def head_zero(xs: List<&2, U32>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{b, t}:
      U32.is_zero(b)

# Drop the trailing zero padding (the list is reversed, so it is leading
# here). `zero` says whether the head is zero; it is computed by the caller,
# so only one branch ever runs (a Bool.pick would recurse on every call).
def drop_zeros(rev: List<&2, U32>, zero: Bool) -> List<&2, U32>:
  match rev:
    case Nil{}:
      Nil{}
    case Con{+b, +t}:
      match zero:
        case True{}:
          drop_zeros(t, head_zero(t))
        case False{}:
          Con{b, t}

def inner_from(rev: List<&2, U32>) -> Inner:
  match rev:
    case Nil{}:
      Inner{0, Nil{}}
    case Con{b, t}:
      Inner{b, List.reverse(&2, U32, t)}

def strip_go(+rev: List<&2, U32>) -> Inner:
  inner_from(drop_zeros(rev, head_zero(rev)))

def inner_of(m: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Inner>:
  match m:
    case None{}:
      None{}
    case Some{value}:
      Some{strip_go(List.reverse(&2, U32, value))}

# Decrypt one record body (after the 5-byte header `hdr`); None if the tag
# does not verify.
def unprotect(+key: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +hdr: List<&2, U32>, +body: List<&2, U32>) -> Maybe<&2, Inner>:
  inner_of(open(key, nonce(iv, seq), hdr, body))

# ---- handshake message stream ---------------------------------------------------------

# Split a byte stream into whole handshake messages (type, u24 length, body).
# Returns the messages and the leftover bytes of an incomplete one.
type Msgs is Data:
  Msgs{msgs: +List<List<&2, U32>>, rest: +List<U32>}

def whole_msg(+bs: List<&2, U32>) -> Bool:
  (len(bs) >= 4 : U32) && (len(bs) >= (4 + get24(bs, 1n) : U32) : U32)

# `go`: a whole message is at the front (computed by the caller, see drop_zeros).
def split_msgs_go(fuel: Nat, +bs: List<&2, U32>, +acc: List<&2, List<&2, U32>>, go: Bool) -> Msgs:
  match fuel:
    case 0n:
      Msgs{List.reverse(&2, List<&2, U32>, acc), bs}
    case 1n+k:
      match go:
        case False{}:
          Msgs{List.reverse(&2, List<&2, U32>, acc), bs}
        case True{}:
          +n = U32.to_nat((4 + get24(bs, 1n) : U32))
          +rest = List.drop(&2, U32, bs, n)
          split_msgs_go(k, rest, List.take(&2, U32, bs, n) <> acc, whole_msg(rest))

def split_msgs(fuel: Nat, +bs: List<&2, U32>, +acc: List<&2, List<&2, U32>>) -> Msgs:
  split_msgs_go(fuel, bs, acc, whole_msg(bs))

def msg_type(+m: List<&2, U32>) -> U32:
  nth(m, 0n)
