import Base
import ./aes.bend as Aes
import ./chacha20.bend as ChaCha
import ./poly1305.bend as Poly

# AES-128-GCM (NIST SP 800-38D) with a 96-bit nonce, the AEAD of the TLS 1.3
# suite TLS_AES_128_GCM_SHA256 (RFC 8446 9.1: a TLS client MUST offer it).
# seal/open have the shapes of poly1305.bend's, so a record is protected the
# same way whichever suite the server chose.

# A 128-bit block as four big-endian words; a is the most significant.
type W4 is Data:
  W4{a: U32, b: U32, c: U32, d: U32}

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  ChaCha.nth(xs, n)

def be32_at(+bs: List<&2, U32>, +i: Nat) -> U32:
  +x0 = nth(bs, i)
  +x1 = nth(bs, Nat.add(i, 1n))
  +x2 = nth(bs, Nat.add(i, 2n))
  +x3 = nth(bs, Nat.add(i, 3n))
  ((x0 * 16777216 : U32) + (x1 * 65536 : U32) + (x2 * 256 : U32) + x3 : U32)

# up to 16 bytes; a short final block is padded with zeros (nth answers 0)
def w4_of(+bs: List<&2, U32>) -> W4:
  W4{be32_at(bs, 0n), be32_at(bs, 4n), be32_at(bs, 8n), be32_at(bs, 12n)}

def be_bytes(+x: U32) -> List<&2, U32>:
  [(x / 16777216 : U32), (x / 65536 % 256 : U32), (x / 256 % 256 : U32), (x % 256 : U32)]

def w4_bytes(w: W4) -> List<&2, U32>:
  match w:
    case W4{a, b, c, d}:
      List.concat(&2, U32, [be_bytes(a), be_bytes(b), be_bytes(c), be_bytes(d)])

def wxor(x: W4, y: W4) -> W4:
  match x y:
    case W4{a, b, c, d} W4{e, f, g, h}:
      W4{U32.xor(a, e), U32.xor(b, f), U32.xor(c, g), U32.xor(d, h)}

def wand(x: W4, +m: U32) -> W4:
  match x:
    case W4{a, b, c, d}:
      W4{U32.and(a, m), U32.and(b, m), U32.and(c, m), U32.and(d, m)}

# V >> 1, and R = 11100001 || 0^120 folded in when a bit fell off (6.3)
def shr1(v: W4) -> W4:
  match v:
    case W4{+a, +b, +c, +d}:
      W4{U32.xor((a / 2 : U32), ((d % 2 : U32) * 3774873600 : U32)),
         ((b / 2 : U32) + ((a % 2 : U32) * 2147483648 : U32) : U32),
         ((c / 2 : U32) + ((b % 2 : U32) * 2147483648 : U32) : U32),
         ((d / 2 : U32) + ((c % 2 : U32) * 2147483648 : U32) : U32)}

type ZV is Data:
  ZV{z: W4, v: W4}

# Algorithm 1 of 6.3 over the 32 bits of one word of X, most significant
# first. Z ^= V when the bit is set, as a mask (0 or all ones), no branch.
def bits(n: Nat, +x: U32, zv: ZV) -> ZV:
  match n:
    case 0n:
      zv
    case 1n+k:
      match zv:
        case ZV{+z, +v}:
          +m = ((x / 2147483648 : U32) * 4294967295 : U32)
          bits(k, (x * 2 : U32), ZV{wxor(z, wand(v, m)), shr1(v)})

def z_of(zv: ZV) -> W4:
  match zv:
    case ZV{z, v}:
      z

# X . H in GF(2^128)
def gmul(x: W4, +h: W4) -> W4:
  match x:
    case W4{a, b, c, d}:
      z_of(bits(32n, d, bits(32n, c, bits(32n, b, bits(32n, a, ZV{W4{0, 0, 0, 0}, h})))))

def blocks(+bs: List<&2, U32>) -> Nat:
  U32.to_nat(((U32.from_nat(List.length(&2, U32, bs)) + 15 : U32) / 16 : U32))

# Y_i = (Y_{i-1} ^ X_i) . H over the data, zero-padded to whole blocks
def ghash_go(n: Nat, +h: W4, +y: W4, +data: List<&2, U32>) -> W4:
  match n:
    case 0n:
      y
    case 1n+r:
      ghash_go(r, h, gmul(wxor(y, w4_of(List.take(&2, U32, data, 16n))), h), List.drop(&2, U32, data, 16n))

def len_block(+aad: List<&2, U32>, +ct: List<&2, U32>) -> W4:
  W4{0, (U32.from_nat(List.length(&2, U32, aad)) * 8 : U32), 0, (U32.from_nat(List.length(&2, U32, ct)) * 8 : U32)}

# GHASH_H(A || 0* || C || 0* || [len A]64 || [len C]64)
def ghash(+h: W4, +aad: List<&2, U32>, +ct: List<&2, U32>) -> W4:
  +ya = ghash_go(blocks(aad), h, W4{0, 0, 0, 0}, aad)
  +yc = ghash_go(blocks(ct), h, ya, ct)
  gmul(wxor(yc, len_block(aad, ct)), h)

def block_at(+ks: List<&2, Aes.B16>, +nonce: List<&2, U32>, +ctr: U32) -> List<&2, U32>:
  Aes.to_bytes(Aes.encrypt_with(ks, Aes.of_bytes(List.append(&2, U32, nonce, be_bytes(ctr)))))

# GCTR from counter `ctr`: one AES block of keystream per 16 bytes
def ctr_go(n: Nat, +ks: List<&2, Aes.B16>, +nonce: List<&2, U32>, +ctr: U32, +data: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      List.append(&2, U32,
        ChaCha.xor_with(List.take(&2, U32, data, 16n), block_at(ks, nonce, ctr)),
        ctr_go(r, ks, nonce, (ctr + 1 : U32), List.drop(&2, U32, data, 16n)))

# H = E(K, 0^128); the tag is E(K, J0) ^ GHASH, J0 = nonce || 1; data from 2
def tag_with(+ks: List<&2, Aes.B16>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ct: List<&2, U32>) -> List<&2, U32>:
  +h = w4_of(Aes.to_bytes(Aes.encrypt_with(ks, Aes.of_bytes(Nil{}))))
  w4_bytes(wxor(w4_of(block_at(ks, nonce, 1)), ghash(h, aad, ct)))

def tag_of(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ct: List<&2, U32>) -> List<&2, U32>:
  tag_with(Aes.expand(key), nonce, aad, ct)

def crypt_with(+ks: List<&2, Aes.B16>, +nonce: List<&2, U32>, +data: List<&2, U32>) -> List<&2, U32>:
  ctr_go(blocks(data), ks, nonce, 2, data)

# ciphertext | tag
def seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  +ks = Aes.expand(key)
  +ct = crypt_with(ks, nonce, pt)
  List.append(&2, U32, ct, tag_with(ks, nonce, aad, ct))

# the plaintext is computed only when the tag verifies (a match, not a pick)
def opened(ok: Bool, +ks: List<&2, Aes.B16>, +nonce: List<&2, U32>, +ct: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      Some{crypt_with(ks, nonce, ct)}
    case False{}:
      None{}

def open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  +ks = Aes.expand(key)
  +n = List.length(&2, U32, sealed)
  +ct = List.take(&2, U32, sealed, Nat.sub(n, 16n))
  opened(Poly.eq_bytes(tag_with(ks, nonce, aad, ct), List.drop(&2, U32, sealed, Nat.sub(n, 16n))), ks, nonce, ct)
