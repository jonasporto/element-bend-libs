import Base
import ./chacha20.bend as ChaCha

# Poly1305 (RFC 8439 section 2.5) and the ChaCha20-Poly1305 AEAD (2.8).
#
# Arithmetic mod p = 2^130 - 5 with 17 limbs of 8 bits and U32 accumulators,
# after TweetNaCl's crypto_onetimeauth (public domain): Bend has no 64-bit
# integers, and 17 * 255 * 255 * 320 still fits in 32 bits. The factor 320
# folds limb 17 + k back to limb k: 2^136 = 2^6 * 2^130 = 320 (mod p).

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  ChaCha.nth(xs, n)

def zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      0 <> zeros(r)

# h + c, limb by limb, carrying 8 bits at a time (add1305).
def add_go(h: List<&2, U32>, c: List<&2, U32>, +u: U32) -> List<&2, U32>:
  match h c:
    case Con{hv, ht} Con{cv, ct}:
      +s = (u + hv + cv : U32)
      (s % 256 : U32) <> add_go(ht, ct, (s / 256 : U32))
    case _ _:
      Nil{}

def add(h: List<&2, U32>, c: List<&2, U32>) -> List<&2, U32>:
  add_go(h, c, 0)

# h * r mod p: the full product in 33 columns (sequential shifted adds, no
# indexing), then column 17 + k folds into column k times 320, because
# 2^136 = 2^6 * 2^130 = 320 (mod p). Column sums stay below 17 * 255^2, and
# 320 times that plus a column still fits in 32 bits.
def scale(xs: List<&2, U32>, +k: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      (x * k : U32) <> scale(t, k)

def zip_add_long(xs: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, xt}:
      match ys:
        case Nil{}:
          Con{x, xt}
        case Con{y, yt}:
          (x + y : U32) <> zip_add_long(xt, yt)

def add_at(off: Nat, acc: List<&2, U32>, ys: List<&2, U32>) -> List<&2, U32>:
  match off:
    case 0n:
      zip_add_long(acc, ys)
    case 1n+k:
      match acc:
        case Nil{}:
          Nil{}
        case Con{a, t}:
          a <> add_at(k, t, ys)

def mul_cols(hs: List<&2, U32>, +r: List<&2, U32>, acc: List<&2, U32>, +off: Nat) -> List<&2, U32>:
  match hs:
    case Nil{}:
      acc
    case Con{h, t}:
      mul_cols(t, r, add_at(off, acc, scale(r, h)), Nat.add(off, 1n))

def mul_go(+h: List<&2, U32>, +r: List<&2, U32>) -> List<&2, U32>:
  +cols = mul_cols(h, r, zeros(33n), 0n)
  zip_add_long(List.take(&2, U32, cols, 17n), scale(List.drop(&2, U32, cols, 17n), 320))

# Carry the first 16 limbs; returns them with the carry appended.
def carry16(n: Nat, h: List<&2, U32>, +u: U32) -> List<&2, U32>:
  match n:
    case 0n:
      [u]
    case 1n+k:
      match h:
        case Nil{}:
          [u]
        case Con{hv, ht}:
          +s = (u + hv : U32)
          (s % 256 : U32) <> carry16(k, ht, (s / 256 : U32))

def last(xs: List<&2, U32>) -> U32:
  nth(xs, 16n)

# After the multiply: squeeze limbs back to 8 bits, folding the bits above
# 2^130 back in times 5 (two passes, as in TweetNaCl).
def squeeze(+x: List<&2, U32>) -> List<&2, U32>:
  +p1 = carry16(16n, x, 0)
  +u1 = (nth(p1, 16n) + nth(x, 16n) : U32)
  +p2 = carry16(16n, List.take(&2, U32, p1, 16n), (5 * (u1 / 4 : U32) : U32))
  List.append(&2, U32, List.take(&2, U32, p2, 16n), [(nth(p2, 16n) + (u1 % 4 : U32) : U32)])

def clamp_byte(+i: U32, +b: U32) -> U32:
  Bool.pick(U32, U32.is_eq(i, 3) || U32.is_eq(i, 7) || U32.is_eq(i, 11) || U32.is_eq(i, 15), (b % 16 : U32),
    Bool.pick(U32, U32.is_eq(i, 4) || U32.is_eq(i, 8) || U32.is_eq(i, 12), U32.and(b, 252), b))

def clamp_go(xs: List<&2, U32>, +i: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      clamp_byte(i, x) <> clamp_go(t, (i + 1 : U32))

# One 16-byte block (the last may be short): c = block | 1, zero-padded to 17.
def block_limbs(+m: List<&2, U32>) -> List<&2, U32>:
  +b = List.take(&2, U32, m, 16n)
  List.concat(&2, U32, [b, [1], zeros(U32.to_nat((16 - U32.from_nat(List.length(&2, U32, b)) : U32)))])

def blocks(n: Nat, +m: List<&2, U32>, +r: List<&2, U32>, h: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      h
    case 1n+k:
      blocks(k, List.drop(&2, U32, m, 16n), r, squeeze(mul_go(add(h, block_limbs(m)), r)))

def minus_p() -> List<&2, U32>:
  [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]

# Reduce fully mod p: h - p if that does not go negative.
def freeze(+h: List<&2, U32>) -> List<&2, U32>:
  +d = add(h, minus_p())
  Bool.pick(List<&2, U32>, (last(d) >= 128 : U32), h, d)

# The 16-byte tag of `m` under the 32-byte one-time key (r | s).
def mac(+key: List<&2, U32>, +m: List<&2, U32>) -> List<&2, U32>:
  +r = List.append(&2, U32, clamp_go(List.take(&2, U32, key, 16n), 0), [0])
  +h = blocks(U32.to_nat(((U32.from_nat(List.length(&2, U32, m)) + 15 : U32) / 16 : U32)), m, r, zeros(17n))
  List.take(&2, U32, add(freeze(h), List.append(&2, U32, List.take(&2, U32, List.drop(&2, U32, key, 16n), 16n), [0])), 16n)

# ---- AEAD (2.8) ------------------------------------------------------------------

def pad16(+xs: List<&2, U32>) -> List<&2, U32>:
  zeros(U32.to_nat(((16 - (U32.from_nat(List.length(&2, U32, xs)) % 16 : U32)) % 16 : U32)))

def le64(+n: U32) -> List<&2, U32>:
  List.append(&2, U32, ChaCha.le_bytes(n), [0, 0, 0, 0])

def tag_of(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +ct: List<&2, U32>) -> List<&2, U32>:
  mac(
    List.take(&2, U32, ChaCha.block(key, 0, nonce), 32n),
    List.concat(&2, U32, [aad, pad16(aad), ct, pad16(ct),
      le64(U32.from_nat(List.length(&2, U32, aad))), le64(U32.from_nat(List.length(&2, U32, ct)))])
  )

# ciphertext | tag
def seal(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +pt: List<&2, U32>) -> List<&2, U32>:
  +ct = ChaCha.crypt(key, 1, nonce, pt)
  List.append(&2, U32, ct, tag_of(key, nonce, aad, ct))

def eq_bytes(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{x, xt} Con{y, yt}:
      U32.is_eq(x, y) && eq_bytes(xt, yt)
    case _ _:
      False{}

# Decrypt `ct | tag`; None if the tag does not verify (the plaintext is never
# released on a bad tag).
def open(+key: List<&2, U32>, +nonce: List<&2, U32>, +aad: List<&2, U32>, +sealed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  +n = List.length(&2, U32, sealed)
  +ct = List.take(&2, U32, sealed, Nat.sub(n, 16n))
  Bool.pick(Maybe<&2, List<&2, U32>>, eq_bytes(tag_of(key, nonce, aad, ct), List.drop(&2, U32, sealed, Nat.sub(n, 16n))),
    Some{ChaCha.crypt(key, 1, nonce, ct)}, None{})
