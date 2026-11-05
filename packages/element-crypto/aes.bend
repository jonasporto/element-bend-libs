import Base
import ./aes_sbox.bend as Sbox

# AES-128 encryption (FIPS-197), the block cipher of the TLS 1.3 suite
# TLS_AES_128_GCM_SHA256. GCM uses only the forward direction, so there is
# no decryption here. The state is 16 bytes in FIPS order: byte r + 4c is
# row r of column c. Keys and blocks are bytes (List<U32>), as in chacha20.

type B16 is Data:
  B16{b0: U32, b1: U32, b2: U32, b3: U32, b4: U32, b5: U32, b6: U32, b7: U32, b8: U32, b9: U32, b10: U32, b11: U32, b12: U32, b13: U32, b14: U32, b15: U32}

def or0(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{value}:
      value

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  or0(List.get(&2, U32, xs, n))

def of_bytes(+bs: List<&2, U32>) -> B16:
  B16{nth(bs, 0n), nth(bs, 1n), nth(bs, 2n), nth(bs, 3n), nth(bs, 4n), nth(bs, 5n), nth(bs, 6n), nth(bs, 7n),
      nth(bs, 8n), nth(bs, 9n), nth(bs, 10n), nth(bs, 11n), nth(bs, 12n), nth(bs, 13n), nth(bs, 14n), nth(bs, 15n)}

def to_bytes(s: B16) -> List<&2, U32>:
  match s:
    case B16{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15}:
      [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15]

def xor16(x: B16, y: B16) -> B16:
  match x y:
    case B16{a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15} B16{c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15}:
      B16{U32.xor(a0, c0), U32.xor(a1, c1), U32.xor(a2, c2), U32.xor(a3, c3), U32.xor(a4, c4), U32.xor(a5, c5), U32.xor(a6, c6), U32.xor(a7, c7),
          U32.xor(a8, c8), U32.xor(a9, c9), U32.xor(a10, c10), U32.xor(a11, c11), U32.xor(a12, c12), U32.xor(a13, c13), U32.xor(a14, c14), U32.xor(a15, c15)}

def s(+x: U32) -> U32:
  Sbox.sub(x)

# SubBytes and ShiftRows together (5.1.1, 5.1.2): row r turns left by r.
def sub_shift(st: B16) -> B16:
  match st:
    case B16{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15}:
      B16{s(b0), s(b5), s(b10), s(b15), s(b4), s(b9), s(b14), s(b3),
          s(b8), s(b13), s(b2), s(b7), s(b12), s(b1), s(b6), s(b11)}

# multiplication by x in GF(2^8), without a branch: the reduction is 0x1b
# times the bit that falls off
def xt(+b: U32) -> U32:
  U32.xor(((b * 2 : U32) % 256 : U32), ((b / 128 : U32) * 27 : U32))

type C4 is Data:
  C4{r0: U32, r1: U32, r2: U32, r3: U32}

# MixColumns on one column (5.1.3): {02}a0+{03}a1+a2+a3 and its rotations.
def mix(+a0: U32, +a1: U32, +a2: U32, +a3: U32) -> C4:
  +all = U32.xor(U32.xor(a0, a1), U32.xor(a2, a3))
  C4{U32.xor(U32.xor(a0, all), xt(U32.xor(a0, a1))), U32.xor(U32.xor(a1, all), xt(U32.xor(a1, a2))),
     U32.xor(U32.xor(a2, all), xt(U32.xor(a2, a3))), U32.xor(U32.xor(a3, all), xt(U32.xor(a3, a0)))}

def cols(m0: C4, m1: C4, m2: C4, m3: C4) -> B16:
  match m0 m1 m2 m3:
    case C4{c0, c1, c2, c3} C4{c4, c5, c6, c7} C4{c8, c9, c10, c11} C4{c12, c13, c14, c15}:
      B16{c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15}

def mix_cols(st: B16) -> B16:
  match st:
    case B16{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15}:
      cols(mix(b0, b1, b2, b3), mix(b4, b5, b6, b7), mix(b8, b9, b10, b11), mix(b12, b13, b14, b15))

# Key expansion (5.2): the next round key from the last and its Rcon.
def next_key(k: B16, +rcon: U32) -> B16:
  match k:
    case B16{p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, +p12, +p13, +p14, +p15}:
      +n0 = U32.xor(p0, U32.xor(s(p13), rcon))
      +n1 = U32.xor(p1, s(p14))
      +n2 = U32.xor(p2, s(p15))
      +n3 = U32.xor(p3, s(p12))
      +n4 = U32.xor(p4, n0)
      +n5 = U32.xor(p5, n1)
      +n6 = U32.xor(p6, n2)
      +n7 = U32.xor(p7, n3)
      +n8 = U32.xor(p8, n4)
      +n9 = U32.xor(p9, n5)
      +n10 = U32.xor(p10, n6)
      +n11 = U32.xor(p11, n7)
      B16{n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, U32.xor(p12, n8), U32.xor(p13, n9), U32.xor(p14, n10), U32.xor(p15, n11)}

def expand_go(n: Nat, +k: B16, +rcon: U32) -> List<&2, B16>:
  match n:
    case 0n:
      [k]
    case 1n+r:
      k <> expand_go(r, next_key(k, rcon), xt(rcon))

# The 11 round keys of a 16-byte key.
def expand(+key: List<&2, U32>) -> List<&2, B16>:
  expand_go(10n, of_bytes(key), 1)

# Rounds 1-9 mix the columns; the last round (no key after it) does not.
def rounds(ks: List<&2, B16>, +st: B16) -> B16:
  match ks:
    case Nil{}:
      st
    case Con{+k, t}:
      match t:
        case Nil{}:
          xor16(sub_shift(st), k)
        case Con{k2, t2}:
          rounds(Con{k2, t2}, xor16(mix_cols(sub_shift(st)), k))

def encrypt_with(ks: List<&2, B16>, +block: B16) -> B16:
  match ks:
    case Nil{}:
      block
    case Con{+k, t}:
      rounds(t, xor16(block, k))

# One 16-byte block under a 16-byte key.
def encrypt(+key: List<&2, U32>, +block: List<&2, U32>) -> List<&2, U32>:
  to_bytes(encrypt_with(expand(key), of_bytes(block)))
