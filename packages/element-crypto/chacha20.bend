import Base

# ChaCha20 (RFC 8439 section 2.3-2.4): the stream cipher of the TLS 1.3 suite
# TLS_CHACHA20_POLY1305_SHA256. Keys, nonces and data are bytes (List<U32>).
# rotl(x, n) = (x * 2^n) | (x / 2^(32-n)) on wrapping U32.

type S16 is Data:
  S16{x0: U32, x1: U32, x2: U32, x3: U32, x4: U32, x5: U32, x6: U32, x7: U32, x8: U32, x9: U32, x10: U32, x11: U32, x12: U32, x13: U32, x14: U32, x15: U32}

type Q4 is Data:
  Q4{a: U32, b: U32, c: U32, d: U32}

def q_a(q: Q4) -> U32:
  match q:
    case Q4{a, b, c, d}:
      a

def q_b(q: Q4) -> U32:
  match q:
    case Q4{a, b, c, d}:
      b

def q_c(q: Q4) -> U32:
  match q:
    case Q4{a, b, c, d}:
      c

def q_d(q: Q4) -> U32:
  match q:
    case Q4{a, b, c, d}:
      d

# rotl by n, given hi = 2^n and lo = 2^(32 - n).
def rotl(+x: U32, +hi: U32, +lo: U32) -> U32:
  U32.or((x * hi : U32), (x / lo : U32))

# The quarter round (2.1): add, xor, rotate by 16, 12, 8, 7.
def qr(+a: U32, +b: U32, +c: U32, +d: U32) -> Q4:
  +a1 = (a + b : U32)
  +d1 = rotl(U32.xor(d, a1), 65536, 65536)
  +c1 = (c + d1 : U32)
  +b1 = rotl(U32.xor(b, c1), 4096, 1048576)
  +a2 = (a1 + b1 : U32)
  +d2 = rotl(U32.xor(d1, a2), 256, 16777216)
  +c2 = (c1 + d2 : U32)
  +b2 = rotl(U32.xor(b1, c2), 128, 33554432)
  Q4{a2, b2, c2, d2}

def column_round(st: S16) -> S16:
  match st:
    case S16{+x0, +x1, +x2, +x3, +x4, +x5, +x6, +x7, +x8, +x9, +x10, +x11, +x12, +x13, +x14, +x15}:
      +q0 = qr(x0, x4, x8, x12)
      +q1 = qr(x1, x5, x9, x13)
      +q2 = qr(x2, x6, x10, x14)
      +q3 = qr(x3, x7, x11, x15)
      S16{q_a(q0), q_a(q1), q_a(q2), q_a(q3), q_b(q0), q_b(q1), q_b(q2), q_b(q3), q_c(q0), q_c(q1), q_c(q2), q_c(q3), q_d(q0), q_d(q1), q_d(q2), q_d(q3)}

def diagonal_round(st: S16) -> S16:
  match st:
    case S16{+x0, +x1, +x2, +x3, +x4, +x5, +x6, +x7, +x8, +x9, +x10, +x11, +x12, +x13, +x14, +x15}:
      +q0 = qr(x0, x5, x10, x15)
      +q1 = qr(x1, x6, x11, x12)
      +q2 = qr(x2, x7, x8, x13)
      +q3 = qr(x3, x4, x9, x14)
      S16{q_a(q0), q_a(q1), q_a(q2), q_a(q3), q_b(q3), q_b(q0), q_b(q1), q_b(q2), q_c(q2), q_c(q3), q_c(q0), q_c(q1), q_d(q1), q_d(q2), q_d(q3), q_d(q0)}

def double_rounds(n: Nat, st: S16) -> S16:
  match n:
    case 0n:
      st
    case 1n+r:
      double_rounds(r, diagonal_round(column_round(st)))

def add16(x: S16, y: S16) -> S16:
  match x y:
    case S16{a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15} S16{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15}:
      S16{(a0 + b0 : U32), (a1 + b1 : U32), (a2 + b2 : U32), (a3 + b3 : U32), (a4 + b4 : U32), (a5 + b5 : U32), (a6 + b6 : U32), (a7 + b7 : U32), (a8 + b8 : U32), (a9 + b9 : U32), (a10 + b10 : U32), (a11 + b11 : U32), (a12 + b12 : U32), (a13 + b13 : U32), (a14 + b14 : U32), (a15 + b15 : U32)}

def or0(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{value}:
      value

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  or0(List.get(&2, U32, xs, n))

# Little-endian word from 4 bytes at offset `i`.
def le32_at(+bs: List<&2, U32>, +i: Nat) -> U32:
  (nth(bs, i) + (nth(bs, Nat.add(i, 1n)) * 256 : U32) + (nth(bs, Nat.add(i, 2n)) * 65536 : U32) + (nth(bs, Nat.add(i, 3n)) * 16777216 : U32) : U32)

def le_bytes(+x: U32) -> List<&2, U32>:
  [(x % 256 : U32), (x / 256 % 256 : U32), (x / 65536 % 256 : U32), (x / 16777216 : U32)]

# 2.3: constants, key (8 words), block counter, nonce (3 words).
def init(+key: List<&2, U32>, +counter: U32, +nonce: List<&2, U32>) -> S16:
  S16{
    1634760805, 857760878, 2036477234, 1797285236,
    le32_at(key, 0n), le32_at(key, 4n), le32_at(key, 8n), le32_at(key, 12n),
    le32_at(key, 16n), le32_at(key, 20n), le32_at(key, 24n), le32_at(key, 28n),
    counter, le32_at(nonce, 0n), le32_at(nonce, 4n), le32_at(nonce, 8n)
  }

def serialize(st: S16) -> List<&2, U32>:
  match st:
    case S16{x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15}:
      List.concat(&2, U32, [le_bytes(x0), le_bytes(x1), le_bytes(x2), le_bytes(x3), le_bytes(x4), le_bytes(x5), le_bytes(x6), le_bytes(x7), le_bytes(x8), le_bytes(x9), le_bytes(x10), le_bytes(x11), le_bytes(x12), le_bytes(x13), le_bytes(x14), le_bytes(x15)])

# 2.3.2: the 64-byte keystream block.
def block(+key: List<&2, U32>, +counter: U32, +nonce: List<&2, U32>) -> List<&2, U32>:
  +st = init(key, counter, nonce)
  serialize(add16(double_rounds(10n, st), st))

def xor_with(xs: List<&2, U32>, ks: List<&2, U32>) -> List<&2, U32>:
  match xs ks:
    case Con{x, xt} Con{k, kt}:
      U32.xor(x, k) <> xor_with(xt, kt)
    case _ _:
      Nil{}

# 2.4: encrypt (or decrypt) `data`, one keystream block per 64 bytes.
def crypt_go(n: Nat, +key: List<&2, U32>, +counter: U32, +nonce: List<&2, U32>, +data: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      List.append(&2, U32,
        xor_with(List.take(&2, U32, data, 64n), block(key, counter, nonce)),
        crypt_go(r, key, (counter + 1 : U32), nonce, List.drop(&2, U32, data, 64n)))

def crypt(+key: List<&2, U32>, +counter: U32, +nonce: List<&2, U32>, +data: List<&2, U32>) -> List<&2, U32>:
  crypt_go(U32.to_nat(((U32.from_nat(List.length(&2, U32, data)) + 63 : U32) / 64 : U32)), key, counter, nonce, data)
