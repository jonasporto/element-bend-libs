import Base

# SHA-256 (FIPS 180-4). Input: bytes (0..255) as a List<U32>. Output: the
# 32-byte digest, or its lowercase hex. Round constants from FIPS 180-4
# section 4.2.2 (checked against BearSSL src/hash/sha2small.c, MIT).
#
# Bend has no hex literals and no rotate: constants are decimal, and
# rotr(x, n) is (x / 2^n) | (x * 2^(32-n)) on wrapping U32 arithmetic.

def k_table() -> List<&2, U32>:
  [
    1116352408, 1899447441, 3049323471, 3921009573,
    961987163, 1508970993, 2453635748, 2870763221,
    3624381080, 310598401, 607225278, 1426881987,
    1925078388, 2162078206, 2614888103, 3248222580,
    3835390401, 4022224774, 264347078, 604807628,
    770255983, 1249150122, 1555081692, 1996064986,
    2554220882, 2821834349, 2952996808, 3210313671,
    3336571891, 3584528711, 113926993, 338241895,
    666307205, 773529912, 1294757372, 1396182291,
    1695183700, 1986661051, 2177026350, 2456956037,
    2730485921, 2820302411, 3259730800, 3345764771,
    3516065817, 3600352804, 4094571909, 275423344,
    430227734, 506948616, 659060556, 883997877,
    958139571, 1322822218, 1537002063, 1747873779,
    1955562222, 2024104815, 2227730452, 2361852424,
    2428436474, 2756734187, 3204031479, 3329325298
  ]

def xor3(+a: U32, +b: U32, +c: U32) -> U32:
  U32.xor(U32.xor(a, b), c)

# rotr by n, given lo = 2^n and hi = 2^(32 - n).
def rotr(+x: U32, +lo: U32, +hi: U32) -> U32:
  U32.or((x / lo : U32), (x * hi : U32))

def big_s0(+a: U32) -> U32:
  xor3(rotr(a, 4, 1073741824), rotr(a, 8192, 524288), rotr(a, 4194304, 1024))

def big_s1(+e: U32) -> U32:
  xor3(rotr(e, 64, 67108864), rotr(e, 2048, 2097152), rotr(e, 33554432, 128))

def small_s0(+x: U32) -> U32:
  xor3(rotr(x, 128, 33554432), rotr(x, 262144, 16384), (x / 8 : U32))

def small_s1(+x: U32) -> U32:
  xor3(rotr(x, 131072, 32768), rotr(x, 524288, 8192), (x / 1024 : U32))

def ch(+e: U32, +f: U32, +g: U32) -> U32:
  U32.xor(U32.and(e, f), U32.and(U32.not(e), g))

def maj(+a: U32, +b: U32, +c: U32) -> U32:
  xor3(U32.and(a, b), U32.and(a, c), U32.and(b, c))

type H8 is Data:
  H8{a: U32, b: U32, c: U32, d: U32, e: U32, f: U32, g: U32, h: U32}

def iv() -> H8:
  H8{1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225}

def round(st: H8, +k: U32, +w: U32) -> H8:
  match st:
    case H8{+a, +b, +c, +d, +e, +f, +g, +h}:
      +t1 = (h + big_s1(e) + ch(e, f, g) + k + w : U32)
      +t2 = (big_s0(a) + maj(a, b, c) : U32)
      H8{(t1 + t2 : U32), a, b, c, (d + t1 : U32), e, f, g}

def rounds(ks: List<&2, U32>, ws: List<&2, U32>, st: H8) -> H8:
  match ks ws:
    case Con{k, kt} Con{w, wt}:
      rounds(kt, wt, round(st, k, w))
    case _ _:
      st

def or0(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{value}:
      value

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  or0(List.get(&2, U32, xs, n))

def drop1(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# Message schedule: the 16 block words, then 48 more, each from a sliding
# window of the last 16 (oldest first).
def sched(n: Nat, +win: List<&2, U32>, out: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      List.reverse(&2, U32, out)
    case 1n+r:
      +w = (small_s1(nth(win, 14n)) + nth(win, 9n) + small_s0(nth(win, 1n)) + nth(win, 0n) : U32)
      sched(r, List.append(&2, U32, drop1(win), [w]), w <> out)

def be32(+b0: U32, +b1: U32, +b2: U32, +b3: U32) -> U32:
  ((b0 * 16777216 : U32) + (b1 * 65536 : U32) + (b2 * 256 : U32) + b3 : U32)

# Big-endian words from bytes (length a multiple of 4).
def words(n: Nat, +bs: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      be32(nth(bs, 0n), nth(bs, 1n), nth(bs, 2n), nth(bs, 3n)) <> words(r, List.drop(&2, U32, bs, 4n))

def add8(x: H8, y: H8) -> H8:
  match x y:
    case H8{a, b, c, d, e, f, g, h} H8{a2, b2, c2, d2, e2, f2, g2, h2}:
      H8{(a + a2 : U32), (b + b2 : U32), (c + c2 : U32), (d + d2 : U32),
         (e + e2 : U32), (f + f2 : U32), (g + g2 : U32), (h + h2 : U32)}

def compress(+st: H8, +block: List<&2, U32>) -> H8:
  +w16 = words(16n, block)
  add8(st, rounds(k_table(), sched(48n, w16, List.reverse(&2, U32, w16)), st))

def blocks(n: Nat, +bs: List<&2, U32>, st: H8) -> H8:
  match n:
    case 0n:
      st
    case 1n+r:
      blocks(r, List.drop(&2, U32, bs, 64n), compress(st, List.take(&2, U32, bs, 64n)))

def zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      0 <> zeros(r)

def bytes32(+x: U32) -> List<&2, U32>:
  [(x / 16777216 : U32), (x / 65536 % 256 : U32), (x / 256 % 256 : U32), (x % 256 : U32)]

# Padding (5.1.1): 0x80, zeros to 56 mod 64, then the bit length as 64 bits.
def pad(+bs: List<&2, U32>) -> List<&2, U32>:
  +len = U32.from_nat(List.length(&2, U32, bs))
  List.concat(&2, U32, [
    bs, [128], zeros(U32.to_nat(((119 - (len % 64 : U32)) % 64 : U32))),
    bytes32((len / 536870912 : U32)), bytes32((len * 8 : U32))
  ])

def digest_words(+bs: List<&2, U32>) -> H8:
  +p = pad(bs)
  blocks(U32.to_nat((U32.from_nat(List.length(&2, U32, p)) / 64 : U32)), p, iv())

def h8_bytes(st: H8) -> List<&2, U32>:
  match st:
    case H8{a, b, c, d, e, f, g, h}:
      List.concat(&2, U32, [bytes32(a), bytes32(b), bytes32(c), bytes32(d), bytes32(e), bytes32(f), bytes32(g), bytes32(h)])

def digest(+bs: List<&2, U32>) -> List<&2, U32>:
  h8_bytes(digest_words(bs))

def hex_digit(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32, (n < 10 : U32), (n + 48 : U32), (n + 87 : U32)))

def hex(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case Con{+b, t}:
      SCon{hex_digit((b / 16 : U32)), SCon{hex_digit((b % 16 : U32)), hex(t)}}

def bytes_of(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{h, t}:
      Char.to_u32(h) <> bytes_of(t)

def hex_of_text(s: String) -> String:
  hex(digest(bytes_of(s)))
