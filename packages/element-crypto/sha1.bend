import Base
import ./sha256.bend as Sha256

# SHA-1 (FIPS 180-4 6.1). Broken for signatures and not used for any here:
# the WebSocket handshake (RFC 6455 4.2.2) names it for Sec-WebSocket-Accept.
# Same padding and word layout as SHA-256 (sha256.bend).

type H5 is Data:
  H5{a: U32, b: U32, c: U32, d: U32, e: U32}

def rotl(+x: U32, +n: U32) -> U32:
  U32.or((x * U32.shln(1, U32.to_nat(n)) : U32), (x / U32.shln(1, U32.to_nat((32 - n : U32))) : U32))

def f_of(+t: U32, +b: U32, +c: U32, +d: U32) -> U32:
  Bool.pick(U32, (t < 20 : U32), U32.or(U32.and(b, c), U32.and(U32.not(b), d)),
    Bool.pick(U32, (t < 40 : U32), U32.xor(U32.xor(b, c), d),
      Bool.pick(U32, (t < 60 : U32), U32.or(U32.or(U32.and(b, c), U32.and(b, d)), U32.and(c, d)), U32.xor(U32.xor(b, c), d))))

def k_of(+t: U32) -> U32:
  Bool.pick(U32, (t < 20 : U32), 1518500249, Bool.pick(U32, (t < 40 : U32), 1859775393, Bool.pick(U32, (t < 60 : U32), 2400959708, 3395469782)))

def round(+st: H5, +t: U32, +w: U32) -> H5:
  match st:
    case H5{+a, +b, +c, +d, +e}:
      H5{(rotl(a, 5) + f_of(t, b, c, d) + e + k_of(t) + w : U32), a, rotl(b, 30), c, d}

def rounds(ws: List<&2, U32>, +t: U32, +st: H5) -> H5:
  match ws:
    case Nil{}:
      st
    case Con{w, rest}:
      rounds(rest, (t + 1 : U32), round(st, t, w))

def drop1(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# 80 words from a 16-word window: w[t] = rotl1(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]).
def sched(n: Nat, +win: List<&2, U32>, +out: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      List.reverse(&2, U32, out)
    case 1n+r:
      +w = rotl(U32.xor(U32.xor(Sha256.nth(win, 13n), Sha256.nth(win, 8n)), U32.xor(Sha256.nth(win, 2n), Sha256.nth(win, 0n))), 1)
      sched(r, List.append(&2, U32, drop1(win), [w]), w <> out)

def add5(x: H5, y: H5) -> H5:
  match x y:
    case H5{a, b, c, d, e} H5{a2, b2, c2, d2, e2}:
      H5{(a + a2 : U32), (b + b2 : U32), (c + c2 : U32), (d + d2 : U32), (e + e2 : U32)}

def compress(+st: H5, +block: List<&2, U32>) -> H5:
  +w16 = Sha256.words(16n, block)
  add5(st, rounds(sched(64n, w16, List.reverse(&2, U32, w16)), 0, st))

def blocks(n: Nat, +bs: List<&2, U32>, st: H5) -> H5:
  match n:
    case 0n:
      st
    case 1n+r:
      blocks(r, List.drop(&2, U32, bs, 64n), compress(st, List.take(&2, U32, bs, 64n)))

def h5_bytes(st: H5) -> List<&2, U32>:
  match st:
    case H5{a, b, c, d, e}:
      List.concat(&2, U32, [Sha256.bytes32(a), Sha256.bytes32(b), Sha256.bytes32(c), Sha256.bytes32(d), Sha256.bytes32(e)])

def digest(+bs: List<&2, U32>) -> List<&2, U32>:
  +p = Sha256.pad(bs)
  h5_bytes(blocks(U32.to_nat((U32.from_nat(List.length(&2, U32, p)) / 64 : U32)), p, H5{1732584193, 4023233417, 2562383102, 271733878, 3285377520}))
