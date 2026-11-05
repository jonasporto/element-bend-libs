import Base
import ./sha256.bend as Sha256

# SHA-512 and SHA-384 (FIPS 180-4), for certificate signatures (ECDSA P-384,
# sha384WithRSAEncryption) and TLS suites that hash with SHA-384. Bend has no
# 64-bit integers: a word is a pair of U32 (hi, lo); addition carries from
# the low half. Round constants from BearSSL src/hash/sha2big.c (MIT).

type W is Data:
  W{hi: U32, lo: U32}

def add(a: W, b: W) -> W:
  match a b:
    case W{+ah, +al} W{+bh, +bl}:
      W{(ah + bh + Bool.pick(U32, ((al + bl : U32) < al : U32), 1, 0) : U32), (al + bl : U32)}

def xor(a: W, b: W) -> W:
  match a b:
    case W{ah, al} W{bh, bl}:
      W{U32.xor(ah, bh), U32.xor(al, bl)}

def and(a: W, b: W) -> W:
  match a b:
    case W{ah, al} W{bh, bl}:
      W{U32.and(ah, bh), U32.and(al, bl)}

def not(a: W) -> W:
  match a:
    case W{ah, al}:
      W{U32.not(ah), U32.not(al)}

# 2^n for n in 0..31 without walking a Nat by a large number.
def p2(+n: U32) -> U32:
  U32.shln(1, U32.to_nat(n))

# Rotate right by n (0 < n < 32) and by 32 + n.
def rotr_small(+x: W, +n: U32) -> W:
  match x:
    case W{+h, +l}:
      W{U32.or((h / p2(n) : U32), (l * p2((32 - n : U32)) : U32)), U32.or((l / p2(n) : U32), (h * p2((32 - n : U32)) : U32))}

def swap(x: W) -> W:
  match x:
    case W{h, l}:
      W{l, h}

def rotr(+x: W, +n: U32) -> W:
  Bool.pick(W, (n >= 32 : U32), rotr_small(swap(x), (n - 32 : U32)), rotr_small(x, n))

def shr(+x: W, +n: U32) -> W:
  match x:
    case W{+h, +l}:
      W{(h / p2(n) : U32), U32.or((l / p2(n) : U32), (h * p2((32 - n : U32)) : U32))}

def xor3(a: W, b: W, c: W) -> W:
  xor(xor(a, b), c)

def big_s0(+a: W) -> W:
  xor3(rotr(a, 28), rotr(a, 34), rotr(a, 39))

def big_s1(+e: W) -> W:
  xor3(rotr(e, 14), rotr(e, 18), rotr(e, 41))

def small_s0(+x: W) -> W:
  xor3(rotr(x, 1), rotr(x, 8), shr(x, 7))

def small_s1(+x: W) -> W:
  xor3(rotr(x, 19), rotr(x, 61), shr(x, 6))

def ch(+e: W, +f: W, +g: W) -> W:
  xor(and(e, f), and(not(e), g))

def maj(+a: W, +b: W, +c: W) -> W:
  xor3(and(a, b), and(a, c), and(b, c))

def k_table() -> List<&2, W>:
  [
    W{1116352408, 3609767458}, W{1899447441, 602891725},
    W{3049323471, 3964484399}, W{3921009573, 2173295548},
    W{961987163, 4081628472}, W{1508970993, 3053834265},
    W{2453635748, 2937671579}, W{2870763221, 3664609560},
    W{3624381080, 2734883394}, W{310598401, 1164996542},
    W{607225278, 1323610764}, W{1426881987, 3590304994},
    W{1925078388, 4068182383}, W{2162078206, 991336113},
    W{2614888103, 633803317}, W{3248222580, 3479774868},
    W{3835390401, 2666613458}, W{4022224774, 944711139},
    W{264347078, 2341262773}, W{604807628, 2007800933},
    W{770255983, 1495990901}, W{1249150122, 1856431235},
    W{1555081692, 3175218132}, W{1996064986, 2198950837},
    W{2554220882, 3999719339}, W{2821834349, 766784016},
    W{2952996808, 2566594879}, W{3210313671, 3203337956},
    W{3336571891, 1034457026}, W{3584528711, 2466948901},
    W{113926993, 3758326383}, W{338241895, 168717936},
    W{666307205, 1188179964}, W{773529912, 1546045734},
    W{1294757372, 1522805485}, W{1396182291, 2643833823},
    W{1695183700, 2343527390}, W{1986661051, 1014477480},
    W{2177026350, 1206759142}, W{2456956037, 344077627},
    W{2730485921, 1290863460}, W{2820302411, 3158454273},
    W{3259730800, 3505952657}, W{3345764771, 106217008},
    W{3516065817, 3606008344}, W{3600352804, 1432725776},
    W{4094571909, 1467031594}, W{275423344, 851169720},
    W{430227734, 3100823752}, W{506948616, 1363258195},
    W{659060556, 3750685593}, W{883997877, 3785050280},
    W{958139571, 3318307427}, W{1322822218, 3812723403},
    W{1537002063, 2003034995}, W{1747873779, 3602036899},
    W{1955562222, 1575990012}, W{2024104815, 1125592928},
    W{2227730452, 2716904306}, W{2361852424, 442776044},
    W{2428436474, 593698344}, W{2756734187, 3733110249},
    W{3204031479, 2999351573}, W{3329325298, 3815920427},
    W{3391569614, 3928383900}, W{3515267271, 566280711},
    W{3940187606, 3454069534}, W{4118630271, 4000239992},
    W{116418474, 1914138554}, W{174292421, 2731055270},
    W{289380356, 3203993006}, W{460393269, 320620315},
    W{685471733, 587496836}, W{852142971, 1086792851},
    W{1017036298, 365543100}, W{1126000580, 2618297676},
    W{1288033470, 3409855158}, W{1501505948, 4234509866},
    W{1607167915, 987167468}, W{1816402316, 1246189591}
  ]

type H8 is Data:
  H8{a: W, b: W, c: W, d: W, e: W, f: W, g: W, h: W}

def iv512() -> H8:
  H8{W{1779033703, 4089235720}, W{3144134277, 2227873595}, W{1013904242, 4271175723}, W{2773480762, 1595750129}, W{1359893119, 2917565137}, W{2600822924, 725511199}, W{528734635, 4215389547}, W{1541459225, 327033209}}

def iv384() -> H8:
  H8{W{3418070365, 3238371032}, W{1654270250, 914150663}, W{2438529370, 812702999}, W{355462360, 4144912697}, W{1731405415, 4290775857}, W{2394180231, 1750603025}, W{3675008525, 1694076839}, W{1203062813, 3204075428}}

def round(st: H8, +k: W, +w: W) -> H8:
  match st:
    case H8{+a, +b, +c, +d, +e, +f, +g, +h}:
      +t1 = add(add(add(add(h, big_s1(e)), ch(e, f, g)), k), w)
      +t2 = add(big_s0(a), maj(a, b, c))
      H8{add(t1, t2), a, b, c, add(d, t1), e, f, g}

def rounds(ks: List<&2, W>, ws: List<&2, W>, st: H8) -> H8:
  match ks ws:
    case Con{k, kt} Con{w, wt}:
      rounds(kt, wt, round(st, k, w))
    case _ _:
      st

def or0(m: Maybe<&2, W>) -> W:
  match m:
    case None{}:
      W{0, 0}
    case Some{value}:
      value

def nth(xs: List<&2, W>, n: Nat) -> W:
  or0(List.get(&2, W, xs, n))

def drop1(xs: List<&2, W>) -> List<&2, W>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# 80-word schedule from a 16-word window.
def sched(n: Nat, +win: List<&2, W>, out: List<&2, W>) -> List<&2, W>:
  match n:
    case 0n:
      List.reverse(&2, W, out)
    case 1n+r:
      +w = add(add(add(small_s1(nth(win, 14n)), nth(win, 9n)), small_s0(nth(win, 1n))), nth(win, 0n))
      sched(r, List.append(&2, W, drop1(win), [w]), w <> out)

def words(n: Nat, +bs: List<&2, U32>) -> List<&2, W>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      W{Sha256.be32(Sha256.nth(bs, 0n), Sha256.nth(bs, 1n), Sha256.nth(bs, 2n), Sha256.nth(bs, 3n)),
        Sha256.be32(Sha256.nth(bs, 4n), Sha256.nth(bs, 5n), Sha256.nth(bs, 6n), Sha256.nth(bs, 7n))}
        <> words(r, List.drop(&2, U32, bs, 8n))

def add8(x: H8, y: H8) -> H8:
  match x y:
    case H8{a, b, c, d, e, f, g, h} H8{a2, b2, c2, d2, e2, f2, g2, h2}:
      H8{add(a, a2), add(b, b2), add(c, c2), add(d, d2), add(e, e2), add(f, f2), add(g, g2), add(h, h2)}

def compress(+st: H8, +block: List<&2, U32>) -> H8:
  +w16 = words(16n, block)
  add8(st, rounds(k_table(), sched(64n, w16, List.reverse(&2, W, w16)), st))

def blocks(n: Nat, +bs: List<&2, U32>, st: H8) -> H8:
  match n:
    case 0n:
      st
    case 1n+r:
      blocks(r, List.drop(&2, U32, bs, 128n), compress(st, List.take(&2, U32, bs, 128n)))

# Padding (5.1.2): 0x80, zeros to 112 mod 128, then the bit length as 128 bits.
def pad(+bs: List<&2, U32>) -> List<&2, U32>:
  +len = U32.from_nat(List.length(&2, U32, bs))
  List.concat(&2, U32, [
    bs, [128], Sha256.zeros(U32.to_nat(((239 - (len % 128 : U32)) % 128 : U32))),
    Sha256.zeros(8n), Sha256.bytes32((len / 536870912 : U32)), Sha256.bytes32((len * 8 : U32))
  ])

def digest_words(+bs: List<&2, U32>, +iv: H8) -> H8:
  +p = pad(bs)
  blocks(U32.to_nat((U32.from_nat(List.length(&2, U32, p)) / 128 : U32)), p, iv)

def w_bytes(x: W) -> List<&2, U32>:
  match x:
    case W{h, l}:
      List.append(&2, U32, Sha256.bytes32(h), Sha256.bytes32(l))

def h8_bytes(st: H8) -> List<&2, U32>:
  match st:
    case H8{a, b, c, d, e, f, g, h}:
      List.concat(&2, U32, [w_bytes(a), w_bytes(b), w_bytes(c), w_bytes(d), w_bytes(e), w_bytes(f), w_bytes(g), w_bytes(h)])

def sha512(+bs: List<&2, U32>) -> List<&2, U32>:
  h8_bytes(digest_words(bs, iv512()))

def sha384(+bs: List<&2, U32>) -> List<&2, U32>:
  List.take(&2, U32, h8_bytes(digest_words(bs, iv384())), 48n)
