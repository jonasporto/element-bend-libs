import Base
import element-math@0.1.0.0/big.bend as Big
import ./hash.bend as Hash

# RSA signature verification (RFC 8017): RSASSA-PKCS1-v1_5 (8.2.2), used by
# most certificate signatures, and RSASSA-PSS (9.1.2) with MGF1 and a salt as
# long as the hash, which TLS 1.3 requires for CertificateVerify. A public key
# is the modulus n and exponent e as big-endian bytes (leading zeros allowed).

def drop_zeros(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{+h, +t}:
      Bool.pick(List<&2, U32>, U32.is_zero(h), drop_zeros(t), h <> t)

def all_zero(bs: List<&2, U32>) -> Bool:
  Big.is_zero(bs)

def same(+a: List<&2, U32>, +b: List<&2, U32>) -> Bool:
  Big.eq(a, b)

def len(+bs: List<&2, U32>) -> Nat:
  List.length(&2, U32, bs)

def fill(n: Nat, +v: U32) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      v <> fill(r, v)

# s^e mod n as |n| bytes, or Nil when s has the wrong length or is not below n.
def open_with(ok: Bool, +n: List<&2, U32>, +e: List<&2, U32>, +s: List<&2, U32>) -> List<&2, U32>:
  match ok:
    case False{}:
      Nil{}
    case True{}:
      Big.to_bytes(Big.pow(Big.modulus_of_bytes(n), Big.from_bytes(s), e), len(n))

def open(+n0: List<&2, U32>, +e: List<&2, U32>, +s: List<&2, U32>) -> List<&2, U32>:
  +n = drop_zeros(n0)
  open_with(Nat.is_eq(len(s), len(n)) && Big.lt(Big.from_bytes(s), Big.from_bytes(n)), n, e, s)

# ---- PKCS #1 v1.5 -----------------------------------------------------------------

# EM = 00 01 FF..FF 00 DigestInfo H, at least 8 bytes of FF.
def expected(+h: Hash.Hash, +k: Nat, +msg: List<&2, U32>) -> List<&2, U32>:
  +t = List.append(&2, U32, Hash.digest_info(h), Hash.digest(h, msg))
  List.concat(&2, U32, [[0, 1], fill(Nat.sub(Nat.sub(k, 3n), len(t)), 255), [0], t])

def pkcs1_verify(+h: Hash.Hash, +n: List<&2, U32>, +e: List<&2, U32>, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  +em = open(n, e, sig)
  +k = len(drop_zeros(n))
  Nat.is_ge(k, Nat.add(len(Hash.digest_info(h)), Nat.add(Hash.size(h), 11n))) && Nat.is_eq(len(em), k) && same(em, expected(h, k, msg))

# ---- PSS --------------------------------------------------------------------------

def be32(+x: U32) -> List<&2, U32>:
  [(x / 16777216 : U32), (x / 65536 % 256 : U32), (x / 256 % 256 : U32), (x % 256 : U32)]

def mgf_go(c: Nat, +h: Hash.Hash, +seed: List<&2, U32>, +i: U32) -> List<&2, U32>:
  match c:
    case 0n:
      Nil{}
    case 1n+r:
      List.append(&2, U32, Hash.digest(h, List.append(&2, U32, seed, be32(i))), mgf_go(r, h, seed, (i + 1 : U32)))

# MGF1 (B.2.1): the first `n` bytes of Hash(seed || counter) for counter 0, 1, ...
def mgf1(+h: Hash.Hash, +seed: List<&2, U32>, +n: Nat) -> List<&2, U32>:
  List.take(&2, U32, mgf_go(Nat.add(Nat.div(n, Hash.size(h)), 1n), h, seed, 0), n)

def xor_with(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  match a b:
    case Con{x, at} Con{y, bt}:
      U32.xor(x, y) <> xor_with(at, bt)
    case _ _:
      Nil{}

def top_bits(c: Nat, +b: U32) -> Nat:
  match c:
    case 0n:
      0n
    case 1n+r:
      Bool.pick(Nat, U32.is_zero(b), 0n, Nat.add(top_bits(r, (b / 2 : U32)), 1n))

# Bits in n, from its big-endian bytes with leading zeros dropped.
def bit_length(+n: List<&2, U32>) -> Nat:
  Nat.add(Nat.mul(Nat.sub(len(n), 1n), 8n), top_bits(8n, Big.nth(n, 0n)))

def first(+bs: List<&2, U32>) -> U32:
  Big.nth(bs, 0n)

def last(+bs: List<&2, U32>) -> U32:
  Big.nth(List.reverse(&2, U32, bs), 0n)

def head_masked(bs: List<&2, U32>, +keep: U32) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      U32.and(h, keep) <> t

# EM is emLen bytes; the leftmost 8 emLen - emBits bits must be zero.
def pss_check(+h: Hash.Hash, +em: List<&2, U32>, +em_len: Nat, +zbits: Nat, +msg: List<&2, U32>) -> Bool:
  +hl = Hash.size(h)
  +db_len = Nat.sub(Nat.sub(em_len, hl), 1n)
  +hh = List.take(&2, U32, List.drop(&2, U32, em, db_len), hl)
  +keep = (255 / U32.shln(1, zbits) : U32)
  +db = head_masked(xor_with(List.take(&2, U32, em, db_len), mgf1(h, hh, db_len)), keep)
  +ps = Nat.sub(Nat.sub(db_len, hl), 1n)
  +salt = List.drop(&2, U32, db, Nat.add(ps, 1n))
  Nat.is_gt(em_len, Nat.add(Nat.mul(hl, 2n), 1n)) && U32.is_eq(last(em), 188) &&
    U32.is_eq(U32.and(first(em), U32.not(keep)), 0) &&
    same(List.take(&2, U32, db, Nat.add(ps, 1n)), List.append(&2, U32, fill(ps, 0), [1])) &&
    same(hh, Hash.digest(h, List.concat(&2, U32, [fill(8n, 0), Hash.digest(h, msg), salt])))

def pss_verify(+h: Hash.Hash, +n0: List<&2, U32>, +e: List<&2, U32>, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  +n = drop_zeros(n0)
  +k = len(n)
  +em_bits = Nat.sub(bit_length(n), 1n)
  +em_len = Nat.div(Nat.add(em_bits, 7n), 8n)
  +full = open(n, e, sig)
  Nat.is_eq(len(full), k) && all_zero(List.take(&2, U32, full, Nat.sub(k, em_len))) &&
    pss_check(h, List.drop(&2, U32, full, Nat.sub(k, em_len)), em_len, Nat.sub(Nat.mul(em_len, 8n), em_bits), msg)
