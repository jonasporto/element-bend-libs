import Base
import ./sha256.bend as Sha256

# HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869), the key schedule of
# TLS 1.3 (RFC 8446 section 7.1). Keys and messages are bytes (List<U32>).

def xor_bytes(xs: List<&2, U32>, +c: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      U32.xor(x, c) <> xor_bytes(t, c)

def zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      0 <> zeros(r)

# The key as one 64-byte block: hashed if longer, zero-padded if shorter.
def block_key(+key: List<&2, U32>) -> List<&2, U32>:
  +k = Bool.pick(List<&2, U32>, (U32.from_nat(List.length(&2, U32, key)) > 64 : U32), Sha256.digest(key), key)
  List.append(&2, U32, k, zeros(U32.to_nat((64 - U32.from_nat(List.length(&2, U32, k)) : U32))))

def hmac(key: List<&2, U32>, msg: List<&2, U32>) -> List<&2, U32>:
  +k = block_key(key)
  Sha256.digest(List.append(&2, U32, xor_bytes(k, 92), Sha256.digest(List.append(&2, U32, xor_bytes(k, 54), msg))))

def extract(salt: List<&2, U32>, ikm: List<&2, U32>) -> List<&2, U32>:
  hmac(salt, ikm)

# T(i) = HMAC(PRK, T(i-1) | info | i), for i = 1..n; output is T(1) | ... | T(n).
def expand_go(n: Nat, +prk: List<&2, U32>, +info: List<&2, U32>, +prev: List<&2, U32>, +i: U32) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      +t = hmac(prk, List.concat(&2, U32, [prev, info, [i]]))
      List.append(&2, U32, t, expand_go(r, prk, info, t, (i + 1 : U32)))

def expand(+prk: List<&2, U32>, +info: List<&2, U32>, +len: U32) -> List<&2, U32>:
  List.take(&2, U32, expand_go(U32.to_nat(((len + 31 : U32) / 32 : U32)), prk, info, Nil{}, 1), U32.to_nat(len))

def repeat(n: Nat, +v: U32) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+r:
      v <> repeat(r, v)

# ---- hex helpers for tests -----------------------------------------------------

def hex_val(+c: U32) -> U32:
  Bool.pick(U32, (c >= 97 : U32), (c - 87 : U32), (c - 48 : U32))

def unhex(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{a, t}:
      match t:
        case SNil{}:
          Nil{}
        case SCon{b, rest}:
          ((hex_val(Char.to_u32(a)) * 16 : U32) + hex_val(Char.to_u32(b)) : U32) <> unhex(rest)
