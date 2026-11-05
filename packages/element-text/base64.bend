import Base

# Base64 (RFC 4648 section 4) decoding, as PEM files use it: characters
# outside the alphabet (line breaks, spaces) are skipped and '=' padding ends
# nothing early, since the leftover bits simply never make a whole byte.

def value(+c: U32) -> U32:
  Bool.pick(U32, (c >= 65 : U32) && (c <= 90 : U32), (c - 65 : U32),
    Bool.pick(U32, (c >= 97 : U32) && (c <= 122 : U32), (c - 71 : U32),
      Bool.pick(U32, (c >= 48 : U32) && (c <= 57 : U32), (c + 4 : U32),
        Bool.pick(U32, U32.is_eq(c, 43), 62, Bool.pick(U32, U32.is_eq(c, 47), 63, 64)))))

# `acc` holds `bits` pending bits (fewer than 8 between characters).
def go(s: String, +acc: U32, +bits: U32, +out: List<&2, U32>) -> List<&2, U32>:
  match s:
    case SNil{}:
      out
    case SCon{c, t}:
      +v = value(Char.to_u32(c))
      +skip = U32.is_eq(v, 64)
      +a = Bool.pick(U32, skip, acc, ((acc * 64 : U32) + v : U32))
      +b = Bool.pick(U32, skip, bits, (bits + 6 : U32))
      +emit = (b >= 8 : U32)
      +sh = U32.shln(1, U32.to_nat(Bool.pick(U32, emit, (b - 8 : U32), 0)))
      go(t, Bool.pick(U32, emit, (a % sh : U32), a), Bool.pick(U32, emit, (b - 8 : U32), b),
        Bool.pick(List<&2, U32>, emit, (a / sh : U32) <> out, out))

def decode(+s: String) -> List<&2, U32>:
  List.reverse(&2, U32, go(s, 0, 0, Nil{}))

# ---- encoding ---------------------------------------------------------------------

def sym(+v: U32) -> Char:
  Char.from_u32(Bool.pick(U32, (v < 26 : U32), (v + 65 : U32),
    Bool.pick(U32, (v < 52 : U32), (v + 71 : U32), Bool.pick(U32, (v < 62 : U32), (v - 4 : U32), Bool.pick(U32, U32.is_eq(v, 62), 43, 47)))))

def enc_go(bs: List<&2, U32>) -> List<&2, Char>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{+a, t}:
      match t:
        case Nil{}:
          [sym((a / 4 : U32)), sym(((a % 4 : U32) * 16 : U32)), '=', '=']
        case Con{+b, t2}:
          match t2:
            case Nil{}:
              [sym((a / 4 : U32)), sym((((a % 4 : U32) * 16 : U32) + (b / 16 : U32) : U32)), sym(((b % 16 : U32) * 4 : U32)), '=']
            case Con{+c, t3}:
              List.append(&2, Char, [sym((a / 4 : U32)), sym((((a % 4 : U32) * 16 : U32) + (b / 16 : U32) : U32)),
                sym((((b % 16 : U32) * 4 : U32) + (c / 64 : U32) : U32)), sym((c % 64 : U32))], enc_go(t3))

# Bytes (0..255) as base64 with '=' padding (RFC 4648 section 4).
def encode(+bs: List<&2, U32>) -> String:
  String.from_list(enc_go(bs))
