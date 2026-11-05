import Base

# CRC-32 (ISO 3309, the polynomial 0xEDB88320 that gzip, zlib's PNG and
# ZIP use) and Adler-32 (RFC 1950), over byte lists, in pure Bend.

def pick(c: Bool, a: U32, b: U32) -> U32:
  Bool.pick(U32, c, a, b)

# ---- CRC-32 ---------------------------------------------------------------------

def crc_bit(+c: U32) -> U32:
  pick(U32.is_eq(U32.and(c, 1), 1), U32.xor(3988292384, (c / 2 : U32)), (c / 2 : U32))

def crc_entry(+n: U32) -> U32:
  crc_bit(crc_bit(crc_bit(crc_bit(crc_bit(crc_bit(crc_bit(crc_bit(n))))))))

# Four-bit CRC table, selected by four bits rather than a linear List index.
# Entries are four applications of crc_bit to 0..15 (polynomial 0xEDB88320).
def crc_nibble_value(a: Bool, b: Bool, c: Bool, d: Bool) -> U32:
  match a b c d:
    case False{} False{} False{} False{}:
      0
    case True{} False{} False{} False{}:
      498536548
    case False{} True{} False{} False{}:
      997073096
    case True{} True{} False{} False{}:
      651767980
    case False{} False{} True{} False{}:
      1994146192
    case True{} False{} True{} False{}:
      1802195444
    case False{} True{} True{} False{}:
      1303535960
    case True{} True{} True{} False{}:
      1342533948
    case False{} False{} False{} True{}:
      3988292384
    case True{} False{} False{} True{}:
      4027552580
    case False{} True{} False{} True{}:
      3604390888
    case True{} True{} False{} True{}:
      3412177804
    case False{} False{} True{} True{}:
      2607071920
    case True{} False{} True{} True{}:
      2262029012
    case False{} True{} True{} True{}:
      2685067896
    case True{} True{} True{} True{}:
      3183342108

def crc_nibble(+c: U32) -> U32:
  +v = crc_nibble_value(U32.is_ne(U32.and(c, 1), 0), U32.is_ne(U32.and(c, 2), 0),
    U32.is_ne(U32.and(c, 4), 0), U32.is_ne(U32.and(c, 8), 0))
  U32.xor((c / 16 : U32), v)

def crc_go(bs: List<&2, U32>, +c: U32) -> U32:
  match bs:
    case Nil{}:
      c
    case Con{b, t}:
      crc_go(t, crc_nibble(crc_nibble(U32.xor(c, b))))

def crc32(+bs: List<&2, U32>) -> U32:
  U32.xor(crc_go(bs, 4294967295), 4294967295)

# ---- Adler-32 ---------------------------------------------------------------------

def adler_go(bs: List<&2, U32>, +a: U32, +b: U32) -> U32:
  match bs:
    case Nil{}:
      ((b * 65536 : U32) + a : U32)
    case Con{x, t}:
      +a2 = ((a + x : U32) % 65521 : U32)
      adler_go(t, a2, ((b + a2 : U32) % 65521 : U32))

def adler32(+bs: List<&2, U32>) -> U32:
  adler_go(bs, 1, 0)
