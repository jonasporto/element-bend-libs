import Base
import ./deflate_rgb.bend as Rgb
import element-compress@0.1.0.1/checksum.bend as Ck

# PNG encoders (ISO/IEC 15948, RFC 2083) for 8-bit RGB images, in pure Bend:
# png uses stored deflate blocks (RFC 1951 3.2.4); compact uses RGB runs
# with fixed Huffman codes. Both produce standard zlib/PNG streams. CRC-32
# (the PNG polynomial 0xEDB88320) and Adler-32 are computed in Bend.
#
# Input: width, height, and the pixels row by row as 0xRRGGBB values.

def pick(c: Bool, a: U32, b: U32) -> U32:
  Bool.pick(U32, c, a, b)

# ---- CRC-32 and Adler-32 (compress/checksum.bend) -------------------------

def crc32(+bs: List<&2, U32>) -> U32:
  Ck.crc32(bs)

def adler32(+bs: List<&2, U32>) -> U32:
  Ck.adler32(bs)

# ---- bytes ----------------------------------------------------------------------

def be32(+x: U32) -> List<&2, U32>:
  [(x / 16777216 : U32), (x / 65536 % 256 : U32), (x / 256 % 256 : U32), (x % 256 : U32)]

def le16(+x: U32) -> List<&2, U32>:
  [(x % 256 : U32), (x / 256 % 256 : U32)]

def ascii(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{h, t}:
      Char.to_u32(h) <> ascii(t)

def len(xs: List<&2, U32>) -> U32:
  U32.from_nat(List.length(&2, U32, xs))

# A chunk: length, type, data, CRC of type + data.
def chunk(+typ: String, +data: List<&2, U32>) -> List<&2, U32>:
  List.concat(&2, U32, [be32(len(data)), ascii(typ), data, be32(crc32(List.append(&2, U32, ascii(typ), data)))])

# ---- zlib with stored blocks --------------------------------------------------------

# Deflate stored blocks of at most 65535 bytes; the last one has BFINAL set.
# Carry the length: rescanning the remaining bytes twice per block made this
# quadratic in image size even though the stored representation is linear.
def stored_go(k: Nat, +bs: List<&2, U32>, +remaining: U32) -> List<&2, U32>:
  match k:
    case 0n:
      Nil{}
    case 1n+r:
      +n = U32.min(remaining, 65535)
      +last = (remaining <= 65535 : U32)
      prefix = List.concat(&2, U32, [
        [pick(last, 1, 0)], le16(n), le16(U32.xor(n, 65535)),
        List.take(&2, U32, bs, U32.to_nat(n))
      ])
      List.append(&2, U32, prefix,
        Bool.pick(List<&2, U32>, last, Nil{}, stored_go(r, List.drop(&2, U32, bs, U32.to_nat(n)), (remaining - n : U32))))

def stored(k: Nat, +bs: List<&2, U32>) -> List<&2, U32>:
  stored_go(k, bs, len(bs))

def zlib(+bs: List<&2, U32>) -> List<&2, U32>:
  +n = len(bs)
  List.concat(&2, U32, [[120, 1], stored_go(U32.to_nat(((n / 65535 : U32) + 1 : U32)), bs, n), be32(adler32(bs))])

# ---- rows ----------------------------------------------------------------------------

def rgb(+c: U32) -> List<&2, U32>:
  [(c / 65536 % 256 : U32), (c / 256 % 256 : U32), (c % 256 : U32)]

def row_bytes(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{c, t}:
      List.append(&2, U32, rgb(c), row_bytes(t))

# Each scanline: filter type 0, then R G B per pixel.
def scanlines(rows: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match rows:
    case Nil{}:
      Nil{}
    case Con{r, t}:
      # concat([prefix, recursive_tail]) copies the entire tail again: with
      # h rows that was O(h^2). Append only this row to the recursive tail.
      0 <> List.append(&2, U32, row_bytes(r), scanlines(t))

def image(+w: U32, +h: U32, data: List<&2, U32>) -> List<&2, U32>:
  List.concat(&2, U32, [
    [137, 80, 78, 71, 13, 10, 26, 10],
    chunk("IHDR", List.concat(&2, U32, [be32(w), be32(h), [8, 2, 0, 0, 0]])),
    chunk("IDAT", data),
    chunk("IEND", Nil{})
  ])

# Established stored-block API, including its exact-byte fixture law.
def png(w: U32, h: U32, rows: List<&2, List<&2, U32>>) -> List<&2, U32>:
  image(w, h, zlib(scanlines(rows)))

# Lossless fixed-Huffman RGB-run encoding for browser screenshots. Both
# encoders expose the same RGB pixels; only their compressed bytes differ.
def compact(w: U32, h: U32, rows: List<&2, List<&2, U32>>) -> List<&2, U32>:
  image(w, h, Rgb.zlib(rows))
