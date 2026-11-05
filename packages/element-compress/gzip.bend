import Base
import ./inflate.bend as Inflate
import ./checksum.bend as Ck

# The gzip (RFC 1952) and zlib (RFC 1950) wrappers around a DEFLATE stream:
# the header is read and checked, the stream inflated, the trailer's
# checksum and size compared with what came out. A mismatch is a Fail, never
# a body shown as text. CRC-32 and Adler-32 are the PNG encoder's
# (lib/image/png.bend, with laws in lib/LAWS.bend).
#
# `decode` is what HTTP needs: a Content-Encoding and the body bytes.

# ---- little-endian numbers ----------------------------------------------------------------------

def le16(xs: List<&2, U32>) -> U32:
  match xs:
    case Nil{}:
      0
    case Con{+a, t}:
      match t:
        case Nil{}:
          a
        case Con{+b, u}:
          (a + U32.shln(b, 8n) : U32)

def le32(+xs: List<&2, U32>) -> U32:
  +lo = le16(xs)
  +hi = le16(List.drop(&2, U32, xs, 2n))
  (lo + U32.shln(hi, 16n) : U32)

def be32(xs: List<&2, U32>) -> U32:
  match xs:
    case Nil{}:
      0
    case Con{+a, t}:
      match t:
        case Nil{}:
          0
        case Con{+b, u}:
          match u:
            case Nil{}:
              0
            case Con{+c, v}:
              match v:
                case Nil{}:
                  0
                case Con{+d, w}:
                  (U32.shln(a, 24n) + U32.shln(b, 16n) + U32.shln(c, 8n) + d : U32)

# the bytes after a zero byte (a zero-terminated name or comment)
def after_zero(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+b, +t}:
      # (a pick builds both arms: the walk continues either way, once)
      +rest = after_zero(t)
      Bool.pick(List<&2, U32>, U32.is_zero(b), t, rest)

def drop_if(c: Bool, xs: List<&2, U32>, +n: Nat) -> List<&2, U32>:
  match c:
    case False{}:
      xs
    case True{}:
      List.drop(&2, U32, xs, n)

def skip_zero_if(c: Bool, xs: List<&2, U32>) -> List<&2, U32>:
  match c:
    case False{}:
      xs
    case True{}:
      after_zero(xs)

def byte_at(+xs: List<&2, U32>, +i: Nat) -> U32:
  le16(List.drop(&2, U32, xs, i))

def low8(+v: U32) -> U32:
  U32.and(v, 255)

# ---- gzip -----------------------------------------------------------------------------------------

# The header: ID1 ID2 CM FLG MTIME(4) XFL OS, then FEXTRA (a 2-byte length
# and that many bytes), FNAME and FCOMMENT (zero-terminated), FHCRC (2
# bytes), as FLG says. Answers the DEFLATE stream and what follows, or "".
def gzip_body(+xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  +id1 = low8(byte_at(xs, 0n))
  +id2 = low8(byte_at(xs, 1n))
  +cm = low8(byte_at(xs, 2n))
  +flg = low8(byte_at(xs, 3n))
  +magic = U32.is_eq(id1, 31) && U32.is_eq(id2, 139)
  +rest0 = List.drop(&2, U32, xs, 10n)
  +fextra = Bool.not(U32.is_zero(U32.and(flg, 4)))
  +xlen = Bool.pick(U32, fextra, le16(rest0), 0)
  +rest1 = drop_if(fextra, rest0, U32.to_nat((xlen + 2 : U32)))
  +rest2 = skip_zero_if(Bool.not(U32.is_zero(U32.and(flg, 8))), rest1)
  +rest3 = skip_zero_if(Bool.not(U32.is_zero(U32.and(flg, 16))), rest2)
  +rest4 = drop_if(Bool.not(U32.is_zero(U32.and(flg, 2))), rest3, 2n)
  Bool.pick(Result<&2, &2, String, List<&2, U32>>, Bool.not(magic), Fail{"gzip: not a gzip stream (no 1f 8b)"},
    Bool.pick(Result<&2, &2, String, List<&2, U32>>, Bool.not(U32.is_eq(cm, 8)), Fail{"gzip: a compression method other than deflate"},
      Bool.pick(Result<&2, &2, String, List<&2, U32>>, (U32.from_nat(List.length(&2, U32, xs)) < 18 : U32), Fail{"gzip: shorter than a header and a trailer"},
        Done{rest4})))

# the trailer: CRC-32 and the size mod 2^32 of the bytes, little-endian
def gzip_trailer(o: Inflate.Out) -> Result<&2, &2, String, List<&2, U32>>:
  match o:
    case Inflate.Out{+bytes, +rest}:
      +crc = le32(rest)
      +isize = le32(List.drop(&2, U32, rest, 4n))
      +n = U32.from_nat(List.length(&2, U32, bytes))
      Bool.pick(Result<&2, &2, String, List<&2, U32>>, (U32.from_nat(List.length(&2, U32, rest)) < 8 : U32), Fail{"gzip: the trailer is missing"},
        Bool.pick(Result<&2, &2, String, List<&2, U32>>, Bool.not(U32.is_eq(isize, n)), Fail{"gzip: the size in the trailer is not the size inflated"},
          Bool.pick(Result<&2, &2, String, List<&2, U32>>, Bool.not(U32.is_eq(crc, Ck.crc32(bytes))), Fail{"gzip: CRC-32 mismatch"},
            Done{bytes})))

def gzip_inflated(r: Result<&2, &2, String, Inflate.Out>) -> Result<&2, &2, String, List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{o}:
      gzip_trailer(o)

def gzip_stream(r: Result<&2, &2, String, List<&2, U32>>) -> Result<&2, &2, String, List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{body}:
      gzip_inflated(Inflate.inflate_rest(body))

# the bytes a gzip member holds (one member; a second is left unread)
def gunzip(+xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  gzip_stream(gzip_body(xs))

# ---- zlib -----------------------------------------------------------------------------------------

def zlib_trailer(o: Inflate.Out) -> Result<&2, &2, String, List<&2, U32>>:
  match o:
    case Inflate.Out{+bytes, +rest}:
      Bool.pick(Result<&2, &2, String, List<&2, U32>>, (U32.from_nat(List.length(&2, U32, rest)) < 4 : U32), Fail{"zlib: the Adler-32 is missing"},
        Bool.pick(Result<&2, &2, String, List<&2, U32>>, Bool.not(U32.is_eq(be32(rest), Ck.adler32(bytes))), Fail{"zlib: Adler-32 mismatch"},
          Done{bytes}))

def zlib_inflated(r: Result<&2, &2, String, Inflate.Out>) -> Result<&2, &2, String, List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{o}:
      zlib_trailer(o)

# CMF (CM 8, CINFO <= 7) and FLG with (CMF * 256 + FLG) a multiple of 31; a
# preset dictionary (FDICT) is refused
def zlib_ok(+xs: List<&2, U32>) -> Bool:
  +cmf = low8(byte_at(xs, 0n))
  +flg = low8(byte_at(xs, 1n))
  U32.is_eq(U32.and(cmf, 15), 8) && (U32.shrn(cmf, 4n) <= 7 : U32) && U32.is_zero(U32.mod((U32.shln(cmf, 8n) + flg : U32), 31))

def zlib_dict(+xs: List<&2, U32>) -> Bool:
  Bool.not(U32.is_zero(U32.and(low8(byte_at(xs, 1n)), 32)))

# (a `match` on the checks: Bool.pick builds both arms, so the inflate
# would run on a stream the header already refused)
def zlib_checked(ok: Bool, dict: Bool, +xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  match ok:
    case False{}:
      Fail{"zlib: not a zlib stream"}
    case True{}:
      match dict:
        case True{}:
          Fail{"zlib: a preset dictionary is not supported"}
        case False{}:
          zlib_inflated(Inflate.inflate_rest(List.drop(&2, U32, xs, 2n)))

def unzlib(+xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  zlib_checked(zlib_ok(xs), zlib_dict(xs), xs)

# ---- Content-Encoding ---------------------------------------------------------------------------

# "deflate" is a zlib stream by the RFCs, a raw one from some servers: the
# header decides (a `match`: a pick would inflate the stream both ways)
def deflate_as(zlib: Bool, +xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  match zlib:
    case True{}:
      unzlib(xs)
    case False{}:
      Inflate.inflate(xs)

def deflate_body(+xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  deflate_as(zlib_ok(xs), xs)

# A Content-Encoding as a constructor, so `decode` matches on it and only
# the decoder named runs (Bool.pick builds every arm: an identity body
# would be tried as gzip and as deflate, a gzip one as raw deflate too).
type Enc is Data:
  Identity{}
  Gz{}
  Defl{}
  Other{name: String}

def enc_of(+enc: String) -> Enc:
  Bool.pick(Enc, String.is_empty(enc) || String.eq(enc, "identity"), Identity{},
    Bool.pick(Enc, String.eq(enc, "gzip") || String.eq(enc, "x-gzip"), Gz{},
      Bool.pick(Enc, String.eq(enc, "deflate"), Defl{}, Other{enc})))

def decode_as(e: Enc, xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  match e:
    case Identity{}:
      Done{xs}
    case Gz{}:
      gunzip(xs)
    case Defl{}:
      deflate_body(xs)
    case Other{name}:
      Fail{"Element does not decode " ++ name ++ " yet"}

# The body a Content-Encoding names decoded: gzip, x-gzip, deflate; "" or
# identity as is; anything else (br, zstd, compress) is refused.
def decode(+enc: String, xs: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  decode_as(enc_of(enc), xs)
