import Base

# K3.3 bytes to text. The network hands the engine raw bytes (Net.recv_bytes);
# decoding happens here, over the whole body, so a multi-byte character that
# arrived split across two reads is simply two adjacent bytes in the list.
#
# UTF-8 (RFC 3629): a malformed or truncated sequence becomes U+FFFD, and
# decoding resumes at the byte that broke it. Latin-1 maps each byte to the
# code point of the same value. The charset comes from the Content-Type
# header, else from a <meta charset> in the first 1024 bytes, else UTF-8.

def pick(c: Bool, a: U32, b: U32) -> U32:
  Bool.pick(U32, c, a, b)

def repl() -> U32:
  65533

# A code point Char.from_u32 accepts: not a surrogate, not past U+10FFFF.
def valid_cp(+c: U32) -> Bool:
  (c <= 1114111 : U32) && Bool.not((c >= 55296 : U32) && (c <= 57343 : U32))

def emit(+c: U32, acc: List<&2, Char>) -> List<&2, Char>:
  Char.from_u32(pick(valid_cp(c), c, repl())) <> acc

def emit_if(yes: Bool, +c: U32, +acc: List<&2, Char>) -> List<&2, Char>:
  Bool.pick(List<&2, Char>, yes, emit(c, acc), acc)

# The WHATWG UTF-8 decoder (Encoding §8.1.1), which is what a browser does:
# a lead is C2..DF (one continuation), E0..EF (two) or F0..F4 (three); the
# first continuation's range is narrowed after E0 (A0..BF), ED (80..9F), F0
# (90..BF) and F4 (80..8F), which refuses overlong forms (C0 80 is not NUL,
# C0 AF is not '/'), surrogates and code points past U+10FFFF. A sequence cut
# short gives one U+FFFD and its next byte is read again as a lead; a byte
# that can start nothing (80..C1, F5..FF) gives one U+FFFD.

# Continuation bytes a lead expects (0 for ASCII and for a byte that starts nothing).
def lead_need(+b: U32) -> U32:
  pick((b < 194 : U32), 0,
    pick((b < 224 : U32), 1,
      pick((b < 240 : U32), 2,
        pick((b < 245 : U32), 3, 0))))

def lead_bits(+b: U32) -> U32:
  pick((b < 128 : U32), b,
    pick((b < 224 : U32), (b % 32 : U32),
      pick((b < 240 : U32), (b % 16 : U32), (b % 8 : U32))))

# The range the first continuation byte must fall in, after a lead.
def lead_lo(+b: U32) -> U32:
  pick(U32.is_eq(b, 224), 160, pick(U32.is_eq(b, 240), 144, 128))

def lead_hi(+b: U32) -> U32:
  pick(U32.is_eq(b, 237), 159, pick(U32.is_eq(b, 244), 143, 191))

# A byte that can start nothing: 80..C1 (a stray continuation or an
# overlong lead) and F5..FF.
def lead_bad(+b: U32) -> Bool:
  (b >= 128 : U32) && U32.is_zero(lead_need(b))

# One fold over the bytes. `need` continuation bytes are still expected for
# the code point `cp` built so far; the next one must be in lo..hi. Output
# is reversed.
def dec(bs: List<&2, U32>, +need: U32, +cp: U32, +lo: U32, +hi: U32, +acc: List<&2, Char>) -> List<&2, Char>:
  match bs:
    case Nil{}:
      emit_if((need > 0 : U32), repl(), acc)
    case Con{+b, t}:
      +cont = (need > 0 : U32) && (b >= lo : U32) && (b <= hi : U32)
      +broke = (need > 0 : U32) && Bool.not(cont)
      +cp2 = ((cp * 64 : U32) + (b % 64 : U32) : U32)
      +acc1 = emit_if(broke, repl(), acc)
      +start_emit = Bool.not(cont) && (U32.is_zero(lead_need(b)))
      dec(
        t,
        pick(cont, (need - 1 : U32), lead_need(b)),
        pick(cont, cp2, lead_bits(b)),
        pick(cont, 128, lead_lo(b)),
        pick(cont, 191, lead_hi(b)),
        Bool.pick(List<&2, Char>, cont,
          emit_if(U32.is_eq(need, 1), cp2, acc1),
          emit_if(start_emit, pick(lead_bad(b), repl(), b), acc1))
      )

def utf8(bs: List<&2, U32>) -> String:
  String.from_list(List.reverse(&2, Char, dec(bs, 0, 0, 128, 191, Nil{})))

def latin1_go(bs: List<&2, U32>, acc: List<&2, Char>) -> List<&2, Char>:
  match bs:
    case Nil{}:
      acc
    case Con{b, t}:
      latin1_go(t, Char.from_u32(b) <> acc)

def latin1(bs: List<&2, U32>) -> String:
  String.from_list(List.reverse(&2, Char, latin1_go(bs, Nil{})))

# ASCII text of the first `n` bytes, for sniffing (bytes >= 128 become '?').
def ascii_prefix(n: Nat, bs: List<&2, U32>) -> String:
  match n:
    case 0n:
      SNil{}
    case 1n+k:
      match bs:
        case Nil{}:
          SNil{}
        case Con{+b, t}:
          SCon{Char.from_u32(pick((b < 128 : U32), b, 63)), ascii_prefix(k, t)}

# ---- charset -----------------------------------------------------------------

# The text after the first "charset=" in `s`, up to a delimiter. Empty if none.
def after_key(s: String, +key: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, +t}:
      Bool.pick(String, String.starts_with(SCon{h, t}, key), String.drop(SCon{h, t}, String.length(key)), after_key(t, key))

def is_delim(+c: Char) -> Bool:
  Char.is_eq(c, '"') || Char.is_eq(c, '\'') || Char.is_eq(c, ';') || Char.is_eq(c, ' ') ||
  Char.is_eq(c, '>') || Char.is_eq(c, '/') || Char.is_eq(c, ',')

def token(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      Bool.pick(String, is_delim(h), SNil{}, SCon{h, token(t)})

def strip_quote(+s: String) -> String:
  Bool.pick(String, String.starts_with(s, "\"") || String.starts_with(s, "'"), String.drop(s, 1n), s)

def charset_in(+s: String) -> String:
  token(strip_quote(after_key(String.to_lower(s), "charset=")))

# Header first, then <meta> in the first 1024 bytes, else utf-8.
def charset(+content_type: String, +bs: List<&2, U32>) -> String:
  Bool.pick(String, Bool.not(String.eq(charset_in(content_type), "")), charset_in(content_type),
    Bool.pick(String, Bool.not(String.eq(charset_in(ascii_prefix(1024n, bs)), "")), charset_in(ascii_prefix(1024n, bs)), "utf-8"))

def is_latin1(+cs: String) -> Bool:
  String.eq(cs, "iso-8859-1") || String.eq(cs, "latin1") || String.eq(cs, "latin-1") ||
  String.eq(cs, "windows-1252") || String.eq(cs, "us-ascii") || String.eq(cs, "ascii")

# windows-1252 differs from Latin-1 only in 0x80..0x9F; those bytes decode
# to C1 controls here (recorded gap, not silently "fixed").
def decode(+content_type: String, +bs: List<&2, U32>) -> String:
  Bool.pick(String, is_latin1(charset(content_type, bs)), latin1(bs), utf8(bs))

# ---- encoding ---------------------------------------------------------------

# Strings hold Unicode scalar values, not octets. HTTP Content-Length and
# TLS plaintext must use the same UTF-8 encoding as TCP.send and WebSocket.
def cp_bytes(+c: U32) -> List<&2, U32>:
  Bool.pick(List<&2, U32>, (c < 128 : U32), [c],
    Bool.pick(List<&2, U32>, (c < 2048 : U32), [(192 + (c / 64 : U32) : U32), (128 + (c % 64 : U32) : U32)],
      Bool.pick(List<&2, U32>, (c < 65536 : U32),
        [(224 + (c / 4096 : U32) : U32), (128 + ((c / 64 : U32) % 64 : U32) : U32), (128 + (c % 64 : U32) : U32)],
        [(240 + (c / 262144 : U32) : U32), (128 + ((c / 4096 : U32) % 64 : U32) : U32), (128 + ((c / 64 : U32) % 64 : U32) : U32), (128 + (c % 64 : U32) : U32)])))

def bytes_of(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{h, t}:
      List.append(&2, U32, cp_bytes(Char.to_u32(h)), bytes_of(t))
