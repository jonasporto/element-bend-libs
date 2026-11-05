import Base
import element-crypto@0.1.0.0/sha1.bend as Sha1
import element-crypto@0.1.0.0/sha256.bend as Sha256
import element-text@0.1.0.0/base64.bend as B64
import element-text@0.1.0.0/utf8.bend as U

# WebSocket server side (RFC 6455), pure: the opening handshake's accept key
# and 101 response, and frames. A server's frames are unmasked; a client's
# are masked (5.3) and are unmasked here. Fragmented messages (FIN 0) are
# joined by the caller. Payload lengths: 7 bits, 16 bits (126) or 64 bits
# (127, of which the low 32 are used).

def guid() -> String:
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Sec-WebSocket-Accept for a client's Sec-WebSocket-Key (4.2.2).
def accept_key(+key: String) -> String:
  B64.encode(Sha1.digest(Sha256.bytes_of(key ++ guid())))

def handshake_response(+key: String) -> String:
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ++ accept_key(key) ++ "\r\n\r\n"

# ---- frames ---------------------------------------------------------------------------

def be16(+n: U32) -> List<&2, U32>:
  [(n / 256 % 256 : U32), (n % 256 : U32)]

# A server frame (unmasked) with FIN set: opcode 1 text, 2 binary, 8 close,
# 9 ping, 10 pong.
def frame(+opcode: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  +n = U32.from_nat(List.length(&2, U32, payload))
  List.concat(&2, U32, [
    [(128 + opcode : U32)],
    Bool.pick(List<&2, U32>, (n < 126 : U32), [n],
      Bool.pick(List<&2, U32>, (n < 65536 : U32), 126 <> be16(n),
        List.append(&2, U32, [127, 0, 0, 0, 0], List.append(&2, U32, be16((n / 65536 : U32)), be16((n % 65536 : U32)))))),
    payload
  ])

def cp_bytes(+c: U32) -> List<&2, U32>:
  U.cp_bytes(c)

# UTF-8 bytes of a String (code points to 1-4 bytes).
def utf8(s: String) -> List<&2, U32>:
  U.bytes_of(s)

def text_frame(+s: String) -> List<&2, U32>:
  frame(1, utf8(s))

# A frame read from the client, and the bytes after it.
type Frame is Data:
  Frame{fin: Bool, opcode: U32, payload: +List<U32>}

type Read is Data:
  RFrame{f: Frame, rest: +List<U32>}
  RMore{}

def nth(xs: List<&2, U32>, n: Nat) -> U32:
  Sha256.nth(xs, n)

# Unmask: payload[i] XOR mask[i mod 4].
def unmask(bs: List<&2, U32>, +m0: U32, +m1: U32, +m2: U32, +m3: U32) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{b, t}:
      U32.xor(b, m0) <> unmask(t, m1, m2, m3, m0)

def read_if(ok: Bool, +bs: List<&2, U32>, +head: Nat, +len: Nat, +masked: Bool) -> Read:
  match ok:
    case False{}:
      RMore{}
    case True{}:
      +mk = Nat.sub(head, Bool.pick(Nat, masked, 4n, 0n))
      +body = List.take(&2, U32, List.drop(&2, U32, bs, head), len)
      RFrame{Frame{(nth(bs, 0n) >= 128 : U32), (nth(bs, 0n) % 16 : U32),
          Bool.pick(List<&2, U32>, masked, unmask(body, nth(bs, mk), nth(bs, Nat.add(mk, 1n)), nth(bs, Nat.add(mk, 2n)), nth(bs, Nat.add(mk, 3n))), body)},
        List.drop(&2, U32, bs, Nat.add(head, len))}

# The first whole frame in bs, or RMore when bs does not hold one yet.
def read(+bs: List<&2, U32>) -> Read:
  +b1 = nth(bs, 1n)
  +masked = (b1 >= 128 : U32)
  +l7 = (b1 % 128 : U32)
  +ext = Bool.pick(Nat, U32.is_eq(l7, 126), 2n, Bool.pick(Nat, U32.is_eq(l7, 127), 8n, 0n))
  +len = U32.to_nat(Bool.pick(U32, U32.is_eq(l7, 126), ((nth(bs, 2n) * 256 : U32) + nth(bs, 3n) : U32),
    Bool.pick(U32, U32.is_eq(l7, 127),
      ((((nth(bs, 6n) * 16777216 : U32) + (nth(bs, 7n) * 65536 : U32) : U32) + (nth(bs, 8n) * 256 : U32) : U32) + nth(bs, 9n) : U32), l7)))
  +head = Nat.add(Nat.add(2n, ext), Bool.pick(Nat, masked, 4n, 0n))
  +have = List.length(&2, U32, bs)
  read_if(Nat.is_ge(have, 2n) && Nat.is_ge(have, Nat.add(head, len)), bs, head, len, masked)

# The payload of the first whole frame ("" as Nil when none) — laws and tests.
def payload_of(r: Read) -> List<&2, U32>:
  match r:
    case RMore{}:
      Nil{}
    case RFrame{f, rest}:
      match f:
        case Frame{fin, opcode, payload}:
          payload

def first_payload(+bs: List<&2, U32>) -> List<&2, U32>:
  payload_of(read(bs))
