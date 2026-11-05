import Base
import ./sha256.bend as Sha256
import ./sha512.bend as Sha512

# The SHA-2 hashes signatures name, as one value to pass around.

type Hash is Data:
  HSha256{}
  HSha384{}
  HSha512{}

def digest(h: Hash, +bs: List<&2, U32>) -> List<&2, U32>:
  match h:
    case HSha256{}:
      Sha256.digest(bs)
    case HSha384{}:
      Sha512.sha384(bs)
    case HSha512{}:
      Sha512.sha512(bs)

def size(h: Hash) -> Nat:
  match h:
    case HSha256{}:
      32n
    case HSha384{}:
      48n
    case HSha512{}:
      64n

# DER of the DigestInfo header that precedes the digest in PKCS#1 v1.5
# signatures (RFC 8017 section 9.2, note 1).
def digest_info(h: Hash) -> List<&2, U32>:
  match h:
    case HSha256{}:
      [48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]
    case HSha384{}:
      [48, 65, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 4, 48]
    case HSha512{}:
      [48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 4, 64]
