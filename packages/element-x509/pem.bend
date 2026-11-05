import Base
import element-text@0.1.0.0/base64.bend as B64

# PEM (RFC 7468): every "-----BEGIN CERTIFICATE-----" ... "-----END
# CERTIFICATE-----" block of a text as its DER bytes. Other blocks and text
# between blocks are ignored, as in a CA bundle (/etc/ssl/cert.pem).

def starts(p: String, s: String) -> Bool:
  match p:
    case SNil{}:
      True{}
    case SCon{pc, pt}:
      match s:
        case SNil{}:
          False{}
        case SCon{sc, st}:
          Char.is_eq(pc, sc) && starts(pt, st)

def rev_str(cs: List<&2, Char>) -> String:
  String.from_list(List.reverse(&2, Char, cs))

# The pieces so far, with the current one closed at a cut (a pick reversed
# it at every char: quadratic in the pieces' length).
def cut_out(cut: Bool, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match cut:
    case True{}:
      rev_str(cur) <> out
    case False{}:
      out

def lines_go(s: String, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, rev_str(cur) <> out)
    case SCon{+c, t}:
      +nl = Char.is_eq(c, '\n')
      lines_go(t, Bool.pick(List<&2, Char>, nl, Nil{}, c <> cur), cut_out(nl, cur, out))

def join(ls: List<&2, String>) -> String:
  match ls:
    case Nil{}:
      ""
    case Con{l, t}:
      l ++ join(t)

# Decoding only at a block's end (a Bool.pick would decode at every line).
def emit(end: Bool, +cur: List<&2, String>, +out: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match end:
    case False{}:
      out
    case True{}:
      B64.decode(join(List.reverse(&2, String, cur))) <> out

# `inside` a block, `cur` holds its lines, newest first.
def blocks(ls: List<&2, String>, +inside: Bool, +cur: List<&2, String>, +out: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match ls:
    case Nil{}:
      List.reverse(&2, List<&2, U32>, out)
    case Con{+l, t}:
      +begin = starts("-----BEGIN CERTIFICATE-----", l)
      +end = inside && starts("-----END CERTIFICATE-----", l)
      blocks(t, Bool.pick(Bool, begin, True{}, Bool.pick(Bool, end, False{}, inside)),
        Bool.pick(List<&2, String>, begin || end, Nil{}, Bool.pick(List<&2, String>, inside, l <> cur, cur)),
        emit(end, cur, out))

def certificates(+text: String) -> List<&2, List<&2, U32>>:
  blocks(lines_go(text, Nil{}, Nil{}), False{}, Nil{}, Nil{})
