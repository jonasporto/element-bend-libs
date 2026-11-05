import Base
import ./dom.bend as Dom
import ./entities.bend as Ent

# HTML tokenizer, after the WHATWG state machine (HTML section 13.2.5),
# reduced to what real pages need: text, start tags with attributes (double,
# single or unquoted values, bare names), self-closing tags, end tags,
# comments, DOCTYPE and other <!...> declarations, and raw text inside
# <script>, <style>, <title> and <textarea> (no tags there until the
# matching end tag). Character references are decoded in text and values.
#
# One recursive def (`go`) walks the characters; two pure helpers give the
# next mode and the tokens a character completes.

type Tok is Data:
  TStart{name: String, attrs: +List<Dom.Attr>, self_close: Bool}
  TEnd{name: String}
  TText{text: String}
  TComment{text: String}

# A tag being read: name (reversed chars), attributes (newest first), and
# whether it is an end tag.
type Tag is Data:
  HTag{name: +List<Char>, attrs: +List<Dom.Attr>, end: Bool}

type Mode is Data:
  HData{text: +List<Char>}
  HTagOpen{}
  HEndOpen{}
  HTagName{tag: Tag}
  HBeforeAttr{tag: Tag}
  HAttrName{tag: Tag, name: +List<Char>}
  HAfterAttrName{tag: Tag, name: +List<Char>}
  HBeforeVal{tag: Tag, name: +List<Char>}
  HValQ{tag: Tag, name: +List<Char>, quote: Char, val: +List<Char>}
  HValUnq{tag: Tag, name: +List<Char>, val: +List<Char>}
  HAfterVal{tag: Tag}
  HSelfClose{tag: Tag}
  HMarkup{dashes: U32}
  HComment{d1: Bool, d2: Bool, text: +List<Char>}
  HBogus{text: +List<Char>}
  HRaw{tag: String, text: +List<Char>}

def str(cs: List<&2, Char>) -> String:
  String.from_list(List.reverse(&2, Char, cs))

def lower(+c: Char) -> Char:
  Char.to_lower(c)

def is_ws(+c: Char) -> Bool:
  Char.is_space(c)

def is_raw(+name: String) -> Bool:
  String.eq(name, "script") || String.eq(name, "style") || String.eq(name, "title") || String.eq(name, "textarea")

def tag_name(t: Tag) -> String:
  match t:
    case HTag{name, attrs, end}:
      str(name)

def tag_end(t: Tag) -> Bool:
  match t:
    case HTag{name, attrs, end}:
      end

def add_char(t: Tag, +c: Char) -> Tag:
  match t:
    case HTag{name, attrs, end}:
      HTag{lower(c) <> name, attrs, end}

# NUL (U+0000): dropped from text (the tree builder ignores it in a body),
# U+FFFD in raw text and attribute values (WHATWG 13.2.5).
def nul_go(s: String, +keep: Bool) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, t}:
      +rest = nul_go(t, keep)
      +nul = U32.is_zero(Char.to_u32(c))
      Bool.pick(String, nul && Bool.not(keep), rest, SCon{Bool.pick(Char, nul, Char.from_u32(65533), c), rest})

def has_nul(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{c, t}:
      U32.is_zero(Char.to_u32(c)) || has_nul(t)

def nul_if(any: Bool, +s: String, +keep: Bool) -> String:
  match any:
    case False{}:
      s
    case True{}:
      nul_go(s, keep)

# Most text has no NUL: one scan, and it comes back unchanged.
def nuls(+s: String, +keep: Bool) -> String:
  nul_if(has_nul(s), s, keep)

def add_attr(t: Tag, +name: List<&2, Char>, +val: List<&2, Char>) -> Tag:
  match t:
    case HTag{tn, attrs, end}:
      HTag{tn, Dom.Attr{str(name), nuls(Ent.decode_attr(str(val)), True{})} <> attrs, end}

def token_of(t: Tag, +self: Bool) -> Tok:
  match t:
    case HTag{+name, attrs, end}:
      match end:
        case True{}:
          TEnd{str(name)}
        case False{}:
          TStart{str(name), List.reverse(&2, Dom.Attr, attrs), self}

# After '>': back to text, or into raw text for <script>, <style>, ...
def after_tag(+t: Tag) -> Mode:
  Bool.pick(Mode, is_raw(tag_name(t)) && Bool.not(tag_end(t)), HRaw{tag_name(t), Nil{}}, HData{Nil{}})

def text_tok(+cs: List<&2, Char>) -> List<&2, Tok>:
  match cs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      [TText{nuls(Ent.decode(str(Con{h, t})), False{})}]

# Raw text: <title> and <textarea> decode character references (RCDATA),
# <script> and <style> do not (RAWTEXT, script data).
def raw_tok(+cs: List<&2, Char>, +tag: String) -> List<&2, Tok>:
  match cs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      +rc = String.eq(tag, "title") || String.eq(tag, "textarea")
      [TText{nuls(Bool.pick(String, rc, Ent.decode(str(Con{h, t})), str(Con{h, t})), True{})}]

# Does the reversed text end with "</" + tag (any case)? `rev` is newest first.
def ends_with_close(+rev: List<&2, Char>, +tag: String) -> Bool:
  String.eq(String.to_lower(str(List.take(&2, Char, rev, Nat.add(String.length(tag), 2n)))), "</" ++ tag)

# ---- comments --------------------------------------------------------------------
# A comment ends at "-->"; "<!-->" and "<!--->" are empty ones (WHATWG
# 13.2.5.43-44, abrupt closing). `text` holds what came after "<!--",
# newest first, with the closing dashes in it.
def one_char(xs: List<&2, Char>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{h, t}:
      List.is_empty(&2, Char, t)

# (checked at every character of a comment: no length, which would walk it)
# "--!>" also ends one (13.2.5.52, comment end bang)
def bang_end(xs: List<&2, Char>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{a, t}:
      match t:
        case Nil{}:
          False{}
        case Con{b, u}:
          match u:
            case Nil{}:
              False{}
            case Con{d, w}:
              Char.is_eq(a, '!') && Char.is_eq(b, '-') && Char.is_eq(d, '-')

def comment_ends(+c: Char, +d1: Bool, +d2: Bool, +text: List<&2, Char>) -> Bool:
  Char.is_eq(c, '>') && ((d1 && d2) || List.is_empty(&2, Char, text) || (d2 && one_char(text)) || bang_end(text))

def comment_data(+d1: Bool, +d2: Bool, +text: List<&2, Char>) -> String:
  +bang = bang_end(text)
  nuls(Bool.pick(String, bang, str(List.drop(&2, Char, text, 3n)),
    Bool.pick(String, d1 && d2 && Nat.is_ge(List.length(&2, Char, text), 2n), str(List.drop(&2, Char, text, 2n)), SNil{})), True{})

# <?target ...>: a processing instruction when the target is a name (an
# ASCII letter or "_", then letters, digits, "-" or "_") not starting with
# "xml";
# any other <?...> is a bogus comment (as Chrome parses them).
def pi_char(+c: Char) -> Bool:
  +u = Char.to_u32(c)
  (u < 128 : U32) && (Char.is_alpha(c) || Char.is_digit(c) || Char.is_eq(c, '-') || Char.is_eq(c, '_'))

def pi_rest(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+c, t}:
      Bool.pick(Bool, Char.is_space(c) || Char.is_eq(c, '?'), True{}, pi_char(c) && pi_rest(t))

def pi_target(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{+c, t}:
      +u = Char.to_u32(c)
      (Char.is_alpha(c) || Char.is_eq(c, '_')) && (u < 128 : U32) && pi_rest(t)

def is_pi(+s: String) -> Bool:
  String.starts_with(s, "?") && pi_target(String.drop(s, 1n)) && Bool.not(String.starts_with(String.to_lower(s), "?xml"))

# A bogus comment (<!...>, </ ...>) is a comment of its text. A DOCTYPE,
# and <?...> (Chrome makes it a processing instruction node), are nodes
# this DOM does not keep.
def bogus_emit(ends: Bool, +text: List<&2, Char>) -> List<&2, Tok>:
  match ends:
    case True{}:
      +s = str(text)
      Bool.pick(List<&2, Tok>, String.starts_with(String.to_lower(s), "doctype") || is_pi(s), Nil{}, [TComment{nuls(s, True{})}])
    case False{}:
      Nil{}

def comment_emit(ends: Bool, +d1: Bool, +d2: Bool, +text: List<&2, Char>) -> List<&2, Tok>:
  match ends:
    case True{}:
      [TComment{comment_data(d1, d2, text)}]
    case False{}:
      Nil{}

# ---- transitions -------------------------------------------------------------

# An attribute value is decoded once, when it ends (a match, not a Bool.pick,
# which would decode the whole value again at every character).
def valq_next(close: Bool, +tag: Tag, +name: List<&2, Char>, +quote: Char, +val: List<&2, Char>, +c: Char) -> Mode:
  match close:
    case True{}:
      HAfterVal{add_attr(tag, name, val)}
    case False{}:
      HValQ{tag, name, quote, c <> val}

def valunq_next(ws: Bool, gt: Bool, +tag: Tag, +name: List<&2, Char>, +val: List<&2, Char>, +c: Char) -> Mode:
  match ws gt:
    case True{} _:
      HBeforeAttr{add_attr(tag, name, val)}
    case False{} True{}:
      after_tag(add_attr(tag, name, val))
    case False{} False{}:
      HValUnq{tag, name, c <> val}

def next_mode(m: Mode, +c: Char) -> Mode:
  match m:
    case HData{+text}:
      Bool.pick(Mode, Char.is_eq(c, '<'), HTagOpen{}, HData{c <> text})
    case HTagOpen{}:
      Bool.pick(Mode, Char.is_eq(c, '!'), HMarkup{0},
        Bool.pick(Mode, Char.is_eq(c, '/'), HEndOpen{},
          Bool.pick(Mode, Char.is_alpha(c), HTagName{HTag{[lower(c)], Nil{}, False{}}},
            Bool.pick(Mode, Char.is_eq(c, '?'), HBogus{[c]}, HData{[c, '<']}))))
    case HEndOpen{}:
      Bool.pick(Mode, Char.is_alpha(c), HTagName{HTag{[lower(c)], Nil{}, True{}}},
        Bool.pick(Mode, Char.is_eq(c, '>'), HData{Nil{}}, HBogus{[c]}))
    case HTagName{+tag}:
      Bool.pick(Mode, is_ws(c), HBeforeAttr{tag},
        Bool.pick(Mode, Char.is_eq(c, '/'), HSelfClose{tag},
          Bool.pick(Mode, Char.is_eq(c, '>'), after_tag(tag), HTagName{add_char(tag, c)})))
    case HBeforeAttr{+tag}:
      Bool.pick(Mode, is_ws(c), HBeforeAttr{tag},
        Bool.pick(Mode, Char.is_eq(c, '/'), HSelfClose{tag},
          Bool.pick(Mode, Char.is_eq(c, '>'), after_tag(tag), HAttrName{tag, [lower(c)]})))
    case HAttrName{+tag, +name}:
      Bool.pick(Mode, Char.is_eq(c, '='), HBeforeVal{tag, name},
        Bool.pick(Mode, is_ws(c), HAfterAttrName{tag, name},
          Bool.pick(Mode, Char.is_eq(c, '>'), after_tag(add_attr(tag, name, Nil{})),
            Bool.pick(Mode, Char.is_eq(c, '/'), HSelfClose{add_attr(tag, name, Nil{})}, HAttrName{tag, lower(c) <> name}))))
    case HAfterAttrName{+tag, +name}:
      Bool.pick(Mode, is_ws(c), HAfterAttrName{tag, name},
        Bool.pick(Mode, Char.is_eq(c, '='), HBeforeVal{tag, name},
          Bool.pick(Mode, Char.is_eq(c, '>'), after_tag(add_attr(tag, name, Nil{})),
            Bool.pick(Mode, Char.is_eq(c, '/'), HSelfClose{add_attr(tag, name, Nil{})}, HAttrName{add_attr(tag, name, Nil{}), [lower(c)]}))))
    case HBeforeVal{+tag, +name}:
      Bool.pick(Mode, is_ws(c), HBeforeVal{tag, name},
        Bool.pick(Mode, Char.is_eq(c, '"') || Char.is_eq(c, '\''), HValQ{tag, name, c, Nil{}},
          Bool.pick(Mode, Char.is_eq(c, '>'), after_tag(add_attr(tag, name, Nil{})), HValUnq{tag, name, [c]})))
    case HValQ{+tag, +name, +quote, +val}:
      valq_next(Char.is_eq(c, quote), tag, name, quote, val, c)
    case HValUnq{+tag, +name, +val}:
      valunq_next(is_ws(c), Char.is_eq(c, '>'), tag, name, val, c)
    case HAfterVal{+tag}:
      Bool.pick(Mode, is_ws(c), HBeforeAttr{tag},
        Bool.pick(Mode, Char.is_eq(c, '/'), HSelfClose{tag},
          Bool.pick(Mode, Char.is_eq(c, '>'), after_tag(tag), HAttrName{tag, [lower(c)]})))
    case HSelfClose{+tag}:
      Bool.pick(Mode, Char.is_eq(c, '>'), HData{Nil{}}, HBeforeAttr{tag})
    case HMarkup{+dashes}:
      Bool.pick(Mode, Char.is_eq(c, '-') && U32.is_zero(dashes), HMarkup{1},
        Bool.pick(Mode, Char.is_eq(c, '-'), HComment{False{}, False{}, Nil{}},
          Bool.pick(Mode, Char.is_eq(c, '>'), HData{Nil{}}, HBogus{Bool.pick(List<&2, Char>, U32.is_zero(dashes), [c], [c, '-'])})))
    case HComment{+d1, +d2, +text}:
      Bool.pick(Mode, comment_ends(c, d1, d2, text), HData{Nil{}}, HComment{d2, Char.is_eq(c, '-'), c <> text})
    case HBogus{+text}:
      Bool.pick(Mode, Char.is_eq(c, '>'), HData{Nil{}}, HBogus{c <> text})
    case HRaw{+tag, +text}:
      Bool.pick(Mode, ends_with_close(c <> text, tag),
        HTagName{HTag{List.reverse(&2, Char, String.to_list(tag)), Nil{}, True{}}},
        HRaw{tag, c <> text})

# The text is decoded only when a token completes: these match on the
# decision, so the decode never runs per character (a Bool.pick would).
def tag_emit(gt: Bool, +tag: Tag, +self: Bool) -> List<&2, Tok>:
  match gt:
    case True{}:
      [token_of(tag, self)]
    case False{}:
      Nil{}

def data_emit(lt: Bool, +text: List<&2, Char>) -> List<&2, Tok>:
  match lt:
    case True{}:
      text_tok(text)
    case False{}:
      Nil{}

def raw_emit(done: Bool, +rev: List<&2, Char>, +tag: String) -> List<&2, Tok>:
  match done:
    case True{}:
      raw_tok(List.drop(&2, Char, rev, Nat.add(String.length(tag), 2n)), tag)
    case False{}:
      Nil{}

# Tokens completed by reading `c` in mode `m`.
def emits(m: Mode, +c: Char) -> List<&2, Tok>:
  match m:
    case HData{+text}:
      data_emit(Char.is_eq(c, '<'), text)
    case HTagName{+tag}:
      tag_emit(Char.is_eq(c, '>'), tag, False{})
    case HBeforeAttr{+tag}:
      tag_emit(Char.is_eq(c, '>'), tag, False{})
    case HAttrName{+tag, +name}:
      tag_emit(Char.is_eq(c, '>'), add_attr(tag, name, Nil{}), False{})
    case HAfterAttrName{+tag, +name}:
      tag_emit(Char.is_eq(c, '>'), add_attr(tag, name, Nil{}), False{})
    case HBeforeVal{+tag, +name}:
      tag_emit(Char.is_eq(c, '>'), add_attr(tag, name, Nil{}), False{})
    case HValUnq{+tag, +name, +val}:
      tag_emit(Char.is_eq(c, '>'), add_attr(tag, name, val), False{})
    case HAfterVal{+tag}:
      tag_emit(Char.is_eq(c, '>'), tag, False{})
    case HSelfClose{+tag}:
      tag_emit(Char.is_eq(c, '>'), tag, True{})
    case HRaw{+tag, +text}:
      raw_emit(ends_with_close(c <> text, tag), c <> text, tag)
    case HTagOpen{}:
      Nil{}
    case HEndOpen{}:
      Nil{}
    case HValQ{tag, name, quote, val}:
      Nil{}
    case HMarkup{dashes}:
      Nil{}
    case HComment{+d1, +d2, +text}:
      comment_emit(comment_ends(c, d1, d2, text), d1, d2, text)
    case HBogus{+text}:
      bogus_emit(Char.is_eq(c, '>'), text)

def at_eof(m: Mode) -> List<&2, Tok>:
  match m:
    case HData{text}:
      text_tok(text)
    case HRaw{+tag, text}:
      raw_tok(text, tag)
    case HTagOpen{}:
      [TText{"<"}]
    case HEndOpen{}:
      Nil{}
    case HTagName{tag}:
      Nil{}
    case HBeforeAttr{tag}:
      Nil{}
    case HAttrName{tag, name}:
      Nil{}
    case HAfterAttrName{tag, name}:
      Nil{}
    case HBeforeVal{tag, name}:
      Nil{}
    case HValQ{tag, name, quote, val}:
      Nil{}
    case HValUnq{tag, name, val}:
      Nil{}
    case HAfterVal{tag}:
      Nil{}
    case HSelfClose{tag}:
      Nil{}
    case HMarkup{dashes}:
      Nil{}
    # the end of input inside a comment ends it (eof-in-comment)
    case HComment{d1, d2, +text}:
      [TComment{str(text)}]
    # a <? the input ends in is no node
    case HBogus{+text}:
      bogus_emit(Bool.not(String.starts_with(str(text), "?")), text)

def rev_append(xs: List<&2, Tok>, acc: List<&2, Tok>) -> List<&2, Tok>:
  match xs:
    case Nil{}:
      acc
    case Con{h, t}:
      rev_append(t, h <> acc)

# Tokens newest first; `tokenize` returns them in order.
def go(s: String, +m: Mode, +acc: List<&2, Tok>) -> List<&2, Tok>:
  match s:
    case SNil{}:
      List.reverse(&2, Tok, rev_append(at_eof(m), acc))
    case SCon{+c, t}:
      go(t, next_mode(m, c), rev_append(emits(m, c), acc))

def tokenize(s: String) -> List<&2, Tok>:
  go(s, HData{Nil{}}, Nil{})
