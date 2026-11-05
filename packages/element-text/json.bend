import Base

# JSON (RFC 8259): parse text into a value and write a value as text.
# Numbers keep their source text (JNum "12.5"): callers read what they need
# (num_u32). Strings decode every escape, \uXXXX with surrogate pairs;
# writing escapes '"', '\' and control characters.
#
# Shape: Bend has no mutual recursion, so parsing is a token list folded by
# one def over an explicit stack of open arrays and objects, and writing is
# one def over a list of values (an object is its keys beside its values).

type Json is Data:
  JNull{}
  JBool{b: Bool}
  JNum{n: String}
  JStr{s: String}
  JArr{items: +List<Json>}
  JObj{keys: +List<String>, vals: +List<Json>}

# ---- tokens --------------------------------------------------------------------------

type Tok is Data:
  TOpen{obj: Bool}
  TClose{obj: Bool}
  TColon{}
  TComma{}
  TVal{v: Json}
  TBad{}

def rev_str(cs: List<&2, Char>) -> String:
  String.from_list(List.reverse(&2, Char, cs))

def hex_val(+c: U32) -> U32:
  Bool.pick(U32, (c >= 97 : U32), (c - 87 : U32), Bool.pick(U32, (c >= 65 : U32), (c - 55 : U32), (c - 48 : U32)))

def nth_c(xs: List<&2, Char>, n: Nat) -> Char:
  match xs:
    case Nil{}:
      '0'
    case Con{h, t}:
      match n:
        case 0n:
          h
        case 1n+r:
          nth_c(t, r)

def hex4(+s: String) -> U32:
  +cs = String.to_list(String.take(s, 4n))
  ((((hex_val(Char.to_u32(nth_c(cs, 0n))) * 4096 : U32) + (hex_val(Char.to_u32(nth_c(cs, 1n))) * 256 : U32) : U32) +
    (hex_val(Char.to_u32(nth_c(cs, 2n))) * 16 : U32) : U32) + hex_val(Char.to_u32(nth_c(cs, 3n))) : U32)

# What a backslash escape turns into, and how many characters it took after
# the backslash.
type Esc is Data:
  Esc{c: U32, used: Nat}

def esc_of(+s: String) -> Esc:
  +e = Char.to_u32(nth_c(String.to_list(String.take(s, 1n)), 0n))
  +u = hex4(String.drop(s, 1n))
  +pair = (u >= 55296 : U32) && (u <= 56319 : U32) && String.starts_with(String.drop(s, 5n), "\\u")
  +lo = hex4(String.drop(s, 7n))
  Bool.pick(Esc, U32.is_eq(e, 117),
    Bool.pick(Esc, pair && (lo >= 56320 : U32) && (lo <= 57343 : U32),
      Esc{((65536 + ((u - 55296 : U32) * 1024 : U32) : U32) + (lo - 56320 : U32) : U32), 11n},
      Esc{Bool.pick(U32, (u >= 55296 : U32) && (u <= 57343 : U32), 65533, u), 5n}),
    Esc{Bool.pick(U32, U32.is_eq(e, 110), 10, Bool.pick(U32, U32.is_eq(e, 116), 9, Bool.pick(U32, U32.is_eq(e, 114), 13,
      Bool.pick(U32, U32.is_eq(e, 98), 8, Bool.pick(U32, U32.is_eq(e, 102), 12, e))))), 1n})

def esc_c(e: Esc) -> U32:
  match e:
    case Esc{c, used}:
      c

def esc_used(e: Esc) -> Nat:
  match e:
    case Esc{c, used}:
      used

# The string body after an opening quote: its characters (reversed) and how
# many source characters it took, closing quote included.
type Str is Data:
  Str{rev: List<&2, Char>, used: Nat}

type SK is Data:
  SChar{}
  SClose{}
  SEsc{}

def sk_of(s: String) -> SK:
  match s:
    case SNil{}:
      SClose{}
    case SCon{+c, t}:
      Bool.pick(SK, Char.is_eq(c, '"'), SClose{}, Bool.pick(SK, Char.is_eq(c, '\\'), SEsc{}, SChar{}))

def after_esc(+t: String) -> String:
  String.drop(t, esc_used(esc_of(t)))

# `k` classifies the head of s (computed by the caller): a plain character,
# the closing quote (or the end), or a backslash escape.
def str_step(fuel: Nat, s: String, +acc: List<&2, Char>, +used: Nat, k: SK) -> Str:
  match fuel:
    case 0n:
      Str{acc, used}
    case 1n+f:
      match s:
        case SNil{}:
          Str{acc, used}
        case SCon{+c, +t}:
          match k:
            case SClose{}:
              Str{acc, Nat.add(used, 1n)}
            case SChar{}:
              str_step(f, t, c <> acc, Nat.add(used, 1n), sk_of(t))
            case SEsc{}:
              +e = esc_of(t)
              +rest = after_esc(t)
              str_step(f, rest, Char.from_u32(esc_c(e)) <> acc, Nat.add(used, Nat.add(esc_used(e), 1n)), sk_of(rest))

def num_char(+c: Char) -> Bool:
  Char.is_digit(c) || Char.is_eq(c, '-') || Char.is_eq(c, '+') || Char.is_eq(c, '.') || Char.is_eq(c, 'e') || Char.is_eq(c, 'E')

def num_head(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{+c, t}:
      num_char(c)

# The number at the head of s. `go` (the caller's test of the head) stops the
# walk at the number's end; a Bool.pick here walked the whole rest of the text
# for every number (bench json: k 1.98).
def num_run(s: String, go: Bool) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, +t}:
      match go:
        case False{}:
          SNil{}
        case True{}:
          SCon{c, num_run(t, num_head(t))}

type TK is Data:
  KSpace{}
  KPunct{}
  KStr{}
  KNum{}
  KWord{}
  KBad{}

def tk_of(+c: Char) -> TK:
  Bool.pick(TK, Char.is_space(c), KSpace{},
    Bool.pick(TK, Char.is_eq(c, '{') || Char.is_eq(c, '}') || Char.is_eq(c, '[') || Char.is_eq(c, ']') || Char.is_eq(c, ':') || Char.is_eq(c, ','), KPunct{},
      Bool.pick(TK, Char.is_eq(c, '"'), KStr{},
        Bool.pick(TK, Char.is_digit(c) || Char.is_eq(c, '-'), KNum{},
          Bool.pick(TK, Char.is_eq(c, 't') || Char.is_eq(c, 'f') || Char.is_eq(c, 'n'), KWord{}, KBad{})))))

def punct(+c: Char) -> Tok:
  Bool.pick(Tok, Char.is_eq(c, '{'), TOpen{True{}}, Bool.pick(Tok, Char.is_eq(c, '['), TOpen{False{}},
    Bool.pick(Tok, Char.is_eq(c, '}'), TClose{True{}}, Bool.pick(Tok, Char.is_eq(c, ']'), TClose{False{}},
      Bool.pick(Tok, Char.is_eq(c, ':'), TColon{}, TComma{})))))

# One token at the head of s (after character c) and how many characters it took.
type Step is Data:
  Step{tok: Maybe<&2, Tok>, used: Nat}

def word(+s: String) -> Step:
  Bool.pick(Step, String.starts_with(s, "true"), Step{Some{TVal{JBool{True{}}}}, 4n},
    Bool.pick(Step, String.starts_with(s, "false"), Step{Some{TVal{JBool{False{}}}}, 5n},
      Bool.pick(Step, String.starts_with(s, "null"), Step{Some{TVal{JNull{}}}, 4n}, Step{Some{TBad{}}, 1n})))

def str_tok(r: Str) -> Step:
  match r:
    case Str{rev, used}:
      Step{Some{TVal{JStr{rev_str(rev)}}}, Nat.add(used, 1n)}

# `fuel` is the tokenizer's own (no String.length of the rest per string,
# which made parsing quadratic in the number of strings).
def string_tok(+fuel: Nat, +t: String) -> Step:
  str_tok(str_step(fuel, t, Nil{}, 0n, sk_of(t)))

def step_of(k: TK, +c: Char, +s: String, +t: String, +fuel: Nat) -> Step:
  match k:
    case KSpace{}:
      Step{None{}, 1n}
    case KPunct{}:
      Step{Some{punct(c)}, 1n}
    case KStr{}:
      string_tok(fuel, t)
    case KNum{}:
      +n = num_run(s, num_head(s))
      Step{Some{TVal{JNum{n}}}, String.length(n)}
    case KWord{}:
      word(s)
    case KBad{}:
      Step{Some{TBad{}}, 1n}

def step_tok(st: Step) -> Maybe<&2, Tok>:
  match st:
    case Step{tok, used}:
      tok

def step_used(st: Step) -> Nat:
  match st:
    case Step{tok, used}:
      used

def push_m(m: Maybe<&2, Tok>, +acc: List<&2, Tok>) -> List<&2, Tok>:
  match m:
    case None{}:
      acc
    case Some{value}:
      value <> acc

def tokens(fuel: Nat, s: String, +acc: List<&2, Tok>) -> List<&2, Tok>:
  match fuel:
    case 0n:
      List.reverse(&2, Tok, acc)
    case 1n+(+f):
      match s:
        case SNil{}:
          List.reverse(&2, Tok, acc)
        case SCon{+c, +t}:
          +st = step_of(tk_of(c), c, SCon{c, t}, t, f)
          tokens(f, String.drop(SCon{c, t}, step_used(st)), push_m(step_tok(st), acc))

# ---- building ------------------------------------------------------------------------

# An open container: an array's items, or an object's keys and values so
# far (reversed), with the key waiting for its value.
type Frame is Data:
  FArr{items: +List<Json>}
  FObj{keys: +List<String>, vals: +List<Json>, key: Maybe<&2, String>}

# The stack of open frames and the finished top-level value.
type B is Data:
  B{stack: +List<Frame>, done: Maybe<&2, Json>, bad: Bool}

def str_of_json(j: Json) -> Maybe<&2, String>:
  match j:
    case JStr{s}:
      Some{s}
    case JNull{}:
      None{}
    case JBool{b}:
      None{}
    case JNum{n}:
      None{}
    case JArr{items}:
      None{}
    case JObj{keys, vals}:
      None{}

# A value lands in the top frame: an array item, an object key (a string
# when no key waits), or the value for the waiting key.
def add_val(stack: List<&2, Frame>, +v: Json, +done: Maybe<&2, Json>) -> B:
  match stack:
    case Nil{}:
      B{Nil{}, Some{v}, False{}}
    case Con{f, t}:
      match f:
        case FArr{+items}:
          B{FArr{v <> items} <> t, done, False{}}
        case FObj{+keys, +vals, key}:
          match key:
            case None{}:
              B{FObj{keys, vals, str_of_json(v)} <> t, done, False{}}
            case Some{k}:
              B{FObj{k <> keys, v <> vals, None{}} <> t, done, False{}}

def close_top(stack: List<&2, Frame>, +done: Maybe<&2, Json>) -> B:
  match stack:
    case Nil{}:
      B{Nil{}, done, True{}}
    case Con{f, t}:
      match f:
        case FArr{items}:
          add_val(t, JArr{List.reverse(&2, Json, items)}, done)
        case FObj{keys, vals, key}:
          add_val(t, JObj{List.reverse(&2, String, keys), List.reverse(&2, Json, vals)}, done)

def on_tok(b: B, t: Tok) -> B:
  match b:
    case B{+stack, +done, +bad}:
      match t:
        case TOpen{obj}:
          B{Bool.pick(Frame, obj, FObj{Nil{}, Nil{}, None{}}, FArr{Nil{}}) <> stack, done, bad}
        case TClose{obj}:
          close_top(stack, done)
        case TColon{}:
          B{stack, done, bad}
        case TComma{}:
          B{stack, done, bad}
        case TVal{v}:
          add_val(stack, v, done)
        case TBad{}:
          B{stack, done, True{}}

def build(ts: List<&2, Tok>, +b: B) -> B:
  match ts:
    case Nil{}:
      b
    case Con{t, rest}:
      build(rest, on_tok(b, t))

def result(b: B) -> Maybe<&2, Json>:
  match b:
    case B{stack, done, bad}:
      Bool.pick(Maybe<&2, Json>, bad || Bool.not(List.is_empty(&2, Frame, stack)), None{}, done)

# A JSON text as a value; None when it is not JSON. (Lenient in one way:
# commas and colons are not checked for position.)
def parse(+s: String) -> Maybe<&2, Json>:
  result(build(tokens(String.length(s), s, Nil{}), B{Nil{}, None{}, False{}}))

# ---- writing -------------------------------------------------------------------------

def hex_digit(+n: U32) -> String:
  String.from_list([Char.from_u32(Bool.pick(U32, (n < 10 : U32), (n + 48 : U32), (n + 87 : U32)))])

# What a character becomes in a JSON string: 0 \", 1 \\, 2 a short escape
# (\b \t \n \f \r, as ES QuoteJSONString writes them), 3 \u00XX (another
# control), 4 \uXXXX (a surrogate code point: a JS string can hold one, and
# it is not valid UTF-8 on the wire; Chrome's JSON escapes it too), 5 itself.
# A match, not Bool.pick: only the character's own escape is built.
def esc_kind(+c: Char) -> U32:
  +u = Char.to_u32(c)
  Bool.pick(U32, Char.is_eq(c, '"'), 0, Bool.pick(U32, Char.is_eq(c, '\\'), 1, Bool.pick(U32, (u >= 8 : U32) && (u <= 13 : U32) && Bool.not(U32.is_eq(u, 11)), 2,
    Bool.pick(U32, (u < 32 : U32), 3, Bool.pick(U32, (u >= 55296 : U32) && (u <= 57343 : U32), 4, 5)))))

def esc_as(k: Nat, +c: Char) -> String:
  match k:
    case 0n:
      "\\\""
    case 1n:
      "\\\\"
    case 2n:
      +u = Char.to_u32(c)
      Bool.pick(String, U32.is_eq(u, 8), "\\b", Bool.pick(String, U32.is_eq(u, 9), "\\t", Bool.pick(String, U32.is_eq(u, 10), "\\n", Bool.pick(String, U32.is_eq(u, 12), "\\f", "\\r"))))
    case 3n:
      +u = Char.to_u32(c)
      "\\u00" ++ hex_digit((u / 16 : U32)) ++ hex_digit((u % 16 : U32))
    case 4n:
      +u = Char.to_u32(c)
      "\\u" ++ hex_digit((u / 4096 : U32)) ++ hex_digit((u / 256 % 16 : U32)) ++ hex_digit((u / 16 % 16 : U32)) ++ hex_digit((u % 16 : U32))
    case 5n+r:
      String.from_list([c])

def esc_char(+c: Char) -> String:
  esc_as(U32.to_nat(esc_kind(c)), c)

def esc_go(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{c, t}:
      esc_char(c) ++ esc_go(t)

def quote(+s: String) -> String:
  "\"" ++ esc_go(s) ++ "\"" 

def first_s(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      h

def rest_s(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

def sep_key(+first: Bool, +obj: Bool, +keys: List<&2, String>) -> String:
  Bool.pick(String, first, "", ",") ++ Bool.pick(String, obj, quote(first_s(keys)) ++ ":", "")

# Values separated by commas; `keys` beside them when they are an object's.
def show_items(xs: List<&2, Json>, +keys: List<&2, String>, +obj: Bool, +first: Bool) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{x, t}:
      match x:
        case JNull{}:
          sep_key(first, obj, keys) ++ "null" ++ show_items(t, rest_s(keys), obj, False{})
        case JBool{b}:
          sep_key(first, obj, keys) ++ Bool.pick(String, b, "true", "false") ++ show_items(t, rest_s(keys), obj, False{})
        case JNum{n}:
          sep_key(first, obj, keys) ++ n ++ show_items(t, rest_s(keys), obj, False{})
        case JStr{s}:
          sep_key(first, obj, keys) ++ quote(s) ++ show_items(t, rest_s(keys), obj, False{})
        case JArr{its}:
          sep_key(first, obj, keys) ++ "[" ++ show_items(its, Nil{}, False{}, True{}) ++ "]" ++ show_items(t, rest_s(keys), obj, False{})
        case JObj{ks, vs}:
          sep_key(first, obj, keys) ++ "{" ++ show_items(vs, ks, True{}, True{}) ++ "}" ++ show_items(t, rest_s(keys), obj, False{})

def show(+v: Json) -> String:
  show_items([v], Nil{}, False{}, True{})

def show_or(m: Maybe<&2, Json>, +d: String) -> String:
  match m:
    case None{}:
      d
    case Some{v}:
      show(v)

# ---- reading values -------------------------------------------------------------------

def lookup(ks: List<&2, String>, vs: List<&2, Json>, +key: String) -> Maybe<&2, Json>:
  match ks vs:
    case Con{k, kt} Con{v, vt}:
      Bool.pick(Maybe<&2, Json>, String.eq(k, key), Some{v}, lookup(kt, vt, key))
    case _ _:
      None{}

# An object's field.
def get(v: Json, +key: String) -> Maybe<&2, Json>:
  match v:
    case JObj{keys, vals}:
      lookup(keys, vals, key)
    case JNull{}:
      None{}
    case JBool{b}:
      None{}
    case JNum{n}:
      None{}
    case JStr{s}:
      None{}
    case JArr{items}:
      None{}

def text_or(m: Maybe<&2, Json>, +d: String) -> String:
  match m:
    case None{}:
      d
    case Some{v}:
      match v:
        case JStr{s}:
          s
        case JNum{n}:
          n
        case JBool{b}:
          Bool.pick(String, b, "true", "false")
        case JNull{}:
          d
        case JArr{items}:
          d
        case JObj{keys, vals}:
          d

def bool_or(m: Maybe<&2, Json>, +d: Bool) -> Bool:
  match m:
    case None{}:
      d
    case Some{v}:
      match v:
        case JBool{b}:
          b
        case JNull{}:
          d
        case JNum{n}:
          d
        case JStr{s}:
          d
        case JArr{items}:
          d
        case JObj{keys, vals}:
          d

def int_go(s: String, +acc: U32) -> U32:
  match s:
    case SNil{}:
      acc
    case SCon{+c, t}:
      Bool.pick(U32, Char.is_digit(c), int_go(t, ((acc * 10 : U32) + (Char.to_u32(c) - 48 : U32) : U32)), acc)

# The integer part of a number (or numeric string) as U32; `d` when absent.
def u32_or(+m: Maybe<&2, Json>, +d: U32) -> U32:
  +t = text_or(m, "")
  Bool.pick(U32, String.is_empty(t), d, int_go(t, 0))

def arr_or_empty(m: Maybe<&2, Json>) -> List<&2, Json>:
  match m:
    case None{}:
      Nil{}
    case Some{v}:
      match v:
        case JArr{items}:
          items
        case JNull{}:
          Nil{}
        case JBool{b}:
          Nil{}
        case JNum{n}:
          Nil{}
        case JStr{s}:
          Nil{}
        case JObj{keys, vals}:
          Nil{}
