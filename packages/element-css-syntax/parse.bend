import Base

# A CSS stylesheet split into rules, without interpreting them (CSS Syntax
# Level 3, reduced): comments are removed, at-rules (@media, @import,
# @font-face, @keyframes, ...) are not applied (@layer blocks are read, as
# media queries that hold: see media_query), and each style rule becomes
# its selector text and its declarations. A style rule inside `@media Q`
# keeps its selector as "@media Q" U+0001 selector (media_sep), for the
# caller to evaluate Q against a viewport. The declarations of every block
# nested in any other at-rule are kept as a rule whose selector is "@": nothing
# matches it, and it tells a reader which properties some rule Element does
# not apply may set (getComputedStyle refuses those rather than guess). Declarations
# are split at ';' into (property, value) with whitespace trimmed and the
# property lowercased; `!important` is dropped from the value.
#
# What selectors and values mean is left to the caller.

type Decl is Data:
  Decl{prop: String, value: String}

type Rule is Data:
  Rule{selector: String, decls: +List<Decl>}

def rev_str(cs: List<&2, Char>) -> String:
  String.from_list(List.reverse(&2, Char, cs))

# ---- comments ----------------------------------------------------------------

# One fold; `st`: 0 text, 1 saw '/', 2 inside a comment, 3 inside a comment
# after '*'. A comment becomes a single space.
def strip_go(s: String, +st: U32, +out: List<&2, Char>) -> List<&2, Char>:
  match s:
    case SNil{}:
      Bool.pick(List<&2, Char>, U32.is_eq(st, 1), '/' <> out, out)
    case SCon{+c, t}:
      +star = Char.is_eq(c, '*')
      +slash = Char.is_eq(c, '/')
      strip_go(
        t,
        Bool.pick(U32, U32.is_zero(st), Bool.pick(U32, slash, 1, 0),
          Bool.pick(U32, U32.is_eq(st, 1), Bool.pick(U32, star, 2, Bool.pick(U32, slash, 1, 0)),
            Bool.pick(U32, U32.is_eq(st, 2), Bool.pick(U32, star, 3, 2),
              Bool.pick(U32, slash, 0, Bool.pick(U32, star, 3, 2))))),
        Bool.pick(List<&2, Char>, U32.is_zero(st), Bool.pick(List<&2, Char>, slash, out, c <> out),
          Bool.pick(List<&2, Char>, U32.is_eq(st, 1), Bool.pick(List<&2, Char>, star, ' ' <> out, Bool.pick(List<&2, Char>, slash, '/' <> out, c <> ('/' <> out))),
            out))
      )

def strip_comments(s: String) -> String:
  rev_str(strip_go(s, 0, Nil{}))

# ---- rules -------------------------------------------------------------------------

# Where the scanner is: selector text, declarations, an at-rule prelude, an
# at-rule block (with its brace depth), or a quoted string in declarations.
type M is Data:
  MSel{}
  MDecl{}
  MPre{}
  MAt{depth: U32, kf: String}
  MStr{q: Char}
  MEsc{q: Char}
  # inside `@media q { ... }`: its style rules, a quoted string in one, and
  # another at-rule nested in it (skipped as MPre/MAt skip)
  MMSel{q: String}
  MMDecl{q: String}
  MMStr{q: String, quote: Char}
  MMEsc{q: String, quote: Char}
  MMPre{q: String}
  MMAt{q: String, depth: U32}

type St is Data:
  St{mode: M, sel: +List<Char>, body: +List<Char>, rules: +List<Rule>}

# Between a media query and the selector it guards (U+0001: no selector or
# query holds it).
def media_sep() -> String:
  String.from_list([Char.from_u32(1)])

# Leading whitespace dropped: one fold, `on` latches at the first non-space.
def trim_go(s: String, +on: Bool, +out: List<&2, Char>) -> List<&2, Char>:
  match s:
    case SNil{}:
      out
    case SCon{+h, t}:
      +keep = on || Bool.not(Char.is_space(h))
      trim_go(t, keep, Bool.pick(List<&2, Char>, keep, h <> out, out))


def trim_left(s: String) -> String:
  rev_str(trim_go(s, False{}, Nil{}))


def trim(+s: String) -> String:
  rev_str(String.to_list(trim_left(rev_str(String.to_list(trim_left(s))))))


# A prelude that opens `@media`: its query ("" when it is another at-rule).
# `@layer name {` opens the same way, its query U+0002 and the layer's name:
# its rules are ordinary ones in that cascade layer (css.bend resolve_one
# and compile rank them).
def media_query(+pre: String) -> String:
  +t = trim(pre)
  +low = String.to_lower(t)
  Bool.pick(String, String.starts_with(low, "layer") && Bool.not(String.contains(t, ",")), "\u{2}" ++ trim(String.drop(t, 5n)),
    Bool.pick(String, String.starts_with(low, "media") && Bool.not(String.eq(low, "media")), trim(String.drop(t, 5n)), ""))

# The name a @keyframes (or @-webkit-keyframes) prelude declares, else "".
def keyframes_name(+pre: String) -> String:
  +t = trim(pre)
  +low = String.to_lower(t)
  Bool.pick(String, String.starts_with(low, "keyframes"), trim(String.drop(t, 9n)),
    Bool.pick(String, String.starts_with(low, "-webkit-keyframes"), trim(String.drop(t, 17n)), ""))

# Opening an at-rule's block: @media parses its rules, any other is skipped
# (a @keyframes block remembers its name).
def open_at(+q: String, +kf: String, +rules: List<&2, Rule>) -> St:
  Bool.pick(St, String.is_empty(q), St{MAt{1, kf}, Nil{}, Nil{}, rules}, St{MMSel{q}, Nil{}, Nil{}, rules})

def has_colon(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{+h, t}:
      Char.is_eq(h, ':') || has_colon(t)


def before_colon(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      Bool.pick(String, Char.is_eq(h, ':'), SNil{}, SCon{h, before_colon(t)})


def before_bang(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      Bool.pick(String, Char.is_eq(h, '!'), SNil{}, SCon{h, before_bang(t)})


# "red !important" -> "red"
def drop_important(+v: String) -> String:
  trim(before_bang(v))


def after_colon(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, +t}:
      Bool.pick(String, Char.is_eq(h, ':'), t, after_colon(t))


def decls_of(xs: List<&2, String>) -> List<&2, Decl>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+d, t}:
      List.append(&2, Decl,
        Bool.pick(List<&2, Decl>, has_colon(d),
          [Decl{String.to_lower(trim(before_colon(d))), drop_important(after_colon(d))}], Nil{}),
        decls_of(t))


# The pieces so far, with the current one closed at a cut. (A pick here
# reversed the current piece at every char, cut or not: a split was
# quadratic in its pieces' length.)
def split_out(cut: Bool, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match cut:
    case True{}:
      rev_str(cur) <> out
    case False{}:
      out

# Split at every `sep` outside parentheses and quotes. `q` is the open quote
# character's code, 0 when outside a string. `esc`: the char before was a
# backslash, so this one is text: Tailwind's `.shadow-\[0_0_0_1px_x\,0_0_0_3px_y\]`
# is one selector, and a cut at its escaped comma made two no engine reads
# (each "may match anything": every element refused box-shadow).
def split_go(s: String, +sep: Char, +paren: U32, +q: U32, +esc: Bool, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, rev_str(cur) <> out)
    case SCon{+c, t}:
      +code = Char.to_u32(c)
      +bs = Bool.not(esc) && Char.is_eq(c, '\\')
      +live = Bool.not(esc) && Bool.not(bs)
      +quote = Char.is_eq(c, '"') || Char.is_eq(c, '\'')
      +cut = live && Char.is_eq(c, sep) && U32.is_zero(paren) && U32.is_zero(q)
      +p2 = Bool.pick(U32, Bool.not(U32.is_zero(q)), paren,
          Bool.pick(U32, Char.is_eq(c, '('), (paren + 1 : U32), Bool.pick(U32, Char.is_eq(c, ')') && (paren > 0 : U32), (paren - 1 : U32), paren)))
      +q2 = Bool.pick(U32, U32.is_zero(q), Bool.pick(U32, quote, code, 0), Bool.pick(U32, U32.is_eq(q, code), 0, q))
      split_go(
        t, sep,
        Bool.pick(U32, live, p2, paren),
        Bool.pick(U32, live, q2, q),
        bs,
        Bool.pick(List<&2, Char>, cut, Nil{}, c <> cur),
        split_out(cut, cur, out)
      )


def split(+s: String, +sep: Char) -> List<&2, String>:
  split_go(s, sep, 0, 0, False{}, Nil{}, Nil{})


def declarations(+text: String) -> List<&2, Decl>:
  decls_of(split(text, ';'))


# A rule inside @media closes as its selector guarded by the query.
def close_mrule(done: Bool, +q: String, +sel: List<&2, Char>, +body: List<&2, Char>, +rules: List<&2, Rule>, +c: Char) -> St:
  match done:
    case True{}:
      St{MMSel{q}, Nil{}, Nil{}, Rule{"@media " ++ q ++ media_sep() ++ trim(rev_str(sel)), declarations(rev_str(body))} <> rules}
    case False{}:
      St{Bool.pick(M, Char.is_eq(c, '"') || Char.is_eq(c, '\''), MMStr{q, c}, MMDecl{q}), sel, c <> body, rules}


# Closing a rule builds it once (a match, so the declarations are not split
# again at every character).
def close_rule(done: Bool, +sel: List<&2, Char>, +body: List<&2, Char>, +rules: List<&2, Rule>, +c: Char) -> St:
  match done:
    case True{}:
      St{MSel{}, Nil{}, Nil{}, Rule{trim(rev_str(sel)), declarations(rev_str(body))} <> rules}
    case False{}:
      St{Bool.pick(M, Char.is_eq(c, '"') || Char.is_eq(c, '\''), MStr{c}, MDecl{}), sel, c <> body, rules}

# An at-rule's block inside `@media Q` keeps Q as its guard ("@media Q"
# U+0001 "@sel"): a query that does not hold leaves it out, as any rule
# under Q. It lost Q, so `.x { @media (display-mode: standalone) {
# @supports (...) { display: none } } }` made display unsure on
# every .x though Element answers that the query does not hold. A layer's
# block (Q starting U+0002) keeps the "@" label alone, as before.
def guard_at(+q: String, +label: String) -> String:
  Bool.pick(String, String.starts_with(q, "\u{2}"), label, "@media " ++ q ++ media_sep() ++ label)

# The declarations a nested block of an at-rule held, as an "@" rule; the
# at-rule's own closing brace (depth 1) holds none.
def at_rule(outer: Bool, +label: String, +body: List<&2, Char>, +rules: List<&2, Rule>) -> List<&2, Rule>:
  match outer:
    case True{}:
      rules
    case False{}:
      Rule{label, declarations(rev_str(body))} <> rules

# What a nested block of a skipped at-rule may reach, for a reader to match:
# "@kf:NAME" for a keyframe of @keyframes NAME (it applies only through an
# animation naming it), "@" and the block's selector for a style rule inside
# @supports, @layer, @container... (only what that selector matches), and
# "@" alone when there is no selector (anything).
def at_label(+kf: String, +sel: List<&2, Char>) -> String:
  +s = trim(rev_str(sel))
  Bool.pick(String, String.is_empty(kf), "@" ++ s, "@kf:" ++ kf)

def at_start(is_at: Bool, +sel: List<&2, Char>) -> Bool:
  match is_at:
    case False{}:
      False{}
    case True{}:
      String.eq(trim(rev_str(sel)), "")

# `@layer a, b;` declares the layers' order: an empty rule per name, its
# layer before its (empty) selector, so the order is seen where it is
# declared (css.bend layer_names); it styles nothing.
def layer_rules(xs: List<&2, String>, +rules: List<&2, Rule>) -> List<&2, Rule>:
  match xs:
    case Nil{}:
      rules
    case Con{+x, t}:
      layer_rules(t, Rule{"\u{3}" ++ trim(x) ++ "\u{3}", Nil{}} <> rules)

def layer_stmt(+pre: String, +rules: List<&2, Rule>) -> List<&2, Rule>:
  +t = trim(pre)
  Bool.pick(List<&2, Rule>, String.starts_with(String.to_lower(t), "layer"), layer_rules(split(String.drop(t, 5n), ','), rules), rules)

# One character of the sheet.
def step(st: St, +c: Char) -> St:
  match st:
    case St{mode, +sel, +body, +rules}:
      match mode:
        case MSel{}:
          Bool.pick(St, at_start(Char.is_eq(c, '@'), sel), St{MPre{}, Nil{}, Nil{}, rules},
            Bool.pick(St, Char.is_eq(c, '{'), St{MDecl{}, sel, Nil{}, rules},
              Bool.pick(St, Char.is_eq(c, '}'), St{MSel{}, Nil{}, Nil{}, rules}, St{MSel{}, c <> sel, body, rules})))
        case MDecl{}:
          close_rule(Char.is_eq(c, '}'), sel, body, rules, c)
        case MStr{+q}:
          # a backslash escapes the next character: content:"\"" is one string (CSS Syntax 3, 4.3.5)
          St{Bool.pick(M, Char.is_eq(c, '\\'), MEsc{q}, Bool.pick(M, Char.is_eq(c, q), MDecl{}, MStr{q})), sel, c <> body, rules}
        case MEsc{+q}:
          St{MStr{q}, sel, c <> body, rules}
        case MPre{}:
          # the at-rule prelude is kept (in `sel`) to tell @media from the others
          Bool.pick(St, Char.is_eq(c, '{'), open_at(media_query(rev_str(sel)), keyframes_name(rev_str(sel)), rules),
            Bool.pick(St, Char.is_eq(c, ';'), St{MSel{}, Nil{}, Nil{}, layer_stmt(rev_str(sel), rules)}, St{MPre{}, c <> sel, Nil{}, rules}))
        case MMSel{+q}:
          Bool.pick(St, at_start(Char.is_eq(c, '@'), sel), St{MMPre{q}, Nil{}, Nil{}, rules},
            Bool.pick(St, Char.is_eq(c, '{'), St{MMDecl{q}, sel, Nil{}, rules},
              Bool.pick(St, Char.is_eq(c, '}'), St{MSel{}, Nil{}, Nil{}, rules}, St{MMSel{q}, c <> sel, body, rules})))
        case MMDecl{+q}:
          close_mrule(Char.is_eq(c, '}'), q, sel, body, rules, c)
        case MMStr{+q, +quote}:
          St{Bool.pick(M, Char.is_eq(c, '\\'), MMEsc{q, quote}, Bool.pick(M, Char.is_eq(c, quote), MMDecl{q}, MMStr{q, quote})), sel, c <> body, rules}
        case MMEsc{+q, +quote}:
          St{MMStr{q, quote}, sel, c <> body, rules}
        case MMPre{+q}:
          Bool.pick(St, Char.is_eq(c, '{'), St{MMAt{q, 1}, Nil{}, Nil{}, rules},
            Bool.pick(St, Char.is_eq(c, ';'), St{MMSel{q}, Nil{}, Nil{}, rules}, St{MMPre{q}, Nil{}, Nil{}, rules}))
        case MMAt{+q, +depth}:
          # as MAt: what came before a '{' (a selector) labels the block's
          # declarations ("@" alone would reach every element)
          Bool.pick(St, Char.is_eq(c, '{'), St{MMAt{q, U32.add(depth, 1)}, body, Nil{}, rules},
            Bool.pick(St, Char.is_eq(c, '}'),
              St{Bool.pick(M, U32.is_eq(depth, 1), MMSel{q}, MMAt{q, U32.sub(depth, 1)}), Nil{}, Nil{},
                at_rule(U32.is_eq(depth, 1), guard_at(q, at_label("", sel)), body, rules)},
              St{MMAt{q, depth}, sel, c <> body, rules}))
        case MAt{+depth, +kf}:
          # '{' starts a nested block (what came before it, kept in `sel`,
          # was a selector or an at-rule prelude, not declarations); '}'
          # closing a nested block keeps what it held as an "@" rule
          Bool.pick(St, Char.is_eq(c, '{'), St{MAt{U32.add(depth, 1), kf}, body, Nil{}, rules},
            Bool.pick(St, Char.is_eq(c, '}'),
              St{Bool.pick(M, U32.is_eq(depth, 1), MSel{}, MAt{U32.sub(depth, 1), kf}), Nil{}, Nil{},
                at_rule(U32.is_eq(depth, 1), at_label(kf, sel), body, rules)},
              St{MAt{depth, kf}, sel, c <> body, rules}))

# ---- CSS Nesting (CSS Nesting 1; Chrome 120+), flattened before parsing -------------
#
# `a { color: red; & b { x: 1 } .c { y: 2 } @media (q) { z: 3 } }` becomes
# `a{color: red;}a b{x: 1}a .c{y: 2}@media (q){a{z: 3}}`: a nested selector
# with `&` takes the parent for it, one without is a descendant of it, a
# nested at-rule wraps the parent's selector; a list (`a, b`) is crossed
# with its parent's. Declarations after a nested rule close as another rule
# of the parent, so the order of the sheet is kept. A sheet that nests
# nothing is parsed as written.
#
# One fold over the characters; each character is first classified (fl_act,
# cheap), then one action runs (a match: building a rule's text in a
# Bool.pick arm would run at every character).

# A block being read: kind 0 a style rule (its resolved selector, its
# declarations so far reversed, the at-rules wrapping it and their closing
# braces), 1 a group at-rule (@media, @supports... holding rules), 2 a block
# copied as written (@keyframes, @font-face...) with its brace depth.
type Fr is Data:
  Fr{kind: U32, sel: String, decls: +List<Char>, wrap: String, unwrap: String, depth: U32}

type NS is Data:
  NS{stack: +List<Fr>, cur: +List<Char>, out: +List<Char>, q: U32, paren: U32, nested: Bool}

def top_kind(xs: List<&2, Fr>) -> U32:
  match xs:
    case Nil{}:
      9
    case Con{f, t}:
      match f:
        case Fr{kind, sel, decls, wrap, unwrap, depth}:
          kind

# What a character does: 0 text, 1 a quote, 2 '(', 3 ')', 4 ';' in a style
# rule, 5 ';' outside one, 6 '{' outside a style rule, 7 '{' inside one (a
# nested rule), 8 '}' closing a style rule, 9 '}' closing a group, 10 inside
# a block copied as written.
def fl_act(+k: U32, +q: U32, +paren: U32, +c: Char) -> U32:
  +code = Char.to_u32(c)
  +free = U32.is_zero(paren)
  Bool.pick(U32, U32.is_eq(k, 2), 10,
    Bool.pick(U32, Bool.not(U32.is_zero(q)) || U32.is_eq(code, 34) || U32.is_eq(code, 39), 1,
      Bool.pick(U32, U32.is_eq(code, 40), 2,
        Bool.pick(U32, U32.is_eq(code, 41), 3,
          Bool.pick(U32, free && U32.is_eq(code, 59), Bool.pick(U32, U32.is_eq(k, 0), 4, 5),
            Bool.pick(U32, free && U32.is_eq(code, 123), Bool.pick(U32, U32.is_eq(k, 0), 7, 6),
              Bool.pick(U32, free && U32.is_eq(code, 125), Bool.pick(U32, U32.is_eq(k, 0), 8, 9), 0)))))))

def rev_onto(+s: String, +out: List<&2, Char>) -> List<&2, Char>:
  List.append(&2, Char, List.reverse(&2, Char, String.to_list(s)), out)

# `&` in a nested selector, the parent in its place (one recursive call per
# character, given to a match: a pick would build both arms each step).
def amp_join(is_amp: Bool, +c: Char, +p: String, +rest: String) -> String:
  match is_amp:
    case True{}:
      p ++ rest
    case False{}:
      SCon{c, rest}

# (`esc`: the char before was a backslash, so this one is text: an escaped
# `\&` is part of a name, as in Tailwind's `.\[a\&\]\:hover\:bg-accent`,
# the class "[a&]:hover:bg-accent"; replaced, it made a selector no engine
# reads, and Element refused every element's background-color for it)
def amp_go(s: String, +esc: Bool, +p: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, t}:
      amp_join(Bool.not(esc) && Char.is_eq(c, '&'), c, p, amp_go(t, Bool.not(esc) && Char.is_eq(c, '\\'), p))

def amp(+s: String, +p: String) -> String:
  amp_go(s, False{}, p)

def has_amp_go(s: String, +esc: Bool) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{+c, t}:
      (Bool.not(esc) && Char.is_eq(c, '&')) || has_amp_go(t, Bool.not(esc) && Char.is_eq(c, '\\'))

def has_amp(+s: String) -> Bool:
  has_amp_go(s, False{})

def nest_one(+n: String, +p: String) -> String:
  Bool.pick(String, has_amp(n), amp(n, p), p ++ " " ++ n)

def nest_parents(ps: List<&2, String>, +n: String) -> List<&2, String>:
  match ps:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      nest_one(n, trim(x)) <> nest_parents(t, n)

def nest_all(ns: List<&2, String>, +ps: List<&2, String>) -> List<&2, String>:
  match ns:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      List.append(&2, String, nest_parents(ps, trim(x)), nest_all(t, ps))

def join_commas(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{+x, +t}:
      Bool.pick(String, List.is_empty(&2, String, t), x, x ++ ", " ++ join_commas(t))

def resolve(+nested: String, +parent: String) -> String:
  join_commas(nest_all(split(nested, ','), split(parent, ',')))

# A style rule's declarations so far, written out as a rule (nothing when
# there are none).
def flush(+f: Fr, +out: List<&2, Char>) -> List<&2, Char>:
  match f:
    case Fr{kind, +sel, +decls, +wrap, +unwrap, depth}:
      Bool.pick(List<&2, Char>, String.is_empty(trim(rev_str(decls))), out,
        rev_onto(wrap ++ sel ++ "{" ++ rev_str(decls) ++ "}" ++ unwrap, out))

def with_decls(+f: Fr, +ds: List<&2, Char>) -> Fr:
  match f:
    case Fr{kind, sel, decls, wrap, unwrap, depth}:
      Fr{kind, sel, ds, wrap, unwrap, depth}

def fr_decls(f: Fr) -> List<&2, Char>:
  match f:
    case Fr{kind, sel, decls, wrap, unwrap, depth}:
      decls

def is_group(+pre: String) -> Bool:
  +l = String.to_lower(pre)
  String.starts_with(l, "@media") || String.starts_with(l, "@supports") || String.starts_with(l, "@layer") ||
    String.starts_with(l, "@container") || String.starts_with(l, "@scope") || String.starts_with(l, "@document")

# '{' outside a style rule: a group at-rule, a block copied as written, or a
# style rule (its own selector: at this level nothing encloses it).
# `@layer name {` opens like a style rule whose selector is the layer's
# marker (U+0003 name U+0003): its rules come out as "<marker> sel" and a
# nested @media wraps them, as nesting does; css.bend reads the marker.
def is_layer_block(+pre: String) -> Bool:
  +l = String.to_lower(pre)
  String.starts_with(l, "@layer") && Bool.not(String.contains(pre, ","))

def layer_mark(+pre: String) -> String:
  "\u{3}" ++ trim(String.drop(pre, 6n)) ++ "\u{3}"

def open_top(+pre: String, +stack: List<&2, Fr>, +out: List<&2, Char>, +q: U32, +nested: Bool) -> NS:
  Bool.pick(NS, is_layer_block(pre), NS{Fr{0, layer_mark(pre), Nil{}, "", "", 0} <> stack, Nil{}, out, 0, 0, True{}},
    Bool.pick(NS, String.starts_with(pre, "@"),
      NS{Fr{Bool.pick(U32, is_group(pre), 1, 2), "", Nil{}, "", "", 1} <> stack, Nil{}, rev_onto(pre ++ "{", out), 0, 0, nested},
      NS{Fr{0, pre, Nil{}, "", "", 0} <> stack, Nil{}, out, 0, 0, nested}))

# '{' inside a style rule: what it held so far is written, then the nested
# rule (a selector resolved against the parent's, or an at-rule wrapping the
# parent's selector) is read.
def open_nested(stack: List<&2, Fr>, +pre: String, +out: List<&2, Char>) -> NS:
  match stack:
    case Nil{}:
      NS{Nil{}, Nil{}, out, 0, 0, True{}}
    case Con{f, t}:
      match f:
        case Fr{+kind, +sel, +decls, +wrap, +unwrap, +depth}:
          +out2 = flush(Fr{kind, sel, decls, wrap, unwrap, depth}, out)
          +inner = Bool.pick(Fr, String.starts_with(pre, "@"),
            Fr{0, sel, Nil{}, wrap ++ pre ++ "{", unwrap ++ "}", 0},
            Fr{0, resolve(pre, sel), Nil{}, wrap, unwrap, 0})
          NS{inner <> (Fr{kind, sel, Nil{}, wrap, unwrap, depth} <> t), Nil{}, out2, 0, 0, True{}}

# '}' closing a style rule: its declarations (and an unterminated last one).
def close_style(stack: List<&2, Fr>, +cur: List<&2, Char>, +out: List<&2, Char>, +nested: Bool) -> NS:
  match stack:
    case Nil{}:
      NS{Nil{}, Nil{}, out, 0, 0, nested}
    case Con{+f, t}:
      NS{t, Nil{}, flush(with_decls(f, List.append(&2, Char, cur, fr_decls(f))), out), 0, 0, nested}

def pop_group(stack: List<&2, Fr>) -> List<&2, Fr>:
  match stack:
    case Nil{}:
      Nil{}
    case Con{f, t}:
      t

# A character inside a block copied as written: its braces counted.
def raw_char(stack: List<&2, Fr>, +c: Char, +cur: List<&2, Char>, +out: List<&2, Char>, +nested: Bool) -> NS:
  match stack:
    case Nil{}:
      NS{Nil{}, cur, c <> out, 0, 0, nested}
    case Con{f, +t}:
      match f:
        case Fr{+kind, +sel, +decls, +wrap, +unwrap, +depth}:
          +d = Bool.pick(U32, Char.is_eq(c, '{'), U32.add(depth, 1), Bool.pick(U32, Char.is_eq(c, '}'), U32.sub(depth, 1), depth))
          Bool.pick(NS, U32.is_zero(d), NS{t, Nil{}, c <> out, 0, 0, nested},
            NS{Fr{kind, sel, decls, wrap, unwrap, d} <> t, Nil{}, c <> out, 0, 0, nested})

def push_decl(stack: List<&2, Fr>, +cur: List<&2, Char>) -> List<&2, Fr>:
  match stack:
    case Nil{}:
      Nil{}
    case Con{+f, t}:
      with_decls(f, ';' <> List.append(&2, Char, cur, fr_decls(f))) <> t

def fl_do(+st: NS, +a: U32, +c: Char) -> NS:
  match st:
    case NS{+stack, +cur, +out, +q, +paren, +nested}:
      match a:
        case 0:
          NS{stack, c <> cur, out, q, paren, nested}
        case 1:
          +code = Char.to_u32(c)
          NS{stack, c <> cur, out, Bool.pick(U32, U32.is_zero(q), code, Bool.pick(U32, U32.is_eq(code, q), 0, q)), paren, nested}
        case 2:
          NS{stack, c <> cur, out, q, U32.add(paren, 1), nested}
        case 3:
          NS{stack, c <> cur, out, q, Bool.pick(U32, U32.is_zero(paren), 0, U32.sub(paren, 1)), nested}
        case 4:
          NS{push_decl(stack, cur), Nil{}, out, q, paren, nested}
        case 5:
          NS{stack, Nil{}, ';' <> List.append(&2, Char, cur, out), q, paren, nested}
        case 6:
          open_top(trim(rev_str(cur)), stack, out, q, nested)
        case 7:
          open_nested(stack, trim(rev_str(cur)), out)
        case 8:
          close_style(stack, cur, out, nested)
        case 9:
          NS{pop_group(stack), Nil{}, '}' <> List.append(&2, Char, cur, out), q, paren, nested}
        case _:
          raw_char(stack, c, cur, out, nested)

def fl_step(st: NS, +c: Char) -> NS:
  match st:
    case NS{+stack, +cur, +out, +q, +paren, +nested}:
      fl_do(NS{stack, cur, out, q, paren, nested}, fl_act(top_kind(stack), q, paren, c), c)

def fl_go(s: String, +st: NS) -> NS:
  match s:
    case SNil{}:
      st
    case SCon{+c, t}:
      fl_go(t, fl_step(st, c))

def fl_result(st: NS, +orig: String) -> String:
  match st:
    case NS{stack, cur, out, q, paren, nested}:
      Bool.pick(String, nested, rev_str(out), orig)

# The sheet with its nested rules flattened, or as written when none nest.
def flatten(+s: String) -> String:
  fl_result(fl_go(s, NS{Nil{}, Nil{}, Nil{}, 0, 0, False{}}), s)

def go(s: String, +st: St) -> St:
  match s:
    case SNil{}:
      st
    case SCon{+c, t}:
      go(t, step(st, c))

def rules_of(st: St) -> List<&2, Rule>:
  match st:
    case St{mode, sel, body, rules}:
      List.reverse(&2, Rule, rules)

# The style rules of a sheet, in order.
def parse(s: String) -> List<&2, Rule>:
  rules_of(go(flatten(strip_comments(s)), St{MSel{}, Nil{}, Nil{}, Nil{}}))
