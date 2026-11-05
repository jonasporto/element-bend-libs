import Base

# K3.1 URLs: RFC 3986. Split a reference into its five components (section
# 3 / appendix B), resolve it against a base (section 5.2.2), and remove dot
# segments (5.2.4). LAWS.bend holds the normative examples of 5.4.1 and 5.4.2.
#
# A component that is absent is not the same as one that is empty: "http://a"
# has no query, "http://a?" has an empty one. `Maybe` keeps that distinction,
# as the RFC requires.

type Url is Data:
  Url{scheme: Maybe<&2, String>, auth: Maybe<&2, String>, path: String,
      query: Maybe<&2, String>, frag: Maybe<&2, String>}

# ---- small string tools ------------------------------------------------------

def rev(s: String) -> String:
  String.from_list(List.reverse(&2, Char, String.to_list(s)))

# Split at the first char in `stops`: (before, Some(rest from that char)) or
# (all, None).
type Cut is Data:
  Cut{before: String, rest: Maybe<&2, String>}

def is_in(+c: Char, stops: String) -> Bool:
  match stops:
    case SNil{}:
      False{}
    case SCon{h, t}:
      Char.is_eq(c, h) || is_in(c, t)

def none_yet(m: Maybe<&2, String>) -> Bool:
  match m:
    case None{}:
      True{}
    case Some{value}:
      False{}

# One pass over the whole string; `found` latches at the first stop char.
def cut_go(s: String, +stops: String, +acc: List<&2, Char>, +found: Maybe<&2, String>) -> Cut:
  match s:
    case SNil{}:
      Cut{String.from_list(List.reverse(&2, Char, acc)), found}
    case SCon{+h, +t}:
      +open = none_yet(found)
      +stop = open && is_in(h, stops)
      cut_go(
        t, stops,
        Bool.pick(List<&2, Char>, open && Bool.not(stop), h <> acc, acc),
        Bool.pick(Maybe<&2, String>, stop, Some{SCon{h, t}}, found)
      )

def cut(s: String, +stops: String) -> Cut:
  cut_go(s, stops, Nil{}, None{})

def cut_before(c: Cut) -> String:
  match c:
    case Cut{before, rest}:
      before

def cut_rest(c: Cut) -> Maybe<&2, String>:
  match c:
    case Cut{before, rest}:
      rest

def drop1(s: String) -> String:
  String.drop(s, 1n)

def drop_maybe1(m: Maybe<&2, String>) -> Maybe<&2, String>:
  match m:
    case None{}:
      None{}
    case Some{value}:
      Some{drop1(value)}

def or_empty(m: Maybe<&2, String>) -> String:
  match m:
    case None{}:
      SNil{}
    case Some{value}:
      value

def is_some(m: Maybe<&2, String>) -> Bool:
  match m:
    case None{}:
      False{}
    case Some{value}:
      True{}

# ---- parse (appendix B) ------------------------------------------------------

def is_scheme_char(+c: Char) -> Bool:
  Char.is_alpha(c) || Char.is_digit(c) || Char.is_eq(c, '+') || Char.is_eq(c, '-') || Char.is_eq(c, '.')

def all_scheme(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+h, t}:
      is_scheme_char(h) && all_scheme(t)

def starts_alpha(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{h, t}:
      Char.is_alpha(h)

# path ? query # fragment
def split_rest(scheme: Maybe<&2, String>, auth: Maybe<&2, String>, +s: String) -> Url:
  +pc = cut(s, "?#")
  +tail = or_empty(cut_rest(pc))
  +has_q = String.starts_with(tail, "?")
  +qc = cut(drop1(tail), "#")
  Url{
    scheme, auth, cut_before(pc),
    Bool.pick(Maybe<&2, String>, has_q, Some{cut_before(qc)}, None{}),
    Bool.pick(Maybe<&2, String>, has_q, drop_maybe1(cut_rest(qc)), drop_maybe1(cut_rest(pc)))
  }

def after_auth_pick(has_auth: Bool, +s: String, scheme: Maybe<&2, String>) -> Url:
  match has_auth:
    case True{}:
      split_rest(scheme, Some{cut_before(cut(String.drop(s, 2n), "/?#"))}, or_empty(cut_rest(cut(String.drop(s, 2n), "/?#"))))
    case False{}:
      split_rest(scheme, None{}, s)

def after_scheme(scheme: Maybe<&2, String>, +s: String) -> Url:
  after_auth_pick(String.starts_with(s, "//"), s, scheme)

# A scheme is the text before the first ':' if that text comes before any
# '/', '?' or '#' and is a valid scheme name.
def scheme_pick(ok: Bool, +c: Cut, s: String) -> Url:
  match ok:
    case True{}:
      after_scheme(Some{String.to_lower(cut_before(c))}, drop1(or_empty(cut_rest(c))))
    case False{}:
      after_scheme(None{}, s)

def is_colon_cut(c: Cut) -> Bool:
  match c:
    case Cut{before, rest}:
      match rest:
        case None{}:
          False{}
        case Some{value}:
          String.starts_with(value, ":")

def parse(+s: String) -> Url:
  +c = cut(s, ":/?#")
  scheme_pick(is_colon_cut(c) && starts_alpha(cut_before(c)) && all_scheme(cut_before(c)), c, s)

# ---- recompose (5.3) ---------------------------------------------------------

def opt(prefix: String, m: Maybe<&2, String>, suffix: String) -> String:
  match m:
    case None{}:
      SNil{}
    case Some{value}:
      prefix ++ value ++ suffix

def show(u: Url) -> String:
  match u:
    case Url{scheme, auth, path, query, frag}:
      opt("", scheme, ":") ++ opt("//", auth, "") ++ path ++ opt("?", query, "") ++ opt("#", frag, "")

# ---- remove_dot_segments (5.2.4) ---------------------------------------------
#
# Works on the path as a list of segments. The output is a stack (newest
# first); ".." pops it. A leading "/" and a trailing "/" (after ".", "..",
# or an empty last segment) are kept as the RFC's string algorithm keeps them.

def split_segs(s: String, +acc: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, String.from_list(List.reverse(&2, Char, acc)) <> out)
    case SCon{+h, t}:
      +slash = Char.is_eq(h, '/')
      split_segs(
        t,
        Bool.pick(List<&2, Char>, slash, Nil{}, h <> acc),
        Bool.pick(List<&2, String>, slash, String.from_list(List.reverse(&2, Char, acc)) <> out, out)
      )

def pop(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# Walk the input segments. `last_dir` records that the final input segment
# was "." or "..", which leaves a trailing slash.
def dots(segs: List<&2, String>, +out: List<&2, String>, last_dir: Bool) -> List<&2, String>:
  match segs:
    case Nil{}:
      List.reverse(&2, String, Bool.pick(List<&2, String>, last_dir, SNil{} <> out, out))
    case Con{+h, t}:
      dots(
        t,
        Bool.pick(List<&2, String>, String.eq(h, "."), out,
          Bool.pick(List<&2, String>, String.eq(h, ".."), pop(out), h <> out)),
        String.eq(h, ".") || String.eq(h, "..")
      )

def join_segs(xs: List<&2, String>, first: Bool) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{+h, t}:
      Bool.pick(String, first, h, "/" ++ h) ++ join_segs(t, False{})

def remove_dots(+p: String) -> String:
  Bool.pick(String, String.starts_with(p, "/"), "/", SNil{}) ++
    join_segs(dots(split_segs(Bool.pick(String, String.starts_with(p, "/"), drop1(p), p), Nil{}, Nil{}), Nil{}, False{}), True{})

# ---- resolve (5.2.2, strict) ---------------------------------------------------

# 5.2.3 merge: base with authority and empty path -> "/" ++ ref; else the base
# path up to its last "/" ++ ref.
def merge(has_auth: Bool, +base_path: String, +ref_path: String) -> String:
  Bool.pick(String, has_auth && String.eq(base_path, ""), "/" ++ ref_path,
    rev(or_empty(cut_rest(cut(rev(base_path), "/")))) ++ ref_path)

def resolve_urls(+b: Url, +r: Url) -> Url:
  match b r:
    case Url{bs, +ba, +bp, +bq, bf} Url{+rs, +ra, +rp, +rq, rf}:
      Bool.pick(Url, is_some(rs), Url{rs, ra, remove_dots(rp), rq, rf},
        Bool.pick(Url, is_some(ra), Url{bs, ra, remove_dots(rp), rq, rf},
          Bool.pick(Url, String.eq(rp, ""), Url{bs, ba, bp, Bool.pick(Maybe<&2, String>, is_some(rq), rq, bq), rf},
            Bool.pick(Url, String.starts_with(rp, "/"), Url{bs, ba, remove_dots(rp), rq, rf},
              Url{bs, ba, remove_dots(merge(is_some(ba), bp, rp)), rq, rf}))))

def resolve(base: String, ref: String) -> String:
  show(resolve_urls(parse(base), parse(ref)))

# ---- accessors for the fetcher -------------------------------------------------

def url_host(u: Url) -> String:
  match u:
    case Url{scheme, auth, path, query, frag}:
      cut_before(cut(or_empty(auth), ":"))

def url_scheme(u: Url) -> String:
  match u:
    case Url{scheme, auth, path, query, frag}:
      or_empty(scheme)

def port_default(m: Maybe<&2, U32>, +sch: String) -> U32:
  match m:
    case None{}:
      Bool.pick(U32, String.eq(sch, "https"), 443, 80)
    case Some{value}:
      value

def port_read(m: Maybe<&2, String>, +sch: String) -> U32:
  match m:
    case None{}:
      Bool.pick(U32, String.eq(sch, "https"), 443, 80)
    case Some{value}:
      port_default(U32.read(drop1(value)), sch)

def port_of(+auth: String, +sch: String) -> U32:
  port_read(cut_rest(cut(auth, ":")), sch)

def url_port(u: Url) -> U32:
  match u:
    case Url{scheme, auth, path, query, frag}:
      port_of(or_empty(auth), or_empty(scheme))

# The request target: path (or "/") plus query. The fragment never leaves.
def url_target(u: Url) -> String:
  match u:
    case Url{scheme, auth, +path, query, frag}:
      Bool.pick(String, String.eq(path, ""), "/", path) ++ opt("?", query, "")

def rfc_base() -> String:
  "http://a/b/c/d;p?q"
