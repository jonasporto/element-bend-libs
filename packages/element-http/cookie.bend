import Base
import element-asn1@0.1.0.0/der.bend as Der

# HTTP cookies (RFC 6265): parse Set-Cookie against the request that got it,
# keep a jar, and pick the Cookie header for a request. The jar reads and
# writes the Netscape cookies.txt format (curl, wget and browser exporters
# use it): one line per cookie, tab-separated
#   domain  include-subdomains  path  secure  expiry  name  value
# with "#HttpOnly_" before the domain of an HttpOnly cookie and expiry 0 for
# a session cookie.
#
# Not done: the public suffix list (a Domain of "com" is refused only when
# it does not domain-match the host), SameSite enforcement (no cross-site
# requests happen in Element yet; the attribute is kept).

type Cookie is Data:
  Cookie{
    name: String, value: String, domain: String, host_only: Bool, path: String,
    expires: U32, secure: Bool, http_only: Bool, same_site: String
  }

# ---- strings ------------------------------------------------------------------

def rev_str(cs: List<&2, Char>) -> String:
  String.from_list(List.reverse(&2, Char, cs))

def ltrim(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, +t}:
      Bool.pick(String, Char.is_space(c), ltrim(t), SCon{c, t})

def trim(+s: String) -> String:
  String.reverse(ltrim(String.reverse(ltrim(s))))

# The pieces so far, with the current one closed at a cut (a pick reversed
# it at every char: quadratic in the pieces' length).
def cut_out(cut: Bool, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match cut:
    case True{}:
      rev_str(cur) <> out
    case False{}:
      out

# Split at every `sep`.
def split_go(s: String, +sep: Char, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, rev_str(cur) <> out)
    case SCon{+c, t}:
      +cut = Char.is_eq(c, sep)
      split_go(t, sep, Bool.pick(List<&2, Char>, cut, Nil{}, c <> cur), cut_out(cut, cur, out))

def split(+s: String, +sep: Char) -> List<&2, String>:
  split_go(s, sep, Nil{}, Nil{})

def before(s: String, +c: Char) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      Bool.pick(String, Char.is_eq(h, c), SNil{}, SCon{h, before(t, c)})

def after(s: String, +c: Char) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, +t}:
      Bool.pick(String, Char.is_eq(h, c), t, after(t, c))

def has(s: String, +c: Char) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{h, t}:
      Char.is_eq(h, c) || has(t, c)

def digits(s: String, +acc: Nat) -> Nat:
  match s:
    case SNil{}:
      acc
    case SCon{+c, t}:
      digits(t, Nat.add(Nat.mul(acc, 10n), U32.to_nat((Char.to_u32(c) - 48 : U32))))

# Decimal digits as U32, saturating (seconds stay U32 for the law checker).
def digits32(s: String, +acc: U32) -> U32:
  match s:
    case SNil{}:
      acc
    case SCon{+c, t}:
      digits32(t, Bool.pick(U32, (acc > 429496728 : U32), 4294967295, ((acc * 10 : U32) + (Char.to_u32(c) - 48 : U32) : U32)))

def all_digits(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c, t}:
      Char.is_digit(c) && all_digits(t)

def lower(+s: String) -> String:
  String.to_lower(s)

# ---- dates (5.1.1) ---------------------------------------------------------------

# Tokens of a cookie-date: runs of letters, digits and ':'.
def date_tokens(s: String, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, Bool.pick(List<&2, String>, List.is_empty(&2, Char, cur), out, rev_str(cur) <> out))
    case SCon{+c, t}:
      +keep = Char.is_alpha(c) || Char.is_digit(c) || Char.is_eq(c, ':')
      +flush = Bool.not(keep) && Bool.not(List.is_empty(&2, Char, cur))
      date_tokens(t, Bool.pick(List<&2, Char>, keep, c <> cur, Nil{}), cut_out(flush, cur, out))

def month_of(+t: String) -> Nat:
  +m = String.take(lower(t), 3n)
  Bool.pick(Nat, String.eq(m, "jan"), 1n, Bool.pick(Nat, String.eq(m, "feb"), 2n, Bool.pick(Nat, String.eq(m, "mar"), 3n,
  Bool.pick(Nat, String.eq(m, "apr"), 4n, Bool.pick(Nat, String.eq(m, "may"), 5n, Bool.pick(Nat, String.eq(m, "jun"), 6n,
  Bool.pick(Nat, String.eq(m, "jul"), 7n, Bool.pick(Nat, String.eq(m, "aug"), 8n, Bool.pick(Nat, String.eq(m, "sep"), 9n,
  Bool.pick(Nat, String.eq(m, "oct"), 10n, Bool.pick(Nat, String.eq(m, "nov"), 11n, Bool.pick(Nat, String.eq(m, "dec"), 12n, 0n))))))))))))

# What the date tokens say so far: time (seconds into the day), day, month,
# year, each with whether it was found.
type D is Data:
  D{tf: Bool, time: Nat, df: Bool, day: Nat, mf: Bool, month: Nat, yf: Bool, year: Nat}

def nth_s(xs: List<&2, String>, n: Nat) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      match n:
        case 0n:
          h
        case 1n+r:
          nth_s(t, r)

def hms(+t: String) -> Nat:
  +ps = split(t, ':')
  Nat.add(Nat.mul(digits(nth_s(ps, 0n), 0n), 3600n), Nat.add(Nat.mul(digits(nth_s(ps, 1n), 0n), 60n), digits(nth_s(ps, 2n), 0n)))

# 1*2DIGIT, the shape of each part of a time and of a day-of-month
def two_digits(+t: String) -> Bool:
  +n = String.length(t)
  all_digits(t) && Nat.is_ge(n, 1n) && Nat.is_le(n, 2n)

# time = hms-time ( non-digit *OCTET ), hms-time = 1*2DIGIT ":" 1*2DIGIT ":"
# 1*2DIGIT (RFC 6265 5.1.1). A token is a time only in that shape, so no
# other token ever reaches the arithmetic.
def is_hms(+t: String) -> Bool:
  +ps = split(t, ':')
  U32.is_eq(U32.from_nat(List.length(&2, String, ps)), 3) && two_digits(nth_s(ps, 0n)) && two_digits(nth_s(ps, 1n)) && two_digits(nth_s(ps, 2n))

# A field is computed only when its token is that field. These were
# Bool.picks, which build both arms: hms and digits ran on every token, and
# hms("Coordinated") (JavaScript's Date.toString ends in "(Coordinated
# Universal Time)", which cloudflare.com sends as Expires) is about 2.7e15,
# past Bend's largest Nat (2^48 - 1): the whole process stopped.
def time_or(take: Bool, +t: String, +old: Nat) -> Nat:
  match take:
    case True{}:
      hms(t)
    case False{}:
      old

def digits_or(take: Bool, +t: String, +old: Nat) -> Nat:
  match take:
    case True{}:
      digits(t, 0n)
    case False{}:
      old

def month_or(take: Bool, +t: String, +old: Nat) -> Nat:
  match take:
    case True{}:
      month_of(t)
    case False{}:
      old

def date_step(d: D, +t: String) -> D:
  match d:
    case D{+tf, +time, +df, +day, +mf, +month, +yf, +year}:
      +is_time = Bool.not(tf) && is_hms(t)
      +n = String.length(t)
      +num = all_digits(t)
      +is_day = Bool.not(is_time) && Bool.not(df) && num && Nat.is_le(n, 2n)
      +is_month = Bool.not(is_time) && Bool.not(is_day) && Bool.not(mf) && Bool.not(Nat.is_eq(month_of(t), 0n))
      +is_year = Bool.not(is_time) && Bool.not(is_day) && Bool.not(is_month) && Bool.not(yf) && num && Nat.is_ge(n, 2n) && Nat.is_le(n, 4n)
      D{tf || is_time, time_or(is_time, t, time),
        df || is_day, digits_or(is_day, t, day),
        mf || is_month, month_or(is_month, t, month),
        yf || is_year, digits_or(is_year, t, year)}

def date_fold(ts: List<&2, String>, +d: D) -> D:
  match ts:
    case Nil{}:
      d
    case Con{t, rest}:
      date_fold(rest, date_step(d, t))

def full_year(+y: Nat) -> Nat:
  Bool.pick(Nat, Nat.is_lt(y, 70n), Nat.add(y, 2000n), Bool.pick(Nat, Nat.is_lt(y, 100n), Nat.add(y, 1900n), y))

# Seconds as U32 (until 2106): a Nat this large is costly to the law checker.
def date_secs(d: D) -> U32:
  match d:
    case D{tf, +time, df, +day, mf, +month, yf, +year}:
      Bool.pick(U32, tf && df && mf && yf && Nat.is_ge(day, 1n) && Nat.is_le(day, 31n) && Nat.is_ge(full_year(year), 1970n) && Nat.is_le(full_year(year), 2105n),
        ((U32.from_nat(Der.days_from_civil(full_year(year), month, day)) * 86400 : U32) + U32.from_nat(time) : U32), 0)

# A cookie-date as seconds since 1970, or 0 when it does not parse (or falls
# outside 1970-2105).
def parse_date(+s: String) -> U32:
  date_secs(date_fold(date_tokens(s, Nil{}, Nil{}), D{False{}, 0n, False{}, 0n, False{}, 0n, False{}, 0n}))

# ---- matching (5.1.3, 5.1.4) -------------------------------------------------------

# host is domain, or ends with "." + domain.
def domain_match(+host: String, +domain: String) -> Bool:
  +h = lower(host)
  +d = lower(domain)
  String.eq(h, d) || (Bool.not(String.is_empty(d)) && String.ends_with(h, "." ++ d))

# The cookie path is the request path, or a prefix of it ending at a '/'.
def path_match(+req: String, +cpath: String) -> Bool:
  String.eq(req, cpath) ||
    (String.starts_with(req, cpath) && (String.ends_with(cpath, "/") || String.starts_with(String.drop(req, String.length(cpath)), "/")))

# The directory of the request path ("/a/b/c" -> "/a/b", "/a" -> "/").
def default_path(+req: String) -> String:
  +rev = String.reverse(req)
  +dir = String.reverse(String.drop(rev, Nat.add(String.length(before(rev, '/')), 1n)))
  Bool.pick(String, Bool.not(String.starts_with(req, "/")) || String.is_empty(dir), "/", dir)

# ---- Set-Cookie (5.2) ---------------------------------------------------------------

type A is Data:
  A{ef: Bool, exp: U32, mf: Bool, neg: Bool, age: U32, domain: String, path: String, secure: Bool, http_only: Bool, same_site: String}

def attr_step(a: A, +part: String) -> A:
  match a:
    case A{+ef, +exp, +mf, +neg, +age, +domain, +path, +secure, +http_only, +same_site}:
      +k = lower(trim(before(part, '=')))
      +v = trim(after(part, '='))
      +is_age = String.eq(k, "max-age") && Bool.not(String.is_empty(v)) &&
        all_digits(Bool.pick(String, String.starts_with(v, "-"), String.drop(v, 1n), v))
      A{ef || String.eq(k, "expires"), Bool.pick(U32, String.eq(k, "expires"), parse_date(v), exp),
        mf || is_age, Bool.pick(Bool, is_age, String.starts_with(v, "-"), neg),
        Bool.pick(U32, is_age, U32.min(digits32(Bool.pick(String, String.starts_with(v, "-"), String.drop(v, 1n), v), 0), 2147483647), age),
        Bool.pick(String, String.eq(k, "domain"), lower(Bool.pick(String, String.starts_with(v, "."), String.drop(v, 1n), v)), domain),
        Bool.pick(String, String.eq(k, "path"), v, path),
        secure || String.eq(k, "secure"), http_only || String.eq(k, "httponly"),
        Bool.pick(String, String.eq(k, "samesite"), v, same_site)}

def attrs_fold(ps: List<&2, String>, +a: A) -> A:
  match ps:
    case Nil{}:
      a
    case Con{p, t}:
      attrs_fold(t, attr_step(a, p))

def tail_s(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# Expiry: Max-Age wins over Expires; Max-Age <= 0 means already expired (1,
# the earliest time); neither means a session cookie (0).
def expiry(+a: A, +now: U32) -> U32:
  match a:
    case A{ef, +exp, mf, +neg, +age, domain, path, secure, http_only, same_site}:
      Bool.pick(U32, mf, Bool.pick(U32, neg || U32.is_zero(age), 1, U32.min((now + age : U32), 4294967294)),
        Bool.pick(U32, ef && (exp > 0 : U32), exp, 0))

def build(ok: Bool, +name: String, +value: String, +a: A, +host: String, +req_path: String, +now: U32) -> Maybe<&2, Cookie>:
  match ok:
    case False{}:
      None{}
    case True{}:
      match a:
        case A{ef, exp, mf, neg, age, +domain, +path, +secure, +http_only, +same_site}:
          +ho = String.is_empty(domain)
          Some{Cookie{name, value, Bool.pick(String, ho, lower(host), domain), ho,
            Bool.pick(String, String.starts_with(path, "/"), path, default_path(req_path)),
            expiry(A{ef, exp, mf, neg, age, domain, path, secure, http_only, same_site}, now),
            secure, http_only, same_site}}

def a_domain(a: A) -> String:
  match a:
    case A{ef, exp, mf, neg, age, domain, path, secure, http_only, same_site}:
      domain

# A Set-Cookie value received from `host` for `req_path` at `now`; None when
# it has no name=value pair or its Domain does not cover the host.
def parse(+header: String, +host: String, +req_path: String, +now: U32) -> Maybe<&2, Cookie>:
  +parts = split(header, ';')
  +first = nth_s(parts, 0n)
  +name = trim(before(first, '='))
  +a = attrs_fold(tail_s(parts), A{False{}, 0, False{}, False{}, 0, "", "", False{}, False{}, ""})
  +dom = a_domain(a)
  build(has(first, '=') && Bool.not(String.is_empty(name)) && (String.is_empty(dom) || domain_match(host, dom)),
    name, trim(after(first, '=')), a, host, req_path, now)

# ---- the jar (5.3, 5.4) --------------------------------------------------------------

def c_name(c: Cookie) -> String:
  match c:
    case Cookie{name, value, domain, host_only, path, expires, secure, http_only, same_site}:
      name

def c_domain(c: Cookie) -> String:
  match c:
    case Cookie{name, value, domain, host_only, path, expires, secure, http_only, same_site}:
      domain

def c_path(c: Cookie) -> String:
  match c:
    case Cookie{name, value, domain, host_only, path, expires, secure, http_only, same_site}:
      path

def c_expires(c: Cookie) -> U32:
  match c:
    case Cookie{name, value, domain, host_only, path, expires, secure, http_only, same_site}:
      expires

def same_key(+a: Cookie, +b: Cookie) -> Bool:
  String.eq(c_name(a), c_name(b)) && String.eq(c_domain(a), c_domain(b)) && String.eq(c_path(a), c_path(b))

def expired(+c: Cookie, +now: U32) -> Bool:
  Bool.not(U32.is_zero(c_expires(c))) && (c_expires(c) <= now : U32)

def without(xs: List<&2, Cookie>, +c: Cookie) -> List<&2, Cookie>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      +rest = without(t, c)
      Bool.pick(List<&2, Cookie>, same_key(x, c), rest, x <> rest)

# Store a cookie: it replaces the one with the same name, domain and path;
# an expired one only removes.
def store(+jar: List<&2, Cookie>, +c: Cookie, +now: U32) -> List<&2, Cookie>:
  +rest = without(jar, c)
  Bool.pick(List<&2, Cookie>, expired(c, now), rest, List.append(&2, Cookie, rest, [c]))

def store_m(m: Maybe<&2, Cookie>, +jar: List<&2, Cookie>, +now: U32) -> List<&2, Cookie>:
  match m:
    case None{}:
      jar
    case Some{value}:
      store(jar, value, now)

# Every Set-Cookie header of a response.
def store_all(hs: List<&2, String>, +jar: List<&2, Cookie>, +host: String, +req_path: String, +now: U32) -> List<&2, Cookie>:
  match hs:
    case Nil{}:
      jar
    case Con{h, t}:
      store_all(t, store_m(parse(h, host, req_path, now), jar, now), host, req_path, now)

def sends(c: Cookie, +host: String, +req_path: String, +https: Bool, +now: U32) -> Bool:
  match c:
    case Cookie{name, value, +domain, +host_only, +path, +expires, +secure, http_only, same_site}:
      Bool.pick(Bool, host_only, String.eq(lower(host), domain), domain_match(host, domain)) &&
        path_match(req_path, path) && (Bool.not(secure) || https) &&
        Bool.not(Bool.not(U32.is_zero(expires)) && (expires <= now : U32))

# Longer paths first; equal paths keep the jar's (creation) order.
def insert(+c: Cookie, xs: List<&2, Cookie>) -> List<&2, Cookie>:
  match xs:
    case Nil{}:
      [c]
    case Con{+x, +t}:
      Bool.pick(List<&2, Cookie>, Nat.is_gt(String.length(c_path(c)), String.length(c_path(x))), c <> Con{x, t}, x <> insert(c, t))

def chosen(xs: List<&2, Cookie>, +host: String, +req_path: String, +https: Bool, +now: U32, +acc: List<&2, Cookie>) -> List<&2, Cookie>:
  match xs:
    case Nil{}:
      acc
    case Con{+x, t}:
      chosen(t, host, req_path, https, now, Bool.pick(List<&2, Cookie>, sends(x, host, req_path, https, now), insert(x, acc), acc))

def pairs(xs: List<&2, Cookie>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{c, t}:
      match c:
        case Cookie{name, value, domain, host_only, path, expires, secure, http_only, same_site}:
          (name ++ "=" ++ value) <> pairs(t)

# The Cookie header value for a request ("" when no cookie applies).
def is_http_only(c: Cookie) -> Bool:
  match c:
    case Cookie{name, value, domain, host_only, path, expires, secure, http_only, same_site}:
      http_only

# A cookie a script stores (document.cookie = ...): not an HttpOnly one (a
# script cannot make one), and never over an HttpOnly cookie of the same
# name, domain and path (RFC 6265 5.3, steps 10 and 11).
def blocks(+c: Cookie, xs: List<&2, Cookie>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{+x, t}:
      (same_key(c, x) && is_http_only(x)) || blocks(c, t)

def script_store_m(m: Maybe<&2, Cookie>, +jar: List<&2, Cookie>, +now: U32) -> List<&2, Cookie>:
  match m:
    case None{}:
      jar
    case Some{+c}:
      Bool.pick(List<&2, Cookie>, is_http_only(c) || blocks(c, jar), jar, store(jar, c, now))

def script_store_all(hs: List<&2, String>, +jar: List<&2, Cookie>, +host: String, +req_path: String, +now: U32) -> List<&2, Cookie>:
  match hs:
    case Nil{}:
      jar
    case Con{+x, t}:
      script_store_all(t, script_store_m(parse(x, host, req_path, now), jar, now), host, req_path, now)

def header(+jar: List<&2, Cookie>, +host: String, +req_path: String, +https: Bool, +now: U32) -> String:
  String.join(pairs(chosen(jar, host, req_path, https, now, Nil{})), "; ")

# ---- cookies.txt ---------------------------------------------------------------------

def tf(+b: Bool) -> String:
  Bool.pick(String, b, "TRUE", "FALSE")

def line_of(c: Cookie) -> String:
  match c:
    case Cookie{name, value, domain, +host_only, path, expires, secure, +http_only, same_site}:
      Bool.pick(String, http_only, "#HttpOnly_", "") ++ Bool.pick(String, host_only, "", ".") ++ domain ++ "\t" ++
        tf(Bool.not(host_only)) ++ "\t" ++ path ++ "\t" ++ tf(secure) ++ "\t" ++ U32.show(expires) ++ "\t" ++ name ++ "\t" ++ value

def lines(xs: List<&2, Cookie>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{c, t}:
      line_of(c) ++ "\n" ++ lines(t)

def to_text(+jar: List<&2, Cookie>) -> String:
  "# Netscape HTTP Cookie File\n" ++ lines(jar)

def cookie_of_line(+l: String) -> Maybe<&2, Cookie>:
  +ho = String.starts_with(l, "#HttpOnly_")
  +fs = split(Bool.pick(String, ho, String.drop(l, 10n), l), '\t')
  +d = nth_s(fs, 0n)
  +sub = String.eq(nth_s(fs, 1n), "TRUE")
  Bool.pick(Maybe<&2, Cookie>, Nat.is_ge(List.length(&2, String, fs), 7n) && (ho || Bool.not(String.starts_with(l, "#"))),
    Some{Cookie{nth_s(fs, 5n), nth_s(fs, 6n), lower(Bool.pick(String, String.starts_with(d, "."), String.drop(d, 1n), d)), Bool.not(sub),
      nth_s(fs, 2n), digits32(nth_s(fs, 4n), 0), String.eq(nth_s(fs, 3n), "TRUE"), ho, ""}},
    None{})

def add_m(m: Maybe<&2, Cookie>, +rest: List<&2, Cookie>) -> List<&2, Cookie>:
  match m:
    case None{}:
      rest
    case Some{value}:
      value <> rest

def of_lines(ls: List<&2, String>) -> List<&2, Cookie>:
  match ls:
    case Nil{}:
      Nil{}
    case Con{l, t}:
      add_m(cookie_of_line(trim(l)), of_lines(t))

# A jar from cookies.txt text (comments, blank and malformed lines skipped).
def of_text(+text: String) -> List<&2, Cookie>:
  of_lines(split(text, '\n'))
