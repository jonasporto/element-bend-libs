import Base
import element-compress@0.1.0.1/gzip.bend as Gzip
import element-rfc3986@0.1.0.0/url.bend as Url
import element-text@0.1.0.0/utf8.bend as U

# K3.2 HTTP/1.1 client, the pure half: build a request, parse a response from
# raw bytes (status line, headers, Content-Length or chunked body), and decide
# what a response means for navigation (a page, a redirect, an error).
# RFC 9112. The IO half (connect, send, read until close) is fetch.bend.

type Hdr is Data:
  Hdr{name: String, value: String}

type Resp is Data:
  Resp{status: U32, headers: +List<Hdr>, body: +List<U32>}

def pick(c: Bool, a: U32, b: U32) -> U32:
  Bool.pick(U32, c, a, b)

# Any request Element sends: GET or POST, a Cookie header when one applies,
# and a body with its type (Content-Length counts UTF-8 bytes).
def default_ua() -> String:
  "Element/0.1 (Bend)"

def accept_after_nl(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{c, +t}:
      +nl = U32.is_eq(Char.to_u32(c), 10)
      (nl && String.starts_with(t, "accept:")) || accept_after_nl(t)

# Is one of these header lines ("Name: value\r\n" each) an Accept header?
# Names are case-insensitive (RFC 9110 5.1).
def has_accept(+extra: String) -> Bool:
  +low = String.to_lower(extra)
  String.starts_with(low, "accept:") || accept_after_nl(low)

def accept_unless(has: Bool) -> String:
  match has:
    case True{}:
      ""
    case False{}:
      "Accept: text/html\r\n"

# The Accept a request sends when `extra` names none: a navigation asks for
# a document. A subresource says what it wants in `extra` (a script */*, a
# stylesheet text/css, as Chrome does), and a server that negotiates on
# Accept answers what was asked for.
def accept_line(+extra: String) -> String:
  accept_unless(has_accept(extra))

# `ua` replaces the User-Agent when not empty; `extra` is header lines
# ("Name: value\r\n" each) sent as given (CDP's setExtraHTTPHeaders).
# `conn` is the Connection header: "close", or "keep-alive" for a request
# that goes out through tls/io.bend's pool.
def request_with(+conn: String, +host: String, +method: String, +target: String, +cookie: String, +ctype: String, +body: String, +ua: String, +extra: String) -> String:
  method ++ " " ++ target ++ " HTTP/1.1\r\nHost: " ++ host ++
  "\r\nUser-Agent: " ++ Bool.pick(String, String.is_empty(ua), default_ua(), ua) ++ "\r\n" ++ accept_line(extra) ++ "Accept-Encoding: gzip, deflate\r\nConnection: " ++ conn ++ "\r\n" ++ extra ++
  Bool.pick(String, String.is_empty(cookie), "", "Cookie: " ++ cookie ++ "\r\n") ++
  Bool.pick(String, String.eq(method, "GET"), "",
    "Content-Type: " ++ ctype ++ "\r\nContent-Length: " ++ Nat.show(List.length(&2, U32, U.bytes_of(body))) ++ "\r\n") ++
  "\r\n" ++ body

def request_full(+host: String, +method: String, +target: String, +cookie: String, +ctype: String, +body: String, +ua: String, +extra: String) -> String:
  request_with("close", host, method, target, cookie, ctype, body, ua, extra)

def request(host: String, target: String) -> String:
  request_full(host, "GET", target, "", "", "", "", "")

# ---- split head / body at the first CRLF CRLF --------------------------------

type Split is Data:
  Split{head: +List<U32>, body: +List<U32>, found: Bool}

# `w` holds the last three bytes seen (newest in the low byte) to spot CRLFCRLF.
# `found` is computed by the caller and matched, so the head is reversed once
# (a Bool.pick would build the found-branch, a reverse, at every byte).
def split_go(bs: List<&2, U32>, found: Bool, +w: U32, +head: List<&2, U32>) -> Split:
  match bs:
    case Nil{}:
      Split{List.reverse(&2, U32, head), Nil{}, found}
    case Con{+b, +t}:
      match found:
        case True{}:
          Split{List.reverse(&2, U32, head), b <> t, True{}}
        case False{}:
          +w2 = ((w * 256 : U32) + b : U32)
          split_go(t, U32.is_eq(w2, 218762506), w2, b <> head)

# ---- head lines --------------------------------------------------------------

def lines_go(s: String, +cur: List<&2, Char>, +out: List<&2, String>) -> List<&2, String>:
  match s:
    case SNil{}:
      List.reverse(&2, String, String.from_list(List.reverse(&2, Char, cur)) <> out)
    case SCon{+h, t}:
      +nl = Char.is_eq(h, '\n')
      lines_go(
        t,
        Bool.pick(List<&2, Char>, nl || Char.is_eq(h, '\r'), Bool.pick(List<&2, Char>, nl, Nil{}, cur), h <> cur),
        Bool.pick(List<&2, String>, nl, String.from_list(List.reverse(&2, Char, cur)) <> out, out)
      )

def trim_left(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, +t}:
      Bool.pick(String, Char.is_space(h), trim_left(t), SCon{h, t})

def rtrim(+s: String) -> String:
  Url.rev(trim_left(Url.rev(s)))

def header_of(+line: String) -> Hdr:
  Hdr{String.to_lower(Url.cut_before(Url.cut(line, ":"))), rtrim(trim_left(Url.drop1(Url.or_empty(Url.cut_rest(Url.cut(line, ":"))))))}

def keep_header(+h: String) -> List<&2, Hdr>:
  Bool.pick(List<&2, Hdr>, String.eq(h, ""), Nil{}, [header_of(h)])

# (Not Bool.pick over the recursive call: both arguments of a call are
# evaluated, which made this exponential in the number of headers.)
def headers_of(xs: List<&2, String>) -> List<&2, Hdr>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+h, t}:
      List.append(&2, Hdr, keep_header(h), headers_of(t))

def header(hs: List<&2, Hdr>, +name: String) -> String:
  match hs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      match h:
        case Hdr{+n, v}:
          Bool.pick(String, String.eq(n, name), v, header(t, name))

# "HTTP/1.1 301 Moved" -> 301
# Every value of a header that may repeat (Set-Cookie).
def all(hs: List<&2, Hdr>, +name: String) -> List<&2, String>:
  match hs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      match h:
        case Hdr{+n, +v}:
          +rest = all(t, name)
          Bool.pick(List<&2, String>, String.eq(n, name), v <> rest, rest)

def resp_headers(r: Result<&2, &2, String, Resp>) -> List<&2, Hdr>:
  match r:
    case Fail{error}:
      Nil{}
    case Done{value}:
      match value:
        case Resp{status, headers, body}:
          headers

def status_of(+line: String) -> U32:
  Url.port_default(U32.read(Url.cut_before(Url.cut(trim_left(Url.or_empty(Url.cut_rest(Url.cut(line, " ")))), " "))), "x")

# ---- bodies ------------------------------------------------------------------

def take(n: Nat, bs: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+k:
      match bs:
        case Nil{}:
          Nil{}
        case Con{b, t}:
          b <> take(k, t)

def hex_val(+b: U32) -> U32:
  pick((b >= 97 : U32), (b - 87 : U32), pick((b >= 65 : U32), (b - 55 : U32), (b - 48 : U32)))

def is_hex(+b: U32) -> Bool:
  ((b >= 48 : U32) && (b <= 57 : U32)) || ((b >= 97 : U32) && (b <= 102 : U32)) || ((b >= 65 : U32) && (b <= 70 : U32))

# Chunked transfer coding (RFC 9112 7.1), one fold over the bytes:
#   mode 0: reading the size in hex   1: skipping to the end of the size line
#   2: `left` data bytes to copy      3: skipping the CRLF after the data
#   4: done (last chunk seen; trailers are ignored)
def dechunk(bs: List<&2, U32>, +mode: U32, +left: U32, +out: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      List.reverse(&2, U32, out)
    case Con{+b, t}:
      +m0 = U32.is_eq(mode, 0)
      +m2 = U32.is_eq(mode, 2)
      +lf = U32.is_eq(b, 10)
      +copy = m2 && (left > 0 : U32)
      dechunk(
        t,
        pick(m0 && is_hex(b), 0,
          pick(m0 || U32.is_eq(mode, 1), pick(lf, pick(U32.is_zero(left), 4, 2), 1),
            pick(m2, pick(U32.is_eq(left, 1), 3, 2),
              pick(U32.is_eq(mode, 3), pick(lf, 0, 3), 4)))),
        pick(m0 && is_hex(b), ((left * 16 : U32) + hex_val(b) : U32),
          pick(copy, (left - 1 : U32), left)),
        Bool.pick(List<&2, U32>, copy, b <> out, out)
      )

# Content-Length bytes of `raw`; a length that does not read as a number
# frames nothing, and the body is what came before the close. (It read as
# Url.port_default's 80, and such a body was cut to 80 bytes.)
def by_length(m: Maybe<&2, U32>, +raw: List<&2, U32>) -> List<&2, U32>:
  match m:
    case None{}:
      raw
    case Some{n}:
      take(U32.to_nat(n), raw)

def body_of(+hs: List<&2, Hdr>, +raw: List<&2, U32>) -> List<&2, U32>:
  Bool.pick(List<&2, U32>, String.ends_with(String.to_lower(header(hs, "transfer-encoding")), "chunked"),
    dechunk(raw, 0, 0, Nil{}),
    by_length(U32.read(header(hs, "content-length")), raw))

def first_line(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      h

def rest_lines(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# ---- when a response is complete (RFC 9112 6.3) -------------------------------

# Element asks every server to close (Connection: close) and reads to the
# end of the stream; some answer keep-alive and hold the socket open
# (geo.craigslist.org), so the reader waited for its deadline. A response
# is complete by its framing: no body (204, 304), the last chunk and the
# end of the trailers, or Content-Length bytes. Without framing the body
# runs to the close, and only the close completes it. A 1xx (103 Early
# Hints) is followed by the real response, so it never completes one.

# The chunked state after `bs`, as in dechunk: 4 is the last chunk seen.
# `after` counts bytes after mode 4 and `w` keeps the last four bytes, so
# the end of the trailers (an empty line) is seen.
type CS is Data:
  CS{mode: U32, left: U32, after: U32, w: U32}

def chunk_state(bs: List<&2, U32>, st: CS) -> CS:
  match bs:
    case Nil{}:
      st
    case Con{+b, t}:
      match st:
        case CS{+mode, +left, +after, +w}:
          +m0 = U32.is_eq(mode, 0)
          +m2 = U32.is_eq(mode, 2)
          +m4 = U32.is_eq(mode, 4)
          +lf = U32.is_eq(b, 10)
          +copy = m2 && (left > 0 : U32)
          +hv = hex_val(b)
          chunk_state(t, CS{
            pick(m0 && is_hex(b), 0,
              pick(m0 || U32.is_eq(mode, 1), pick(lf, pick(U32.is_zero(left), 4, 2), 1),
                pick(m2, pick(U32.is_eq(left, 1), 3, 2),
                  pick(U32.is_eq(mode, 3), pick(lf, 0, 3), 4)))),
            pick(m0 && is_hex(b), ((left * 16 : U32) + hv : U32),
              pick(copy, (left - 1 : U32), left)),
            pick(m4, (after + 1 : U32), 0),
            pick(m4, ((w * 256 : U32) + b : U32), 0)})

# Done when the last chunk was seen and either no trailer followed (just
# CRLF) or the trailers ended with an empty line (CRLF CRLF).
def chunked_done(st: CS) -> Bool:
  match st:
    case CS{mode, left, +after, +w}:
      U32.is_eq(mode, 4) && ((U32.is_eq(after, 2) && U32.is_eq((w % 65536 : U32), 3338)) || U32.is_eq(w, 218762506))

def no_body(+status: U32) -> Bool:
  U32.is_eq(status, 204) || U32.is_eq(status, 304)

# Content-Length bytes received. A length that does not read as a number
# frames nothing: the body then runs to the close.
def have_length(m: Maybe<&2, U32>, +n: U32) -> Bool:
  match m:
    case None{}:
      False{}
    case Some{want}:
      (n >= want : U32)

# the walk over the body runs only for a chunked one (a match, not a pick)
def chunked_complete(chunked: Bool, +body: List<&2, U32>) -> Bool:
  match chunked:
    case True{}:
      chunked_done(chunk_state(body, CS{0, 0, 0, 0}))
    case False{}:
      False{}

def complete_by(+status: U32, +hs: List<&2, Hdr>, +body: List<&2, U32>) -> Bool:
  +te = String.to_lower(header(hs, "transfer-encoding"))
  +cl = header(hs, "content-length")
  +chunked = String.ends_with(te, "chunked")
  Bool.pick(Bool, (status < 200 : U32), False{},
  Bool.pick(Bool, no_body(status), True{},
    Bool.pick(Bool, chunked, chunked_complete(chunked, body),
      have_length(U32.read(cl), U32.from_nat(List.length(&2, U32, body))))))

def complete_lines(+ls: List<&2, String>, +body: List<&2, U32>) -> Bool:
  complete_by(status_of(first_line(ls)), headers_of(rest_lines(ls)), body)

def complete_split(sp: Split) -> Bool:
  match sp:
    case Split{head, +body, found}:
      match found:
        case False{}:
          False{}
        case True{}:
          complete_lines(lines_go(U.latin1(head), Nil{}, Nil{}), body)

# Whether `bs` (from the first byte of the response) is a whole response.
def complete(bs: List<&2, U32>) -> Bool:
  complete_split(split_go(bs, False{}, 0, Nil{}))

# ---- keeping the connection (RFC 9112 9.3) ----------------------------------------

# Whether the server keeps the connection after the response `bs`: an
# HTTP/1.1 response unless it says Connection: close, an HTTP/1.0 one only
# when it says keep-alive. Reads the head only (split_go stops there).
def reusable_lines(+ls: List<&2, String>) -> Bool:
  +conn = String.to_lower(header(headers_of(rest_lines(ls)), "connection"))
  Bool.pick(Bool, String.starts_with(first_line(ls), "HTTP/1.1"),
    Bool.not(String.contains(conn, "close")),
    String.contains(conn, "keep-alive"))

def reusable_split(sp: Split) -> Bool:
  match sp:
    case Split{head, body, found}:
      match found:
        case False{}:
          False{}
        case True{}:
          reusable_lines(lines_go(U.latin1(head), Nil{}, Nil{}))

def reusable(bs: List<&2, U32>) -> Bool:
  reusable_split(split_go(bs, False{}, 0, Nil{}))

# a request's bytes start "GET " (only GETs go out twice on a stale connection)
def is_get(bs: List<&2, U32>) -> Bool:
  match bs:
    case Con{a, t}:
      match t:
        case Con{b, t2}:
          match t2:
            case Con{c, t3}:
              match t3:
                case Con{d, t4}:
                  U32.is_eq(a, 71) && U32.is_eq(b, 69) && U32.is_eq(c, 84) && U32.is_eq(d, 32)
                case Nil{}:
                  False{}
            case Nil{}:
              False{}
        case Nil{}:
          False{}
    case Nil{}:
      False{}

# ---- the same, read by read ------------------------------------------------------

# `complete` reads the whole response again; asked after every read, a body
# of n bytes over r reads cost n * r steps (github.com's 367 KB chunked page:
# 10.8 s of CPU for one fetch, 0.47 s for a 100 KB one). Fr is the framing
# after the bytes seen so far, and each read feeds it only the bytes it
# added: fr_done(fr_feed(...)) over the reads is `complete` over their
# concatenation.
type Fr is Data:
  FHead{head: +List<U32>}
  FLen{left: U32}
  FChunk{st: CS}
  FOpen{}
  FDone{}

def fr_start() -> Fr:
  FHead{Nil{}}

def fr_len(m: Maybe<&2, U32>) -> Fr:
  match m:
    case None{}:
      FOpen{}
    case Some{n}:
      FLen{n}

# As complete_by: a 1xx is followed by the real response (never complete),
# 204/304 have no body, then chunked, then Content-Length, else the close.
def fr_framing(+status: U32, +hs: List<&2, Hdr>) -> Fr:
  Bool.pick(Fr, (status < 200 : U32), FOpen{},
  Bool.pick(Fr, no_body(status), FDone{},
  Bool.pick(Fr, String.ends_with(String.to_lower(header(hs, "transfer-encoding")), "chunked"), FChunk{CS{0, 0, 0, 0}},
    fr_len(U32.read(header(hs, "content-length"))))))

def fr_of_lines(+ls: List<&2, String>) -> Fr:
  fr_framing(status_of(first_line(ls)), headers_of(rest_lines(ls)))

# the body's bytes, once the framing is known
def fr_rest(fr: Fr, +bs: List<&2, U32>) -> Fr:
  match fr:
    case FLen{+left}:
      +n = U32.from_nat(List.length(&2, U32, bs))
      FLen{pick((n >= left : U32), 0, (left - n : U32))}
    case FChunk{st}:
      FChunk{chunk_state(bs, st)}
    case FHead{head}:
      FHead{head}
    case FOpen{}:
      FOpen{}
    case FDone{}:
      FDone{}

# split_go's window over the head kept newest first: its first four bytes
def fr_w(n: Nat, head: List<&2, U32>) -> U32:
  match n:
    case 0n:
      0
    case 1n+k:
      match head:
        case Nil{}:
          0
        case Con{+h, t}:
          +up = fr_w(k, t)
          (h + (up * 256 : U32) : U32)

# the head up to CRLFCRLF (split_go, carried on from the bytes seen), then
# what follows it as the body
def fr_split(sp: Split) -> Fr:
  match sp:
    case Split{+head, body, found}:
      match found:
        case True{}:
          fr_rest(fr_of_lines(lines_go(U.latin1(head), Nil{}, Nil{})), body)
        case False{}:
          FHead{List.reverse(&2, U32, head)}

def fr_feed(fr: Fr, +bs: List<&2, U32>) -> Fr:
  match fr:
    case FHead{+head}:
      fr_split(split_go(bs, False{}, fr_w(4n, head), head))
    case FLen{left}:
      fr_rest(FLen{left}, bs)
    case FChunk{st}:
      fr_rest(FChunk{st}, bs)
    case FOpen{}:
      FOpen{}
    case FDone{}:
      FDone{}

def fr_done(fr: Fr) -> Bool:
  match fr:
    case FLen{left}:
      U32.is_zero(left)
    case FChunk{st}:
      chunked_done(st)
    case FDone{}:
      True{}
    case FHead{head}:
      False{}
    case FOpen{}:
      False{}

# Element asks for Accept-Encoding: gzip, deflate (since 2026-10-27; it
# asked for identity before, and python.org compressed anyway, curl
# confirms). A gzip, x-gzip or deflate body is decoded (compress; the
# trailer's checksum verified); bytes Element cannot decode (br, zstd, a
# corrupt stream) are not a page: the response is refused, never shown as
# text. The headers stay as sent (Content-Encoding and Content-Length
# describe the wire, the body is the content).
def coded(+hs: List<&2, Hdr>) -> String:
  +e = String.to_lower(rtrim(trim_left(header(hs, "content-encoding"))))
  Bool.pick(String, String.eq(e, "identity"), "", e)

def resp_body(r: Result<&2, &2, String, List<&2, U32>>, +ls: List<&2, String>, +enc: String) -> Result<&2, &2, String, Resp>:
  match r:
    case Fail{e}:
      Fail{"http: the server sent its body " ++ enc ++ "-encoded and Element cannot decode it; " ++ e}
    case Done{body}:
      Done{Resp{status_of(first_line(ls)), headers_of(rest_lines(ls)), body}}

def resp_build(+ls: List<&2, String>, +raw: List<&2, U32>) -> Result<&2, &2, String, Resp>:
  +hs = headers_of(rest_lines(ls))
  +enc = coded(hs)
  resp_body(Gzip.decode(enc, body_of(hs, raw)), ls, enc)

def resp_lines(+text: String, +raw: List<&2, U32>) -> Result<&2, &2, String, Resp>:
  resp_build(lines_go(text, Nil{}, Nil{}), raw)

def resp_of(sp: Split) -> Result<&2, &2, String, Resp>:
  match sp:
    case Split{head, body, found}:
      match found:
        case False{}:
          Fail{"http: no end of headers"}
        case True{}:
          resp_lines(U.latin1(head), body)

def parse(bs: List<&2, U32>) -> Result<&2, &2, String, Resp>:
  resp_of(split_go(bs, False{}, 0, Nil{}))

# ---- navigation --------------------------------------------------------------

# What a response means at `url`: a page (decoded HTML), a redirect to an
# absolute URL, or an error.
type Next is Data:
  Page{html: String}
  Go{url: String}
  Bad{msg: String}

def is_redirect(+s: U32) -> Bool:
  U32.is_eq(s, 301) || U32.is_eq(s, 302) || U32.is_eq(s, 303) || U32.is_eq(s, 307) || U32.is_eq(s, 308)

def next_of(r: Resp, +url: String) -> Next:
  match r:
    case Resp{+status, +headers, +body}:
      Bool.pick(Next, is_redirect(status) && Bool.not(String.eq(header(headers, "location"), "")),
        Go{Url.resolve(url, header(headers, "location"))},
        Bool.pick(Next, (status >= 200 : U32) && (status < 300 : U32),
          Page{U.decode(header(headers, "content-type"), body)},
          Bad{"http: status " ++ U32.show(status)}))

def next(r: Result<&2, &2, String, Resp>, +url: String) -> Next:
  match r:
    case Fail{error}:
      Bad{error}
    case Done{value}:
      next_of(value, url)

# ---- K3.5 redirects, simulated over recorded responses -----------------------
# `table` maps a URL to the raw response it would return. Follows at most
# `fuel` redirects; a loop (or a longer chain) is a loud error.

type Rec is Data:
  Rec{url: String, resp: String}

def lookup(t: List<&2, Rec>, +u: String) -> String:
  match t:
    case Nil{}:
      SNil{}
    case Con{r, rest}:
      match r:
        case Rec{+ru, v}:
          Bool.pick(String, String.eq(ru, u), v, lookup(rest, u))

def is_go(n: Next) -> Bool:
  match n:
    case Go{url}:
      True{}
    case Page{html}:
      False{}
    case Bad{msg}:
      False{}

def go_url(n: Next) -> String:
  match n:
    case Go{url}:
      url
    case Page{html}:
      SNil{}
    case Bad{msg}:
      SNil{}

def final_of(n: Next) -> String:
  match n:
    case Page{html}:
      html
    case Bad{msg}:
      "ERROR " ++ msg
    case Go{url}:
      SNil{}

def follow(fuel: Nat, +table: List<&2, Rec>, +url: String) -> String:
  match fuel:
    case 0n:
      "ERROR too many redirects"
    case 1n+k:
      +n = next(parse(U.bytes_of(lookup(table, url))), url)
      Bool.pick(String, is_go(n), follow(k, table, go_url(n)), final_of(n))

# A recorded site: / -> 301 /a (relative Location) -> 200 chunked page;
# /loop -> 302 /loop forever.
def recorded() -> List<&2, Rec>:
  [
    Rec{"http://h/", "HTTP/1.1 301 Moved Permanently\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n"},
    Rec{"http://h/a", "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"},
    Rec{"http://h/loop", "HTTP/1.1 302 Found\r\nLocation: http://h/loop\r\n\r\n"}
  ]
