import Base
import ./sock.bend as Sock
import element-rfc3986@0.1.0.0/url.bend as Url
import ./http.bend as Http
import element-text@0.1.0.0/utf8.bend as U
import ./io.bend as Tls
import ./cookie.bend as Ck

# K3.2/K3.5/K3.6 fetch, the IO half: resolve the host, connect, send the
# request, read raw bytes until the server closes, parse, and follow up to
# 5 redirects. Over the byte cap is a loud error, never a partial page.
#
# https:// runs over tls (TLS 1.3 in pure Bend) and authenticates the
# server with x509 against the system CA bundle. `trust` is the store
# (Tls.Store): Unverified is a caller's explicit opt-out, which skips
# that check: an explicit opt-out for debugging, never a silent fallback.
#
# Shape: Bend allows no mutual recursion and a `match` only heads a def or a
# case, so each loop is ONE def over a state type. Pure helpers classify what
# just happened into the next state; the def matches on that state.

type Page is Data:
  Page{url: String, html: String}

def max_redirects() -> U32:
  5

# ---- reading a socket to EOF ---------------------------------------------------

# More: keep reading. Eof/Over/Err: stop (the socket is closed on the way out).
type RS is Type:
  More{sock: Socket, chunks: +List<List<&2, U32>>, total: U32, fr: Http.Fr}
  Eof{sock: Socket, chunks: +List<List<&2, U32>>}
  Over{sock: Socket}
  Err{sock: Socket, code: U32, msg: String}

def rs_done(
  eof: Bool, over: Bool, s: Socket, bs: List<&2, U32>, chunks: List<&2, List<&2, U32>>, +total: U32, fr: Http.Fr
) -> RS:
  match eof over:
    case True{} _:
      Eof{s, chunks}
    case False{} True{}:
      Over{s}
    case False{} False{}:
      More{s, bs <> chunks, total, fr}

def rs_of(
  got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, chunks: List<&2, List<&2, U32>>,
  +total: U32, +cap: U32, fr: Http.Fr
) -> RS:
  match got:
    case (s, r):
      match r:
        case Fail{e}:
          match e:
            case (c, m):
              Err{s, c, m}
        case Done{+bs}:
          +n = U32.from_nat(List.length(&2, U32, bs))
          rs_done(U32.is_zero(n), ((total + n : U32) > cap : U32), s, bs, chunks, (total + n : U32), fr)

def close_with(s: Socket, r: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    Socket.close(s)
    return r

def rs_stop(st: RS, +cap: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match st:
    case Eof{s, chunks}:
      close_with(s, Done{List.concat(&2, U32, List.reverse(&2, List<&2, U32>, chunks))})
    case Over{s}:
      close_with(s, Fail{(27, "page is over the byte cap of " ++ U32.show(cap) ++ " bytes")})
    case Err{s, c, m}:
      close_with(s, Fail{(c, m)})
    case More{s, chunks, total, fr}:
      close_with(s, Fail{(1, "too many reads")})

# A whole response by its framing ends the read even when the server keeps
# the socket open (keep-alive hosts ignore Connection: close). The framing
# (Http.Fr) is fed each read's bytes once: the newest chunk.
def whole(done: Bool, s: Socket, +chunks: List<&2, List<&2, U32>>, +total: U32, fr: Http.Fr) -> RS:
  match done:
    case True{}:
      Eof{s, chunks}
    case False{}:
      More{s, chunks, total, fr}

def newest(chunks: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match chunks:
    case Nil{}:
      Nil{}
    case Con{c, t}:
      c

def framed(st: RS) -> RS:
  match st:
    case More{s, +chunks, +total, fr}:
      +fr2 = Http.fr_feed(fr, newest(chunks))
      whole(Http.fr_done(fr2), s, chunks, total, fr2)
    case Eof{s, chunks}:
      Eof{s, chunks}
    case Over{s}:
      Over{s}
    case Err{s, c, m}:
      Err{s, c, m}

def read_loop(k: Nat, st: RS, +cap: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match k:
    case 0n:
      rs_stop(st, cap)
    case 1n+r:
      match st:
        case More{s, +chunks, +total, fr}:
          IO.bind(
            Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
            Result<&1, &1, U32 & String, List<&2, U32>>,
            Sock.Net.recv_bytes(s, 65536),
            got => read_loop(r, framed(rs_of(got, chunks, total, cap, fr)), cap)
          )
        case Eof{s, chunks}:
          rs_stop(Eof{s, chunks}, cap)
        case Over{s}:
          rs_stop(Over{s}, cap)
        case Err{s, c, m}:
          rs_stop(Err{s, c, m}, cap)

# ---- one request ---------------------------------------------------------------

def sock_of(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  match sent:
    case (s, r):
      s

def get_sock(r: Result<&1, &1, U32 & String, Socket>, +req: String, +cap: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- Sock.Net.send(sock, req)
        body : Result<&1, &1, U32 & String, List<&2, U32>> <- read_loop(U32.to_nat(16384), More{sock_of(sent), Nil{}, 0, Http.fr_start()}, cap)
        return body

def get_ip(r: Result<&1, &1, U32 & String, String>, port: U32, +req: String, +cap: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{ip}:
      IO.bind(Result<&1, &1, U32 & String, Socket>, Result<&1, &1, U32 & String, List<&2, U32>>, TCP.connect(ip, port), c => get_sock(c, req, cap))

# A host that does not resolve or a port that refuses is this request's
# error (the caller answers it), never the end of the program.
def get(+host: String, port: U32, +req: String, +cap: U32) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  IO.bind(Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, List<&2, U32>>, Sock.Net.resolve(host), r => get_ip(r, port, req, cap))

# ---- navigation: request, redirects, cookies ------------------------------------

# A request to make: method, body and its type (a form POST; GET has none),
# and the User-Agent ("" = Element's) and extra header lines it carries,
# kept across redirects.
type Req is Data:
  Req{method: String, body: String, ctype: String, ua: String, extra: String}

def get_req() -> Req:
  Req{"GET", "", "", "", ""}

# The GET a redirect makes: same User-Agent and extra headers, no body.
def as_get(r: Req) -> Req:
  match r:
    case Req{method, body, ctype, +ua, +extra}:
      Req{"GET", "", "", ua, extra}

type FS is Data:
  Want{url: String, hops: U32, req: Req}
  Plain{url: String, host: String, port: U32, target: String, hops: U32, tls: Bool, req: Req}
  Read{url: String, bytes: +List<U32>, hops: U32, req: Req}
  Final{url: String, html: String}
  Refuse{msg: String}
  Got{url: String, status: U32, ctype: String, body: String, acao: String, hdrs: String}

def plan_scheme(+sch: String, +url: String, +hops: U32, +req: Req) -> FS:
  Bool.pick(FS, (hops > max_redirects() : U32), Refuse{"more than " ++ U32.show(max_redirects()) ++ " redirects"},
    Bool.pick(FS, String.eq(sch, "http") || String.eq(sch, "https"),
      Plain{url, Url.url_host(Url.parse(url)), Url.url_port(Url.parse(url)), Url.url_target(Url.parse(url)), hops, String.eq(sch, "https"), req},
      Refuse{"unsupported URL scheme: " ++ sch}))

def plan(+url: String, +hops: U32, +req: Req) -> FS:
  plan_scheme(Url.url_scheme(Url.parse(url)), url, hops, req)

# A redirect is followed with GET (what browsers do after a form POST).
def after_read(n: Http.Next, +url: String, +hops: U32, +req: Req) -> FS:
  match n:
    case Http.Page{html}:
      Final{url, html}
    case Http.Go{to}:
      Want{to, (hops + 1 : U32), as_get(req)}
    case Http.Bad{msg}:
      Refuse{msg}

def read_result(r: Result<&1, &1, U32 & String, List<&2, U32>>, +url: String, +hops: U32, +req: Req) -> FS:
  match r:
    case Fail{e}:
      match e:
        case (c, m):
          Refuse{"fetch " ++ url ++ ": " ++ m}
    case Done{bs}:
      Read{url, bs, hops, req}

# A page, where it ended up, and the cookie jar after every response on the way.
type Visit is Data:
  Visit{url: String, html: String, jar: +List<Ck.Cookie>}

def out_of_steps() -> IO(Result<&1, &1, U32 & String, Visit>):
  IO.pure(Result<&1, &1, U32 & String, Visit>, Fail{(1, "navigation ran out of steps")})

# The path part of a request target (cookies match on the path, not the query).
def path_of(+target: String) -> String:
  Ck.before(target, '?')

def send_now(tls: Bool, +host: String, port: U32, +req: String, +cap: U32, +trust: Tls.Store) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match tls:
    case True{}:
      Tls.https_get(host, port, U.bytes_of(req), cap, trust)
    case False{}:
      get(host, port, req, cap)

# A host that accepts and then goes silent held a navigation forever. Each
# exchange (connect, TLS, request, whole answer) now has a deadline, and
# missing it is an error the caller sees, as Chrome's net::ERR_TIMED_OUT.
#
# Not IO.within: it cannot cancel its loser, and when the answer wins the
# loser is a 60 s sleep that a CLI run waited out before exiting (every
# `element --url` took 60 s). Here the clock is a ticker of 200 ms slices
# that sends each tick into the answer's channel; the waiter counts ticks,
# and closes the channel as soon as the answer comes, so the ticker's next
# send fails and it stops within one slice. A late exchange still runs on
# (nothing can cancel it) and closes its own socket when the host ends it.
def tick_ms() -> U32:
  200

def deadline_ticks() -> Nat:
  300n

def deadline_s() -> U32:
  60

type W is Type:
  WMore{}
  WDone{r: Result<&1, &1, U32 & String, List<&2, U32>>}
  WShut{}

def decide(m: Maybe<&1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>>) -> W:
  match m:
    case None{}:
      WShut{}
    case Some{v}:
      match v:
        case None{}:
          WMore{}
        case Some{r}:
          WDone{r}

# (`ms`: the deadline this exchange had: 60 s, or a page's own timeout)
def timed_out(+host: String, +ms: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  Fail{(60, "net::ERR_TIMED_OUT: " ++ host ++ " sent no complete answer within " ++ Bool.pick(String, U32.is_zero((ms % 1000 : U32)), U32.show((ms / 1000 : U32)) ++ " s", U32.show(ms) ++ " ms"))}

def late(+c: Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>), +host: String, +ms: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    Chan.close(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, c)
    return timed_out(host, ms)

# Chan.send (Base 2.0.36+): Done{} once the channel took the value,
# Fail{value} once it is closed; the ticker stops at the first refusal.
def taken(r: Result<&1, &1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, Unit>) -> Bool:
  match r:
    case Done{u}:
      True{}
    case Fail{v}:
      False{}

def ticker(n: Nat, go: Bool, +c: Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>)) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+k:
      match go:
        case False{}:
          IO.pure(Unit, Unit{})
        case True{}:
          IO.bind(Unit, Unit, IO.sleep(tick_ms()), u =>
            IO.bind(Result<&1, &1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, Unit>, Unit, Chan.send(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, c, None{}), r => ticker(k, taken(r), c)))

def settle(d: W, +c: Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>), +host: String, +ms: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match d:
    case WDone{r}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        Chan.close(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, c)
        return r
    case WShut{}:
      late(c, host, ms)
    case WMore{}:
      late(c, host, ms)

# n: how many more items to take. The ticker sends deadline_ticks() ticks at
# most, so the waiter never takes more than that and never blocks past it.
def wait(n: Nat, d: W, +c: Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>), +host: String, +ms: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match n:
    case 0n:
      settle(d, c, host, ms)
    case 1n+k:
      match d:
        case WMore{}:
          IO.bind(Maybe<&1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>>, Result<&1, &1, U32 & String, List<&2, U32>>,
            Chan.recv(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, c), m => wait(k, decide(m), c, host, ms))
        case WDone{r}:
          settle(WDone{r}, c, host, ms)
        case WShut{}:
          late(c, host, ms)

def answer_into(+c: Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>), act: IO(Result<&1, &1, U32 & String, List<&2, U32>>)) -> IO(Result<&1, &1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, Unit>):
  IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Result<&1, &1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, Unit>, act, r => Chan.send(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, c, Some{r}))

# `ticks` slices of tick_ms(): deadline_ticks() (60 s), or fewer for a
# page's own timeout (XMLHttpRequest.timeout)
def race(+ticks: Nat, +c: Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>), act: IO(Result<&1, &1, U32 & String, List<&2, U32>>), +host: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  +n = U32.from_nat(ticks)
  +tk = tick_ms()
  +ms = (n * tk : U32)
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    IO.spawn(Result<&1, &1, Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, Unit>, answer_into(c, act))
    IO.spawn(Unit, ticker(ticks, True{}, c))
    wait(ticks, WMore{}, c, host, ms)

def send_within(+ticks: Nat, tls: Bool, +host: String, port: U32, +req: String, +cap: U32, +trust: Tls.Store) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  IO.bind(
    Chan(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>),
    Result<&1, &1, U32 & String, List<&2, U32>>,
    Chan.new(Maybe<&1, Result<&1, &1, U32 & String, List<&2, U32>>>, 1),
    c => race(ticks, c, send_now(tls, host, port, req, cap, trust), host)
  )

def send_any(tls: Bool, +host: String, port: U32, +req: String, +cap: U32, +trust: Tls.Store) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  send_within(deadline_ticks(), tls, host, port, req, cap, trust)

# an https request through a pool asks the server to keep the connection
def request_of(r: Req, +host: String, +target: String, +cookie: String, +keep: Bool) -> String:
  match r:
    case Req{+method, +body, +ctype, +ua, +extra}:
      Http.request_with(Bool.pick(String, keep, "keep-alive", "close"), host, method, target, cookie, ctype, body, ua, extra)

def url_host_of(+url: String) -> String:
  Url.url_host(Url.parse(url))

def url_path_of(+url: String) -> String:
  path_of(Url.url_target(Url.parse(url)))

def nav(k: Nat, st: FS, +cap: U32, +trust: Tls.Store, +jar: List<&2, Ck.Cookie>, +now: U32) -> IO(Result<&1, &1, U32 & String, Visit>):
  match k:
    case 0n:
      out_of_steps()
    case 1n+r:
      match st:
        case Final{url, html}:
          IO.pure(Result<&1, &1, U32 & String, Visit>, Done{Visit{url, html, jar}})
        case Refuse{msg}:
          IO.pure(Result<&1, &1, U32 & String, Visit>, Fail{(1, msg)})
        case Got{url, status, ctype, body, acao, hdrs}:
          IO.pure(Result<&1, &1, U32 & String, Visit>, Fail{(1, "a script request's answer in a navigation")})
        case Want{+url, +hops, +req}:
          nav(r, plan(url, hops, req), cap, trust, jar, now)
        case Read{+url, bytes, +hops, +req}:
          +parsed = Http.parse(bytes)
          +jar2 = Ck.store_all(Http.all(Http.resp_headers(parsed), "set-cookie"), jar, url_host_of(url), url_path_of(url), now)
          nav(r, after_read(Http.next(parsed, url), url, hops, req), cap, trust, jar2, now)
        case Plain{+url, +host, port, +target, +hops, +tls, +req}:
          IO.bind(
            Result<&1, &1, U32 & String, List<&2, U32>>,
            Result<&1, &1, U32 & String, Visit>,
            send_any(tls, host, port, request_of(req, host, target, Ck.header(jar, host, path_of(target), tls, now), tls && Tls.is_pooled(trust)), cap, trust),
            res => nav(r, read_result(res, url, hops, req), cap, trust, jar, now)
          )

# Fetch with a cookie jar at time `now`, as GET or a form POST: 3 steps per
# hop (plan, send, read), 6 hops at most.
def visit(+url: String, +req: Req, +cap: U32, +trust: Tls.Store, +jar: List<&2, Ck.Cookie>, +now: U32) -> IO(Result<&1, &1, U32 & String, Visit>):
  nav(U32.to_nat(24), Want{url, 0, req}, cap, trust, jar, now)

def page_of(r: Result<&1, &1, U32 & String, Visit>) -> IO(Result<&1, &1, U32 & String, Page>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Page>, Fail{e})
    case Done{v}:
      match v:
        case Visit{url, html, jar}:
          IO.pure(Result<&1, &1, U32 & String, Page>, Done{Page{url, html}})

# Fetch with no cookies, as `req` says (a page's stylesheets carry its
# User-Agent and extra headers).
def fetch_as(url: String, +req: Req, +cap: U32, +trust: Tls.Store) -> IO(Result<&1, &1, U32 & String, Page>):
  IO.bind(Result<&1, &1, U32 & String, Visit>, Result<&1, &1, U32 & String, Page>, visit(url, as_get(req), cap, trust, Nil{}, 0), page_of)

# Fetch a page with no cookies (GET).
def fetch(url: String, +cap: U32, +trust: Tls.Store) -> IO(Result<&1, &1, U32 & String, Page>):
  IO.bind(Result<&1, &1, U32 & String, Visit>, Result<&1, &1, U32 & String, Page>, visit(url, get_req(), cap, trust, Nil{}, 0), page_of)

# ---- a script's request (fetch, XMLHttpRequest) --------------------------------------------
# The answer whatever its status (a script sees 404s too), after the
# redirects a navigation would follow, with the cookie jar after them.
# `acao`: the Access-Control-Allow-Origin the answer carried, which the page
# checks before it lets a script read an answer from another origin.

type Answer is Data:
  Answer{url: String, status: U32, ctype: String, body: String, acao: String, jar: +List<Ck.Cookie>, headers: String}

# Every response header a script may read, as "name: value" lines
# (Set-Cookie and Set-Cookie2 never: Fetch's forbidden response header
# names). A page's Response and XMLHttpRequest answer from these.
def hdr_line(h: Http.Hdr) -> String:
  match h:
    case Http.Hdr{+name, +value}:
      +low = String.to_lower(name)
      Bool.pick(String, String.eq(low, "set-cookie") || String.eq(low, "set-cookie2"), "", name ++ ": " ++ value ++ "\n")

def hdr_lines(hs: List<&2, Http.Hdr>) -> String:
  match hs:
    case Nil{}:
      ""
    case Con{h, t}:
      hdr_line(h) ++ hdr_lines(t)

def got_of(r: Result<&2, &2, String, Http.Resp>, +url: String, +hops: U32, +req: Req) -> FS:
  match r:
    case Fail{e}:
      Refuse{e}
    case Done{resp}:
      match resp:
        case Http.Resp{+status, +headers, +body}:
          +loc = Http.header(headers, "location")
          Bool.pick(FS, Http.is_redirect(status) && Bool.not(String.is_empty(loc)), Want{Url.resolve(url, loc), (hops + 1 : U32), as_get(req)},
            Got{url, status, Http.header(headers, "content-type"), U.decode(Http.header(headers, "content-type"), body),
              Http.header(headers, "access-control-allow-origin"), hdr_lines(headers)})

# A refusal keeps only its words; one that says the deadline passed keeps its
# code (60) for the page (an XMLHttpRequest reports it as a timeout).
def has_sub(s: String, +needle: String) -> Bool:
  match s:
    case SNil{}:
      String.is_empty(needle)
    case SCon{+c, +t}:
      String.starts_with(SCon{c, t}, needle) || has_sub(t, needle)

def refuse_code(+msg: String) -> U32:
  Bool.pick(U32, has_sub(msg, "net::ERR_TIMED_OUT"), 60, 1)

def anav(k: Nat, st: FS, +cap: U32, +trust: Tls.Store, +jar: List<&2, Ck.Cookie>, +now: U32, +ticks: Nat) -> IO(Result<&1, &1, U32 & String, Answer>):
  match k:
    case 0n:
      IO.pure(Result<&1, &1, U32 & String, Answer>, Fail{(1, "request ran out of steps")})
    case 1n+r:
      match st:
        case Got{+url, +status, +ctype, +body, +acao, +hdrs}:
          IO.pure(Result<&1, &1, U32 & String, Answer>, Done{Answer{url, status, ctype, body, acao, jar, hdrs}})
        case Final{url, html}:
          IO.pure(Result<&1, &1, U32 & String, Answer>, Fail{(1, "a navigation's page in a script request")})
        case Refuse{+msg}:
          IO.pure(Result<&1, &1, U32 & String, Answer>, Fail{(refuse_code(msg), msg)})
        case Want{+url, +hops, +req}:
          anav(r, plan(url, hops, req), cap, trust, jar, now, ticks)
        case Read{+url, bytes, +hops, +req}:
          +parsed = Http.parse(bytes)
          +jar2 = Ck.store_all(Http.all(Http.resp_headers(parsed), "set-cookie"), jar, url_host_of(url), url_path_of(url), now)
          anav(r, got_of(parsed, url, hops, req), cap, trust, jar2, now, ticks)
        case Plain{+url, +host, port, +target, +hops, +tls, +req}:
          IO.bind(
            Result<&1, &1, U32 & String, List<&2, U32>>,
            Result<&1, &1, U32 & String, Answer>,
            send_within(ticks, tls, host, port, request_of(req, host, target, Ck.header(jar, host, path_of(target), tls, now), tls && Tls.is_pooled(trust)), cap, trust),
            res => anav(r, read_result(res, url, hops, req), cap, trust, jar, now, ticks)
          )

def request(+url: String, +req: Req, +cap: U32, +trust: Tls.Store, +jar: List<&2, Ck.Cookie>, +now: U32) -> IO(Result<&1, &1, U32 & String, Answer>):
  anav(U32.to_nat(24), Want{url, 0, req}, cap, trust, jar, now, deadline_ticks())

# A request with a page's own deadline (ms, XMLHttpRequest.timeout; 0: none),
# never past the 60 s every exchange has: each exchange of it (a redirect
# is another) gets that long. Its failure is code 60, ERR_TIMED_OUT.
def request_within(+url: String, +req: Req, +cap: U32, +trust: Tls.Store, +jar: List<&2, Ck.Cookie>, +now: U32, +ms: U32) -> IO(Result<&1, &1, U32 & String, Answer>):
  +tk = tick_ms()
  +t = ((ms + tk - 1 : U32) / tk : U32)
  +ticks = Bool.pick(U32, U32.is_zero(ms) || (t > 300 : U32), 300, Bool.pick(U32, U32.is_zero(t), 1, t))
  anav(U32.to_nat(24), Want{url, 0, req}, cap, trust, jar, now, U32.to_nat(ticks))
