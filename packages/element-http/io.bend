import Base
import ./sock.bend as Sock
import element-tls13@0.1.0.0/client.bend as C
import element-hostio@0.1.0.0/clock.bend as Wall
import element-x509@0.1.0.0/cert.bend as X509
import element-x509@0.1.0.0/pem.bend as Pem
import ./http.bend as Http

# Runs the sans-IO TLS client (client.bend: 1.3, else 1.2) over a socket: write what it
# wants to send, read, feed, repeat, until the server closes. Returns the
# decrypted application bytes. Randomness comes from /dev/urandom.
#
# The server is authenticated against the CA bundle named by SSL_CERT_FILE,
# else the system's (the first of /etc/ssl/cert.pem,
# /etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt that
# opens), at the wall-clock time. With
# `verify` off the connection is encrypted but unauthenticated: a caller's
# explicit opt-out, never a fallback.

# Go carries the response's framing (Http.Fr) and how many plaintext
# records it has read, so each record's bytes are framed once.
type TS is Type:
  Go{sock: Socket, cs: C.Cs, fr: Http.Fr, seen: Nat}
  Finish{sock: Socket, out: +List<U32>}
  Framed{sock: Socket, cs: C.Cs}
  Abort{sock: Socket, msg: String}

def over_cap(over: Bool, s: Socket, +cs: C.Cs, fr: Http.Fr, +seen: Nat) -> TS:
  match over:
    case True{}:
      Abort{s, "page is over the byte cap"}
    case False{}:
      Go{s, cs, fr, seen}

# Application data that is a whole HTTP response by its framing ends the
# exchange, though the server may keep the connection open (keep-alive).
def app_state(done: Bool, s: Socket, +cs: C.Cs, +cap: U32, fr: Http.Fr, +seen: Nat) -> TS:
  match done:
    case True{}:
      Framed{s, cs}
    case False{}:
      over_cap((C.out_len(cs) > cap : U32), s, cs, fr, seen)

# the records this feed added (out is newest first) go through the framing
def app_fed(s: Socket, +cs: C.Cs, +cap: U32, fr: Http.Fr, +seen: Nat) -> TS:
  +chunks = C.out_chunks(cs)
  +n = List.length(&2, List<&2, U32>, chunks)
  +fresh = List.reverse(&2, List<&2, U32>, List.take(&2, List<&2, U32>, chunks, Nat.sub(n, seen)))
  +fr2 = Http.fr_feed(fr, List.concat(&2, U32, fresh))
  app_state(Http.fr_done(fr2), s, cs, cap, fr2, n)

def classify(p: C.Phase, s: Socket, +cs: C.Cs, +cap: U32, fr: Http.Fr, +seen: Nat) -> TS:
  match p:
    case C.PClosed{}:
      Finish{s, C.out_of(cs)}
    case C.PFailed{msg}:
      Abort{s, "tls: " ++ msg}
    case C.PAwait{}:
      Go{s, cs, fr, seen}
    case C.PHs{}:
      Go{s, cs, fr, seen}
    case C.PHs12{x}:
      Go{s, cs, fr, seen}
    case C.PFin12{x}:
      Go{s, cs, fr, seen}
    case C.PApp{}:
      app_fed(s, cs, cap, fr, seen)
    case C.PApp12{}:
      app_fed(s, cs, cap, fr, seen)

# The server closed the connection: fine once application data flows (many
# servers skip close_notify), an error during the handshake.
def at_eof(p: C.Phase, s: Socket, +cs: C.Cs) -> TS:
  match p:
    case C.PApp{}:
      Finish{s, C.out_of(cs)}
    case C.PClosed{}:
      Finish{s, C.out_of(cs)}
    case C.PFailed{msg}:
      Abort{s, "tls: " ++ msg}
    case C.PAwait{}:
      Abort{s, "tls: connection closed before ServerHello"}
    case C.PHs{}:
      Abort{s, "tls: connection closed during the handshake"}
    case C.PApp12{}:
      Finish{s, C.out_of(cs)}
    case C.PHs12{x}:
      Abort{s, "tls: connection closed during the handshake"}
    case C.PFin12{x}:
      Abort{s, "tls: connection closed during the handshake"}

def fed(s: Socket, +cs2: C.Cs, +cap: U32, fr: Http.Fr, +seen: Nat) -> TS:
  classify(C.phase_of(cs2), s, cs2, cap, fr, seen)

def after_bytes(n: Nat, s: Socket, +cs: C.Cs, +bs: List<&2, U32>, +cap: U32, fr: Http.Fr, +seen: Nat) -> TS:
  match n:
    case 0n:
      at_eof(C.phase_of(cs), s, cs)
    case 1n+k:
      fed(s, C.feed(cs, bs), cap, fr, seen)

def after_recv(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +cs: C.Cs, +cap: U32, fr: Http.Fr, +seen: Nat) -> TS:
  match got:
    case (s, r):
      match r:
        case Fail{e}:
          match e:
            case (c, m):
              Abort{s, "tls: read failed: " ++ m}
        case Done{+bs}:
          after_bytes(List.length(&2, U32, bs), s, cs, bs, cap, fr, seen)

def sock_of(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  match sent:
    case (s, r):
      s

# What an exchange leaves: its result, and the session when the response
# was whole by its framing and the server keeps the connection (the pool
# lends it again); otherwise the socket is closed here.
type Ended is Type:
  Ended{res: Result<&1, &1, U32 & String, List<&2, U32>>, keep: Maybe<&1, Sess>}

type Sess is Type:
  Sess{sock: Socket, cs: C.Cs}

def closed(s: Socket, r: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Ended):
  do IO<Ended>:
    Socket.close(s)
    return Ended{r, None{}}

def app_phase(p: C.Phase) -> Bool:
  match p:
    case C.PApp{}:
      True{}
    case C.PApp12{}:
      True{}
    case _:
      False{}

def kept(ok: Bool, s: Socket, +cs: C.Cs) -> IO(Ended):
  match ok:
    case True{}:
      IO.pure(Ended, Ended{Done{C.out_of(cs)}, Some{Sess{s, cs}}})
    case False{}:
      closed(s, Done{C.out_of(cs)})

def stop(st: TS, +keep: Bool) -> IO(Ended):
  match st:
    case Go{s, cs, fr, seen}:
      closed(s, Fail{(1, "tls: too many round trips")})
    case Finish{s, out}:
      closed(s, Done{out})
    case Framed{s, +cs}:
      kept(keep && app_phase(C.phase_of(cs)) && Http.reusable(C.out_of(cs)), s, cs)
    case Abort{s, msg}:
      closed(s, Fail{(1, msg)})

def loop(k: Nat, st: TS, +cap: U32, +keep: Bool) -> IO(Ended):
  match k:
    case 0n:
      stop(st, keep)
    case 1n+r:
      match st:
        case Finish{s, out}:
          stop(Finish{s, out}, keep)
        case Framed{s, cs}:
          stop(Framed{s, cs}, keep)
        case Abort{s, msg}:
          stop(Abort{s, msg}, keep)
        case Go{s, +cs, fr, +seen}:
          do IO<Ended>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- Sock.Net.send_bytes(s, C.send_of(cs))
            got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- Sock.Net.recv_bytes(sock_of(sent), 65536)
            res : Ended <- loop(r, after_recv(got, C.clear_send(cs), cap, fr, seen), cap, keep)
            return res

def random_done(got: File & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(List<&2, U32>):
  match got:
    case (f, r):
      do IO<List<&2, U32>>:
        File.close(f)
        bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
        return bs

def random_bytes(n: U32) -> IO(List<&2, U32>):
  do IO<List<&2, U32>>:
    f : File <- IO.try(File, File.open("/dev/urandom", "r"))
    got : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(f, n)
    bs : List<&2, U32> <- random_done(got)
    return bs

# ---- trust --------------------------------------------------------------------------

def close_after(got: File & Result<&1, &1, U32 & String, String>) -> IO(String):
  match got:
    case (f, r):
      do IO<String>:
        File.close(f)
        text : String <- IO.pass(String, r)
        return text

def read_opened(r: Result<&1, &1, U32 & String, File>, alt: IO(String)) -> IO(String):
  match r:
    case Fail{e}:
      alt
    case Done{f}:
      do IO<String>:
        got : File & Result<&1, &1, U32 & String, String> <- File.read(f, 16777216)
        text : String <- close_after(got)
        return text

# The file's text, or `alt` when it does not open.
def read_or(path: String, alt: IO(String)) -> IO(String):
  do IO<String>:
    r : Result<&1, &1, U32 & String, File> <- File.open(path, "r")
    text : String <- read_opened(r, alt)
    return text

def system_bundle() -> IO(String):
  read_or("/etc/ssl/cert.pem",
    read_or("/etc/ssl/certs/ca-certificates.crt",
      read_or("/etc/pki/tls/certs/ca-bundle.crt", IO.pure(String, ""))))

def bundle_at(r: Result<&1, &1, U32 & String, String>) -> IO(String):
  match r:
    case Fail{e}:
      system_bundle()
    case Done{+path}:
      Bool.pick(IO(String), String.is_empty(path), system_bundle(), read_or(path, IO.pure(String, "")))

# SSL_CERT_FILE (OpenSSL's convention) names the bundle to trust instead;
# when it is set but does not open, nothing is trusted.
def ca_bundle() -> IO(String):
  do IO<String>:
    r : Result<&1, &1, U32 & String, String> <- IO.get_env("SSL_CERT_FILE")
    text : String <- bundle_at(r)
    return text

# The trusted roots, parsed once. Parsing the system bundle (128 roots, 333
# KB on macOS) took about 0.4 s of CPU, and it was done for every https
# connection: a page with 30 https subresources paid it 30 times.
#   Unverified  the caller's explicit opt-out
#   Lazy        verify, reading the bundle per connection: a run that may
#               never open one (a local file) does not pay at start
#   Loaded      verify against roots parsed once (a URL fetch, the servers)
#   Pooled      another store's trust, through a pool of open sessions
#               (pool_start: one client's connections, reused)
type Store is Data:
  Unverified{}
  Lazy{}
  Loaded{roots: List<&2, X509.Cert>}
  Pooled{base: Store, inbox: Chan(PAsk)}

def roots_now() -> IO(List<&2, X509.Cert>):
  do IO<List<&2, X509.Cert>>:
    pem : String <- ca_bundle()
    return X509.parse_all(Pem.certificates(pem))

def loaded_of(rs: List<&2, X509.Cert>) -> IO(Store):
  IO.pure(Store, Loaded{rs})

# verify off: Unverified; verify on and `now`: the roots parsed here, once.
def store_of(verify: Bool, now: Bool) -> IO(Store):
  match verify:
    case False{}:
      IO.pure(Store, Unverified{})
    case True{}:
      match now:
        case False{}:
          IO.pure(Store, Lazy{})
        case True{}:
          IO.bind(List<&2, X509.Cert>, Store, roots_now(), loaded_of)

def trust_with(+check: Bool, rs: List<&2, X509.Cert>, +host: String) -> IO(C.Trust):
  do IO<C.Trust>:
    now : Nat <- Wall.Clock.unix()
    return C.Trust{check, rs, host, now}

def trust_for(st: Store, +host: String) -> IO(C.Trust):
  match st:
    case Unverified{}:
      IO.pure(C.Trust, C.Trust{False{}, Nil{}, host, 0n})
    case Lazy{}:
      IO.bind(List<&2, X509.Cert>, C.Trust, roots_now(), rs => trust_with(True{}, rs, host))
    case Loaded{roots}:
      trust_with(True{}, roots, host)
    case Pooled{base, inbox}:
      trust_for(base, host)

def tls_sock(r: Result<&1, &1, U32 & String, Socket>, trust: C.Trust, +host: String, rnd: List<&2, U32>, req: List<&2, U32>, +cap: U32, +keep: Bool) -> IO(Ended):
  match r:
    case Fail{e}:
      IO.pure(Ended, Ended{Fail{e}, None{}})
    case Done{sock}:
      loop(U32.to_nat(4096), Go{sock, C.start(trust, host, rnd, req), Http.fr_start(), 0n}, cap, keep)

# A host that does not resolve or a port that refuses is the request's error,
# never the end of the program.
def tls_ip(r: Result<&1, &1, U32 & String, String>, +port: U32, trust: C.Trust, +host: String, rnd: List<&2, U32>, req: List<&2, U32>, +cap: U32, +keep: Bool) -> IO(Ended):
  match r:
    case Fail{e}:
      IO.pure(Ended, Ended{Fail{e}, None{}})
    case Done{ip}:
      IO.bind(Result<&1, &1, U32 & String, Socket>, Ended, TCP.connect(ip, port), c => tls_sock(c, trust, host, rnd, req, cap, keep))

# A new connection: resolve, connect, handshake, the request.
def fresh(+host: String, +port: U32, req: List<&2, U32>, +cap: U32, st: Store, +keep: Bool) -> IO(Ended):
  do IO<Ended>:
    trust : C.Trust <- trust_for(st, host)
    rnd : List<&2, U32> <- random_bytes(96)
    r : Result<&1, &1, U32 & String, String> <- Sock.Net.resolve(host)
    res : Ended <- tls_ip(r, port, trust, host, rnd, req, cap, keep)
    return res

def result_of(e: Ended) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match e:
    case Ended{res, keep}:
      res

# ---- one connection per host, reused (keep-alive) -----------------------------------------
# A page's sheets and modules come mostly from one or two hosts, and each
# was a connection of its own: a TLS handshake each (x25519, the chain's
# signatures: 0.25-1.2 s of CPU), ~40 on github.com, which is most of the
# 45 s the bench gives a page. A pool (a process: lend, put back, give up)
# holds the open sessions of one client (a CDP connection; never shared
# between clients) by host and port, at most 6 per host as Chrome. A GET
# borrows an idle session or a free slot; with neither, it waits for one.
# A borrowed session that the server closed meanwhile (no byte back, or an
# error) is dropped and the request goes out once more on a new one; only
# GETs are pooled, so sending one twice is safe.

type PAsk is Type:
  PTake{key: String, reply: Chan(Maybe<&1, Sess>)}
  PPut{key: String, s: Sess}
  PGone{key: String}
  PEnd{}

def per_host() -> U32:
  6

def most_idle() -> Nat:
  32n

type Idle is Type:
  Idle{key: String, s: Sess}

type Open is Data:
  Open{key: String, n: U32}

type Waiter is Type:
  Waiter{key: String, reply: Chan(Maybe<&1, Sess>)}

type Eff is Type:
  EReply{reply: Chan(Maybe<&1, Sess>), m: Maybe<&1, Sess>}
  EClose{s: Sess}

# The pool's state, and what to do before the next ask.
type PS is Type:
  PS{idle: List<&1, Idle>, open: List<&2, Open>, waits: List<&1, Waiter>, effs: List<&1, Eff>}
  PStop{idle: List<&1, Idle>, waits: List<&1, Waiter>}

def open_n(os: List<&2, Open>, +key: String) -> U32:
  match os:
    case Nil{}:
      0
    case Con{o, t}:
      match o:
        case Open{+k, +n}:
          Bool.pick(U32, String.eq(k, key), n, open_n(t, key))

def open_add(os: List<&2, Open>, +key: String, +d: U32, +up: Bool) -> List<&2, Open>:
  match os:
    case Nil{}:
      Bool.pick(List<&2, Open>, up, [Open{key, d}], Nil{})
    case Con{o, +t}:
      match o:
        case Open{+k, +n}:
          Bool.pick(List<&2, Open>, String.eq(k, key),
            Open{k, Bool.pick(U32, up, (n + d : U32), Bool.pick(U32, (n > d : U32), (n - d : U32), 0))} <> t,
            Open{k, n} <> open_add(t, key, d, up))

# the first idle session for key, and the others
type TakeI is Type:
  TakeI{m: Maybe<&1, Sess>, rest: List<&1, Idle>}

def took_i(i: Idle, r: TakeI) -> TakeI:
  match r:
    case TakeI{m, rest}:
      TakeI{m, i <> rest}

def idle_back(m: Maybe<&1, Sess>, +k: String, rest: List<&1, Idle>) -> List<&1, Idle>:
  match m:
    case None{}:
      rest
    case Some{x}:
      Idle{k, x} <> rest

# (the tail's answer is computed first and combined here: a match cannot
# look at String.eq, and a helper that recursed back would be mutual)
def idle_pick(hit: Bool, +k: String, s: Sess, r: TakeI) -> TakeI:
  match hit:
    case True{}:
      match r:
        case TakeI{m, rest}:
          TakeI{Some{s}, idle_back(m, k, rest)}
    case False{}:
      took_i(Idle{k, s}, r)

def take_idle(xs: List<&1, Idle>, +key: String) -> TakeI:
  match xs:
    case Nil{}:
      TakeI{None{}, Nil{}}
    case Con{i, t}:
      match i:
        case Idle{+k, s}:
          idle_pick(String.eq(k, key), k, s, take_idle(t, key))

type TakeW is Type:
  TakeW{m: Maybe<&1, Chan(Maybe<&1, Sess>)>, rest: List<&1, Waiter>}

def took_w(w: Waiter, r: TakeW) -> TakeW:
  match r:
    case TakeW{m, rest}:
      TakeW{m, w <> rest}

def wait_back(m: Maybe<&1, Chan(Maybe<&1, Sess>)>, +k: String, rest: List<&1, Waiter>) -> List<&1, Waiter>:
  match m:
    case None{}:
      rest
    case Some{c}:
      Waiter{k, c} <> rest

def wait_pick(hit: Bool, +k: String, c: Chan(Maybe<&1, Sess>), r: TakeW) -> TakeW:
  match hit:
    case True{}:
      match r:
        case TakeW{m, rest}:
          TakeW{Some{c}, wait_back(m, k, rest)}
    case False{}:
      took_w(Waiter{k, c}, r)

def take_wait(xs: List<&1, Waiter>, +key: String) -> TakeW:
  match xs:
    case Nil{}:
      TakeW{None{}, Nil{}}
    case Con{w, t}:
      match w:
        case Waiter{+k, c}:
          wait_pick(String.eq(k, key), k, c, take_wait(t, key))

# a take: an idle session, else a free slot (None: open one), else wait
def on_take_slot(free: Bool, +key: String, reply: Chan(Maybe<&1, Sess>), rest: List<&1, Idle>, +os: List<&2, Open>, ws: List<&1, Waiter>) -> PS:
  match free:
    case True{}:
      PS{rest, open_add(os, key, 1, True{}), ws, [EReply{reply, None{}}]}
    case False{}:
      PS{rest, os, List.append(&1, Waiter, ws, [Waiter{key, reply}]), Nil{}}

def on_take(r: TakeI, +key: String, reply: Chan(Maybe<&1, Sess>), +os: List<&2, Open>, ws: List<&1, Waiter>) -> PS:
  match r:
    case TakeI{m, rest}:
      match m:
        case Some{s}:
          PS{rest, os, ws, [EReply{reply, Some{s}}]}
        case None{}:
          +have = open_n(os, key)
          +most = per_host()
          on_take_slot((have < most : U32), key, reply, rest, os, ws)

def idle_put(full: Bool, +key: String, s: Sess, ids: List<&1, Idle>, +os: List<&2, Open>, ws: List<&1, Waiter>) -> PS:
  match full:
    case True{}:
      PS{ids, open_add(os, key, 1, False{}), ws, [EClose{s}]}
    case False{}:
      PS{Idle{key, s} <> ids, os, ws, Nil{}}

# the idle sessions and how many (a list of sockets is read once)
type Counted is Type:
  Counted{n: Nat, xs: List<&1, Idle>}

def counted_con(i: Idle, c: Counted) -> Counted:
  match c:
    case Counted{n, xs}:
      Counted{Nat.add(n, 1n), i <> xs}

def count_idle(xs: List<&1, Idle>) -> Counted:
  match xs:
    case Nil{}:
      Counted{0n, Nil{}}
    case Con{i, t}:
      counted_con(i, count_idle(t))

def idle_counted(c: Counted, +key: String, s: Sess, +os: List<&2, Open>, ws: List<&1, Waiter>) -> PS:
  match c:
    case Counted{n, xs}:
      idle_put(Nat.is_le(most_idle(), n), key, s, xs, os, ws)

# a put: to the first waiter for its host, else idle (else closed: too many idle)
def on_put(r: TakeW, +key: String, s: Sess, ids: List<&1, Idle>, +os: List<&2, Open>) -> PS:
  match r:
    case TakeW{m, rest}:
      match m:
        case Some{c}:
          PS{ids, os, rest, [EReply{c, Some{s}}]}
        case None{}:
          idle_counted(count_idle(ids), key, s, os, rest)

# a session gone: its slot to the first waiter (who opens one), else free
def on_gone(r: TakeW, +key: String, ids: List<&1, Idle>, +os: List<&2, Open>) -> PS:
  match r:
    case TakeW{m, rest}:
      match m:
        case Some{c}:
          PS{ids, os, rest, [EReply{c, None{}}]}
        case None{}:
          PS{ids, open_add(os, key, 1, False{}), rest, Nil{}}

def pool_next(q: Maybe<&1, PAsk>, ids: List<&1, Idle>, +os: List<&2, Open>, ws: List<&1, Waiter>) -> PS:
  match q:
    case None{}:
      PStop{ids, ws}
    case Some{a}:
      match a:
        case PTake{+key, reply}:
          on_take(take_idle(ids, key), key, reply, os, ws)
        case PPut{+key, s}:
          on_put(take_wait(ws, key), key, s, ids, os)
        case PGone{+key}:
          on_gone(take_wait(ws, key), key, ids, os)
        case PEnd{}:
          PStop{ids, ws}

def close_sess(x: Sess) -> IO(Unit):
  match x:
    case Sess{s, cs}:
      Socket.close(s)

def do_effs(es: List<&1, Eff>) -> IO(Unit):
  match es:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{e, t}:
      match e:
        case EReply{c, m}:
          IO.bind(Result<&1, &1, Maybe<&1, Sess>, Unit>, Unit, Chan.send(Maybe<&1, Sess>, c, m), ok => do_effs(t))
        case EClose{x}:
          IO.bind(Unit, Unit, close_sess(x), u => do_effs(t))

def close_idle(xs: List<&1, Idle>) -> IO(Unit):
  match xs:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{i, t}:
      match i:
        case Idle{k, x}:
          IO.bind(Unit, Unit, close_sess(x), u => close_idle(t))

# the end: idle sessions closed; each waiter told to open its own
def wake_all(xs: List<&1, Waiter>) -> IO(Unit):
  match xs:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{w, t}:
      match w:
        case Waiter{k, c}:
          IO.bind(Result<&1, &1, Maybe<&1, Sess>, Unit>, Unit, Chan.send(Maybe<&1, Sess>, c, None{}), ok => wake_all(t))

def pool_serve(n: Nat, st: PS, +inbox: Chan(PAsk)) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+r:
      match st:
        case PStop{ids, ws}:
          IO.bind(Unit, Unit, close_idle(ids), u => wake_all(ws))
        case PS{ids, +os, ws, es}:
          do IO<Unit>:
            u : Unit <- do_effs(es)
            q : Maybe<&1, PAsk> <- Chan.recv(PAsk, inbox)
            done : Unit <- pool_serve(r, pool_next(q, ids, os, ws), inbox)
            return done

# A pool for one client: the store to pass down (every https GET through it
# shares connections) and the channel to end it with (pool_end).
def pool_start(+inbox: Chan(PAsk)) -> IO(Unit):
  IO.spawn(Unit, pool_serve(4294967295n, PS{Nil{}, Nil{}, Nil{}, Nil{}}, inbox))

def pool_end(+inbox: Chan(PAsk)) -> IO(Unit):
  IO.bind(Result<&1, &1, PAsk, Unit>, Unit, Chan.send(PAsk, inbox, PEnd{}), ok => IO.pure(Unit, Unit{}))

def pooled(+base: Store, +inbox: Chan(PAsk)) -> Store:
  Pooled{base, inbox}

def is_pooled(st: Store) -> Bool:
  match st:
    case Pooled{b, c}:
      True{}
    case _:
      False{}

# ---- a GET through the pool ------------------------------------------------------------------

def unsent(r: Result<&1, &1, PAsk, Unit>) -> IO(Unit):
  match r:
    case Done{u}:
      IO.pure(Unit, Unit{})
    case Fail{a}:
      match a:
        case PPut{k, x}:
          close_sess(x)
        case _:
          IO.pure(Unit, Unit{})

# back to the pool: the session, or the slot it held (a send to a pool that
# ended fails and hands the ask back: the session is closed here)
def give_back(m: Maybe<&1, Sess>, +key: String, +inbox: Chan(PAsk)) -> IO(Unit):
  match m:
    case None{}:
      IO.bind(Result<&1, &1, PAsk, Unit>, Unit, Chan.send(PAsk, inbox, PGone{key}), ok => IO.pure(Unit, Unit{}))
    case Some{x}:
      IO.bind(Result<&1, &1, PAsk, Unit>, Unit, Chan.send(PAsk, inbox, PPut{key, x}), r => unsent(r))

def returned(e: Ended, +key: String, +inbox: Chan(PAsk)) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match e:
    case Ended{res, keep}:
      IO.bind(Unit, Result<&1, &1, U32 & String, List<&2, U32>>, give_back(keep, key, inbox), u => IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, res))

def close_m(m: Maybe<&1, Sess>) -> IO(Unit):
  match m:
    case None{}:
      IO.pure(Unit, Unit{})
    case Some{x}:
      close_sess(x)

def retry_empty(empty: Bool, +bs: List<&2, U32>, keep: Maybe<&1, Sess>, +host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) -> IO(Ended):
  match empty:
    case True{}:
      IO.bind(Unit, Ended, close_m(keep), u => fresh(host, port, req, cap, st, True{}))
    case False{}:
      IO.pure(Ended, Ended{Done{bs}, keep})

# a borrowed session the server had closed meanwhile: an error, or nothing
# came back; the request goes out once more on a new connection
def retry_stale(e: Ended, +host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) -> IO(Ended):
  match e:
    case Ended{res, keep}:
      match res:
        case Fail{x}:
          IO.bind(Unit, Ended, close_m(keep), u => fresh(host, port, req, cap, st, True{}))
        case Done{+bs}:
          retry_empty(List.is_empty(&2, U32, bs), bs, keep, host, port, req, cap, st)

def on_borrowed(x: Sess, +host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) -> IO(Ended):
  match x:
    case Sess{s, cs}:
      IO.bind(Ended, Ended, loop(U32.to_nat(4096), Go{s, C.again(cs, req), Http.fr_start(), 0n}, cap, True{}),
        e => retry_stale(e, host, port, req, cap, st))

def lent(m: Maybe<&1, Maybe<&1, Sess>>, +host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) -> IO(Ended):
  match m:
    case Some{l}:
      match l:
        case Some{x}:
          on_borrowed(x, host, port, req, cap, st)
        case None{}:
          fresh(host, port, req, cap, st, True{})
    case None{}:
      fresh(host, port, req, cap, st, True{})

def asked(ok: Result<&1, &1, PAsk, Unit>, +reply: Chan(Maybe<&1, Sess>), +host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) -> IO(Ended):
  match ok:
    case Fail{a}:
      fresh(host, port, req, cap, st, False{})
    case Done{u}:
      IO.bind(Maybe<&1, Maybe<&1, Sess>>, Ended, Chan.recv(Maybe<&1, Sess>, reply), m => lent(m, host, port, req, cap, st))

def pooled_get(+host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store, +inbox: Chan(PAsk)) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  +key = host ++ ":" ++ U32.show(port)
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    +reply : Chan(Maybe<&1, Sess>) <- Chan.new(Maybe<&1, Sess>, 1)
    ok : Result<&1, &1, PAsk, Unit> <- Chan.send(PAsk, inbox, PTake{key, reply})
    e : Ended <- asked(ok, reply, host, port, req, cap, st)
    res : Result<&1, &1, U32 & String, List<&2, U32>> <- returned(e, key, inbox)
    return res

def own(+host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  IO.bind(Ended, Result<&1, &1, U32 & String, List<&2, U32>>, fresh(host, port, req, cap, st, False{}), e => IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, result_of(e)))

def get_or_own(get: Bool, +host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store, +inbox: Chan(PAsk)) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match get:
    case True{}:
      pooled_get(host, port, req, cap, st, inbox)
    case False{}:
      own(host, port, req, cap, st)

# GET over TLS: returns the raw HTTP response bytes. Through a pool when the
# store has one and the request is a GET; else a connection of its own.
def https_get(+host: String, +port: U32, +req: List<&2, U32>, +cap: U32, st: Store) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match st:
    case Pooled{+base, +inbox}:
      get_or_own(Http.is_get(req), host, port, req, cap, base, inbox)
    case _:
      own(host, port, req, cap, st)
