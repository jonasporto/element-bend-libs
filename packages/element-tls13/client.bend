import Base
import ./tls13.bend as T
import ./tls12.bend as T12
import element-crypto@0.1.0.0/x25519.bend as X
import element-crypto@0.1.0.0/ecdh.bend as Ecdh
import element-crypto@0.1.0.0/poly1305.bend as Poly
import element-x509@0.1.0.0/cert.bend as X509

# A TLS 1.3 client, with TLS 1.2 for servers that speak nothing newer, as a
# pure state machine ("sans-IO"): `start` gives the
# first flight, `feed` takes bytes from the network and returns the next
# state, whose `send` holds bytes to write and whose `out` holds decrypted
# application data. lib/tls/io.bend runs it over a socket.
#
# Handshake: ClientHello -> ServerHello (x25519 + ChaCha20-Poly1305 only)
# -> EncryptedExtensions, Certificate, CertificateVerify, Finished (checked)
# -> client Finished + the request. At CertificateVerify the server is
# authenticated (lib/x509): the chain must reach a trusted root and name the
# host, and the signature over the transcript must verify with the leaf key.

# TLS 1.2 (lib/tls/tls12.bend), between ServerHello and application data:
# the suite, the server random, the server's ECDHE key (empty until
# ServerKeyExchange), whether the server echoed extended_master_secret, the
# master secret (empty until ServerHelloDone), whether ChangeCipherSpec came.
type S12 is Data:
  S12{suite: U32, sr: +List<U32>, spub: +List<U32>, ems: Bool, ms: +List<U32>, ccs: Bool}

# PHs12: the server's plaintext flight (Certificate, ServerKeyExchange,
# ServerHelloDone). PFin12: ours is sent, its ChangeCipherSpec and Finished
# are awaited. PApp12: application data under TLS 1.2 records.
type Phase is Data:
  PAwait{}
  PHs{}
  PApp{}
  PClosed{}
  PFailed{msg: String}
  PHs12{s: S12}
  PFin12{s: S12}
  PApp12{}

# Traffic keys in use: read (server) and write (client), with sequence numbers.
type Keys is Data:
  Keys{rkey: +List<U32>, riv: +List<U32>, rseq: U32, wkey: +List<U32>, wiv: +List<U32>, wseq: U32}

# The handshake secret and the two handshake traffic secrets (from CH..SH).
type Sec is Data:
  Sec{hs: +List<U32>, shs: +List<U32>, chs: +List<U32>}

# How to authenticate the server: `check` on, the chain must reach one of
# `roots` for `host` at `now` (seconds since 1970) and CertificateVerify must
# verify with the leaf key; `check` off (an explicit opt-out), the connection
# is encrypted but unauthenticated.
type Trust is Data:
  Trust{check: Bool, roots: List<&2, X509.Cert>, host: String, now: Nat}

type Cs is Data:
  Cs{
    phase: Phase, priv: +List<U32>, tr: +List<U32>, buf: +List<U32>, hsbuf: +List<U32>,
    hs: Sec, keys: Keys, req: +List<U32>, out: +List<List<&2, U32>>, send: +List<U32>,
    certs: +List<U32>, trust: Trust, outn: U32
  }

def no_keys() -> Keys:
  Keys{Nil{}, Nil{}, 0, Nil{}, Nil{}, 0}

# n: the suite's key length (T.key_len), which also selects its AEAD.
def keys_for(+read_secret: List<&2, U32>, +write_secret: List<&2, U32>, +wseq: U32, +n: U32) -> Keys:
  Keys{T.traffic_key(read_secret, n), T.traffic_iv(read_secret), 0, T.traffic_key(write_secret, n), T.traffic_iv(write_secret), wseq}

def key_len_of(k: Keys) -> U32:
  match k:
    case Keys{rkey, riv, rseq, wkey, wiv, wseq}:
      T.len(wkey)

# rnd: 96 random bytes (32 random, 32 session id, 32 x25519 private key).
def start(+trust: Trust, +host: String, +rnd: List<&2, U32>, +req: List<&2, U32>) -> Cs:
  +priv = T.slice(rnd, 64, 32)
  +ch = T.client_hello(host, T.slice(rnd, 0, 32), T.slice(rnd, 32, 32), X.public_key(priv))
  Cs{PAwait{}, priv, ch, Nil{}, Nil{}, Sec{Nil{}, Nil{}, Nil{}}, no_keys(), req, Nil{}, T.record(22, ch), Nil{}, trust, 0}

def fail(+msg: String) -> Phase:
  PFailed{msg}

# ---- field updates -------------------------------------------------------------------

def with_send(st: Cs, +more: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, List.append(&2, U32, send, more), certs, trust, outn}

def clear_send(st: Cs) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, Nil{}, certs, trust, outn}

def with_phase(st: Cs, +p: Phase) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{p, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}

def with_buf(st: Cs, +b: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, b, hsbuf, hs, keys, req, out, send, certs, trust, outn}

def add_buf(st: Cs, +more: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, List.append(&2, U32, buf, more), hsbuf, hs, keys, req, out, send, certs, trust, outn}

def bump_rseq(k: Keys) -> Keys:
  match k:
    case Keys{rkey, riv, rseq, wkey, wiv, wseq}:
      Keys{rkey, riv, (rseq + 1 : U32), wkey, wiv, wseq}

# ---- accessors ------------------------------------------------------------------------

def phase_of(st: Cs) -> Phase:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      phase

def send_of(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      send

# Application data received so far (chunks are kept newest first).
def out_of(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      List.concat(&2, U32, List.reverse(&2, List<&2, U32>, out))

# Another request on a session whose last response was whole (keep-alive,
# lib/tls/io.bend's pool): sealed as `finish` sealed the first, with the
# write key at its next sequence number (TLS 1.3 or 1.2 records); the
# plaintext read so far is dropped, the next response starts empty.
def seal_app(p: Phase, +k: List<&2, U32>, +iv: List<&2, U32>, +seq: U32, +req: List<&2, U32>) -> List<&2, U32>:
  match p:
    case PApp12{}:
      T12.protect(k, iv, seq, 23, req)
    case _:
      T.protect(k, iv, seq, 23, req)

def again(st: Cs, +req: List<&2, U32>) -> Cs:
  match st:
    case Cs{+phase, priv, tr, buf, hsbuf, hs, keys, r0, out, send, certs, trust, outn}:
      match keys:
        case Keys{rkey, riv, rseq, +wkey, +wiv, +wseq}:
          Cs{phase, priv, tr, buf, hsbuf, hs, Keys{rkey, riv, rseq, wkey, wiv, (wseq + 1 : U32)}, req, Nil{},
             List.append(&2, U32, send, seal_app(phase, wkey, wiv, wseq, req)), certs, trust, 0}

# the plaintext as received, newest record first (add_out prepends)
def out_chunks(st: Cs) -> List<&2, List<&2, U32>>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      out

def out_len(st: Cs) -> U32:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      outn

def buf_of(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      buf

# ---- ServerHello --------------------------------------------------------------------

def on_sh_keys(st: Cs, +sh: List<&2, U32>, +secret: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, +priv, +tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      +tr2 = List.append(&2, U32, tr, sh)
      +hsec = T.handshake_secret(secret)
      +shs = T.derive_secret(hsec, "s hs traffic", tr2)
      +chs = T.derive_secret(hsec, "c hs traffic", tr2)
      Cs{PHs{}, priv, tr2, buf, Nil{}, Sec{hsec, shs, chs}, keys_for(shs, chs, 0, T.key_len(T.sh_cipher(sh))), req, out, send, certs, trust, outn}

# RFC 8446 §7.4.2: an all-zero X25519 secret aborts the handshake.
def on_sh_shared(m: Maybe<&2, List<&2, U32>>, st: Cs, +sh: List<&2, U32>) -> Cs:
  match m:
    case None{}:
      with_phase(st, fail("illegal_parameter: the server's key share gives an all-zero X25519 secret"))
    case Some{+secret}:
      on_sh_keys(st, sh, secret)

def on_sh_ok(st: Cs, +sh: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, +priv, +tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      on_sh_shared(X.shared(priv, T.sh_key_share(sh)), Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}, sh)

def on_sh_check(ok: Bool, st: Cs, +sh: List<&2, U32>, +why: String) -> Cs:
  match ok:
    case True{}:
      on_sh_ok(st, sh)
    case False{}:
      with_phase(st, fail(why))

def sh_problem(+sh: List<&2, U32>) -> String:
  Bool.pick(String, Bool.not(U32.is_eq(T.msg_type(sh), 2)), "expected ServerHello",
    Bool.pick(String, T.is_hrr(sh), "server sent HelloRetryRequest (only x25519 is offered)",
      Bool.pick(String, Bool.not(U32.is_eq(T.sh_version(sh), 772)), "server did not choose TLS 1.3",
        Bool.pick(String, Bool.not(T.is_suite(T.sh_cipher(sh))), "server chose a cipher suite Element did not offer", ""))))

def first_msg(m: T.Msgs) -> List<&2, U32>:
  match m:
    case T.Msgs{msgs, rest}:
      match msgs:
        case Nil{}:
          Nil{}
        case Con{h, t}:
          h

def has_msg(m: T.Msgs) -> Bool:
  match m:
    case T.Msgs{msgs, rest}:
      match msgs:
        case Nil{}:
          False{}
        case Con{h, t}:
          True{}

# ---- encrypted handshake --------------------------------------------------------------

def verify_ok(+got: List<&2, U32>, +want: List<&2, U32>) -> Bool:
  Poly.eq_bytes(got, want)

# Server Finished verified: derive application secrets, send the client
# Finished (after a compatibility ChangeCipherSpec) and the request.
def finish(st: Cs, +m: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, +tr, buf, hsbuf, sec, keys, +req, out, send, certs, trust, outn}:
      match sec:
        case Sec{+hs, +shs, +chs}:
          +tr2 = List.append(&2, U32, tr, m)
          +ms = T.master_secret(hs)
          +cap = T.derive_secret(ms, "c ap traffic", tr2)
          +n = key_len_of(keys)
          Cs{PApp{}, priv, tr2, buf, Nil{}, Sec{hs, shs, chs},
             keys_for(T.derive_secret(ms, "s ap traffic", tr2), cap, 1, n),
             req, out,
             List.concat(&2, U32, [
               send,
               T.record(20, [1]),
               T.protect(T.traffic_key(chs, n), T.traffic_iv(chs), 0, 22, T.handshake(20, T.verify_data(chs, tr2))),
               T.protect(T.traffic_key(cap, n), T.traffic_iv(cap), 0, 23, req)
             ]),
             certs, trust, outn}

def on_finished(ok: Bool, st: Cs, +m: List<&2, U32>) -> Cs:
  match ok:
    case True{}:
      finish(st, m)
    case False{}:
      with_phase(st, fail("server Finished does not verify"))

def append_tr(st: Cs, +m: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, List.append(&2, U32, tr, m), buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}

def keep_cert(st: Cs, +m: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, List.append(&2, U32, tr, m), buf, hsbuf, hs, keys, req, out, send, m, trust, outn}

def trust_of(st: Cs) -> Trust:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      trust

def tr_of(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      tr

def certs_of(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      certs

# Certificate (4.4.2): context<0..255>, then entries of cert_data<1..2^24-1>
# and extensions<0..2^16-1>. The DER certificates, leaf first.
def entries(fuel: Nat, +bs: List<&2, U32>) -> List<&2, List<&2, U32>>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+r:
      +n = T.get24(bs, 0n)
      +e = T.get16(bs, U32.to_nat((3 + n : U32)))
      +rest = List.drop(&2, U32, bs, U32.to_nat((5 + n + e : U32)))
      Bool.pick(List<&2, List<&2, U32>>, (T.len(bs) < 3 : U32), Nil{}, T.slice(bs, 3, n) <> entries(r, rest))

def cert_ders(+m: List<&2, U32>) -> List<&2, List<&2, U32>>:
  +ctx = T.nth(m, 4n)
  +list = T.slice(m, (8 + ctx : U32), T.get24(m, U32.to_nat((5 + ctx : U32))))
  entries(16n, list)

def first_der(ds: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match ds:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      h

def verify_problem(+t: Trust, +st: Cs, +m: List<&2, U32>) -> String:
  match t:
    case Trust{check, +roots, +host, +now}:
      +ders = cert_ders(certs_of(st))
      +chain = X509.verify_chain(ders, roots, host, now)
      +sig = T.slice(m, 8, T.get16(m, 6n))
      Bool.pick(String, Bool.not(String.is_empty(chain)), "certificate: " ++ chain,
        Bool.pick(String, X509.certificate_verify(X509.parse(first_der(ders)), T.get16(m, 4n), sig, T.hash(tr_of(st))), "",
          "CertificateVerify signature does not verify (scheme " ++ U32.show(T.get16(m, 4n)) ++ ")"))

def on_problem(+why: String, +st: Cs, +m: List<&2, U32>) -> Cs:
  Bool.pick(Cs, String.is_empty(why), append_tr(st, m), with_phase(st, fail(why)))

# CertificateVerify (4.4.3): authenticate the server, unless the caller opted out.
def on_verify(t: Trust, +st: Cs, +m: List<&2, U32>) -> Cs:
  match t:
    case Trust{check, roots, host, now}:
      match check:
        case False{}:
          append_tr(st, m)
        case True{}:
          on_problem(verify_problem(Trust{True{}, roots, host, now}, st, m), st, m)

def expected_fin(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, sec, keys, req, out, send, certs, trust, outn}:
      match sec:
        case Sec{hs, shs, chs}:
          T.verify_data(shs, tr)

def still_hs(p: Phase) -> Bool:
  match p:
    case PHs{}:
      True{}
    case _:
      False{}

type MK is Data:
  KSkip{}
  KAppend{}
  KCert{}
  KVerify{}
  KFin{}
  KBad{typ: U32}

def kind_of(+typ: U32, +hs: Bool) -> MK:
  Bool.pick(MK, Bool.not(hs), KSkip{},
    Bool.pick(MK, U32.is_eq(typ, 8), KAppend{},
      Bool.pick(MK, U32.is_eq(typ, 15), KVerify{},
      Bool.pick(MK, U32.is_eq(typ, 11), KCert{},
        Bool.pick(MK, U32.is_eq(typ, 20), KFin{}, KBad{typ})))))

# One handshake message in the Hs phase (a match: only its branch computes).
def on_msg(k: MK, +st: Cs, +m: List<&2, U32>) -> Cs:
  match k:
    case KSkip{}:
      st
    case KAppend{}:
      append_tr(st, m)
    case KCert{}:
      keep_cert(st, m)
    case KVerify{}:
      on_verify(trust_of(st), st, m)
    case KFin{}:
      on_finished(verify_ok(T.slice(m, 4, 32), expected_fin(st)), st, m)
    case KBad{typ}:
      with_phase(st, fail("unexpected handshake message " ++ U32.show(typ)))

def on_msgs(msgs: List<&2, List<&2, U32>>, +st: Cs) -> Cs:
  match msgs:
    case Nil{}:
      st
    case Con{+m, t}:
      on_msgs(t, on_msg(kind_of(T.msg_type(m), still_hs(phase_of(st))), st, m))

def with_hsbuf(st: Cs, +b: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, buf, b, hs, keys, req, out, send, certs, trust, outn}

def hsbuf_of(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      hsbuf

def msgs_of(m: T.Msgs) -> List<&2, List<&2, U32>>:
  match m:
    case T.Msgs{msgs, rest}:
      msgs

def rest_of(m: T.Msgs) -> List<&2, U32>:
  match m:
    case T.Msgs{msgs, rest}:
      rest

# Decrypted handshake bytes: append, split into whole messages, handle them.
def on_hs_bytes(+st: Cs, +content: List<&2, U32>) -> Cs:
  +m = T.split_msgs(64n, List.append(&2, U32, hsbuf_of(st), content), Nil{})
  on_msgs(msgs_of(m), with_hsbuf(st, rest_of(m)))

# ---- records ------------------------------------------------------------------------

def keys_of(st: Cs) -> Keys:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      keys

def with_keys(st: Cs, +k: Keys) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, buf, hsbuf, hs, k, req, out, send, certs, trust, outn}

def add_out(st: Cs, +more: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, more <> out, send, certs, trust, (outn + U32.from_nat(List.length(&2, U32, more)) : U32)}

def open_record(+k: Keys, +hdr: List<&2, U32>, +body: List<&2, U32>) -> Maybe<&2, T.Inner>:
  match k:
    case Keys{+rkey, +riv, +rseq, wkey, wiv, wseq}:
      T.unprotect(rkey, riv, rseq, hdr, body)

def alert_text(+content: List<&2, U32>) -> String:
  "TLS alert " ++ U32.show(T.nth(content, 1n))

type IK is Data:
  IAlert{}
  IData{}
  IHs{}
  IOther{}

def inner_kind(+typ: U32, +app: Bool) -> IK:
  Bool.pick(IK, U32.is_eq(typ, 21), IAlert{},
    Bool.pick(IK, U32.is_eq(typ, 23) && app, IData{},
      Bool.pick(IK, U32.is_eq(typ, 22) && Bool.not(app), IHs{}, IOther{})))

def on_inner_k(k: IK, +st: Cs, +content: List<&2, U32>) -> Cs:
  match k:
    case IAlert{}:
      with_phase(st, Bool.pick(Phase, U32.is_zero(T.nth(content, 1n)), PClosed{}, fail(alert_text(content))))
    case IData{}:
      add_out(st, content)
    case IHs{}:
      on_hs_bytes(st, content)
    case IOther{}:
      st

# A decrypted record: an alert, application data, or handshake bytes. A match
# on the kind, so only the right branch runs.
def on_inner(+app: Bool, st: Cs, i: T.Inner) -> Cs:
  match i:
    case T.Inner{+typ, +content}:
      on_inner_k(inner_kind(typ, app), st, content)

def on_opened(+app: Bool, m: Maybe<&2, T.Inner>, +st: Cs) -> Cs:
  match m:
    case None{}:
      with_phase(st, fail("bad record MAC"))
    case Some{value}:
      on_inner(app, with_keys(st, bump_rseq(keys_of(st))), value)

def rec_encrypted(enc: Bool, +app: Bool, +st: Cs, +hdr: List<&2, U32>, +body: List<&2, U32>) -> Cs:
  match enc:
    case False{}:
      st
    case True{}:
      on_opened(app, open_record(keys_of(st), hdr, body), st)

# ---- TLS 1.2 -----------------------------------------------------------------------------

def s12_of(p: Phase) -> S12:
  match p:
    case PHs12{s}:
      s
    case PFin12{s}:
      s
    case _:
      S12{0, Nil{}, Nil{}, False{}, Nil{}, False{}}

def s12_spub(s: S12, +pub: List<&2, U32>) -> S12:
  match s:
    case S12{suite, sr, spub, ems, ms, ccs}:
      S12{suite, sr, pub, ems, ms, ccs}

def s12_ccs_on(s: S12) -> S12:
  match s:
    case S12{suite, sr, spub, ems, ms, ccs}:
      S12{suite, sr, spub, ems, ms, True{}}

def sr_of(s: S12) -> List<&2, U32>:
  match s:
    case S12{suite, sr, spub, ems, ms, ccs}:
      sr

def ms_of(s: S12) -> List<&2, U32>:
  match s:
    case S12{suite, sr, spub, ems, ms, ccs}:
      ms

def ccs_of(s: S12) -> Bool:
  match s:
    case S12{suite, sr, spub, ems, ms, ccs}:
      ccs

def has_key_of(s: S12) -> Bool:
  match s:
    case S12{suite, sr, spub, ems, ms, ccs}:
      Bool.not(List.is_empty(&2, U32, spub))

def with_s12_spub(st: Cs, +pub: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{PHs12{s12_spub(s12_of(phase), pub)}, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}

# ServerKeyExchange: the curve must be x25519 (a 32-byte key) or secp256r1
# (a 65-byte uncompressed point); with `check` on, the chain must verify and
# the leaf must have signed client_random | server_random | params.
def ske_problem(+t: Trust, +st: Cs, +m: List<&2, U32>) -> String:
  match t:
    case Trust{check, +roots, +host, +now}:
      +ders = T12.cert_ders(certs_of(st))
      +chain = X509.verify_chain(ders, roots, host, now)
      +signed = T12.ske_signed(T.slice(tr_of(st), 6, 32), sr_of(s12_of(phase_of(st))), m)
      Bool.pick(String, Bool.not(T12.ske_group_ok(m)), "ServerKeyExchange is neither x25519 nor P-256 (the groups Element offers for TLS 1.2)",
        Bool.pick(String, Bool.not(check), "",
          Bool.pick(String, Bool.not(String.is_empty(chain)), "certificate: " ++ chain,
            Bool.pick(String, X509.ske_verify(X509.parse(first_der(ders)), T12.ske_scheme(m), T12.ske_sig(m), signed), "",
              "ServerKeyExchange signature does not verify (scheme " ++ U32.show(T12.ske_scheme(m)) ++ ")"))))

def ske_then(ok: Bool, +why: String, +st: Cs, +m: List<&2, U32>) -> Cs:
  match ok:
    case True{}:
      append_tr(with_s12_spub(st, T12.ske_public(m)), m)
    case False{}:
      with_phase(st, fail(why))

def on_ske_problem(+why: String, +st: Cs, +m: List<&2, U32>) -> Cs:
  ske_then(String.is_empty(why), why, st, m)

# The key exchange follows the server's key, as the AEAD follows the key
# length: a 65-byte point is P-256 (lib/crypto/ecdh.bend), 32 bytes x25519.
# The P-256 scalar is derived from the same 32 secret bytes under a label.
def pms_of(p256: Bool, +priv: List<&2, U32>, +spub: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match p256:
    case True{}:
      Ecdh.shared(priv, spub)
    case False{}:
      X.shared(priv, spub)

def ecdhe_pub(p256: Bool, +priv: List<&2, U32>) -> List<&2, U32>:
  match p256:
    case True{}:
      Ecdh.public_key(priv)
    case False{}:
      X.public_key(priv)

def flight_go(m: Maybe<&2, List<&2, U32>>, +pub: List<&2, U32>, +suite: U32, +sr: List<&2, U32>, +spub: List<&2, U32>, +ems: Bool, +priv: List<&2, U32>, +tr: List<&2, U32>, buf: List<&2, U32>, hsbuf: List<&2, U32>, hs: Sec, req: List<&2, U32>, out: List<&2, List<&2, U32>>, +send: List<&2, U32>, certs: List<&2, U32>, trust: Trust, outn: U32, +shd: List<&2, U32>) -> Cs:
  match m:
    case None{}:
      Cs{PFailed{"the server's P-256 key is not a point on the curve"}, priv, tr, buf, hsbuf, hs, no_keys(), req, out, send, certs, trust, outn}
    case Some{+pms}:
      +cr = T.slice(tr, 6, 32)
      +cke = T12.client_key_exchange(pub)
      +tr2 = T.cat([tr, shd, cke])
      +ms2 = T12.master_secret(ems, pms, cr, sr, tr2)
      +kb = T12.key_block(ms2, cr, sr, suite)
      +ckey = T12.client_key(kb, suite)
      +civ = T12.client_iv(kb, suite)
      +fin = T.handshake(20, T12.verify_data(ms2, "client finished", tr2))
      Cs{PFin12{S12{suite, sr, spub, ems, ms2, False{}}}, priv, List.append(&2, U32, tr2, fin), buf, hsbuf, hs,
         Keys{T12.server_key(kb, suite), T12.server_iv(kb, suite), 0, ckey, civ, 1},
         req, out,
         T.cat([send, T.record(22, cke), T.record(20, [1]), T12.protect(ckey, civ, 0, 22, fin)]),
         certs, trust, outn}

def flight_with(s: S12, +priv: List<&2, U32>, +tr: List<&2, U32>, buf: List<&2, U32>, hsbuf: List<&2, U32>, hs: Sec, req: List<&2, U32>, out: List<&2, List<&2, U32>>, +send: List<&2, U32>, certs: List<&2, U32>, trust: Trust, outn: U32, +shd: List<&2, U32>) -> Cs:
  match s:
    case S12{+suite, +sr, +spub, +ems, ms, ccs}:
      +p256 = U32.is_eq(T.len(spub), 65)
      flight_go(pms_of(p256, priv, spub), ecdhe_pub(p256, priv), suite, sr, spub, ems, priv, tr, buf, hsbuf, hs, req, out, send, certs, trust, outn, shd)

# ServerHelloDone: answer with ClientKeyExchange, ChangeCipherSpec and an
# encrypted Finished (seq 0); the request waits for the server's Finished.
# ServerHelloDone enters the transcript here, once (the session hash of the
# extended master secret covers it, then ClientKeyExchange).
def client_flight(st: Cs, +shd: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, +priv, +tr, buf, hsbuf, hs, keys, req, out, +send, certs, trust, outn}:
      flight_with(s12_of(phase), priv, tr, buf, hsbuf, hs, req, out, send, certs, trust, outn, shd)

def on_done12(has_key: Bool, +st: Cs, +m: List<&2, U32>) -> Cs:
  match has_key:
    case True{}:
      client_flight(st, m)
    case False{}:
      with_phase(st, fail("ServerHelloDone before ServerKeyExchange"))

def s12_has_key(p: Phase) -> Bool:
  has_key_of(s12_of(p))

type MK12 is Data:
  K12Skip{}
  K12Cert{}
  K12Ske{}
  K12Done{}
  K12Append{}
  K12Bad{typ: U32}

def in_hs12(p: Phase) -> Bool:
  match p:
    case PHs12{s}:
      True{}
    case _:
      False{}

def kind12_of(+typ: U32, +hs: Bool) -> MK12:
  Bool.pick(MK12, Bool.not(hs), K12Skip{},
    Bool.pick(MK12, U32.is_eq(typ, 11), K12Cert{},
      Bool.pick(MK12, U32.is_eq(typ, 12), K12Ske{},
        Bool.pick(MK12, U32.is_eq(typ, 14), K12Done{},
          Bool.pick(MK12, U32.is_eq(typ, 22), K12Append{}, K12Bad{typ})))))

def on_msg12(k: MK12, +st: Cs, +m: List<&2, U32>) -> Cs:
  match k:
    case K12Skip{}:
      st
    case K12Cert{}:
      keep_cert(st, m)
    case K12Ske{}:
      on_ske_problem(ske_problem(trust_of(st), st, m), st, m)
    case K12Done{}:
      on_done12(s12_has_key(phase_of(st)), st, m)
    case K12Append{}:
      append_tr(st, m)
    case K12Bad{+typ}:
      with_phase(st, fail(Bool.pick(String, U32.is_eq(typ, 13), "the server asks for a client certificate (Element has none)", "unexpected TLS 1.2 handshake message " ++ U32.show(typ))))

def on_msgs12(msgs: List<&2, List<&2, U32>>, +st: Cs) -> Cs:
  match msgs:
    case Nil{}:
      st
    case Con{+m, t}:
      on_msgs12(t, on_msg12(kind12_of(T.msg_type(m), in_hs12(phase_of(st))), st, m))

def on_hs12_bytes(+st: Cs, +content: List<&2, U32>) -> Cs:
  +m = T.split_msgs(64n, List.append(&2, U32, hsbuf_of(st), content), Nil{})
  on_msgs12(msgs_of(m), with_hsbuf(st, rest_of(m)))

def open12_record(+k: Keys, +typ: U32, +body: List<&2, U32>) -> Maybe<&2, T.Inner>:
  match k:
    case Keys{+rkey, +riv, +rseq, wkey, wiv, wseq}:
      T12.unprotect(rkey, riv, rseq, typ, body)

# The server's Finished verified: send the request (write seq 1).
def app12(st: Cs) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, +req, out, +send, certs, trust, outn}:
      match keys:
        case Keys{rkey, riv, rseq, +wkey, +wiv, +wseq}:
          Cs{PApp12{}, priv, tr, buf, hsbuf, hs, Keys{rkey, riv, rseq, wkey, wiv, (wseq + 1 : U32)}, req, out,
             List.append(&2, U32, send, T12.protect(wkey, wiv, wseq, 23, req)), certs, trust, outn}

def expected12(st: Cs) -> List<&2, U32>:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      T12.verify_data(ms_of(s12_of(phase)), "server finished", tr)

def fin12_check(ok: Bool, +st: Cs) -> Cs:
  match ok:
    case True{}:
      app12(st)
    case False{}:
      with_phase(st, fail("server Finished does not verify"))

def on_fin12(m: Maybe<&2, T.Inner>, +st: Cs) -> Cs:
  match m:
    case None{}:
      with_phase(st, fail("bad record MAC"))
    case Some{value}:
      match value:
        case T.Inner{typ, +content}:
          +st2 = with_keys(st, bump_rseq(keys_of(st)))
          fin12_check(U32.is_eq(T.msg_type(content), 20) && verify_ok(T.slice(content, 4, 12), expected12(st2)), st2)

def ccs_seen(st: Cs) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      Cs{PFin12{s12_ccs_on(s12_of(phase))}, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}

# What a record means to TLS 1.2, by phase and type; a match then runs only
# the branch it names (decryption is never computed for nothing).
type R12 is Data:
  RHs{}
  RCcs{}
  RFin{}
  RSealed{}
  RAlert{}
  RSkip{}

def r12_hs(+typ: U32) -> R12:
  Bool.pick(R12, U32.is_eq(typ, 22), RHs{}, Bool.pick(R12, U32.is_eq(typ, 21), RAlert{}, RSkip{}))

def r12_fin(+typ: U32, +ccs: Bool) -> R12:
  Bool.pick(R12, U32.is_eq(typ, 20), RCcs{},
    Bool.pick(R12, U32.is_eq(typ, 22) && ccs, RFin{},
      Bool.pick(R12, U32.is_eq(typ, 21) && ccs, RSealed{},
        Bool.pick(R12, U32.is_eq(typ, 21), RAlert{}, RSkip{}))))

def r12_app(+typ: U32) -> R12:
  Bool.pick(R12, U32.is_eq(typ, 23) || U32.is_eq(typ, 21), RSealed{}, RSkip{})

def on_r12(k: R12, +st: Cs, +typ: U32, +body: List<&2, U32>) -> Cs:
  match k:
    case RHs{}:
      on_hs12_bytes(st, body)
    case RCcs{}:
      ccs_seen(st)
    case RFin{}:
      on_fin12(open12_record(keys_of(st), typ, body), st)
    case RSealed{}:
      on_opened(True{}, open12_record(keys_of(st), typ, body), st)
    case RAlert{}:
      with_phase(st, fail(alert_text(body)))
    case RSkip{}:
      st

# ---- ServerHello ---------------------------------------------------------------------

# A TLS 1.2 answer: no supported_versions, legacy_version 0x0303.
def is_tls12(+sh: List<&2, U32>) -> Bool:
  U32.is_eq(T.msg_type(sh), 2) && U32.is_zero(T.sh_version(sh)) && U32.is_eq(T.sh_legacy(sh), 771)

def sh12_problem(+sh: List<&2, U32>) -> String:
  Bool.pick(String, T12.downgraded(T.sh_random(sh)), "TLS 1.2 ServerHello carries the TLS 1.3 downgrade sentinel (RFC 8446 4.1.3)",
    Bool.pick(String, Bool.not(T12.is_suite(T.sh_cipher(sh))), "server chose a TLS 1.2 cipher suite Element did not offer", ""))

# After a TLS 1.2 ServerHello the same bytes often carry the next messages.
def on_sh12_ok(st: Cs, +sh: List<&2, U32>, +rest: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      on_hs12_bytes(
        Cs{PHs12{S12{T.sh_cipher(sh), T.sh_random(sh), Nil{}, T.sh_ems(sh), Nil{}, False{}}}, priv, List.append(&2, U32, tr, sh), buf, Nil{}, hs, keys, req, out, send, certs, trust, outn},
        rest)

def on_sh12_check(ok: Bool, st: Cs, +sh: List<&2, U32>, +rest: List<&2, U32>, +why: String) -> Cs:
  match ok:
    case True{}:
      on_sh12_ok(st, sh, rest)
    case False{}:
      with_phase(st, fail(why))

def on_sh(v12: Bool, st: Cs, +sh: List<&2, U32>, +all: List<&2, U32>) -> Cs:
  match v12:
    case True{}:
      on_sh12_check(String.eq(sh12_problem(sh), ""), st, sh, List.drop(&2, U32, all, List.length(&2, U32, sh)), sh12_problem(sh))
    case False{}:
      on_sh_check(String.eq(sh_problem(sh), ""), st, sh, sh_problem(sh))

# A plaintext handshake record while waiting for ServerHello.
def sh_ready(ready: Bool, st: Cs, +m: T.Msgs, +all: List<&2, U32>) -> Cs:
  match ready:
    case False{}:
      st
    case True{}:
      on_sh(is_tls12(first_msg(m)), st, first_msg(m), all)

def on_plain_hs(st: Cs, +body: List<&2, U32>) -> Cs:
  match st:
    case Cs{phase, priv, tr, buf, +hsbuf, hs, keys, req, out, send, certs, trust, outn}:
      +all = List.append(&2, U32, hsbuf, body)
      +m = T.split_msgs(16n, all, Nil{})
      sh_ready(has_msg(m), Cs{phase, priv, tr, buf, all, hs, keys, req, out, send, certs, trust, outn}, m, all)

# A whole record, dispatched on the phase (a match: one branch computes).
def on_record(p: Phase, +st: Cs, +typ: U32, +hdr: List<&2, U32>, +body: List<&2, U32>) -> Cs:
  match p:
    case PAwait{}:
      Bool.pick(Cs, U32.is_eq(typ, 21), with_phase(st, fail(alert_text(body) ++ " before ServerHello: the server refused Element's hello (TLS 1.3 or 1.2; x25519, or P-256 for 1.2; AES-128-GCM or ChaCha20-Poly1305)")),
        Bool.pick(Cs, U32.is_eq(typ, 22), on_plain_hs(st, body), st))
    case PHs{}:
      rec_encrypted(U32.is_eq(typ, 23), False{}, st, hdr, body)
    case PApp{}:
      rec_encrypted(U32.is_eq(typ, 23), True{}, st, hdr, body)
    case PHs12{s}:
      on_r12(r12_hs(typ), st, typ, body)
    case PFin12{s}:
      on_r12(r12_fin(typ, ccs_of(s)), st, typ, body)
    case PApp12{}:
      on_r12(r12_app(typ), st, typ, body)
    case PClosed{}:
      st
    case PFailed{msg}:
      st

def rec_len(+buf: List<&2, U32>) -> U32:
  (5 + T.get16(buf, 3n) : U32)

def whole_record(+buf: List<&2, U32>) -> Bool:
  (T.len(buf) >= 5 : U32) && (T.len(buf) >= rec_len(buf) : U32)

def live(p: Phase) -> Bool:
  match p:
    case PClosed{}:
      False{}
    case PFailed{msg}:
      False{}
    case _:
      True{}

def step_record(go: Bool, +st: Cs) -> Cs:
  match go:
    case False{}:
      st
    case True{}:
      on_record(
        phase_of(st),
        with_buf(st, List.drop(&2, U32, buf_of(st), U32.to_nat(rec_len(buf_of(st))))),
        T.nth(buf_of(st), 0n),
        T.slice(buf_of(st), 0, 5),
        T.slice(buf_of(st), 5, (rec_len(buf_of(st)) - 5 : U32))
      )

# Process every whole record in the buffer, stopping as soon as none is left
# (`go` is computed by the caller: a match cannot scrutinize a computed value).
def pump(fuel: Nat, go: Bool, +st: Cs) -> Cs:
  match fuel:
    case 0n:
      st
    case 1n+k:
      match go:
        case False{}:
          st
        case True{}:
          +st2 = step_record(True{}, st)
          pump(k, whole_record(buf_of(st2)) && live(phase_of(st2)), st2)

def feed(+st: Cs, +bytes: List<&2, U32>) -> Cs:
  +st2 = add_buf(st, bytes)
  pump(U32.to_nat(((T.len(buf_of(st2)) / 5) + 1 : U32)), whole_record(buf_of(st2)) && live(phase_of(st2)), st2)

def failed_msg(p: Phase) -> String:
  match p:
    case PFailed{msg}:
      msg
    case _:
      SNil{}
