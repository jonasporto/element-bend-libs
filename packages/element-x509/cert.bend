import Base
import element-asn1@0.1.0.0/der.bend as Der
import element-math@0.1.0.0/big.bend as Big
import element-crypto@0.1.0.0/hash.bend as Hash
import element-crypto@0.1.0.0/rsa.bend as Rsa
import element-crypto@0.1.0.0/ecdsa.bend as Ecdsa

# X.509 certificates (RFC 5280) for TLS server authentication: parsing,
# signature checks (RSA PKCS #1 v1.5, ECDSA P-256/P-384 with SHA-2), host
# names (RFC 6125: subjectAltName dNSName with a leftmost "*." wildcard, and
# iPAddress), validity periods, basicConstraints cA, extendedKeyUsage
# serverAuth, and path building from the server's certificates to a trusted
# root. It fails closed: an unknown critical extension (nameConstraints, for
# one, which is not implemented), an unsupported algorithm, or a malformed
# certificate is a verification failure, never a pass.
#
# Not checked: revocation (CRL, OCSP), certificate transparency, root expiry
# (as browsers treat roots as trust anchors, not certificates), keyUsage.

type Cert is Data:
  Cert{
    ok: Bool, tbs: List<&2, U32>, sig_alg: List<&2, U32>, sig: List<&2, U32>,
    issuer: List<&2, U32>, subject: List<&2, U32>, not_before: Nat, not_after: Nat,
    key_alg: List<&2, U32>, curve: List<&2, U32>, key: List<&2, U32>,
    ca: Bool, eku: Bool, crit: Bool, names: List<&2, String>
  }

# ---- object identifiers (DER contents bytes) ---------------------------------------

def oid_rsa() -> List<&2, U32>:
  [42, 134, 72, 134, 247, 13, 1, 1, 1]

def oid_rsa_sha(+n: U32) -> List<&2, U32>:
  [42, 134, 72, 134, 247, 13, 1, 1, n]

def oid_ec() -> List<&2, U32>:
  [42, 134, 72, 206, 61, 2, 1]

def oid_p256() -> List<&2, U32>:
  [42, 134, 72, 206, 61, 3, 1, 7]

def oid_p384() -> List<&2, U32>:
  [43, 129, 4, 0, 34]

def oid_ecdsa_sha(+n: U32) -> List<&2, U32>:
  [42, 134, 72, 206, 61, 4, 3, n]

def oid_ext(+n: U32) -> List<&2, U32>:
  [85, 29, n]

def oid_server_auth() -> List<&2, U32>:
  [43, 6, 1, 5, 5, 7, 3, 1]

def oid_any_eku() -> List<&2, U32>:
  [85, 29, 37, 0]

def same(+a: List<&2, U32>, +b: List<&2, U32>) -> Bool:
  Der.same(a, b)

# ---- extensions ------------------------------------------------------------------

def ext_id(+e: Der.Tlv) -> List<&2, U32>:
  Der.body(Der.kid(e, 0n))

# The extnValue OCTET STRING's contents (itself DER).
def ext_value(+e: Der.Tlv) -> List<&2, U32>:
  Der.body(Der.kid(e, Nat.sub(Der.count(e), 1n)))

def ext_critical(+e: Der.Tlv) -> Bool:
  +b = Der.kid(e, 1n)
  Nat.is_eq(Der.count(e), 3n) && U32.is_eq(Der.tag(b), 1) && Bool.not(U32.is_zero(Der.nth(Der.body(b), 0n)))

def is_ext(+e: Der.Tlv, +n: U32) -> Bool:
  same(ext_id(e), oid_ext(n))

# keyUsage, subjectAltName, basicConstraints, certificatePolicies, extKeyUsage.
def known(+e: Der.Tlv) -> Bool:
  is_ext(e, 15) || is_ext(e, 17) || is_ext(e, 19) || is_ext(e, 32) || is_ext(e, 37)

def any_unknown_critical(es: List<&2, Der.Tlv>) -> Bool:
  match es:
    case Nil{}:
      False{}
    case Con{+e, t}:
      (ext_critical(e) && Bool.not(known(e))) || any_unknown_critical(t)

def ca_value(+v: List<&2, U32>) -> Bool:
  +b = Der.kid(Der.decode(v), 0n)
  U32.is_eq(Der.tag(b), 1) && Bool.not(U32.is_zero(Der.nth(Der.body(b), 0n)))

def is_ca(es: List<&2, Der.Tlv>) -> Bool:
  match es:
    case Nil{}:
      False{}
    case Con{+e, t}:
      (is_ext(e, 19) && ca_value(ext_value(e))) || is_ca(t)

def has_purpose(ps: List<&2, Der.Tlv>) -> Bool:
  match ps:
    case Nil{}:
      False{}
    case Con{+p, t}:
      Der.is_oid(p, oid_server_auth()) || Der.is_oid(p, oid_any_eku()) || has_purpose(t)

# extendedKeyUsage, when present, must allow TLS server authentication.
def eku_ok(es: List<&2, Der.Tlv>) -> Bool:
  match es:
    case Nil{}:
      True{}
    case Con{+e, t}:
      Bool.pick(Bool, is_ext(e, 37), has_purpose(Der.kids(Der.decode(ext_value(e)))), eku_ok(t))

def ascii(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case Con{b, t}:
      SCon{Char.to_lower(Char.from_u32(b)), ascii(t)}

def dotted(+bs: List<&2, U32>) -> String:
  String.join([U32.show(Der.nth(bs, 0n)), U32.show(Der.nth(bs, 1n)), U32.show(Der.nth(bs, 2n)), U32.show(Der.nth(bs, 3n))], ".")

# GeneralNames: dNSName [2] and 4-byte iPAddress [7]; others are skipped.
def general_names(gs: List<&2, Der.Tlv>) -> List<&2, String>:
  match gs:
    case Nil{}:
      Nil{}
    case Con{+g, t}:
      +tag = Der.tag(g)
      +ip = U32.is_eq(tag, 135) && Nat.is_eq(List.length(&2, U32, Der.body(g)), 4n)
      +rest = general_names(t)
      Bool.pick(List<&2, String>, U32.is_eq(tag, 130), ascii(Der.body(g)) <> rest,
        Bool.pick(List<&2, String>, ip, dotted(Der.body(g)) <> rest, rest))

def names_of(es: List<&2, Der.Tlv>) -> List<&2, String>:
  match es:
    case Nil{}:
      Nil{}
    case Con{+e, t}:
      List.append(&2, String, Bool.pick(List<&2, String>, is_ext(e, 17), general_names(Der.kids(Der.decode(ext_value(e)))), Nil{}), names_of(t))

# The [3] EXPLICIT extensions after the six fixed TBS fields.
def find_exts(ts: List<&2, Der.Tlv>) -> List<&2, Der.Tlv>:
  match ts:
    case Nil{}:
      Nil{}
    case Con{+t, rest}:
      Bool.pick(List<&2, Der.Tlv>, U32.is_eq(Der.tag(t), 163), Der.kids(Der.kid(t, 0n)), find_exts(rest))

# ---- parsing ------------------------------------------------------------------------

def drop1(ts: List<&2, Der.Tlv>) -> List<&2, Der.Tlv>:
  match ts:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

def curve_of(+p: Der.Tlv) -> List<&2, U32>:
  Bool.pick(List<&2, U32>, U32.is_eq(Der.tag(p), 6), Der.body(p), Nil{})

def parse(+der: List<&2, U32>) -> Cert:
  +c = Der.decode(der)
  +top = Der.kids(c)
  +tbs = Der.at(top, 0n)
  +tk = Der.kids(tbs)
  +f = Bool.pick(List<&2, Der.Tlv>, U32.is_eq(Der.tag(Der.at(tk, 0n)), 160), drop1(tk), tk)
  +validity = Der.at(f, 3n)
  +spki = Der.at(f, 5n)
  +algid = Der.kid(spki, 0n)
  +es = find_exts(List.drop(&2, Der.Tlv, f, 6n))
  +ok = U32.is_eq(Der.tag(c), 48) && Nat.is_eq(List.length(&2, Der.Tlv, top), 3n) && U32.is_eq(Der.tag(tbs), 48) &&
    Nat.is_ge(List.length(&2, Der.Tlv, f), 6n) && U32.is_eq(Der.tag(Der.at(top, 2n)), 3)
  Cert{
    ok, Der.raw(tbs), Der.body(Der.kid(Der.at(top, 1n), 0n)), Der.bits(Der.at(top, 2n)),
    Der.raw(Der.at(f, 2n)), Der.raw(Der.at(f, 4n)), Der.time(Der.kid(validity, 0n)), Der.time(Der.kid(validity, 1n)),
    Der.body(Der.kid(algid, 0n)), curve_of(Der.kid(algid, 1n)), Der.bits(Der.kid(spki, 1n)),
    is_ca(es), eku_ok(es), any_unknown_critical(es), names_of(es)
  }

# ---- fields ------------------------------------------------------------------------

def ok_of(c: Cert) -> Bool:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      ok

def issuer_of(c: Cert) -> List<&2, U32>:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      issuer

def subject_of(c: Cert) -> List<&2, U32>:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      subject

def names_in(c: Cert) -> List<&2, String>:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      names

# Well formed, in its validity period, and without unknown critical extensions.
def usable(c: Cert, +now: Nat) -> Bool:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      ok && Nat.is_le(nb, now) && Nat.is_le(now, na) && Bool.not(crit)

def is_ca_cert(c: Cert) -> Bool:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      ca

def server_ok(c: Cert) -> Bool:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      eku

# ---- signatures -------------------------------------------------------------------

type Key is Data:
  KRsa{n: List<&2, U32>, e: List<&2, U32>}
  KEc{curve: Ecdsa.Curve, point: List<&2, U32>}
  KNone{}

def ec_key(+curve: List<&2, U32>, +point: List<&2, U32>) -> Key:
  Bool.pick(Key, same(curve, oid_p256()), KEc{Ecdsa.p256(), point},
    Bool.pick(Key, same(curve, oid_p384()), KEc{Ecdsa.p384(), point}, KNone{}))

def rsa_key(+k: Der.Tlv) -> Key:
  KRsa{Der.body(Der.kid(k, 0n)), Der.body(Der.kid(k, 1n))}

def key_pick(rsa: Bool, ec: Bool, +curve: List<&2, U32>, +key: List<&2, U32>) -> Key:
  match rsa:
    case True{}:
      rsa_key(Der.decode(key))
    case False{}:
      match ec:
        case True{}:
          ec_key(curve, key)
        case False{}:
          KNone{}

# The subject public key.
def key_of(c: Cert) -> Key:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, +key_alg, +curve, +key, ca, eku, crit, names}:
      key_pick(same(key_alg, oid_rsa()), same(key_alg, oid_ec()), curve, key)

# A signature by `key` over `msg`: RSA PKCS #1 v1.5 or ECDSA (r, s) in DER.
def check_rsa(k: Key, +h: Hash.Hash, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match k:
    case KRsa{n, e}:
      Rsa.pkcs1_verify(h, n, e, sig, msg)
    case KEc{curve, point}:
      False{}
    case KNone{}:
      False{}

def check_ec(k: Key, +h: Hash.Hash, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match k:
    case KRsa{n, e}:
      False{}
    case KEc{curve, point}:
      +rs = Der.decode(sig)
      Ecdsa.verify_point(curve, h, point, Der.body(Der.kid(rs, 0n)), Der.body(Der.kid(rs, 1n)), msg)
    case KNone{}:
      False{}

type Alg is Data:
  ARsa{h: Hash.Hash}
  AEc{h: Hash.Hash}
  ANone{}

def alg_of(+oid: List<&2, U32>) -> Alg:
  Bool.pick(Alg, same(oid, oid_rsa_sha(11)), ARsa{Hash.HSha256{}},
    Bool.pick(Alg, same(oid, oid_rsa_sha(12)), ARsa{Hash.HSha384{}},
      Bool.pick(Alg, same(oid, oid_rsa_sha(13)), ARsa{Hash.HSha512{}},
        Bool.pick(Alg, same(oid, oid_ecdsa_sha(2)), AEc{Hash.HSha256{}},
          Bool.pick(Alg, same(oid, oid_ecdsa_sha(3)), AEc{Hash.HSha384{}},
            Bool.pick(Alg, same(oid, oid_ecdsa_sha(4)), AEc{Hash.HSha512{}}, ANone{}))))))

def check_alg(a: Alg, +k: Key, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match a:
    case ARsa{h}:
      check_rsa(k, h, sig, msg)
    case AEc{h}:
      check_ec(k, h, sig, msg)
    case ANone{}:
      False{}

# `child` carries a valid signature by `parent`'s key.
def signed_by(+child: Cert, +parent: Cert) -> Bool:
  match child:
    case Cert{ok, +tbs, +sig_alg, +sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      check_alg(alg_of(sig_alg), key_of(parent), sig, tbs)

# ---- host names ----------------------------------------------------------------------

def after_dot(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, +t}:
      Bool.pick(String, Char.is_eq(c, '.'), t, after_dot(t))

# "*.example.com" matches exactly one non-empty leftmost label.
def name_matches(+pat: String, +host: String) -> Bool:
  +wild = String.starts_with(pat, "*.")
  +rest = after_dot(host)
  Bool.pick(Bool, wild,
    String.eq(String.drop(pat, 2n), rest) && Bool.not(String.is_empty(rest)) && Bool.not(String.starts_with(host, ".")),
    String.eq(pat, host))

def any_name(ns: List<&2, String>, +host: String) -> Bool:
  match ns:
    case Nil{}:
      False{}
    case Con{+n, t}:
      name_matches(n, host) || any_name(t, host)

def host_matches(+c: Cert, +host: String) -> Bool:
  any_name(names_in(c), String.to_lower(host))

# ---- path building --------------------------------------------------------------------

def issued(+child: Cert, +parent: Cert) -> Bool:
  same(issuer_of(child), subject_of(parent))

# The candidates whose subject is the child's issuer.
def issuers(xs: List<&2, Cert>, +child: Cert) -> List<&2, Cert>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      +rest = issuers(t, child)
      Bool.pick(List<&2, Cert>, issued(child, x), x <> rest, rest)

# A trusted root signed the child.
def any_signed(rs: List<&2, Cert>, +child: Cert) -> Bool:
  match rs:
    case Nil{}:
      False{}
    case Con{+r, t}:
      signed_by(child, r) || any_signed(t, child)

def trusted(+roots: List<&2, Cert>, +child: Cert) -> Bool:
  any_signed(issuers(roots, child), child)

# The first server-sent CA certificate, usable now, that signed the child.
def first_signed(cs: List<&2, Cert>, +child: Cert, +now: Nat) -> Maybe<&2, Cert>:
  match cs:
    case Nil{}:
      None{}
    case Con{+c, t}:
      Bool.pick(Maybe<&2, Cert>, is_ca_cert(c) && usable(c, now) && signed_by(child, c), Some{c}, first_signed(t, child, now))

def next_up(+pool: List<&2, Cert>, +child: Cert, +now: Nat) -> Maybe<&2, Cert>:
  first_signed(issuers(pool, child), child, now)

# Climb from the leaf: stop at a certificate a root signed, else step to the
# server-sent certificate that signed it. At most `fuel` links.
def walk(fuel: Nat, done: Bool, next: Maybe<&2, Cert>, +pool: List<&2, Cert>, +roots: List<&2, Cert>, +now: Nat) -> String:
  match fuel:
    case 0n:
      "certificate chain too long"
    case 1n+r:
      match done:
        case True{}:
          ""
        case False{}:
          match next:
            case None{}:
              "certificate is not signed by a trusted root"
            case Some{+c}:
              walk(r, trusted(roots, c), next_up(pool, c, now), pool, roots, now)

type Check is Data:
  Check{ok: Bool, msg: String}

def first_error(ps: List<&2, Check>) -> String:
  match ps:
    case Nil{}:
      ""
    case Con{p, t}:
      match p:
        case Check{ok, msg}:
          Bool.pick(String, ok, first_error(t), msg)

def parse_all(ds: List<&2, List<&2, U32>>) -> List<&2, Cert>:
  match ds:
    case Nil{}:
      Nil{}
    case Con{d, t}:
      parse(d) <> parse_all(t)

def or_leaf(m: Maybe<&2, Cert>) -> Cert:
  match m:
    case None{}:
      parse(Nil{})
    case Some{value}:
      value

def first_cert(+cs: List<&2, Cert>) -> Cert:
  or_leaf(List.get(&2, Cert, cs, 0n))

def drop1c(cs: List<&2, Cert>) -> List<&2, Cert>:
  match cs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      t

# Verify the server's certificates (DER, leaf first) for `host` at `now`
# (seconds since 1970) against parsed roots: "" when trusted, else the reason.
def verify_chain(+ders: List<&2, List<&2, U32>>, +roots: List<&2, Cert>, +host: String, +now: Nat) -> String:
  +certs = parse_all(ders)
  +leaf = first_cert(certs)
  +pool = drop1c(certs)
  +path = walk(8n, trusted(roots, leaf), next_up(pool, leaf, now), pool, roots, now)
  first_error([
    Check{Bool.not(List.is_empty(&2, List<&2, U32>, ders)), "no certificate"},
    Check{Bool.not(List.is_empty(&2, Cert, roots)), "no trusted roots (no CA bundle found)"},
    Check{ok_of(leaf), "malformed certificate"},
    Check{usable(leaf, now), "certificate expired, not yet valid, or has an unknown critical extension"},
    Check{host_matches(leaf, host), "certificate is not valid for " ++ host},
    Check{server_ok(leaf), "certificate is not for TLS servers (extendedKeyUsage)"},
    Check{String.is_empty(path), path}
  ])

# ---- TLS 1.3 CertificateVerify ---------------------------------------------------------

def cv_pss(k: Key, +h: Hash.Hash, +sig: List<&2, U32>, +msg: List<&2, U32>) -> Bool:
  match k:
    case KRsa{n, e}:
      Rsa.pss_verify(h, n, e, sig, msg)
    case KEc{curve, point}:
      False{}
    case KNone{}:
      False{}

def cv_label() -> List<&2, U32>:
  [84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121]

# The signed content (RFC 8446 4.4.3): 64 spaces, the context string, 0, and
# the transcript hash.
def cv_msg(+th: List<&2, U32>) -> List<&2, U32>:
  List.concat(&2, U32, [Rsa.fill(64n, 32), cv_label(), [0], th])

def curve_is(+c: Cert, +oid: List<&2, U32>) -> Bool:
  match c:
    case Cert{ok, tbs, sig_alg, sig, issuer, subject, nb, na, key_alg, curve, key, ca, eku, crit, names}:
      same(curve, oid)

type Scheme is Data:
  SEc{h: Hash.Hash, curve: List<&2, U32>}
  SPss{h: Hash.Hash}
  SPkcs{h: Hash.Hash}
  SEcAny{h: Hash.Hash}
  SNone{}

def scheme_of(+code: U32) -> Scheme:
  Bool.pick(Scheme, U32.is_eq(code, 1027), SEc{Hash.HSha256{}, oid_p256()},
    Bool.pick(Scheme, U32.is_eq(code, 1283), SEc{Hash.HSha384{}, oid_p384()},
      Bool.pick(Scheme, U32.is_eq(code, 2052), SPss{Hash.HSha256{}},
        Bool.pick(Scheme, U32.is_eq(code, 2053), SPss{Hash.HSha384{}},
          Bool.pick(Scheme, U32.is_eq(code, 2054), SPss{Hash.HSha512{}}, SNone{})))))

def cv_check(s: Scheme, +leaf: Cert, +sig: List<&2, U32>, +m: List<&2, U32>) -> Bool:
  match s:
    case SEc{h, curve}:
      curve_is(leaf, curve) && check_ec(key_of(leaf), h, sig, m)
    case SPss{h}:
      cv_pss(key_of(leaf), h, sig, m)
    case SPkcs{h}:
      check_rsa(key_of(leaf), h, sig, m)
    case SEcAny{h}:
      check_ec(key_of(leaf), h, sig, m)
    case SNone{}:
      False{}

# The leaf's signature over the handshake transcript hash `th`, by scheme:
# ecdsa_secp256r1_sha256 0x0403, ecdsa_secp384r1_sha384 0x0503,
# rsa_pss_rsae_sha256/384/512 0x0804/5/6.
def certificate_verify(+leaf: Cert, +scheme: U32, +sig: List<&2, U32>, +th: List<&2, U32>) -> Bool:
  cv_check(scheme_of(scheme), leaf, sig, cv_msg(th))

def first_cert_der(ds: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match ds:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      h

# ---- TLS 1.2 ServerKeyExchange ----------------------------------------------------------

# In TLS 1.2 (RFC 5246 7.4.1.4.1, RFC 8422 5.4) a scheme names the hash and
# the signature algorithm only: rsa_pkcs1_sha256/384/512 0x0401/0x0501/0x0601
# are allowed, and an ECDSA code does not bind the curve (the key's own
# curve is used). PSS as in TLS 1.3.
def scheme12_of(+code: U32) -> Scheme:
  Bool.pick(Scheme, U32.is_eq(code, 1025), SPkcs{Hash.HSha256{}},
    Bool.pick(Scheme, U32.is_eq(code, 1281), SPkcs{Hash.HSha384{}},
      Bool.pick(Scheme, U32.is_eq(code, 1537), SPkcs{Hash.HSha512{}},
        Bool.pick(Scheme, U32.is_eq(code, 1027), SEcAny{Hash.HSha256{}},
          Bool.pick(Scheme, U32.is_eq(code, 1283), SEcAny{Hash.HSha384{}},
            scheme_of(code))))))

# The leaf's signature over client_random | server_random | ECDH params.
def ske_verify(+leaf: Cert, +scheme: U32, +sig: List<&2, U32>, +signed: List<&2, U32>) -> Bool:
  cv_check(scheme12_of(scheme), leaf, sig, signed)
