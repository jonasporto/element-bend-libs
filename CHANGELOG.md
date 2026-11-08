# Changelog

One line per published version. A version on BendHub never changes; a fix
is a new version.

## 2026-11-05

- element-ints 0.1.0.0, element-asn1 0.1.0.0: first versions.
- element-text 0.1.0.0: first version; its UTF-8 decoder is WHATWG's
  (overlong forms, surrogates and code points past U+10FFFF become U+FFFD).
- element-compress 0.1.0.0, then 0.1.0.1 (comments only: CRC-32 and Adler-32
  live in `checksum.bend`).
- element-image 0.1.0.0, then 0.1.0.1 (imports element-compress 0.1.0.1).

## 2026-11-06

- element-math 0.1.0.0, element-hostio 0.1.0.0, element-rfc3986 0.1.0.0:
  first versions.
- element-html 0.1.0.0: first version; a newline right after the start tag of
  `<pre>`, `<listing>` or `<textarea>` is not text (HTML Standard 13.2.6.4.7).
- element-css-syntax 0.1.0.0: first version, with backslash escapes inside
  strings.
- element-rfc3986 0.1.0.1, element-css-syntax 0.1.0.1: `package.bend` imports
  `PROOF.bend`, so the laws reach the hub; the code is unchanged.

## 2026-11-07

- element-crypto 0.1.0.0: SHA-1/2, HMAC, HKDF, AES-128-GCM, ChaCha20-Poly1305,
  X25519 on a 20-limb field, P-256 and P-384 on generated Montgomery fields,
  ECDSA in strict DER, RSA verification; its laws ship with it. Not audited.
- element-x509 0.1.0.0, element-tls13 0.1.0.0, element-http 0.1.0.0: first
  versions; each README states what it does not check. Not audited.

## Next (in this repository, not yet on the hub)

- element-crypto: X25519 over a 20-limb record field (`fe25519.bend`),
  about 200x faster than the list version; an all-zero shared secret is
  refused. P-256 and P-384 on generated Montgomery fields (13-bit limbs in
  `U32` records); ECDSA signatures in strict DER (the old parser accepted 34
  invalid Wycheproof signatures per curve).
- element-tls13: refuses an all-zero X25519 secret (RFC 8446 7.4.2).
- element-x509, element-http: their READMEs state what they do not check.
- element-crypto, element-x509, element-http: `package.bend` imports
  `PROOF.bend`, so the laws reach the hub.
