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

## Next (in this repository, not yet on the hub)

- element-crypto: X25519 over a 20-limb record field (`fe25519.bend`),
  about 200x faster than the list version; an all-zero shared secret is
  refused.
- element-tls13: refuses an all-zero X25519 secret (RFC 8446 7.4.2).
- element-css-syntax: backslash escapes inside strings.
