# Element libraries for Bend

Libraries for [Bend 2](https://github.com/bendlang/bend), written while
building Element, a browser engine for AI agents, and kept free of anything
specific to it. Each directory under `packages/` is one BendHub package.

| Package | What it does | Native code |
|---|---|---|
| `element-html` | HTML parser as the HTML Standard: tokenizer, tree construction, entities, serialization | none |
| `element-css-syntax` | A style sheet split into rules and declarations (CSS Syntax 3) | none |
| `element-rfc3986` | URLs as RFC 3986: parse, resolve, remove dot segments | none |
| `element-tls13` | TLS 1.3 client (and TLS 1.2), a pure state machine | none |
| `element-x509` | X.509: PEM, parsing, host names, validity, path building | none |
| `element-asn1` | DER reading (X.690) | none |
| `element-crypto` | SHA-1/2, HMAC/HKDF, AES-128-GCM, ChaCha20-Poly1305, X25519, P-256, RSA verification | none |
| `element-math` | Big naturals (Montgomery), binary64 in software, correctly rounded elementary functions | none |
| `element-ints` | Signed 32-bit helpers on `U32` | none |
| `element-text` | UTF-8 (WHATWG decoder), Latin-1, charset sniffing, base64, JSON | none |
| `element-compress` | DEFLATE inflate, zlib and gzip framing, CRC-32, Adler-32 | none |
| `element-image` | PNG encoder for 8-bit RGB | none |
| `element-hostio` | Host effects Base lacks: arguments, binary output, wall clock, loopback listener | C and JS, host IO only |
| `element-http` | HTTP/1.1 client over TCP and TLS: chunked, gzip, redirects, cookies, DNS | C and JS, DNS only |

```bend
import element-html@0.1.0.0/package.bend as Html
```

## How they are checked

Every package runs inside Element and is held by its test suites: the HTML
parser against html5lib-tests, the URL parser against all 42 examples of
RFC 3986 §5.4, TLS against live servers and RFC 8448's trace, the crypto
against RFC and NIST vectors, binary64 against V8. Before the first publish
they were also compared, once, with the hub's other packages on neutral
sets: Wycheproof for HMAC, AES-GCM, ChaCha20-Poly1305 and X25519 (every
case passed), 3000 UTF-8 sequences against V8's `TextDecoder` (no
difference), JSONTestSuite, a zlib corpus and tinycss2. Each package README lists what is known
to be weaker, and better packages on the hub where they exist.

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside Element
under its test suites (every package today), 2 has laws for every input and a
differential oracle in the package, 3 is kernel-checked (`--verdict`) and
fuzzed, 4 is a long stable run. `A` goes up when the API changes. `N` goes
up with each fix, speed gain or new proof. A version never moves: an import
by name and version, or by hash, always gets the same files.

## Licence

Apache-2.0. See `LICENSE`. Each package carries its own copy.

## Security

See `SECURITY.md`. A publish on BendHub is permanent; a fix ships as a new
version.
