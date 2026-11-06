# How these packages compare with others on BendHub

Measured on 2026-11-05 on one Apple M3 Pro, Bend 2.0.37 and 2.0.39, native
builds. Both sides of each comparison got the same inputs. Speed figures are
medians of alternating rounds, run while the machine carried other work, so
read them as ratios, not absolute times. Where another package is better, the
table says so: use it.

## Correctness on neutral sets

| Subject | Set | Ours | Others |
|---|---|---|---|
| URL resolution | RFC 3986 §5.4, 42 examples | **42/42** | bend-kit-url 33/42 |
| UTF-8 decoding | 3000 generated sequences vs V8's `TextDecoder` | **0 differences** | — |
| UTF-8 decoding | Kuhn's test file, fuzz and edge cases (635) | 635/635 since the WHATWG decoder (550/635 before) | bend-kit-encoding 635/635 |
| CSS rule splitting | normalize.css, pure-min.css, bootstrap.min.css vs tinycss2 | **exact on all three** | gralha-css-style: an empty declaration in every rule |
| HMAC-SHA256 | Wycheproof | 174/174 | bend-collections 174/174 |
| HKDF-SHA256 | Wycheproof | 83/86 (no refusal of an output past 255 × 32 bytes) | bend-collections 86/86 |
| AES-128-GCM | Wycheproof, 96-bit IVs | 67/67 | bend-collections 67/67 |
| ChaCha20-Poly1305 | Wycheproof | 325/325 | bend-collections 325/325 |
| X25519 | Wycheproof | 518/518, and an all-zero secret refused | bend-collections 518/518 |
| JSON | JSONTestSuite: 95 must accept, 188 must refuse | accepts 95, **refuses only 67** | ezjson and bend-kit-json: 95 and 188 |
| DEFLATE/gzip | 122 streams made by Python's zlib, 11 that must be refused | 109/111, refuses 10/11 | bend-kit-zlib 111/111, 11/11 |
| binary64 arithmetic | 8000 cases vs node | 0 wrong | bend-kit-f64, bend-collections: 0 wrong |

## Speed (ours / theirs; below 1 means ours is faster)

| Operation | Ours vs | Ratio |
|---|---|---|
| 600 X25519 (fe25519, 20 limbs of 13 bits) | bend-collections 1.0.0.0 | **0.005** (0.21 s against 39.8 s) |
| 2048-bit modular exponentiation | bend-kit-bignum | **0.15** (Montgomery) |
| AES-128-GCM, 1 MiB | bend-collections 1.0.0.0 | about 2 |
| ChaCha20-Poly1305, 1 MiB | bend-collections 1.0.0.0 | about 1.15 |
| JSON parse, 1 MB | bend-kit-json | 9.2 (packed bytes) |
| inflate, 1 MB | bend-kit-zlib (pure path) | 6.0 |
| binary64 mul + add, 1M each | bend-kit-f64 / bend-collections | 72 / 85 |
| CSS split, 233 KB | gralha-css-style | 1.7 |

## Where to use something else today

- **Laws for every input on cryptography:** bend-collections. Its SHA-2,
  HMAC/HKDF, Poly1305 and X25519 laws are accepted by the kernel.
- **Strict JSON with laws for every input:** ezjson.
- **Fast JSON, inflate and UTF-8 over packed bytes:** bend-kit.
- **Proved binary64:** bend-collections.

## Guarantees, plainly

Every package here is in phase 1 (`0.1.x.x`). It runs inside Element under
its test suites, and its `LAWS.bend` holds closed equalities from the
standards. None has laws for every input yet; that is phase 2.
