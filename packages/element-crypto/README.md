# element-crypto

SHA-1/2, HMAC, HKDF, AES-128-GCM, ChaCha20-Poly1305, X25519, P-256 ECDH, ECDSA and RSA verification.

```bend
import element-crypto@0.1.0.0/hash.bend as Hash
```

Import the module you use: `package.bend` only gathers the modules for the
hub, and exposes no names of its own.

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `sha256.bend`
- `sha512.bend`
- `sha1.bend`
- `hash.bend`
- `hmac.bend`
- `aes_sbox.bend`
- `aes.bend`
- `chacha20.bend`
- `poly1305.bend`
- `gcm.bend`
- `x25519.bend`
- `ecdsa.bend`
- `ecdh.bend`
- `rsa.bend`
- `suite_ours.bend`
- `suite.bend`

## Depends on

- `element-math@0.1.0.0`

## Native code

Pure Bend: no `.c` or `.js` files.

## Known issues

- Not audited, and not written for constant time (the AES S-box is a
  decision tree; tag comparison stops early).
- HKDF does not refuse an output longer than 255 × 32 bytes.
- AES is AES-128 only, and encryption only.
- For laws that hold for every input, and much faster code, see
  `bend-collections` (src/crypto).

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
