# element-http

HTTP/1.1 client over TCP and TLS: requests, chunked bodies, gzip, redirects, cookies, DNS.

```bend
import element-http@0.1.0.0/fetch.bend as Fetch
```

Import the module you use: `package.bend` only gathers the modules for the
hub, and exposes no names of its own.

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `sock.bend`
- `http.bend`
- `cookie.bend`
- `session.bend`
- `websocket.bend`
- `io.bend`
- `fetch.bend`

## Depends on

- `element-asn1@0.1.0.0`
- `element-compress@0.1.0.1`
- `element-crypto@0.1.0.0`
- `element-hostio@0.1.0.0`
- `element-rfc3986@0.1.0.1`
- `element-text@0.1.0.0`
- `element-tls13@0.1.0.0`
- `element-x509@0.1.0.0`

## Native code

This package carries native code: `effs/net_resolve.c`, `effs/net_resolve.js`. It is host IO only (DNS, the clock, binary output), with a C and a JS twin each; no parsing or cryptography is native.

## Known issues

- Not audited. HTTPS here rests on `element-tls13` and `element-x509`, and
  carries their known issues.

## Laws

`LAWS.bend` holds 14 laws over this package, closed equalities from the
standards it follows; `bend PROOF.bend` in this directory checks them. They
ship with the package and are imported only by `package.bend`, so importing a
module does not check them again. Laws for every input are the next phase (F = 2).

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE`; `NOTICE` is in the source repository.
