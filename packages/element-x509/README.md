# element-x509

X.509 certificates: PEM, parsing, host names, validity, path building to a root.

```bend
import element-x509@0.1.0.0/cert.bend as Cert
```

Import the module you use: `package.bend` only gathers the modules for the
hub, and exposes no names of its own.

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `pem.bend`
- `cert.bend`

## Depends on

- `element-asn1@0.1.0.0`
- `element-crypto@0.1.0.0`
- `element-math@0.1.0.0`
- `element-text@0.1.0.0`

## Native code

Pure Bend: no `.c` or `.js` files.

## Known issues

- Not audited.
- Not checked: revocation (CRL, OCSP), certificate transparency, root expiry,
  keyUsage.
- `nameConstraints` is not read: when critical it fails closed, like any
  unknown critical extension; when not critical it is ignored.

## Laws

`LAWS.bend` holds 1 laws over this package, closed equalities from the
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
