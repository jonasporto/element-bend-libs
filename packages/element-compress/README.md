# element-compress

DEFLATE inflate (RFC 1951), zlib and gzip framing, CRC-32 and Adler-32.

```bend
import element-compress@0.1.0.1/gzip.bend as Gzip
```

Import the module you use: `package.bend` only gathers the modules for the
hub, and exposes no names of its own.

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `checksum.bend`
- `inflate.bend`
- `gzip.bend`

## Depends on

- none beyond Base

## Native code

Pure Bend: no `.c` or `.js` files.

## Known issues

- gzip reads only the first member, and accepts trailing bytes.

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
