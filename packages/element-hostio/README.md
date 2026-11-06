# element-hostio

Host effects Base lacks: arguments, binary output, the wall clock, a loopback listener.

```bend
import element-hostio@0.1.0.0/args.bend as Args
```

Import the module you use: `package.bend` only gathers the modules for the
hub, and exposes no names of its own.

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `args.bend`
- `bytes.bend`
- `clock.bend`
- `listen.bend`

## Depends on

- none beyond Base

## Native code

This package carries native code: `effs/bytes_write.c`, `effs/bytes_write.js`, `effs/clock_unix.c`, `effs/clock_unix.js`. It is host IO only (DNS, the clock, binary output), with a C and a JS twin each; no parsing or cryptography is native.

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
