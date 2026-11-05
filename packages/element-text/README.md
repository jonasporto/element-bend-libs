# element-text

UTF-8 decoding with U+FFFD recovery, Latin-1, charset sniffing, base64, JSON.

```bend
import element-text@0.1.0.0/package.bend as Text
```

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `utf8.bend`
- `base64.bend`
- `json.bend`

## Depends on

- none beyond Base

## Native code

Pure Bend: no `.c` or `.js` files.

## Known issues

- `base64` is tolerant (for PEM): it refuses nothing, and `=` does not reset
  the bit buffer.
- `json` accepts some invalid text (`[1,]`, `01`). For strict RFC 8259 with
  laws for every input, see `ezjson`.

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
