# element-css-syntax

A style sheet split into rules and declarations, as CSS Syntax 3, without interpreting them.

```bend
import element-css-syntax@0.1.0.0/package.bend as Css_syntax
```

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `parse.bend`

## Depends on

- none beyond Base

## Native code

Pure Bend: no `.c` or `.js` files.

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
