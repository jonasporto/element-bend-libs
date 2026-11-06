# element-html

An HTML parser after the WHATWG algorithm: the full tokenizer, tree construction reduced to what server-rendered pages need, all 2231 named entities, serialization.

```bend
import element-html@0.1.0.0/parse.bend as Parse
```

Import the module you use: `package.bend` only gathers the modules for the
hub, and exposes no names of its own.

Written for Element, a browser engine for agents in Bend 2, and kept free of
anything specific to it.

## Modules

- `dom.bend`
- `entity_table.bend`
- `entities.bend`
- `tokenize.bend`
- `parse.bend`
- `serialize.bend`
- `dump.bend`

## Depends on

- none beyond Base

## Native code

Pure Bend: no `.c` or `.js` files.

## Not modelled yet

Tree construction is the WHATWG algorithm reduced to what server-rendered
pages need: implied html/head/body, void elements, implied end tags. Not yet:
the adoption agency algorithm (misnested formatting tags), foster parenting in
tables, `<template>` contents, foreign content (SVG, MathML).

## Versions

`0.F.A.N`. The first number stays 0. `F` is the phase: 1 runs inside
Element under its test suites, 2 has laws for every input and a differential
oracle in the package, 3 is kernel-checked (`--verdict`) and fuzzed, 4 is a
long stable run. `A` goes up when the API changes. `N` goes up with each
fix, speed gain or new proof.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
