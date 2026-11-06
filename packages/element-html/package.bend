# An HTML parser after the WHATWG algorithm: the full tokenizer, tree construction reduced to what server-rendered pages need, all 2231 named entities, serialization. Apache-2.0. Source: https://github.com/jonasporto/element-bend-libs/tree/main/packages/element-html
import Base
import ./dom.bend as Dom
import ./entity_table.bend as Entity_table
import ./entities.bend as Entities
import ./tokenize.bend as Tokenize
import ./parse.bend as Parse
import ./serialize.bend as Serialize
import ./dump.bend as Dump
