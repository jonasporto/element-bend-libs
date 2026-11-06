import Base
import ./parse.bend as CssP

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# character, so content:"\"" is one string and the next rule survives.
law css_escaped_quote_keeps_later_rules:
  {List.length(&2, CssP.Rule, CssP.parse("a{content:\"\\\"\"}b{color:red}c{x:y}")) == 3n : Nat}

law css_escaped_quote_in_media_keeps_later_rules:
  {List.length(&2, CssP.Rule, CssP.parse("@media screen{a{content:'\\''}b{color:red}}c{x:y}")) == 3n : Nat}
