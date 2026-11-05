import Base
import ./dom.bend as Dom
import ./parse.bend as Parse

# A DOM tree in the tree-construction test format of html5lib-tests (now in
# web-platform-tests, html/syntax/parsing): one node per line, "| " then two
# spaces per depth; elements as <tag>, their attributes sorted by name one
# level deeper as name="value", text as "text" with adjacent text merged.
# A <template>'s children are listed under "content", as the format writes
# its contents fragment. Comments are <!-- data -->. The #document header
# and doctype nodes are not produced (the DOM does not model them).

def indent(d: Nat) -> String:
  match d:
    case 0n:
      ""
    case 1n+r:
      "  " ++ indent(r)

def name_of(a: Dom.Attr) -> String:
  match a:
    case Dom.Attr{name, value}:
      name

def insert(+a: Dom.Attr, xs: List<&2, Dom.Attr>) -> List<&2, Dom.Attr>:
  match xs:
    case Nil{}:
      [a]
    case Con{+x, +t}:
      Bool.pick(List<&2, Dom.Attr>, String.is_lt(name_of(a), name_of(x)), a <> Con{x, t}, x <> insert(a, t))

def sorted(xs: List<&2, Dom.Attr>) -> List<&2, Dom.Attr>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{a, t}:
      insert(a, sorted(t))

def attr_lines(xs: List<&2, Dom.Attr>, +d: Nat) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{a, t}:
      match a:
        case Dom.Attr{name, value}:
          "| " ++ indent(d) ++ name ++ "=\"" ++ value ++ "\"\n" ++ attr_lines(t, d)

def flush(+pend: String, +d: Nat) -> String:
  Bool.pick(String, String.is_empty(pend), "", "| " ++ indent(d) ++ "\"" ++ pend ++ "\"\n")

# `pend` is text read so far and not yet written (adjacent text merges).
def nodes(xs: List<&2, Dom.Node>, +d: Nat, +pend: String) -> String:
  match xs:
    case Nil{}:
      flush(pend, d)
    case Con{h, t}:
      match h:
        case Dom.TextNode{content, tnid}:
          nodes(t, d, pend ++ content)
        case Dom.Element{+tag, +attrs, children}:
          +tpl = String.eq(tag, "template")
          # a comment is one line, <!-- data --> (it has no children)
          flush(pend, d) ++ "| " ++ indent(d) ++ Bool.pick(String, Dom.is_comment(tag), "<!-- " ++ Dom.attr(Dom.Element{tag, attrs, Nil{}}, "data") ++ " -->\n",
            "<" ++ tag ++ ">\n" ++
            attr_lines(sorted(attrs), 1n+d) ++
            Bool.pick(String, tpl, "| " ++ indent(1n+d) ++ "content\n", "") ++
            nodes(children, Bool.pick(Nat, tpl, 2n+d, 1n+d), "")) ++ nodes(t, d, "")

def tree(+root: Dom.Node) -> String:
  nodes([root], 0n, "")

# The test-format tree of a parsed document.
def document(+html: String) -> String:
  tree(Parse.parse(html))
