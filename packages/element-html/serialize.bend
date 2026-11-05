import Base
import ./dom.bend as Dom

# A DOM tree back to HTML (the HTML fragment serialization algorithm,
# simplified): void elements get no end tag, <script>/<style> text is written
# raw, other text escapes & < >, attribute values escape & and ".
# Parsing the result gives the same tree for trees the parser built.

def is_void(+t: String) -> Bool:
  String.eq(t, "area") || String.eq(t, "base") || String.eq(t, "br") || String.eq(t, "col") || String.eq(t, "embed") ||
    String.eq(t, "hr") || String.eq(t, "img") || String.eq(t, "input") || String.eq(t, "link") || String.eq(t, "meta") ||
    String.eq(t, "source") || String.eq(t, "track") || String.eq(t, "wbr")

def is_raw(+t: String) -> Bool:
  String.eq(t, "script") || String.eq(t, "style")

def esc_go(s: String, +attr: Bool) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, t}:
      +rest = esc_go(t, attr)
      Bool.pick(String, Char.is_eq(c, '&'), "&amp;" ++ rest,
        Bool.pick(String, attr && Char.is_eq(c, '"'), "&quot;" ++ rest,
          Bool.pick(String, Bool.not(attr) && Char.is_eq(c, '<'), "&lt;" ++ rest,
            Bool.pick(String, Bool.not(attr) && Char.is_eq(c, '>'), "&gt;" ++ rest, SCon{c, rest}))))

def attrs_html(xs: List<&2, Dom.Attr>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{a, t}:
      match a:
        case Dom.Attr{n, v}:
          " " ++ n ++ "=\"" ++ esc_go(v, True{}) ++ "\"" ++ attrs_html(t)

# `raw`: the text belongs to <script> or <style>.
def nodes(xs: List<&2, Dom.Node>, +raw: Bool) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{h, t}:
      match h:
        case Dom.TextNode{+content, tnid}:
          Bool.pick(String, raw, content, esc_go(content, False{})) ++ nodes(t, raw)
        case Dom.Element{+tag, +attrs, +children}:
          # a comment is serialized as one (HTML 13.3: "<!--" data "-->"); it
          # has no children, so the other branch costs nothing
          Bool.pick(String, Dom.is_comment(tag), "<!--" ++ Dom.attr(Dom.Element{tag, attrs, Nil{}}, "data") ++ "-->",
            Bool.pick(String, Dom.is_shadow(tag), "",
              # a template's content serializes in its place (HTML 13.3)
              Bool.pick(String, Dom.is_content(tag), nodes(children, False{}), "<" ++ tag ++ attrs_html(attrs) ++ ">" ++
                Bool.pick(String, is_void(tag), "", nodes(children, is_raw(tag)) ++ "</" ++ tag ++ ">")))) ++ nodes(t, raw)

def to_html(+root: Dom.Node) -> String:
  nodes([root], False{})
