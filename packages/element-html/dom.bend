import Base

# A DOM tree: elements with attributes and children, and text nodes.

type Attr is Data:
  Attr{name: String, value: String}

type Node is Data:
  Element{tag: String, attrs: +List<Attr>, children: +List<Node>}
  # (TextNode, not Text: Bend 2.0.38 gave Base's Event a constructor Text, and
  # constructor names are one namespace with Base)
  TextNode{content: String, id: U32}

def tag_of(n: Node) -> String:
  match n:
    case Element{tag, attrs, children}:
      tag
    case TextNode{content, tnid}:
      SNil{}

def attrs_of(n: Node) -> List<&2, Attr>:
  match n:
    case Element{tag, attrs, children}:
      attrs
    case TextNode{content, tnid}:
      Nil{}

def children_of(n: Node) -> List<&2, Node>:
  match n:
    case Element{tag, attrs, children}:
      children
    case TextNode{content, tnid}:
      Nil{}

# A comment is kept as an element with this tag, its text in a "data"
# attribute; it is not an element to anything that asks for elements, its
# text is not text content, and nothing renders it.
def comment_tag() -> String:
  "#comment"

def is_comment(+tag: String) -> Bool:
  String.eq(tag, "#comment")

def only_elements(xs: List<&2, Node>) -> List<&2, Node>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      match h:
        case Element{+tag, attrs, children}:
          +rest = only_elements(t)
          Bool.pick(List<&2, Node>, is_comment(tag), rest, Element{tag, attrs, children} <> rest)
        case TextNode{content, tnid}:
          only_elements(t)

def element_children(n: Node) -> List<&2, Node>:
  only_elements(children_of(n))

def attr_go(xs: List<&2, Attr>, +name: String, acc: String) -> String:
  match xs:
    case Nil{}:
      acc
    case Con{a, t}:
      match a:
        case Attr{+n, v}:
          attr_go(t, name, Bool.pick(String, String.eq(n, name), v, acc))

# The value of attribute `name` (the first one wins in HTML), or "".
def attr(n: Node, +name: String) -> String:
  match n:
    case Element{tag, attrs, children}:
      attr_go(List.reverse(&2, Attr, attrs), name, SNil{})
    case TextNode{content, tnid}:
      SNil{}

# A shadow root is kept as a child of its host with this tag; the host's
# textContent, serialization and queries do not see into it.
def is_shadow(+tag: String) -> Bool:
  String.eq(tag, "#shadow-root")

# A <template>'s content (HTML 4.12.3: a DocumentFragment, not its
# children) is kept as one child of the template with this tag: the
# template's childNodes, textContent and queries do not see into it, no
# script in it runs and no style in it applies; serializing the template
# writes it (its innerHTML is its content's).
def is_content(+tag: String) -> Bool:
  String.eq(tag, "#content")

# A child that is a fragment of its own (a shadow root or a template's
# content): not in the parent's child list, a root for what is under it.
def is_root_child(+tag: String) -> Bool:
  is_shadow(tag) || is_content(tag)

# All text under a node, in document order.
def text_list(xs: List<&2, Node>) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      match h:
        case Element{+tag, attrs, children}:
          Bool.pick(String, is_root_child(tag) || is_comment(tag), "", text_list(children)) ++ text_list(t)
        case TextNode{content, tnid}:
          content ++ text_list(t)

# The text of a node's subtree (a shadow tree under it is not its text; a
# shadow root's own text is).
def text_of(n: Node) -> String:
  match n:
    case Element{tag, attrs, children}:
      text_list(children)
    case TextNode{content, tnid}:
      content

def first_of(a: Maybe<&2, Node>, b: Maybe<&2, Node>, c: Maybe<&2, Node>) -> Maybe<&2, Node>:
  match a:
    case Some{value}:
      Some{value}
    case None{}:
      match b:
        case Some{value}:
          Some{value}
        case None{}:
          c

# First element with this tag, depth-first (document order).
def find_go(xs: List<&2, Node>, +name: String) -> Maybe<&2, Node>:
  match xs:
    case Nil{}:
      None{}
    case Con{h, t}:
      match h:
        case Element{+tag, +attrs, +children}:
          first_of(
            Bool.pick(Maybe<&2, Node>, String.eq(tag, name) && Bool.not(is_comment(tag)), Some{Element{tag, attrs, children}}, None{}),
            find_go(children, name),
            find_go(t, name))
        case TextNode{content, tnid}:
          find_go(t, name)

def find(n: Node, +name: String) -> Maybe<&2, Node>:
  find_go([n], name)

# Every <template>'s children moved into its content (a "#content" child),
# as the HTML parser does (13.2.6.4.4: a template's contents go to its
# template contents). A template whose only child is its content already
# is left as it is.
def has_content(xs: List<&2, Node>) -> Bool:
  match xs:
    case Con{h, t}:
      match h:
        case Element{+tag, attrs, children}:
          is_content(tag) && List.is_empty(&2, Node, t)
        case TextNode{c, i}:
          False{}
    case Nil{}:
      False{}

def contents(xs: List<&2, Node>) -> List<&2, Node>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      match h:
        case TextNode{+c, +i}:
          TextNode{c, i} <> contents(t)
        case Element{+tag, +attrs, +children}:
          +wrap = String.eq(tag, "template") && Bool.not(has_content(children))
          +kids = contents(children)
          Element{tag, attrs, Bool.pick(List<&2, Node>, wrap, [Element{"#content", Nil{}, kids}], kids)} <> contents(t)

# The nodes without template contents (what loads, runs and styles).
def no_contents(xs: List<&2, Node>) -> List<&2, Node>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      match h:
        case TextNode{+c, +i}:
          TextNode{c, i} <> no_contents(t)
        case Element{+tag, +attrs, children}:
          +rest = no_contents(t)
          Bool.pick(List<&2, Node>, is_content(tag), rest, Element{tag, attrs, no_contents(children)} <> rest)
