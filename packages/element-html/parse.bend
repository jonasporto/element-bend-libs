import Base
import ./dom.bend as Dom
import ./tokenize.bend as Tk

# HTML tree construction, after the WHATWG algorithm (HTML section 13.2.6),
# reduced to what server-rendered pages need. Every input parses: there is no
# "malformed HTML" error, only repairs, as in browsers.
#
# - html, head and body are implied. Head elements (meta, link, title, style,
#   script, base, noscript, template) before any body content go to <head>.
# - Void elements (br, img, input, meta, link, hr, ...) never take children.
# - Implied end tags: a block start closes an open <p>; <li> closes an open
#   <li> (up to its list); <dt>/<dd> close each other; a heading closes an
#   open heading; <option> closes <option>; <tr> closes <tr>; <td>/<th>
#   close a cell; <a> closes an open <a>.
# - An end tag closes the matching open element and everything above it; an
#   end tag with no match is ignored. At the end, everything open closes.
# Not modelled yet: the adoption agency algorithm (misnested formatting
# tags), foster parenting in tables, <template> contents, foreign content.

type Frame is Data:
  Frame{tag: String, attrs: +List<Dom.Attr>, kids: +List<Dom.Node>, head: Bool}

# stack: open elements, top first; the body frame is always at the bottom.
# cm: where a comment goes (13.2.6: the insertion mode's "comment token"):
# 0 before head, 4 after head and 3 after body: the document or <html>,
# which this DOM does not keep, so it is dropped; 1 in head: into head (or
# the open head element); 2 in body: the open element.
type B is Data:
  B{stack: +List<Frame>, head: +List<Dom.Node>, body_attrs: +List<Dom.Attr>, in_body: Bool, html_attrs: +List<Dom.Attr>, cm: U32}

def is_one_of(+s: String, xs: List<&2, String>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{h, t}:
      String.eq(s, h) || is_one_of(s, t)

def void_tags() -> List<&2, String>:
  ["area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img", "input", "keygen", "link", "meta", "param", "source", "track", "wbr"]

def head_tags() -> List<&2, String>:
  ["base", "link", "meta", "style", "script", "title", "noscript", "template"]

def closes_p() -> List<&2, String>:
  ["address", "article", "aside", "blockquote", "center", "details", "dialog", "dir", "div", "dl", "fieldset",
   "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr",
   "main", "menu", "nav", "ol", "p", "pre", "section", "summary", "table", "ul", "li", "dd", "dt"]

def headings() -> List<&2, String>:
  ["h1", "h2", "h3", "h4", "h5", "h6"]

# Scope boundaries: an open element below one of these is out of reach.
def scope_tags() -> List<&2, String>:
  ["button", "table", "td", "th", "caption", "marquee", "object", "applet", "template", "html", "body"]

def is_ws_text(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+h, t}:
      Char.is_space(h) && is_ws_text(t)

# ---- frames ------------------------------------------------------------------------

def frame_tag(f: Frame) -> String:
  match f:
    case Frame{tag, attrs, kids, head}:
      tag

def top_tag(xs: List<&2, Frame>) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{f, t}:
      frame_tag(f)

def add_kid(f: Frame, +n: Dom.Node) -> Frame:
  match f:
    case Frame{tag, attrs, kids, head}:
      Frame{tag, attrs, n <> kids, head}

def append_node(xs: List<&2, Frame>, +n: Dom.Node) -> List<&2, Frame>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{f, t}:
      add_kid(f, n) <> t

def node_of(f: Frame) -> Dom.Node:
  match f:
    case Frame{tag, attrs, kids, head}:
      Dom.Element{tag, attrs, List.reverse(&2, Dom.Node, kids)}

def frame_head(f: Frame) -> Bool:
  match f:
    case Frame{tag, attrs, kids, head}:
      head

# Close the top frame: its element joins the frame below it, or <head> if it
# was opened there. The body frame (last) is never closed here.
def pop1(b: B) -> B:
  match b:
    case B{stack, +head, +body_attrs, +in_body, +html_attrs, +cm}:
      match stack:
        case Nil{}:
          B{Nil{}, head, body_attrs, in_body, html_attrs, cm}
        case Con{+f, rest}:
          match rest:
            case Nil{}:
              B{[f], head, body_attrs, in_body, html_attrs, cm}
            case Con{+g, +gs}:
              Bool.pick(B, frame_head(f),
                B{Con{g, gs}, node_of(f) <> head, body_attrs, in_body, html_attrs, cm},
                B{append_node(Con{g, gs}, node_of(f)), head, body_attrs, in_body, html_attrs, cm})

def stack_of(b: B) -> List<&2, Frame>:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      stack

# Is `name` open, above any scope boundary in `stop`?
def open_in(xs: List<&2, Frame>, +name: String, +stop: List<&2, String>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{f, t}:
      match f:
        case Frame{+tag, attrs, kids, head}:
          String.eq(tag, name) || (Bool.not(is_one_of(tag, stop)) && open_in(t, name, stop))

# Pop frames until one named `name` has been popped (the caller checked it is
# open). `top` says whether the top frame is `name`.
def close_go(fuel: Nat, +b: B, +name: String, top: Bool) -> B:
  match fuel:
    case 0n:
      b
    case 1n+k:
      match top:
        case True{}:
          pop1(b)
        case False{}:
          close_go(k, pop1(b), name, String.eq(top_tag(stack_of(pop1(b))), name))

def close_to(+b: B, +name: String) -> B:
  close_go(List.length(&2, Frame, stack_of(b)), b, name, String.eq(top_tag(stack_of(b)), name))

def close_if(open: Bool, +b: B, +name: String) -> B:
  match open:
    case True{}:
      close_to(b, name)
    case False{}:
      b

def close_if_open(+b: B, +name: String, +stop: List<&2, String>) -> B:
  close_if(open_in(stack_of(b), name, stop), b, name)

# ---- start tags ---------------------------------------------------------------------

def implied_closes(+b: B, +name: String) -> B:
  +b1 = Bool.pick(B, is_one_of(name, closes_p()), close_if_open(b, "p", scope_tags()), b)
  +b2 = Bool.pick(B, String.eq(name, "li"), close_if_open(b1, "li", ["ul", "ol", "button", "table", "td", "th", "body"]), b1)
  +b3 = Bool.pick(B, String.eq(name, "dd") || String.eq(name, "dt"),
    close_if_open(close_if_open(b2, "dd", ["dl", "button", "table", "body"]), "dt", ["dl", "button", "table", "body"]), b2)
  +b4 = Bool.pick(B, is_one_of(name, headings()) && is_one_of(top_tag(stack_of(b3)), headings()), pop1(b3), b3)
  +b5 = Bool.pick(B, String.eq(name, "option") && String.eq(top_tag(stack_of(b4)), "option"), pop1(b4), b4)
  +b6 = Bool.pick(B, String.eq(name, "tr"), close_if_open(b5, "tr", ["table", "body"]), b5)
  +b7 = Bool.pick(B, String.eq(name, "td") || String.eq(name, "th"),
    close_if_open(close_if_open(b6, "td", ["tr", "table", "body"]), "th", ["tr", "table", "body"]), b6)
  Bool.pick(B, String.eq(name, "a"), close_if_open(b7, "a", scope_tags()), b7)

def push(b: B, +f: Frame) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      B{f <> stack, head, body_attrs, in_body, html_attrs, cm}

def append(b: B, +n: Dom.Node) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      B{append_node(stack, n), head, body_attrs, in_body, html_attrs, cm}

def to_head(b: B, +n: Dom.Node) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      B{stack, n <> head, body_attrs, in_body, html_attrs, cm}

def enter_body(b: B) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      B{stack, head, body_attrs, True{}, html_attrs, 2}

def has_name(xs: List<&2, Dom.Attr>, +n: String) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{a, t}:
      match a:
        case Dom.Attr{k, v}:
          String.eq(k, n) || has_name(t, n)

def add_new(xs: List<&2, Dom.Attr>, +acc: List<&2, Dom.Attr>) -> List<&2, Dom.Attr>:
  match xs:
    case Nil{}:
      acc
    case Con{a, t}:
      match a:
        case Dom.Attr{+k, +v}:
          add_new(t, Bool.pick(List<&2, Dom.Attr>, has_name(acc, k), acc, List.append(&2, Dom.Attr, acc, [Dom.Attr{k, v}])))

# <html>'s attributes go to the root element (HTML 13.2.6.4.7: an attribute
# the element already has is kept).
def set_html_attrs(b: B, +attrs: List<&2, Dom.Attr>) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      B{stack, head, body_attrs, in_body, add_new(attrs, html_attrs), cm}

def set_body_attrs(b: B, +attrs: List<&2, Dom.Attr>) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      B{stack, head, List.append(&2, Dom.Attr, body_attrs, attrs), True{}, html_attrs, 2}

def in_body_of(b: B) -> Bool:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      in_body

type SK is Data:
  SHtml{}
  SIgnore{}
  SBody{}
  SHeadVoid{}
  SHeadOpen{}
  SVoid{}
  SOpen{}

def start_kind(+name: String, +in_body: Bool) -> SK:
  Bool.pick(SK, String.eq(name, "html"), SHtml{},
  Bool.pick(SK, String.eq(name, "head"), SIgnore{},
    Bool.pick(SK, String.eq(name, "body"), SBody{},
      Bool.pick(SK, Bool.not(in_body) && is_one_of(name, head_tags()) && is_one_of(name, void_tags()), SHeadVoid{},
        Bool.pick(SK, Bool.not(in_body) && is_one_of(name, head_tags()), SHeadOpen{},
          Bool.pick(SK, is_one_of(name, void_tags()), SVoid{}, SOpen{}))))))

def cm_of(b: B) -> U32:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, cm}:
      cm

def set_cm(b: B, +v: U32) -> B:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, cm}:
      B{stack, head, body_attrs, in_body, html_attrs, v}

# <head>, or a head element before the body (an implied head), is "in head"
def into_head(+b: B) -> B:
  Bool.pick(B, U32.is_zero(cm_of(b)), set_cm(b, 1), b)

def on_start(k: SK, +b: B, +name: String, +attrs: List<&2, Dom.Attr>) -> B:
  match k:
    case SHtml{}:
      set_html_attrs(b, attrs)
    case SIgnore{}:
      into_head(b)
    case SBody{}:
      set_body_attrs(b, attrs)
    case SHeadVoid{}:
      to_head(into_head(b), Dom.Element{name, attrs, Nil{}})
    case SHeadOpen{}:
      push(into_head(b), Frame{name, attrs, Nil{}, True{}})
    case SVoid{}:
      append(implied_closes(enter_body(b), name), Dom.Element{name, attrs, Nil{}})
    case SOpen{}:
      push(implied_closes(enter_body(b), name), Frame{name, attrs, Nil{}, False{}})

# ---- tokens -------------------------------------------------------------------------

def on_end(+b: B, +name: String) -> B:
  Bool.pick(B, String.eq(name, "head"), Bool.pick(B, U32.is_eq(cm_of(b), 1), set_cm(b, 4), b),
  Bool.pick(B, String.eq(name, "html") || String.eq(name, "body"), Bool.pick(B, U32.is_eq(cm_of(b), 2), set_cm(b, 3), b),
    Bool.pick(B, String.eq(name, "br"), append(b, Dom.Element{"br", Nil{}, Nil{}}),
      close_if_open(b, name, ["html"]))))

# Text: whitespace before the body is dropped; text in an open head element
# (title, style, script) stays there; anything else starts the body.
# text that is not white space after the body puts the parser back in body
def after_text(+b: B, +s: String) -> B:
  Bool.pick(B, U32.is_eq(cm_of(b), 3) && Bool.not(is_ws_text(s)), set_cm(b, 2), b)

def text_in(+b: B, +s: String) -> B:
  Bool.pick(B, Bool.not(in_body_of(b)) && is_ws_text(s) && String.eq(top_tag(stack_of(b)), "body"), b,
    Bool.pick(B, String.eq(top_tag(stack_of(b)), "body") && Bool.not(in_body_of(b)), append(enter_body(b), Dom.TextNode{s, 0}),
      append(b, Dom.TextNode{s, 0})))

def on_text(+b: B, +s: String) -> B:
  after_text(text_in(b, s), s)

# A comment goes where the parser is (see cm): the open element in body,
# head in head; one at document or <html> level is dropped.
def comment_node(+s: String) -> Dom.Node:
  Dom.Element{Dom.comment_tag(), [Dom.Attr{"data", s}], Nil{}}

def on_comment(+b: B, +s: String) -> B:
  +node = comment_node(s)
  +cm = cm_of(b)
  # in head, an open head element (noscript...) takes it; else head does
  Bool.pick(B, U32.is_eq(cm, 2), append(b, node),
    Bool.pick(B, U32.is_eq(cm, 1), Bool.pick(B, String.eq(top_tag(stack_of(b)), "body"), to_head(b, node), append(b, node)), b))

def on_token(t: Tk.Tok, +b: B) -> B:
  match t:
    case Tk.TStart{+name, +attrs, self_close}:
      on_start(start_kind(name, in_body_of(b)), b, name, attrs)
    case Tk.TEnd{+name}:
      on_end(b, name)
    case Tk.TText{+text}:
      on_text(b, text)
    case Tk.TComment{+text}:
      on_comment(b, text)

def build(toks: List<&2, Tk.Tok>, +b: B) -> B:
  match toks:
    case Nil{}:
      b
    case Con{t, rest}:
      build(rest, on_token(t, b))

# Close everything down to the body frame.
def close_all(fuel: Nat, +b: B) -> B:
  match fuel:
    case 0n:
      b
    case 1n+k:
      close_all(k, pop1(b))

def body_of(xs: List<&2, Frame>, attrs: List<&2, Dom.Attr>) -> Dom.Node:
  match xs:
    case Nil{}:
      Dom.Element{"body", attrs, Nil{}}
    case Con{f, t}:
      match f:
        case Frame{tag, a, kids, head}:
          Dom.Element{"body", attrs, List.reverse(&2, Dom.Node, kids)}

def finish(b: B) -> Dom.Node:
  match b:
    case B{stack, head, body_attrs, in_body, html_attrs, +cm}:
      Dom.Element{"html", html_attrs, [
        Dom.Element{"head", Nil{}, List.reverse(&2, Dom.Node, head)},
        body_of(stack, body_attrs)
      ]}

def empty() -> B:
  B{[Frame{"body", Nil{}, Nil{}, False{}}], Nil{}, Nil{}, False{}, Nil{}, 0}

# Parse a document. Always succeeds: html > (head, body).
def parse(s: String) -> Dom.Node:
  +b = build(Tk.tokenize(s), empty())
  finish(close_all(List.length(&2, Frame, stack_of(b)), b))

def first_or(xs: List<&2, Dom.Node>) -> Dom.Node:
  match xs:
    case Nil{}:
      Dom.TextNode{SNil{}, 0}
    case Con{h, t}:
      h

# The body element of a parsed document.
def body(+doc: Dom.Node) -> Dom.Node:
  first_or(List.drop(&2, Dom.Node, Dom.element_children(doc), 1n))

def head(+doc: Dom.Node) -> Dom.Node:
  first_or(Dom.element_children(doc))

# ---- a compact dump for tests: tag(child child ...) and "text" ------------------------

def dump_list(xs: List<&2, Dom.Node>) -> String:
  match xs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      match h:
        case Dom.Element{tag, attrs, children}:
          " " ++ tag ++ "(" ++ dump_list(children) ++ " )" ++ dump_list(t)
        case Dom.TextNode{content, tnid}:
          " \"" ++ content ++ "\"" ++ dump_list(t)

def dump(n: Dom.Node) -> String:
  dump_list([n])
