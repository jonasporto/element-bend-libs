import Base
import ./url.bend as Url

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# K3.1 RFC 3986 section 5.4.1: all 23 normal examples, base http://a/b/c/d;p?q.
law url_rfc3986_normal_examples:
  {Url.resolve(Url.rfc_base(), "g:h") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "./g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g/") ++ "|" ++
    Url.resolve(Url.rfc_base(), "/g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "//g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "?y") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g?y") ++ "|" ++
    Url.resolve(Url.rfc_base(), "#s") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g#s") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g?y#s") ++ "|" ++
    Url.resolve(Url.rfc_base(), ";x") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g;x") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g;x?y#s") ++ "|" ++
    Url.resolve(Url.rfc_base(), "") ++ "|" ++
    Url.resolve(Url.rfc_base(), ".") ++ "|" ++
    Url.resolve(Url.rfc_base(), "./") ++ "|" ++
    Url.resolve(Url.rfc_base(), "..") ++ "|" ++
    Url.resolve(Url.rfc_base(), "../") ++ "|" ++
    Url.resolve(Url.rfc_base(), "../g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "../..") ++ "|" ++
    Url.resolve(Url.rfc_base(), "../../") ++ "|" ++
    Url.resolve(Url.rfc_base(), "../../g")
    == "g:h|http://a/b/c/g|http://a/b/c/g|http://a/b/c/g/|http://a/g|http://g|http://a/b/c/d;p?y|http://a/b/c/g?y|http://a/b/c/d;p?q#s|http://a/b/c/g#s|http://a/b/c/g?y#s|http://a/b/c/;x|http://a/b/c/g;x|http://a/b/c/g;x?y#s|http://a/b/c/d;p?q|http://a/b/c/|http://a/b/c/|http://a/b/|http://a/b/|http://a/b/g|http://a/|http://a/|http://a/g" : String}

# K3.1 RFC 3986 section 5.4.2: all 19 abnormal examples (strict parser).
law url_rfc3986_abnormal_examples:
  {Url.resolve(Url.rfc_base(), "../../../g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "../../../../g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "/./g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "/../g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g.") ++ "|" ++
    Url.resolve(Url.rfc_base(), ".g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g..") ++ "|" ++
    Url.resolve(Url.rfc_base(), "..g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "./../g") ++ "|" ++
    Url.resolve(Url.rfc_base(), "./g/.") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g/./h") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g/../h") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g;x=1/./y") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g;x=1/../y") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g?y/./x") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g?y/../x") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g#s/./x") ++ "|" ++
    Url.resolve(Url.rfc_base(), "g#s/../x") ++ "|" ++
    Url.resolve(Url.rfc_base(), "http:g")
    == "http://a/g|http://a/g|http://a/g|http://a/g|http://a/b/c/g.|http://a/b/c/.g|http://a/b/c/g..|http://a/b/c/..g|http://a/b/g|http://a/b/c/g/|http://a/b/c/g/h|http://a/b/c/h|http://a/b/c/g;x=1/y|http://a/b/c/y|http://a/b/c/g?y/./x|http://a/b/c/g?y/../x|http://a/b/c/g#s/./x|http://a/b/c/g#s/../x|http:g" : String}
