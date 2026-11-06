import Base
import ./cert.bend as X509

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# RFC 6125 6.4.3: "*.example.com" names exactly one leftmost label.
law x509_wildcard_one_label:
  {Bool.pick(String, X509.name_matches("*.example.com", "a.example.com"), "y", "n") ++
    Bool.pick(String, X509.name_matches("*.example.com", "example.com"), "y", "n") ++
    Bool.pick(String, X509.name_matches("*.example.com", "a.b.example.com"), "y", "n") ++
    Bool.pick(String, X509.name_matches("example.com", "example.com"), "y", "n") == "ynny" : String}
