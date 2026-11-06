import Base
import ./der.bend as Der

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# DER time: days_from_civil at the epoch and on 2000-03-01 (11017 days).
law der_days_from_civil:
  {Nat.show(Der.days_from_civil(1970n, 1n, 1n)) ++ "|" ++ Nat.show(Der.days_from_civil(2000n, 3n, 1n)) == "0|11017" : String}

# DER lengths: short form, and the long form 82 01 00 (256 bytes of contents).
law der_long_length:
  {Nat.show(List.length(&2, U32, Der.body(Der.decode(List.append(&2, U32, [4, 130, 1, 0], Der.zeros(256n)))))) == "256" : String}
