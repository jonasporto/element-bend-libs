import Base

# Signed page coordinates on U32, two's complement. Layout adds and subtracts
# as U32 (which wraps exactly like i32), so an inline box with padding at the
# top of the page sits at y = -2, as in Chrome. Only comparisons and printing
# need to know the sign. Widths and heights stay unsigned.

def bias(+v: U32) -> U32:
  U32.xor(v, 2147483648)

# The comparison is annotated `: U32`, and from Bend 2.0.21 a name inside
# that annotation is looked for in the U32 namespace first — so a bare
# `bias(a)` there resolves to `U32.bias`, which does not exist. Binding the
# values first keeps them in this module's scope, and compiles on every
# version. See wiki/docs/upgrading-bend.md.
def s_ge(+a: U32, +b: U32) -> Bool:
  +x = bias(a)
  +y = bias(b)
  (x >= y : U32)

def s_lt(+a: U32, +b: U32) -> Bool:
  +x = bias(a)
  +y = bias(b)
  (x < y : U32)

def s_le(+a: U32, +b: U32) -> Bool:
  +x = bias(a)
  +y = bias(b)
  (x <= y : U32)

def s_gt(+a: U32, +b: U32) -> Bool:
  +x = bias(a)
  +y = bias(b)
  (x > y : U32)

def is_neg(+v: U32) -> Bool:
  (v >= 2147483648 : U32)

def show_i(+v: U32) -> String:
  Bool.pick(String, is_neg(v), "-" ++ U32.show((0 - v : U32)), U32.show(v))
