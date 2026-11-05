import Base

# A program's own arguments, the same on every Bend: what follows the first
# "--args". Bend 2.0.32 began IO.args() with argv[0] (it had none), so a
# list read by position means one thing on one release and another on the
# next; a caller passes `-- --args a b ...` and reads from the marker.
# Without the marker the answer is empty (an argument read by position is
# never guessed).
def after_marker(xs: List<&1, String>, seen: Bool) -> List<&1, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      match seen:
        case True{}:
          Con{x, t}
        case False{}:
          after_marker(t, String.eq(x, "--args"))

def own(xs: List<&1, String>) -> List<&1, String>:
  after_marker(xs, False{})
