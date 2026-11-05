import Base

# RGB scanlines -> a zlib stream, in Bend. RFC 1951 sections 3.2.5/3.2.6:
# fixed Huffman codes and distance-three matches for repeated RGB pixels.
# Runs are capped at 86 pixels, so all Adler-32 arithmetic fits U32.
type S is Data:
  S{bits: U32, count: U32, out: List<&2, U32>, a: U32, b: U32}

def flush(full: Bool, s: S) -> S:
  match full s:
    case False{} s:
      s
    case True{} S{+bits, count, out, a, b}:
      S{(bits / 256 : U32), (count - 8 : U32), (bits % 256 : U32) <> out, a, b}

def flush_one(s: S) -> S:
  match s:
    case S{bits, +count, out, a, b}:
      flush((count >= 8 : U32), S{bits, count, out, a, b})

# At most 13 bits enter a buffer holding at most seven: flush twice.
def put(s: S, value: U32, width: U32) -> S:
  match s:
    case S{bits, +count, out, a, b}:
      flush_one(flush_one(S{U32.or(bits, U32.shln(value, U32.to_nat(count))), (count + width : U32), out, a, b}))

def reverse(n: Nat, +x: U32, out: U32) -> U32:
  match n:
    case 0n:
      out
    case 1n+r:
      reverse(r, (x / 2 : U32), ((out * 2 : U32) + (x % 2 : U32) : U32))

def literal_kind(small: Bool, s: S, c: U32) -> S:
  match small:
    case True{}:
      put(s, reverse(8n, (c + 48 : U32), 0), 8)
    case False{}:
      put(s, reverse(9n, (c + 256 : U32), 0), 9)

def literal(s: S, +c: U32) -> S:
  literal_kind((c < 144 : U32), s, c)

def length_code_kind(short: Bool, s: S, code: U32) -> S:
  match short:
    case True{}:
      put(s, reverse(7n, (code - 256 : U32), 0), 7)
    case False{}:
      put(s, reverse(8n, (code - 88 : U32), 0), 8)

def length_code(s: S, +code: U32) -> S:
  length_code_kind((code < 280 : U32), s, code)

def extra(+n: U32) -> U32:
  Bool.pick(U32, (n <= 18 : U32), 1,
    Bool.pick(U32, (n <= 34 : U32), 2,
      Bool.pick(U32, (n <= 66 : U32), 3, Bool.pick(U32, (n <= 130 : U32), 4, 5))))

def length_kind(short: Bool, s: S, +n: U32) -> S:
  match short:
    case True{}:
      length_code(s, (n + 254 : U32))
    case False{}:
      +e = extra(n)
      +step = U32.shln(1, U32.to_nat(e))
      +offset = (n - ((step * 4 : U32) + 3 : U32) : U32)
      +code = ((261 + (e * 4 : U32) : U32) + (offset / step : U32) : U32)
      put(length_code(s, code), (offset % step : U32), e)

def repeat_pixels(repeat: Bool, s: S, +n: U32) -> S:
  match repeat:
    case False{}:
      s
    case True{}:
      +length = ((n - 1 : U32) * 3 : U32)
      # Distance 3 is fixed distance code 2, reversed over five bits = 8.
      put(length_kind((length <= 10 : U32), s, length), 8, 5)

def continued_length(full: Bool, s: S, +n: U32) -> S:
  match full:
    case True{}:
      # The special length-258 code has no extra bits.
      put(length_code(s, 285), 8, 5)
    case False{}:
      +length = (n * 3 : U32)
      put(length_kind((length <= 10 : U32), s, length), 8, 5)

def run_body(continued: Bool, s: S, +r: U32, +g: U32, +b: U32, +n: U32) -> S:
  match continued:
    case True{}:
      continued_length(U32.is_eq(n, 86), s, n)
    case False{}:
      body = literal(literal(literal(s, r), g), b)
      repeat_pixels((n > 1 : U32), body, n)

# For n repetitions of RGB: A += n*(r+g+b), and B adds the weighted
# byte sum plus 3*n*A(old). Max n=86 keeps the largest product < 2^32.
def adler_rgb(s: S, +n: U32, +r: U32, +g: U32, +b: U32) -> S:
  match s:
    case S{bits, count, out, +a, old_b}:
      +sum = ((r + g : U32) + b : U32)
      +weighted = (((r * 3 : U32) + (g * 2 : U32) : U32) + b : U32)
      +triangle = ((n * (n - 1 : U32) : U32) / 2 : U32)
      +a2 = ((a + (n * sum : U32) : U32) % 65521 : U32)
      +b2 = (((old_b + ((3 * n : U32) * a : U32) : U32) + (n * weighted : U32) : U32) + ((3 * triangle : U32) * sum : U32) : U32)
      S{bits, count, out, a2, (b2 % 65521 : U32)}

def run_kind(empty: Bool, s: S, +color: U32, +n: U32, continued: Bool) -> S:
  match empty:
    case True{}:
      s
    case False{}:
      +r = (color / 65536 % 256 : U32)
      +g = (color / 256 % 256 : U32)
      +b = (color % 256 : U32)
      adler_rgb(run_body(continued, s, r, g, b, n), n, r, g, b)

def run(s: S, color: U32, +n: U32, continued: Bool) -> S:
  run_kind(U32.is_eq(n, 0), s, color, n, continued)

def next_run(same: Bool, s: S, color: U32, n: U32, continued: Bool) -> S:
  match same:
    case True{}:
      s
    case False{}:
      run(s, color, n, continued)

def row(xs: List<&2, U32>, s: S, +color: U32, +n: U32, +continued: Bool) -> S:
  match xs:
    case Nil{}:
      run(s, color, n, continued)
    case Con{+c, t}:
      +equal = U32.is_eq(c, color)
      +same = equal && (n < 86 : U32)
      row(t, next_run(same, s, color, n, continued), c,
        Bool.pick(U32, same, (n + 1 : U32), 1), Bool.pick(Bool, same, continued, equal))

def filter(s: S) -> S:
  match s:
    case S{bits, count, out, +a, b}:
      literal(S{bits, count, out, a, ((b + a : U32) % 65521 : U32)}, 0)

def rows(xs: List<&2, List<&2, U32>>, s: S) -> S:
  match xs:
    case Nil{}:
      s
    case Con{r, t}:
      rows(t, row(r, filter(s), 0, 0, False{}))

def final_bytes(empty: Bool, bits: U32, out: List<&2, U32>) -> List<&2, U32>:
  match empty:
    case True{}:
      List.reverse(&2, U32, out)
    case False{}:
      List.reverse(&2, U32, bits <> out)

def finish(s: S) -> List<&2, U32>:
  match s:
    case S{bits, count, out, +a, +b}:
      List.append(&2, U32, [120, 1], List.append(&2, U32,
        final_bytes(U32.is_eq(count, 0), bits, out),
        [(b / 256 : U32), (b % 256 : U32), (a / 256 : U32), (a % 256 : U32)]))

def zlib(xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  # BFINAL=1, BTYPE=01; end-of-block symbol 256 has seven zero bits.
  finish(put(rows(xs, S{3, 3, Nil{}, 1, 0}), 0, 7))
