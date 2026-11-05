import Base

# DEFLATE decoding (RFC 1951): stored, fixed-Huffman and dynamic-Huffman
# blocks into bytes. A port of tinf's tinflate.c (jibsen/tinf 57ffa1f, zlib
# licence, read 2026-10-27; ~/Projects/refs/tinf) to Bend: a Huffman table
# is the count of codes per length and the symbols in code order, and a
# symbol is decoded one bit at a time against the counts, as tinf does.
#
# Shapes Bend asks for: the decoder state is one owner (Arrays are Type),
# threaded through every def; a pair a call answers is taken apart by the
# def it is passed to (a `(a, b) = f(x)` is refused: only a parameter or a
# field is matched); every loop is a def recursing on a fuel Nat whose state
# is one tuple parameter, matched (`case (go, s)`) so its stop flag, decided
# by the step before, is a field (a pick would build both arms); a loop's
# body is a chain of defs that never call the loop back. Errors
# set `bad` (a code: see bad_text) and the run stops at the next loop head;
# the caller gets Fail with the text.
#
# Output: bytes in a reversed list (one cons a byte) and a 32 KB ring
# (Array<U32>, 2^15) that back-references read from; the ring index wraps
# by Array's own masking, the explicit mask is for the reader.

type Tree is Type:
  Tree{counts: Array<U32>, syms: Array<U32>, max: U32, ok: U32}

type St is Type:
  St{inp: List<&2, U32>, tag: U32, nbits: U32, out: List<&2, U32>, ring: Array<U32>, opos: U32, bad: U32}

# ---- errors ------------------------------------------------------------------------------------

def bad_text(+code: U32) -> String:
  Bool.pick(String, U32.is_eq(code, 1), "inflate: the stream ends inside a block",
    Bool.pick(String, U32.is_eq(code, 2), "inflate: a block type of 3 (reserved)",
      Bool.pick(String, U32.is_eq(code, 3), "inflate: a stored block's length and its complement disagree",
        Bool.pick(String, U32.is_eq(code, 4), "inflate: a Huffman table that is over- or under-subscribed",
          Bool.pick(String, U32.is_eq(code, 5), "inflate: a symbol outside the table",
            Bool.pick(String, U32.is_eq(code, 6), "inflate: a back-reference before the start of the output",
              Bool.pick(String, U32.is_eq(code, 7), "inflate: a code-length repeat past the table",
                Bool.pick(String, U32.is_eq(code, 8), "inflate: the dynamic header is out of range (HLIT > 286 or HDIST > 30)",
                  "inflate: malformed stream"))))))))

def mark(st: St, +code: U32) -> St:
  match st:
    case St{inp, tag, nbits, out, ring, opos, +bad}:
      St{inp, tag, nbits, out, ring, opos, Bool.pick(U32, U32.is_zero(bad), code, bad)}

def mark_if(fail: Bool, st: St, +code: U32) -> St:
  match fail:
    case False{}:
      st
    case True{}:
      mark(st, code)

def is_bad(st: St) -> St & Bool:
  match st:
    case St{inp, tag, nbits, out, ring, opos, +bad}:
      (St{inp, tag, nbits, out, ring, opos, bad}, Bool.not(U32.is_zero(bad)))

# ---- bits --------------------------------------------------------------------------------------

# one more input byte into the tag (a missing byte is eight zero bits and bad 1, as tinf's overflow)
def pull(st: St) -> St:
  match st:
    case St{inp, +tag, +nbits, out, ring, opos, +bad}:
      match inp:
        case Nil{}:
          St{Nil{}, tag, (nbits + 8 : U32), out, ring, opos, Bool.pick(U32, U32.is_zero(bad), 1, bad)}
        case Con{+b, t}:
          St{t, U32.or(tag, U32.shln(b, U32.to_nat(nbits))), (nbits + 8 : U32), out, ring, opos, bad}

def pull_if(need: Bool, st: St) -> St:
  match need:
    case False{}:
      st
    case True{}:
      pull(st)

def need(st: St, +num: U32) -> St & Bool:
  match st:
    case St{inp, tag, +nbits, out, ring, opos, bad}:
      (St{inp, tag, nbits, out, ring, opos, bad}, U32.is_lt(nbits, num))

def step(sn: St & Bool) -> St:
  (s, n) = sn
  pull_if(n, s)

# at least `num` (<= 24) bits in the tag: three pulls at most
def refill(st: St, +num: U32) -> St:
  step(need(step(need(step(need(st, num)), num)), num))

def take(st: St, +num: U32) -> St & U32:
  match st:
    case St{inp, +tag, +nbits, out, ring, opos, bad}:
      +n = U32.to_nat(num)
      +bits = U32.and(tag, (U32.shln(1, n) - 1 : U32))
      (St{inp, U32.shrn(tag, n), (nbits - num : U32), out, ring, opos, bad}, bits)

# `num` bits (0 to 24), least significant first
def getbits(st: St, +num: U32) -> St & U32:
  take(refill(st, num), num)

def plus(+base: U32, sb: St & U32) -> St & U32:
  (s, b) = sb
  (s, (base + b : U32))

# a stored block starts at a byte: the tag's partial byte is dropped
def align(st: St) -> St:
  match st:
    case St{inp, tag, nbits, out, ring, opos, bad}:
      St{inp, 0, 0, out, ring, opos, bad}

# ---- output ------------------------------------------------------------------------------------

def emit(st: St, +b: U32) -> St:
  match st:
    case St{inp, tag, nbits, out, ring, +opos, bad}:
      St{inp, tag, nbits, b <> out, Array.set(U32, ring, U32.and(opos, 32767), b), (opos + 1 : U32), bad}

def emit_pair(sb: St & U32) -> St:
  (s, b) = sb
  emit(s, b)

def ring_back(r: Array<U32> & U32, inp: List<&2, U32>, +tag: U32, +nbits: U32, out: List<&2, U32>, +opos: U32, +bad: U32) -> St & U32:
  (ring, b) = r
  (St{inp, tag, nbits, out, ring, opos, bad}, b)

# the byte `dist` back
def back(st: St, +dist: U32) -> St & U32:
  match st:
    case St{inp, +tag, +nbits, out, ring, +opos, +bad}:
      ring_back(Array.get(U32, ring, U32.and((opos - dist : U32), 32767)), inp, tag, nbits, out, opos, bad)

# `n` bytes from `dist` back (a run may overlap itself: byte by byte)
def copy(n: Nat, st: St, +dist: U32) -> St:
  match n:
    case 0n:
      st
    case 1n+p:
      copy(p, emit_pair(back(st, dist)), dist)

def copy_checked(fits: Bool, st: St, +len: U32, +dist: U32) -> St:
  match fits:
    case False{}:
      mark(st, 6)
    case True{}:
      copy(U32.to_nat(len), st, dist)

def opos_of(st: St) -> St & U32:
  match st:
    case St{inp, tag, nbits, out, ring, +opos, bad}:
      (St{inp, tag, nbits, out, ring, opos, bad}, opos)

# ---- Huffman tables ----------------------------------------------------------------------------

# an Array is one owner: a conditional write is a match, not a pick
def set_if(doit: Bool, a: Array<U32>, +i: U32, +v: U32) -> Array<U32>:
  match doit:
    case False{}:
      a
    case True{}:
      Array.set(U32, a, i, v)

def tree_new() -> Tree:
  Tree{Array.new(U32, 4n, 0), Array.new(U32, 9n, 0), 0, 1}

def tree_bad(t: Tree) -> Tree:
  match t:
    case Tree{counts, syms, max, ok}:
      Tree{counts, syms, max, 0}

def tree_bad_if(fail: Bool, t: Tree) -> Tree:
  match fail:
    case False{}:
      t
    case True{}:
      tree_bad(t)

def tree_ok(t: Tree) -> Tree & Bool:
  match t:
    case Tree{counts, syms, +max, +ok}:
      (Tree{counts, syms, max, ok}, Bool.not(U32.is_zero(ok)))

def tree_max(t: Tree) -> Tree & U32:
  match t:
    case Tree{counts, syms, +max, ok}:
      (Tree{counts, syms, max, ok}, max)

def with_counts(r: Array<U32> & U32, syms: Array<U32>, +max: U32, +ok: U32) -> Tree & U32:
  (counts, v) = r
  (Tree{counts, syms, max, ok}, v)

def count_at(t: Tree, +i: U32) -> Tree & U32:
  match t:
    case Tree{counts, syms, +max, +ok}:
      with_counts(Array.get(U32, counts, i), syms, max, ok)

def with_syms(r: Array<U32> & U32, counts: Array<U32>, +max: U32, +ok: U32) -> Tree & U32:
  (syms, v) = r
  (Tree{counts, syms, max, ok}, v)

def sym_at(t: Tree, +i: U32) -> Tree & U32:
  match t:
    case Tree{counts, syms, +max, +ok}:
      with_syms(Array.get(U32, syms, i), counts, max, ok)

# counts[len] += 1 and max = i, for a length that is not 0
def count_len_fin(r: Tree & U32, +len: U32, +i: U32) -> Tree:
  (t, +v) = r
  match t:
    case Tree{counts, syms, +max, ok}:
      +zero = U32.is_zero(len)
      Tree{Array.set(U32, counts, len, Bool.pick(U32, zero, v, (v + 1 : U32))), syms, Bool.pick(U32, zero, max, i), ok}

def count_len(t: Tree, +len: U32, +i: U32) -> Tree:
  count_len_fin(count_at(t, len), len, i)

# pass 1: the counts of each length over lengths[0 .. num)
def count_step(r: Array<U32> & U32, +i: U32, t: Tree) -> Array<U32> & Tree:
  (ls, len) = r
  (ls, count_len(t, len, i))

def count_go(n: Nat, +i: U32, r: Array<U32> & Tree) -> Array<U32> & Tree:
  match n:
    case 0n:
      r
    case 1n+p:
      match r:
        case (ls, t):
          count_go(p, (i + 1 : U32), count_step(Array.get(U32, ls, i), i, t))

# pass 2: offs[len] = the first code index of that length; `avail` the codes
# left at this length (over-subscribed when used > avail); ncodes the total;
# over counts 2 per over-subscribed length
# the loop's state: the table, the offsets, (avail, (ncodes, over))
def offs_step(r: Tree & U32, +i: U32, offs: Array<U32>, +avail: U32, +ncodes: U32, +over: U32) -> (Tree & Array<U32>) & (U32 & (U32 & U32)):
  (t, +used) = r
  +bad = U32.is_lt(avail, used)
  +avail2 = Bool.pick(U32, bad, 0, U32.shl((avail - used : U32)))
  ((t, Array.set(U32, offs, i, ncodes)), (avail2, ((ncodes + used : U32), (over + Bool.pick(U32, bad, 2, 0) : U32))))

def offs_go(n: Nat, +i: U32, r: (Tree & Array<U32>) & (U32 & (U32 & U32))) -> (Tree & Array<U32>) & (U32 & (U32 & U32)):
  match n:
    case 0n:
      r
    case 1n+p:
      match r:
        case ((t, offs), (avail, (ncodes, over))):
          offs_go(p, (i + 1 : U32), offs_step(count_at(t, i), i, offs, avail, ncodes, over))

# pass 3: syms[offs[len]] = i, offs[len] += 1, for each non-zero length
def place_put(r: Array<U32> & U32, +i: U32, +len: U32, ls: Array<U32>, t: Tree) -> (Array<U32> & Array<U32>) & Tree:
  (offs, +at) = r
  match t:
    case Tree{counts, syms, max, ok}:
      +zero = U32.is_zero(len)
      ((ls, Array.set(U32, offs, len, Bool.pick(U32, zero, at, (at + 1 : U32)))),
        Tree{counts, set_if(Bool.not(zero), syms, at, i), max, ok})

def place_step(r: Array<U32> & U32, +i: U32, offs: Array<U32>, t: Tree) -> (Array<U32> & Array<U32>) & Tree:
  (ls, +len) = r
  place_put(Array.get(U32, offs, len), i, len, ls, t)

def place_go(n: Nat, +i: U32, r: (Array<U32> & Array<U32>) & Tree) -> (Array<U32> & Array<U32>) & Tree:
  match n:
    case 0n:
      r
    case 1n+p:
      match r:
        case ((ls, offs), t):
          place_go(p, (i + 1 : U32), place_step(Array.get(U32, ls, i), i, offs, t))

# over: 2 per over-subscribed length, 1 when codes are left unused; a single
# code of length 1 is fine, as tinf allows; an empty table is fine too, the
# caller decides
def verdict_fin(r: Tree & U32, +ncodes: U32, +over: U32) -> Tree:
  (t, c1) = r
  +one = U32.is_eq(ncodes, 1)
  +fail = (over >= 2 : U32) || (U32.is_eq(over, 1) && (ncodes > 1 : U32)) || (one && Bool.not(U32.is_eq(c1, 1)))
  tree_bad_if(fail, t)

def verdict(t: Tree, +ncodes: U32, +over: U32) -> Tree:
  verdict_fin(count_at(t, 1), ncodes, over)

# tinf: one code (always 0) gets a sibling code 1 with a symbol past max,
# so a stream using it is caught as "outside the table"
def single(t: Tree, +ncodes: U32) -> Tree:
  match t:
    case Tree{counts, syms, +max, ok}:
      +one = U32.is_eq(ncodes, 1)
      Tree{set_if(one, counts, 1, 2), set_if(one, syms, 1, (max + 1 : U32)), max, ok}

def build_fin(r: (Array<U32> & Array<U32>) & Tree, +ncodes: U32, +over: U32) -> Array<U32> & Tree:
  ((ls, offs), t) = r
  (ls, single(verdict(t, ncodes, over), ncodes))

def build_place(r: (Tree & Array<U32>) & (U32 & (U32 & U32)), ls: Array<U32>, +num: U32) -> Array<U32> & Tree:
  ((t, offs), (avail, (ncodes, over0))) = r
  +over = (over0 + Bool.pick(U32, U32.is_zero(avail), 0, 1) : U32)
  build_fin(place_go(U32.to_nat(num), 0, ((ls, offs), t)), ncodes, over)

def build_offs(r: Array<U32> & Tree, +num: U32) -> Array<U32> & Tree:
  (ls, t) = r
  build_place(offs_go(16n, 0, ((t, Array.new(U32, 4n, 0)), (1, (0, 0)))), ls, num)

# A table from code lengths (0 = no code) lengths[0 .. num), num <= 320.
# The lengths come back (the caller reads the distance lengths after).
def build(ls: Array<U32>, +num: U32) -> Array<U32> & Tree:
  build_offs(count_go(U32.to_nat(num), 0, (ls, tree_new())), num)

def tree_of(r: Array<U32> & Tree) -> Tree:
  (ls, t) = r
  t

# ---- decoding a symbol ---------------------------------------------------------------------------

def dec_found(r: Tree & U32, st: St) -> (St & Tree) & U32:
  (t, sym) = r
  ((st, t), sym)

def dec_count(r: Tree & U32, st: St, +base: U32, +offs2: U32, +len2: U32) -> ((St & Tree) & (U32 & (U32 & U32))) & Bool:
  (t, +cnt) = r
  +hit = U32.is_lt(offs2, cnt)
  (((st, t), (Bool.pick(U32, hit, base, (base + cnt : U32)), (Bool.pick(U32, hit, offs2, (offs2 - cnt : U32)), len2))), hit)

def dec_bit(r: St & U32, t: Tree, +base: U32, +offs: U32, +len: U32) -> ((St & Tree) & (U32 & (U32 & U32))) & Bool:
  (st, bit) = r
  +len2 = (len + 1 : U32)
  dec_count(count_at(t, len2), st, base, (U32.shl(offs) + bit : U32), len2)

# One bit a step: `offs` is the index among the codes of this length, `base`
# the codes of shorter lengths; `found` was decided by the step before.
def dec_go(n: Nat, r: ((St & Tree) & (U32 & (U32 & U32))) & Bool) -> (St & Tree) & U32:
  match n:
    case 0n:
      match r:
        case (((st, t), rest), found):
          ((mark(st, 5), t), 0)
    case 1n+p:
      match r:
        case (((st, t), (base, (offs, len))), found):
          match found:
            case True{}:
              dec_found(sym_at(t, (base + offs : U32)), st)
            case False{}:
              dec_go(p, dec_bit(getbits(st, 1), t, base, offs, len))

def decode(st: St, t: Tree) -> (St & Tree) & U32:
  dec_go(17n, (((st, t), (0, (0, 0))), False{}))

# ---- the fixed tables (RFC 1951 3.2.6) -------------------------------------------------------

def fixed_len(+i: U32) -> U32:
  Bool.pick(U32, (i < 144 : U32), 8, Bool.pick(U32, (i < 256 : U32), 9, Bool.pick(U32, (i < 280 : U32), 7, 8)))

def fill_go(n: Nat, +i: U32, ls: Array<U32>, +fixed: Bool) -> Array<U32>:
  match n:
    case 0n:
      ls
    case 1n+p:
      fill_go(p, (i + 1 : U32), Array.set(U32, ls, i, Bool.pick(U32, fixed, fixed_len(i), 5)), fixed)

def fixed_lit() -> Tree:
  tree_of(build(fill_go(288n, 0, Array.new(U32, 9n, 0), True{}), 288))

def fixed_dist() -> Tree:
  tree_of(build(fill_go(32n, 0, Array.new(U32, 9n, 0), False{}), 32))

# ---- the dynamic tables (RFC 1951 3.2.7) -----------------------------------------------------

# the order the code length code lengths come in
def clc_index(+i: U32) -> U32:
  Bool.pick(U32, U32.is_eq(i, 0), 16, Bool.pick(U32, U32.is_eq(i, 1), 17, Bool.pick(U32, U32.is_eq(i, 2), 18,
    Bool.pick(U32, U32.is_eq(i, 3), 0, Bool.pick(U32, U32.is_eq(i, 4), 8, Bool.pick(U32, U32.is_eq(i, 5), 7,
      Bool.pick(U32, U32.is_eq(i, 6), 9, Bool.pick(U32, U32.is_eq(i, 7), 6, Bool.pick(U32, U32.is_eq(i, 8), 10,
        Bool.pick(U32, U32.is_eq(i, 9), 5, Bool.pick(U32, U32.is_eq(i, 10), 11, Bool.pick(U32, U32.is_eq(i, 11), 4,
          Bool.pick(U32, U32.is_eq(i, 12), 12, Bool.pick(U32, U32.is_eq(i, 13), 3, Bool.pick(U32, U32.is_eq(i, 14), 13,
            Bool.pick(U32, U32.is_eq(i, 15), 2, Bool.pick(U32, U32.is_eq(i, 16), 14, Bool.pick(U32, U32.is_eq(i, 17), 1, 15))))))))))))))))))

def clc_step(r: St & U32, +i: U32, ls: Array<U32>) -> St & Array<U32>:
  (st, v) = r
  (st, Array.set(U32, ls, clc_index(i), v))

# the hclen code length code lengths, 3 bits each
def clc_go(n: Nat, +i: U32, r: St & Array<U32>) -> St & Array<U32>:
  match n:
    case 0n:
      r
    case 1n+p:
      match r:
        case (st, ls):
          clc_go(p, (i + 1 : U32), clc_step(getbits(st, 3), i, ls))

# writes `sym` `len` times from `at`
def rep_go(n: Nat, +at: U32, ls: Array<U32>, +sym: U32) -> Array<U32>:
  match n:
    case 0n:
      ls
    case 1n+p:
      rep_go(p, (at + 1 : U32), Array.set(U32, ls, at, sym), sym)

# the repeat count read, the lengths written, the next step decided
def lens_write(r: St & U32, clt: Tree, ls: Array<U32>, +at: U32, +total: U32, +sym: U32, +prev: U32) -> (((St & Tree) & Array<U32>) & U32) & Bool:
  (st, +cnt) = r
  +is16 = U32.is_eq(sym, 16)
  +val = Bool.pick(U32, is16, prev, Bool.pick(U32, (sym > 15 : U32), 0, sym))
  +room = (total - at : U32)
  +over = (cnt > room : U32) || (is16 && U32.is_zero(at)) || (sym > 18 : U32)
  +n = Bool.pick(U32, over, 0, cnt)
  +at2 = (at + n : U32)
  ((((mark_if(over, st, 7), clt), rep_go(U32.to_nat(n), at, ls, val)), at2), over || U32.is_eq(at2, total))

def lens_prev(r: Array<U32> & U32, st: St, clt: Tree, +at: U32, +total: U32, +sym: U32) -> (((St & Tree) & Array<U32>) & U32) & Bool:
  (ls, prev) = r
  +is16 = U32.is_eq(sym, 16)
  +is17 = U32.is_eq(sym, 17)
  +is18 = U32.is_eq(sym, 18)
  +extra = Bool.pick(U32, is16, 2, Bool.pick(U32, is17, 3, Bool.pick(U32, is18, 7, 0)))
  +base = Bool.pick(U32, is16, 3, Bool.pick(U32, is17, 3, Bool.pick(U32, is18, 11, 1)))
  lens_write(plus(base, getbits(st, extra)), clt, ls, at, total, sym, prev)

def lens_sym(r: (St & Tree) & U32, ls: Array<U32>, +at: U32, +total: U32) -> (((St & Tree) & Array<U32>) & U32) & Bool:
  ((st, clt), +sym) = r
  lens_prev(Array.get(U32, ls, Bool.pick(U32, U32.is_zero(at), 0, (at - 1 : U32))), st, clt, at, total, sym)

# The hlit + hdist code lengths, decoded with the code length table: a
# symbol 0-15 is a length, 16 repeats the previous 3-6 times, 17 writes
# 3-10 zeros, 18 writes 11-138 zeros. The state: stop (decided the step
# before), the decoder and table, the lengths, the write position.
def lens_go(n: Nat, +total: U32, r: (((St & Tree) & Array<U32>) & U32) & Bool) -> (St & Tree) & Array<U32>:
  match n:
    case 0n:
      match r:
        case ((((st, clt), ls), at), stop):
          ((mark(st, 7), clt), ls)
    case 1n+p:
      match r:
        case ((((st, clt), ls), at), stop):
          match stop:
            case True{}:
              ((st, clt), ls)
            case False{}:
              lens_go(p, total, lens_sym(decode(st, clt), ls, at, total))

def shift_step(r: Array<U32> & U32, +i: U32) -> Array<U32>:
  (ls, v) = r
  Array.set(U32, ls, i, v)

# the distance lengths follow the literal ones: moved down to 0
def shift_go(n: Nat, +i: U32, ls: Array<U32>, +from: U32) -> Array<U32>:
  match n:
    case 0n:
      ls
    case 1n+p:
      shift_go(p, (i + 1 : U32), shift_step(Array.get(U32, ls, (from + i : U32)), i), from)

def dyn_dist_fin(r: Array<U32> & Tree, st: St, lt: Tree) -> (St & Tree) & Tree:
  (ls, dt) = r
  ((st, lt), dt)

def dyn_dist(r: Array<U32> & Tree, st: St, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  (ls, lt) = r
  dyn_dist_fin(build(shift_go(U32.to_nat(hdist), 0, ls, hlit), hdist), st, lt)

def dyn_eob(r: Array<U32> & U32, st: St, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  (ls, eob) = r
  dyn_dist(build(ls, hlit), mark_if(U32.is_zero(eob), st, 4), hlit, hdist)

def dyn_tables(r: (St & Tree) & Array<U32>, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  ((st, clt), ls) = r
  dyn_eob(Array.get(U32, ls, 256), st, hlit, hdist)

def dyn_clt_ok(r: Tree & Bool, st: St, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  (clt, +okc) = r
  dyn_tables(lens_go(U32.to_nat((hlit + hdist + 1 : U32)), (hlit + hdist : U32), ((((mark_if(Bool.not(okc), st, 4), clt), Array.new(U32, 9n, 0)), 0), Bool.not(okc))), hlit, hdist)

def dyn_clt(r: Array<U32> & Tree, st: St, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  (cls, clt) = r
  dyn_clt_ok(tree_ok(clt), st, hlit, hdist)

def dyn_lens(r: St & Array<U32>, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  (st, cls) = r
  dyn_clt(build(cls, 19), st, hlit, hdist)

def dyn_header(st: St, +hlit: U32, +hdist: U32, +hclen: U32) -> (St & Tree) & Tree:
  +range = (hlit > 286 : U32) || (hdist > 30 : U32)
  dyn_lens(clc_go(U32.to_nat(hclen), 0, (mark_if(range, st, 8), Array.new(U32, 9n, 0))), hlit, hdist)

def dyn_hclen(r: St & U32, +hlit: U32, +hdist: U32) -> (St & Tree) & Tree:
  (s, hclen) = r
  dyn_header(s, hlit, hdist, hclen)

def dyn_hdist(r: St & U32, +hlit: U32) -> (St & Tree) & Tree:
  (s, hdist) = r
  dyn_hclen(plus(4, getbits(s, 4)), hlit, hdist)

def dyn_hlit(r: St & U32) -> (St & Tree) & Tree:
  (s, hlit) = r
  dyn_hdist(plus(1, getbits(s, 5)), hlit)

def dynamic(st: St) -> (St & Tree) & Tree:
  dyn_hlit(plus(257, getbits(st, 5)))

# ---- a block's codes (RFC 1951 3.2.5) --------------------------------------------------------

def len_extra(+s: U32) -> U32:
  Bool.pick(U32, (s < 8 : U32), 0, Bool.pick(U32, (s < 12 : U32), 1, Bool.pick(U32, (s < 16 : U32), 2, Bool.pick(U32, (s < 20 : U32), 3, Bool.pick(U32, (s < 24 : U32), 4, Bool.pick(U32, (s < 28 : U32), 5, 0))))))

def len_base(+s: U32) -> U32:
  Bool.pick(U32, (s < 8 : U32), (s + 3 : U32),
    Bool.pick(U32, (s < 12 : U32), (11 + U32.shln((s - 8 : U32), 1n) : U32),
      Bool.pick(U32, (s < 16 : U32), (19 + U32.shln((s - 12 : U32), 2n) : U32),
        Bool.pick(U32, (s < 20 : U32), (35 + U32.shln((s - 16 : U32), 3n) : U32),
          Bool.pick(U32, (s < 24 : U32), (67 + U32.shln((s - 20 : U32), 4n) : U32),
            Bool.pick(U32, (s < 28 : U32), (131 + U32.shln((s - 24 : U32), 5n) : U32), 258))))))

def dist_extra(+s: U32) -> U32:
  Bool.pick(U32, (s < 4 : U32), 0, U32.shr((s - 2 : U32)))

def dist_base(+s: U32) -> U32:
  Bool.pick(U32, (s < 4 : U32), (s + 1 : U32),
    (1 + U32.shln((2 + U32.and(s, 1) : U32), U32.to_nat(U32.shr((s - 2 : U32)))) : U32))

def match_fits(r: St & U32, +len: U32, +dist: U32) -> St:
  (s, opos) = r
  copy_checked(U32.is_le(dist, opos), s, len, dist)

def match_dist(r: St & U32, lt: Tree, dt: Tree, +len: U32, ok: Bool) -> (St & Tree) & Tree:
  (s, dist) = r
  ((match_fits(opos_of(mark_if(Bool.not(ok), s, 5)), len, dist), lt), dt)

def match_dmax(r: Tree & U32, s: St, lt: Tree, +len: U32, +dsym: U32) -> (St & Tree) & Tree:
  (dt, dmax) = r
  +ok = (dsym <= dmax : U32) && (dsym < 30 : U32)
  match_dist(plus(dist_base(dsym), getbits(s, Bool.pick(U32, ok, dist_extra(dsym), 0))), lt, dt, len, ok)

def do_match(r: (St & Tree) & U32, lt: Tree, +len: U32) -> (St & Tree) & Tree:
  ((s, dt), dsym) = r
  match_dmax(tree_max(dt), s, lt, len, dsym)

def code_len(r: St & U32, dt: Tree, lt: Tree) -> (St & Tree) & Tree:
  (s, len) = r
  do_match(decode(s, dt), lt, len)

def code_pick(lit: Bool, end: Bool, ok: Bool, s: St, lt: Tree, dt: Tree, +sym: U32, +ls: U32) -> ((St & Tree) & Tree) & Bool:
  match lit:
    case True{}:
      (((emit(s, sym), lt), dt), False{})
    case False{}:
      match end:
        case True{}:
          (((s, lt), dt), True{})
        case False{}:
          match ok:
            case True{}:
              (code_len(plus(len_base(ls), getbits(s, len_extra(ls))), dt, lt), False{})
            case False{}:
              (((mark(s, 5), lt), dt), True{})

# a literal is emitted, 256 ends the block (stop at the next step), 257-285
# are a length whose distance code follows, anything else is an error
def code_kind(r: Tree & U32, s: St, dt: Tree, +sym: U32) -> ((St & Tree) & Tree) & Bool:
  (lt, lmax) = r
  +lit = (sym < 256 : U32)
  +end = U32.is_eq(sym, 256)
  +ok = (sym <= lmax : U32) && (sym < 286 : U32)
  +ls = (sym - 257 : U32)
  code_pick(lit, end, ok, s, lt, dt, sym, ls)

def one_code(r: (St & Tree) & U32, dt: Tree) -> ((St & Tree) & Tree) & Bool:
  ((s, lt), +sym) = r
  code_kind(tree_max(lt), s, dt, sym)

def codes_or(bad: Bool, s: St, lt: Tree, dt: Tree) -> ((St & Tree) & Tree) & Bool:
  match bad:
    case True{}:
      (((s, lt), dt), True{})
    case False{}:
      one_code(decode(s, lt), dt)

# a step: unless the decoder is already bad, one symbol
def codes_bad(r: St & Bool, lt: Tree, dt: Tree) -> ((St & Tree) & Tree) & Bool:
  (s, bad) = r
  codes_or(bad, s, lt, dt)

def codes_go(n: Nat, r: ((St & Tree) & Tree) & Bool) -> St:
  match n:
    case 0n:
      match r:
        case (((st, lt), dt), stop):
          mark(st, 1)
    case 1n+p:
      match r:
        case (((st, lt), dt), stop):
          match stop:
            case True{}:
              st
            case False{}:
              codes_go(p, codes_bad(is_bad(st), lt, dt))

# a bound on the symbols left: eight a byte of input, plus the tag's
def fuel_of(st: St) -> St & U32:
  match st:
    case St{+inp, tag, +nbits, out, ring, opos, bad}:
      +n = (U32.shln(U32.from_nat(List.length(&2, U32, inp)), 3n) + nbits + 2 : U32)
      (St{inp, tag, nbits, out, ring, opos, bad}, n)

def codes_fuel(r: St & U32, lt: Tree, dt: Tree) -> St:
  (st, n) = r
  codes_go(U32.to_nat(n), (((st, lt), dt), False{}))

def codes(st: St, lt: Tree, dt: Tree) -> St:
  codes_fuel(fuel_of(st), lt, dt)

# ---- blocks -------------------------------------------------------------------------------------

def stored_go(n: Nat, st: St) -> St:
  match n:
    case 0n:
      st
    case 1n+p:
      stored_go(p, emit_pair(getbits(st, 8)))

def stored_nlen(r: St & U32, +len: U32) -> St:
  (s, nlen) = r
  +ok = U32.is_eq(U32.and(U32.not(nlen), 65535), len)
  stored_go(U32.to_nat(Bool.pick(U32, ok, len, 0)), mark_if(Bool.not(ok), s, 3))

def stored_len(r: St & U32) -> St:
  (s, len) = r
  stored_nlen(getbits(s, 16), len)

# a stored block: LEN, NLEN, then LEN bytes (RFC 1951 3.2.4)
def stored(st: St) -> St:
  stored_len(getbits(align(st), 16))

def dyn_ok_d(r: Tree & Bool, s: St, lt: Tree, okl: Bool) -> St:
  (dt, okd) = r
  codes(mark_if(Bool.not(okl && okd), s, 4), lt, dt)

def dyn_ok_l(r: Tree & Bool, s: St, dt: Tree) -> St:
  (lt, okl) = r
  dyn_ok_d(tree_ok(dt), s, lt, okl)

def dyn_block(r: (St & Tree) & Tree) -> St:
  ((s, lt), dt) = r
  dyn_ok_l(tree_ok(lt), s, dt)

def block_pick(stored_: Bool, fixed: Bool, dyn: Bool, st: St) -> St:
  match stored_:
    case True{}:
      stored(st)
    case False{}:
      match fixed:
        case True{}:
          codes(st, fixed_lit(), fixed_dist())
        case False{}:
          match dyn:
            case True{}:
              dyn_block(dynamic(st))
            case False{}:
              mark(st, 2)

def block(st: St, +btype: U32) -> St:
  block_pick(U32.is_eq(btype, 0), U32.is_eq(btype, 1), U32.is_eq(btype, 2), st)

def block_done(r: St & Bool, +final: U32) -> St & Bool:
  (s, bad) = r
  (s, Bool.not(U32.is_zero(final)) || bad)

def block_type(r: St & U32, +final: U32) -> St & Bool:
  (s, btype) = r
  block_done(is_bad(block(s, btype)), final)

def block_header(r: St & U32) -> St & Bool:
  (s, final) = r
  block_type(getbits(s, 2), final)

def blocks_flip(r: St & Bool) -> St & Bool:
  r

# blocks until the one marked final (or an error); `last` decided before
def blocks_go(n: Nat, r: St & Bool) -> St:
  match n:
    case 0n:
      match r:
        case (st, last):
          mark(st, 1)
    case 1n+p:
      match r:
        case (st, last):
          match last:
            case True{}:
              st
            case False{}:
              blocks_go(p, blocks_flip(block_header(getbits(st, 1))))

# ---- the entry -------------------------------------------------------------------------------

# the bytes decoded, and the bytes after the final block (a `&` pair is Type:
# Result wants Data)
type Out is Data:
  Out{bytes: List<&2, U32>, rest: List<&2, U32>}

def finish(st: St) -> Result<&2, &2, String, Out>:
  match st:
    case St{inp, tag, nbits, out, ring, opos, +bad}:
      Bool.pick(Result<&2, &2, String, Out>, U32.is_zero(bad), Done{Out{List.reverse(&2, U32, out), inp}}, Fail{bad_text(bad)})

# The bytes a raw DEFLATE stream (RFC 1951) encodes, beside the bytes after
# its final block (a gzip trailer, a zlib checksum), or why it cannot be read.
def inflate_rest(+bytes: List<&2, U32>) -> Result<&2, &2, String, Out>:
  +n = (U32.from_nat(List.length(&2, U32, bytes)) + 2 : U32)
  finish(blocks_go(U32.to_nat(n), (St{bytes, 0, 0, Nil{}, Array.new(U32, 15n, 0), 0, 0}, False{})))

def only_bytes(r: Result<&2, &2, String, Out>) -> Result<&2, &2, String, List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{o}:
      match o:
        case Out{bytes, rest}:
          Done{bytes}

# The bytes alone; what follows the final block is ignored.
def inflate(+bytes: List<&2, U32>) -> Result<&2, &2, String, List<&2, U32>>:
  only_bytes(inflate_rest(bytes))
