import Base
import element-ints@0.1.0.0/signed.bend as S
import ./f64.bend as F64
import ./consts.bend as C

# Correctly rounded exp, log, sin, cos and tan for JavaScript's Math: the
# double nearest the exact value, which is what Chrome answers (V8 forwards
# these to LLVM libc's correctly rounded math; Node's older fdlibm differs on
# 1-17% of inputs, so Chrome, not Node, is the oracle).
#
# Ziv's strategy on math/f64.bend's exact naturals: the value is
# computed in fixed point with p fraction bits (a natural scaled by 2^p)
# with a bound on its error; when value - err and value + err round to the
# same double, that double is the answer. Otherwise p grows (128, 256,
# 512); past that the answer is None and the caller refuses. Terms of
# either sign go to two natural accumulators, subtracted at the end.
# Constants (ln 2, pi/2, 2/pi) come from math/consts.bend, generated
# exactly by a generator script. Algorithms prototyped in Python and
# checked against headless Chrome on 20020 inputs each (0 different).

type Acc is Data:
  Acc{pos: +List<U32>, neg: +List<U32>, k: U32}

def acc_pos(a: Acc) -> List<&2, U32>:
  match a:
    case Acc{pos, neg, k}:
      pos

def acc_neg(a: Acc) -> List<&2, U32>:
  match a:
    case Acc{pos, neg, k}:
      neg

def acc_k(a: Acc) -> U32:
  match a:
    case Acc{pos, neg, k}:
      k

# 2^p
def pw(+p: U32) -> List<&2, U32>:
  F64.n_shl(F64.one(), p)

# a b / 2^p, truncated
def mul_p(+a: List<&2, U32>, +b: List<&2, U32>, +p: U32) -> List<&2, U32>:
  F64.n_shr(F64.n_mul(a, b), p)

def div_n(+a: List<&2, U32>, +d: U32) -> List<&2, U32>:
  F64.q_of(F64.n_divmod(a, F64.n_of(d)))

# a constant of math/consts.bend with p fraction bits
def c_at(+c: List<&2, U32>, +p: U32) -> List<&2, U32>:
  +bb = C.b()
  F64.n_shr(c, (bb - p : U32))

def add_if(c: Bool, +acc: List<&2, U32>, +t: List<&2, U32>) -> List<&2, U32>:
  match c:
    case True{}:
      F64.n_add(acc, t)
    case False{}:
      acc

# |a - b|, given whether a >= b (a match: n_sub wants a >= b)
def sub_abs(ge: Bool, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  match ge:
    case True{}:
      F64.n_sub(a, b)
    case False{}:
      F64.n_sub(b, a)

def acc_val(+a: Acc) -> List<&2, U32>:
  F64.n_sub(acc_pos(a), acc_neg(a))

# Taylor for sin (t = r, k = 1) or cos (t = 1, k = 0): the next term is
# t r^2 / ((k+1)(k+2)) with the other sign; `nn`: the next term is negative.
def alt_go(fuel: Nat, done: Bool, +t: List<&2, U32>, +r2: List<&2, U32>, +k: U32, +pos: List<&2, U32>, +neg: List<&2, U32>, +nn: Bool, +p: U32) -> Acc:
  match fuel:
    case 0n:
      Acc{pos, neg, k}
    case 1n+f:
      match done:
        case True{}:
          Acc{pos, neg, k}
        case False{}:
          +k1 = (k + 1 : U32)
          +k2 = (k + 2 : U32)
          +d = (k1 * k2 : U32)
          +t2 = div_n(mul_p(t, r2, p), d)
          alt_go(f, F64.is_zero(t2), t2, r2, k2, add_if(Bool.not(nn), pos, t2), add_if(nn, neg, t2), Bool.not(nn), p)

# Taylor for e^r (t = 1, i = 0): the next term is t r / (i+1); with r < 0
# the signs alternate (`alt`), `nn`: the next term is negative.
def exp_go(fuel: Nat, done: Bool, +t: List<&2, U32>, +r: List<&2, U32>, +i: U32, +pos: List<&2, U32>, +neg: List<&2, U32>, +alt: Bool, +nn: Bool, +p: U32) -> Acc:
  match fuel:
    case 0n:
      Acc{pos, neg, i}
    case 1n+f:
      match done:
        case True{}:
          Acc{pos, neg, i}
        case False{}:
          +i2 = (i + 1 : U32)
          +t2 = div_n(mul_p(t, r, p), i2)
          exp_go(f, F64.is_zero(t2), t2, r, i2, add_if(Bool.not(nn), pos, t2), add_if(nn, neg, t2), alt, alt && Bool.not(nn), p)

# atanh z = z + z^3/3 + z^5/5 ...: `t` is z^j, the sum in `pos`.
def ath_go(fuel: Nat, done: Bool, +t: List<&2, U32>, +z2: List<&2, U32>, +j: U32, +s: List<&2, U32>, +p: U32) -> Acc:
  match fuel:
    case 0n:
      Acc{s, Nil{}, j}
    case 1n+f:
      match done:
        case True{}:
          Acc{s, Nil{}, j}
        case False{}:
          +t2 = mul_p(t, z2, p)
          +j2 = (j + 2 : U32)
          +d = div_n(t2, j2)
          ath_go(f, F64.is_zero(d), t2, z2, j2, F64.n_add(s, d), p)

def same_f(a: F64.F, b: F64.F) -> Bool:
  match a:
    case F64.F{ah, al}:
      match b:
        case F64.F{bh, bl}:
          U32.is_eq(ah, bh) && U32.is_eq(al, bl)

def decided(ok: Bool, +lo: F64.F, +hi: F64.F) -> Maybe<&2, F64.F>:
  match ok:
    case True{}:
      Bool.pick(Maybe<&2, F64.F>, same_f(lo, hi), Some{lo}, None{})
    case False{}:
      None{}

def lo_of(ok: Bool, +neg: Bool, +mag: List<&2, U32>, +err: List<&2, U32>, +e: U32) -> F64.F:
  match ok:
    case True{}:
      F64.exact(neg, F64.n_sub(mag, err), e)
    case False{}:
      F64.zero(neg)

# The double (-1)^neg (mag +- err) 2^e rounds to, when both ends agree.
def ziv_round(+neg: Bool, +mag: List<&2, U32>, +err: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  +ok = F64.n_ge(mag, err)
  decided(ok, lo_of(ok, neg, mag, err, e), F64.exact(neg, F64.n_add(mag, err), e))

# The same for a quotient (num +- err) / (den -+ err).
def ziv_div(+neg: Bool, +num: List<&2, U32>, +den: List<&2, U32>, +err: List<&2, U32>) -> Maybe<&2, F64.F>:
  +ok = F64.n_ge(num, err) && U32.is_eq(F64.n_cmp(den, err), 2)
  decided(ok, F64.div_fin(neg, sub_abs(ok, num, err), 0, F64.n_add(den, err), 0), F64.div_fin(neg, F64.n_add(num, err), 0, sub_abs(ok, den, err), 0))

def precisions() -> List<&2, U32>:
  [128, 256, 512]

def absu(+k: U32) -> U32:
  Bool.pick(U32, S.is_neg(k), (0 - k : U32), k)

# |x| 2^p as a natural (x = m 2^e), truncated
def fix_sel(right: Bool, +m: List<&2, U32>, +s: U32) -> List<&2, U32>:
  match right:
    case True{}:
      F64.n_shr(m, (0 - s : U32))
    case False{}:
      F64.n_shl(m, s)

def fix_of(+m: List<&2, U32>, +e: U32, +p: U32) -> List<&2, U32>:
  +s = (e + p : U32)
  fix_sel(S.is_neg(s), m, s)

# ---- exp ---------------------------------------------------------------------------------------

# x = k ln 2 + r (k = trunc(x / ln 2)); e^x = 2^k e^r.
def exp_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +neg: Bool, +m: List<&2, U32>, +e: U32, +k: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +x = fix_of(m, e, p)
          +p64 = (p + 64 : U32)
          +l = F64.n_shr(F64.n_mul(F64.n_of(absu(k)), c_at(C.ln2_n(), p64)), 64)
          +ge = F64.n_ge(x, l)
          +rneg = Bool.pick(Bool, ge, neg, Bool.not(neg))
          +acc = exp_go(600n, False{}, pw(p), sub_abs(ge, x, l), 0, pw(p), Nil{}, rneg, rneg, p)
          +ak = acc_k(acc)
          +err = F64.n_of((ak + 16 : U32))
          exp_try(rest, ziv_round(False{}, acc_val(acc), err, (k - p : U32)), neg, m, e, k)

def exp_in(out: Bool, +neg: Bool, +m: List<&2, U32>, +e: U32, +f: F64.F) -> Maybe<&2, F64.F>:
  match out:
    case True{}:
      # |x| >= 1000: e^x is +Infinity or +0
      Some{Bool.pick(F64.F, neg, F64.zero(False{}), F64.inf(False{}))}
    case False{}:
      exp_try(precisions(), None{}, neg, m, e, F64.to_int32(F64.mul(f, F64.F{1073157447, 1697350398})))

def exp_dec(d: F64.Dec, +f: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DNaN{}:
      Some{F64.nan()}
    case F64.DInf{neg}:
      Some{Bool.pick(F64.F, neg, F64.zero(False{}), F64.inf(False{}))}
    case F64.DZero{neg}:
      Some{F64.from_i32(1)}
    case F64.DFin{+neg, +m, +e}:
      exp_in(U32.is_eq(F64.cmp(F64.abs(f), F64.F{1083129856, 0}), 2), neg, m, e, f)

def exp(+f: F64.F) -> Maybe<&2, F64.F>:
  exp_dec(F64.dec(f), f)

def div_q(+a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  F64.q_of(F64.n_divmod(a, b))

# ---- log ---------------------------------------------------------------------------------------

# x = 2^k mm, mm in [1/sqrt 2, sqrt 2); log mm = 2 atanh((mm-1)/(mm+1)).
# ---- sin, cos, tan -------------------------------------------------------------------------------

# |x| = q pi/2 + r exactly enough: t = |x| 2/pi with p+64 fraction bits (2/pi
# to C.b() bits covers |x| up to 2^1024 at p = 512), q its nearest integer,
# r = (t - q) pi/2; sin r and cos r by Taylor. `which`: 0 sin, 1 cos, 2 tan.
def trig_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +which: U32, +neg: Bool, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +bb = C.b()
          +p64 = (p + 64 : U32)
          +sh = ((bb - e : U32) - p64 : U32)
          +t = F64.n_shr(F64.n_mul(m, C.twoopi_n()), sh)
          +half = pw((p64 - 1 : U32))
          +q = F64.n_shr(F64.n_add(t, half), p64)
          +qs = F64.n_shl(q, p64)
          +ge = F64.n_ge(t, qs)
          +fr = sub_abs(ge, t, qs)
          +fneg = Bool.not(ge)
          +r = F64.n_shr(F64.n_mul(fr, c_at(C.pio2_n(), p64)), (p64 + 64 : U32))
          +r2 = mul_p(r, r, p)
          +sa = alt_go(600n, F64.is_zero(r), r, r2, 1, r, Nil{}, True{}, p)
          +ca = alt_go(600n, False{}, pw(p), r2, 0, pw(p), Nil{}, True{}, p)
          +s = acc_val(sa)
          +c = acc_val(ca)
          +ks = acc_k(sa)
          +kc = acc_k(ca)
          +err = F64.n_of(((ks + kc : U32) + 24 : U32))
          +qm = U32.and(F64.head0(q), 3)
          +odd = U32.is_eq(U32.and(qm, 1), 1)
          # sin: q 0 (s, fneg) 1 (c, +) 2 (s, not fneg) 3 (c, -)
          +sin_neg = Bool.pick(Bool, odd, (qm > 1 : U32), Bool.pick(Bool, (qm > 1 : U32), Bool.not(fneg), fneg))
          # cos: q 0 (c, +) 1 (s, not fneg) 2 (c, -) 3 (s, fneg)
          +cos_neg = Bool.pick(Bool, odd, Bool.pick(Bool, (qm > 1 : U32), fneg, Bool.not(fneg)), (qm > 1 : U32))
          +sc_mag = Bool.pick(List<&2, U32>, odd, c, s)
          +cs_mag = Bool.pick(List<&2, U32>, odd, s, c)
          +ep = (0 - p : U32)
          +res = Bool.pick(Maybe<&2, F64.F>, U32.is_eq(which, 0), ziv_round(Bool.pick(Bool, neg, Bool.not(sin_neg), sin_neg), sc_mag, err, ep),
            Bool.pick(Maybe<&2, F64.F>, U32.is_eq(which, 1), ziv_round(cos_neg, cs_mag, err, ep),
              # tan: even q, s/c with sign fneg; odd q, -c/s
              ziv_div(Bool.pick(Bool, neg, Bool.not(Bool.pick(Bool, odd, Bool.not(fneg), fneg)), Bool.pick(Bool, odd, Bool.not(fneg), fneg)), sc_mag, cs_mag, err)))
          trig_try(rest, res, which, neg, m, e)

# |x| < 2^-30: sin x and tan x round to x, cos x to 1.
def trig_fin(tiny: Bool, +which: U32, +f: F64.F, +neg: Bool, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match tiny:
    case True{}:
      Some{Bool.pick(F64.F, U32.is_eq(which, 1), F64.from_i32(1), f)}
    case False{}:
      trig_try(precisions(), None{}, which, neg, m, e)

def trig_dec(d: F64.Dec, +which: U32, +f: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DNaN{}:
      Some{F64.nan()}
    case F64.DInf{neg}:
      Some{F64.nan()}
    case F64.DZero{neg}:
      Some{Bool.pick(F64.F, U32.is_eq(which, 1), F64.from_i32(1), f)}
    case F64.DFin{+neg, +m, +e}:
      +bl = F64.bitlen(m)
      +top = (bl + e : U32)
      trig_fin(S.s_lt(top, (0 - 29 : U32)), which, f, neg, m, e)

def trig(+which: U32, +f: F64.F) -> Maybe<&2, F64.F>:
  trig_dec(F64.dec(f), which, f)

def shl_if(c: Bool, +a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  match c:
    case True{}:
      F64.n_shl(a, s)
    case False{}:
      a

# a - b (a >= b) or a + b
def add_or_sub(sub: Bool, +a: List<&2, U32>, +b: List<&2, U32>) -> List<&2, U32>:
  match sub:
    case True{}:
      F64.n_sub(a, b)
    case False{}:
      F64.n_add(a, b)

# ---- log2, log10, log1p, expm1, atan, atan2, asin, acos --------------------------------------
# The callers (a JavaScript Math) pass only finite, non-zero arguments in
# each function's domain; the special values, and the arguments where the
# answer is the argument itself, are decided there.

type Sig is Data:
  Sig{neg: Bool, mag: +List<U32>, err: U32}

def sig_neg(g: Sig) -> Bool:
  match g:
    case Sig{neg, mag, err}:
      neg

def sig_mag(g: Sig) -> List<&2, U32>:
  match g:
    case Sig{neg, mag, err}:
      mag

def sig_err(g: Sig) -> U32:
  match g:
    case Sig{neg, mag, err}:
      err

# log(m 2^e) with p fraction bits (m > 0 of any size): the sign, the
# magnitude and an error bound, as log_try computes it.
def ln_sig(+m: List<&2, U32>, +e: U32, +p: U32) -> Sig:
  +bl = F64.bitlen(m)
  +top = (bl - 1 : U32)
  +k0 = (top + e : U32)
  +sh = (p - top : U32)
  +cut = S.is_neg(sh)
  +mm0 = fix_sel(cut, m, sh)
  +p2 = ((p + p : U32) + 1 : U32)
  +big = U32.is_eq(F64.n_cmp(F64.n_mul(mm0, mm0), pw(p2)), 2)
  +mm = Bool.pick(List<&2, U32>, big, F64.n_shr(mm0, 1), mm0)
  +k = Bool.pick(U32, big, (k0 + 1 : U32), k0)
  +one = pw(p)
  +ge = F64.n_ge(mm, one)
  +z = div_q(F64.n_shl(sub_abs(ge, mm, one), p), F64.n_add(mm, one))
  +acc = ath_go(600n, F64.is_zero(z), z, mul_p(z, z, p), 1, z, p)
  +s2 = F64.n_shl(acc_pos(acc), 1)
  +sneg = Bool.not(ge)
  +kneg = S.is_neg(k)
  +ka = absu(k)
  +kl = F64.n_mul(F64.n_of(ka), c_at(C.ln2_n(), p))
  +same = Bool.pick(Bool, sneg, kneg, Bool.not(kneg))
  +sge = F64.n_ge(s2, kl)
  +mag = Bool.pick(List<&2, U32>, same, F64.n_add(s2, kl), sub_abs(sge, s2, kl))
  +neg = Bool.pick(Bool, same, sneg, Bool.pick(Bool, sge, sneg, kneg))
  +ak = acc_k(acc)
  +extra = Bool.pick(U32, cut, 4, 0)
  Sig{neg, mag, ((ak + 16 : U32) + (ka + extra : U32) : U32)}

# log(m 2^e) for m of any size (log1p passes 1 + x, which can be far wider
# than a double's 53 bits)
def log_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +g = ln_sig(m, e, p)
          log_try(rest, ziv_round(sig_neg(g), sig_mag(g), F64.n_of(sig_err(g)), (0 - p : U32)), m, e)

# log 1 is exactly +0 (Ziv cannot decide a value whose interval holds 0)
def log_fin(one: Bool, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match one:
    case True{}:
      Some{F64.zero(False{})}
    case False{}:
      log_try(precisions(), None{}, m, e)

def log_dec(d: F64.Dec, +f: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DNaN{}:
      Some{F64.nan()}
    case F64.DInf{neg}:
      Some{Bool.pick(F64.F, neg, F64.nan(), F64.inf(False{}))}
    case F64.DZero{neg}:
      Some{F64.inf(True{})}
    case F64.DFin{+neg, +m, +e}:
      Bool.pick(Maybe<&2, F64.F>, neg, Some{F64.nan()}, log_fin(U32.is_eq(F64.cmp(f, F64.from_i32(1)), 1), m, e))

def log(+f: F64.F) -> Maybe<&2, F64.F>:
  log_dec(F64.dec(f), f)

# log2 and log10: log x / log c (c = ln 2 or ln 10 at C.b() bits)
def logb_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +m: List<&2, U32>, +e: U32, +c: List<&2, U32>) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +g = ln_sig(m, e, p)
          +q = div_q(F64.n_shl(sig_mag(g), p), c_at(c, p))
          +ge = sig_err(g)
          +err = F64.n_of(((ge + ge : U32) + 4 : U32))
          logb_try(rest, ziv_round(sig_neg(g), q, err, (0 - p : U32)), m, e, c)

def logb_fin(d: F64.Dec, +c: List<&2, U32>) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      logb_try(precisions(), None{}, m, e, c)
    case _:
      None{}

def logb(+f: F64.F, +c: List<&2, U32>) -> Maybe<&2, F64.F>:
  logb_fin(F64.dec(f), c)

# log1p x = log u, u = 1 + x exactly: (2^-e +- m) 2^e for e < 0 (x is not an
# integer), m 2^e + 1 otherwise (x >= 1 here: x > -1 and non-zero).
def u_n(frac: Bool, +neg: Bool, +m: List<&2, U32>, +e: U32) -> List<&2, U32>:
  match frac:
    case True{}:
      +base = pw((0 - e : U32))
      add_or_sub(neg, base, m)
    case False{}:
      F64.n_add(F64.n_shl(m, e), F64.one())

def log1p_fin(d: F64.Dec) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      +frac = S.is_neg(e)
      log_try(precisions(), None{}, u_n(frac, neg, m, e), Bool.pick(U32, frac, e, 0))
    case _:
      None{}

def log1p(+f: F64.F) -> Maybe<&2, F64.F>:
  log1p_fin(F64.dec(f))

# expm1: e^x = S 2^(k-p) as exp_try computes it, then minus 1 exactly
def em1_sig(below: Bool, +s: List<&2, U32>, +ea: U32, +err: U32) -> Sig:
  match below:
    case True{}:
      +one_s = pw((0 - ea : U32))
      +ge = F64.n_ge(s, one_s)
      Sig{Bool.not(ge), sub_abs(ge, s, one_s), err}
    case False{}:
      Sig{False{}, F64.n_sub(F64.n_shl(s, ea), F64.one()), err}

def expm1_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +neg: Bool, +m: List<&2, U32>, +e: U32, +k: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +x = fix_of(m, e, p)
          +p64 = (p + 64 : U32)
          +l = F64.n_shr(F64.n_mul(F64.n_of(absu(k)), c_at(C.ln2_n(), p64)), 64)
          +ge = F64.n_ge(x, l)
          +rneg = Bool.pick(Bool, ge, neg, Bool.not(neg))
          +acc = exp_go(600n, False{}, pw(p), sub_abs(ge, x, l), 0, pw(p), Nil{}, rneg, rneg, p)
          +ak = acc_k(acc)
          +ea = (k - p : U32)
          +below = S.is_neg(ea) || U32.is_zero(ea)
          +g = em1_sig(below, acc_val(acc), ea, (ak + 16 : U32))
          +err0 = F64.n_of(sig_err(g))
          +err = shl_if(Bool.not(below), err0, ea)
          +eo = Bool.pick(U32, below, ea, 0)
          expm1_try(rest, ziv_round(sig_neg(g), sig_mag(g), err, eo), neg, m, e, k)

def expm1_fin(d: F64.Dec, +f: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      expm1_try(precisions(), None{}, neg, m, e, F64.to_int32(F64.mul(f, F64.F{1073157447, 1697350398})))
    case _:
      None{}

def expm1(+f: F64.F) -> Maybe<&2, F64.F>:
  expm1_fin(F64.dec(f), f)

# atan t for t in [0, 1] (p fraction bits): two half-angle steps
# t / (1 + sqrt(1 + t^2)), then Taylor; the final x4 scales every error.
def halve(+t: List<&2, U32>, +p: U32) -> List<&2, U32>:
  +one = pw(p)
  +s = F64.q_of(F64.isqrt(F64.n_add(F64.n_shl(one, p), F64.n_mul(t, t))))
  div_q(F64.n_shl(t, p), F64.n_add(one, s))

def ats_go(fuel: Nat, done: Bool, +t: List<&2, U32>, +z2: List<&2, U32>, +j: U32, +pos: List<&2, U32>, +neg: List<&2, U32>, +nn: Bool, +p: U32) -> Acc:
  match fuel:
    case 0n:
      Acc{pos, neg, j}
    case 1n+f:
      match done:
        case True{}:
          Acc{pos, neg, j}
        case False{}:
          +t2 = mul_p(t, z2, p)
          +j2 = (j + 2 : U32)
          +d = div_n(t2, j2)
          ats_go(f, F64.is_zero(d), t2, z2, j2, add_if(Bool.not(nn), pos, d), add_if(nn, neg, d), Bool.not(nn), p)

def atan_fixed(+t: List<&2, U32>, +p: U32) -> Sig:
  +h = halve(halve(t, p), p)
  +acc = ats_go(600n, F64.is_zero(h), h, mul_p(h, h, p), 1, h, Nil{}, True{}, p)
  +ak = acc_k(acc)
  Sig{False{}, F64.n_shl(acc_val(acc), 2), (((ak + 24 : U32) * 4 : U32) + 16 : U32)}

# atan(num / den) for num, den > 0: by 1/t past 1 (pi/2 - atan(den/num))
def atan_side(le: Bool, +num: List<&2, U32>, +den: List<&2, U32>, +p: U32) -> Sig:
  match le:
    case True{}:
      +g = atan_fixed(div_q(F64.n_shl(num, p), den), p)
      +ge = sig_err(g)
      Sig{False{}, sig_mag(g), (ge + 4 : U32)}
    case False{}:
      +g = atan_fixed(div_q(F64.n_shl(den, p), num), p)
      +ge = sig_err(g)
      Sig{False{}, F64.n_sub(c_at(C.pio2_n(), p), sig_mag(g)), (ge + 6 : U32)}

def atan_ratio(+num: List<&2, U32>, +den: List<&2, U32>, +p: U32) -> Sig:
  atan_side(Bool.not(U32.is_eq(F64.n_cmp(num, den), 2)), num, den, p)

# x = m 2^e as num / den
def num_sel(frac: Bool, +m: List<&2, U32>, +e: U32) -> List<&2, U32>:
  match frac:
    case True{}:
      m
    case False{}:
      F64.n_shl(m, e)

def den_sel(frac: Bool, +e: U32) -> List<&2, U32>:
  match frac:
    case True{}:
      pw((0 - e : U32))
    case False{}:
      F64.one()

def num_of(+m: List<&2, U32>, +e: U32) -> List<&2, U32>:
  num_sel(S.is_neg(e), m, e)

def den_of(+e: U32) -> List<&2, U32>:
  den_sel(S.is_neg(e), e)

def atan_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +neg: Bool, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +g = atan_ratio(num_of(m, e), den_of(e), p)
          atan_try(rest, ziv_round(neg, sig_mag(g), F64.n_of(sig_err(g)), (0 - p : U32)), neg, m, e)

def atan_fin(d: F64.Dec) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      atan_try(precisions(), None{}, neg, m, e)
    case _:
      None{}

def atan(+f: F64.F) -> Maybe<&2, F64.F>:
  atan_fin(F64.dec(f))

# atan2(y, x), both finite and non-zero: atan(|y| / |x|), or pi minus it for
# x < 0. A ratio below 2^-60 with x > 0 is |y| / |x| rounded once.
def atan2_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +yneg: Bool, +xneg: Bool, +num: List<&2, U32>, +den: List<&2, U32>) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +g = atan_ratio(num, den, p)
          +pi_p = F64.n_shl(c_at(C.pio2_n(), p), 1)
          +mag = Bool.pick(List<&2, U32>, xneg, sub_abs(True{}, pi_p, sig_mag(g)), sig_mag(g))
          +ge = sig_err(g)
          +err = Bool.pick(U32, xneg, (ge + 4 : U32), ge)
          atan2_try(rest, ziv_round(yneg, mag, F64.n_of(err), (0 - p : U32)), yneg, xneg, num, den)

def atan2_go(tiny: Bool, +yneg: Bool, +xneg: Bool, +num: List<&2, U32>, +den: List<&2, U32>) -> Maybe<&2, F64.F>:
  match tiny:
    case True{}:
      Some{F64.div_fin(yneg, num, 0, den, 0)}
    case False{}:
      atan2_try(precisions(), None{}, yneg, xneg, num, den)

def atan2_xy(+yneg: Bool, +ny: List<&2, U32>, +ey: U32, +xneg: Bool, +nx: List<&2, U32>, +ex: U32) -> Maybe<&2, F64.F>:
  +up = S.s_ge(ey, ex)
  +dy = (ey - ex : U32)
  +num = shl_if(up, ny, dy)
  +den = shl_if(Bool.not(up), nx, (0 - dy : U32))
  +tiny = Bool.not(xneg) && U32.is_zero(F64.n_cmp(F64.n_shl(num, 60), den))
  atan2_go(tiny, yneg, xneg, num, den)

def atan2_x(d: F64.Dec, +yneg: Bool, +ny: List<&2, U32>, +ey: U32) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      atan2_xy(yneg, ny, ey, neg, m, e)
    case _:
      None{}

def atan2_y(d: F64.Dec, +x: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      atan2_x(F64.dec(x), neg, m, e)
    case _:
      None{}

def atan2(+y: F64.F, +x: F64.F) -> Maybe<&2, F64.F>:
  atan2_y(F64.dec(y), x)

# asin and acos for 0 < |x| < 1: asin |x| = atan(|x| / sqrt(1 - x^2)),
# acos x = pi/2 - asin x. `which`: 0 asin, 1 acos.
def asin_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +which: U32, +neg: Bool, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +x = div_q(F64.n_shl(num_of(m, e), p), den_of(e))
          +one = pw(p)
          +sq = F64.q_of(F64.isqrt(F64.n_sub(F64.n_shl(one, p), F64.n_mul(x, x))))
          +g = atan_ratio(x, sq, p)
          +ge = sig_err(g)
          +pio2 = c_at(C.pio2_n(), p)
          +acos_mag = Bool.pick(List<&2, U32>, neg, F64.n_add(pio2, sig_mag(g)), sub_abs(True{}, pio2, sig_mag(g)))
          +res = Bool.pick(Maybe<&2, F64.F>, U32.is_zero(which), ziv_round(neg, sig_mag(g), F64.n_of((ge + 8 : U32)), (0 - p : U32)),
            ziv_round(False{}, acos_mag, F64.n_of((ge + 10 : U32)), (0 - p : U32)))
          asin_try(rest, res, which, neg, m, e)

def asin_fin(d: F64.Dec, +which: U32) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      asin_try(precisions(), None{}, which, neg, m, e)
    case _:
      None{}

def asin(+which: U32, +f: F64.F) -> Maybe<&2, F64.F>:
  asin_fin(F64.dec(f), which)

# ---- fround, cbrt, tanh ------------------------------------------------------------------------

# Math.fround: the float32 nearest x (ties to even), as a double: m rounded
# to 24 bits, or to float32's subnormal step 2^-149; past its largest
# finite value, Infinity. Exact: no Ziv.
def f32_q(right: Bool, +m: List<&2, U32>, +sh: U32) -> List<&2, U32>:
  match right:
    case True{}:
      F64.round_shr(m, sh)
    case False{}:
      F64.n_shl(m, (0 - sh : U32))

def fround_fin(+neg: Bool, +m: List<&2, U32>, +e: U32) -> F64.F:
  +bl = F64.bitlen(m)
  +top = (e + bl : U32)
  +want = (top - 24 : U32)
  +lsb = Bool.pick(U32, S.s_lt(want, (0 - 149 : U32)), (0 - 149 : U32), want)
  +sh = (lsb - e : U32)
  +q = f32_q(S.s_gt(sh, 0), m, sh)
  +qb = F64.bitlen(q)
  +over = S.s_gt((lsb + qb : U32), 128)
  Bool.pick(F64.F, over, F64.inf(neg), F64.exact(neg, q, lsb))

def fround_dec(d: F64.Dec, +f: F64.F) -> F64.F:
  match d:
    case F64.DFin{+neg, +m, +e}:
      fround_fin(neg, m, e)
    case _:
      f

def fround(+f: F64.F) -> Maybe<&2, F64.F>:
  Some{fround_dec(F64.dec(f), f)}

# ---- float32 bits (Float32Array, DataView get/setFloat32) -------------------------------------

# A float32's bits from a double that is one already (fround's answer):
# class k 0 a zero, 1 a float32 subnormal (E < 897), 2 normal, 3 Infinity
# or NaN. A NaN is stored as 0x7FC00000, as Chrome stores it. (A match, not
# picks: the subnormal shift is only valid in its own class.)
def f32_enc(k: Nat, +s: U32, +e: U32, +hi: U32, +lo: U32) -> U32:
  match k:
    case 0n:
      s
    case 1n:
      # the 53-bit significand >> (926 - E), done as (it >> 30) >> (896 - E)
      +top = U32.or(U32.shln(U32.or(U32.and(hi, 1048575), 1048576), 2n), U32.shrn(lo, 30n))
      +sh = (896 - e : U32)
      U32.or(s, U32.shrn(top, U32.to_nat(sh)))
    case 2n:
      +m = U32.or(U32.shln(U32.and(hi, 1048575), 3n), U32.shrn(lo, 29n))
      +be = (e - 896 : U32)
      U32.or(s, U32.or(U32.shln(be, 23n), m))
    case 3n+r:
      +none = U32.is_zero(U32.and(hi, 1048575)) && U32.is_zero(lo)
      Bool.pick(U32, none, U32.or(s, 2139095040), 2143289344)

def f32_cls(+e: U32) -> U32:
  Bool.pick(U32, U32.is_eq(e, 2047), 3, Bool.pick(U32, U32.is_zero(e), 0, Bool.pick(U32, (e < 897 : U32), 1, 2)))

def f32_of_f(f: F64.F) -> U32:
  match f:
    case F64.F{+hi, +lo}:
      +s = U32.and(hi, 2147483648)
      +e = U32.and(U32.shrn(hi, 20n), 2047)
      +k = f32_cls(e)
      f32_enc(U32.to_nat(k), s, e, hi, lo)

# the bits of the float32 nearest x (ties to even)
def f32_bits(+f: F64.F) -> U32:
  +r = fround_dec(F64.dec(f), f)
  f32_of_f(r)

# the double a float32's bits stand for (exact: every float32 is a double)
def f32_dec(k: Nat, +neg: Bool, +w: U32, +ex: U32, +mt: U32) -> F64.F:
  match k:
    case 0n:
      F64.zero(neg)
    case 1n:
      F64.exact(neg, F64.n_of(mt), (0 - 149 : U32))
    case 2n:
      +be = (ex + 896 : U32)
      +hi = U32.or(U32.and(w, 2147483648), U32.or(U32.shln(be, 20n), U32.shrn(mt, 3n)))
      F64.F{hi, U32.shln(U32.and(mt, 7), 29n)}
    case 3n+r:
      Bool.pick(F64.F, U32.is_zero(mt), F64.inf(neg), F64.nan())

def f32_val(+w: U32) -> F64.F:
  +neg = Bool.not(U32.is_zero(U32.and(w, 2147483648)))
  +ex = U32.and(U32.shrn(w, 23n), 255)
  +mt = U32.and(w, 8388607)
  +k = Bool.pick(U32, U32.is_eq(ex, 255), 3, Bool.pick(U32, U32.is_zero(ex), Bool.pick(U32, U32.is_zero(mt), 0, 1), 2))
  f32_dec(U32.to_nat(k), neg, w, ex, mt)

# cbrt: N = m 2^(3s + t) with e - t divisible by 3; r = floor(cbrt N) bit by
# bit; the value lies in [r, r+1) 2^((e - t)/3 - s): both ends round alike,
# or r^3 = N (exact). s grows when they do not.
def cb_go(fuel: Nat, +n: List<&2, U32>, +r: List<&2, U32>, +b: U32) -> List<&2, U32>:
  match fuel:
    case 0n:
      r
    case 1n+f:
      +t = F64.n_add(r, F64.n_shl(F64.one(), b))
      +fits = F64.n_ge(n, F64.n_mul(F64.n_mul(t, t), t))
      +r2 = Bool.pick(List<&2, U32>, fits, t, r)
      # the fuel is the number of bits, top + 1: b reaches 0 as it ends
      cb_go(f, n, r2, (b - 1 : U32))

def icbrt(+n: List<&2, U32>) -> List<&2, U32>:
  +bl = F64.bitlen(n)
  +top = ((bl + 2 : U32) / 3 : U32)
  cb_go(U32.to_nat((top + 1 : U32)), n, Nil{}, top)

def mod3(+e: U32) -> U32:
  # e mod 3 in 0..2 for a signed e
  +a = absu(e)
  +r = (a % 3 : U32)
  Bool.pick(U32, S.is_neg(e) && Bool.not(U32.is_zero(r)), (3 - r : U32), r)

def cbrt_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +neg: Bool, +m: List<&2, U32>, +e: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+s, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +t = mod3(e)
          +sh = ((s * 3 : U32) + t : U32)
          +n = F64.n_shl(m, sh)
          +r = icbrt(n)
          # e - t is divisible by 3: (e - t) / 3 exactly, signed
          +et = (e - t : U32)
          +net = (0 - et : U32)
          +q = Bool.pick(U32, S.is_neg(et), (0 - (net / 3 : U32) : U32), (et / 3 : U32))
          +eo = (q - s : U32)
          +exact_cube = U32.is_eq(F64.n_cmp(F64.n_mul(F64.n_mul(r, r), r), n), 1)
          +lo = F64.exact(neg, r, eo)
          +hi = F64.exact(neg, F64.n_add(r, F64.one()), eo)
          +res = Bool.pick(Maybe<&2, F64.F>, exact_cube, Some{lo}, decided(True{}, lo, hi))
          cbrt_try(rest, res, neg, m, e)

def cbrt_dec(d: F64.Dec, +f: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      cbrt_try([60, 120, 240], None{}, neg, m, e)
    case _:
      Some{f}

def cbrt(+f: F64.F) -> Maybe<&2, F64.F>:
  cbrt_dec(F64.dec(f), f)

# tanh |x| = (e^2|x| - 1) / (e^2|x| + 1), for 2^-30 <= |x| < 22 (the
# prelude answers the rest): e^2|x| = S 2^(k-p) with 0 <= k <= 63 < p, so
# S 2^k is it with p fraction bits.
def tanh_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +neg: Bool, +m: List<&2, U32>, +e: U32, +k: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          +e1 = (e + 1 : U32)
          +x = fix_of(m, e1, p)
          +p64 = (p + 64 : U32)
          +l = F64.n_shr(F64.n_mul(F64.n_of(k), c_at(C.ln2_n(), p64)), 64)
          +ge = F64.n_ge(x, l)
          +rneg = Bool.not(ge)
          +acc = exp_go(600n, False{}, pw(p), sub_abs(ge, x, l), 0, pw(p), Nil{}, rneg, rneg, p)
          +ak = acc_k(acc)
          +ef = F64.n_shl(acc_val(acc), k)
          +em = F64.n_sub(ef, pw(p))
          +p1 = (p + 1 : U32)
          +den = F64.n_add(em, pw(p1))
          +err = F64.n_shl(F64.n_of((ak + 16 : U32)), k)
          tanh_try(rest, ziv_div(neg, em, den, err), neg, m, e, k)

def tanh_dec(d: F64.Dec, +f: F64.F) -> Maybe<&2, F64.F>:
  match d:
    case F64.DFin{+neg, +m, +e}:
      +af = F64.abs(f)
      tanh_try(precisions(), None{}, neg, m, e, F64.to_int32(F64.mul(F64.add(af, af), F64.F{1073157447, 1697350398})))
    case _:
      None{}

def tanh(+f: F64.F) -> Maybe<&2, F64.F>:
  tanh_dec(F64.dec(f), f)

# ---- decimal rounding (toFixed, toPrecision, toExponential) --------------------------------------

# The decimal digits of round(|x| 10^s), ties away from zero (ES's "the
# larger n"). x is m 2^e exactly, so this is one division of naturals:
# floor((2 num + den) / (2 den)). No double is rounded on the way.
def pad4(+d: U32) -> String:
  +s = U32.show(d)
  Bool.pick(String, (d < 10 : U32), "000" ++ s, Bool.pick(String, (d < 100 : U32), "00" ++ s, Bool.pick(String, (d < 1000 : U32), "0" ++ s, s)))

def lo_limb(xs: List<&2, U32>) -> U32:
  match xs:
    case Nil{}:
      0
    case Con{x, rest}:
      x

# four digits a step (a remainder below 10000 is one 16-bit limb), each
# padded to four: the caller drops the leading zeros. `done` is set once
# the quotient is 0; the fuel, a step per 13 bits, outlasts the digits.
def dec_go(fuel: Nat, done: Bool, +n: List<&2, U32>, +acc: String) -> String:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      match done:
        case True{}:
          acc
        case False{}:
          +qr = F64.n_divmod(n, F64.n_of(10000))
          +q = F64.q_of(qr)
          +d = lo_limb(F64.r_of(qr))
          dec_go(f, F64.is_zero(q), q, pad4(d) ++ acc)

def nat_dec(+n: List<&2, U32>) -> String:
  +bl = F64.bitlen(n)
  +fuel = ((bl / 13 : U32) + 2 : U32)
  dec_go(U32.to_nat(fuel), False{}, n, "")

def dec_round_d(d: F64.Dec, +s: U32) -> String:
  match d:
    case F64.DFin{+neg, +m, +e}:
      +ep = Bool.pick(U32, S.is_neg(e), 0, e)
      +en = Bool.pick(U32, S.is_neg(e), (0 - e : U32), 0)
      +sp = Bool.pick(U32, S.is_neg(s), 0, s)
      +sn = Bool.pick(U32, S.is_neg(s), (0 - s : U32), 0)
      +num = F64.n_mul(F64.n_shl(m, ep), F64.pow10(U32.to_nat(sp)))
      +den = F64.n_mul(F64.n_shl(F64.one(), en), F64.pow10(U32.to_nat(sn)))
      +q = F64.q_of(F64.n_divmod(F64.n_add(F64.n_shl(num, 1), den), F64.n_shl(den, 1)))
      nat_dec(q)
    case _:
      "0"

# s is signed; the caller keeps |s| under 1200
def dec_round(+f: F64.F, +s: U32) -> String:
  dec_round_d(F64.dec(f), s)

# ---- pow ---------------------------------------------------------------------------------------
# x^y = e^(y ln x), correctly rounded, for x > 0 finite and y finite and not
# an integer (the caller decides integers exactly, the special values, and
# V8's shortcuts y = 2 and y = 0.5). V8's Math.pow is std::pow or LLVM
# libc's correctly rounded pow (src/numbers/ieee754.cc), so Chrome's last
# bit is its platform's libm: this is the value both aim at (Apple's libm
# differs on ~0.2% of inputs; honesty-and-fidelity-gaps.md).
#
# ln x with q fraction bits and its error (ln_sig), times y = my 2^ey
# exactly, then e^t as exp_try does it (t = k ln 2 + r, the Taylor series of
# e^r) with the error of t carried through: e^(r +- d) is within
# e^r (1 +- 2d), and e^r < 2, so it adds at most 4 d in units of 2^-q. An
# error in ln x grows by |y|: q is p plus the bits of |y| plus 8.

# a natural times 2^s (s signed); a right shift rounds up (an error bound).
# (a match, as fix_sel: a pick builds both sides, and a left shift by a
# negative s read unsigned is a shift by ~2^32 bits)
def shift_up_sel(right: Bool, +a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  match right:
    case True{}:
      F64.n_add(F64.n_shr(a, (0 - s : U32)), F64.one())
    case False{}:
      F64.n_shl(a, s)

def shift_up(+a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  shift_up_sel(S.is_neg(s), a, s)

def shift_down(+a: List<&2, U32>, +s: U32) -> List<&2, U32>:
  fix_sel(S.is_neg(s), a, s)

# e^(+-T 2^-q) with T's error terr (units of 2^-q), when |t| < 1024
def pow_exp(+tneg: Bool, +tt: List<&2, U32>, +terr: List<&2, U32>, +q: U32) -> Maybe<&2, F64.F>:
  +k = F64.q_of(F64.n_divmod(tt, c_at(C.ln2_n(), q)))
  +ku = F64.head0(k)
  +q64 = (q + 64 : U32)
  +l = F64.n_shr(F64.n_mul(k, c_at(C.ln2_n(), q64)), 64)
  +ge = F64.n_ge(tt, l)
  +rneg = Bool.pick(Bool, ge, tneg, Bool.not(tneg))
  +acc = exp_go(600n, False{}, pw(q), sub_abs(ge, tt, l), 0, pw(q), Nil{}, rneg, rneg, q)
  +ak = acc_k(acc)
  +err = F64.n_add(F64.n_of((ak + 20 : U32)), F64.n_shl(terr, 2))
  +ks = Bool.pick(U32, tneg, (0 - ku : U32), ku)
  ziv_round(False{}, acc_val(acc), err, (ks - q : U32))

# |t| >= 1024: e^t is +Infinity or +0 (a match: the series never runs)
def pow_range(out: Bool, +tneg: Bool, +tt: List<&2, U32>, +terr: List<&2, U32>, +q: U32) -> Maybe<&2, F64.F>:
  match out:
    case True{}:
      Some{Bool.pick(F64.F, tneg, F64.zero(False{}), F64.inf(False{}))}
    case False{}:
      pow_exp(tneg, tt, terr, q)

def pow_at(+mx: List<&2, U32>, +ex: U32, +yneg: Bool, +my: List<&2, U32>, +ey: U32, +p: U32) -> Maybe<&2, F64.F>:
  +yb = (F64.bitlen(my) + ey : U32)
  +q = ((p + Bool.pick(U32, S.is_neg(yb), 0, yb) : U32) + 8 : U32)
  +g = ln_sig(mx, ex, q)
  +tneg = Bool.pick(Bool, yneg, Bool.not(sig_neg(g)), sig_neg(g))
  +tt = shift_down(F64.n_mul(sig_mag(g), my), ey)
  +terr = F64.n_add(shift_up(F64.n_mul(F64.n_of(sig_err(g)), my), ey), F64.n_of(2))
  pow_range((F64.bitlen(tt) > (q + 10 : U32) : U32), tneg, tt, terr, q)

def pow_try(ps: List<&2, U32>, prev: Maybe<&2, F64.F>, +mx: List<&2, U32>, +ex: U32, +yneg: Bool, +my: List<&2, U32>, +ey: U32) -> Maybe<&2, F64.F>:
  match ps:
    case Nil{}:
      prev
    case Con{+p, rest}:
      match prev:
        case Some{v}:
          Some{v}
        case None{}:
          pow_try(rest, pow_at(mx, ex, yneg, my, ey, p), mx, ex, yneg, my, ey)

def pow_dy(dy: F64.Dec, +mx: List<&2, U32>, +ex: U32) -> Maybe<&2, F64.F>:
  match dy:
    case F64.DFin{+yneg, +my, +ey}:
      pow_try(precisions(), None{}, mx, ex, yneg, my, ey)
    case _:
      None{}

def pow_dx(dx: F64.Dec, +y: F64.F) -> Maybe<&2, F64.F>:
  match dx:
    case F64.DFin{+xneg, +mx, +ex}:
      Bool.pick(Maybe<&2, F64.F>, xneg, None{}, pow_dy(F64.dec(y), mx, ex))
    case _:
      None{}

# x > 0 finite, x != 1, y finite and not an integer; None outside that
# domain, or when 512 bits do not decide the rounding
def pow_frac(+x: F64.F, +y: F64.F) -> Maybe<&2, F64.F>:
  pow_dx(F64.dec(x), y)

# ---- x ** y for a y the caller has no exact integer path for ----------------------------------
# y is NaN, infinite, not an integer, or an integer past int32. V8's
# Math.pow (src/numbers/ieee754.cc): y = 0.5 is sqrt(x + 0) (-Infinity:
# +Infinity); else the value pow_frac rounds correctly. Special values as
# ES 6.1.6.1.3. None: 512 bits did not decide the rounding (refuse).

def pow_neg_int(odd: Bool, m: Maybe<&2, F64.F>) -> Maybe<&2, F64.F>:
  match m:
    case Some{+v}:
      Some{Bool.pick(F64.F, odd, F64.negate(v), v)}
    case None{}:
      None{}

# x finite and not zero: a negative x has a real power only for an integer y
def pow_fin(+xneg: Bool, +x: F64.F, +y: F64.F, +yint: Bool, +yodd: Bool) -> Maybe<&2, F64.F>:
  Bool.pick(Maybe<&2, F64.F>, xneg,
    Bool.pick(Maybe<&2, F64.F>, yint, pow_neg_int(yodd, pow_frac(F64.negate(x), y)), Some{F64.nan()}),
    Bool.pick(Maybe<&2, F64.F>, U32.is_eq(F64.cmp(x, F64.from_i32(1)), 1), Some{F64.from_i32(1)}, pow_frac(x, y)))

def pow_xd(dx: F64.Dec, +x: F64.F, +y: F64.F, +yneg: Bool, +yint: Bool, +yodd: Bool) -> Maybe<&2, F64.F>:
  match dx:
    case F64.DNaN{}:
      Some{F64.nan()}
    case F64.DInf{+xneg}:
      # an odd integer y keeps -Infinity's sign (and -0's below)
      Some{Bool.pick(F64.F, yneg, F64.zero(xneg && yodd), F64.inf(xneg && yodd))}
    case F64.DZero{+xneg}:
      Some{Bool.pick(F64.F, yneg, F64.inf(xneg && yodd), F64.zero(xneg && yodd))}
    case F64.DFin{+xneg, mx, ex}:
      pow_fin(xneg, x, y, yint, yodd)

# an infinite y: |x| against 1 (0 less, 1 equal, 2 greater)
def pow_yinf(+c: U32, +xnan: Bool, +yneg: Bool) -> Maybe<&2, F64.F>:
  Bool.pick(Maybe<&2, F64.F>, xnan || U32.is_eq(c, 1), Some{F64.nan()},
    Some{Bool.pick(F64.F, U32.is_eq(c, 2), Bool.pick(F64.F, yneg, F64.zero(False{}), F64.inf(False{})), Bool.pick(F64.F, yneg, F64.inf(False{}), F64.zero(False{})))})

def pow_half(half: Bool, +x: F64.F, +y: F64.F, +yneg: Bool, +yint: Bool, +yodd: Bool) -> Maybe<&2, F64.F>:
  match half:
    case True{}:
      Bool.pick(Maybe<&2, F64.F>, U32.is_eq(F64.cmp(x, F64.inf(True{})), 1), Some{F64.inf(False{})}, Some{F64.sqrt(F64.add(x, F64.zero(False{})))})
    case False{}:
      pow_xd(F64.dec(x), x, y, yneg, yint, yodd)

def pow_yd(dy: F64.Dec, +x: F64.F, +y: F64.F) -> Maybe<&2, F64.F>:
  match dy:
    case F64.DNaN{}:
      Some{F64.nan()}
    case F64.DInf{yneg}:
      pow_yinf(F64.cmp(F64.abs(x), F64.from_i32(1)), F64.is_nan(x), yneg)
    case F64.DZero{n}:
      Some{F64.from_i32(1)}
    case F64.DFin{+yneg, +my, +ey}:
      +eneg = S.is_neg(ey)
      +yint = F64.frac_zero(eneg, my, ey)
      +yodd = yint && F64.odd(F64.whole_part(eneg, my, ey))
      pow_half(U32.is_eq(F64.cmp(y, F64.F{1071644672, 0}), 1), x, y, yneg, yint, yodd)

def pow_js(+x: F64.F, +y: F64.F) -> Maybe<&2, F64.F>:
  pow_yd(F64.dec(y), x, y)
