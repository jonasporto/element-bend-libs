// Clock.unix on the JS target: seconds since the Unix epoch. A Nat crosses
// to JS as a plain number since Bend 2.0.37 (PR #1506; it was a BigInt).
function clock_unix() {
  return Math.floor(Date.now() / 1000);
}

// registered under its def (Bend 2.0.28: a JS effect registers as a C one does)
io_eff(CID(Clock.unix), clock_unix);
