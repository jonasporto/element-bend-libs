// Net.resolve on the JS target: no system resolver is reachable from the
// FFI used by Base, so the effect fails with ENOSYS (78) instead of guessing.
function net_resolve(host) {
  return io_fail(78);
}

// registered under its def (Bend 2.0.28: a JS effect registers as a C one does)
io_eff(CID(Net.resolve), net_resolve);
