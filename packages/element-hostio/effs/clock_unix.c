// Clock.unix: seconds since the Unix epoch, from the real-time clock.

Term clock_unix_run(Env e, Term* f, IoWork* w) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (Term)(u64)ts.tv_sec;
}

static void __attribute__((constructor)) clock_unix_use(void) {
  io_eff(CID(Clock.unix), clock_unix_run);
}
