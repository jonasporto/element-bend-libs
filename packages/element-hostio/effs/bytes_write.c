// Bytes.write: File.write without the UTF-8 encode. Each List cell is one
// byte (0..255), written as is (PNG, binary files, stdout via /dev/stdout).

static void bytes_write_call(IoWork* w) {
  int fd = (int)w->hand;
  ssize_t n = 0;
  for (uint64_t at = 0; n >= 0 && at < w->size; at += (uint64_t)n) {
    n = write(fd, w->data + at, w->size - at);
  }
  io_sys_end(w, n);
}

static Term bytes_write_pack(Env e, IoWork* w) {
  Term r = w->code != 0 ? io_fail(e, w->code, NULL)
    : io_done(e, term_pak(CID(Unit), 0));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term bytes_write_run(Env e, Term* f, IoWork* w) {
  u64   cap = 256;
  u64   n   = 0;
  char* buf = io_mem(malloc(cap));
  Term  s   = f[1];
  while (term_aux(s) == CID(Con)) {
    Term fb[2];
    spare_free(e, cls_fit(2), ctr_take(e, s, 2, fb));
    if (n + 1 > cap) {
      cap *= 2;
      buf = io_mem(realloc(buf, cap));
    }
    buf[n++] = (char)(uint8_t)fb[0];
    s = fb[1];
  }
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->data = buf;
  w->size = n;
  return io_work(w, bytes_write_call, bytes_write_pack);
}

static void __attribute__((constructor)) bytes_write_use(void) {
  io_eff(CID(Bytes.write), bytes_write_run);
}
