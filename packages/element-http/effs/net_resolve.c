// Net.resolve: host name -> dotted IPv4, through the system resolver
// (getaddrinfo). Base's TCP.connect takes only a numeric IPv4 address.
#include <netdb.h>
#include <arpa/inet.h>

static void net_resolve_call(IoWork* w) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(w->data, NULL, &hints, &res);
  free(w->data);
  w->data = NULL;
  if (rc != 0 || res == NULL) {
    w->code = 2;  // ENOENT: the name does not resolve
    return;
  }
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
  freeaddrinfo(res);
  w->size = strlen(buf);
  w->data = io_mem(malloc(w->size + 1));
  memcpy(w->data, buf, w->size + 1);
  w->code = 0;
}

static Term net_resolve_pack(Env e, IoWork* w) {
  Term r = w->code ? io_fail(e, w->code, NULL) : io_done(e, io_str(e, w->data, w->size));
  free(w->data);
  return r;
}

Term net_resolve_run(Env e, Term* f, IoWork* w) {
  w->data = io_cstr(e, f[0], &w->size);
  return io_work(w, net_resolve_call, net_resolve_pack);
}

static void __attribute__((constructor)) net_resolve_use(void) {
  io_eff(CID(Net.resolve), net_resolve_run);
}
