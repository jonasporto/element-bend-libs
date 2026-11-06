import Base
import ./cookie.bend as Ck
import ./http.bend as Http
import ./websocket.bend as Ws

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# K3.2 HTTP/1.1 on recorded responses: status line, chunked body.
law http_status_line:
  {Http.status_of("HTTP/1.1 301 Moved Permanently") == 301 : U32}

law http_chunked_body:
  {Http.follow(1n, Http.recorded(), "http://h/a") == "Wikipedia" : String}

# a loop is a loud error once the redirect bound is spent.
law http_redirect_followed:
  {Http.follow(5n, Http.recorded(), "http://h/") == "Wikipedia" : String}

law http_redirect_loop_fails:
  {Http.follow(5n, Http.recorded(), "http://h/loop") == "ERROR too many redirects" : String}

law cookie_secure_only_over_https:
  {Ck.header(Ck.store_all(["SID=31d4d96e407aad42; Path=/; Secure; HttpOnly", "lang=en-US; Path=/"], Nil{}, "example.com", "/a", 1789754256), "example.com", "/", True{}, 1789754256) ++ "|" ++
   Ck.header(Ck.store_all(["SID=31d4d96e407aad42; Path=/; Secure; HttpOnly", "lang=en-US; Path=/"], Nil{}, "example.com", "/a", 1789754256), "example.com", "/", False{}, 1789754256)
   == "SID=31d4d96e407aad42; lang=en-US|lang=en-US" : String}

law cookie_domain_covers_subdomains_host_only_does_not:
  {Ck.header(Ck.store_all(["a=1; Domain=example.com; Path=/", "b=2; Path=/"], Nil{}, "www.example.com", "/", 1789754256), "docs.example.com", "/", True{}, 1789754256) ++ "|" ++
   Ck.header(Ck.store_all(["a=1; Domain=.example.com; Path=/", "b=2; Path=/"], Nil{}, "www.example.com", "/", 1789754256), "www.example.com", "/", True{}, 1789754256)
   == "a=1|a=1; b=2" : String}

law cookie_foreign_domain_is_refused:
  {Ck.header(Ck.store_all(["evil=1; Domain=example.org"], Nil{}, "example.com", "/", 1789754256), "example.org", "/", True{}, 1789754256) == "" : String}

law cookie_date_rfc1123:
  {Ck.parse_date("Wed, 09 Jun 2021 10:18:14 GMT") == 1623233894 : U32}

law cookie_expired_and_max_age_zero_remove:
  {Ck.header(Ck.store_all(["s=1; Path=/", "t=2; Path=/", "s=gone; Path=/; Max-Age=0", "t=old; Path=/; Expires=Wed, 09 Jun 2021 10:18:14 GMT"], Nil{}, "h.test", "/", 1789754256), "h.test", "/", True{}, 1789754256) == "" : String}

law cookie_path_match_and_longest_first:
  {Ck.header(Ck.store_all(["root=1; Path=/", "docs=2; Path=/docs"], Nil{}, "h.test", "/", 1789754256), "h.test", "/docs/web", True{}, 1789754256) ++ "|" ++
   Ck.header(Ck.store_all(["root=1; Path=/", "docs=2; Path=/docs"], Nil{}, "h.test", "/", 1789754256), "h.test", "/docsets", True{}, 1789754256) ++ "|" ++
   Ck.header(Ck.store_all(["d=1"], Nil{}, "h.test", "/a/b/page", 1789754256), "h.test", "/a/b/x", True{}, 1789754256) ++
   Ck.header(Ck.store_all(["d=1"], Nil{}, "h.test", "/a/b/page", 1789754256), "h.test", "/a/x", True{}, 1789754256)
   == "docs=2; root=1|root=1|d=1" : String}

law cookie_jar_file_round_trip:
  {Ck.to_text(Ck.of_text(Ck.to_text(Ck.store_all(["SID=31d; Path=/; Secure; HttpOnly; Max-Age=3600", "lang=en; Domain=example.com"], Nil{}, "www.example.com", "/", 1789754256)))) ==
   "# Netscape HTTP Cookie File\n#HttpOnly_www.example.com\tFALSE\t/\tTRUE\t1789757856\tSID\t31d\n.example.com\tTRUE\t/\tFALSE\t0\tlang\ten\n" : String}

law websocket_masked_client_hello:
  {Ws.first_payload([129, 133, 55, 250, 33, 61, 127, 159, 77, 81, 88]) == [72, 101, 108, 108, 111] : List<&2, U32>}

law websocket_server_text_frame:
  {Ws.text_frame("Hello") == [129, 5, 72, 101, 108, 108, 111] : List<&2, U32>}

law websocket_partial_frame_waits:
  {Ws.first_payload([129, 133, 55, 250]) == [] : List<&2, U32>}
