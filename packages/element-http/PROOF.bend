import Base
import ./LAWS.bend as Laws

# Each law is a closed equality, proven by computation.

def Laws.http_status_line():
  {==}

def Laws.http_chunked_body():
  {==}

def Laws.http_redirect_followed():
  {==}

def Laws.http_redirect_loop_fails():
  {==}

def Laws.cookie_secure_only_over_https():
  {==}

def Laws.cookie_domain_covers_subdomains_host_only_does_not():
  {==}

def Laws.cookie_foreign_domain_is_refused():
  {==}

def Laws.cookie_date_rfc1123():
  {==}

def Laws.cookie_expired_and_max_age_zero_remove():
  {==}

def Laws.cookie_path_match_and_longest_first():
  {==}

def Laws.cookie_jar_file_round_trip():
  {==}

def Laws.websocket_masked_client_hello():
  {==}

def Laws.websocket_server_text_frame():
  {==}

def Laws.websocket_partial_frame_waits():
  {==}
