import Base
import ./LAWS.bend as Laws

# Each law is a closed equality, proven by computation.

def Laws.utf8_split_read_survives():
  {==}

def Laws.utf8_four_byte():
  {==}

def Laws.utf8_malformed_is_replacement():
  {==}

def Laws.utf8_overlong_nul_refused():
  {==}

def Laws.utf8_overlong_slash_refused():
  {==}

def Laws.utf8_overlong_three_byte_refused():
  {==}

def Laws.utf8_surrogate_refused():
  {==}

def Laws.utf8_past_max_refused():
  {==}

def Laws.utf8_cut_sequence_is_one_replacement():
  {==}

def Laws.utf8_max_and_three_byte_accepted():
  {==}

def Laws.charset_from_header_first():
  {==}

def Laws.charset_from_meta():
  {==}

def Laws.json_round_trip_with_escapes():
  {==}

def Laws.json_fields_of_a_ports_cookie():
  {==}
