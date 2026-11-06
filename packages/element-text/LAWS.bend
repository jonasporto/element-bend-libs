import Base
import ./json.bend as Json
import ./utf8.bend as U8

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# decoding runs on the joined bytes; malformed bytes become U+FFFD.
law utf8_split_read_survives:
  {U8.utf8(List.append(&2, U32, [97, 195], [169])) == "aé" : String}

law utf8_four_byte:
  {U8.utf8([240, 159, 152, 128]) == "😀" : String}

law utf8_malformed_is_replacement:
  {U8.utf8([255, 65]) == String.from_list([Char.from_u32(65533), 'A']) : String}

# nor is a code point past U+10FFFF; each bad byte or cut sequence is one U+FFFD.
law utf8_overlong_nul_refused:
  {U8.utf8([192, 128]) == String.from_list([Char.from_u32(65533), Char.from_u32(65533)]) : String}

law utf8_overlong_slash_refused:
  {U8.utf8([192, 175, 65]) == String.from_list([Char.from_u32(65533), Char.from_u32(65533), 'A']) : String}

law utf8_overlong_three_byte_refused:
  {U8.utf8([224, 128, 128]) == String.from_list([Char.from_u32(65533), Char.from_u32(65533), Char.from_u32(65533)]) : String}

law utf8_surrogate_refused:
  {U8.utf8([237, 160, 128]) == String.from_list([Char.from_u32(65533), Char.from_u32(65533), Char.from_u32(65533)]) : String}

law utf8_past_max_refused:
  {U8.utf8([244, 144, 128, 128]) == String.from_list([Char.from_u32(65533), Char.from_u32(65533), Char.from_u32(65533), Char.from_u32(65533)]) : String}

law utf8_cut_sequence_is_one_replacement:
  {U8.utf8([240, 159, 152, 65]) == String.from_list([Char.from_u32(65533), 'A']) : String}

law utf8_max_and_three_byte_accepted:
  {U8.utf8([244, 143, 191, 191, 237, 159, 191]) == String.from_list([Char.from_u32(1114111), Char.from_u32(55295)]) : String}

law charset_from_header_first:
  {U8.charset("text/html; charset=ISO-8859-1", U8.bytes_of("<meta charset=utf-8>")) == "iso-8859-1" : String}

law charset_from_meta:
  {U8.charset("text/html", U8.bytes_of("<html><head><meta charset=\"windows-1252\">")) == "windows-1252" : String}

law json_round_trip_with_escapes:
  {Json.show_or(Json.parse(" { \"a\" : [1, -2.5e3, true, null, \"x\\ny\\u00e9\\\"\"], \"b\": {} } "), "NONE") ++ "|" ++
   Json.show_or(Json.parse("[1, 2"), "NONE")
   == "{\"a\":[1,-2.5e3,true,null,\"x\\nyé\\\"\"],\"b\":{}}|NONE" : String}

law json_fields_of_a_ports_cookie:
  {Json.text_or(Json.get(Json.JObj{["name", "hostOnly"], [Json.JStr{"sid"}, Json.JBool{True{}}]}, "name"), "") ==
   "sid" : String}
