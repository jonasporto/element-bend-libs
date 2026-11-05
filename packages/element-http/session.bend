import Base
import ./cookie.bend as Ck
import element-text@0.1.0.0/json.bend as Json

# A browser session exported as JSON into a cookie jar. Accepts the
# chrome.cookies shape a browser extension exports (name, value, domain,
# path, secure, httpOnly, hostOnly, session, expirationDate in seconds,
# sameSite), as a bare array or inside a {"cookies": [...]} object (a
# session blob, whose local and session storage a cookie jar does not use).

def strip_dot(+d: String) -> String:
  String.to_lower(Bool.pick(String, String.starts_with(d, "."), String.drop(d, 1n), d))

def cookie_of(+c: Json.Json) -> Ck.Cookie:
  +d = Json.text_or(Json.get(c, "domain"), "")
  +host_only = Json.bool_or(Json.get(c, "hostOnly"), Bool.not(String.starts_with(d, ".")))
  +session = Json.bool_or(Json.get(c, "session"), False{})
  +p = Json.text_or(Json.get(c, "path"), "/")
  Ck.Cookie{
    Json.text_or(Json.get(c, "name"), ""), Json.text_or(Json.get(c, "value"), ""),
    strip_dot(d), host_only, Bool.pick(String, String.is_empty(p), "/", p),
    Bool.pick(U32, session, 0, Json.u32_or(Json.get(c, "expirationDate"), 0)),
    Json.bool_or(Json.get(c, "secure"), False{}), Json.bool_or(Json.get(c, "httpOnly"), False{}),
    Json.text_or(Json.get(c, "sameSite"), "")
  }

def cookies_of(xs: List<&2, Json.Json>, +jar: List<&2, Ck.Cookie>, +now: U32) -> List<&2, Ck.Cookie>:
  match xs:
    case Nil{}:
      jar
    case Con{x, t}:
      cookies_of(t, Ck.store(jar, cookie_of(x), now), now)

def list_of(m: Maybe<&2, Json.Json>) -> List<&2, Json.Json>:
  match m:
    case None{}:
      Nil{}
    case Some{v}:
      match v:
        case Json.JArr{items}:
          items
        case Json.JObj{keys, vals}:
          Json.arr_or_empty(Json.get(Json.JObj{keys, vals}, "cookies"))
        case Json.JNull{}:
          Nil{}
        case Json.JBool{b}:
          Nil{}
        case Json.JNum{n}:
          Nil{}
        case Json.JStr{s}:
          Nil{}

# Add a JSON session's cookies to a jar (expired ones are dropped).
def import_json(+text: String, +jar: List<&2, Ck.Cookie>, +now: U32) -> List<&2, Ck.Cookie>:
  cookies_of(list_of(Json.parse(text)), jar, now)

def jb(b: Bool) -> Json.Json:
  Json.JBool{b}

def cookie_json(c: Ck.Cookie) -> Json.Json:
  match c:
    case Ck.Cookie{name, value, +domain, +host_only, path, +expires, secure, http_only, same_site}:
      Json.JObj{["name", "value", "domain", "hostOnly", "path", "secure", "httpOnly", "session", "expirationDate", "sameSite"],
        [Json.JStr{name}, Json.JStr{value}, Json.JStr{Bool.pick(String, host_only, domain, "." ++ domain)}, jb(host_only),
         Json.JStr{path}, jb(secure), jb(http_only), jb(U32.is_zero(expires)), Json.JNum{U32.show(expires)}, Json.JStr{same_site}]}

def jar_items(xs: List<&2, Ck.Cookie>) -> List<&2, Json.Json>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{c, t}:
      cookie_json(c) <> jar_items(t)

# The jar in the same chrome.cookies shape (reading a sliding session back).
def export_json(+jar: List<&2, Ck.Cookie>) -> Json.Json:
  Json.JArr{jar_items(jar)}
