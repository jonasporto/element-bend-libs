import Base

# Host effects the network layer needs beyond Base:
# - TCP.connect takes a numeric IPv4 address only: Net.resolve does DNS.
# Raw bytes (0..255) in and out were our own effects until Base 2.0.32 added
# TCP.recv_bytes and TCP.send_bytes; Net.* now name those. Base refuses
# (EINVAL) a value past 255 where ours truncated it to a byte, and a recv
# of 0 bytes where ours answered an empty read that looked like EOF.

def Net.resolve(host: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./effs/net_resolve.c"
  import "./effs/net_resolve.js"

# Base 2.0.36 (PR #1259) says the end of the peer's data as None (a read of
# Some{[]} never comes) and hands a failed send back what the kernel did not
# take. Element's readers test an empty read for the end (fetch's read_loop,
# main.bend's got_data, the TLS record reader) and never resend, so both are
# folded here to the 2.0.35 shapes every caller keeps.
def recv_fold(p: Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>) ->
  Socket & Result<&1, &1, U32 & String, List<&2, U32>>:
  match p:
    case (s, r):
      match r:
        case Fail{e}:
          (s, Fail{e})
        case Done{m}:
          match m:
            case None{}:
              (s, Done{Nil{}})
            case Some{bs}:
              (s, Done{bs})

def send_fold(p: Socket & Result<&1, &1, (U32 & String) & List<&2, U32>, Unit>) ->
  Socket & Result<&1, &1, U32 & String, Unit>:
  match p:
    case (s, r):
      match r:
        case Fail{e}:
          match e:
            case (err, rest):
              (s, Fail{err})
        case Done{u}:
          (s, Done{Unit{}})

def Net.recv_bytes(sock: Socket, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
    got : Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>> <- TCP.recv_bytes(sock, max)
    return recv_fold(got)

def Net.send_bytes(sock: Socket, data: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & Result<&1, &1, (U32 & String) & List<&2, U32>, Unit> <- TCP.send_bytes(sock, data)
    return send_fold(got)

# A text send, the same way (the HTTP request line and headers). Bend 2.0.38+
# hands the unsent bytes back as a List<&2, U32> (a write cut inside a UTF-8
# character loses nothing); it was a String.
def Net.send(sock: Socket, data: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & Result<&1, &1, (U32 & String) & List<&2, U32>, Unit> <- TCP.send(sock, data)
    return send_fold(got)
