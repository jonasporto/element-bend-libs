import Base

# A listening socket on the loopback interface only. A DevTools port must
# not answer the network: whoever reaches it drives the browser and reads its
# cookies (Chrome binds 127.0.0.1 too). Base's TCP.listen bound 0.0.0.0 until
# 2.0.32, so this was our own effect; it now takes the address.

def Loopback.listen(port: U32) -> IO(Result<&1, &1, U32 & String, Listener>):
  TCP.listen("127.0.0.1", port)
