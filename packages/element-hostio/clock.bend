import Base

# Wall-clock time: Base's IO.now is a monotonic tick (CLOCK_MONOTONIC), fine
# for measuring but not for asking what day it is. Certificate validity needs
# the calendar, so Clock.unix answers seconds since 1970-01-01 UTC
# (CLOCK_REALTIME). A .c + .js host effect, like Base's own.

def Clock.unix() -> IO(Nat):
  import "./effs/clock_unix.c"
  import "./effs/clock_unix.js"
