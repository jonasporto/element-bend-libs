import Base

# Binary output: Base's File.write encodes a String as UTF-8, so a byte >= 128
# cannot be written as itself. Bytes.write takes the bytes (0..255) as a
# List<U32>. A .c + .js host effect, like Base's own.

def Bytes.write(file: File, data: List<&2, U32>) ->
  IO(File & Result<&1, &1, U32 & String, Unit>):
  import "./effs/bytes_write.c"
  import "./effs/bytes_write.js"
