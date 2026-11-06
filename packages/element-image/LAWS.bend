import Base
import ./png.bend as Png

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# Python's zlib, which also decompresses the stored block).
law png_crc32_check_value:
  {Png.crc32(Png.ascii("123456789")) == 3421780262 : U32}

law png_adler32_wikipedia:
  {Png.adler32(Png.ascii("Wikipedia")) == 300286872 : U32}
