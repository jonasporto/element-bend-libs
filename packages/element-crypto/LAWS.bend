import Base
import ./sha256.bend as Sha256

# Laws over this package, from Element's own; `bend PROOF.bend` checks them.

# message, and a two-block message (448 bits).
law sha256_abc:
  {Sha256.hex_of_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" : String}

law sha256_empty:
  {Sha256.hex_of_text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" : String}

law sha256_two_blocks:
  {Sha256.hex_of_text("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" : String}
