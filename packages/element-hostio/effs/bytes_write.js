// Bytes.write on the JS target: raw bytes to a file descriptor.
function bytes_write(file, data) {
  const fs = require("fs");
  const out = [];
  for (let xs = data; xs.$ === "Con"; xs = xs.tail) out.push(Number(xs.head) & 255);
  const b = Uint8Array.from(out);
  let at = 0;
  try {
    while (at < b.length) at += fs.writeSync(file, b, at, b.length - at, null);
    return io_tup(file, io_done({ $: "Unit" }));
  } catch (e) {
    return io_tup(file, io_fail(Math.abs(e.errno ?? 5)));
  }
}

// registered under its def (Bend 2.0.28: a JS effect registers as a C one does)
io_eff(CID(Bytes.write), bytes_write);
