"use strict";
const zlib = require("node:zlib");
const crypto = require("node:crypto");
function parseTar(data) {
  if (data[0] === 0x1f && data[1] === 0x8b) data = zlib.gunzipSync(data, { maxOutputLength: 128 * 1024 * 1024 });
  const entries = [];
  for (let offset = 0; offset + 512 <= data.length;) {
    const header = data.subarray(offset, offset + 512);
    if (header.every(x => x === 0)) break;
    const str = (a, b) => header.subarray(a, b).toString().replace(/\0.*$/, "");
    const stored = parseInt(str(148, 156).trim(), 8), checksum = header.reduce((sum, n, i) => sum + (i >= 148 && i < 156 ? 32 : n), 0);
    if (stored !== checksum) throw Error("Invalid tar checksum");
    const name = [str(345, 500), str(0, 100)].filter(Boolean).join("/").replace(/^\.\//, "");
    const size = parseInt(str(124, 136).trim(), 8) || 0, type = str(156, 157) || "0";
    if (!name || name.startsWith("/") || name.split("/").includes("..") || !["0", "5"].includes(type)) throw Error("Unsupported archive entry: " + name + " type " + type);
    if (offset + 512 + size > data.length) throw Error("Truncated tar");
    entries.push({ name: name.replace(/\/$/, ""), type, mode: parseInt(str(100, 108), 8), data: Buffer.from(data.subarray(offset + 512, offset + 512 + size)) });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (new Set(entries.map(x => x.name)).size !== entries.length) throw Error("Duplicate archive entry");
  return entries;
}
function packTar(entries, epoch = 0) {
  const buffers = [];
  for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name, "en"))) {
    const h = Buffer.alloc(512), bytes = entry.type === "5" ? Buffer.alloc(0) : entry.data;
    let name = entry.name, prefix = "";
    if (Buffer.byteLength(name) > 100) {
      const positions = [...name.matchAll(/\//g)].map(m => m.index).reverse();
      const split = positions.find(i => Buffer.byteLength(name.slice(0, i)) <= 155 && Buffer.byteLength(name.slice(i + 1)) <= 100);
      if (split === undefined) throw Error("Archive path too long: " + name);
      prefix = name.slice(0, split); name = name.slice(split + 1);
    }
    const octal = (n, len) => n.toString(8).padStart(len - 1, "0") + "\0";
    h.write(name, 0, 100); h.write(octal(entry.mode, 8), 100); h.write(octal(0, 8), 108); h.write(octal(0, 8), 116);
    h.write(octal(bytes.length, 12), 124); h.write(octal(epoch, 12), 136); h.fill(32, 148, 156); h.write(entry.type, 156);
    h.write("ustar\0", 257); h.write("00", 263); h.write("root", 265); h.write("root", 297); h.write(prefix, 345, 155);
    const sum = h.reduce((n, x) => n + x, 0); h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    buffers.push(h, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  buffers.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(buffers), { level: 9 });
}
function normalizeFpk(data, epoch = 0) {
  const outer = parseTar(data), app = outer.find(x => x.name === "app.tgz"), manifest = outer.find(x => x.name === "manifest");
  if (!app || !manifest) throw Error("Missing manifest/app.tgz");
  const inner = parseTar(app.data).map(x => ({ ...x, mode: x.type === "5" || x.name.endsWith(".sh") ? 0o755 : 0o644 }));
  app.data = packTar(inner, epoch);
  const md5 = crypto.createHash("md5").update(app.data).digest("hex");
  let text = manifest.data.toString("utf8");
  if (!/^checksum\s*=/m.test(text)) throw Error("fnpack manifest has no checksum");
  text = text.replace(/^checksum\s*=.*$/m, "checksum              = " + md5); manifest.data = Buffer.from(text);
  const normalized = outer.map(x => ({ ...x, mode: x.type === "5" || x.name.startsWith("cmd/") ? 0o755 : 0o644 }));
  const result = packTar(normalized, epoch);
  const verified = parseTar(result), payload = verified.find(x => x.name === "app.tgz").data;
  if (crypto.createHash("md5").update(payload).digest("hex") !== md5) throw Error("Package checksum verification failed");
  return result;
}
module.exports = { parseTar, packTar, normalizeFpk };
