"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
function virtualTree(type, failRead = false) {
  const calls = [], closed = [], module = { exports: {} };
  const io = { constants: { ...fs.constants, O_NOFOLLOW: 0x20000, O_DIRECTORY: 0x10000, O_NONBLOCK: 0x800 },
    openSync(p, flags) { calls.push({ p, flags }); if (calls.length === 2 && failRead) throw Object.assign(Error("denied"), { code: "EACCES" }); return calls.length === 1 ? 10 : 20; },
    fstatSync() { return { isDirectory: () => type === "directory", isFile: () => type === "file" }; }, closeSync(fd) { closed.push(fd); }
  };
  const context = { module, exports: module.exports, process: { platform: "linux", arch: "x64", getuid: () => 0 }, require(name) { if (name === "node:fs") return io; if (name === "./policy") return require("../app/app/server/lib/policy"); return require(name); } };
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, "../app/app/server/lib/tree.js"), "utf8"), context);
  return { api: module.exports, calls, closed, constants: io.constants };
}
test("descriptor opener checks inode via O_PATH before reopening an ordinary file", () => {
  const f = virtualTree("file"); assert.equal(f.api.openOrdinary("/proc/self/fd/3/data"), 20);
  assert(f.calls[0].flags & 0x200000); assert(f.calls[0].flags & f.constants.O_NOFOLLOW);
  assert.equal(f.calls[1].p, "/proc/self/fd/10"); assert.deepEqual(f.closed, [10]);
});
test("device/FIFO/symlink replacement is rejected before a readable open", () => {
  const f = virtualTree("other"); assert.throws(() => f.api.openOrdinary("/proc/self/fd/3/data"), /特殊文件/);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.closed, [10]);
});
test("guard descriptor closes even when actual read access fails", () => {
  const f = virtualTree("file", true); assert.throws(() => f.api.openOrdinary("/proc/self/fd/3/data"), /denied/); assert.deepEqual(f.closed, [10]);
});
