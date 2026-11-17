"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const T = require("../app/app/server/lib/tree");
const P = require("../app/app/server/lib/policy");
const enabled = process.platform === "linux" && process.getuid?.() === 0 && process.env.RUN_LINUX_PERMISSION_TESTS === "1";
test("Linux real permission and descriptor integration (explicit isolated root environment)", { skip: !enabled }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "perm-fix-linux-"));
  t.after(() => { const actual = fs.realpathSync(dir), relative = path.relative(fs.realpathSync(os.tmpdir()), actual); assert(relative.startsWith("perm-fix-linux-") && !relative.startsWith("..") && !relative.includes(path.sep)); fs.rmSync(actual, { recursive: true, force: true }); });
  const source = path.join(dir, "source"); fs.mkdirSync(source); fs.writeFileSync(path.join(source, "data"), "test data");
  fs.chownSync(source, 999, 999); fs.chownSync(path.join(source, "data"), 999, 999); fs.chmodSync(source, 0o700); fs.chmodSync(path.join(source, "data"), 0o600);
  const root = T.openRoot(source); t.after(() => fs.closeSync(root));
  await t.test("700 owner directory and 600 file pass; inaccessible host ancestors do not create a false positive", async () => {
    fs.chmodSync(dir, 0o700);
    const r = await T.probe(root, { uid: 999, gid: 999, groups: [] }, "read-write", path.resolve(__dirname, "../app/app/server/worker.js"));
    assert.equal(r.complete, true); assert.deepEqual(r.evidence, []);
  });
  await t.test("same-owner 000 file yields exact failing child path", async () => {
    fs.chmodSync(path.join(source, "data"), 0);
    const r = await T.probe(root, { uid: 999, gid: 999, groups: [] }, "read", path.resolve(__dirname, "../app/app/server/worker.js"));
    assert(r.evidence.some(x => x.relativePath === "data" && x.missing.includes("read")));
    fs.chmodSync(path.join(source, "data"), 0o600);
  });
  await t.test("supplementary group grants access without chown", async () => {
    fs.chownSync(path.join(source, "data"), 1000, 2000); fs.chmodSync(path.join(source, "data"), 0o640);
    const r = await T.probe(root, { uid: 999, gid: 999, groups: [2000] }, "read", path.resolve(__dirname, "../app/app/server/worker.js"));
    assert.deepEqual(r.evidence, []);
  });
  await t.test("descriptor mutation changes only selected object", () => {
    T.withObject(root, "data", fd => { fs.fchownSync(fd, 999, 999); fs.fchmodSync(fd, 0o600); const s = P.stateToken(fs.fstatSync(fd, { bigint: true })); assert.equal(s.mode, 0o600); assert.equal(s.uid, 999); });
  });
  await t.test("symbolic links and hardlinks disqualify recursive modification", () => {
    fs.symlinkSync(path.join(source, "data"), path.join(source, "link")); fs.linkSync(path.join(source, "data"), path.join(dir, "outside-hardlink"));
    const tree = T.inventory(root); assert(tree.exclusions.some(x => x.reason === "symlink")); assert(tree.exclusions.some(x => x.reason === "hardlink"));
    assert.throws(() => T.withObject(root, "link", () => assert.fail("followed a symlink")));
  });
});
