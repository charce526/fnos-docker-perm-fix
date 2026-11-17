"use strict";
// Exercising the real planner/executor state machine with a virtual kernel and Docker snapshot.
const test = require("node:test"), assert = require("node:assert/strict"), vm = require("node:vm"), fs = require("node:fs"), path = require("node:path"), { EventEmitter } = require("node:events");
const P = require("../app/app/server/lib/policy");
function fixture(options = {}) {
  const root = { dev: 2n, ino: 10n, mode: 0o40000n, uid: 999n, gid: 999n, nlink: 2n, ctimeNs: 1n, isDirectory: () => true, isFile: () => false };
  const file = { dev: 2n, ino: 11n, mode: 0o100000n, uid: 999n, gid: 999n, nlink: 1n, ctimeNs: 1n, isDirectory: () => false, isFile: () => true };
  const acl = () => `user::${Number(file.mode) & 0o400 ? "r" : "-"}${Number(file.mode) & 0o200 ? "w" : "-"}-\nuser:2000:r--\ngroup::---\nmask::r--\nother::---\ndefault:user::rwx\n`;
  const events = [], writes = [], closed = [];
  const c = { Id: "a".repeat(64), Name: "/test", Image: "image", Config: { User: "999:999", Image: "example" }, HostConfig: {}, State: { Running: !!options.running }, Mounts: [{ Type: "bind", Source: "/vol1/project", Destination: "/data", RW: true }] };
  const data = { info: { DockerRootDir: "/var/lib/docker" }, containers: [c] };
  const obj = fd => fd === 1 ? root : file;
  const fakeFs = { constants: fs.constants, realpathSync: p => p, existsSync: p => options.noGetcap ? !p.includes("getcap") : true,
    readFileSync: () => "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 / /vol1 rw - ext4 /dev/data rw\n",
    statSync: () => root, fstatSync: fd => obj(fd),
    openSync: p => p.startsWith("/proc/self/fd/") ? Number(p.split("/").at(-1)) : 900,
    closeSync: fd => closed.push(fd), fsyncSync() {}, writeSync(fd, value) { events.push(JSON.parse(value)); },
    fchownSync(fd, uid, gid) { writes.push(["chown", uid, gid]); obj(fd).uid = BigInt(uid); obj(fd).gid = BigInt(gid); obj(fd).ctimeNs++; },
    fchmodSync(fd, mode) { if (options.chmodFailure) throw Object.assign(Error("simulated chmod failure"), { code: "EROFS" }); writes.push(["chmod", mode]); obj(fd).mode = BigInt(0o100000 | mode); obj(fd).ctimeNs++; }
  };
  const objects = () => [{ relativePath: ".", ...P.stateToken(root) }, { relativePath: "data", ...P.stateToken(file) }];
  const inventory = (_rootFd, { recursive = true } = {}) => {
    const selected = recursive ? objects() : objects().slice(0, 1);
    return { objects: selected, exclusions: [], digest: P.digest(selected) };
  };
  const fakeT = { linuxReady: () => true, inventory, openRoot: () => 1, fdPath: fd => "/proc/self/fd/" + fd,
    withObject(rootFd, relative, fn) { fn(relative === "." ? 1 : 2); },
    actionsFor: require("../app/app/server/lib/tree").actionsFor,
    probe: async () => ({ complete: !options.probeIncomplete, evidence: options.probeDenied ? [{ relativePath: "data", missing: ["read"] }] : [], checked: 2 })
  };
  const fakeChildProcess = { spawn(executable) {
    const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.kill = () => {};
    setImmediate(() => { if (executable.includes("getcap")) { if (options.fileCapabilities) child.stdout.emit("data", "/proc/self/fd/3 cap_net_bind_service=ep\n"); } else child.stdout.emit("data", acl()); child.emit("close", options.aclFailure ? 1 : 0); });
    return child;
  } };
  const fakeD = { collect: async () => data, identity: async () => ({ uid: 999, gid: 999, groups: [], confidence: "verified", mappingVerified: true }), };
  const module = { exports: {} }, context = { module, exports: module.exports, __dirname: "/virtual/server", __filename: "/virtual/server/worker.js", Buffer, console, setTimeout, clearTimeout, process: { ppid: 10, env: {}, version: "v22.0.0", connected: false, getuid: () => 0 }, require(name) {
    if (name === "node:fs") return fakeFs;
    if (name === "node:child_process") return fakeChildProcess;
    if (name === "./lib/docker") return fakeD;
    if (name === "./lib/tree") return fakeT;
    if (name === "./lib/policy") return P;
    return require(name);
  } };
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, "../app/app/server/worker.js"), "utf8"), context);
  const rootInventory = inventory(null, { recursive: false });
  const item = { key: "a".repeat(64), container: "test", containerId: c.Id, source: "/vol1/project", real: "/vol1/project", target: "/data", token: P.stateToken(root), signature: P.containerSignature(c), treeDigest: rootInventory.digest, requirement: "read", identity: { uid: 999, gid: 999, groups: [], mappingVerified: true }, actions: [{ relativePath: "data", before: objects()[1], after: { uid: options.changeOwner ? 1000 : 999, gid: 999, mode: 0o400 }, acl: acl() }] };
  const plan = { schemaVersion: 2, planId: "plan", expiresAt: new Date(Date.now() + 60000).toISOString(), items: [item] };
  const snapshot = () => ({ schemaVersion: 2, scanId: "scan", createdAt: new Date().toISOString(), complete: true, profile: "read", capabilities: { getfacl: "/usr/bin/getfacl" }, containers: [{ id: c.Id, name: "test", signature: P.containerSignature(c), identity: { uid: 999, gid: 999, groups: [], confidence: "verified", mappingVerified: true }, mounts: [{ ...item, canPlanRepair: true, safetyStatus: "eligible" }] }] });
  return { api: module.exports, plan, file, root, c, data, writes, events, closed, context, snapshot, execute: () => module.exports.execute({ plan, journalPath: "journal.jsonl" }) };
}
test("metadata identity compares token fields rather than relative-path wrapper", () => {
  const token = { dev: "1", ino: "2", uid: 999, gid: 999, mode: 0o700, nlink: 1, ctimeNs: "1", type: "file" };
  assert(P.sameObject(token, { relativePath: "child", ...token })); assert(!P.sameObject(token, { ...token, ctimeNs: "2" }));
});
test("executor preserves ACL, journals before/after and requires an actual access recheck", async () => {
  const f = fixture(), result = await f.execute();
  assert.equal(result.results[0].status, "verified_success", JSON.stringify(result)); assert.deepEqual(f.writes, [["chmod", 0o400]]);
  assert.deepEqual(f.events.map(x => x.type), ["snapshot", "before", "after", "item_result", "finished"]);
  assert.equal(f.events[1].object.acl.includes("user:2000:r--"), true);
});
test("running container is repaired after runtime identity is rechecked", async () => {
  const f = fixture({ running: true }), result = await f.execute();
  assert.equal(result.results[0].status, "verified_success");
  assert.deepEqual(f.writes, [["chmod", 0o400]]);
  assert.deepEqual(f.events.map(x => x.type), ["snapshot", "before", "after", "item_result", "finished"]);
});
test("expired plan and changed identity/container binding do not mutate", async () => {
  const expired = fixture(); expired.plan.expiresAt = new Date(0).toISOString(); await assert.rejects(expired.execute(), /过期/); assert.deepEqual(expired.writes, []);
  const changed = fixture(); changed.c.Config.User = "1000:1000"; await assert.rejects(changed.execute(), /变化/); assert.deepEqual(changed.writes, []);
  const mapped = fixture(); mapped.data.info.SecurityOptions = ["name=userns"]; await assert.rejects(mapped.execute(), /身份映射/); assert.deepEqual(mapped.writes, []);
});
test("changed mount-root metadata aborts the whole batch before mutation", async () => {
  const rootChanged = fixture(); rootChanged.root.ctimeNs++; await assert.rejects(rootChanged.execute(), /挂载对象或权限/); assert.deepEqual(rootChanged.writes, []);
});
test("chown followed by chmod failure is partial, not a JSON parse failure or success", async () => {
  const f = fixture({ changeOwner: true, chmodFailure: true }), result = await f.execute();
  assert.equal(result.results[0].status, "partial_failure"); assert.equal(result.results[0].errors[0].code, "EROFS"); assert.equal(result.results[0].errors[0].pending, "data");
  assert.equal(f.events.some(x => x.type === "after"), false); assert.doesNotThrow(() => JSON.parse(JSON.stringify(result)));
});
test("access verification denied/incomplete cannot become verified success", async () => {
  for (const options of [{ probeDenied: true }, { probeIncomplete: true }]) { const f = fixture(options); assert.equal((await f.execute()).results[0].status, "partial_failure"); }
});
test("ACL read failure prevents mutation and yields a per-item result", async () => { const f = fixture({ aclFailure: true }); assert.equal((await f.execute()).results[0].status, "failed"); assert.deepEqual(f.writes, []); });
test("file capabilities or missing getcap prevent destructive ownership changes", async () => {
  for (const options of [{ changeOwner: true, fileCapabilities: true }, { changeOwner: true, noGetcap: true }]) { const f = fixture(options); const result = await f.execute(); assert.equal(result.results[0].status, "failed"); assert.deepEqual(f.writes, []); }
});
test("orphaned worker stops without mutation", async () => { const f = fixture(); f.context.process.ppid = 1; assert.equal((await f.execute()).results[0].status, "interrupted"); assert.deepEqual(f.writes, []); });
test("planner snapshots exact changed objects without mutating them", async () => {
  const f = fixture(), s = f.snapshot();
  const plan = await f.api.buildPlan({ scan: s, keys: [s.containers[0].mounts[0].key], action: "align-container-identity" });
  assert.equal(plan.items.length, 1); assert.equal(plan.items[0].actions.length, 1); assert.equal(plan.items[0].actions[0].relativePath, ".");
  assert.equal(plan.items[0].actions[0].after.uid, 999); assert.equal(plan.items[0].actions[0].after.mode, 0o500); assert.match(plan.items[0].actions[0].acl, /user:2000:r--/); assert.deepEqual(f.writes, []);
});
test("planner accepts an engine warning when the selected root is safely plannable", async () => {
  const f = fixture(), s = f.snapshot(), key = s.containers[0].mounts[0].key;
  assert.equal((await f.api.buildPlan({ scan: { ...s, complete: false }, keys: [key], action: "align-container-identity" })).items.length, 1);
  await assert.rejects(f.api.buildPlan({ scan: { ...s, createdAt: new Date(0).toISOString() }, keys: [key], action: "align-container-identity" }));
  await assert.rejects(f.api.buildPlan({ scan: s, keys: ["b".repeat(64)], action: "align-container-identity" }), /不可建立/);
  assert.deepEqual(f.writes, []);
});
test("planner cannot use stale root metadata and requires verified declared identity", async () => {
  const f = fixture(), s = f.snapshot(), key = s.containers[0].mounts[0].key;
  f.root.ctimeNs++;
  await assert.rejects(f.api.buildPlan({ scan: s, keys: [key], action: "align-container-identity" }), /对象或权限/);
  const declared = fixture(), reference = declared.snapshot(), declaredKey = reference.containers[0].mounts[0].key;
  reference.containers[0].identity.confidence = "reference";
  await assert.rejects(declared.api.buildPlan({ scan: reference, keys: [declaredKey], action: "align-container-identity" }), /修复身份不可靠/);
});
