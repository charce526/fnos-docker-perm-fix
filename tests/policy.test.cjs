"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const P = require("../app/app/server/lib/policy");
const T = require("../app/app/server/lib/tree");
const M = require("../app/app/server/public/model");
const W = require("../app/app/server/worker");
const { parseTar, packTar, normalizeFpk } = require("../scripts/archive.cjs");
for (const p of ["/", "/etc", "/etc/ssh", "/var/lib/docker/volumes", "/vol1", "/vol1/@appcenter/example", "/vol2/@appdata", "/proc/1", "/tmp", "/opt"]) test("protected subtree " + p, () => assert.equal(P.protectedPath(p), true));
for (const p of ["/vol1/projects/db", "/etc-backup", "/data/a|name", "/vol1/中文 空格", "/vol2/@appshare/docker/postgres", "/vol2/@docker/project/data", "/vol2/@appdata/postgres/data", "/mnt/projects/db", "/opt/projects/data", "/data/a\\b"]) test("valid project path " + p, () => assert.equal(P.protectedPath(p), false));
for (const p of ["/vol1/a\nb", "/vol1/a\0b", "/data/../etc", "/data//a", "relative"]) test("reject ambiguous path " + JSON.stringify(p), () => assert.equal(P.validPath(p), false));
test("component overlap avoids common-prefix false positives", () => { assert(P.overlap("/data/a", "/data/a/b")); assert(P.overlap("/data/a/b", "/data/a")); assert(!P.overlap("/data/a", "/data/ab")); });
test("extra protected runtime root", () => assert(P.protectedPath("/vol1/docker-root/volumes", ["/vol1/docker-root"])));
test("numeric identity canonicalizes values, never guesses missing group", () => { assert.equal(P.numericIdentity("0999:0999").uid, 999); assert.equal(P.numericIdentity("999"), null); assert.equal(P.numericIdentity("postgres"), null); assert.equal(P.numericIdentity("2147483648:0"), null); });
test("batch keys deduplicate and reject bad formats/limits", () => { const k = "a".repeat(64); assert.deepEqual(P.uniqueKeys([k, k]), [k]); assert.throws(() => P.uniqueKeys(["$(id)"])); assert.throws(() => P.uniqueKeys(Array(101).fill(k))); assert.throws(() => P.uniqueKeys([])); });
test("special bits are separated correctly in ordinary mode operations", () => { assert.equal(P.desiredMode(0o2750, "directory", "read-write"), 0o2750); assert.equal(P.desiredMode(0o1700, "directory", "read"), 0o1700); assert.equal(P.desiredMode(0o044, "file", "read-write"), 0o644); });
const table = P.parseMountInfo("1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 / /vol1 rw - btrfs /dev/data rw\n");
test("mountinfo decoding and supported project mount", () => { assert.equal(P.mountSafety("/vol1/projects", table).code, "eligible"); assert.equal(P.parseMountInfo("3 1 8:2 / /space\\040dir rw - ext4 /dev/a rw")[0].point, "/space dir"); });
test("cross-device nested mount blocks modification", () => assert.equal(P.mountSafety("/vol1/project", [...table, { ...table[1], id: "3", device: "8:3", point: "/vol1/project/sub" }]).code, "nested_mount"));
test("same-device bind child blocks modification", () => assert.equal(P.mountSafety("/vol1/project", [...table, { ...table[1], id: "3", point: "/vol1/project/sub", root: "/other" }]).code, "nested_mount"));
test("root-only repair ignores child mounts because they are outside the modified object", () => assert.equal(P.mountSafety("/vol1/project", [...table, { ...table[1], id: "3", device: "8:3", point: "/vol1/project/sub" }], { recursive: false }).code, "eligible"));
test("external bind alias is not considered exclusive", () => assert.equal(P.mountSafety("/vol1/project", [...table, { ...table[1], id: "3", point: "/another-view", root: "/project" }]).code, "shared_overlap"));
test("read-only and unsupported filesystems block repair", () => { assert.equal(P.mountSafety("/vol1/project", [table[0], { ...table[1], options: ["ro"] }]).code, "unsupported"); assert.equal(P.mountSafety("/vol1/project", [table[0], { ...table[1], fsType: "nfs" }]).code, "unsupported"); });
test("stopped/unknown container overlaps block safety", () => { const a = { containerId: "a", name: "a", real: "/vol1/project", token: { type: "directory", dev: "1", ino: "2" } }, b = { containerId: "b", name: "b", real: "/vol1/project/db", token: { type: "directory", dev: "1", ino: "3" } }; assert.equal(W.safety(a, [a, b], table, []).code, "shared_overlap"); });
test("inode aliases block safety even without a lexical overlap", () => { const a = { name: "a", real: "/vol1/a", token: { type: "directory", dev: "1", ino: "2" } }, b = { name: "b", real: "/vol1/b", token: a.token }; assert.equal(W.safety(a, [a, b], table, []).code, "shared_overlap"); });
test("missing, special and hardlinked objects cannot become candidates", () => {
  assert.equal(W.safety({ error: "ENOENT" }, [], [], []).code, "missing");
  assert.equal(W.safety({ real: "/vol1/project", token: { type: "other" } }, [], table, []).code, "unsupported");
  assert.equal(W.safety({ real: "/vol1/project", token: { type: "file", nlink: 2 } }, [], table, []).code, "unsupported");
  assert.equal(W.safety({ real: "/vol1/project", token: { type: "file", nlink: 1, dev: "1", ino: "2" } }, [], table, []).code, "eligible");
});
test("an unrelated unreadable mount no longer blocks a valid root object", () => { const m = { real: "/vol1/project", token: { type: "directory", dev: "1", ino: "2" } }; assert.equal(W.safety(m, [m, { error: "EACCES" }], table, []).code, "eligible"); });
const objects = [ { relativePath: ".", uid: 999, gid: 20, mode: 0o100, type: "directory" }, { relativePath: "config", uid: 0, gid: 0, mode: 0o444, type: "file" } ];
test("single repair action aligns the mount root to the container identity", () => {
  const changes = T.actionsFor(objects, { uid: 999, gid: 999 }, "read");
  assert.equal(changes.length, 2); assert.deepEqual(changes[0].after, { uid: 999, gid: 999, mode: 0o500 }); assert.deepEqual(changes[1].after, { uid: 999, gid: 999, mode: 0o444 });
});
test("ACL invariant preserves named/group/default entries while allowing owner bits", () => { const a = "user::r--\nuser:1000:r--\ngroup::---\nmask::r--\nother::---\ndefault:user::rwx\n"; assert.equal(W.aclInvariant(a), W.aclInvariant(a.replace("user::r--", "user::rw-"))); assert.notEqual(W.aclInvariant(a), W.aclInvariant(a.replace("user:1000:r--", "user:1000:rw-"))); });
test("container snapshot rejects same-name replacement and altered mount/user", () => { const c = { Id: "a", Image: "image", Config: { User: "999:999" }, HostConfig: {}, Mounts: [] }; const s = P.containerSignature(c); assert.notEqual(P.containerSignature({ ...c, Id: "b" }), s); assert.notEqual(P.containerSignature({ ...c, Config: { User: "1000:1000" } }), s); assert.equal(P.containerSignature({ ...c, State: { Running: false } }), s); });
const snapshot = { containers: [{ id: "a", name: "alpha", image: "demo", running: true, identity: { uid: 999 }, mounts: [{ key: "a".repeat(64), source: "/a", target: "/a", reason: "", evidence: [], status: "permission_denied", canPlanRepair: true }] }, { id: "b", name: "beta", image: "demo", running: false, identity: { uid: 1000 }, mounts: [{ key: "b".repeat(64), source: "/b", target: "/b", reason: "", evidence: [], status: "ownerdiff", canPlanRepair: true }] }] };
test("UI select all and deselect operate on one authoritative collection", () => { const rows = M.flatten(snapshot), selected = M.selectVisible(new Set(), rows, true); assert.equal(M.selection(selected, rows, rows).count, 2); const cleared = M.selectVisible(selected, rows, false); assert.deepEqual([...cleared], []); });
test("UI filtering keeps bulk selection scoped to visible rows", () => { const all = M.flatten(snapshot), rows = M.visible(all, { search: "alpha" }); const selected = M.selectVisible(new Set(), rows, true); assert.deepEqual([...selected], ["a".repeat(64)]); assert.equal(M.selection(new Set(all.map(x => x.m.key)), rows, all).hidden, 1); });
test("visible rows follow mount paths and ownership differences count as normal", () => { const all = M.flatten(snapshot); assert.deepEqual(M.visible(all).map(x => x.m.source), ["/a", "/b"]); assert.equal(M.stats(all).attention, 1); assert.equal(M.stats(all).normal, 1); });

test("UI uses four outcomes without treating partial or protected checks as normal", () => {
  for (const [raw, expected] of Object.entries({ accessible: "normal", ownerdiff: "normal", permission_denied: "attention", write_limited: "attention", missing: "attention", not_directory: "attention", not_checked: "incomplete", identity_unknown: "incomplete", unverified: "incomplete", root_checked: "incomplete", protected: "incomplete", shared_overlap: "incomplete", unsupported: "incomplete", scan_error: "error" })) assert.equal(M.statusOf({ status: raw }), expected);
  assert.equal(M.statusLabels.incomplete, "未检测");
  assert.equal(M.visible(M.flatten(snapshot), { status: "normal" }).length, 1);
});

test("UI groups Compose projects and summarizes every container including those without mounts", () => {
  const [a, b] = snapshot.containers;
  const grouped = M.projects({ containers: [{ ...a, project: "demo" }, { ...b, project: "demo" }, { ...b, id: "empty", name: "empty", mounts: [] }] });
  assert.equal(grouped.length, 2); assert.equal(grouped.find(p => p.name === "demo").containers.length, 2);
  assert.equal(grouped.find(p => p.name === "demo").status, "attention"); assert.equal(grouped.find(p => p.name === "empty").status, "incomplete");
  assert.equal(M.aggregate([{ status: "scan_error" }, { status: "permission_denied" }]), "error");
});
test("UI reports partial selection using indeterminate", () => { const all = M.flatten(snapshot); const s = M.selection(new Set([all[0].m.key]), all, all); assert.equal(s.checked, false); assert.equal(s.indeterminate, true); });
test("archive normalizer secures modes and updates nested checksum", () => {
  const inner = packTar([{ name: "server/test.js", type: "0", mode: 0o666, data: Buffer.from("source") }]);
  const outer = packTar([{ name: "app.tgz", type: "0", mode: 0o666, data: inner }, { name: "manifest", type: "0", mode: 0o666, data: Buffer.from("version = 1.1.0\nchecksum = old\n") }, { name: "cmd/main", type: "0", mode: 0o666, data: Buffer.from("#!/bin/bash\n") }]);
  const normalized = parseTar(normalizeFpk(outer)); assert.equal(normalized.find(x => x.name === "cmd/main").mode, 0o755); assert.equal(parseTar(normalized.find(x => x.name === "app.tgz").data)[0].mode, 0o644); assert.match(normalized.find(x => x.name === "manifest").data.toString(), /checksum\s*=\s*[a-f0-9]{32}/);
});
test("archive parser rejects path escape, links, corrupt checksums and duplicates", () => { assert.throws(() => parseTar(packTar([{ name: "../bad", type: "0", mode: 0o644, data: Buffer.from("") }]))); assert.throws(() => parseTar(packTar([{ name: "link", type: "2", mode: 0o777, data: Buffer.from("") }]))); });
