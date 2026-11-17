"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const D = require("../app/app/server/lib/docker");
const id = "a".repeat(64), mapping = "0 0 4294967295\n";
function status(uid, gid, groups = [gid], caps = "0000000000000000") { return `Uid:\t${uid}\t${uid}\t${uid}\t${uid}\nGid:\t${gid}\t${gid}\t${gid}\t${gid}\nGroups:\t${groups.join(" ")}\nCapEff:\t${caps}\nNoNewPrivs:\t0\n`; }
function container(user = "999:999") { return { Id: id, Name: "/demo", Image: "sha256:image", Config: { User: user, Image: "image" }, HostConfig: {}, State: { Running: true }, Mounts: [] }; }
function reader(statuses, map = mapping) { return p => p.endsWith("_map") ? map : p.endsWith("/cgroup") ? "0::/docker/" + id : p.endsWith("/stat") ? "1 (demo) " + ["S", ...Array(18).fill("0"), "123"].join(" ") : statuses[/\/proc\/(\d+)\//.exec(p)[1]]; }
test("multiple actual container identities are probed but not repaired", async () => {
  for (const user of ["999:999", "", "postgres"]) {
    const identity = await D.identity(container(user), {}, async () => "PID\n11\n12\n", reader({ 11: status(999, 999), 12: status(1000, 1000) }));
    assert.equal(identity.confidence, "observed"); assert.equal(identity.canProbe, true); assert.equal(identity.uid, null); assert.equal(identity.candidates.length, 2); assert.match(identity.message, /多个/);
  }
});
test("root launcher does not hide a unique nonroot worker and its supplementary groups", async () => {
  const r = await D.identity(container(""), {}, async () => "PID\n11\n12\n", reader({ 11: status(0, 0), 12: status(999, 999, [999, 2000]) }));
  assert.equal(r.uid, 999); assert.deepEqual(r.groups, [999, 2000]); assert.equal(r.confidence, "verified");
});
test("root with DAC override is reported as privileged, not unknown", async () => { const r = await D.identity(container(), {}, async () => "PID\n11\n", reader({ 11: status(0, 0, [0], "0000000000000002") })); assert.equal(r.uid, 0); assert.equal(r.confidence, "root-privileged"); assert.equal(r.rootPrivileged, true); assert.equal(r.canProbe, false); });
test("root without DAC override remains unchecked", async () => { const r = await D.identity(container(), {}, async () => "PID\n11\n", reader({ 11: status(0, 0) })); assert.equal(r.uid, 0); assert.equal(r.confidence, "observed"); assert.equal(r.canProbe, false); });
test("mapped IDs, rootless and capabilities are not simulated as ordinary UID", async () => {
  const run = async () => "PID\n11\n";
  for (const r of [await D.identity(container(), {}, run, reader({ 11: status(999, 999) }, "0 231072 65536")), await D.identity(container(), { SecurityOptions: ["name=rootless"] }, run, reader({})), await D.identity(container(), {}, run, reader({ 11: status(999, 999, [], "0000000000000001") }))]) { assert.equal(r.uid, 999); assert.equal(r.canProbe, false); assert.notEqual(r.confidence, "unknown"); }
});
test("same UID/GID with different groups can still probe each root", async () => { const r = await D.identity(container(), {}, async () => "PID\n11\n12\n", reader({ 11: status(999, 999, [1]), 12: status(999, 999, [2]) })); assert.equal(r.uid, 999); assert.equal(r.canProbe, true); assert.equal(r.probeCandidates.length, 2); });
test("Docker membership does not require a particular cgroup path format", async () => { const read = reader({ 11: status(999, 999) }); const r = await D.identity(container(), {}, async () => "PID\n11\n", p => p.endsWith("/cgroup") ? "0::/custom/scope" : read(p)); assert.equal(r.confidence, "verified"); assert.equal(r.canProbe, true); });

test("changed PID membership or reused PID cannot supply verified credentials", async () => {
  let calls = 0;
  const r = await D.identity(container(), {}, async () => ++calls === 1 ? "PID\n11\n" : "PID\n12\n", reader({ 11: status(999, 999) }));
  assert.equal(r.canProbe, false); assert.match(r.message, /列表发生变化/);
  let stamps = 0; const read = reader({ 11: status(999, 999) });
  const reused = await D.identity(container(), {}, async () => "PID\n11\n", p => p.endsWith("/stat") ? read(p).replace(/123$/, String(++stamps)) : read(p));
  assert.equal(reused.canProbe, false); assert.match(reused.message, /替换/);
});
test("stopped identity is a reference only and no missing GID/root guess is made", async () => {
  const c = container(); c.State.Running = false;
  assert.equal((await D.identity(c, {})).confidence, "reference");
  for (const user of ["999", "postgres"]) { c.Config.User = user; const r = await D.identity(c, {}); assert.equal(r.confidence, "reference"); assert.equal(r.declaredUser, user); assert.equal(r.canProbe, false); }
  c.Config.User = ""; assert.equal((await D.identity(c, {})).confidence, "unknown");
});
test("real/effective/filesystem IDs must agree", () => assert.throws(() => D.procStatus(status(999, 999).replace("999\t999\t999\t999", "999\t1000\t999\t999"))));
test("Docker collection distinguishes empty daemon from failures", async () => {
  const result = await D.collect(async (_, args) => args[0] === "info" ? '{"DockerRootDir":"/vol1/docker"}' : "");
  assert.deepEqual(result.containers, []);
  await assert.rejects(D.collect(async () => { throw Error("daemon down"); }), /daemon down/);
});
test("partial inspect and malformed JSON invalidate the whole snapshot", async () => {
  for (const inspect of ["[]", "invalid"]) await assert.rejects(D.collect(async (_, args) => args[0] === "info" ? '{"DockerRootDir":"/vol1/docker"}' : args[0] === "ps" ? id : inspect));
});
test("container list changes invalidate the snapshot", async () => {
  let ps = 0;
  await assert.rejects(D.collect(async (_, args) => args[0] === "info" ? '{"DockerRootDir":"/vol1/docker"}' : args[0] === "ps" ? (++ps === 1 ? id : "") : JSON.stringify([container()])), /发生变化/);
});
test("Docker JSON preserves delimiter characters without shell splitting", async () => {
  const c = container(); c.Mounts = [{ Type: "bind", Source: "/vol1/data|name", Destination: "/data", RW: true }];
  const r = await D.collect(async (_, args) => args[0] === "info" ? '{"DockerRootDir":"/vol1/docker"}' : args[0] === "ps" ? id : JSON.stringify([c]));
  assert.equal(r.containers[0].Mounts[0].Source, "/vol1/data|name");
});
