"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { createApp } = require("../app/app/server/server");
const { JobManager, validateResult } = require("../app/app/server/lib/jobs");
const { Audit, tail, ProcessLock } = require("../app/app/server/lib/storage");
const admin = { "X-Trim-Userid": "admin", "X-Trim-Isadmin": "true" };
function fakeManager() {
  return { active: null, calls: [], start(mode, payload, owner, requestKey) { this.calls.push({ mode, payload, owner, requestKey }); return { id: "job" }; }, list() { return []; }, findResult(field, value) { return { result: field === "scanId" ? { scanId: value } : { planId: value, items: [] } }; }, get(id, owner) { if (owner !== "admin") throw Object.assign(Error("missing"), { status: 404 }); return { id }; } };
}
async function serve(t, options = {}) {
  const manager = options.manager || fakeManager(), events = [], audit = { write(...args) { events.push(args); }, read() { return []; } };
  const server = createApp({ manager, audit, ...options }).listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}/app/docker-perm-fix/api`;
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return { manager, events, base, async request(route, { headers = admin, body, method, raw } = {}) { return fetch(base + route, { method: method || (body !== undefined || raw ? "POST" : "GET"), headers: { ...headers, ...(body !== undefined || raw ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined || raw ? { body: raw || JSON.stringify(body) } : {}) }); }, async csrf(headers = admin) { return (await (await fetch(base + "/session", { headers })).json()).csrfToken; } };
}
test("health is minimal, every sensitive API requires gateway administrator", async t => {
  const s = await serve(t);
  assert.deepEqual(await (await s.request("/health", { headers: {} })).json(), { ok: true });
  assert.equal((await s.request("/session", { headers: {} })).status, 401);
  assert.equal((await s.request("/session", { headers: { "X-Trim-Userid": "user", "X-Trim-Isadmin": "false" } })).status, 403);
  assert.equal((await s.request("/session")).status, 200);
});
test("development authentication cannot be forged using NAS headers", async t => {
  const token = "d".repeat(64), s = await serve(t, { devToken: token });
  assert.equal((await s.request("/session")).status, 401);
  assert.equal((await s.request("/session", { headers: { "X-Dev-Token": token } })).status, 200);
});
test("write endpoints require CSRF and reject cross-site or mismatched origin", async t => {
  const s = await serve(t), csrf = await s.csrf();
  assert.equal((await s.request("/scan", { body: { profile: "read" } })).status, 403);
  for (const headers of [{ Origin: "https://foreign.example" }, { "Sec-Fetch-Site": "cross-site" }]) assert.equal((await s.request("/scan", { headers: { ...admin, "X-CSRF-Token": csrf, ...headers }, body: {} })).status, 403);
  assert.equal((await s.request("/scan", { headers: { ...admin, "X-CSRF-Token": csrf }, body: { profile: "read" } })).status, 202);
});
test("invalid profiles, legacy fix keys and >100 entries are rejected", async t => {
  const s = await serve(t), headers = { ...admin, "X-CSRF-Token": await s.csrf() };
  assert.equal((await s.request("/scan", { headers, body: { profile: "guess" } })).status, 400);
  assert.equal((await s.request("/fix", { headers, body: { keys: ["a".repeat(64)] } })).status, 400);
  assert.equal((await s.request("/plan", { headers, body: { keys: Array(101).fill("a".repeat(64)) } })).status, 400);
});
test("plan request deduplicates keys and binds stored scan to current owner", async t => {
  const s = await serve(t), headers = { ...admin, "X-CSRF-Token": await s.csrf() }, key = "a".repeat(64);
  const r = await s.request("/plan", { headers, body: { scanId: "scan", keys: [key, key], action: "owner-permissions" } });
  assert.equal(r.status, 202); assert.deepEqual(s.manager.calls[0].payload.keys, [key]); assert.equal(s.manager.calls[0].owner, "admin");
});
test("unknown APIs and malformed/oversized JSON return JSON errors", async t => {
  const s = await serve(t);
  for (const r of [await s.request("/not-found"), await s.request("/scan", { raw: "{" }), await s.request("/scan", { raw: JSON.stringify({ text: "a".repeat(65536) }) })]) { assert(r.status >= 400); assert.match(r.headers.get("content-type"), /json/); assert.equal(typeof (await r.json()).error, "string"); }
});
test("task records cannot be read by another administrator", async t => {
  const s = await serve(t);
  assert.equal((await s.request("/jobs/id", { headers: { "X-Trim-Userid": "other", "X-Trim-Isadmin": "true" } })).status, 404);
});
test("schema rejects null, incomplete scan and incomplete execute output", () => {
  assert.throws(() => validateResult("scan", null, {}));
  assert.throws(() => validateResult("scan", { schemaVersion: 2, containers: [] }, {}));
  assert.throws(() => validateResult("execute", { schemaVersion: 2, planId: "a", results: [] }, { plan: { planId: "a", items: [{ key: "x" }] } }));
});
async function wait(manager, id) { for (let n = 0; n < 200; n++) { const j = manager.jobs.get(id); if (j.state !== "running") return j; await new Promise(resolve => setTimeout(resolve, 25)); } throw Error("fixture job timed out"); }
function workspace(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "perm-fix-test-"));
  t.after(() => { const actual = fs.realpathSync(dir), relative = path.relative(fs.realpathSync(os.tmpdir()), actual); assert(!relative.startsWith("..") && !path.isAbsolute(relative) && relative.startsWith("perm-fix-test-") && !relative.includes(path.sep)); fs.rmSync(actual, { recursive: true, force: true }); });
  return dir;
}
test("real job runner rejects concurrency and deduplicates retried request keys", async t => {
  const dir = workspace(t), manager = new JobManager(dir, new Audit(dir), { workerFile: path.join(__dirname, "fixtures/worker.cjs") });
  t.after(() => manager.shutdown());
  const a = manager.start("scan", { delay: 100 }, "admin", "one");
  assert.equal(manager.start("scan", {}, "admin", "one").id, a.id);
  assert.throws(() => manager.start("scan", {}, "other"), /已有任务/);
  assert.throws(() => new JobManager(dir, new Audit(dir)), /仍在运行/);
  assert.equal((await wait(manager, a.id)).state, "completed");
  assert.throws(() => manager.get(a.id, "other"));
});
test("nonzero child exit cannot become success even with valid result", async t => {
  const dir = workspace(t), manager = new JobManager(dir, new Audit(dir), { workerFile: path.join(__dirname, "fixtures/worker.cjs") });
  t.after(() => manager.shutdown());
  assert.equal((await wait(manager, manager.start("scan", { behavior: "nonzero" }, "admin").id)).state, "failed");
});
test("invalid child schema is an execution failure", async t => {
  const dir = workspace(t), manager = new JobManager(dir, new Audit(dir), { workerFile: path.join(__dirname, "fixtures/worker.cjs") });
  t.after(() => manager.shutdown());
  assert.equal((await wait(manager, manager.start("scan", { behavior: "invalid" }, "admin").id)).state, "failed");
});
test("job timeout persists interrupted state and releases lock", async t => {
  const dir = workspace(t), manager = new JobManager(dir, new Audit(dir), { timeout: 200, workerFile: path.join(__dirname, "fixtures/worker.cjs") });
  t.after(() => manager.shutdown());
  const job = await wait(manager, manager.start("scan", { behavior: "hang" }, "admin").id);
  assert.equal(job.state, "interrupted"); assert.equal(manager.active, null); assert.equal(fs.existsSync(path.join(dir, "execution.lock")), false);
});
test("cross-process lock blocks a second manager", t => { const dir = workspace(t), a = new ProcessLock(dir), b = new ProcessLock(dir); a.acquire(); try { assert.throws(() => b.acquire()); } finally { a.release(); } });
test("audit records are structured and tail reads bounded bytes", t => { const dir = workspace(t), audit = new Audit(dir); audit.write("FIX", { owner: "admin", message: "name\nline" }); assert.equal(JSON.parse(audit.read()[0]).message, "name\nline"); const large = path.join(dir, "large.log"); fs.writeFileSync(large, "prefix\n".repeat(30000) + "last\n"); const lines = tail(large, 1024); assert(lines.length <= 200); assert.equal(lines.at(-1), "last"); });
