"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { fork } = require("node:child_process");
const { ensure, AppError, profile, MAX_ITEMS } = require("./policy");
const { safeDirectory, atomicJson, ProcessLock, processAlive } = require("./storage");
function validateResult(mode, r, payload) {
  ensure(r && r.schemaVersion === 2, "ENGINE_PROTOCOL", "引擎返回协议无效", 503);
  ensure(Buffer.byteLength(JSON.stringify(r)) <= 8 * 1024 * 1024, "ENGINE_LIMIT", "引擎结果超过 8MB，请缩小检查范围", 503);
  if (mode === "scan") {
    ensure(typeof r.scanId === "string" && Number.isFinite(Date.parse(r.createdAt)) && typeof r.complete === "boolean" && Array.isArray(r.containers) && Array.isArray(r.warnings), "ENGINE_PROTOCOL", "扫描结果不完整", 503);
    profile(r.profile);
    const keys = new Set();
    for (const c of r.containers) {
      ensure(typeof c.id === "string" && typeof c.name === "string" && c.identity && Array.isArray(c.mounts), "ENGINE_PROTOCOL", "容器结果无效", 503);
      for (const m of c.mounts) { ensure(/^[a-f0-9]{64}$/.test(m.key) && !keys.has(m.key) && typeof m.status === "string" && typeof m.canPlanRepair === "boolean" && Array.isArray(m.evidence), "ENGINE_PROTOCOL", "挂载结果无效", 503); keys.add(m.key); }
    }
  } else if (mode === "plan") {
    ensure(typeof r.planId === "string" && Number.isFinite(Date.parse(r.expiresAt)) && r.aclPolicy === "preserve" && Array.isArray(r.items) && r.items.length === payload.keys.length && r.items.length <= MAX_ITEMS, "ENGINE_PROTOCOL", "计划结果不完整", 503);
    ensure(new Set(r.items.map(x => x.key)).size === r.items.length && r.items.every(x => payload.keys.includes(x.key) && Array.isArray(x.actions) && x.actions.length && x.actions.every(a => a.before && a.after && typeof a.acl === "string")), "ENGINE_PROTOCOL", "计划动作无效", 503);
  } else {
    ensure(r.planId === payload.plan.planId && Array.isArray(r.results) && r.results.length === payload.plan.items.length, "ENGINE_PROTOCOL", "修复结果不完整", 503);
    ensure(new Set(r.results.map(x => x.key)).size === r.results.length && r.results.every(x => payload.plan.items.some(y => y.key === x.key) && ["verified_success", "partial_failure", "failed", "skipped", "interrupted"].includes(x.status)), "ENGINE_PROTOCOL", "修复结果无效", 503);
  }
  return r;
}
class JobManager {
  constructor(dir, audit, { timeout = 10 * 60 * 1000, workerFile = path.join(__dirname, "..", "worker.js") } = {}) {
    this.dir = path.join(dir, "jobs"); safeDirectory(this.dir); this.audit = audit; this.timeout = timeout; this.workerFile = workerFile;
    this.jobs = new Map(); this.active = null; this.closing = false; this.lock = new ProcessLock(dir);
    const lockFile = path.join(dir, "execution.lock", "owner.json");
    ensure(!fs.existsSync(path.dirname(lockFile)) || fs.existsSync(lockFile), "BUSY_LOCK", "执行锁尚未完整写入，不能确定旧任务状态", 503);
    if (fs.existsSync(lockFile)) {
      let owner; try { owner = JSON.parse(fs.readFileSync(lockFile)); } catch { throw new AppError("BUSY_LOCK", "不能确定旧执行者状态，请核对执行锁", 503); }
      ensure(owner.parent && Number.isSafeInteger(owner.parent.pid) && owner.parent.pid > 1 && !processAlive(owner.parent) && !processAlive(owner.worker), "BUSY", "旧服务或执行者仍在运行，不能重写任务恢复状态", 503);
    }
    const files = fs.readdirSync(this.dir).filter(x => /^[a-f0-9-]{36}\.json$/.test(x)).sort((a, b) => fs.statSync(path.join(this.dir, b)).mtimeMs - fs.statSync(path.join(this.dir, a)).mtimeMs).slice(0, 40);
    for (const file of files) {
      ensure(fs.statSync(path.join(this.dir, file)).size < 12 * 1024 * 1024, "STORAGE_LIMIT", "历史任务文件异常，请管理员检查", 503);
      const job = JSON.parse(fs.readFileSync(path.join(this.dir, file)));
      if (job.state === "running") { job.state = "interrupted"; job.error = { code: "SERVER_RESTART", message: "服务中断；请核对修改记录，已完成修改不自动回滚" }; this.save(job); }
      this.jobs.set(job.id, job);
    }
  }
  save(job) { atomicJson(path.join(this.dir, job.id + ".json"), job); }
  get(id, owner) { const job = this.jobs.get(id); ensure(job && job.owner === owner, "NOT_FOUND", "任务不存在", 404); return job; }
  findResult(field, value, owner) { const job = [...this.jobs.values()].find(j => j.owner === owner && j.state === "completed" && j.result?.[field] === value); ensure(job, "NOT_FOUND", "扫描或计划不存在，请重新扫描", 404); return job; }
  list(owner) { return [...this.jobs.values()].filter(x => x.owner === owner).sort((a, b) => b.createdAt.localeCompare(a.createdAt)); }
  trim() {
    const sorted = [...this.jobs.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    for (const old of sorted.slice(40)) {
      if (old.state === "running") continue;
      for (const suffix of [".json", ".journal.jsonl"]) { const file = path.join(this.dir, old.id + suffix); if (fs.existsSync(file)) fs.unlinkSync(file); }
      this.jobs.delete(old.id);
    }
    const bytes = fs.readdirSync(this.dir).reduce((n, f) => n + fs.lstatSync(path.join(this.dir, f)).size, 0);
      ensure(bytes < 128 * 1024 * 1024, "STORAGE_LIMIT", "任务和修改记录超过 128MB，请导出并按维护文档归档", 503);
  }
  start(mode, payload, owner, requestKey) {
    ensure(!this.closing, "SHUTTING_DOWN", "应用正在停止", 503);
    const duplicate = requestKey && [...this.jobs.values()].find(x => x.owner === owner && x.requestKey === requestKey);
    if (duplicate) return duplicate;
    ensure(!this.active, "BUSY", "已有任务正在执行，请等待完成", 409);
    this.trim(); this.lock.acquire();
    const job = { id: crypto.randomUUID(), owner, mode, requestKey: requestKey || null, state: "running", createdAt: new Date().toISOString(), progress: { phase: "starting", message: "任务启动中" } };
    let child;
    try {
      this.audit.write("TASK_START", { owner, jobId: job.id, mode, planId: payload.plan?.planId, keys: payload.keys || payload.plan?.items.map(x => x.key) });
      if (mode === "execute") payload = { ...payload, journalPath: path.join(this.dir, job.id + ".journal.jsonl") };
      this.save(job); this.jobs.set(job.id, job);
      child = fork(this.workerFile, [], { detached: process.platform === "linux", stdio: ["ignore", "ignore", "pipe", "ipc"], execArgv: [], env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8", VAR_DIR: path.dirname(this.dir) } });
      this.lock.worker(child.pid);
    } catch (e) { if (child) child.kill("SIGKILL"); this.lock.release(); throw e; }
    let result, error, stderr = "", lastSave = 0, final = false, killTimer;
    const terminate = reason => {
      if (!error || ["TIMEOUT", "STOPPED"].includes(reason)) error = { code: reason, message: reason === "TIMEOUT" ? "任务超时；请查看保留的结果和修改记录" : "任务被停止；已完成修改不自动回滚" };
      child.kill("SIGTERM");
      killTimer = setTimeout(() => { try { if (process.platform === "linux") process.kill(-child.pid, "SIGKILL"); else child.kill("SIGKILL"); } catch {} }, 5000);
    };
    this.active = { job, child, terminate };
    const timer = setTimeout(() => terminate("TIMEOUT"), this.timeout);
    child.stderr.on("data", b => { stderr = (stderr + b).slice(-4000); });
    child.on("message", m => {
      try {
        if (m?.type === "progress" && m.data && typeof m.data.message === "string") {
          job.progress = m.data;
          if (Date.now() - lastSave > 1000) { this.save(job); lastSave = Date.now(); }
        } else if (m?.type === "result") result = validateResult(mode, m.data, payload);
        else if (m?.type === "error") error = { code: String(m.error?.code || "ENGINE_ERROR"), message: String(m.error?.message || "引擎执行失败"), status: m.error?.status };
      } catch (e) { error = { code: e.code || "ENGINE_PROTOCOL", message: e.message }; terminate(error.code); }
    });
    const finish = (code, signal) => {
      if (final) return; final = true; clearTimeout(timer); clearTimeout(killTimer);
      if (!error && (code !== 0 || !result)) error = { code: "ENGINE_EXIT", message: `引擎未完整完成（${signal || code}）${stderr ? "：" + stderr : ""}` };
      job.state = error ? (["TIMEOUT", "STOPPED", "INTERRUPTED"].includes(error.code) ? "interrupted" : "failed") : "completed";
      job.finishedAt = new Date().toISOString(); if (result) job.result = result; if (error) job.error = error;
      try { this.save(job); this.audit.write("TASK_END", { owner, jobId: job.id, mode, state: job.state, error, results: result?.results, journal: result?.journal }); }
      catch (e) { job.state = "failed"; job.error = { code: "PERSIST_FAILED", message: e.message }; console.error(e); }
      finally { this.active = null; try { this.lock.release(); } catch (e) { console.error("Lock release:", e.message); } }
    };
    child.on("error", e => { error = { code: "ENGINE_SPAWN", message: e.message }; });
    child.on("close", finish);
    child.send({ mode, payload });
    return job;
  }
  async shutdown() {
    this.closing = true;
    if (!this.active) return;
    const active = this.active;
    active.terminate("STOPPED");
    await new Promise(resolve => active.child.once("close", resolve));
  }
}
module.exports = { JobManager, validateResult };
