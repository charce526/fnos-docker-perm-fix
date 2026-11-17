"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { ensure, AppError } = require("./policy");
function safeDirectory(dir, { initialize = false } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const s = fs.lstatSync(dir);
  ensure(s.isDirectory() && !s.isSymbolicLink(), "UNSAFE_STORAGE", "数据目录不是独立真实目录", 503);
  if (process.platform === "linux") {
    const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const current = fs.fstatSync(fd);
      ensure(current.dev === s.dev && current.ino === s.ino, "UNSAFE_STORAGE", "数据目录在初始化期间发生变化", 503);
      if (initialize) {
        // Only the trusted AppCenter TRIM_PKGVAR directory may be initialized by root.
        // fnOS can create it with the package UID and inherited group permissions.
        ensure(process.getuid() === 0, "UNSAFE_STORAGE", "初始化应用数据目录需要 root", 503);
        if (current.uid !== 0 || current.gid !== 0) fs.fchownSync(fd, 0, 0);
        fs.fchmodSync(fd, 0o700);
      }
      const secured = fs.fstatSync(fd);
      ensure(secured.uid === process.getuid() && !(secured.mode & 0o022), "UNSAFE_STORAGE", "数据目录属主或写权限不安全：" + dir, 503);
    } finally { fs.closeSync(fd); }
  }
}
function atomicJson(file, value) {
  const temporary = file + "." + crypto.randomUUID() + ".tmp";
  const fd = fs.openSync(temporary, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try { fs.renameSync(temporary, file); } catch (e) { fs.unlinkSync(temporary); throw e; }
}
function tail(file, bytes = 128 * 1024) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const size = fs.fstatSync(fd).size, start = Math.max(0, size - bytes), buffer = Buffer.alloc(size - start);
    fs.readSync(fd, buffer, 0, buffer.length, start);
    const lines = buffer.toString("utf8").trimEnd().split("\n");
    if (start) lines.shift();
    return lines.filter(Boolean).slice(-200);
  } catch (e) { if (e.code === "ENOENT") return []; throw e; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
class Audit {
  constructor(dir) { safeDirectory(dir); this.file = path.join(dir, "audit.log"); this.error = null; }
  write(action, detail) {
    try {
      if (fs.existsSync(this.file) && fs.lstatSync(this.file).size > 2 * 1024 * 1024) {
        for (let i = 3; i >= 1; i--) {
          const from = this.file + (i === 1 ? "" : "." + (i - 1)), to = this.file + "." + i;
          if (fs.existsSync(from)) { if (fs.existsSync(to)) fs.unlinkSync(to); fs.renameSync(from, to); }
        }
      }
      const fd = fs.openSync(this.file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0), 0o600);
      try { fs.writeSync(fd, JSON.stringify({ at: new Date().toISOString(), action, ...detail }) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      this.error = null;
    } catch (e) { this.error = e.message; console.error("Audit unavailable:", e.message); throw new AppError("AUDIT_UNAVAILABLE", "审计日志不可写，特权任务已阻止，请检查磁盘和权限", 503); }
  }
  read() { return tail(this.file); }
}
function startTime(pid) {
  try { const s = fs.readFileSync(`/proc/${pid}/stat`, "utf8"); return s.slice(s.lastIndexOf(")") + 2).trim().split(/\s+/)[19]; } catch { return null; }
}
function processAlive(record) {
  if (!record || !Number.isSafeInteger(record.pid) || record.pid <= 1) return false;
  if (process.platform === "linux") return record.start == null || startTime(record.pid) === record.start;
  try { process.kill(record.pid, 0); return true; } catch (e) { return e.code === "EPERM"; }
}
class ProcessLock {
  constructor(dir, name = "execution.lock") { this.dir = path.join(dir, name); this.owned = false; }
  acquire() {
    try { fs.mkdirSync(this.dir, { mode: 0o700 }); }
    catch (e) {
      if (e.code !== "EEXIST") throw e;
      let old;
      try { old = JSON.parse(fs.readFileSync(path.join(this.dir, "owner.json"))); } catch { throw new AppError("BUSY_LOCK", "执行锁信息不完整，请管理员核对任务进程后处理", 409); }
      ensure(old.parent && Number.isSafeInteger(old.parent.pid) && old.parent.pid > 1, "BUSY_LOCK", "锁拥有者信息无效，请管理员核对", 409);
      ensure(!processAlive(old.parent) && !processAlive(old.worker), "BUSY", "其他进程仍在运行任务", 409);
      fs.unlinkSync(path.join(this.dir, "owner.json")); fs.rmdirSync(this.dir);
      fs.mkdirSync(this.dir, { mode: 0o700 });
    }
    this.owned = true; this.record = { parent: { pid: process.pid, start: startTime(process.pid) }, worker: null };
    try { atomicJson(path.join(this.dir, "owner.json"), this.record); } catch (e) { this.release(); throw e; }
  }
  worker(pid) { this.record.worker = { pid, start: startTime(pid) }; atomicJson(path.join(this.dir, "owner.json"), this.record); }
  release() { if (!this.owned) return; const file = path.join(this.dir, "owner.json"); if (fs.existsSync(file)) fs.unlinkSync(file); fs.rmdirSync(this.dir); this.owned = false; }
}
module.exports = { safeDirectory, atomicJson, tail, Audit, ProcessLock, startTime, processAlive };
