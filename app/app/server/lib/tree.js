"use strict";
const fs = require("node:fs");
const path = require("node:path").posix;
const { spawn } = require("node:child_process");
const { ensure, AppError, MAX_OBJECTS, stateToken, sameObject, desiredMode, digest } = require("./policy");
const C = fs.constants;
// Linux x86_64/arm64 O_PATH: inspect inode type before opening a possible device/FIFO.
const O_PATH = 0x200000;
const fdPath = fd => `/proc/self/fd/${fd}`;
function linuxReady() {
  if (!(process.platform === "linux" && ["x64", "arm64"].includes(process.arch) && process.getuid?.() === 0 && C.O_NOFOLLOW && C.O_DIRECTORY && fs.existsSync("/proc/self/fd"))) return false;
  try { return ["uid_map", "gid_map"].every(name => /^\s*0\s+0\s+4294967295\s*$/.test(fs.readFileSync("/proc/self/" + name, "utf8"))); } catch { return false; }
}
function openOrdinary(p, directory = false) {
  const guard = fs.openSync(p, O_PATH | C.O_NOFOLLOW | (directory ? C.O_DIRECTORY : 0));
  try {
    const s = fs.fstatSync(guard);
    ensure(s.isDirectory() || s.isFile(), "UNSUPPORTED_OBJECT", "对象已变成链接或特殊文件，禁止打开", 422);
    return fs.openSync(fdPath(guard), C.O_RDONLY | C.O_NONBLOCK | (s.isDirectory() ? C.O_DIRECTORY : 0));
  } finally { fs.closeSync(guard); }
}
function openRoot(source) {
  ensure(linuxReady(), "UNSUPPORTED_RUNTIME", "安全目录操作需要 Linux root 和 /proc/self/fd", 503);
  ensure(source.startsWith("/") && !source.split("/").some(x => x === ".."), "INVALID_PATH", "目录路径不合法");
  let fd = fs.openSync("/", C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  try {
    const parts = source.split("/").filter(Boolean);
    for (let index = 0; index < parts.length; index++) {
      const last = index === parts.length - 1;
      const next = fs.openSync(`${fdPath(fd)}/${parts[index]}`, C.O_RDONLY | C.O_NOFOLLOW | (last ? 0 : C.O_DIRECTORY));
      const stat = fs.fstatSync(next);
      ensure(stat.isDirectory() || (last && stat.isFile()), "UNSUPPORTED_OBJECT", "挂载路径不是普通文件或目录", 422);
      fs.closeSync(fd); fd = next;
    }
    return fd;
  } catch (error) { fs.closeSync(fd); throw error; }
}
function withObject(rootFd, relative, fn) {
  const parts = relative === "." ? [] : relative.split("/");
  ensure(parts.every(x => x && x !== "." && x !== ".." && !/[\x00-\x1f\x7f]/.test(x)), "INVALID_PATH", "对象相对路径不合法");
  let current = rootFd;
  const opened = [];
  try {
    for (let i = 0; i < parts.length; i++) {
      const last = i === parts.length - 1;
      const next = openOrdinary(`${fdPath(current)}/${parts[i]}`, !last);
      opened.push(next); current = next;
    }
    return fn(current);
  } finally { opened.reverse().forEach(fd => fs.closeSync(fd)); }
}
function inventory(rootFd, { max = MAX_OBJECTS, deadline = Date.now() + 120000, recursive = true } = {}) {
  const objects = [], exclusions = [];
  function walk(fd, relative, depth) {
    ensure(depth <= 128 && Date.now() <= deadline && objects.length < max, "SCAN_LIMIT", "目录过深、对象过多或扫描超时，未完成检查", 422);
    const s = fs.fstatSync(fd, { bigint: true });
    ensure(s.isDirectory() || s.isFile(), "UNSUPPORTED_OBJECT", "对象不是普通文件或目录", 422);
    const token = stateToken(s);
    objects.push({ relativePath: relative, ...token });
    if (!s.isDirectory()) {
      if (s.nlink > 1n) exclusions.push({ relativePath: relative, reason: "hardlink" });
      return;
    }
    if (!recursive) return;
    const names = fs.readdirSync(fdPath(fd), { encoding: "buffer" });
    for (const bytes of names) {
      const name = bytes.toString("utf8");
      ensure(Buffer.from(name).equals(bytes) && !/[\x00-\x1f\x7f]/.test(name), "UNSUPPORTED_NAME", "目录包含无法安全展示的文件名，未完成检查", 422);
      const childPath = `${fdPath(fd)}/${name}`;
      const rel = relative === "." ? name : relative + "/" + name;
      const before = fs.lstatSync(childPath, { bigint: true });
      if (!before.isDirectory() && !before.isFile()) { exclusions.push({ relativePath: rel, reason: before.isSymbolicLink() ? "symlink" : "special" }); continue; }
      ensure(before.dev === s.dev, "NESTED_MOUNT", "目录内存在其他设备，停止检查", 422);
      const child = openOrdinary(childPath, before.isDirectory());
      try {
        ensure(sameObject(stateToken(before), stateToken(fs.fstatSync(child, { bigint: true }))), "STALE_OBJECT", "扫描期间对象发生变化", 409);
        walk(child, rel, depth + 1);
      } finally { fs.closeSync(child); }
    }
  }
  walk(rootFd, ".", 0);
  return { objects, exclusions, digest: digest(objects) };
}
function probe(rootFd, identity, profile, workerFile, { recursive = true } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [workerFile, "probe"], { stdio: ["pipe", "pipe", "pipe", rootFd], env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" } });
    let output = "", errorText = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new AppError("PROBE_TIMEOUT", "身份模拟检查超时", 503)); }, 120000);
    child.stdout.on("data", b => { output += b; if (output.length > 1024 * 1024) child.kill("SIGKILL"); });
    child.stderr.on("data", b => { errorText = (errorText + b).slice(-2000); });
    child.on("error", e => { clearTimeout(timer); reject(e); });
    child.on("close", code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new AppError("PROBE_FAILED", "身份模拟失败：" + errorText, 503));
      try { const r = JSON.parse(output); ensure(r && typeof r.complete === "boolean" && Array.isArray(r.evidence) && Number.isInteger(r.checked), "PROTOCOL", "检查结果格式错误", 503); resolve(r); } catch (e) { reject(e); }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify({ identity, profile, recursive }));
  });
}
function runProbe({ identity, profile, recursive = true }) {
  ensure(process.getuid?.() === 0 && identity.uid > 0 && Number.isInteger(identity.gid) && identity.groups.every(x => Number.isInteger(x) && x >= 0), "IDENTITY", "无法安全切换检查身份");
  process.setgroups(identity.groups); process.setgid(identity.gid); process.setuid(identity.uid);
  ensure(process.getuid() === identity.uid && process.getgid() === identity.gid, "IDENTITY", "身份切换失败");
  const evidence = [], warnings = [];
  let checked = 0, complete = true, rootAccess = null;
  const deadline = Date.now() + 110000;
  function inspect(p, relative, depth) {
    if (++checked > MAX_OBJECTS || depth > 128 || Date.now() > deadline) { complete = false; return; }
    let s;
    try { s = fs.statSync(p); } catch (e) { complete = false; if (evidence.length < 32) evidence.push({ relativePath: relative, missing: [], errorCode: e.code, message: "无法读取对象属性" }); return; }
    const missing = [];
    if (relative === ".") {
      rootAccess = {};
      for (const [op, flag] of [["read", C.R_OK], ["write", C.W_OK], ...(s.isDirectory() ? [["enter", C.X_OK]] : [])]) { try { fs.accessSync(p, flag); rootAccess[op] = true; } catch { rootAccess[op] = false; } }
    }
    const ops = [["read", C.R_OK], ...(s.isDirectory() ? [["enter", C.X_OK]] : []), ...(profile === "read-write" ? [["write", C.W_OK]] : [])];
    for (const [op, flag] of ops) { try { fs.accessSync(p, flag); } catch (e) { missing.push(op); if (!["EACCES", "EPERM"].includes(e.code)) warnings.push(e.code); } }
    if (missing.length && evidence.length < 32) evidence.push({ relativePath: relative, type: s.isDirectory() ? "directory" : "file", owner: `${s.uid}:${s.gid}`, mode: (s.mode & 0o7777).toString(8), missing });
    if (!s.isDirectory() || !recursive) return;
    if (missing.includes("read") || missing.includes("enter")) { complete = false; return; }
    let names;
    try { names = fs.readdirSync(p); } catch (e) { complete = false; warnings.push(e.code); return; }
    for (const name of names) {
      let child;
      try {
        const cp = `${p}/${name}`, st = fs.lstatSync(cp);
        if (!st.isFile() && !st.isDirectory()) { complete = false; continue; }
        child = openOrdinary(cp, st.isDirectory());
        inspect(fdPath(child), relative === "." ? name : `${relative}/${name}`, depth + 1);
      } catch (e) {
        complete = false;
        // Opening read-only may fail before recursion: still report the actual access failures.
        try {
          const cp = `${p}/${name}`, st = fs.lstatSync(cp);
          const denied = [];
          for (const [op, flag] of [["read", C.R_OK], ...(st.isDirectory() ? [["enter", C.X_OK]] : []), ...(profile === "read-write" ? [["write", C.W_OK]] : [])]) { try { fs.accessSync(cp, flag); } catch { denied.push(op); } }
          if (evidence.length < 32) evidence.push({ relativePath: relative === "." ? name : `${relative}/${name}`, type: st.isDirectory() ? "directory" : "file", owner: `${st.uid}:${st.gid}`, mode: (st.mode & 0o7777).toString(8), missing: denied, errorCode: e.code });
        } catch { warnings.push(e.code); }
      } finally { if (child !== undefined) fs.closeSync(child); }
      if (checked >= MAX_OBJECTS || Date.now() > deadline) { complete = false; break; }
    }
  }
  inspect(fdPath(3), ".", 0);
  return { complete, evidence, checked, rootAccess, scope: recursive ? "tree" : "root", warnings: [...new Set(warnings)], method: "host-mount-root-with-process-groups", requirement: profile };
}
function actionsFor(objects, identity, profile) {
  return objects.map(o => {
    const after = { uid: identity.uid, gid: identity.gid, mode: desiredMode(o.mode, o.type, profile) };
    return { relativePath: o.relativePath, before: o, after };
  }).filter(x => x.before.uid !== x.after.uid || x.before.gid !== x.after.gid || x.before.mode !== x.after.mode);
}
module.exports = { linuxReady, fdPath, openRoot, withObject, inventory, probe, runProbe, actionsFor, openOrdinary };
