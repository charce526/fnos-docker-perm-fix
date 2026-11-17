"use strict";
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { spawn } = require("node:child_process");
const { ensure } = require("./lib/policy");
const { safeDirectory, atomicJson, ProcessLock, startTime } = require("./lib/storage");
const { verifyCode } = require("./server");
const { initializeCode } = require("./lib/code-permissions");
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function main(mode) {
  ensure(process.platform === "linux" && process.getuid?.() === 0, "ROOT_REQUIRED", "应用控制需要 Linux root 环境");
  ensure(["start", "stop", "status", "preflight"].includes(mode), "MODE", "不支持的控制命令");
  for (const name of ["TRIM_APPDEST", "TRIM_PKGVAR"]) ensure(process.env[name]?.startsWith("/"), "CONFIG", `缺少 ${name}`);
  // fnOS may expose target/var through root-managed symlinks; operate on their canonical targets.
  const destination = fs.realpathSync(process.env.TRIM_APPDEST), dir = fs.realpathSync(process.env.TRIM_PKGVAR);
  ensure(path.join(destination, "server") === fs.realpathSync(__dirname), "CONFIG", "应用目标路径与当前代码不一致");
  if (mode === "preflight" || mode === "start") initializeCode(__dirname);
  safeDirectory(dir, { initialize: mode === "preflight" || mode === "start" });
  const pidFile = path.join(dir, "app.pid.json"), socket = path.join(destination, "app.sock"), serverFile = path.join(__dirname, "server.js");
  const lock = new ProcessLock(dir, "control.lock"); lock.acquire();
  try {
    let record;
    if (fs.existsSync(pidFile)) { try { record = JSON.parse(fs.readFileSync(pidFile)); } catch { record = null; } }
    const belongs = r => {
      if (!r || !Number.isSafeInteger(r.pid) || r.pid <= 1 || !r.start || startTime(r.pid) !== r.start || r.server !== serverFile) return false;
      try { return fs.readFileSync(`/proc/${r.pid}/cmdline`, "utf8").split("\0").includes(serverFile); } catch { return false; }
    };
    const health = () => new Promise(resolve => {
      const request = http.get({ socketPath: socket, path: "/app/docker-perm-fix/api/health", timeout: 1000 }, response => { response.resume(); resolve(response.statusCode === 200); });
      request.on("timeout", () => { request.destroy(); resolve(false); }); request.on("error", () => resolve(false));
    });
    if (mode === "status") { process.exitCode = belongs(record) && await health() ? 0 : 3; return; }
    if (mode === "preflight") { verifyCode(__dirname); require("express"); console.log("Node " + process.version + "，代码权限及 Express 依赖检查通过；Docker 和 getfacl 能力将在扫描时检查。"); return; }
    if (mode === "stop") {
      if (!belongs(record)) {
        // Never signal a reused PID or a process whose identity wasn't recorded.
        ensure(!await health(), "UNTRACKED_SERVICE", "发现未受当前 PID 记录管理的服务，请核对旧版本进程后处理");
        if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
        return;
      }
      process.kill(record.pid, "SIGTERM");
      for (let i = 0; i < 48 && belongs(record); i++) await sleep(250);
      if (belongs(record)) {
        const ownerFile = path.join(dir, "execution.lock", "owner.json");
        if (fs.existsSync(ownerFile)) {
          const owner = JSON.parse(fs.readFileSync(ownerFile));
          if (owner.parent?.pid === record.pid && owner.parent.start === record.start && owner.worker?.pid > 1 && owner.worker.start && startTime(owner.worker.pid) === owner.worker.start) {
            process.kill(-owner.worker.pid, "SIGTERM"); await sleep(1000);
            if (startTime(owner.worker.pid) === owner.worker.start) process.kill(-owner.worker.pid, "SIGKILL");
          }
        }
        process.kill(-record.pid, "SIGKILL");
      }
      if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
      if (fs.existsSync(socket)) { const s = fs.lstatSync(socket); ensure(s.isSocket() && s.uid === 0, "SOCKET", "残留 Socket 类型或属主异常"); fs.unlinkSync(socket); }
      return;
    }
    if (belongs(record)) { ensure(await health(), "UNHEALTHY", "服务进程存在但健康检查失败，请先停止并核对日志"); return; }
    ensure(!await health(), "UNTRACKED_SERVICE", "已有未跟踪服务占用 Socket，请核对旧版本");
    verifyCode(__dirname);
    if (fs.existsSync(socket)) { const s = fs.lstatSync(socket); ensure(s.isSocket() && s.uid === 0, "SOCKET", "禁止删除非本应用类型的 Socket 路径"); fs.unlinkSync(socket); }
    let config = {};
    if (process.env.TRIM_PKGETC) {
      const file = path.join(process.env.TRIM_PKGETC, "runtime.json");
      if (fs.existsSync(file)) {
        const s = fs.lstatSync(file); ensure(s.isFile() && s.uid === 0 && !(s.mode & 0o077), "CONFIG", "runtime.json 必须 root:root 0600");
        config = JSON.parse(fs.readFileSync(file));
        ensure(Object.keys(config).every(x => x === "gatewayGid") && (config.gatewayGid === undefined || Number.isInteger(config.gatewayGid) && config.gatewayGid >= 0 && config.gatewayGid <= 2147483647), "CONFIG", "runtime.json 仅支持数字 gatewayGid");
      }
    }
    const log = path.join(dir, "app.log");
    if (fs.existsSync(log) && fs.lstatSync(log).size > 2 * 1024 * 1024) {
      for (let i = 3; i >= 1; i--) { const from = log + (i === 1 ? "" : "." + (i - 1)), to = log + "." + i; if (fs.existsSync(from)) { if (fs.existsSync(to)) fs.unlinkSync(to); fs.renameSync(from, to); } }
    }
    const logFd = fs.openSync(log, fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
    const child = spawn(process.execPath, [serverFile], { detached: true, stdio: ["ignore", logFd, logFd], env: { PATH: "/var/apps/nodejs_v22/target/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8", VAR_DIR: dir, SOCKET_PATH: socket, ...(config.gatewayGid === undefined ? {} : { GATEWAY_GID: String(config.gatewayGid) }) } });
    fs.closeSync(logFd); child.unref();
    await new Promise((resolve, reject) => { child.once("spawn", resolve); child.once("error", reject); });
    record = { pid: child.pid, start: startTime(child.pid), server: serverFile };
    ensure(record.start, "START_FAILED", "无法记录服务启动身份"); atomicJson(pidFile, record);
    for (let i = 0; i < 60; i++) { if (await health()) { console.log("服务启动成功"); return; } if (!belongs(record)) break; await sleep(250); }
    if (belongs(record)) process.kill(record.pid, "SIGTERM");
    if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
    throw Error("服务未就绪，请查看 " + log);
  } finally { lock.release(); }
}
if (require.main === module) main(process.argv[2]).catch(e => { const message = (e.code ? e.code + ": " : "") + e.message; console.error(message); if (process.env.TRIM_TEMP_LOGFILE) { try { fs.writeFileSync(process.env.TRIM_TEMP_LOGFILE, message + "\n"); } catch {} } process.exitCode = process.argv[2] === "status" ? 3 : 1; });
module.exports = { main };
