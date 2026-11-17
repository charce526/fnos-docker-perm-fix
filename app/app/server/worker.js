"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const D = require("./lib/docker");
const T = require("./lib/tree");
const P = require("./lib/policy");
let cancelled = false;
const initialParent = process.ppid;
const progress = data => { if (process.connected) process.send({ type: "progress", data }); };
function checkpoint() { P.ensure(!cancelled && process.ppid === initialParent, "INTERRUPTED", "任务已中断；已完成修改不会自动回滚", 409); }
function capabilities() {
  return { linuxRoot: T.linuxReady(), node: process.version, getfacl: ["/usr/bin/getfacl", "/bin/getfacl"].find(p => fs.existsSync(p)) || null, getcap: ["/usr/sbin/getcap", "/sbin/getcap", "/usr/bin/getcap"].find(p => fs.existsSync(p)) || null, supportedFileSystems: ["ext4", "btrfs", "xfs"], repairAclPolicy: "preserve", recursiveLimit: P.MAX_OBJECTS };
}
function mounts() { return P.parseMountInfo(fs.readFileSync("/proc/self/mountinfo", "utf8")); }
function extraProtected(info) {
  const dockerRoot = fs.realpathSync(info.DockerRootDir);
  const engineFolders = new Set(["containers", "image", "volumes", "overlay", "overlay2", "aufs", "btrfs", "devicemapper", "zfs", "vfs", "buildkit", "network", "plugins", "runtimes", "swarm", "tmp", "containerd", "distribution", "trust"]);
  if (/^[a-zA-Z0-9_.-]+$/.test(info.Driver || "")) engineFolders.add(info.Driver);
  // User Compose folders can share a NAS parent with Docker storage. Protect engine internals,
  // not every sibling project below that parent.
  return [{ path: dockerRoot, recursive: false, reason: "Docker 存储根目录" }, ...[...engineFolders].map(name => ({ path: path.join(dockerRoot, name), reason: "Docker 引擎内部目录" })), { path: fs.realpathSync(path.resolve(__dirname, "..")), reason: "本工具程序目录" }, ...[process.env.VAR_DIR, process.env.TRIM_PKGETC, process.env.TRIM_PKGHOME].filter(Boolean).map(p => ({ path: fs.realpathSync(p), reason: "本工具运行目录" }))];
}
function collectMounts(data) {
  const out = [];
  for (const c of data.containers) for (const m of c.Mounts.filter(m => m.Type === "bind")) {
    const item = { containerId: c.Id, name: c.Name.replace(/^\//, ""), source: m.Source, target: m.Destination, rw: !!m.RW };
    try { P.ensure(P.validPath(m.Source), "INVALID_PATH", "路径包含控制字符或未规范化"); item.real = fs.realpathSync(m.Source); item.token = P.stateToken(fs.statSync(item.real, { bigint: true })); }
    catch (e) { item.error = e.code || "PATH_ERROR"; item.message = e.message; }
    out.push(item);
  }
  return out;
}
function safety(m, all, mountTable, protectedPaths) {
  if (m.error) return { code: m.error === "ENOENT" ? "missing" : "unsupported", message: m.message };
  if (!["directory", "file"].includes(m.token.type)) return { code: "unsupported", message: "绑定对象不是普通文件或目录" };
  if (m.token.type === "file" && m.token.nlink !== 1) return { code: "unsupported", message: "文件存在硬链接，无法确认独占修改范围" };
  const protectedReason = P.protectionReason(m.real, protectedPaths);
  if (protectedReason) return { code: "protected", message: protectedReason };
  const conflicts = all.filter(other => other !== m && !other.error && (P.overlap(m.real, other.real) || (m.token.dev === other.token.dev && m.token.ino === other.token.ino)));
  if (conflicts.length) return { code: "shared_overlap", message: "挂载路径相等、父子重叠或指向同一对象", conflicts: conflicts.map(x => ({ container: x.name, source: x.source, target: x.target })) };
  return P.mountSafety(m.real, mountTable, { recursive: false });
}
async function scan({ profile = "auto" } = {}) {
  P.profile(profile);
  const cap = capabilities();
  P.ensure(cap.linuxRoot, "UNSUPPORTED_RUNTIME", "扫描需要 Linux root 环境及安全文件描述符操作支持", 503);
  progress({ phase: "collect", message: "读取 Docker 快照" });
  const data = await D.collect(), table = mounts(), all = collectMounts(data), protectedPaths = extraProtected(data.info);
  const containers = [], warnings = all.filter(x => x.error).map(x => ({ container: x.name, source: x.source, code: x.error, message: x.message }));
  let done = 0;
  for (const c of data.containers) {
    checkpoint();
    const id = await D.identity(c, data.info);
    const record = { id: c.Id, name: c.Name.replace(/^\//, ""), project: c.Config.Labels?.["com.docker.compose.project"] || null, service: c.Config.Labels?.["com.docker.compose.service"] || null, image: c.Config.Image, running: !!c.State.Running, state: c.State.Status, signature: P.containerSignature(c), identity: id, mounts: [] };
    for (const m of all.filter(x => x.containerId === c.Id)) {
      checkpoint();
      const safe = safety(m, all, table, protectedPaths);
      const requirement = profile === "auto" ? (m.rw ? "read-write" : "read") : profile;
    const result = { key: crypto.randomBytes(32).toString("hex"), source: m.source, real: m.real, target: m.target, rw: m.rw, token: m.token, safetyStatus: safe.code, repairBlockedReason: safe.code === "eligible" ? null : safe.message, conflicts: safe.conflicts || [], status: "unverified", reason: safe.message, canPlanRepair: false, evidence: [], requirement, checkMethod: "not_checked" };
      let root;
      if (m.error || !["directory", "file"].includes(m.token?.type)) result.status = safe.code;
      else if (!id.canProbe) {
        if (id.rootPrivileged) {
          result.status = "accessible";
          result.reason = "容器以 root 运行，权限不受限";
          result.repairBlockedReason = "容器 root 有文件访问能力，无需修复权限";
        } else {
          result.status = "not_checked";
          result.reason = c.State.Running ? "无法可靠识别容器身份，未检测权限" : "容器已停止，未检测权限";
        }
        const canUseDeclared = !id.rootPrivileged && !c.State.Running && id.source === "declared" && id.uid > 0 && id.mappingVerified && (m.token.type !== "file" || m.token.nlink === 1);
        result.canPlanRepair = canUseDeclared && safe.code === "eligible" && !!cap.getfacl;
        result.repairBlockedReason = safe.code !== "eligible" ? safe.message : !cap.getfacl ? "缺少 getfacl，修复已禁用" : canUseDeclared ? "已按容器声明身份预览修复" : "未取得可用于修复的 UID:GID";
      }
      else {
        try {
          root = T.openRoot(m.real);
          const tree = T.inventory(root, { recursive: false });
          result.treeCount = tree.objects.length; result.exclusions = tree.exclusions.slice(0, 32); result.treeDigest = tree.digest; result.scope = "mount-root";
          const identities = id.probeCandidates?.length ? id.probeCandidates : [id];
          const probes = [];
          for (const candidate of identities) probes.push(await T.probe(root, candidate, requirement, __filename, { recursive: false }));
          const evidence = probes.flatMap(x => x.evidence).slice(0, 32);
          result.evidence = evidence;
          result.access = probes.length === 1 ? probes[0].rootAccess || null : ["read", "write", "enter"].reduce((access, key) => {
            const values = probes.map(x => x.rootAccess?.[key]).filter(x => x !== undefined);
            if (values.length) access[key] = values.every(Boolean);
            return access;
          }, {});
          result.checkMethod = probes[0].method; result.checked = probes.reduce((n, x) => n + x.checked, 0); result.coverageComplete = probes.every(x => x.complete) && !tree.exclusions.length;
          const denied = evidence.some(x => x.missing.some(op => op === "read" || op === "enter")) || (m.rw && result.access?.write === false);
          result.status = denied ? "permission_denied" : result.coverageComplete ? ((m.token.uid !== id.uid || m.token.gid !== id.gid) ? "ownerdiff" : "accessible") : "not_checked";
          const missing = evidence.flatMap(x => x.missing).filter((x, i, list) => list.indexOf(x) === i);
          result.reason = denied ? `挂载路径缺少：${missing.map(x => ({ read: "读", write: "写", enter: "进入" }[x] || x)).join("、")}` : result.coverageComplete ? ((m.token.uid !== id.uid || m.token.gid !== id.gid) ? "可访问，宿主机属主与容器 UID/GID 不同" : "挂载路径访问正常") : "本次未检测挂载路径访问权限";
          if (tree.exclusions.length) result.safetyStatus = "unsupported";
          result.canPlanRepair = safe.code === "eligible" && !tree.exclusions.length && !!cap.getfacl && !id.rootPrivileged && identities.length === 1 && id.uid > 0 && ["permission_denied", "ownerdiff"].includes(result.status);
          if (!cap.getfacl) result.reason += "；缺少 getfacl，不能记录修改信息，修复已禁用";
        } catch (e) { result.status = "scan_error"; result.reason = e.message; warnings.push({ container: record.name, source: m.source, code: e.code || "SCAN_ERROR", message: e.message }); }
        finally { if (root !== undefined) fs.closeSync(root); }
      }
      record.mounts.push(result);
      progress({ phase: "scan", done: ++done, total: all.length, container: record.name, message: "检查挂载路径" });
    }
    containers.push(record);
  }
  return { schemaVersion: 2, checkVersion: 4, scanId: crypto.randomUUID(), createdAt: new Date().toISOString(), complete: !warnings.length, profile, capabilities: cap, warnings, containers };
}
async function aclFor(fd, executable) {
  return new Promise((resolve, reject) => {
    const { spawn } = require("node:child_process");
    const child = spawn(executable, ["-c", "-p", "-n", "--", "/proc/self/fd/3"], { stdio: ["ignore", "pipe", "pipe", fd], env: { PATH: "/usr/bin:/bin", LANG: "C" } });
    let text = "", errorText = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 10000);
    child.stdout.on("data", b => { text += b; if (text.length > 65536) child.kill("SIGKILL"); });
    child.stderr.on("data", b => { errorText = (errorText + b).slice(-1000); });
    child.on("error", e => { clearTimeout(timer); reject(e); });
    child.on("close", code => { clearTimeout(timer); if (code === 0 && /^user::[rwx-]{3}$/m.test(text)) resolve(text); else reject(new P.AppError("ACL_SNAPSHOT", "无法读取 ACL 信息：" + errorText, 503)); });
  });
}
async function fileCapabilities(fd, executable) {
  P.ensure(executable, "CAPABILITY_TOOL", "调整文件属主前需要 getcap 检查；当前缺少该工具，已拒绝此操作", 503);
  return new Promise((resolve, reject) => {
    const { spawn } = require("node:child_process");
    const child = spawn(executable, ["-n", "/proc/self/fd/3"], { stdio: ["ignore", "pipe", "pipe", fd], env: { PATH: "/usr/bin:/bin", LANG: "C" } });
    let text = "", diagnostic = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 10000);
    child.stdout.on("data", b => { text += b; if (text.length > 65536) child.kill("SIGKILL"); });
    child.stderr.on("data", b => { diagnostic = (diagnostic + b).slice(-1000); });
    child.on("error", e => { clearTimeout(timer); reject(e); });
    child.on("close", code => { clearTimeout(timer); if (code === 0 && !diagnostic) resolve(text.trim()); else reject(new P.AppError("CAPABILITY_TOOL", "文件能力检查失败：" + diagnostic, 503)); });
  });
}
async function assertBinding(item, data, table, all) {
  const c = data.containers.find(x => x.Id === item.containerId);
  P.ensure(c && P.containerSignature(c) === item.signature, "STALE_PLAN", "容器配置或挂载已变化，请重新扫描", 409);
  P.ensure(P.identitySpaceSupported(c, data.info), "IDENTITY_MAP", "Docker 身份映射或 rootless 状态已变化，拒绝使用旧计划", 409);
  const m = all.find(x => x.containerId === c.Id && x.source === item.source && x.target === item.target);
  P.ensure(m && !m.error && m.real === item.real && P.sameObject(m.token, item.token), "STALE_PLAN", "挂载对象或权限已变化，请重新扫描", 409);
  const safe = safety(m, all, table, extraProtected(data.info));
  P.ensure(safe.code === "eligible", "UNSAFE_PATH", safe.message, 409);
  return c;
}
function sameRuntimeIdentity(a, b) {
  return a?.uid === b?.uid && a?.gid === b?.gid &&
    JSON.stringify(a?.groups || []) === JSON.stringify(b?.groups || []) &&
    a?.mappingVerified === b?.mappingVerified;
}
async function buildPlan({ scan: snapshot, keys, action }) {
  P.uniqueKeys(keys);
  P.ensure(snapshot && snapshot.schemaVersion === 2 && Date.now() - Date.parse(snapshot.createdAt) < P.PLAN_TTL, "STALE_SCAN", "扫描已超过五分钟，请重新扫描", 409);
  P.ensure(snapshot.capabilities?.getfacl, "ACL_SNAPSHOT", "缺少 getfacl，不能建立可追溯计划", 503);
  const data = await D.collect(), table = mounts(), all = collectMounts(data), items = [];
  for (const key of P.uniqueKeys(keys)) {
    checkpoint();
    const c = snapshot.containers.find(c => c.mounts.some(m => m.key === key));
    const m = c?.mounts.find(m => m.key === key);
    P.ensure(m?.canPlanRepair && m.safetyStatus === "eligible", "NOT_ELIGIBLE", "候选项不可建立修复计划", 409);
    P.ensure(action === "align-container-identity", "INVALID_ACTION", "修复方式无效", 409);
    P.ensure(c.identity.uid > 0 && c.identity.mappingVerified, "IDENTITY", "修复身份不可靠", 409);
    P.ensure(c.identity.confidence === "verified", "IDENTITY", "修复身份不可靠", 409);
    const item = { ...m, containerId: c.id, container: c.name, identity: c.identity, signature: c.signature, action, requirement: m.requirement || snapshot.profile };
    const current = await assertBinding(item, data, table, all);
    if (current.State.Running) {
      const now = await D.identity(current, data.info);
      P.ensure(P.digest(now) === P.digest(c.identity), "STALE_IDENTITY", "工作进程身份发生变化，请重扫", 409);
    }
    const root = T.openRoot(item.real);
    try {
      const tree = T.inventory(root, { recursive: false });
      P.ensure(tree.digest === m.treeDigest && !tree.exclusions.length, "STALE_PLAN", "挂载路径属性发生变化或包含不支持对象，请重扫", 409);
      const actions = T.actionsFor(tree.objects, c.identity, item.requirement);
      P.ensure(actions.length, "NO_ACTION", "挂载路径已符合容器身份和权限，无需修复", 409);
      P.ensure(actions.length <= 2000 && actions.every(x => !(x.before.mode & 0o7000)), "UNSUPPORTED_OBJECT", "涉及特殊权限位或超过 2000 个变更对象，请拆分并人工处理", 422);
      for (const a of actions) {
        checkpoint();
        let objectFd;
        T.withObject(root, a.relativePath, fd => { objectFd = fs.openSync(T.fdPath(fd), fs.constants.O_RDONLY | fs.constants.O_NONBLOCK); });
        try {
          P.ensure(P.sameObject(P.stateToken(fs.fstatSync(objectFd, { bigint: true })), a.before), "STALE_OBJECT", "预览期间对象发生变化，请重扫", 409);
          if (a.before.type === "file" && (a.before.uid !== a.after.uid || a.before.gid !== a.after.gid)) P.ensure(!await fileCapabilities(objectFd, capabilities().getcap), "FILE_CAPABILITIES", "文件带有 capability，调整属主可能清除该属性，已拒绝自动修复", 422);
          a.acl = await aclFor(objectFd, snapshot.capabilities.getfacl);
        } finally { fs.closeSync(objectFd); }
      }
      items.push({ ...item, treeDigest: tree.digest, treeCount: tree.objects.length, actions });
      P.ensure(items.reduce((n, x) => n + x.actions.length, 0) <= 2000 && Buffer.byteLength(JSON.stringify(items)) <= 4 * 1024 * 1024, "PLAN_LIMIT", "整批计划超过 2000 个动作或 4MB，请缩小范围", 422);
    } finally { fs.closeSync(root); }
    progress({ phase: "plan", done: items.length, total: keys.length, message: "保存挂载路径的权限及 ACL 快照" });
  }
  return { schemaVersion: 2, planId: crypto.randomUUID(), createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + P.PLAN_TTL).toISOString(), profile: snapshot.profile, action: "align-container-identity", aclPolicy: "preserve", items };
}
function aclInvariant(text) { return text.split("\n").filter(x => x && !/^user::/.test(x)).sort().join("\n"); }
async function execute({ plan, journalPath }) {
  P.ensure(plan && plan.schemaVersion === 2 && Date.parse(plan.expiresAt) > Date.now(), "STALE_PLAN", "计划已过期，请重新预览", 409);
  const cap = capabilities();
  P.ensure(cap.linuxRoot && cap.getfacl, "UNSUPPORTED_RUNTIME", "当前运行环境不支持安全修复", 503);
  const results = [];
  const initial = await D.collect(), table = mounts(), all = collectMounts(initial);
  for (const item of plan.items) {
    const c = await assertBinding(item, initial, table, all);
    if (c.State.Running) {
      const now = await D.identity(c, initial.info);
      P.ensure(sameRuntimeIdentity(now, item.identity), "STALE_IDENTITY", "容器运行身份已变化，请重新预览", 409);
    }
    const root = T.openRoot(item.real);
    try { const inv = T.inventory(root, { recursive: false }); P.ensure(inv.digest === item.treeDigest && !inv.exclusions.length, "STALE_PLAN", "计划中的挂载路径已变化", 409); }
    finally { fs.closeSync(root); }
  }
  const journal = fs.openSync(journalPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  function log(event) { fs.writeSync(journal, JSON.stringify({ at: new Date().toISOString(), ...event }) + "\n"); fs.fsyncSync(journal); }
  try {
    log({ type: "snapshot", plan });
    for (const item of plan.items) {
      let root, changed = 0, pending = null;
      const errors = [];
      try {
        checkpoint(); root = T.openRoot(item.real);
        for (const a of item.actions) {
          checkpoint();
          if (changed % 20 === 0) {
            const fresh = await D.collect(), own = fresh.containers.find(c => c.Id === item.containerId);
            P.ensure(own && P.containerSignature(own) === item.signature, "STALE_PLAN", "执行期间容器配置、挂载或运行身份发生变化", 409);
            P.ensure(P.identitySpaceSupported(own, fresh.info), "IDENTITY_MAP", "执行期间 Docker 身份映射已变化", 409);
            if (own.State.Running) {
              const freshIdentity = await D.identity(own, fresh.info);
              P.ensure(sameRuntimeIdentity(freshIdentity, item.identity), "STALE_IDENTITY", "执行期间容器运行身份发生变化", 409);
            }
            const freshAll = collectMounts(fresh), ownMount = freshAll.find(m => m.containerId === item.containerId && m.source === item.source && m.target === item.target);
            P.ensure(ownMount && ownMount.real === item.real && ownMount.token.dev === item.token.dev && ownMount.token.ino === item.token.ino && safety(ownMount, freshAll, mounts(), extraProtected(fresh.info)).code === "eligible", "UNSAFE_PATH", "执行期间挂载边界发生变化", 409);
          }
          let fd;
          T.withObject(root, a.relativePath, handle => { fd = fs.openSync(T.fdPath(handle), fs.constants.O_RDONLY | fs.constants.O_NONBLOCK); });
          try {
            const current = P.stateToken(fs.fstatSync(fd, { bigint: true }));
            P.ensure(P.sameObject(current, a.before) && (current.type !== "file" || current.nlink === 1), "STALE_OBJECT", "对象已变化或出现硬链接", 409);
            P.ensure(aclInvariant(await aclFor(fd, cap.getfacl)) === aclInvariant(a.acl), "STALE_ACL", "对象 ACL 已变化", 409);
            if (current.type === "file" && (current.uid !== a.after.uid || current.gid !== a.after.gid)) P.ensure(!await fileCapabilities(fd, cap.getcap), "FILE_CAPABILITIES", "对象带有文件能力，拒绝更改属主", 422);
            checkpoint(); pending = a.relativePath;
            log({ type: "before", key: item.key, object: a });
            P.ensure(P.sameObject(P.stateToken(fs.fstatSync(fd, { bigint: true })), a.before), "STALE_OBJECT", "修改前对象再次发生变化，操作已停止", 409);
            if (current.uid !== a.after.uid || current.gid !== a.after.gid) fs.fchownSync(fd, a.after.uid, a.after.gid);
            fs.fchmodSync(fd, a.after.mode);
            const after = P.stateToken(fs.fstatSync(fd, { bigint: true }));
            P.ensure(after.uid === a.after.uid && after.gid === a.after.gid && after.mode === a.after.mode && after.nlink === current.nlink && aclInvariant(await aclFor(fd, cap.getfacl)) === aclInvariant(a.acl), "VERIFY_FAILED", "权限或 ACL 验证失败", 503);
            log({ type: "after", key: item.key, relativePath: a.relativePath, after });
            changed++; pending = null;
          } finally { fs.closeSync(fd); }
          progress({ phase: "fix", done: changed, total: item.actions.length, container: item.container, message: "按已确认计划修改并验证挂载路径" });
        }
        const verified = await T.probe(root, item.identity, item.requirement, __filename, { recursive: false });
        const success = verified.complete && !verified.evidence.length;
        const result = { key: item.key, container: item.container, source: item.source, changed, status: success ? "verified_success" : "partial_failure", message: success ? "挂载路径权限及访问需求已验证；请重启容器并结合业务日志确认效果" : "挂载路径已部分修改，但复测仍有受限项；请重启容器并结合业务日志确认", verification: verified };
        results.push(result); log({ type: "item_result", result });
      } catch (e) {
        errors.push({ code: e.code || "FS_ERROR", message: e.message, pending });
        const result = { key: item.key, container: item.container, source: item.source, changed, status: e.code === "INTERRUPTED" ? "interrupted" : (changed || pending ? "partial_failure" : "failed"), message: e.message, errors };
        results.push(result); log({ type: "item_result", result });
        for (const rest of plan.items.slice(results.length)) results.push({ key: rest.key, container: rest.container, source: rest.source, status: "skipped", changed: 0, message: "前项失败或任务中断，尚未执行" });
        break;
      } finally { if (root !== undefined) fs.closeSync(root); }
    }
    log({ type: "finished", results });
    return { schemaVersion: 2, planId: plan.planId, results, journal: path.basename(journalPath) };
  } finally { fs.closeSync(journal); }
}
async function main() {
  if (process.argv[2] === "probe") {
    let input = "";
    for await (const chunk of process.stdin) { input += chunk; P.ensure(input.length < 32768, "INPUT_LIMIT", "探测输入超限"); }
    process.stdout.write(JSON.stringify(T.runProbe(JSON.parse(input)))); return;
  }
  if (process.argv[2] === "scan") { process.stdout.write(JSON.stringify(await scan())); return; }
  P.ensure(process.send, "IPC_REQUIRED", "写操作只能通过应用的计划与任务接口执行");
  process.on("SIGTERM", () => { cancelled = true; });
  process.on("disconnect", () => { cancelled = true; });
  process.once("message", async message => {
    try {
      const handlers = { scan, plan: buildPlan, execute };
      P.ensure(handlers[message.mode], "INVALID_MODE", "任务模式无效");
      const result = await handlers[message.mode](message.payload);
      if (process.connected) process.send({ type: "result", data: result }, () => process.disconnect());
    } catch (e) { if (process.connected) process.send({ type: "error", error: { code: e.code || "ENGINE_ERROR", message: e.message, status: e.status || 500 } }, () => process.disconnect()); }
  });
}
if (require.main === module) main().catch(e => { process.stderr.write(JSON.stringify({ code: e.code || "ENGINE_ERROR", message: e.message }) + "\n"); process.exitCode = 1; });
module.exports = { scan, buildPlan, execute, collectMounts, safety, aclInvariant, capabilities, assertBinding };
