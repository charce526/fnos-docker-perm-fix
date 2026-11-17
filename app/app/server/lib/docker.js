"use strict";
const fs = require("node:fs");
const { execFile } = require("node:child_process");
const { AppError, ensure, numericIdentity, containerSignature, identitySpaceSupported } = require("./policy");
function command(file, args, options = {}) {
  // Never inherit a Docker context/DOCKER_HOST that could describe remote paths as local paths.
  if (file === "docker") args = ["--host", "unix:///var/run/docker.sock", ...args];
  return new Promise((resolve, reject) => execFile(file, args, { timeout: 20000, maxBuffer: 32 * 1024 * 1024, encoding: "utf8", env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8" }, ...options }, (error, stdout, stderr) => {
    if (error) return reject(new AppError(error.killed ? "COMMAND_TIMEOUT" : "COMMAND_FAILED", `${file} 执行失败：${String(stderr || error.message).slice(0, 1000)}`, 503));
    resolve(stdout);
  }));
}
function json(text, kind) { try { return JSON.parse(text); } catch { throw new AppError("DOCKER_PROTOCOL", `Docker ${kind} 返回了无效 JSON`, 503); } }
async function collect(run = command) {
  const info = json(await run("docker", ["info", "--format", "{{json .}}"]), "info");
  ensure(typeof info.DockerRootDir === "string" && info.DockerRootDir.startsWith("/"), "DOCKER_INFO", "无法确认 Docker 数据目录", 503);
  const ids = (await run("docker", ["ps", "-aq", "--no-trunc"])).trim().split(/\s+/).filter(Boolean);
  ensure(ids.every(x => /^[a-f0-9]{64}$/.test(x)), "DOCKER_PROTOCOL", "容器 ID 格式异常", 503);
  const containers = [];
  for (let offset = 0; offset < ids.length; offset += 50) {
    const batch = json(await run("docker", ["inspect", ...ids.slice(offset, offset + 50)]), "inspect");
    ensure(Array.isArray(batch) && batch.length === ids.slice(offset, offset + 50).length, "INCOMPLETE_SCAN", "容器数据不完整，请重新扫描", 503);
    containers.push(...batch);
  }
  ensure(containers.every(c => /^[a-f0-9]{64}$/.test(c.Id) && c.Config && c.HostConfig && c.State && Array.isArray(c.Mounts)), "DOCKER_PROTOCOL", "容器结构不完整", 503);
  ensure(new Set(containers.map(c => c.Id)).size === ids.length && containers.every(c => ids.includes(c.Id)), "INCOMPLETE_SCAN", "Docker 返回了不匹配的容器集合", 503);
  const second = (await run("docker", ["ps", "-aq", "--no-trunc"])).trim().split(/\s+/).filter(Boolean).sort();
  ensure(JSON.stringify([...ids].sort()) === JSON.stringify(second), "INCOMPLETE_SCAN", "扫描期间容器列表发生变化，请重试", 409);
  return { info, containers };
}
function procStatus(text) {
  const values = {};
  for (const line of text.split("\n")) { const i = line.indexOf(":"); if (i > 0) values[line.slice(0, i)] = line.slice(i + 1).trim(); }
  const uid = (values.Uid || "").split(/\s+/).map(Number), gid = (values.Gid || "").split(/\s+/).map(Number);
  ensure(uid.length === 4 && gid.length === 4 && [...uid, ...gid].every(Number.isSafeInteger), "IDENTITY", "进程身份信息不完整", 503);
  ensure(new Set(uid).size === 1 && new Set(gid).size === 1, "IDENTITY", "进程真实/有效/文件系统身份不同，暂不支持自动修复", 503);
  const groups = (values.Groups || "").split(/\s+/).filter(Boolean).map(Number).sort((a, b) => a - b);
  ensure(groups.every(x => Number.isSafeInteger(x) && x >= 0), "IDENTITY", "补充组信息无效", 503);
  return { uid: uid[0], gid: gid[0], groups, capabilities: values.CapEff, noNewPrivs: values.NoNewPrivs };
}
function identityMap(text) { return text.trim().split("\n").every(line => /^\s*0\s+0\s+4294967295\s*$/.test(line)); }
function processStamp(text) { const stamp = text.slice(text.lastIndexOf(")") + 2).trim().split(/\s+/)[19]; ensure(/^\d+$/.test(stamp || ""), "IDENTITY", "无法确认进程启动标识", 503); return stamp; }
function hasDacOverride(caps) { try { return (BigInt("0x" + (caps || "0")) & 2n) !== 0n; } catch { return false; } }
async function identity(c, info, run = command, read = p => fs.readFileSync(p, "utf8")) {
  const declaredUser = c.Config.User || "";
  // A configured user is useful diagnostic information, even when it cannot be used to repair a stopped container.
  const reference = message => ({ uid: null, gid: null, groups: [], source: declaredUser ? "declared" : "unknown", confidence: declaredUser ? "reference" : "unknown", ...numericIdentity(declaredUser), declaredUser, message, mappingVerified: false, canProbe: false });
  if (!identitySpaceSupported(c, info)) return reference("使用用户命名空间或 rootless；仅展示启动用户配置，尚未核对宿主机身份映射，未检查访问权限");
  if (!c.State.Running) {
    const declared = numericIdentity(c.Config.User);
    return declared ? { ...declared, declaredUser, mappingVerified: true, canProbe: false, message: "容器已停止，未检测权限" } : reference(declaredUser ? "容器已停止，UID/GID 不完整，未检测权限" : "容器已停止，未检测权限");
  }
  try {
    const listPids = async () => {
      const pids = (await run("docker", ["top", c.Id, "-eo", "pid"])).trim().split("\n").slice(1).map(x => x.trim()).filter(Boolean);
      ensure(pids.length && pids.every(p => /^[1-9]\d*$/.test(p)) && new Set(pids).size === pids.length, "IDENTITY", "无法读取进程列表");
      return pids.sort((a, b) => Number(a) - Number(b));
    };
    const pids = await listPids(), stamps = new Map();
    const identities = [];
    for (const pid of pids) {
      const stamp = processStamp(read(`/proc/${pid}/stat`));
      const mappingVerified = identityMap(read(`/proc/${pid}/uid_map`)) && identityMap(read(`/proc/${pid}/gid_map`));
      identities.push({ ...procStatus(read(`/proc/${pid}/status`)), mappingVerified });
      ensure(processStamp(read(`/proc/${pid}/stat`)) === stamp, "PROCESS_CHANGED", "读取身份时进程已被替换", 503);
      stamps.set(pid, stamp);
    }
    // Docker supplies membership. Recheck the PID set and process start times;
    // cgroup paths need not contain a literal full Docker ID on every host.
    ensure(JSON.stringify(await listPids()) === JSON.stringify(pids), "PROCESS_CHANGED", "读取身份时容器进程列表发生变化，请重新扫描", 503);
    for (const pid of pids) ensure(processStamp(read(`/proc/${pid}/stat`)) === stamps.get(pid), "PROCESS_CHANGED", "读取身份时进程已被替换，请重新扫描", 503);
    const nonroot = identities.filter(x => x.uid !== 0);
    const candidates = [...new Map(identities.map(x => [JSON.stringify(x), x])).values()].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const work = [...new Map(nonroot.map(x => [JSON.stringify(x), x])).values()];
    const pairs = new Set(work.map(x => `${x.uid}:${x.gid}`));
    if (!nonroot.length) {
      const value = candidates[0];
      const base = { uid: 0, gid: 0, groups: value.groups, candidates, declaredUser, source: "observed-process", mappingVerified: value.mappingVerified, canProbe: false };
      if (hasDacOverride(value.capabilities)) return { ...base, confidence: "root-privileged", rootPrivileged: true, message: "容器以 root 运行，挂载权限不受限" };
      return { ...base, confidence: "observed", message: "容器以 root 运行，缺少访问能力，未检测权限" };
    }
    const usable = work.filter(x => x.mappingVerified && /^0+$/.test(x.capabilities || ""));
    const base = { uid: pairs.size === 1 ? work[0].uid : null, gid: pairs.size === 1 ? work[0].gid : null, groups: usable.length === 1 ? usable[0].groups : [], candidates, declaredUser, source: "observed-process", mappingVerified: usable.length > 0, probeCandidates: usable, canProbe: usable.length > 0 };
    if (pairs.size !== 1) return { ...base, confidence: "observed", message: "存在多个容器 UID/GID，未自动修复" };
    if (!usable.length) return { ...base, confidence: "observed", message: "容器身份映射或能力不支持检测" };
    return { ...base, confidence: "verified", message: "可检测挂载路径访问权限" };
  } catch (error) { return reference(`实际进程身份读取失败：${error.message}；配置身份仅供参考，未检查访问权限`); }
}
module.exports = { command, collect, identity, procStatus, identityMap, containerSignature };
