"use strict";
const crypto = require("node:crypto");
const path = require("node:path").posix;
const MAX_ITEMS = 100;
const MAX_OBJECTS = 10000;
const PLAN_TTL = 5 * 60 * 1000;
class AppError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}
function ensure(condition, code, message, status) { if (!condition) throw new AppError(code, message, status); }
function isInside(parent, child) { return parent === child || child.startsWith(parent === "/" ? "/" : parent + "/"); }
function overlap(a, b) { return isInside(a, b) || isInside(b, a); }
function validPath(p) { return typeof p === "string" && p.startsWith("/") && !/[\x00-\x1f\x7f]/.test(p) && path.normalize(p) === p; }
function protectionReason(p, extra = []) {
  if (!validPath(p)) return "路径包含不支持的字符或未规范化";
  if (p === "/" || /^\/vol\d+$/.test(p)) return "不能自动修改文件系统根目录或 NAS 卷根：" + p;
  const system = ["/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/run", "/var", "/boot", "/root", "/lost+found"];
  const matched = system.find(x => isInside(x, p));
  if (matched) return "Linux 系统目录：" + matched;
  if (["/home", "/mnt", "/media", "/opt", "/tmp"].includes(p)) return "不能自动修改公共目录根：" + p;
  const managed = /^\/vol\d+\/@(?:appcenter|appconf)(?:\/|$)/.exec(p);
  if (managed) return "NAS 应用程序或配置目录：" + managed[0].replace(/\/$/, "");
  if (/^\/vol\d+\/@[^/]+$/.test(p)) return "不能自动修改 NAS 管理或共享目录的根：" + p;
  for (const entry of extra.filter(Boolean)) {
    const root = typeof entry === "string" ? entry : entry.path;
    if (root && (typeof entry === "object" && entry.recursive === false ? p === root : isInside(root, p))) return typeof entry === "string" ? "受保护的运行目录：" + root : entry.reason + "：" + root;
  }
  return null;
}
function protectedPath(p, extra = []) { return protectionReason(p, extra) !== null; }
function profile(value) { ensure(["auto", "read", "read-write"].includes(value), "INVALID_PROFILE", "检查参数无效"); return value; }
function uniqueKeys(keys) {
  ensure(Array.isArray(keys) && keys.length && keys.length <= MAX_ITEMS, "INVALID_KEYS", `请选择 1–${MAX_ITEMS} 项`);
  ensure(keys.every(k => typeof k === "string" && /^[a-f0-9]{64}$/.test(k)), "INVALID_KEYS", "候选项标识无效");
  return [...new Set(keys)];
}
function digest(value) { return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
function containerSignature(c) {
  return digest({ id: c.Id, image: c.Image, user: c.Config?.User || "", groups: c.HostConfig?.GroupAdd || [], userns: c.HostConfig?.UsernsMode || "", capAdd: c.HostConfig?.CapAdd || [], capDrop: c.HostConfig?.CapDrop || [], privileged: c.HostConfig?.Privileged || false, mounts: c.Mounts });
}
function numericIdentity(user) {
  const m = /^(\d+):(\d+)$/.exec(user || "");
  if (!m) return null;
  const uid = Number(m[1]), gid = Number(m[2]);
  return [uid, gid].every(x => Number.isSafeInteger(x) && x >= 0 && x <= 2147483647) ? { uid, gid, groups: [], source: "declared", confidence: "reference" } : null;
}
function identitySpaceSupported(c, info) { return !/rootless|userns/i.test(JSON.stringify(info.SecurityOptions || [])) && (!c.HostConfig?.UsernsMode || c.HostConfig.UsernsMode === "host"); }
function stateToken(s) {
  return { dev: String(s.dev), ino: String(s.ino), mode: Number(s.mode) & 0o7777, uid: Number(s.uid), gid: Number(s.gid), nlink: Number(s.nlink), ctimeNs: s.ctimeNs !== undefined ? String(s.ctimeNs) : String(s.ctimeMs), type: s.isDirectory() ? "directory" : s.isFile() ? "file" : "other" };
}
function sameObject(a, b) { return ["dev", "ino", "mode", "uid", "gid", "nlink", "ctimeNs", "type"].every(k => a?.[k] !== undefined && a[k] === b?.[k]); }
function desiredMode(mode, type, requirement) {
  // Keep group/other and special bits unchanged. A requirement is an explicit user-selected policy.
  return mode | (type === "directory" ? (requirement === "read-write" ? 0o700 : 0o500) : (requirement === "read-write" ? 0o600 : 0o400));
}
function mountUnescape(s) { return s.replace(/\\([0-7]{3})/g, (_, x) => String.fromCharCode(parseInt(x, 8))); }
function parseMountInfo(text) {
  return text.trim().split("\n").filter(Boolean).map(line => {
    const [left, right] = line.split(" - ");
    const a = left.split(" "), b = (right || "").split(" ");
    ensure(a.length >= 6 && b.length >= 3, "MOUNTINFO", "无法解析挂载信息", 503);
    return { id: a[0], device: a[2], root: mountUnescape(a[3]), point: mountUnescape(a[4]), options: a[5].split(","), fsType: b[0], source: mountUnescape(b[1]), superOptions: b[2].split(",") };
  });
}
function mountSafety(source, mounts, { recursive = true } = {}) {
  const under = recursive ? mounts.filter(m => m.point !== source && isInside(source, m.point)) : [];
  if (under.length) return { code: "nested_mount", message: "目录内存在子挂载，不能递归修复", conflicts: under.map(x => x.point) };
  const own = mounts.filter(m => isInside(m.point, source)).sort((a, b) => b.point.length - a.point.length)[0];
  if (!own || own.options.includes("ro") || own.superOptions.includes("ro") || !["ext4", "btrfs", "xfs"].includes(own.fsType)) return { code: "unsupported", message: "底层文件系统只读或未在支持范围（ext4/btrfs/xfs）内" };
  // A second bind view of any overlapping inode subtree makes exclusive ownership unprovable.
  const subtree = path.join(own.root, path.relative(own.point, source));
  const aliases = mounts.filter(m => m.id !== own.id && m.device === own.device && overlap(m.root, subtree) && !isInside(m.point, own.point));
  if (aliases.length) return { code: "shared_overlap", message: "存在同一底层目录的其他挂载视图", conflicts: aliases.map(x => x.point) };
  return { code: "eligible", message: "路径边界检查通过" };
}
module.exports = { AppError, ensure, MAX_ITEMS, MAX_OBJECTS, PLAN_TTL, isInside, overlap, validPath, protectedPath, protectionReason, profile, uniqueKeys, digest, containerSignature, numericIdentity, identitySpaceSupported, stateToken, sameObject, desiredMode, parseMountInfo, mountSafety };
