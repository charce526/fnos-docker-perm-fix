"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { ensure } = require("./policy");
function codeRoot(directory) {
  const real = fs.realpathSync(directory), root = path.dirname(real);
  ensure(path.basename(real) === "server" && root !== path.parse(root).root, "UNSAFE_CODE", "应用代码目录位置不正确", 503);
  return { real, root };
}
function initializeCode(directory) {
  ensure(process.platform === "linux" && process.getuid?.() === 0, "ROOT_REQUIRED", "初始化应用代码权限需要 Linux root", 503);
  const { real, root } = codeRoot(directory);
  ensure(process.env.TRIM_APPDEST && fs.realpathSync(process.env.TRIM_APPDEST) === root, "UNSAFE_CODE", "只允许初始化应用中心指定的本应用目录", 503);
  const set = (file, directory) => {
    const before = fs.lstatSync(file);
    ensure(!before.isSymbolicLink() && (directory ? before.isDirectory() : before.isFile()) && (directory || before.nlink === 1), "UNSAFE_CODE", "应用代码包含链接或特殊对象：" + file, 503);
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK | (directory ? fs.constants.O_DIRECTORY : 0));
    try {
      const current = fs.fstatSync(fd);
      ensure(current.dev === before.dev && current.ino === before.ino, "UNSAFE_CODE", "应用代码目录在初始化期间发生变化：" + file, 503);
      if (current.uid !== 0 || current.gid !== 0) fs.fchownSync(fd, 0, 0);
      fs.fchmodSync(fd, directory || file.endsWith(".sh") ? 0o755 : 0o644);
    } finally { fs.closeSync(fd); }
  };
  const walk = dir => {
    set(dir, true);
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(file); else set(file, false);
    }
  };
  // AppCenter owns the NAS volume and @appcenter parents. Never chmod/chown those paths.
  set(root, true);
  walk(real);
  const ui = path.join(root, "ui");
  if (fs.existsSync(ui)) walk(ui);
}
function verifyCode(directory) {
  const { real, root } = codeRoot(directory);
  const check = file => {
    const s = fs.lstatSync(file);
    ensure(!s.isSymbolicLink() && s.uid === 0 && !(s.mode & 0o022), "UNSAFE_CODE", "本应用代码权限不安全：" + file, 503);
    return s;
  };
  check(root);
  const walk = dir => { check(dir); for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const file = path.join(dir, entry.name); if (entry.isDirectory()) walk(file); else check(file); } };
  walk(real);
}
module.exports = { initializeCode, verifyCode };
