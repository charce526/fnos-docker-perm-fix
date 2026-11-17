"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { AppError, ensure, profile, uniqueKeys } = require("./lib/policy");
const { Audit, safeDirectory } = require("./lib/storage");
const { JobManager } = require("./lib/jobs");
const VERSION = "1.3.0";
const PREFIX = "/app/docker-perm-fix";
function parseOrigin(value) {
  try {
    ensure(typeof value === "string" && value.length <= 2048, "ORIGIN", "请求来源不合法", 403);
    const url = new URL(value);
    ensure(["http:", "https:"].includes(url.protocol) && !url.username && !url.password && url.origin === value, "ORIGIN", "请求来源不合法", 403);
    return url.origin;
  } catch { throw new AppError("ORIGIN", "请求来源不合法", 403); }
}
function publicOrigin(req) {
  const browserOrigin = req.headers.origin && parseOrigin(req.headers.origin);
  const appOrigin = req.headers["x-app-origin"] && parseOrigin(req.headers["x-app-origin"]);
  ensure(!browserOrigin || !appOrigin || browserOrigin === appOrigin, "ORIGIN", "页面来源与请求来源不一致，请刷新应用", 403);
  if (browserOrigin || appOrigin) return browserOrigin || appOrigin;
  if (req.headers.referer) {
    try { return parseOrigin(new URL(req.headers.referer).origin); } catch { throw new AppError("ORIGIN", "页面来源不合法", 403); }
  }
  // Non-browser API clients can still obtain a token. The fnOS UI supplies X-App-Origin.
  return parseOrigin(req.protocol + "://" + req.headers.host);
}
function createApp({ manager, audit, devToken = null } = {}) {
  // Production calls this only after verifyCode; don't load third-party code before that check.
  const express = require("express");
  const app = express();
  app.disable("x-powered-by");
  const tokens = new Map(), scans = new Map();
  app.use((req, res, next) => {
    res.set({ "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'none'; form-action 'self'", "Cache-Control": "no-store" });
    next();
  });
  app.use(express.json({ limit: "64kb", strict: true }));
  const api = express.Router();
  api.get("/health", (req, res) => res.json({ ok: true }));
  api.use((req, res, next) => {
    try {
      if (devToken) {
        const value = req.headers["x-dev-token"];
        ensure(typeof value === "string" && value.length === devToken.length && crypto.timingSafeEqual(Buffer.from(value), Buffer.from(devToken)), "UNAUTHENTICATED", "开发模式需要独立开发令牌", 401);
        req.user = { uid: "local-development", username: "local-development" };
      } else {
        ensure(typeof req.headers["x-trim-userid"] === "string" && req.headers["x-trim-userid"].length <= 128 && req.headers["x-trim-userid"], "UNAUTHENTICATED", "登录状态已失效，请重新登录飞牛", 401);
        ensure(req.headers["x-trim-isadmin"] === "true", "FORBIDDEN", "仅管理员可以使用本应用", 403);
        req.user = { uid: req.headers["x-trim-userid"], username: String(req.headers["x-trim-username"] || "unknown").slice(0, 128) };
      }
      next();
    } catch (e) {
      try { audit.write("DENY", { code: e.code, method: req.method, path: req.path, uid: String(req.headers["x-trim-userid"] || "").slice(0, 128) }); } catch {}
      next(e);
    }
  });
  api.get("/session", (req, res) => {
    const now = Date.now();
    for (const [k, value] of tokens) if (now > value.expires) tokens.delete(k);
    const origin = publicOrigin(req), key = req.user.uid + "\0" + origin;
    let token = tokens.get(key);
    if (!token) {
      if (tokens.size >= 256) return res.status(503).json({ code: "SESSION_LIMIT", error: "会话过多，请稍后重试" });
      token = { value: crypto.randomBytes(32).toString("hex"), owner: req.user.uid, origin, expires: now + 3600000 }; tokens.set(key, token);
    }
    res.json({ version: VERSION, csrfToken: token.value, maxItems: 100, planTtlSeconds: 300, activeJob: manager.active?.job.owner === req.user.uid ? manager.active.job.id : null, busy: !!manager.active, auditError: audit.error, devMode: !!devToken });
  });
  api.use((req, res, next) => {
    if (["GET", "HEAD"].includes(req.method)) return next();
    try {
      ensure(req.headers["sec-fetch-site"] !== "cross-site", "ORIGIN", "不接受跨站操作", 403);
      const token = [...tokens.values()].find(t => t.owner === req.user.uid && t.value === req.headers["x-csrf-token"]);
      ensure(token && token.expires > Date.now() && req.headers["x-csrf-token"] === token.value, "CSRF", "页面会话已过期，请刷新后重试", 403);
      // Compare with the browser origin bound when issuing this token, not the proxy's Host.
      if (req.headers.origin) ensure(parseOrigin(req.headers.origin) === token.origin, "ORIGIN", "请求来源与当前页面不一致，请刷新应用", 403);
      if (req.headers["x-app-origin"]) ensure(parseOrigin(req.headers["x-app-origin"]) === token.origin, "ORIGIN", "页面来源已变化，请重新进入应用", 403);
      next();
    } catch (e) { try { audit.write("REJECT", { owner: req.user.uid, code: e.code, path: req.path }); } catch {} next(e); }
  });
  api.post("/scan", (req, res, next) => {
    try {
      const checkProfile = profile(req.body?.profile || "auto");
      const now = Date.now();
      for (const [uid, list] of scans) { const alive = list.filter(t => now - t < 30000); if (!alive.length) scans.delete(uid); else scans.set(uid, alive); }
      const list = scans.get(req.user.uid) || [];
      ensure(list.length < 10, "RATE_LIMIT", "扫描过于频繁，请 30 秒后重试", 429);
      const job = manager.start("scan", { profile: checkProfile }, req.user.uid);
      scans.set(req.user.uid, [...list, now]);
      res.status(202).json({ jobId: job.id });
    } catch (e) { next(e); }
  });
  api.post("/plan", (req, res, next) => {
    try {
      const keys = uniqueKeys(req.body?.keys);
      ensure(req.body?.action === "align-container-identity", "INVALID_ACTION", "修复方式无效");
      const source = manager.findResult("scanId", req.body.scanId, req.user.uid);
      const job = manager.start("plan", { scan: source.result, keys, action: req.body.action }, req.user.uid);
      res.status(202).json({ jobId: job.id });
    } catch (e) { next(e); }
  });
  api.post("/fix", (req, res, next) => {
    try {
      ensure(typeof req.body?.planId === "string" && /^[a-f0-9-]{36}$/.test(req.body.planId), "PLAN_REQUIRED", "修复需要有效的服务器计划");
      const source = manager.findResult("planId", req.body.planId, req.user.uid);
      const job = manager.start("execute", { plan: source.result }, req.user.uid, "execute:" + source.result.planId);
      res.status(202).json({ jobId: job.id });
    } catch (e) { next(e); }
  });
  api.get("/jobs", (req, res) => res.json({ busy: !!manager.active, jobs: manager.list(req.user.uid).map(({ id, mode, state, createdAt, finishedAt }) => ({ id, mode, state, createdAt, finishedAt })) }));
  api.get("/jobs/:id", (req, res, next) => { try { res.json(manager.get(req.params.id, req.user.uid)); } catch (e) { next(e); } });
  api.get("/audit", (req, res, next) => { try { res.json({ lines: audit.read() }); } catch (e) { next(e); } });
  api.use((req, res) => res.status(404).json({ code: "API_NOT_FOUND", error: "接口或请求方法不存在" }));
  app.use(PREFIX + "/api", api);
  app.use("/api", (req, res) => res.status(404).json({ code: "API_NOT_FOUND", error: "请使用应用网关前缀" }));
  app.get("/", (req, res) => res.redirect(PREFIX + "/"));
  app.use(PREFIX, express.static(path.join(__dirname, "public"), { index: "index.html", dotfiles: "deny", fallthrough: false, etag: false, lastModified: false, cacheControl: false }));
  app.use((req, res) => res.status(404).json({ code: "NOT_FOUND", error: "资源不存在" }));
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = err.type === "entity.too.large" ? 413 : err.type === "entity.parse.failed" ? 400 : (err.status || 500);
    if (status >= 400) { try { audit.write("REQUEST_ERROR", { owner: req.user?.uid || null, authenticated: !!req.user, path: req.path, code: err.code || err.type, status }); } catch {} }
    res.status(status).json({ code: err.code || err.type || "INTERNAL_ERROR", error: status === 413 ? "请求内容超过 64KB" : status === 500 && !(err instanceof AppError) ? "服务内部错误，请查看应用日志" : err.message });
  });
  return app;
}
const { verifyCode } = require("./lib/code-permissions");
async function start() {
  const dev = process.env.DEV_MODE === "1";
  const varDir = process.env.VAR_DIR;
  ensure(varDir && path.isAbsolute(varDir), "CONFIG", "必须提供绝对路径 VAR_DIR", 503);
  if (!dev) {
    ensure(process.platform === "linux" && process.getuid?.() === 0, "ROOT_REQUIRED", "生产服务需要 Linux root", 503);
    verifyCode(__dirname);
  }
  process.umask(0o077); safeDirectory(varDir);
  const audit = new Audit(varDir), manager = new JobManager(varDir, audit);
  let token = null;
  if (dev) { token = process.env.DEV_TOKEN; ensure(typeof token === "string" && /^[a-f0-9]{64}$/.test(token), "CONFIG", "开发模式需要 64 位随机十六进制 DEV_TOKEN", 503); }
  const app = createApp({ manager, audit, devToken: token });
  let server;
  let ownedSocket = false;
  let socketPath;
  if (dev) {
    const port = Number(process.env.PORT || 5002);
    ensure(Number.isInteger(port) && port > 0 && port < 65536, "CONFIG", "开发端口无效");
    server = app.listen(port, "127.0.0.1");
  } else {
    socketPath = process.env.SOCKET_PATH;
    ensure(socketPath && path.resolve(socketPath) === path.resolve(__dirname, "..", "app.sock"), "CONFIG", "生产模式必须使用安装目录中的 app.sock，禁止回退 TCP", 503);
    ensure(!fs.existsSync(socketPath), "SOCKET_EXISTS", "Socket 路径已存在；请核对旧实例后再清理", 503);
    const parent = fs.statSync(path.dirname(socketPath));
    ensure(parent.uid === 0 && !(parent.mode & 0o022), "UNSAFE_SOCKET", "Socket 父目录权限不安全", 503);
    server = app.listen(socketPath, () => {
      try {
        const gid = process.env.GATEWAY_GID;
        ensure(gid === undefined || /^\d+$/.test(gid), "CONFIG", "GATEWAY_GID 必须是已核实的网关数字组 ID");
        if (gid !== undefined) { fs.chownSync(socketPath, 0, Number(gid)); fs.chmodSync(socketPath, 0o660); } else fs.chmodSync(socketPath, 0o600);
        ownedSocket = true;
        audit.write("SERVICE_START", { version: VERSION, socketMode: gid === undefined ? "0600 root-only" : "0660 configured gateway group" });
      } catch (e) { console.error(e); server.close(); process.exitCode = 1; }
    });
  }
  server.on("error", e => { console.error(e); process.exitCode = 1; });
  let stopping = false;
  async function shutdown() {
    if (stopping) return; stopping = true;
    server.close();
    await manager.shutdown();
    server.closeAllConnections();
    if (ownedSocket && fs.existsSync(socketPath) && fs.lstatSync(socketPath).isSocket()) fs.unlinkSync(socketPath);
    try { audit.write("SERVICE_STOP", { version: VERSION }); } catch {}
  }
  process.on("SIGTERM", shutdown); process.on("SIGINT", shutdown);
  return { app, server, manager, shutdown };
}
if (require.main === module) start().catch(e => { console.error(JSON.stringify({ code: e.code || "START_FAILED", error: e.message })); process.exitCode = 1; });
module.exports = { createApp, start, verifyCode, VERSION };
