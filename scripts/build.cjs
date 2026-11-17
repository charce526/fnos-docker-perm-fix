"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { parseTar, normalizeFpk } = require("./archive.cjs");
const root = path.resolve(__dirname, ".."), source = path.join(root, "app"), buildRoot = path.join(root, ".build");
fs.mkdirSync(buildRoot, { recursive: true });
const stage = fs.mkdtempSync(path.join(buildRoot, "stage-"));
const offline = process.argv.includes("--offline");
function run(file, args, cwd) { execFileSync(file, args, { cwd, stdio: "inherit", windowsHide: true }); }
try {
  fs.cpSync(source, stage, { recursive: true, filter: file => !file.split(path.sep).includes("node_modules") && !file.endsWith(".fpk"), dereference: false });
  const server = path.join(stage, "app", "server");
  const candidates = [process.env.NPM_CLI, path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"), path.resolve(path.dirname(process.execPath), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")].filter(Boolean);
  const npm = candidates.find(p => fs.existsSync(p));
  if (!npm) throw Error("Cannot locate npm CLI; set NPM_CLI to its absolute npm-cli.js path");
  run(process.execPath, [npm, "ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund", ...(offline ? ["--offline"] : [])], server);
  const npmVersion = execFileSync(process.execPath, [npm, "--version"], { encoding: "utf8", windowsHide: true }).trim();
  // The application never executes dependency CLI shims. Omit platform-specific .bin files/links.
  const bin = path.join(server, "node_modules", ".bin");
  if (fs.existsSync(bin)) {
    const realStage = fs.realpathSync(stage), realBin = fs.realpathSync(bin), rel = path.relative(realStage, realBin);
    if (rel.startsWith("..") || path.isAbsolute(rel) || !rel.endsWith(path.join("node_modules", ".bin"))) throw Error("Unsafe dependency shim cleanup target: " + realBin);
    fs.rmSync(realBin, { recursive: true, force: true });
  }
  // Normalize shell line endings in the staging tree without altering the working source.
  function shellFiles(dir) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isSymbolicLink()) throw Error("Build input contains symlink: " + p); if (e.isDirectory()) shellFiles(p); else if (p.endsWith(".sh") || path.dirname(p) === path.join(stage, "cmd")) fs.writeFileSync(p, fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n")); } }
  shellFiles(stage);
  const fnpack = process.env.FNPACK || path.join(root, "tools", process.platform === "win32" ? "fnpack.exe" : "fnpack");
  // fnpack writes to its working directory, not necessarily the -d source directory.
  run(fnpack, ["build", "-d", stage], stage);
  const built = path.join(stage, "docker-perm-fix.fpk");
  if (!fs.existsSync(built) || fs.statSync(built).size < 1000) throw Error("fnpack did not create a new valid package");
  const epoch = Number(process.env.SOURCE_DATE_EPOCH || 0);
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw Error("Invalid SOURCE_DATE_EPOCH");
  const output = normalizeFpk(fs.readFileSync(built), epoch), outer = parseTar(output), inner = parseTar(outer.find(e => e.name === "app.tgz").data);
  const manifest = outer.find(e => e.name === "manifest").data.toString(), version = /^version\s*=\s*(\S+)/m.exec(manifest)?.[1];
  if (version !== JSON.parse(fs.readFileSync(path.join(source, "app/server/package.json"))).version) throw Error("Version mismatch");
  for (const name of ["ICON.PNG", "ICON_256.PNG"]) {
    const entry = outer.find(e => e.name === name);
    if (!entry || !entry.data.equals(fs.readFileSync(path.join(source, name)))) throw Error("Package icon mismatch: " + name);
  }
  for (const file of ["server/server.js", "server/worker.js", "server/control.js", "server/lib/policy.js", "server/public/ui.js", "server/public/model.js", "server/public/index.html"]) {
    const entry = inner.find(e => e.name === file);
    if (!entry || !entry.data.equals(fs.readFileSync(path.join(stage, "app", file)))) throw Error("Package source mismatch: " + file);
  }
  function verifyRuntime(dir, relative = "") {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === "node_modules") continue;
      const local = path.join(dir, e.name), name = [relative, e.name].filter(Boolean).join("/");
      if (e.isDirectory()) verifyRuntime(local, name);
      else { const entry = inner.find(x => x.name === name); if (!entry || !entry.data.equals(fs.readFileSync(local))) throw Error("Runtime source mismatch: " + name); }
    }
  }
  verifyRuntime(path.join(stage, "app"));
  if (!inner.some(e => e.name === "server/node_modules/express/package.json")) throw Error("Missing offline Express dependency");
  if ([...outer, ...inner].some(e => e.mode & 0o022)) throw Error("Package has group/world writable entries");
  const release = path.join(root, "release"); fs.mkdirSync(release, { recursive: true });
  const names = [`docker-perm-fix-${version}.fpk`];
  for (const name of names) { const destination = path.join(release, name), temporary = destination + ".new"; fs.writeFileSync(temporary, output); fs.renameSync(temporary, destination); }
  const fnpackVersion = /Version\s+([^\r\n]+)/.exec(execFileSync(fnpack, ["--help"], { encoding: "utf8", windowsHide: true }))?.[1] || "unknown";
  const metadata = { version, node: process.version, npm: npmVersion, fnpack: fnpackVersion, builtAt: new Date().toISOString(), epoch, lockfileSha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(server, "package-lock.json"))).digest("hex"), fnpackSha256: crypto.createHash("sha256").update(fs.readFileSync(fnpack)).digest("hex"), packageSha256: crypto.createHash("sha256").update(output).digest("hex"), files: inner.length, permissionsNormalized: true, npmMode: offline ? "ci-offline" : "ci", express: JSON.parse(inner.find(e => e.name === "server/node_modules/express/package.json").data).version };
  fs.writeFileSync(path.join(release, "build-metadata.json"), JSON.stringify(metadata, null, 2) + "\n");
  console.log(JSON.stringify(metadata, null, 2));
} finally {
  // Windows recursive deletion is permitted only after checking the final absolute target.
  const actual = fs.realpathSync(stage), approved = fs.realpathSync(buildRoot), relative = path.relative(approved, actual);
  if (!relative.startsWith("stage-") || relative.includes(path.sep) || relative.startsWith("..") || path.isAbsolute(relative)) throw Error("Refusing cleanup outside the verified staging directory: " + actual);
  fs.rmSync(actual, { recursive: true, force: true });
}
