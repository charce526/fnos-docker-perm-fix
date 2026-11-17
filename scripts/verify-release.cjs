"use strict";
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), vm = require("node:vm"), assert = require("node:assert/strict");
const { parseTar } = require("./archive.cjs");
const root = path.resolve(__dirname, ".."), read = p => fs.readFileSync(path.join(root, p));
const hash = b => crypto.createHash("sha256").update(b).digest("hex");
const metadata = JSON.parse(read("release/build-metadata.json"));
const bytes = read(`release/docker-perm-fix-${metadata.version}.fpk`);
assert.equal(hash(bytes), metadata.packageSha256);
const outer = parseTar(bytes), payload = outer.find(x => x.name === "app.tgz").data, inner = parseTar(payload);
assert([...outer, ...inner].every(x => (x.mode & 0o022) === 0));
assert(outer.filter(x => x.name.startsWith("cmd/")).every(x => x.mode === 0o755));
const manifest = outer.find(x => x.name === "manifest").data.toString();
assert.equal(/^version\s*=\s*(\S+)/m.exec(manifest)[1], metadata.version);
assert.equal(/^checksum\s*=\s*(\S+)/m.exec(manifest)[1], crypto.createHash("md5").update(payload).digest("hex"));
let sources = 0, parsedJs = 0;
function runtime(dir, relative = "") {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const file = path.join(dir, entry.name), name = [relative, entry.name].filter(Boolean).join("/");
    if (entry.isDirectory()) runtime(file, name);
    else {
      const installed = inner.find(x => x.name === name); assert(installed, name);
      assert(installed.data.equals(fs.readFileSync(file)), "source mismatch: " + name); sources++;
      if (file.endsWith(".js")) { new vm.Script(installed.data.toString(), { filename: name }); parsedJs++; }
    }
  }
}
runtime(path.join(root, "app/app"));
const activeDocs = ["README.md", "RELEASE_NOTES.md", "app/README.md", "docs/API.md", "docs/MAINTENANCE.md", "docs/fnos-apps-guide.md", "docs/fnos-developer-skill-SKILL.md", "docs/IMPLEMENTATION-STATUS-1.1.0.md"];
let checkedLinks = 0;
for (const doc of activeDocs) {
  const text = read(doc).toString();
  assert.equal((text.match(/^```/gm) || []).length % 2, 0, "unbalanced fence: " + doc);
  for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1].split("#")[0]; if (!target || /^(https?:|mailto:)/.test(target)) continue;
    assert(fs.existsSync(path.resolve(root, path.dirname(doc), target)), "broken doc link: " + doc + " -> " + target); checkedLinks++;
  }
}
const expectedIds = [...read("docs/AI-REVIEW-HANDOFF-2026-11-17.md").toString().matchAll(/^### ((?:SAFE|SCAN|API|PKG|UI|DOC)-\d+)/gm)].map(x => x[1]).sort();
const actualIds = [...read("docs/IMPLEMENTATION-STATUS-1.1.0.md").toString().matchAll(/^\| ((?:SAFE|SCAN|API|PKG|UI|DOC)-\d+) /gm)].map(x => x[1]).sort();
assert.equal(expectedIds.length, 45); assert.deepEqual(actualIds, expectedIds);
const result = { passed: true, version: metadata.version, node: process.version, packageSha256: hash(bytes), runtimeFilesMatched: sources, javascriptFilesParsed: parsedJs, outerEntries: outer.length, innerEntries: inner.length, checkedDocLinks: checkedLinks, checklistIdsCovered: actualIds.length, checks: ["version", "package checksum", "runtime source parity", "archive permissions", "manifest checksum", "JavaScript syntax", "documentation links"] };
fs.mkdirSync(path.join(root, "release"), { recursive: true });
fs.writeFileSync(path.join(root, "release/verification.json"), JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify(result, null, 2));
