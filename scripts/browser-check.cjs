"use strict";
// Browser regression against a local mock API. Never connects to Docker or a NAS.
const fs = require("node:fs"), path = require("node:path"), http = require("node:http"), assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const root = path.resolve(__dirname, ".."), publicDir = path.join(root, "app/app/server/public");
const basePath = "/app/docker-perm-fix", output = path.join(root, "logs/browser");
fs.mkdirSync(output, { recursive: true });
const keys = ["a".repeat(64), "b".repeat(64)];
const scan = { schemaVersion: 2, checkVersion: 4, scanId: "scan-browser", createdAt: new Date().toISOString(), complete: false, profile: "read", warnings: [], containers: [
  { id: "a", name: "alpha-database", image: "postgres:17-with-a-long-image-name-for-layout-check", running: true, identity: { uid: 999, gid: 999, confidence: "verified", source: "observed-process", canProbe: true }, mounts: [{ key: keys[0], source: "/vol1/项目资料/database/data", target: "/var/lib/postgresql/data", rw: true, token: { type: "directory", uid: 999, gid: 999, mode: 448 }, treeCount: 1, status: "permission_denied", safetyStatus: "eligible", canPlanRepair: true, reason: "挂载路径缺少：读", checkMethod: "host-mount-root-with-process-groups", coverageComplete: true, conflicts: [], evidence: [{ relativePath: ".", type: "directory", owner: "999:999", mode: "000", missing: ["read"] }] }] },
  { id: "b", name: "beta-service", image: "example/web:latest", running: false, identity: { uid: 1000, gid: 1000, confidence: "reference", source: "declared" }, mounts: [{ key: keys[1], source: "/vol1/服务/config", target: "/config", rw: true, token: { type: "directory", uid: 1001, gid: 1001, mode: 493 }, treeCount: 1, status: "ownerdiff", safetyStatus: "eligible", canPlanRepair: true, reason: "可访问，宿主机属主与容器 UID/GID 不同", checkMethod: "host-mount-root-with-process-groups", coverageComplete: true, conflicts: [], evidence: [] }] }
] };
for (const [index, c] of scan.containers.entries()) { c.project = "cloud-suite"; c.service = index === 0 ? "database" : "web"; c.identity.canProbe = true; }
for (let i = 0; i < 8; i++) {
  const status = ["accessible", "root_checked", "scan_error", "write_limited"][i % 4];
  scan.containers.push({ ...scan.containers[1], id: "extra-" + i, name: "service-" + i, project: "project-" + i, service: "app", mounts: i === 7 ? [] : [{ ...scan.containers[1].mounts[0], key: String(i + 10).padStart(64, "0"), status, canPlanRepair: false, source: "/vol1/很长的项目目录/" + "data-".repeat(20), evidence: [] }] });
}
scan.containers[0].mounts[0].access = { read: false, write: true, enter: true };
scan.containers[0].mounts[0].evidence.push(...Array.from({ length: 20 }, (_, i) => ({ relativePath: "root-diagnostic-" + "very-long-value-".repeat(12) + i, missing: ["read"], owner: "999:999", mode: "000" })));
let planKeys = [], executePolls = 0;
const plan = { schemaVersion: 2, planId: "11111111-1111-4111-8111-111111111111", expiresAt: new Date(Date.now() + 300000).toISOString(), action: "align-container-identity", items: [{ key: keys[0], container: "alpha-database", source: scan.containers[0].mounts[0].source, target: "/var/lib/postgresql/data", identity: scan.containers[0].identity, action: "align-container-identity", actions: [{ relativePath: ".", before: { uid: 999, gid: 999, mode: 0 }, after: { uid: 999, gid: 999, mode: 320 } }] }] };
const jobs = new Map();
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://local");
  const relative = url.pathname === basePath + "/" ? "index.html" : url.pathname.slice((basePath + "/").length);
  if (!["index.html", "styles.css", "model.js", "ui.js", "app-icon.png"].includes(relative)) { res.writeHead(404); res.end(); return; }
  const file = path.join(publicDir, relative);
  res.setHeader("Content-Type", relative.endsWith(".png") ? "image/png" : relative.endsWith(".js") ? "application/javascript" : relative.endsWith(".css") ? "text/css" : "text/html"); res.end(fs.readFileSync(file));
});
async function main() {
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1080 } });
    const pageErrors = []; page.on("pageerror", e => pageErrors.push(e.message));
    await page.route("**/api/**", async route => {
      const request = route.request(), p = new URL(request.url()).pathname.replace(basePath + "/api", "");
      let data;
      if (p === "/session") data = { version: "1.2.4", csrfToken: "csrf", activeJob: null, busy: false };
      else if (p === "/jobs") data = { jobs: [...jobs.values()].map(j => ({ id: j.id, state: j.state, mode: j.mode, createdAt: j.createdAt })) .reverse() };
      else if (p === "/scan") { jobs.set("scan-job", { id: "scan-job", owner: "admin", mode: "scan", state: "completed", createdAt: new Date().toISOString(), result: scan }); data = { jobId: "scan-job" }; }
      else if (p === "/plan") { planKeys = request.postDataJSON().keys; jobs.set("plan-job", { id: "plan-job", mode: "plan", state: "completed", createdAt: new Date().toISOString(), result: plan }); data = { jobId: "plan-job" }; }
      else if (p === "/fix") { jobs.set("fix-job", { id: "fix-job", mode: "execute", state: "running", createdAt: new Date().toISOString() }); data = { jobId: "fix-job" }; }
      else if (p === "/jobs/fix-job") {
        const job = jobs.get("fix-job");
        if (++executePolls >= 3) Object.assign(job, { state: "completed", finishedAt: new Date().toISOString(), result: { journal: "fix-job.journal.jsonl", results: [{ key: keys[0], container: "alpha-database", source: scan.containers[0].mounts[0].source, changed: 1, status: "verified_success", message: "计划动作与读取需求复测通过", verification: { evidence: [] } }] } });
        data = { ...job, progress: { message: "正在验证挂载路径", done: 0, total: 1 } };
      } else if (p.startsWith("/jobs/")) data = jobs.get(p.slice(6));
      else if (p === "/audit") data = { lines: ['{"action":"TASK_END","state":"completed"}'] };
      else return route.fulfill({ status: 404, contentType: "application/json", body: '{"error":"not found"}' });
      await route.fulfill({ status: request.method() === "POST" ? 202 : 200, contentType: "application/json", body: JSON.stringify(data) });
    });
    const url = `http://127.0.0.1:${server.address().port}${basePath}/`;
    await page.goto(url);
    await page.waitForFunction(() => !document.getElementById("btn-scan").disabled);
    await page.click("#btn-scan"); await page.waitForSelector("input[data-key]");
    assert.equal(await page.locator("#filter-status option").count(), 5);
    assert.equal(await page.locator("#filter-status option[value=incomplete]").innerText(), "未检测");
    assert.equal(await page.locator("#sort").count(), 0);
    assert.equal(await page.locator(".project-link").count(), 9);
    assert.equal(await page.locator(".tree-container").count(), 10);
    assert.equal(await page.locator(".logo").evaluate(img => img.naturalWidth), 256);
    await page.click("#btn-help"); await page.waitForSelector("#help-dlg[open]");
    assert.match(await page.locator("#help-dlg").innerText(), /charce526/);
    await page.click("#btn-close-help");
    const widths = () => page.locator("#container-a table th").evaluateAll(nodes => nodes.map(x => x.getBoundingClientRect().width));
    const before = await widths(); await page.locator("#container-a .diagnostics summary").click();
    const after = await widths(); assert(before.every((n, i) => Math.abs(n - after[i]) < 1), JSON.stringify({ before, after }));
    const detailBounds = await page.locator("#container-a .diagnostic-body").evaluate(el => ({ height: el.clientHeight, content: el.scrollHeight, width: el.clientWidth, contentWidth: el.scrollWidth }));
    assert(detailBounds.height <= 360 && detailBounds.content > detailBounds.height && detailBounds.contentWidth <= detailBounds.width + 1, JSON.stringify(detailBounds));
    await page.fill("#search", "no-match"); await page.selectOption("#filter-status", "normal");
    await page.locator('[data-jump-container="a"]').click();
    assert.equal(await page.inputValue("#search"), ""); assert.equal(await page.inputValue("#filter-status"), "all");
    assert.equal(await page.locator("#container-a").evaluate(el => document.activeElement === el), true);
    await page.locator('[data-toggle-project="compose:cloud-suite"]').click();
    assert.equal(await page.locator('[data-toggle-project="compose:cloud-suite"]').getAttribute("aria-expanded"), "false");
    await page.locator('[data-toggle-project="compose:cloud-suite"]').click();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await page.screenshot({ path: path.join(output, "desktop-projects.png"), fullPage: false });
    await page.locator('input[data-key="' + keys[0] + '"]').check();
    assert.equal(await page.isEnabled("#btn-plan"), true);
    await page.uncheck('input[data-key="' + keys[0] + '"]');
    await page.locator('input[data-key="' + keys[0] + '"]').check();
    assert.equal(await page.isEnabled("#btn-plan"), true);
    await page.uncheck('input[data-key="' + keys[0] + '"]');
    await page.fill("#search", "alpha"); await page.check("#select-all"); assert.equal(await page.locator("input[data-key]:checked").count(), 1);
    await page.screenshot({ path: path.join(output, "desktop-scan.png"), fullPage: true });
    await page.click("#btn-plan"); await page.waitForSelector("#confirm-dlg[open]"); assert.deepEqual(planKeys, [keys[0]]);
    assert.equal(await page.isDisabled("#btn-scan"), true);
    await page.screenshot({ path: path.join(output, "plan-preview.png"), fullPage: true });
    await page.check("#confirm-impact"); await page.click("#dlg-ok");
    await page.waitForFunction(() => document.getElementById("scan-status").textContent.includes("挂载路径"));
    assert.equal(await page.isDisabled("#btn-scan"), true); assert.equal(await page.isDisabled("#btn-plan"), true);
    await page.waitForSelector(".result-success"); await page.waitForFunction(() => !document.getElementById("btn-scan").disabled);
    assert.equal(await page.locator("input[data-key]:checked").count(), 0);
    await page.click("#btn-scan"); await page.waitForFunction(() => !document.getElementById("btn-scan").disabled);
    assert.equal(await page.locator(".result-success").count(), 1);
    await page.reload(); await page.waitForSelector(".result-success");
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(output, "mobile-scan.png"), fullPage: true });
    const layout = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth, unlabeledCheckboxes: [...document.querySelectorAll('input[type="checkbox"]')].filter(x => !x.getAttribute("aria-label") && !x.closest("label") && !document.querySelector('label[for="'+x.id+'"]')).length }));
    assert.equal(layout.document <= layout.viewport, true, JSON.stringify(layout)); assert.equal(layout.unlabeledCheckboxes, 0); assert.deepEqual(pageErrors, []);
    const result = { passed: true, version: "1.2.4", browser: await browser.version(), layout, columns: { before, after }, checks: ["four result states", "not-checked label", "single align-container-identity repair", "bulk repair enabled without engine-wide completeness", "tree and result order use the same sort", "all projects and containers in navigation", "project jump clears conflicting filters", "keyboard focus on jump", "project collapse", "unified help", "new icon loaded", "fixed columns with expanded long diagnostics", "bounded diagnostic scroll", "authoritative selection", "visible-only bulk", "exact plan keys", "busy exclusion", "consumed selection", "persistent repair result", "reload recovery", "mobile layout", "checkbox labels", "no page errors"] };
    fs.writeFileSync(path.join(output, "result.json"), JSON.stringify(result, null, 2)); console.log(JSON.stringify(result, null, 2));
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
}
main().catch(e => { console.error(e); server.close(); process.exitCode = 1; });
