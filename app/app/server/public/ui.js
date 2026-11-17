/* global PermissionFixModel */
"use strict";
(() => {
  const M = PermissionFixModel, $ = id => document.getElementById(id), BASE = "api/";
  const labels = M.statusLabels;
  const resultLabels = { verified_success: "复测通过", partial_failure: "部分完成或复测未通过", failed: "失败", skipped: "未执行", interrupted: "中断" };
  const state = { snapshot: null, selected: new Set(), plan: null, result: null, phase: "connecting", csrf: null, activeId: null, devToken: sessionStorage.getItem("perm-fix-dev-token") || "", connected: false, activeContainer: null, activeProject: null, collapsed: new Set() };
  let pollGeneration = 0;
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const locked = () => state.phase !== "idle";
  function error(message) { $("error").hidden = !message; $("error").textContent = message || ""; }
  function status(message) { $("scan-status").textContent = message; }
  window.addEventListener("error", e => {
    if (e.target && e.target !== window && (e.target.tagName === "SCRIPT" || e.target.tagName === "LINK" || e.target.tagName === "IMG")) {
      error(`界面资源加载失败：${e.target.src || e.target.href || "未知资源"}。请强制刷新页面（Ctrl+F5）后重试。`);
    } else if (e.message) { error(`页面异常：${e.message}`); }
  }, true);
  function filters() { return { search: $("search").value, status: $("filter-status").value, running: $("filter-running").value }; }
  const all = () => M.flatten(state.snapshot), visible = () => M.visible(all(), filters());
  async function api(route, body) {
    const headers = { Accept: "application/json", "X-App-Origin": location.origin };
    if (state.devToken) headers["X-Dev-Token"] = state.devToken;
    if (body !== undefined) { headers["Content-Type"] = "application/json"; headers["X-CSRF-Token"] = state.csrf || ""; }
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 15000);
    try {
      const r = await fetch(BASE + route, { method: body === undefined ? "GET" : "POST", headers, credentials: "same-origin", cache: "no-store", signal: abort.signal, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      if (!r.headers.get("Content-Type")?.includes("application/json")) throw Error("收到非接口页面；登录状态可能已失效，请重新进入飞牛应用");
      const data = await r.json();
      if (!r.ok) { const e = Error(data.error || `请求失败（${r.status}）`); e.code = data.code; throw e; }
      if (!data || typeof data !== "object") throw Error("接口结果格式异常，请保留诊断信息");
      return data;
    } catch (e) { if (e.name === "AbortError") throw Error("网络请求超时；后台任务可能仍在运行，请重新连接查看"); throw e; }
    finally { clearTimeout(timer); }
  }
  function controls() {
    const selected = M.selection(state.selected, visible(), all());
    $("btn-scan").disabled = locked() || !state.connected;
    $("btn-plan").disabled = locked() || selected.count === 0 || selected.count > 100;
    $("btn-plan").textContent = selected.count ? `批量修复选中项（${selected.count}）` : "批量修复选中项";
    $("btn-export").disabled = !state.snapshot && !state.result;
    $("btn-audit").disabled = !state.connected;
    for (const id of ["select-all", "btn-invert", "btn-clear"]) $(id).disabled = locked();
    $("select-all").checked = selected.checked; $("select-all").indeterminate = selected.indeterminate;
    $("selection-info").textContent = `已选 ${selected.count} 项，当前筛选外 ${selected.hidden} 项；最多 100 项`;
    document.querySelectorAll("input[data-key]").forEach(cb => { cb.disabled = locked() || !all().some(x => x.m.key === cb.dataset.key && M.selectable(x)); cb.checked = state.selected.has(cb.dataset.key); });
    $("scan-area").setAttribute("aria-busy", String(locked()));
  }
  function evidence(list) {
    if (!list?.length) return "";
    return '<ul class="evidence">' + list.map(e => `<li><code>${esc(e.relativePath === "." ? "挂载路径" : e.relativePath)}</code> ${esc(({ directory: "目录", file: "文件" }[e.type] || e.type) || "")} ${e.owner ? `属主 ${esc(e.owner)} / 权限 ${esc(e.mode)}` : ""}<br>${e.missing?.length ? "受限操作：" + esc(e.missing.map(x => ({ read: "读", write: "写", enter: "进入" }[x] || x)).join("、")) : "未能确认访问能力"}${e.errorCode ? "；" + esc(e.errorCode) : ""}</li>`).join("") + "</ul>";
  }
  const badge = status => `<span class="badge ${status}">${labels[status]}</span>`;
  function accessBadges(m) {
    if (!m.access) return "";
    const operations = [["read", "读"], ["write", "写"], ...(m.token?.type === "directory" ? [["enter", "进入"]] : [])];
    return '<div class="root-access">' + operations.map(([key, label]) => {
      if (key === "write" && !m.rw) return '<span class="access-neutral">只读挂载</span>';
      const value = m.access[key];
      return `<span class="${value === true ? "access-ok" : value === false ? "access-no" : "access-neutral"}">${label} ${value === true ? "✓" : value === false ? "✗" : "?"}</span>`;
    }).join("") + '</div>';
  }
  function identityText(id) {
    if (id?.rootPrivileged) return "容器身份：root，权限不受限";
    if (id?.uid != null && id.gid != null) return `容器身份：${id.uid}:${id.gid}${id.canProbe ? "" : "（需核对）"}`;
    const pairs = [...new Set((id?.candidates || []).map(x => `${x.uid}:${x.gid}`).filter(x => !x.startsWith("null:") && !x.endsWith(":null")))];
    if (pairs.length) return `容器身份：${pairs.join("、")}（需核对）`;
    if (id?.declaredUser) return `容器声明用户：${id.declaredUser}（无法映射，未检测）`;
    return "容器身份未检测";
  }
  function renderTree() {
    const projects = M.projects(state.snapshot), nav = $("project-tree"), scroll = nav.scrollTop;
    $("project-count").textContent = projects.length;
    if (!state.snapshot) return;
    const query = $("project-search").value.trim().toLowerCase();
    const matches = projects.filter(p => [p.name, ...p.containers.flatMap(c => [c.name, c.service || ""])].some(x => x.toLowerCase().includes(query)));
    nav.innerHTML = `<button class="tree-overview" data-jump-all>全部项目 <span>${projects.length}</span></button>` + (matches.length ? matches.map(p => {
      const open = !state.collapsed.has(p.key);
      const active = state.activeProject === p.key;
      const heading = `<button class="project-link" data-jump-project="${esc(p.key)}" title="${esc(p.name)}" ${active ? 'aria-current="true"' : ""}><span class="folder-symbol" aria-hidden="true">▣</span><span class="tree-name">${esc(p.name)}</span><span class="tree-state ${p.status}">${labels[p.status]}</span></button>`;
      return `<div class="project-node"><div class="project-head ${active ? "active" : ""}">${p.compose ? `<button class="tree-toggle" data-toggle-project="${esc(p.key)}" aria-label="${open ? "折叠" : "展开"} ${esc(p.name)}" aria-expanded="${open}">${open ? "▾" : "▸"}</button>` : ""}${heading}</div>${p.compose ? `<div class="tree-children" ${open ? "" : "hidden"}>${p.containers.map(c => {
        const s = M.aggregate(c.mounts);
        return `<button class="tree-container" data-jump-container="${esc(c.id)}" title="${esc(c.name)}" ${state.activeContainer === c.id ? 'aria-current="true"' : ""}><span class="status-dot ${s}" aria-hidden="true"></span><span class="tree-name">${esc(c.name)}</span><span class="tree-state ${s}">${labels[s]}</span></button>`;
      }).join("")}</div>` : ""}</div>`;
    }).join("") : '<p class="empty">没有匹配项目</p>');
    nav.scrollTop = scroll;
  }
  function diagnostics(c, m) {
    const id = c.identity;
    const kind = m.token?.type === "file" ? "宿主文件" : "宿主目录";
    const rootCurrent = m.token ? `${kind}：属主 ${m.token.uid}:${m.token.gid}，权限 ${m.token.mode.toString(8)}` : "宿主路径属主和权限未知";
    return `<details class="diagnostics"><summary>查看诊断与范围</summary><div class="diagnostic-body"><p>${esc(m.reason)}</p><p><strong>本次检查身份</strong><br>${esc(identityText(id))}</p><p class="muted">${esc(rootCurrent)}</p>${m.repairBlockedReason ? `<p class="warning"><strong>自动修复限制</strong><br>${esc(m.repairBlockedReason)}</p>` : ""}${evidence(m.evidence)}${m.conflicts?.length ? '<p class="warning">冲突挂载：' + esc(m.conflicts.map(x => typeof x === "string" ? x : `${x.container}: ${x.source} → ${x.target}`).join("；")) + "</p>" : ""}${m.exclusions?.length ? '<p class="warning">不可修复对象：' + esc(m.exclusions.map(x => `${x.relativePath} (${x.reason})`).join("；")) + "</p>" : ""}</div></details>`;
  }
  function containerCard(c, mounts) {
    const s = M.aggregate(c.mounts), id = c.identity;
    return `<section class="card container-group" id="container-${esc(c.id)}" tabindex="-1" aria-label="${esc(c.name)}"><div class="container-heading"><div><h3 class="group-title">${esc(c.name)}</h3><div class="container-meta"><span class="lifecycle ${c.running ? "running" : ""}">${c.running ? "运行中" : "已停止"}</span>${esc(identityText(id))}<br>${esc(c.image)}</div></div>${badge(s)}</div>${mounts.length ? `<div class="table-scroll"><table><caption class="sr-only">${esc(c.name)} 的挂载路径检查结果</caption><colgroup><col class="select-col"><col class="mount-col"><col class="result-col"></colgroup><thead><tr><th scope="col"><span class="sr-only">选择</span></th><th scope="col">宿主机 → 容器</th><th scope="col">检查结果</th></tr></thead><tbody>${mounts.map(m => {
      return `<tr><td><input type="checkbox" data-key="${esc(m.key)}" aria-label="选择 ${esc(c.name)} 的 ${esc(m.source)}" ${M.selectable({ c, m }) ? "" : "disabled"}></td><td><div class="row-title">${esc(m.source)}</div><div class="mount-target">→ ${esc(m.target)}</div><div class="mount-tools"><span class="mount-mode">${m.rw ? "读写挂载" : "只读挂载"}</span><button class="copy ghost" data-copy="${esc(m.source)}" aria-label="复制路径 ${esc(m.source)}">复制路径</button></div></td><td>${badge(M.statusOf(m))}${accessBadges(m)}${diagnostics(c, m)}</td></tr>`;
    }).join("")}</tbody></table></div>` : '<div class="empty-inline">没有绑定挂载路径</div>'}</section>`;
  }
  function renderScan() {
    if (!state.snapshot) return controls();
    renderTree();
    const items = all(), rows = visible(), projects = M.projects(state.snapshot), f = filters();
    $("filter-area").hidden = false;
    const s = M.stats(items, state.snapshot.containers);
    const activeFilter = filters().status;
    $("stats-area").innerHTML = `<div class="stats">${["normal", "attention", "incomplete", "error"].map(key => `<button type="button" class="stat ${key}" data-filter="${key}" aria-pressed="${activeFilter === key}" title="按${labels[key]}筛选"><span class="l">${labels[key]}</span><span class="v">${s[key]}</span></button>`).join("")}</div>`;
    const groups = new Map();
    rows.forEach(({ c, m }) => { if (!groups.has(c.id)) groups.set(c.id, []); groups.get(c.id).push(m); });
    for (const c of state.snapshot.containers.filter(c => !c.mounts.length)) {
      const query = f.search.trim().toLowerCase();
      if ((f.status === "all" || f.status === "incomplete") && (f.running === "all" || c.running === (f.running === "running")) && (!query || [c.project, c.name, c.image].join(" ").toLowerCase().includes(query))) groups.set(c.id, []);
    }
    let markup = "";
    const orderedProjects = projects;
    for (const p of orderedProjects) {
      const members = p.containers.filter(c => groups.has(c.id));
      if (!members.length) continue;
      const sorted = members;
      markup += `<section class="project-section" id="project-${esc(p.containers[0].id)}"><h2 class="project-title"><span class="folder-symbol" aria-hidden="true">▣</span>${esc(p.name)}<span class="count">${members.length} 个容器</span></h2>${sorted.map(c => containerCard(c, groups.get(c.id))).join("")}</section>`;
    }
    $("scan-area").innerHTML = `<div class="result-heading"><h2>检查结果 <span class="muted">${rows.length} / ${items.length} 个挂载路径</span></h2><span class="muted">${esc(new Date(state.snapshot.createdAt).toLocaleString())}</span></div>` + (markup || `<div class="card empty">${state.snapshot.containers.length ? "没有符合筛选条件的结果" : "Docker 当前没有容器"}</div>`);
    controls();
  }
  function navigateTo(project, container) {
    if (!project && !container) $("project-search").value = "";
    $("search").value = ""; $("filter-status").value = "all"; $("filter-running").value = "all";
    state.activeProject = project?.key || null; state.activeContainer = container?.id || null;
    if (project) state.collapsed.delete(project.key);
    renderScan();
    const target = container ? document.getElementById("container-" + container.id) : project ? document.getElementById("project-" + project.containers[0].id) : $("scan-area");
    if (target) { target.scrollIntoView({ block: "start", behavior: "instant" }); target.focus({ preventScroll: true }); }
  }
  function renderResult() {
    const job = state.result;
    if (!job) return;
    $("fix-area").hidden = false;
    const results = job.result?.results || [];
    const completed = results.filter(r => r.status === "verified_success").length;
    const failed = results.filter(r => r.status !== "verified_success").length;
    const heading = job.error ? "修复失败" : failed ? "修复未完成" : "修复成功";
    const notice = completed ? '<p class="warning">修复已写入。请重启对应容器，并结合业务日志确认效果。</p>' : "";
    $("fix-area").innerHTML = `<div class="card"><div class="section-heading"><h2>${heading}</h2><button id="btn-close-result" class="small ghost">收起</button></div>${notice}${job.error ? `<p class="warning">${esc(job.error.code)}：${esc(job.error.message)}</p>` : ""}${results.map(r => `<div class="result-item ${r.status === "verified_success" ? "result-success" : "result-failure"}"><b>${esc(r.container)}</b> · ${esc(resultLabels[r.status] || r.status)}<p class="muted">${esc(r.source)} · 已修改 ${r.changed ?? 0} 个对象</p><details class="diagnostics"><summary>查看执行详情</summary><div class="diagnostic-body"><p>${esc(r.message)}</p>${evidence(r.verification?.evidence)}${r.errors?.map(e => `<p class="warning">${esc(e.code)}：${esc(e.message)}${e.pending ? "；执行状态需核对：" + esc(e.pending) : ""}</p>`).join("") || ""}</div></details></div>`).join("")}<details class="diagnostics"><summary>任务记录</summary><p class="muted">任务 ${esc(job.id)} · ${esc(new Date(job.finishedAt || job.createdAt).toLocaleString())}<br>${job.result?.journal ? "修改记录：" + esc(job.result.journal) : ""}</p></details></div>`;
    $("fix-area").scrollIntoView({ block: "start", behavior: "instant" });
    $("fix-area").focus({ preventScroll: true });
  }
  function presentPlan(plan) {
    state.plan = plan; state.phase = "confirming"; $("confirm-impact").checked = false; $("dlg-ok").disabled = true;
    $("confirm-list").innerHTML = plan.items.map(item => `<details class="plan-item" open><summary><b>${esc(item.container)}</b> · ${item.actions.length} 个挂载路径</summary><p><code>${esc(item.source)} → ${esc(item.target)}</code></p><p>${esc(identityText(item.identity))}。将挂载路径对齐到上述容器 UID/GID，再补访问权限；ACL 保留。</p><div class="actions-preview">${item.actions.slice(0, 30).map(a => `<p><code>${esc(a.relativePath === "." ? item.source : a.relativePath)}</code><br>${esc(a.before.uid)}:${esc(a.before.gid)}/${esc(a.before.mode.toString(8))} → ${esc(a.after.uid)}:${esc(a.after.gid)}/${esc(a.after.mode.toString(8))}</p>`).join("")}</div>${item.actions.length > 30 ? `<p class="muted">其余 ${item.actions.length - 30} 个挂载路径可通过顶部“导出诊断”查看。</p>` : ""}</details>`).join("");
    $("confirm-dlg").showModal(); controls();
  }
  async function waitJob(id) {
    state.activeId = id; localStorage.setItem("perm-fix-active-job", id);
    const generation = ++pollGeneration;
    while (generation === pollGeneration) {
      const job = await api("/jobs/" + encodeURIComponent(id));
      if (job.state !== "running") {
        localStorage.removeItem("perm-fix-active-job"); state.activeId = null;
        if (job.mode === "execute") { state.result = job; state.selected.clear(); state.plan = null; renderResult(); }
        if (job.state !== "completed") throw Error(`${job.error?.code || job.state}：${job.error?.message || "任务未完成"}（任务 ${job.id}）`);
        if (job.mode === "scan") {
          state.snapshot = job.result; state.selected.clear(); state.plan = null; renderScan();
          const s = M.stats(all()); status(`检查完成 · ${M.projects(state.snapshot).length} 个项目 · ${s.mounts} 个挂载路径`);
        } else if (job.mode === "plan") { state.plan = job.result; presentPlan(job.result); }
        else status("修复任务已结束，结果在页面顶部。可重新扫描验证最新状态。");
        return job;
      }
      const p = job.progress || {};
      status(`${p.message || "任务执行中"}${p.total ? ` ${p.done || 0}/${p.total}` : ""}${p.container ? " · " + p.container : ""}；刷新页面可恢复进度。`);
      await new Promise(resolve => setTimeout(resolve, 750));
    }
  }
  async function task(route, body) {
    error(""); state.phase = "working"; controls();
    try { const data = await api(route, body); await waitJob(data.jobId); }
    catch (e) { error(route === "/fix" ? `修复任务失败：${e.message}` : e.message); if (state.activeId) status("任务状态尚未确认；请刷新或重新连接，勿重复提交修复。"); }
    finally { if (state.phase !== "confirming") state.phase = state.activeId ? "reconnecting" : "idle"; controls(); }
  }
  async function connect() {
    error(""); state.phase = "connecting"; controls();
    try {
      const session = await api("/session");
      state.csrf = session.csrfToken; state.connected = true; $("version").textContent = session.version;
      if (session.auditError) error("审计不可写，修复已受阻：" + session.auditError);
      const list = await api("/jobs");
      const latest = list.jobs.find(x => x.mode === "scan" && x.state === "completed");
      if (latest) { const saved = (await api("/jobs/" + latest.id)).result; if (saved.checkVersion >= 4) { state.snapshot = saved; renderScan(); } }
      const repair = list.jobs.find(x => x.mode === "execute" && x.state !== "running");
      if (repair) { state.result = await api("/jobs/" + repair.id); renderResult(); }
      if (session.activeJob) { state.phase = "working"; await waitJob(session.activeJob); }
      else if (session.busy) { status("其他管理员的任务正在执行，请稍后重新连接。"); state.phase = "reconnecting"; setTimeout(connect, 2500); return; }
      else { localStorage.removeItem("perm-fix-active-job"); state.activeId = null; status(state.snapshot ? "已恢复最近检查结果" : "已连接，可开始扫描"); }
      if (state.phase !== "confirming") state.phase = "idle";
    } catch (e) { state.phase = "disconnected"; state.connected = false; error(`连接失败：${e.message}。请强制刷新页面后重试；仍失败时请提供浏览器地址、开发者工具 Network 中失败请求和应用 app.log。`); }
    controls();
  }
  $("project-search").addEventListener("input", renderTree);
  $("project-tree").addEventListener("click", e => {
    const projects = M.projects(state.snapshot), toggle = e.target.closest("[data-toggle-project]");
    if (toggle) { const key = toggle.dataset.toggleProject; if (state.collapsed.has(key)) state.collapsed.delete(key); else state.collapsed.add(key); return renderTree(); }
    const link = e.target.closest("[data-jump-project]"), child = e.target.closest("[data-jump-container]");
    if (link) { const p = projects.find(p => p.key === link.dataset.jumpProject); if (p) navigateTo(p, p.compose ? null : p.containers[0]); }
    else if (child) { const c = state.snapshot.containers.find(c => c.id === child.dataset.jumpContainer); if (c) navigateTo(projects.find(p => p.key === M.projectKey(c)), c); }
    else if (e.target.closest("[data-jump-all]")) navigateTo(null, null);
  });
  for (const id of ["btn-help", "btn-footer-help"]) $(id).addEventListener("click", () => { if (!$("help-dlg").open) $("help-dlg").showModal(); });
  $("btn-close-help").addEventListener("click", () => $("help-dlg").close());
  $("btn-close-audit").addEventListener("click", () => { $("audit-area").hidden = true; });
  for (const id of ["btn-audit", "btn-export"]) $(id).addEventListener("click", () => { document.querySelector(".more-menu").open = false; });
  $("btn-scan").addEventListener("click", () => { $("fix-area").hidden = true; $("fix-area").innerHTML = ""; state.result = null; task("/scan", {}); });
  $("fix-area").addEventListener("click", e => {
    if (e.target.closest("#btn-close-result")) { $("fix-area").hidden = true; $("fix-area").innerHTML = ""; }
  });
  $("stats-area").addEventListener("click", e => {
    const stat = e.target.closest("[data-filter]"); if (!stat) return;
    $("filter-status").value = $("filter-status").value === stat.dataset.filter ? "all" : stat.dataset.filter;
    renderScan();
  });
  $("btn-plan").addEventListener("click", () => {
    const keys = M.selection(state.selected, visible(), all()).keys;
    if (!keys.length || keys.length > 100) return error("请选择 1–100 项");
    task("/plan", { scanId: state.snapshot.scanId, keys, action: "align-container-identity" });
  });
  $("scan-area").addEventListener("change", e => { if (e.target.matches("input[data-key]")) { if (e.target.checked) state.selected.add(e.target.dataset.key); else state.selected.delete(e.target.dataset.key); controls(); } });
  $("scan-area").addEventListener("click", async e => { const button = e.target.closest("[data-copy]"); if (button) { try { await navigator.clipboard.writeText(button.dataset.copy); status("已复制路径"); } catch { error("浏览器未允许复制，请从页面选择路径复制"); } } });
  $("select-all").addEventListener("change", e => { state.selected = M.selectVisible(state.selected, visible(), e.target.checked); controls(); });
  $("btn-invert").addEventListener("click", () => { for (const x of visible().filter(M.selectable)) { if (state.selected.has(x.m.key)) state.selected.delete(x.m.key); else state.selected.add(x.m.key); } controls(); });
  $("btn-clear").addEventListener("click", () => { state.selected.clear(); controls(); });
  for (const id of ["search", "filter-status", "filter-running"]) $(id).addEventListener(id === "search" ? "input" : "change", renderScan);
  $("confirm-impact").addEventListener("change", e => { $("dlg-ok").disabled = !e.target.checked; });
  function cancelPlan() { state.plan = null; state.phase = "idle"; controls(); }
  $("dlg-cancel").addEventListener("click", () => { $("confirm-dlg").close(); cancelPlan(); });
  $("confirm-dlg").addEventListener("cancel", cancelPlan);
  $("dlg-ok").addEventListener("click", () => {
    if (!state.plan || !$("confirm-impact").checked) return;
    const planId = state.plan.planId;
    if (Date.parse(state.plan.expiresAt) <= Date.now()) { $("confirm-dlg").close(); cancelPlan(); return error("修复确认已过期，请关闭后重新确认"); }
    $("confirm-dlg").close(); state.plan = null; state.selected.clear(); task("/fix", { planId });
  });
  $("btn-audit").addEventListener("click", async () => { try { const data = await api("/audit"); $("audit-content").textContent = data.lines.join("\n") || "暂无审计记录"; $("audit-area").hidden = false; } catch (e) { error(e.message); } });
  function exportDiagnostics() {
    const data = { exportedAt: new Date().toISOString(), version: $("version").textContent, scan: state.snapshot, plan: state.plan, result: state.result };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = "docker-perm-fix-diagnostics-" + Date.now() + ".json"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    status("诊断已导出");
  }
  $("btn-export").addEventListener("click", exportDiagnostics);
  if (["localhost", "127.0.0.1"].includes(location.hostname)) $("dev-controls").hidden = false;
  $("btn-connect").addEventListener("click", () => { state.devToken = $("dev-token").value.trim(); sessionStorage.setItem("perm-fix-dev-token", state.devToken); connect(); });
  connect();
})();
