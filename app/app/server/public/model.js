(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(); else root.PermissionFixModel = factory();
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const statusLabels = { normal: "正常", attention: "需关注", incomplete: "未检测", error: "检测失败" };
  const priorities = { error: 0, attention: 1, incomplete: 2, normal: 3 };
  function statusOf(m) {
    if (["accessible", "ownerdiff"].includes(m.status)) return "normal";
    if (["permission_denied", "write_limited", "missing", "not_directory"].includes(m.status)) return "attention";
    if (m.status === "scan_error") return "error";
    return "incomplete";
  }
  function aggregate(mounts) {
    return mounts.reduce((result, m) => priorities[statusOf(m)] < priorities[result] ? statusOf(m) : result, mounts.length ? "normal" : "incomplete");
  }
  function projectKey(c) { return c.project ? "compose:" + c.project : "container:" + c.id; }
  function projects(snapshot) {
    const result = new Map();
    for (const c of snapshot?.containers || []) {
      const key = projectKey(c);
      if (!result.has(key)) result.set(key, { key, name: c.project || c.name, compose: !!c.project, containers: [] });
      result.get(key).containers.push(c);
    }
    return [...result.values()].map(p => {
      p.containers.sort((a, b) => a.name.localeCompare(b.name, "zh-CN", { numeric: true }));
      const states = p.containers.map(c => aggregate(c.mounts));
      return { ...p, status: states.reduce((a, b) => priorities[a] < priorities[b] ? a : b, "normal") };
    }).sort((a, b) => a.name.localeCompare(b.name, "zh-CN", { numeric: true }));
  }
  function flatten(snapshot) { return (snapshot?.containers || []).flatMap(c => c.mounts.map(m => ({ c, m }))); }
  function visible(items, { search = "", status = "all", running = "all" } = {}) {
    const q = search.trim().toLowerCase();
    return items.filter(x => (status === "all" || (status === "repair_blocked" ? x.m.safetyStatus !== "eligible" : statusOf(x.m) === status || x.m.status === status)) && (running === "all" || x.c.running === (running === "running")) && (!q || [x.c.project, x.c.name, x.c.image, x.m.source, x.m.target, x.m.reason, ...(x.m.evidence || []).map(e => e.relativePath)].join(" ").toLowerCase().includes(q))).sort((a, b) => a.m.source.localeCompare(b.m.source));
  }
  function selectable(x) { return x.m.canPlanRepair === true; }
  function selectVisible(selected, rows, checked) {
    const result = new Set(selected);
    for (const x of rows.filter(selectable)) { if (checked) result.add(x.m.key); else result.delete(x.m.key); }
    return result;
  }
  function selection(selected, rows, all) {
    const eligible = rows.filter(selectable), count = eligible.filter(x => selected.has(x.m.key)).length;
    const known = new Set(all.filter(selectable).map(x => x.m.key));
    const keys = [...selected].filter(x => known.has(x));
    return { checked: eligible.length > 0 && count === eligible.length, indeterminate: count > 0 && count < eligible.length, count: keys.length, hidden: keys.filter(k => !rows.some(x => x.m.key === k)).length, keys };
  }
  function stats(items, containers = []) {
    const emptyContainers = containers.filter(c => !c.mounts?.length).length;
    return { mounts: items.length, normal: items.filter(x => statusOf(x.m) === "normal").length, attention: items.filter(x => statusOf(x.m) === "attention").length, incomplete: items.filter(x => statusOf(x.m) === "incomplete").length + emptyContainers, error: items.filter(x => statusOf(x.m) === "error").length };
  }
  return { statusLabels, statusOf, aggregate, projectKey, projects, flatten, visible, selectable, selectVisible, selection, stats };
});
