// Read-only review probes: source runs in isolated VM mocks; no Docker or repair commands run.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, p));
const findings = [];
function record(id, evidence) { findings.push({ id, evidence }); }

function frontend() {
  const elements = new Map();
  let rows = [];
  const timers = [];
  let response = {};
  let fetchHook;
  function element(id) {
    if (!elements.has(id)) {
      let html = '';
      const el = { id, disabled: false, checked: false, value: '', dataset: {}, style: {}, textContent: '', handlers: {},
        addEventListener(type, fn) { this.handlers[type] = fn; },
        dispatch(type, event = {}) { return this.handlers[type]?.(event); },
        click() { if (!this.disabled) return this.dispatch('click'); },
        focus() {}, setSelectionRange() {}, showModal() {}, close() {} };
      Object.defineProperty(el, 'innerHTML', { get: () => html, set(value) {
        html = value;
        if (id === 'result-area') {
          rows = [...value.matchAll(/<input[^>]*class="check row-check"[^>]*>/g)].map(([tag]) => ({
            dataset: { key: /data-key="([^"]*)"/.exec(tag)?.[1] || '' },
            disabled: / disabled/.test(tag), checked: / checked/.test(tag), addEventListener() {}
          }));
          elements.delete('check-all-head');
          if (value.includes('id="check-all-head"')) element('check-all-head');
        }
      }});
      elements.set(id, el);
    }
    return elements.get(id);
  }
  const sandbox = {
    document: { getElementById: element, querySelectorAll: selector => selector === '.row-check' ? rows : [] },
    fetch: async (url, opts) => { if (fetchHook) await fetchHook(url, opts); return { ok: true, json: async () => response }; },
    setTimeout: fn => timers.push(fn)
  };
  const html = read('app/app/server/public/index.html').toString();
  let source = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
  new vm.Script(source); // Check original inline script before in-memory instrumentation.
  source = source.replace(/\}\)\(\);\s*$/, `globalThis.probe = {
    setContainers: v => { containers = v; }, setState: v => { state = v; },
    getState: () => state, setSearch: v => { searchText = v; },
    setSort: (v,d) => { sortKey = v; sortDir = d; }, countFixable, sortedItems,
    renderTable, refreshFixBtn, getPending: () => pendingKeys
  }; })();`);
  vm.runInNewContext(source, sandbox);
  return { api: sandbox.probe, element, rows: () => rows, timers, setResponse: v => { response = v; },
    setFetchHook: fn => { fetchHook = fn; } };
}

function backend() {
  const routes = new Map();
  const calls = [];
  let callback;
  let payload = '{}';
  let engineError = null;
  function router() { return { get: (url, ...fns) => routes.set('GET '+url, fns), post: (url, ...fns) => routes.set('POST '+url, fns) }; }
  const app = { ...router(), use() {}, listen(...args) { calls.push({ listenArguments: args.slice(0, -1) }); } };
  const express = () => app;
  express.Router = router;
  express.json = () => () => {};
  express.static = () => () => {};
  const sandbox = { __dirname: path.join(root, 'app/app/server'), console: { log() {} }, process: { env: {} },
    require(name) {
      if (name === 'express') return express;
      if (name === 'path') return path;
      if (name === 'fs') return { existsSync: () => false, mkdirSync() {}, appendFileSync() {}, rmSync() {} };
      if (name === 'child_process') return { execFile(file, args, opts, cb) {
        calls.push({ mode: args[1], keys: args.slice(2) });
        if (callback) callback(cb); else cb(engineError, payload, '');
      }};
      throw Error(name);
    }
  };
  vm.runInNewContext(read('app/app/server/server.js').toString()+'\nglobalThis.probe = { runEngine, requireAdmin };', sandbox);
  return { api: sandbox.probe, routes, calls, setPayload: v => { payload = v; }, setError: v => { engineError = v; },
    holdCallbacks: fn => { callback = fn; } };
}

const keyA = 'a'.repeat(64), keyB = 'b'.repeat(64);
const containers = [
  { name: 'alpha', image: 'example', running: true, uid: 999, gid: 999,
    mounts: [{ key: keyA, source: '/data/a', target: '/data', rw: true, status: 'problem', recommend: true }] },
  { name: 'beta', image: 'example', running: true, uid: 1000, gid: 1000,
    mounts: [{ key: keyB, source: '/data/b', target: '/data', rw: true, status: 'ownerdiff', recommend: false }] }
];
function freshUI() { const ui = frontend(); ui.api.setContainers(containers); ui.api.renderTable(); return ui; }

async function main() {
  if (JSON.parse(read("app/app/server/package.json")).version !== "1.0.0") throw Error("Historical 1.0.0 probe only; use tests/ for 1.1.0. Original evidence will not be overwritten.");
  let ui = freshUI();
  ui.element('check-all-head').checked = true;
  ui.element('check-all-head').dispatch('change');
  record('UI-01-select', { displayed: ui.rows().filter(r => r.checked).map(r => r.dataset.key), submitted: Object.keys(ui.api.getState()).filter(k => ui.api.getState()[k]) });
  ui = freshUI(); ui.api.setState({ [keyB]: true }); ui.api.renderTable();
  ui.element('check-all-head').checked = false; ui.element('check-all-head').dispatch('change');
  record('UI-01-deselect', { displayedChecked: ui.rows().filter(r => r.checked).length, submitted: Object.keys(ui.api.getState()).filter(k => ui.api.getState()[k]) });
  ui = freshUI(); ui.api.setSearch('alpha'); ui.api.renderTable(); ui.element('btn-sel-problem').click();
  record('UI-02', { visibleRows: ui.rows().length, selectedKeys: Object.keys(ui.api.getState()).filter(k => ui.api.getState()[k]) });
  ui = freshUI(); record('UI-03', { trueProblems: 1, countFixable: ui.api.countFixable() });
  ui.api.setSort('uid', 1);
  record('UI-04', { ascendingUIDs: Array.from(ui.api.sortedItems(containers.map(c => ({ c, m: c.mounts[0] }))), x => x.c.uid) });
  ui = freshUI(); ui.api.setState({ [keyA]: true }); ui.api.refreshFixBtn();
  let releaseScan;
  ui.setFetchHook(() => new Promise(resolve => { releaseScan = resolve; }));
  ui.setResponse({ containers });
  const scanning = ui.element('btn-scan').click();
  record('UI-05-scan', { scanDisabled: ui.element('btn-scan').disabled, fixDisabled: ui.element('btn-fix').disabled });
  releaseScan(); await scanning;
  ui = freshUI(); ui.api.setState({ [keyA]: true }); ui.api.refreshFixBtn(); ui.element('btn-fix').click();
  let releaseFix;
  ui.setFetchHook(() => new Promise(resolve => { releaseFix = resolve; }));
  ui.setResponse({ results: [{ key: keyA, status: 'ok', message: 'done' }] });
  const fixing = ui.element('dlg-ok').click();
  record('UI-05-fix', { scanDisabled: ui.element('btn-scan').disabled, fixDisabled: ui.element('btn-fix').disabled });
  releaseFix(); await fixing;
  const beforeRescan = ui.element('result-area').innerHTML.includes('修复结果');
  const reenabledFix = !ui.element('btn-fix').disabled;
  ui.setFetchHook(null); ui.setResponse({ containers }); ui.timers[0]();
  await new Promise(resolve => setImmediate(resolve));
  record('UI-06', { hadFixResults: beforeRescan, fixEnabledBeforeRescan: reenabledFix, retainedFixResultsAfterRescan: ui.element('result-area').innerHTML.includes('修复结果') });

  let be = backend(); record('BE-01', { listen: be.calls[0] });
  let passed = false;
  be.api.requireAdmin({ headers: { 'x-trim-userid': 'mock', 'x-trim-isadmin': 'true' } }, {}, () => { passed = true; });
  record('BE-01-header', { arbitraryHeaderAcceptedByMiddleware: passed, note: 'Requires direct access; no real socket/gateway exploit attempted.' });
  be = backend(); be.setError({ code: 2 }); be.setPayload('{"containers":[]}');
  record('BE-02', await be.api.runEngine('scan', []));
  be = backend(); be.setPayload('null'); record('BE-03', await be.api.runEngine('scan', []));
  be = backend();
  const pending = [];
  be.holdCallbacks(cb => pending.push(cb));
  const p1 = be.api.runEngine('fix', [keyA]); const p2 = be.api.runEngine('fix', [keyB]);
  record('BE-04', { concurrentlyStartedFixes: pending.length });
  pending.forEach(cb => cb(null, '{"results":[]}', '')); await Promise.all([p1, p2]);

  const jsonFiles = ['app/config/resource','app/config/privilege','app/app/ui/config','app/wizard/install','app/app/server/package.json','app/app/server/package-lock.json'];
  for (const p of jsonFiles) JSON.parse(read(p));
  record('syntax', { jsonFilesParsed: jsonFiles.length, inlineJavaScriptParsed: true });

  function tarEntries(buffer) {
    if (buffer[0] === 0x1f && buffer[1] === 0x8b) buffer = zlib.gunzipSync(buffer);
    const entries = [];
    for (let offset = 0; offset + 512 <= buffer.length; ) {
      const header = buffer.subarray(offset, offset + 512);
      if (header.every(b => b === 0)) break;
      const string = (from, to) => header.subarray(from, to).toString().replace(/\0.*$/, '');
      const name = [string(345, 500), string(0, 100)].filter(Boolean).join('/');
      const size = parseInt(string(124, 136).trim(), 8) || 0;
      entries.push({ name, mode: string(100, 108), content: buffer.subarray(offset+512, offset+512+size) });
      offset += 512 + Math.ceil(size/512)*512;
    }
    return entries;
  }
  const outer = tarEntries(read('release/docker-perm-fix.fpk'));
  const inner = tarEntries(outer.find(e => e.name === 'app.tgz').content);
  const comparisons = [];
  for (const [archiveName, local] of [['server/server.js','app/app/server/server.js'],['server/bin/docker-perm-fix.sh','app/app/server/bin/docker-perm-fix.sh'],['server/public/index.html','app/app/server/public/index.html']]) {
    const entry = inner.find(e => e.name.replace(/^\.\//, '') === archiveName);
    comparisons.push({ local, entry: entry?.name, mode: entry?.mode, sameBytes: !!entry && entry.content.equals(read(local)) });
  }
  record('package', { outerEntries: outer.length, innerEntries: inner.length, comparisons,
    lifecycleModes: outer.filter(e => e.name.startsWith('cmd/')).map(e => ({ name: e.name, mode: e.mode })),
    expressIncluded: inner.some(e => /server\/node_modules\/express\/package.json$/.test(e.name)) });

  const tracked = ['app/app/server/bin/docker-perm-fix.sh','app/app/server/server.js','app/app/server/public/index.html','app/cmd/main','app/build.sh','app/README.md','README.md','app/manifest','docs/fnos-developer-skill-SKILL.md','docs/fnos-apps-guide.md','release/docker-perm-fix.fpk'];
  const baseline = tracked.map(file => ({ file, sha256: crypto.createHash('sha256').update(read(file)).digest('hex'), lines: file.endsWith('.fpk') ? null : read(file).toString().split('\n').length }));
  const report = { reviewDate: '2026-11-17', runtime: process.version, method: 'VM mocks and archive inspection; no real Docker, permission mutation, listener or gateway used', findings, baseline };
  fs.mkdirSync(path.join(root, 'logs'), { recursive: true });
  fs.writeFileSync(path.join(root, 'logs/audit-review-evidence.json'), JSON.stringify(report, null, 2)+'\n');
  console.log(JSON.stringify(report, null, 2));
}
main().catch(e => { console.error(e); process.exitCode = 1; });
