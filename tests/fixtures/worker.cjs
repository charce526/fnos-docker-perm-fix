"use strict";
process.once("message", ({ mode, payload }) => {
  if (payload.behavior === "hang") { setInterval(() => {}, 10000); return; }
  if (payload.behavior === "invalid") { process.send({ type: "result", data: null }, () => process.disconnect()); return; }
  const data = { schemaVersion: 2, scanId: "scan-fixture", createdAt: new Date().toISOString(), complete: true, containers: [], profile: "read", warnings: [] };
  setTimeout(() => process.send({ type: "result", data }, () => { process.exitCode = payload.behavior === "nonzero" ? 2 : 0; process.disconnect(); }), payload.delay || 0);
});
