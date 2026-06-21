// Tests for ollama-security: simulate an Ollama server via a fetch monkeypatch
// and assert the auditor confirms the real leaks on an exposed box, stays quiet
// on a server it cannot reach anonymously, and normalises bare host inputs.
import { audit } from "../scripts/audit.js";
import assert from "node:assert";

function mockFetch({ exposed = false, cors = false } = {}) {
  return async (url, opts = {}) => {
    const u = String(url);
    const method = (opts.method || "GET").toUpperCase();
    const headers = new Map();
    const get = (k) => headers.get(k.toLowerCase()) ?? null;
    const wrap = (status, body) => ({
      ok: status < 400,
      status,
      headers: { get },
      text: async () => JSON.stringify(body),
      json: async () => body,
    });

    if (!exposed) {
      // A locked / unreachable server: version refuses anonymous access.
      return wrap(401, {});
    }

    if (u.endsWith("/api/version")) return wrap(200, { version: "0.5.1" });
    if (u.endsWith("/api/tags")) {
      if (cors && opts.headers?.Origin) headers.set("access-control-allow-origin", opts.headers.Origin);
      return wrap(200, {
        models: [
          { name: "llama3:8b", size: 4700000000, details: { family: "llama", parameter_size: "8B" } },
          { name: "mistral:latest", size: 4100000000, details: { family: "llama", parameter_size: "7B" } },
        ],
      });
    }
    if (u.endsWith("/api/ps")) return wrap(200, { models: [{ name: "llama3:8b", size_vram: 5000000000 }] });
    if (u.endsWith("/api/generate") && method === "POST") return wrap(400, { error: "missing prompt" });
    if (u.endsWith("/api/pull") && method === "POST") return wrap(400, { error: "model is required" });
    return wrap(404, {});
  };
}

let pass = 0;

// 1. Fully exposed server: every leak should fire.
globalThis.fetch = mockFetch({ exposed: true, cors: true });
let r = await audit({ url: "http://exposed.test:11434" });
assert.strictEqual(r.reachable, true, "exposed server should be reachable");
assert.ok(r.findings.find((f) => f.check === "no_auth_exposed"), "should flag no-auth exposure");
assert.ok(r.findings.find((f) => f.check === "model_inventory_leak"), "should flag /api/tags leak");
assert.ok(r.findings.find((f) => f.check === "running_models_leak"), "should flag /api/ps leak");
assert.ok(r.findings.find((f) => f.check === "cors_reflection"), "should flag CORS reflection");
assert.ok(r.findings.find((f) => f.check === "free_inference"), "should flag free inference");
assert.ok(r.findings.find((f) => f.check === "model_pull_push"), "should flag pull/push write path");
assert.ok(r.findings.find((f) => f.check === "version_disclosure"), "should flag version disclosure");
assert.ok(r.summary.critical >= 2, "should have >=2 critical findings");
assert.ok(r.active_probe.confirmed >= 6, "should confirm >=6 issues");
console.log("PASS: fully exposed Ollama flagged (no-auth + tags + ps + CORS + generate + pull + version)"); pass++;

// 2. Locked / unreachable server: clean, no findings.
globalThis.fetch = mockFetch({ exposed: false });
r = await audit({ url: "http://locked.test:11434" });
assert.strictEqual(r.reachable, false, "locked server should be marked not reachable");
assert.strictEqual(r.findings.length, 0, "locked server should have no findings");
console.log("PASS: locked/unreachable server is clean"); pass++;

// 3. Bare host input is normalised to http:// and port 11434.
globalThis.fetch = mockFetch({ exposed: true });
r = await audit({ url: "myhost.local" });
assert.strictEqual(r.ollama_url, "http://myhost.local:11434", "should default scheme http and port 11434");
console.log("PASS: bare host normalised to http://myhost.local:11434"); pass++;

// 4. --no-probe sends nothing and lists checks.
let calls = 0;
globalThis.fetch = async () => { calls++; throw new Error("should not be called"); };
r = await audit({ url: "http://exposed.test:11434", activeProbe: false });
assert.strictEqual(calls, 0, "no-probe must not send any request");
assert.ok(Array.isArray(r.checks_available) && r.checks_available.length >= 6, "should list available checks");
console.log("PASS: --no-probe sends zero requests"); pass++;

console.log(`\n${pass}/4 tests passed`);
