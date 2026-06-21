#!/usr/bin/env node
// Ollama Security Auditor — pure Node.js, no deps.
//
// Detects, and PROVES with an anonymous probe, the one misconfiguration that
// actually leaks compute and models from an Ollama server: a public-facing API
// bound to 0.0.0.0 with NO authentication. Ollama ships with no auth on port
// 11434 by default (CNVD-2025-04094); ~175,000 instances were found exposed
// with zero auth (LeakIX / Cisco–Shodan, Feb 2026). An anonymous attacker can
// enumerate and steal your models, pin your GPU with free inference, and — via
// known push/pull and RCE chains — turn the box into a malware brain
// (Sysdig, Jun 2026).
//
// What it confirms, anonymously:
//   - /api/version  reachable with no auth          (server is exposed)
//   - /api/tags     lists every local model         (model inventory leaked)
//   - /api/ps       lists running models + VRAM      (live workload leaked)
//   - CORS reflects an arbitrary Origin             (browser-based abuse)
//   - /api/generate / /api/pull reachable           (free inference / model push-pull)
//
// Keyless by design: point it at a URL and it issues the exact unauthenticated
// requests an attacker would. Every request goes straight from this process to
// your server — nothing leaves your machine.
//
// Usage:
//   ollama-security --url http://your-host:11434
//   ollama-security --url http://your-host:11434 --html report.html
//   ollama-security --url http://your-host:11434 --no-probe

import { writeFileSync } from "node:fs";

const UA = "ollama-security/0.1";
const EVIL_ORIGIN = "https://ollama-security-probe.example";
const DEFAULT_PORT = 11434;

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  no_auth_exposed: {
    severity: "critical",
    title: "Ollama API is reachable with no authentication",
    explain:
      "The Ollama API answered an anonymous request. Ollama has NO authentication by default (CNVD-2025-04094), so anyone who can reach this port has full control of the server's models and GPU. Bind Ollama to 127.0.0.1 (OLLAMA_HOST=127.0.0.1), or put it behind a reverse proxy that enforces auth, and firewall port 11434.",
  },
  model_inventory_leak: {
    severity: "high",
    title: "/api/tags leaks your full model inventory",
    explain:
      "An anonymous GET /api/tags returned the list of every model on the box (names, sizes, families, quantization). Attackers use this to fingerprint the host, pull your private/fine-tuned models, and target known-vulnerable model formats. Restrict access so /api/tags is not world-readable.",
  },
  running_models_leak: {
    severity: "high",
    title: "/api/ps leaks running models and VRAM usage",
    explain:
      "An anonymous GET /api/ps returned the models currently loaded and their memory footprint. This reveals live workload, lets an attacker time GPU-abuse, and confirms the server is hot. Lock the API down behind auth.",
  },
  free_inference: {
    severity: "high",
    title: "/api/generate accepts anonymous inference (free GPU / compute theft)",
    explain:
      "The generate endpoint is reachable without auth, so anyone can run arbitrary prompts on your hardware — free inference at your electricity/GPU cost, and a documented path to using the box as a malware brain (Sysdig, Jun 2026). Require authentication in front of the API.",
  },
  model_pull_push: {
    severity: "critical",
    title: "/api/pull is reachable — anonymous model push/pull (model theft + RCE chain)",
    explain:
      "The pull endpoint is reachable without auth. Combined with push, an attacker can exfiltrate models or plant a poisoned one; unpatched Ollama versions chain this into path-traversal / RCE. Block write endpoints (pull/push/create/delete) behind authentication and update Ollama.",
  },
  cors_reflection: {
    severity: "high",
    title: "CORS reflects arbitrary Origin — any website can drive your Ollama",
    explain:
      "The server echoes any Origin back in Access-Control-Allow-Origin (commonly OLLAMA_ORIGINS=*). A malicious web page a victim visits can then call this API directly from the browser — model theft and free inference with no network access to the host. Set OLLAMA_ORIGINS to an explicit allowlist, never '*'.",
  },
  version_disclosure: {
    severity: "medium",
    title: "/api/version discloses the exact Ollama version",
    explain:
      "The version endpoint is anonymous and reveals the exact build, letting attackers match it against known CVEs before attacking. Restrict the API to trusted clients and keep Ollama updated.",
  },
};

// --- HTTP helpers ------------------------------------------------------------

async function getJson(url, headers = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      headers: { "User-Agent": UA, ...headers },
      redirect: "follow",
      signal: ctrl.signal,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { ok: r.ok, status: r.status, headers: r.headers, text, json };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  } finally {
    clearTimeout(t);
  }
}

async function postJson(url, body, headers = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "User-Agent": UA, "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
      redirect: "follow",
      signal: ctrl.signal,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* may be ndjson stream */ }
    return { ok: r.ok, status: r.status, headers: r.headers, text, json };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  } finally {
    clearTimeout(t);
  }
}

// --- individual probes -------------------------------------------------------

// /api/version — proves the server is reachable & unauthenticated.
async function checkVersion(base) {
  const r = await getJson(`${base}/api/version`);
  if (r.status === 200 && r.json && typeof r.json.version === "string") {
    return { confirmed: true, status: 200, version: r.json.version };
  }
  return { confirmed: false, status: r.status, error: r.error };
}

// /api/tags — model inventory.
async function checkTags(base) {
  const r = await getJson(`${base}/api/tags`);
  if (r.status === 200 && r.json && Array.isArray(r.json.models)) {
    const models = r.json.models.slice(0, 10).map((m) => ({
      name: m.name || m.model,
      size: m.size ?? null,
      family: m.details?.family ?? null,
      parameter_size: m.details?.parameter_size ?? null,
    }));
    return { confirmed: true, status: 200, count: r.json.models.length, models };
  }
  return { confirmed: false, status: r.status };
}

// /api/ps — running models.
async function checkPs(base) {
  const r = await getJson(`${base}/api/ps`);
  if (r.status === 200 && r.json && Array.isArray(r.json.models)) {
    const running = r.json.models.map((m) => ({
      name: m.name || m.model,
      size_vram: m.size_vram ?? null,
    }));
    return { confirmed: true, status: 200, count: r.json.models.length, running };
  }
  return { confirmed: false, status: r.status };
}

// CORS reflection on a real endpoint.
async function checkCors(base) {
  const r = await getJson(`${base}/api/tags`, { Origin: EVIL_ORIGIN });
  const acao = r.headers?.get?.("access-control-allow-origin");
  if (acao && (acao === EVIL_ORIGIN || acao === "*")) {
    return { confirmed: true, reflected: acao, sentOrigin: EVIL_ORIGIN };
  }
  return { confirmed: false, reflected: acao || "(none)" };
}

// /api/generate reachable anonymously. We DON'T actually run a heavy prompt:
// a malformed/no-model request that returns a 400 (not 401/403/404) proves the
// endpoint is open and would accept a real request.
async function checkGenerate(base, model) {
  const body = model
    ? { model, prompt: "ping", stream: false, options: { num_predict: 1 } }
    : { model: "", prompt: "" };
  const r = await postJson(`${base}/api/generate`, body);
  // 200 = it actually ran; 400 = endpoint open but our payload was rejected.
  if (r.status === 200 || r.status === 400) {
    return { confirmed: true, status: r.status, ran: r.status === 200 };
  }
  return { confirmed: false, status: r.status };
}

// /api/pull reachable anonymously (write path). Probe without a valid model so
// we never actually download anything; an open endpoint replies 200/400, a
// protected one replies 401/403/404.
async function checkPull(base) {
  const r = await postJson(`${base}/api/pull`, { model: "", stream: false });
  if (r.status === 200 || r.status === 400) {
    return { confirmed: true, status: r.status };
  }
  return { confirmed: false, status: r.status };
}

// --- URL normalisation -------------------------------------------------------

// Accept "host", "host:port", "http://host", "http://host:port". Default to
// http:// and port 11434 when not specified.
function normalizeUrl(input) {
  let s = String(input).trim();
  if (!/^https?:\/\//i.test(s)) s = "http://" + s;
  const u = new URL(s);
  if (!u.port) u.port = String(DEFAULT_PORT);
  return u.origin;
}

// --- main audit --------------------------------------------------------------

export async function audit({ url, activeProbe = true } = {}) {
  if (!url) throw new Error("audit() requires { url }");
  const base = normalizeUrl(url);
  const findings = [];
  let probed = 0;
  let confirmed = 0;

  if (!activeProbe) {
    return {
      ollama_url: base,
      scanned_by: "ollama-security v0.1",
      active_probe: { enabled: false, probed: 0, confirmed: 0 },
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      checks_available: Object.keys(CHECKS),
      findings: [],
    };
  }

  // 1. Version / reachability — the gate for everything else.
  const ver = await checkVersion(base); probed++;
  if (ver.confirmed) {
    confirmed++;
    findings.push({
      check: "no_auth_exposed", ...CHECKS.no_auth_exposed,
      target: `${base}/api/version`,
      details: { version: ver.version },
      probe: ver,
      fix: "Set OLLAMA_HOST=127.0.0.1 (or bind to a private interface), firewall port 11434, and require auth via a reverse proxy for any remote access.",
    });
    confirmed++; // version disclosure
    findings.push({
      check: "version_disclosure", ...CHECKS.version_disclosure,
      target: `${base}/api/version`,
      details: { version: ver.version },
      probe: ver,
      fix: "Do not expose the API publicly; keep Ollama updated to the latest release.",
    });
  } else {
    // Not reachable / authenticated — report clean and stop the active probes.
    return {
      ollama_url: base,
      scanned_by: "ollama-security v0.1",
      active_probe: { enabled: true, probed, confirmed: 0 },
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      reachable: false,
      note:
        ver.status === 0
          ? `No response from ${base} (${ver.error || "connection failed"}). If this is your server, it is not publicly reachable — good.`
          : `${base}/api/version returned HTTP ${ver.status}: the API is not anonymously reachable (good).`,
      findings: [],
    };
  }

  // 2. Model inventory.
  const tags = await checkTags(base); probed++;
  if (tags.confirmed) {
    confirmed++;
    findings.push({
      check: "model_inventory_leak", ...CHECKS.model_inventory_leak,
      target: `${base}/api/tags`,
      details: { model_count: tags.count, sample_models: tags.models },
      probe: tags,
      fix: "Put the API behind authentication; never expose /api/tags to untrusted networks.",
    });
  }

  // 3. Running models.
  const ps = await checkPs(base); probed++;
  if (ps.confirmed) {
    confirmed++;
    findings.push({
      check: "running_models_leak", ...CHECKS.running_models_leak,
      target: `${base}/api/ps`,
      details: { running_count: ps.count, running: ps.running },
      probe: ps,
      fix: "Restrict the API to trusted clients; /api/ps should never be world-readable.",
    });
  }

  // 4. CORS reflection.
  const cors = await checkCors(base); probed++;
  if (cors.confirmed) {
    confirmed++;
    findings.push({
      check: "cors_reflection", ...CHECKS.cors_reflection,
      target: `${base}/api/tags`,
      details: cors,
      probe: cors,
      fix: "Set OLLAMA_ORIGINS to an explicit allowlist of your own front-ends. Never use '*'.",
    });
  }

  // 5. Free inference. Use a real model name if we found one (probe is cheap:
  //    num_predict=1), otherwise send a malformed request that still proves the
  //    endpoint is open.
  const firstModel = tags.confirmed && tags.models[0] ? tags.models[0].name : null;
  const gen = await checkGenerate(base, firstModel); probed++;
  if (gen.confirmed) {
    confirmed++;
    findings.push({
      check: "free_inference", ...CHECKS.free_inference,
      target: `${base}/api/generate`,
      details: { http_status: gen.status, executed_prompt: !!gen.ran },
      probe: gen,
      fix: "Require authentication in front of the API so /api/generate cannot be called anonymously.",
    });
  }

  // 6. Model pull/push write path.
  const pull = await checkPull(base); probed++;
  if (pull.confirmed) {
    confirmed++;
    findings.push({
      check: "model_pull_push", ...CHECKS.model_pull_push,
      target: `${base}/api/pull`,
      details: { http_status: pull.status },
      probe: pull,
      fix: "Block write endpoints (pull/push/create/delete) behind auth and update Ollama to a patched version.",
    });
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    ollama_url: base,
    scanned_by: "ollama-security v0.1",
    active_probe: { enabled: true, probed, confirmed },
    reachable: true,
    ollama_version: ver.version,
    summary,
    findings,
  };
}

// --- CLI ---------------------------------------------------------------------

function parseArgs(argv) {
  const a = argv.slice(2);
  const flag = (k) => { const i = a.indexOf(k); return i !== -1 ? a[i + 1] : null; };
  return {
    help: a.includes("--help") || a.includes("-h"),
    url: flag("--url") || process.env.OLLAMA_URL || (a[0] && !a[0].startsWith("-") ? a[0] : null),
    activeProbe: !a.includes("--no-probe"),
    html: a.includes("--html") ? (flag("--html") || "ollama-report.html") : null,
  };
}

export async function run() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.url) {
    console.error(`ollama-security — audit an Ollama server, prove each leak with an anonymous probe.

Usage:
  ollama-security --url http://your-host:11434
  ollama-security --url your-host            (defaults to http:// and port 11434)
  ollama-security --url http://your-host:11434 --html report.html
  ollama-security --url http://your-host:11434 --no-probe

Flags:
  --url <url>     Ollama base URL or host (or OLLAMA_URL env)
  --no-probe      List the checks without sending any request
  --html <file>   Write a shareable HTML report

Confirms anonymously: no-auth exposure, model inventory (/api/tags),
running models (/api/ps), CORS reflection, free inference (/api/generate),
model pull/push write path (/api/pull), and version disclosure.`);
    process.exit(opts.url ? 0 : 1);
  }

  const result = await audit(opts);

  if (opts.html) {
    const { renderHtml } = await import("./report.js");
    writeFileSync(opts.html, renderHtml(result));
    console.error(`HTML report written to ${opts.html}`);
  }
  console.log(JSON.stringify(result, null, 2));
  const s = result.summary;
  if (result.reachable === false) {
    console.error(`\n${result.note}`);
  } else {
    console.error(
      `\n${s.critical} critical, ${s.high} high, ${s.medium} medium` +
        (result.active_probe.enabled
          ? ` — ${result.active_probe.confirmed} CONFIRMED via anonymous probe`
          : "")
    );
  }
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) run().catch((e) => { console.error(e.message); process.exit(1); });
