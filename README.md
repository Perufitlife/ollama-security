# ollama-security

> Audit any **Ollama** server for the one misconfiguration that actually leaks compute and models — a public API bound with **no authentication** — and **prove it live with an anonymous probe** of `/api/tags`, `/api/ps`, `/api/version`, `/api/generate` and CORS reflection. Other checklists tell you what *might* be wrong; this fetches the bytes and shows you what *is*.

> ⚡ **Run it in one line, no token, no install:**
> ```bash
> npx ollama-security --url http://your-host:11434
> ```

> 🤝 **Want it done for you?** [Fixed-scope audit — $99 / 24h](https://buy.stripe.com/3cIeVdgikfj47yx9LkcAo0m): I verify each finding live and send a written report with the exact config fixes.

[![npm](https://img.shields.io/npm/v/ollama-security?color=red)](https://www.npmjs.com/package/ollama-security) [![downloads](https://img.shields.io/npm/dw/ollama-security)](https://www.npmjs.com/package/ollama-security) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

```
$ npx ollama-security --url http://10.0.0.5:11434
2 critical, 4 high, 1 medium — 7 CONFIRMED via anonymous probe
  CRITICAL  /api/version    Ollama API reachable with no authentication (v0.5.1)
  CRITICAL  /api/pull       anonymous model push/pull reachable — model theft + RCE chain
  HIGH      /api/tags       full model inventory leaked — 11 models reachable
  HIGH      /api/ps         running models + VRAM exposed
  HIGH      CORS            Origin reflected → any website can drive your Ollama
  HIGH      /api/generate   anonymous inference accepted — free GPU / compute theft
```

## Why this exists

Ollama is the default way to run local LLMs — and it ships with **no
authentication** on port `11434` (CNVD-2025-04094). If `OLLAMA_HOST` is bound to
`0.0.0.0` and the port is reachable, *anyone* who finds it has full control of
your models and your GPU.

This is not theoretical. In February 2026, ~**175,000 Ollama instances** were
found exposed with zero auth (LeakIX / the Cisco–Shodan study). The documented
abuse is brutal: model theft via `pull`/`push`, free inference on your hardware,
and proven RCE chains — in June 2026 Sysdig caught an attacker using an exposed
Ollama as a **malware brain**.

`ollama-security` checks for these and **confirms the real ones** by issuing the
exact anonymous request an attacker would — so you triage facts, not maybes. If
your server isn't anonymously reachable, it tells you so and exits clean.

## What it checks

| Check | Severity | How it's confirmed |
|---|---|---|
| API reachable with no auth | critical | anonymous `GET /api/version` answers `{version}` |
| Model push/pull write path open | critical | anonymous `POST /api/pull` accepted (not 401/403) |
| Model inventory leak | high | anonymous `GET /api/tags` returns every model |
| Running models / VRAM leak | high | anonymous `GET /api/ps` returns loaded models |
| CORS reflects arbitrary Origin | high | a foreign `Origin` is echoed in `Access-Control-Allow-Origin` |
| Free inference (compute theft) | high | anonymous `POST /api/generate` accepted |
| Version disclosure | medium | `/api/version` reveals the exact build for CVE matching |

The write-path probes (`/api/pull`, `/api/generate`) are sent with empty/`num_predict=1`
payloads so the tool **never downloads a model or runs a real workload** — a `200`
or `400` proves the endpoint is open; `401`/`403`/`404` means it's protected.

## Usage

```bash
# Probe a live instance
npx ollama-security --url http://your-host:11434

# Bare host works too (defaults to http:// and port 11434)
npx ollama-security --url your-host

# Write a shareable HTML report
npx ollama-security --url http://your-host:11434 --html report.html

# Static only (no requests sent) — just list the checks
npx ollama-security --url http://your-host:11434 --no-probe
```

Output is JSON on stdout (pipe it into CI) and a one-line summary on stderr.
Exit is non-zero only on usage errors — gate your pipeline on the JSON `summary`.

## The fix, in one line

```bash
# bind Ollama to localhost only, then firewall 11434 / front it with an authed proxy
export OLLAMA_HOST=127.0.0.1
# and never set OLLAMA_ORIGINS=* on a public box
```

## Install (optional)

```bash
npm i -g ollama-security
ollama-security --url http://your-host:11434
```

Zero dependencies. Your data and credentials never leave your machine — every
request goes straight from the tool to your Ollama server.

## Sister tools

Same active-probe philosophy for the rest of the stack, all MIT:

[supabase-security](https://github.com/Perufitlife/supabase-security-skill) ·
[pocketbase-security](https://github.com/Perufitlife/pocketbase-security-skill) ·
[firebase-security](https://github.com/Perufitlife/firebase-security-skill) ·
[appwrite-security](https://github.com/Perufitlife/appwrite-security-skill) ·
[nhost-security](https://github.com/Perufitlife/nhost-security-skill) ·
[strapi-security](https://github.com/Perufitlife/strapi-security) ·
[directus-security](https://github.com/Perufitlife/directus-security)

## License

MIT © [Renzo Madueno](https://github.com/Perufitlife)

---

📚 Part of [**Awesome Backend Security Auditors**](https://github.com/Perufitlife/awesome-backend-security) — the full collection of keyless active-probe auditors.
