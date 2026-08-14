# Cytadel Sentinel

Authorized, scope-gated web-application penetration-testing pipeline for internal
use. It orchestrates **deterministic open-source security tooling** — there is
**no LLM/AI in the runtime execution path**. Every run is repeatable, auditable,
and hard-gated to an explicit authorization scope.

> ⚠️ **Authorized use only.** Sentinel runs active security tools against live
> hosts. Only run it against systems you are explicitly authorized to test. The
> scope file *is* the authorization record — no scope, no run.

---

## What it does (Phase 1)

```
recon → scan → normalize → import(DefectDojo) → report
```

- **Recon** — passive subdomain discovery (`subfinder`), liveness + fingerprint
  (`httpx`), URL/endpoint discovery (`katana`, `gau`, `waybackurls`), light port
  context (`naabu`). Every discovered asset passes the scope gate before it is kept.
- **Scan** — `nuclei` (cve/misconfig/exposure), `testssl.sh` (TLS), `retire.js`
  (outdated JS), `nikto` (server checks). **Authenticated scanning** injects the
  session cookie/header so testing goes past login.
- **Normalize** — every tool's raw output → one unified finding schema, deduped
  by `tool + template-id + host + matched-location`.
- **DefectDojo** — findings are imported via DefectDojo's native `import-scan`
  parsers. DefectDojo owns storage, cross-run dedupe, and triage. Sentinel keeps
  only lightweight run/asset/finding state locally.
- **Report** — a Cytadel-branded HTML + JSON executive report per run under
  `reports/<run-id>/`.

**Phasing:** Phase 1 (on-demand CLI) is built fully. Phase 2 (weekly schedule +
verification layer) and Phase 3 (CI DAST-lite) are scaffolded as clearly-marked
TODO stubs (`src/core/schedule.ts`, `src/stages/verify/`, `.github/workflows/`).

---

## Safety model (non-negotiable)

| Rule | Where enforced |
|------|----------------|
| **No AI at runtime** | entire pipeline is deterministic tooling |
| **Mandatory scope gate** | `src/config/inScope.ts` — every stage calls `gate()`; exclusions win over inclusions |
| **No shell interpolation of target data** | `src/lib/exec.ts` spawns via `execFile` + argv arrays only (no `shell`); replays use `src/lib/http.ts` |
| **Non-destructive by default** | destructive checks need **both** `allow_destructive: true` in scope **and** `--allow-destructive` |
| **Append-only audit log** | `src/lib/audit.ts` — who/when/scope-hash/tools+versions/targets, to Postgres **and** `audit/audit.jsonl` |

---

## Requirements

- **Linux or WSL2** (the security tools are Linux binaries installed via `apt`
  and `go install`). Native Windows/Git-Bash is **not** a supported run target —
  `setup.sh` detects it and refuses to guess.
- Node.js ≥ 20, Docker + Docker Compose, `git`, `curl`.

---

## Setup

```bash
# 1) Install/verify all external tools + bring up DefectDojo (idempotent)
npm run setup            # == bash scripts/setup.sh

# 2) Node deps + Prisma client + DB schema
npm install
cp .env.example .env      # then edit — see below
npm run prisma:generate
npm run prisma:deploy     # or: npm run prisma:migrate  (dev)
```

`setup.sh` is **idempotent**: it checks each dependency and installs only what is
missing, then prints a **summary table** (tool / status / version). It never
fails silently — every failed install is reported with a reason and the script
exits non-zero if a *required* tool failed. Re-run it any time.

Installed/verified: Go, `libpcap-dev`, `subfinder`, `httpx`, `naabu`, `nuclei`
(+ templates), `katana`, `gau`, `waybackurls`, `nikto`, `testssl.sh`,
`retire.js`, `wpscan` (optional), Redis (Docker), and DefectDojo (Docker).

### Getting the DefectDojo API key

1. `setup.sh` prints the admin URL (default **http://localhost:8080**) once the
   stack is healthy.
2. The **first-boot admin password** is printed by the initializer container:
   ```bash
   cd docker/defectdojo && docker compose logs initializer | grep -i "Admin password"
   ```
3. Log in → top-right user menu → **API v2 Key** → copy it into `.env`:
   ```
   DEFECTDOJO_URL="http://localhost:8080"
   DEFECTDOJO_API_KEY="<paste here>"
   ```

### Environment variables

See `.env.example`. Key ones: `DATABASE_URL`, `REDIS_URL`, `DEFECTDOJO_URL`,
`DEFECTDOJO_API_KEY`, and the **session secret** referenced by your scope
(`SENTINEL_SESSION_COOKIE` by default). Secrets live in `.env` only — the scope
YAML references the env-var *name*, never the value.

---

## Scope configuration

Copy `scope/scope.example.yaml` to `scope/<name>.yaml` and edit. Real scope files
are gitignored.

```yaml
name: "acme-web"
authorized_by: "security@company"
authorization_ref: "TICKET-123"
in_scope:
  domains: ["app.acme.com", "*.acme.com"]   # "*.acme.com" ≠ apex "acme.com"
  urls: ["https://app.acme.com"]
exclusions:
  domains: ["status.acme.com"]              # exclusions ALWAYS win
  paths: ["/logout", "/delete"]
auth:
  type: "cookie"                            # cookie | header | none
  session: "SENTINEL_SESSION_COOKIE"        # env var NAME (secret read at runtime)
rate_limit_rps: 10
allow_destructive: false
```

Validate before running:

```bash
npm run sentinel -- scope validate scope/acme-web.yaml
```

---

## Running (Phase 1, on-demand)

```bash
# Full pipeline, waits and prints the report path when done:
npm run sentinel -- run scope/acme-web.yaml

# Permit destructive checks (requires allow_destructive: true in scope too):
npm run sentinel -- run scope/acme-web.yaml --allow-destructive

# Enqueue only (a separate worker processes it):
npm run sentinel -- run scope/acme-web.yaml --detach
npm run sentinel -- worker

# Check a run:
npm run sentinel -- status <run-id>
```

After `npm run build`, the CLI is also available as `node dist/cli.js …` (or the
`sentinel` bin).

### Terminal output

The terminal shows a clean, human reporter by default: a header, one section per
stage (Recon / Scan / Normalize / Import / Report) that resolves to ✓/✗ with a
short result, and a color-coded severity summary with a clickable report link.

- **`--json`** (or `CI=true`, or a non-TTY stdout, e.g. piping) → raw structured
  JSON log lines instead, for CI and piping.
- **`--verbose`** → per-host / debug detail under each stage.
- **`SENTINEL_UI=pretty|json`** forces a mode; `auto` (default) decides by TTY/CI.

Two separate channels, never mixed:

| Channel | Destination | Controlled by |
|---------|-------------|---------------|
| Human reporter | terminal (pretty mode) | `--verbose`, TTY |
| Structured log | `logs/sentinel.log` (pretty) or stdout JSON (CI/`--json`) | `LOG_LEVEL` |
| **Audit trail** | `audit/audit.jsonl` + Postgres | always on (compliance) |

The audit trail is independent of terminal presentation — changing the UI never
changes `audit/audit.jsonl`.

### Where reports land

```
reports/<run-id>/
  report.html     # Cytadel-branded executive report
  report.json     # same data, machine-readable
  raw/            # native tool outputs (also imported into DefectDojo)
```

Full triage, cross-run dedupe, and trends live in **DefectDojo** (the report
links to the engagement).

---

## Architecture

```
cli.ts                      CLI entry (commander)
src/
  config/    scope loader + zod validation + isInScope gate + auth resolution
  core/      run lifecycle, BullMQ queue, orchestrator, context (+ schedule stub)
  stages/
    recon/     subdomain + url/endpoint + port discovery
    scan/      nuclei / testssl / retire / nikto (+ authenticated)
    normalize/ tool output → unified finding schema + dedupe
    verify/    Phase 2 verification layer (interfaces + reference verifier)
    report/    Cytadel-branded HTML/JSON export
  integrations/defectdojo/   API client + import orchestration
  lib/       exec (safe argv runner), http (undici), logger, audit, paths, parse
  db/        prisma client
prisma/schema.prisma         runs, assets, findings, append-only audit log
docker/defectdojo/           DefectDojo compose stack
scripts/setup.sh             idempotent tool installer
```

- **Queue:** BullMQ + Redis (`src/core/queue.ts`). `run` executes inline by
  default (spins an ephemeral worker); `--detach` + `sentinel worker` decouples.
- **DB:** Prisma + PostgreSQL (`prisma/schema.prisma`).

---

## Tests

```bash
npm test        # vitest — includes the scope-gate safety tests
```

The scope gate (`src/config/inScope.test.ts`) is covered directly: wildcard vs
apex, exclusions-win, path-prefix exclusion, URL/host:port parsing, case-folding.

---

## Phase 2 / 3 (scaffolded, not wired)

- **Phase 2** — weekly cron per scope + verification layer. See
  `src/core/schedule.ts` and `src/stages/verify/`. The classifier and one
  reference verifier (missing-security-header, replayed via `lib/http.ts`) are
  implemented; the remaining AUTO verifiers are TODO stubs.
- **Phase 3** — CI DAST-lite on staging deploy. See
  `.github/workflows/sentinel-dast-lite.yml` (guarded `if: false`).
