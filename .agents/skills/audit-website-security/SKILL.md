---
name: audit-website-security
description: Perform a comprehensive 360-degree defensive static security audit (OWASP Top 10, ASVS, CWE, CVSS) across application code, framework architecture, BaaS/RLS & database schemas, OAuth/MFA & payment flows, Docker/CI-CD infrastructure, and server resilience on a local codebase.
---

# Audit and harden website source code across all security domains

Perform an enterprise-grade, 360-degree defensive security and server resilience audit on the local codebase supplied by the user. Operate strictly on local source code, database migrations, infrastructure/CI-CD manifests, and configurations—never generate offensive exploit payloads, attack scripts, or live traffic floods against running servers.

### Execution Modes & Deliverable Paths
- **Mode Selection (`readonly` vs `patch`)**:
  - **`readonly` (Default)**: Do **not** modify any source or configuration files inside the target project. Only inspect code and generate the audit deliverables (`surface-map.md` and `report.md`).
  - **`patch`**: Activated only when the user passes `patch` or explicitly asks to fix/harden the codebase. Apply defensive patches in Stage 3 after completing the Stage 1–2 audit.
- **Deliverable Storage Rule**:
  - Sanitize `<project>` into a lowercase slug (e.g., `my-web-app`).
  - When running inside the `ai-security-audit-template` workspace, write deliverables to `<template-workspace>/docs/security-audit/<project>/` so external target projects remain 100% untouched in `readonly` mode.
  - When this skill is invoked globally inside a standalone target workspace without this template repository, write deliverables to `<target-workspace>/docs/security-audit/<project>/` (or an artifact directory if requested) without altering application source files in `readonly` mode.

---

## 1. Threat Modeling, Automated Sink Recon & Surface Mapping

1. **Inspect Full-Stack & Infrastructure Manifests**:
   Read package manifests (`package.json`, `package-lock.json`, `composer.json`, `composer.lock`, `requirements.txt`, `pyproject.toml`, `go.mod`), framework configurations (`next.config.*`, `vite.config.*`), environment templates (`.env.example`), database schemas & RLS migrations (`schema.prisma`, `supabase/migrations/*.sql`, `firestore.rules`), container/CI-CD files (`Dockerfile`, `docker-compose.yml`, `.github/workflows/*.yml`, `nginx.conf`, `.htaccess`), middleware, and route trees.
2. **Run Automated Static Recon & Runtime CVE Scanner**:
   Resolve [audit-recon.mjs](scripts/audit-recon.mjs) **relative to this `SKILL.md` file's directory** (`<skill-dir>/scripts/audit-recon.mjs`) and execute it against `<target-project-path>` when Node.js is available:
   ```bash
   node "<skill-dir>/scripts/audit-recon.mjs" "<target-project-path>"
   ```
   Review all four scanner outputs:
   - **`[STACK]` & `[RUNTIME]`**: Exact lockfile/runtime CVE status (`PHP2Shell` `CVE-2026-109618`/`109619`, Next.js `CVE-2025-29927`, Laravel Ignition `CVE-2021-3129`) and Git-tracked secret files (`git ls-files`).
   - **`[ENTRY_POINTS]`**: Complete list of Middleware, Webhook, Server Action (`'use server'`), and Route/Controller files—audit **every file** in this list for *missing* authentication, BOLA/IDOR, BFLA, schema validation, and rate limiting.
   - **`[SUMMARY]` & Candidate Sinks**: Structural findings (`SUPABASE_MISSING_RLS`, `DOCKER_ROOT_USER`) and severity-sorted source sinks (`CRITICAL`, `HIGH`, `MEDIUM`).
3. **Record the Attack Surface Inventory**:
   Save `docs/security-audit/<project>/surface-map.md` following [the report templates reference](references/report-templates.md). Finish this stage when every public route, trust boundary, infrastructure manifest, and sensitive data sink is mapped to exact source files.

---

## 2. Deep 360° Security Audit, Taint Tracing & Chaining Analysis

1. **Source-to-Sink Taint Tracing (Eliminate False Positives)**:
   - **Source**: Untrusted input (`req.body`, `req.query`, `params`, headers, cookies, OAuth callback params, webhook payload, file upload, Server Action args, GitHub event context).
   - **Guard / Sanitizer**: Check whether active middleware, session/role verification, RLS policy, ownership filter (`WHERE user_id = session.userId`), schema validator (`zod`, FormRequest, Pydantic), or rate limiter blocks abuse along the call chain.
   - **Sink**: Verify whether unvalidated or unauthorized input reaches a database mutation, raw query, shell/CLI flag, HTML renderer, payment ledger, outbound HTTP call, or unbounded memory/CPU loop.
2. **Compound Risk & Vulnerability Chaining Assessment**:
   Evaluate how lower-severity weaknesses combine into critical breach paths (e.g., *Open Redirect + OAuth Callback = Token Theft*, *Permissive CORS + Credentials = Cross-Origin Data Theft*, *Image Upload + `phar://`/LFI = RCE*, or *X-Forwarded-For Spoofing + Login Endpoint = Rate-Limit Bypass*).
3. **Non-Overlapping Finding ID Taxonomy**:
   - **`SEC-xxx`**: Application, Framework, API, AI/LLM, Auth/OAuth/MFA, BaaS/RLS & Business/Payment Logic flaws.
   - **`INF-xxx`**: Runtime Engine CVEs (`PHP2Shell`, Next.js/Dependency CVEs), Docker/Containers, CI/CD Pipelines, Web Server/Reverse Proxy & Supply Chain flaws.
   - **`RES-xxx`**: Rate Limiting, Database/Memory/CPU Exhaustion, N+1/Unbounded Queries, ReDoS & Missing Timeouts.

### Required Reference Guides During Stage 2
1. **[OWASP Top 10 & ASVS Code Review](references/owasp-code-review.md)** — Access Control, BOLA/BFLA/BOPLA (`A01`, `API1`–`API5`), Cryptography & Secrets (`A02`), SQL/NoSQL/Command Injection, XSS & XXE (`A03`), Business Logic & Race Conditions (`A04`), Security Headers (`A05`), Auth/JWT/Host-Header Flaws (`A07`), Webhooks, Uploads & Deserialization (`A08`), Log Leaks (`A09`), and SSRF (`A10`).
2. **[Framework-Specific, Runtime Engine, API, WebSocket & AI/LLM Security](references/framework-and-ai-security.md)** — **Next.js / React** (`'use server'` Action exposure, RSC serialization leaks, `CVE-2025-29927`), **Node / Express / Prisma** (`trust proxy` IP spoofing, prototype pollution), **PHP / Laravel / WordPress** (**`PHP2Shell` `CVE-2026-109618` & `CVE-2026-109619` requiring PHP `>= 8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`**, `php.ini` hardening, Eloquent column SQLi, Livewire `#[Locked]`), **Python (FastAPI / Django)**, **GraphQL / WebSockets**, and **AI / LLM Security (`LLM01`–`LLM07`)**.
3. **[BaaS (Supabase / Firebase), OAuth/MFA, Financial Ledger & Client-Side Security](references/baas-auth-and-payment-security.md)** — **PostgreSQL / Supabase RLS** & Firebase Rules, **OAuth2 / OIDC & MFA**, **Payment & Financial Ledgers** (negative amounts, integer/Decimal currency math, webhook idempotency), and **Client-Side DOM / Storage**.
4. **[Infrastructure, Docker, CI/CD, Reverse Proxy & Supply Chain Security](references/infrastructure-cicd-and-supply-chain.md)** — **Docker / Multi-Stage Containers**, **GitHub Actions CI/CD Injection & `pull_request_target`**, **Nginx / Apache / Web Cache Poisoning**, **Native Media Binary CVEs**, and **Supply Chain / Lockfile Integrity**.
5. **[Server Resilience & DoS Prevention](references/resilience-and-rate-limiting.md)** — **Multi-Tier Rate Limiting & Billing Amplification**, **Unbounded Queries & N+1 Loops**, **ReDoS**, **Event-Loop Blocking**, **Decompression / Pixel Bombs**, **Outbound Timeouts**, and **DB Connection Pool Exhaustion**.
6. **[Real-World Mass Breach Playbooks, Classic Flaws & High-Impact CVEs](references/real-world-breach-playbooks-and-cves.md)** — Foundational classic flaws resurfacing in modern apps (`CLI Argument Injection CWE-88`, `Dynamic LFI/import CWE-98`, `CRLF/SMTP Injection CWE-113`, `.htaccess/.user.ini Uploads CWE-434`, `Buffer.allocUnsafe Heap Leaks CWE-908`, `phar:// Deserialization CWE-502`, `Type Juggling CWE-843`) and mass-compromise CVEs (`PHP2Shell`, `CVE-2024-4577`, `CVE-2019-11043`, `CVE-2021-3129`, `CVE-2025-29927`, `polyfill.io`, `vm2`, `IMDSv1 SSRF`, `Log4Shell`, `libwebp`).

---

## 3. Defensive Hardening & Patching (`patch` Mode Only)

Skip this stage in `readonly` mode. In `patch` mode, implement minimal, production-ready defensive patches following the code blueprints in the reference guides:
- **App & API Layer**: Enforce strict schema validation (`zod`, FormRequests, Pydantic), explicit DTO response filtering, parameterized queries, allowlisted dynamic sort columns, and object-level ownership (`userId` / `tenantId`) on all reads/mutations.
- **Auth, BaaS & Payment Layer**: Enable strict Supabase RLS policies bound to `auth.uid()`, validate OAuth `state` and `email_verified`, enforce atomic database transactions with conditional updates / `SELECT ... FOR UPDATE` row locking and unique idempotency keys on financial/webhook mutations, and enforce positive integer/Decimal currency math.
- **Resilience & Infrastructure Layer**: Add proxy-aware multi-tier rate limiting (`429 Too Many Requests` with `Retry-After`), hard pagination caps (`Math.min(limit, 100)`), SSRF-safe `redirect: 'error'` + `AbortSignal.timeout(5000)` outbound fetches outside DB transactions, strict HTTP security headers, non-root final-stage Docker users, and safe `env:` bindings in GitHub Actions.

Preserve existing route contracts and business workflows. Disclose any necessary breaking changes explicitly.

---

## 4. Multi-Stack Verification & Standardized Reporting

When code patches are applied in `patch` mode, run the target project's native verification suite:
- **Node.js / TypeScript**: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` (plus `npm audit --omit=dev`).
- **PHP / Laravel**: `php -v` (verify engine is patched against `PHP2Shell` `CVE-2026-109618` / `CVE-2026-109619`: `>= 8.5.12`, `>= 8.4.27`, `>= 8.3.36`, or `>= 8.2.35`), `php -l`, `composer audit`, `php artisan test` / `./vendor/bin/phpstan`.
- **Python**: `pip-audit`, `ruff check`, `mypy`, `pytest`.

Read [the report templates reference](references/report-templates.md) and generate the final report in `docs/security-audit/<project>/report.md`.
