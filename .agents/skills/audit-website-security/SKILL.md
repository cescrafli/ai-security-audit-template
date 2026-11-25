---
name: audit-website-security
description: Perform a comprehensive 360-degree defensive static security audit (OWASP Top 10, ASVS, CWE, CVSS) across application code, framework architecture, BaaS/RLS & database schemas, OAuth/MFA & payment flows, Docker/CI-CD infrastructure, and server resilience on a local codebase.
---

# Audit and harden website source code across all security domains

Perform an enterprise-grade, 360-degree defensive security and server resilience audit on the local codebase supplied by the user. Operate strictly on local source code, database migrations, infrastructure/CI-CD manifests, and configurations—never generate offensive exploit payloads, attack scripts, or live traffic floods against running servers.

---

## 1. Threat Modeling, Automated Sink Recon & Surface Mapping

1. **Inspect Full-Stack & Infrastructure Manifests**:
   Read package manifests (`package.json`, `composer.json`, `requirements.txt`, `pyproject.toml`, `go.mod`), framework configurations (`next.config.*`, `vite.config.*`), environment templates (`.env.example`), database schemas & RLS migrations (`schema.prisma`, `supabase/migrations/*.sql`, `firestore.rules`), container/CI-CD files (`Dockerfile`, `docker-compose.yml`, `.github/workflows/*.yml`, `nginx.conf`, `.htaccess`), middleware, and route trees.
2. **Run Automated Static Recon & Runtime CVE Scanner**:
   Execute the bundled read-only reconnaissance script [audit-recon.mjs](scripts/audit-recon.mjs) against the target project path (when Node.js is available) or use native search tools to immediately surface runtime CVE status (`PHP2Shell` `CVE-2026-109618`/`109619`, Next.js `CVE-2025-29927`) and candidate source code sinks:
   ```bash
   node .agents/skills/audit-website-security/scripts/audit-recon.mjs <target-project-path>
   ```
   Also scan for stack-specific entry points and sinks:
   - **Routes, Actions & Webhooks**: `'use server'`, `export async function (GET|POST|PUT|PATCH|DELETE)`, `Route::`, `@app.(get|post|put|delete)`, GraphQL resolvers, WebSocket `.on(`, webhook handlers (`stripe`, `midtrans`, `xendit`, `svix`).
   - **Injection, Execution & Deserialization Sinks**: `$queryRawUnsafe`, `$executeRawUnsafe`, `DB::raw`, `whereRaw`, `orderByRaw`, `.raw(`, `exec(`, `execSync`, `spawn(`, `shell_exec`, `eval(`, `unserialize(`, `pickle.`, `yaml.load`, `dangerouslySetInnerHTML`, `v-html`, `{!!`, `mark_safe`, `postMessage(`.
   - **Auth, BaaS, Secrets & External Calls**: `NEXT_PUBLIC_`, `VITE_`, `SERVICE_ROLE`, `jwt.verify`, `jwt.decode`, `Math.random`, `localStorage.`, `ENABLE ROW LEVEL SECURITY`, `USING (true)`, `fetch(`, `axios`, `Http::`, `requests.`.
3. **Record the Attack Surface Inventory**:
   Save a complete map in `docs/security-audit/<project>/surface-map.md` following [the report templates reference](references/report-templates.md):
   - **Technology Stack, Infrastructure & Trust Boundaries**
   - **Entry Points & Route Matrix** (Public, Authenticated, Admin, Webhooks, Server Actions, GraphQL, WebSockets)
   - **Authentication, OAuth/MFA, Session & BaaS/RLS Isolation Architecture**
   - **Financial/Payment Flows, Sensitive Data Sinks & High-Cost Paths**

Finish this stage when every public route, trust boundary, infrastructure manifest, and sensitive data sink is mapped to exact source files.

---

## 2. Deep 360° Security Audit & Source-to-Sink Taint Tracing

Inspect the mapped files systematically across all security domains. To eliminate false positives, apply **Source-to-Sink Taint Tracing** for every candidate issue:
1. **Source**: Where does untrusted data enter? (`req.body`, `req.query`, `params`, headers, cookies, OAuth callback params, webhook payload, file upload, Server Action args, GitHub event context).
2. **Guard / Sanitizer**: Does an active middleware, auth check, RLS policy, ownership filter (`WHERE user_id = session.userId`), schema validator (`zod`, FormRequest, Pydantic), or rate limiter intercept the data along the call chain?
3. **Sink**: Does unvalidated or unauthorized input reach a privileged database mutation, raw query, shell command, HTML renderer, payment ledger, outbound HTTP call, or unbounded memory/CPU loop?

Classify every verified finding with a unique ID (`SEC-001`, `RES-001`, `INF-001`), CVSS-aligned severity (`Critical`, `High`, `Medium`, `Low`, `Informational`), **CWE identifier**, **Security Domain**, and exact file/line range (`path/to/file:L10-L25`).

### Required Reference Guides During Stage 2
1. **[OWASP Top 10 & ASVS Code Review](references/owasp-code-review.md)** — Core inspection criteria for Broken Access Control & IDOR (`A01`), Cryptographic & Secret Failures (`A02`), SQL/NoSQL/Command Injection & XSS (`A03`), Business Logic & Race Conditions / TOCTOU (`A04`), Misconfiguration & Security Headers (`A05`), Vulnerable Dependencies (`A06`), Auth/JWT/Session Flaws (`A07`), Webhook Integrity, File Uploads & Deserialization (`A08`), Sensitive Logging & Stack Trace Leaks (`A09`), and SSRF (`A10`).
2. **[Framework-Specific, Runtime Engine, API, WebSocket & AI/LLM Security](references/framework-and-ai-security.md)** — Stack-specific checks for **Next.js / React** (`'use server'` Action exposure, RSC prop serialization leaks, `next/image` SSRF), **Node.js / Express / Prisma** (`trust proxy` IP spoofing, prototype pollution, Prisma model over-exposure), **PHP / Laravel / WordPress** (**PHP Core Engine RCE — `PHP2Shell` `CVE-2026-109618` & `CVE-2026-109619` requiring PHP `>= 8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`**, `php.ini` hardening, Eloquent column-name SQLi, Mass Assignment, Blade/Livewire property tampering), **Python (FastAPI / Django)** (missing `response_model`, async event-loop blocking), **GraphQL / WebSockets** (query depth/batching DoS, CSWSH), and **AI / LLM Integrations** (Indirect Prompt Injection to tool calls, LLM-to-XSS, Denial of Wallet).
3. **[BaaS (Supabase / Firebase), OAuth/MFA, Financial Ledger & Client-Side Security](references/baas-auth-and-payment-security.md)** — Deep checks for **PostgreSQL / Supabase RLS** (missing `ENABLE ROW LEVEL SECURITY`, `USING (true)` policies, leaked `service_role` keys) & **Firebase Rules**, **OAuth2 / OIDC & MFA** (missing `state` verification, pre-account takeover via unverified email linking, open redirects, MFA step bypass, OTP brute-force), **Payment & Financial Ledgers** (negative amount injection, floating-point currency math, webhook idempotency/double-crediting), and **Client-Side DOM / Storage** (tokens in `localStorage`, insecure `postMessage`, missing SRI).
4. **[Infrastructure, Docker, CI/CD, Reverse Proxy & Supply Chain Security](references/infrastructure-cicd-and-supply-chain.md)** — Checks for **Docker / Containers** (running as root, secrets in `ENV`/`ARG` layers, missing `.dockerignore`, exposed DB/Redis ports), **CI/CD Pipelines** (GitHub Actions `${{ ... }}` script injection in `run:`, dangerous `pull_request_target` checkouts, excessive `GITHUB_TOKEN` permissions), **Nginx / Apache / Cloud Configs** (exposed `.git`/`.env`/backups, script execution in upload dirs), and **Supply Chain Integrity** (lockfile verification, lifecycle script risks).
5. **[Server Resilience & DoS Prevention](references/resilience-and-rate-limiting.md)** — Checks for **Multi-Tier Rate Limiting & Third-Party Billing Amplification** (`CWE-770`), **Unbounded Queries, Missing Indexes & N+1 Loops** (`CWE-400`), **ReDoS** (`CWE-1333`), **Event-Loop Blocking**, **Decompression / Pixel Bombs** (`CWE-409`), **Missing Outbound Timeouts**, and **DB Connection Pool Exhaustion** (external HTTP calls inside open DB transactions).
6. **[Real-World Mass Breach Playbooks, Classic Flaws & High-Impact CVEs](references/real-world-breach-playbooks-and-cves.md)** — Checks against both **foundational classic vulnerabilities that resurface in modern wrappers** (CLI Argument Injection `--flag` in `spawn`/`execFile` `CWE-88`, Dynamic `include`/`import()` LFI `CWE-98`, CRLF/SMTP Header Injection `CWE-113`, Double-Extension & `.htaccess`/`.user.ini` Webshell Uploads `CWE-434`, XXE `CWE-611`, Heartbleed-style Node.js `Buffer.allocUnsafe` heap memory leaks `CWE-908`, PHP `phar://` metadata deserialization `CWE-502`, Type Juggling / loose comparison `==` `CWE-843`) and **high-impact mass-compromise CVEs** (**PHP2Shell `CVE-2026-109618` / `CVE-2026-109619`**, **PHP-CGI `CVE-2024-4577`**, **Nginx+FPM `CVE-2019-11043`**, **Laravel Ignition `CVE-2021-3129`**, **Next.js Middleware Bypass `CVE-2025-29927`**, **Magecart `polyfill.io` CDN hijack**, **`vm2` Sandbox Escape**, **Cloud IMDSv1 SSRF**, **Supabase Missing RLS**, and **Log4Shell / `libwebp` / `ImageTragick`**).

---

## 3. Defensive Hardening & Patching (When Requested)

Operate in **Read-Only Audit Mode** by default if the user only asks for an audit or report. When the user asks to fix or harden the codebase, implement minimal, production-ready defensive patches across all affected layers:
- **App & API Layer**: Enforce strict schema validation (`zod`, FormRequests, Pydantic), explicit DTO response filtering (stripping password hashes/secrets), parameterized queries, allowlisted dynamic sort columns, and object-level ownership (`userId` / `tenantId`) on all reads/mutations.
- **Auth, BaaS & Payment Layer**: Enable strict Supabase RLS policies bound to `auth.uid()`, validate OAuth `state` and `email_verified`, enforce atomic database transactions with pessimistic row locking (`SELECT ... FOR UPDATE`) and unique idempotency keys on financial/webhook mutations, and enforce positive integer/Decimal currency math.
- **Resilience & Infrastructure Layer**: Add proxy-aware multi-tier rate limiting (`429 Too Many Requests` with `Retry-After`), hard pagination caps (`Math.min(limit, 100)`), explicit outbound timeouts (`AbortSignal.timeout(5000)`), strict HTTP security headers (CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options`), non-root Docker users, and safe `env:` variable passing in GitHub Actions workflows.

Preserve existing route contracts and business workflows. Disclose any necessary breaking changes explicitly.

---

## 4. Multi-Stack Verification & Standardized Reporting

When code patches are applied, run the project's native verification suite based on its stack:
- **Node.js / TypeScript**: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` (plus `npm audit --omit=dev`).
- **PHP / Laravel**: `php -v` (verify engine is patched against `PHP2Shell` `CVE-2026-109618` / `CVE-2026-109619`: `>= 8.5.12`, `>= 8.4.27`, `>= 8.3.36`, or `>= 8.2.35`), `php -l`, `composer audit`, `php artisan test` / `./vendor/bin/phpstan`.
- **Python**: `pip-audit`, `ruff check`, `mypy`, `pytest`.

Read [the report templates reference](references/report-templates.md) and generate the final report in `docs/security-audit/<project>/report.md`. Include the Executive Summary, 360° Domain & CVSS Risk Matrix, Detailed Technical Findings (with Source-to-Sink trace, CWE, File:Line, Vulnerable Code, and Defensive Patch), and a prioritized Hardening Roadmap (`P0`, `P1`, `P2`).
