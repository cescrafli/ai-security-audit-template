# Standardized 360° Security & Resilience Audit Report Templates

Use these templates and CVSS-aligned severity rubrics to generate consistent, audit-grade deliverables in `docs/security-audit/<project>/`.

---

## 1. Severity Classification Rubric (CVSS v3.1 / v4.0 Aligned)

Assign severity objectively based on exploitability, authentication requirements, and confidentiality/integrity/availability impact:

| Severity | CVSS Range | Application, Auth, BaaS, Payment & Infra Criteria | Resilience / DoS Criteria |
| :--- | :---: | :--- | :--- |
| **Critical** | `9.0 – 10.0` | Unauthenticated RCE (including vulnerable PHP runtime engines affected by **PHP2Shell `CVE-2026-109618` / `CVE-2026-109619`** below `8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`), SQL/Command Injection, CI/CD workflow command injection with write secrets, Auth/MFA Bypass, missing Supabase RLS or `USING (true)` on sensitive tables, leaked `service_role`/DB credentials, negative payment amount crediting balance, or unauthenticated cross-tenant data compromise. | Single or low-rate unauthenticated request crashes the server process, exhausts all DB connections, or triggers unbounded paid external API / LLM billing (*Denial of Wallet*). |
| **High** | `7.0 – 8.9` | IDOR/BOLA reading or modifying other users' data, Stored XSS, Race Condition (TOCTOU) allowing balance/coupon/webhook double-spend, OAuth pre-account takeover, SSRF to internal networks, missing auth on Server Actions, or Docker container running privileged/exposing DB ports publicly. | Missing rate limiting on login/OTP/expensive endpoints (or bypassable via `X-Forwarded-For` spoofing), unbounded DB queries (`SELECT *` without limit) on large tables, or synchronous CPU/ReDoS blocking the event loop. |
| **Medium** | `4.0 – 6.9` | Reflected XSS, CSRF on non-critical actions, RSC prop over-serialization of internal metadata, JWTs stored in `localStorage`, open redirect in `callbackUrl`, permissive CORS without credentials, or Docker container running as root without host mounts. | N+1 query loops degrading response latency under moderate load, missing outbound `fetch()` timeouts, or missing pagination defaults on secondary endpoints. |
| **Low / Info** | `0.1 – 3.9` | Missing defense-in-depth HTTP headers (`X-Frame-Options`, `Permissions-Policy`, SRI), verbose non-sensitive error messages, mutable `:latest` Docker tags, or minor lockfile hygiene issues. | Minor missing secondary indexes or non-critical in-memory caching improvements. |

---

## 2. Template for `surface-map.md`

```markdown
# 360° Attack Surface & Architecture Map — <Project Name>

- **Audit Date**: YYYY-MM-DD
- **Target Path**: `<local-path>`
- **Tech Stack**: <Framework, Runtime, Database/ORM/BaaS, Auth Provider, Payment Gateway, Infra/CI-CD>

## 1. Trust Boundaries, Auth & BaaS Isolation Architecture
- **Session / Token / OAuth / MFA Mechanism**: <JWT / Cookie / NextAuth / Supabase Auth / Clerk>
- **Global Middleware & Guards**: `<path/to/middleware>`
- **Database & BaaS Isolation (RLS / Firestore Rules)**: <Status of RLS policies & service-role key scoping>
- **Reverse Proxy / IP Trust Config**: <`trust proxy` / `CF-Connecting-IP` / `X-Forwarded-For` handling>

## 2. Entry Points & Route Inventory

| Route / Action / Webhook | Type / Method | Auth Guard | Input Schema | Rate Limit | Data Sink / External Call | Risk Tier |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/auth/login` | `POST` | Public | Partial | None | DB (`users`) | High |
| `transferFundsAction` | Server Action | Session | None | None | DB (`wallets`) | Critical |
| `/api/webhooks/stripe` | `POST` | Signature | Raw Body | None | DB (`orders`, `ledger`) | Critical |

## 3. Infrastructure, CI/CD & High-Cost Resource Paths
- **Containers, Reverse Proxy & CI/CD Workflows**: <`Dockerfile`, `docker-compose.yml`, `.github/workflows/*`, `nginx.conf`>
- **Database, Transaction & Ledger Hotspots**: <Files/Routes>
- **File Uploads, Media Processing & AI/LLM Integrations**: <Files/Routes>
```

---

## 3. Template for `report.md`

```markdown
# 360° Security & Server Resilience Audit Report — <Project Name>

- **Audit Date**: YYYY-MM-DD
- **Target Path**: `<local-path>`
- **Audit Mode**: <Read-Only Static Audit | Static Audit + Defensive Patching>

---

## 1. Executive Summary

<2–3 sentence assessment of the application's overall security and resilience posture across application/auth/payment code (`SEC`), runtime/infrastructure/CI-CD (`INF`), and server availability (`RES`).>

| Severity | App, Auth, BaaS & Payment (`SEC`) | Runtime, Infra, CI/CD & Supply Chain (`INF`) | Resilience & DoS (`RES`) | Total | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Critical** | 0 | 0 | 0 | 0 | <Open / Patched> |
| **High** | 0 | 0 | 0 | 0 | <Open / Patched> |
| **Medium** | 0 | 0 | 0 | 0 | <Open / Patched> |
| **Low / Info** | 0 | 0 | 0 | 0 | <Open / Patched> |

### Compound Risk & Vulnerability Chaining Summary
<Briefly highlight if any findings combine into a higher-severity attack chain (e.g., Open Redirect + OAuth Callback, Missing Proxy Trust + Login Rate Limit, or File Upload + Path Traversal), or state "No compound exploit chains identified.">

---

## 2. Finding Summary Matrix

| ID | Title | Domain | CWE | Severity | Location | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-001` | <Short Title> | OWASP A01 / Auth & BaaS | `CWE-639` | **High** | `src/app/api/...:L12-L34` | <Open/Patched> |
| `INF-001` | <Short Title> | CI/CD / Docker | `CWE-78` | **Critical** | `.github/workflows/...:L25` | <Open/Patched> |
| `RES-001` | <Short Title> | Resilience / DoS | `CWE-770` | **High** | `src/app/api/...:L40-L62` | <Open/Patched> |

---

## 3. Detailed Technical Findings

### [SEC-001] <Finding Title>
- **Severity**: **Critical / High / Medium / Low**
- **Classification**: <Security Domain / OWASP Category> · `<CWE-ID: CWE Name>`
- **Location**: `path/to/file.ext` (Lines `XX–YY`)

#### Source-to-Sink Taint & Impact Analysis
- **Source**: `<Untrusted input parameter/header/payload/event>`
- **Missing Guard**: `<Why existing validation, auth, RLS policy, or rate limiting fails to block it>`
- **Sink & Impact**: `<Exact line where data reaches the sink and resulting confidentiality, integrity, financial, or availability impact>`

#### Vulnerable Code
\`\`\`<lang>
// Exact snippet from the audited file
\`\`\`

#### Defensive Remediation Patch
\`\`\`<lang>
// Production-ready fixed code snippet
\`\`\`

---

## 4. Prioritized Hardening Roadmap

1. **Immediate (P0 — Blockers & Critical/High Security & Financial Fixes)**: <List>
2. **Short-Term (P1 — Rate Limiting, RLS/Auth Hardening, Query Bounds & CI/CD Fixes)**: <List>
3. **Defense-in-Depth (P2 — Security Headers, Docker Non-Root, Logging & Dependency Hygiene)**: <List>

---

## 5. 360° Verification & Hardening Checklist

- [ ] **Authentication, OAuth & MFA**: `HttpOnly`/`Secure`/`SameSite` cookies, strict JWT verification, OAuth `state` & `email_verified` checks, MFA brute-force protection, session revocation on password change
- [ ] **Authorization, BaaS & Tenant Isolation**: Server-side auth inside every API route & Server Action; object-level ownership (`IDOR`) checks; Supabase/Postgres RLS enabled on all public tables with no `service_role` client leak
- [ ] **DTO, Privacy & Client Storage**: Sensitive DB fields (`passwordHash`, secrets, PII) stripped from API responses, RSC props, `localStorage`, and production logs/error responses
- [ ] **Input Validation & Injection Defense**: Parameterized queries, allowlisted dynamic sort columns, strict schema validation (`zod`/FormRequest/Pydantic), sanitized HTML/Markdown
- [ ] **Financial Ledger, Webhooks & Concurrency**: Positive integer/Decimal currency math, cryptographic webhook signature & idempotency checks, atomic DB transactions with `SELECT ... FOR UPDATE` row locking
- [ ] **AI / LLM Security**: Server-enforced tenant scoping on LLM tool calls, sanitized LLM output rendering, and strict per-user token/cost quotas (*Denial of Wallet* protection)
- [ ] **Rate Limiting & Proxy Trust**: Multi-tier rate limiters with accurate proxy IP configuration (`trust proxy`) and GraphQL batching/depth limits
- [ ] **Query, Memory & CPU Bounds**: Hard `LIMIT`/pagination caps (`<= 100`), N+1 elimination, ReDoS-safe regexes, bounded file upload/image dimensions, explicit `AbortSignal.timeout()` outside DB transactions
- [ ] **Infrastructure, Docker & CI/CD**: Non-root Docker containers, complete `.dockerignore`, loopback-bound DB ports, no raw `${{ ... }}` interpolation in GitHub Actions `run:` blocks, dotfile blocking in Nginx/Apache
- [ ] **HTTP Security Headers & Supply Chain**: CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, strict CORS allowlist, committed lockfiles, clean `npm audit` / `composer audit` / `pip-audit`
```
