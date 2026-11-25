<div align="center">

# AI Security & Resilience Audit Template

### 360° source code, architecture, infrastructure, and server resilience auditing with one command

Give your AI coding agent a local project folder and watch it map your attack surface, trace untrusted inputs from source to sink across OWASP Top 10, framework pitfalls, BaaS/RLS policies, OAuth/MFA & payment ledgers, Docker/CI-CD pipelines, and server resilience bottlenecks, apply defensive patches, and generate a standardized CWE/CVSS-mapped audit report.

**Works with Antigravity, Claude Code, Codex, Cursor, and OpenCode.**

[![Use this template](https://img.shields.io/badge/Use_this_template-Create_your_copy-2ea44f?style=for-the-badge&logo=github&logoColor=white)](https://github.com/cescrafli/ai-security-audit-template/generate)

[How It Works](#how-it-works) · [360° Audit Coverage](#360-audit-coverage) · [Supported Platforms](#supported-platforms) · [Project Structure](#project-structure)

</div>

---

## How It Works

The `audit-website-security` skill follows a four-stage application and infrastructure security methodology:

1. **Threat Modeling, Automated Sink Recon & Surface Mapping** — Runs the read-only static reconnaissance scanner ([`scripts/audit-recon.mjs`](.agents/skills/audit-website-security/scripts/audit-recon.mjs)) to auto-detect the technology stack, inventory all entry-point files (Middlewares, Webhooks, Server Actions, Routes/Controllers) for missing-control review, check Git-tracked secret files (`git ls-files`), verify exact lockfile/runtime CVEs (`PHP2Shell` `CVE-2026-109618`/`109619`, Next.js `CVE-2025-29927`, Laravel Ignition `CVE-2021-3129`), perform multi-stage `Dockerfile` and cross-migration per-table Supabase RLS checks, and output masked, comment-filtered candidate sinks sorted by severity (`CRITICAL`, `HIGH`, `MEDIUM`) before generating `docs/security-audit/<project>/surface-map.md`.
2. **Deep 360° Audit, Source-to-Sink Taint Tracing & Chaining Analysis** — Traces untrusted inputs (`Source → Guard/Sanitizer/RLS → Sink`) to eliminate false positives, evaluates compound exploit chains across six domain guides, and formats deliverables using the standardized report template (`SEC-xxx`, `INF-xxx`, `RES-xxx` with CVSS-aligned Severity and `CWE-ID`):
   - **[OWASP Top 10 & ASVS Code Review](.agents/skills/audit-website-security/references/owasp-code-review.md)**
   - **[Framework-Specific, Runtime Engine, API, WebSocket & AI/LLM Security](.agents/skills/audit-website-security/references/framework-and-ai-security.md)**
   - **[BaaS (Supabase / Firebase), OAuth/MFA, Financial Ledger & Client-Side Security](.agents/skills/audit-website-security/references/baas-auth-and-payment-security.md)**
   - **[Infrastructure, Docker, CI/CD, Reverse Proxy & Supply Chain Security](.agents/skills/audit-website-security/references/infrastructure-cicd-and-supply-chain.md)**
   - **[Server Resilience & DoS Prevention](.agents/skills/audit-website-security/references/resilience-and-rate-limiting.md)**
   - **[Real-World Mass Breach Playbooks, Classic Flaws & High-Impact CVEs](.agents/skills/audit-website-security/references/real-world-breach-playbooks-and-cves.md)**
   - **[CVSS Severity Rubric & 360° Audit Report Templates](.agents/skills/audit-website-security/references/report-templates.md)**
3. **Defensive Hardening & Patching** — Operates in read-only audit mode by default, or applies minimal, production-ready defensive patches (schema validation, DTO serialization filtering, parameterized queries, Supabase RLS policies, atomic database transactions with row locking, proxy-aware rate limiting, non-root Docker configs, safe CI/CD workflow env bindings, and HTTP security headers) when requested.
4. **Multi-Stack Verification & Standardized Reporting** — Runs the target stack's native verification checks (`lint`, `typecheck`, `test`, `build`, `npm audit` / `composer audit` / `pip-audit`) and outputs a comprehensive report in `docs/security-audit/<project>/report.md`.

---

## 360° Audit Coverage

| Security Domain | What Is Inspected in Source Code & Configs |
| :--- | :--- |
| **Access Control, Auth, OAuth & MFA (`A01`, `A07`)** | Missing route/Server Action auth guards (`CWE-862`), IDOR/BOLA (`CWE-639`), mass assignment (`CWE-915`), path traversal (`CWE-22`), CSRF (`CWE-352`), CORS (`CWE-942`), OAuth `state` & unverified email account takeover, MFA step bypass & OTP brute-force (`CWE-287`, `CWE-307`), insecure JWT/cookie flags (`CWE-347`, `CWE-614`) |
| **BaaS, Database RLS & Client Storage** | Missing PostgreSQL / Supabase `ENABLE ROW LEVEL SECURITY` or `USING (true)` policies (`CWE-284`), client-leaked `SUPABASE_SERVICE_ROLE_KEY` / Firebase Admin keys (`CWE-798`), permissive `firestore.rules`, sensitive tokens/PII in `localStorage` (`CWE-922`), insecure `postMessage` (`CWE-346`) |
| **Cryptography & Secrets (`A02`)** | Hardcoded or client-bundled secrets (`NEXT_PUBLIC_` / `VITE_`, `CWE-798`), weak password hashing (`CWE-916`), predictable tokens (`Math.random()`, `CWE-330`), non-constant-time HMAC comparisons (`CWE-208`) |
| **Injection, XSS & SSRF (`A03`, `A10`)** | SQL/NoSQL injection (`CWE-89`, `CWE-943`), Eloquent column-name injection, OS command injection (`CWE-78`), DOM/Stored XSS (`CWE-79`), SSTI (`CWE-1336`), SSRF without private IP blocking (`CWE-918`) |
| **Financial Ledgers, Payments & Concurrency (`A04`)** | Race conditions / TOCTOU on balances, coupons, and inventory (`CWE-362`), negative amount/quantity injection (`CWE-840`), IEEE 754 floating-point currency rounding flaws (`CWE-682`), client-side price tampering (`CWE-602`), unsigned or non-idempotent payment webhooks (`CWE-345`) |
| **Framework, Runtime Engine, GraphQL, WebSocket & AI/LLM** | **PHP Core Engine RCE — `PHP2Shell` (`CVE-2026-109618` & `CVE-2026-109619`, enforcing PHP `>= 8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`) & `php.ini` hardening**, Next.js RSC prop serialization leaks & `'use server'` action exposure, Express `trust proxy` IP spoofing, Prototype Pollution (`CWE-1321`), Laravel Livewire property tampering, FastAPI missing `response_model` & async loop blocking, GraphQL depth/batching DoS, WebSocket CSWSH, LLM Indirect Prompt Injection & Denial of Wallet (`LLM01`–`LLM04`) |
| **Infrastructure, Docker, CI/CD & Supply Chain** | Docker containers running as root (`CWE-250`), secrets baked into `Dockerfile` `ENV`/`ARG` layers (`CWE-522`), missing `.dockerignore`, exposed DB/Redis ports (`CWE-668`), GitHub Actions `${{ ... }}` script injection in `run:` blocks (`CWE-78`), dangerous `pull_request_target` checkouts (`CWE-269`), Nginx/Apache dotfile exposure (`CWE-538`), lockfile & postinstall risks |
| **Real-World Mass Breach Vectors & High-Impact CVEs** | CLI Argument Injection (`--flag` in `spawn`/`execFile`, `CWE-88`), Dynamic `include`/`import()` LFI (`CWE-98`), CRLF & SMTP Mail Header Injection (`CWE-113`), `.htaccess`/`.user.ini` & Double-Extension Webshell Uploads (`CWE-434`), XXE (`CWE-611`), Node.js `Buffer.allocUnsafe` Heap Memory Leaks (`CWE-908`), PHP `phar://` Metadata Deserialization (`CWE-502`), Type Juggling / Magic Hashes (`==`, `CWE-843`), **PHP2Shell (`CVE-2026-109618` / `CVE-2026-109619`)**, **PHP-CGI Unicode RCE (`CVE-2024-4577`)**, **Nginx + PHP-FPM (`CVE-2019-11043`)**, **Laravel Ignition `APP_DEBUG` & `APP_KEY` RCE (`CVE-2021-3129`, `CVE-2018-15133`)**, **Next.js Middleware Bypass (`CVE-2025-29927`) & Server Action SSRF (`CVE-2024-34351`)**, **Magecart `polyfill.io` CDN hijack**, **`vm2` Sandbox Escape (`CVE-2023-37466`)**, **Cloud IMDSv1 SSRF (`169.254.169.254`)**, **Log4Shell (`CVE-2021-44228`)**, and **Native Media Binary RCE (`libwebp` `CVE-2023-4863`, `ImageTragick`, `wkhtmltopdf`)** |
| **Server Resilience & DoS Prevention** | Missing multi-tier rate limiting (`CWE-770`), third-party billing/quota amplification, unbounded DB queries & N+1 loops (`CWE-400`), ReDoS (`CWE-1333`), decompression/pixel bombs (`CWE-409`), event-loop blocking, missing outbound `fetch` timeouts, DB connection pool exhaustion |

---

## Supported Platforms

| Agent | Status |
| :--- | :--- |
| **Antigravity** | Supported (via `.agents/skills/` or `~/.gemini/config/skills/`) |
| **Claude Code** | Supported (via `.claude/commands/audit-website-security.md` & `CLAUDE.md`) |
| **Cursor** | Supported (via `.agents/skills/` & `AGENTS.md`) |
| **Codex CLI** | Supported (via `.agents/skills/` & `AGENTS.md`) |
| **OpenCode** | Supported (via `.agents/skills/` & `AGENTS.md`) |

---

## Project Structure

```text
docs/
  security-audit/
    <project>/
      surface-map.md      # 360° threat model & inventory of routes, auth, BaaS/RLS, and infra
      report.md           # Full CWE/CVSS vulnerability, infra & resilience audit report with patches
.agents/
  skills/
    audit-website-security/
      SKILL.md            # Canonical 4-stage defensive audit, taint-tracing & hardening workflow
      scripts/
        audit-recon.mjs   # Read-only static sink & runtime CVE scanner (PHP2Shell, Next.js, OWASP sinks)
      references/
        owasp-code-review.md                   # Complete OWASP Top 10 (A01–A10), API Top 10, ASVS & CWE checklist
        framework-and-ai-security.md           # Next.js, Node, PHP/Laravel (PHP2Shell), Python, GraphQL, WebSocket & LLM
        baas-auth-and-payment-security.md      # Supabase RLS, Firebase, OAuth2/MFA, payment ledgers & client DOM
        infrastructure-cicd-and-supply-chain.md # Docker, GitHub Actions CI/CD, Nginx/Cache Poisoning & supply chain
        resilience-and-rate-limiting.md        # Server lag/DoS prevention, ReDoS & DB pool hardening
        real-world-breach-playbooks-and-cves.md # Real-world mass breach vectors, classic flaws & high-impact CVEs
        report-templates.md                    # CVSS severity rubric & templates for surface-map.md & report.md
.claude/
  commands/
    audit-website-security.md                  # Thin Claude Code invocation bridge
AGENTS.md                 # Agent instructions (single source of truth)
CLAUDE.md                 # Claude Code config (imports AGENTS.md)
README.md                 # Project overview & 360° coverage documentation
```

---

## Scope & Safety Notice

- **Defensive Static Source Code & Configuration Analysis Only** — This template is strictly designed for auditing local source code and infrastructure configs you own or are authorized to review, and applying defensive patches.
- **No Offensive Exploitation or Live Traffic Flooding** — This skill never generates weaponized exploit payloads or sends automated stress/DoS traffic against live servers.
