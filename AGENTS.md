# Website Security & Resilience Audit Template

## What This Is
A reusable, enterprise-grade 360° defensive workspace template for auditing software and web application codebases across all security domains:
1. **Application Security (OWASP Top 10 A01–A10, ASVS & CWE)**
2. **Framework, API, GraphQL, WebSocket & AI/LLM Security (OWASP LLM Top 10)**
3. **BaaS (Supabase RLS / Firebase Rules), OAuth2/MFA, Financial Ledgers & Client-Side DOM/Storage Security**
4. **Infrastructure, Docker/Containers, CI/CD Pipelines (GitHub Actions), Reverse Proxy & Supply Chain Security**
5. **Server Resilience, Performance Bottlenecks & DoS/Resource-Exhaustion Prevention**

## Scope & Safety Principles
- **Defensive Static Source Code & Config Review Only** — all analysis operates strictly on local source code, database migrations, container/CI-CD manifests, configuration files, and dependency lockfiles.
- **No Offensive Payloads or Live Traffic Flooding** — never generate functional exploit payloads or send automated load/DoS traffic against live servers.
- **Source-to-Sink Taint Verification** — every candidate issue is traced from untrusted input source through guards/validators/RLS policies to the sensitive sink to eliminate false positives before reporting.
- **Standardized CWE & CVSS Classification** — every finding is tagged with an ID (`SEC-xxx`, `INF-xxx`, `RES-xxx`), CVSS-aligned Severity, Security Domain, and `CWE-ID`, with exact file/line references and production-ready defensive patches.

## Supported Application & Infrastructure Stacks
- **JavaScript / TypeScript**: Next.js (App Router, Server Actions, RSC, API Routes), React, Node.js, Express, NestJS, Prisma, Drizzle, GraphQL, Socket.io
- **PHP**: Laravel, Symfony, Native PHP, Eloquent, Blade, Livewire
- **Python**: FastAPI, Django, Flask, SQLAlchemy, Pydantic
- **BaaS, Databases & Payments**: PostgreSQL, Supabase (RLS), Firebase (Firestore/Storage Rules), MongoDB, Redis, Stripe, Midtrans, Xendit
- **AI / LLM & Infrastructure**: OpenAI/Anthropic/Gemini integrations, Docker, Docker Compose, GitHub Actions, GitLab CI, Nginx, Apache

## Project Structure
```text
docs/
  security-audit/
    <project>/
      surface-map.md     # 360° threat model & inventory of routes, auth, BaaS/RLS, and infra
      report.md          # Standardized CWE/CVSS vulnerability, infra & resilience audit report
.agents/
  skills/
    audit-website-security/
      SKILL.md           # Canonical 4-stage defensive audit, taint-tracing & hardening workflow
      scripts/
        audit-recon.mjs  # Read-only static sink & runtime CVE scanner (PHP2Shell, Next.js, OWASP sinks)
      references/
        owasp-code-review.md                   # OWASP Top 10 (A01–A10), API Top 10, ASVS & CWE checklist
        framework-and-ai-security.md           # Next.js, Node, PHP/Laravel (PHP2Shell), Python, GraphQL, WebSocket & LLM
        baas-auth-and-payment-security.md      # Supabase RLS, Firebase, OAuth2/MFA, payment ledgers & client DOM
        infrastructure-cicd-and-supply-chain.md # Docker, GitHub Actions CI/CD, Nginx/Cache Poisoning & supply chain
        resilience-and-rate-limiting.md        # Server lag/DoS prevention, ReDoS, memory & DB pool hardening
        real-world-breach-playbooks-and-cves.md # Real-world mass breach vectors, classic flaws & high-impact CVEs
        report-templates.md                    # CVSS severity rubric & Markdown templates for deliverables
.claude/
  commands/
    audit-website-security.md # Thin command invocation bridge
```

## Agent Workflow
- Read `.agents/skills/audit-website-security/SKILL.md` and its linked references in `.agents/skills/audit-website-security/references/` when auditing or hardening a local codebase.
- Default to **Read-Only Audit Mode (`readonly`)** unless the user explicitly passes `patch` or asks to apply defensive fixes to the target project.
- Save audit deliverables (`surface-map.md` and `report.md`) under `docs/security-audit/<project>/` following `references/report-templates.md` (git-ignored by default so private vulnerability reports are never accidentally committed).
