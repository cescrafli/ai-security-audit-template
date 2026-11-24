---
name: audit-website-security
description: Perform a defensive static source code security audit and resilience review on a local web application codebase. Use when auditing local source code for OWASP vulnerabilities, missing rate limiting, resource exhaustion risks, insecure headers, and applying defensive code patches.
---

# Audit and harden website source code

Perform a defensive security and resilience audit on the local source code supplied by the user. Operate strictly on local code, configuration files, and package manifests—never generate live attack payloads, exploit scripts, or traffic floods against running servers.

## 1. Map the architecture and entry points

Read project configuration (`package.json`, framework config, environment templates, middleware, and route directories). Identify the tech stack, deployment target, authentication flow, and data storage layer.

Record an inventory of exposed surfaces in `docs/security-audit/<project>/surface-map.md`:
- **Public & authenticated API routes / Server Actions / Controllers**
- **Authentication & session boundaries** (JWT, cookies, OAuth callbacks, middleware guards)
- **Database queries, file uploads, and external webhooks/fetch calls**
- **Resource-intensive endpoints** (search, unpaginated lists, file processing, AI/LLM endpoints, email/SMS triggers)

Finish this stage when every public route, middleware boundary, and data sink has been mapped to specific source files.

## 2. Audit source code for vulnerabilities and bottlenecks

Inspect the mapped files systematically. For each finding, record the exact file path, line numbers, root cause, severity (`Critical`, `High`, `Medium`, `Low`), and defensive remediation plan.

Read [the OWASP code review reference](references/owasp-code-review.md) to check for application vulnerabilities:
- **Broken Access Control & Auth**: Missing session checks, IDOR (Insecure Direct Object References), privilege escalation, weak cookie flags (`HttpOnly`, `Secure`, `SameSite`).
- **Injection & XSS**: Raw SQL/NoSQL string concatenation, `dangerouslySetInnerHTML` without sanitization, command execution, SSRF via unvalidated URLs.
- **Secrets & Configuration**: Hardcoded API keys/tokens, exposed `.env` variables in client bundles (`NEXT_PUBLIC_`, `VITE_`), permissive CORS (`*` with credentials), missing security headers (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`).

Read [the resilience and rate-limiting reference](references/resilience-and-rate-limiting.md) to check why a server might lag or fail under load:
- **Missing Rate Limiting**: Unthrottled login, signup, password reset, search, or expensive API endpoints.
- **Unbounded Queries & Payloads**: Database queries without `LIMIT`/pagination, N+1 query loops, missing request body size limits, synchronous heavy computation blocking the event loop.
- **Missing Timeouts & Circuit Breakers**: Outbound `fetch`/database calls without `AbortSignal.timeout()` or connection pool limits.

## 3. Apply defensive hardening (when requested)

When the user asks to fix or harden the codebase, implement clean, minimal defensive patches:
- Add schema validation (e.g., `zod`) and strict payload size limits on all untrusted inputs.
- Parameterize queries and enforce ownership checks (`userId`) on data reads/mutations.
- Add rate-limiting middleware, pagination bounds, caching headers, and outbound request timeouts.
- Configure standard HTTP security headers in the framework config or middleware.

Preserve existing business logic and route signatures unless a breaking change is required to close a security flaw (disclose any breaking change clearly).

## 4. Verify and deliver the audit report

Run the project's static verification commands (`npm run lint`, `npm run typecheck`, `npm test`, `npm run build`) to ensure defensive patches compile cleanly and do not break existing functionality.

Deliver a structured report in `docs/security-audit/<project>/report.md` containing:
1. **Executive Summary**: Tech stack, scope audited, and finding counts by severity.
2. **Vulnerability & Resilience Findings**: File/line references, explanation of the flaw in code, and defensive fix code snippet.
3. **Hardening Checklist**: Status of security headers, rate limiting, input validation, dependency audit (`npm audit`), and query timeouts.
