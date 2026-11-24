<div align="center">

# AI Security & Resilience Audit Template

### Audit and harden your web application source code with one command

Give your AI coding agent a local project folder and watch it map your attack surface, inspect source code for OWASP Top 10 vulnerabilities and server resilience bottlenecks, apply defensive patches, and generate a complete audit report.

**Works with Antigravity, Claude Code, Codex, Cursor, and OpenCode.**

[![Use this template](https://img.shields.io/badge/Use_this_template-Create_your_copy-2ea44f?style=for-the-badge&logo=github&logoColor=white)](https://github.com/cescrafli/ai-security-audit-template/generate)

[How It Works](#how-it-works) · [Supported Platforms](#supported-platforms) · [Project Structure](#project-structure)

</div>

---

## How It Works

The `audit-website-security` skill follows four structured stages:

1. **Map the Architecture & Entry Points** — Inventories all public/authenticated routes, controllers, Server Actions, middleware guards, database queries, file uploads, and external API calls into `docs/security-audit/<project>/surface-map.md`.
2. **Audit Source Code for Vulnerabilities & Bottlenecks** — Inspects the mapped source files against two reference guides:
   - **[OWASP Code Review](.agents/skills/audit-website-security/references/owasp-code-review.md)**: Broken Access Control, IDOR, SQL/NoSQL Injection, XSS, SSRF, hardcoded secrets, insecure cookies/JWTs, CORS misconfiguration, and missing HTTP security headers.
   - **[Resilience & Rate Limiting](.agents/skills/audit-website-security/references/resilience-and-rate-limiting.md)**: Unthrottled endpoints (missing rate limiting), unbounded database queries (`SELECT` without `LIMIT`), N+1 query loops, missing payload/upload size limits, synchronous event-loop blocking, and missing outbound `fetch` timeouts.
3. **Apply Defensive Hardening** — Implements minimal, production-ready defensive code fixes (input validation, parameterized queries, ownership checks, rate-limiting middleware, query pagination caps, and security headers) when requested.
4. **Verify & Deliver Report** — Runs the target project's build/lint/typecheck checks and produces a structured report in `docs/security-audit/<project>/report.md` with severity ratings (`Critical`, `High`, `Medium`, `Low`), exact file/line references, and remediation code snippets.

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
      surface-map.md      # Inventory of routes, auth boundaries, and data sinks
      report.md           # Full vulnerability & resilience audit report with patches
.agents/
  skills/
    audit-website-security/
      SKILL.md            # Canonical 4-stage defensive audit & hardening workflow
      references/
        owasp-code-review.md            # OWASP Top 10 static source code checklist
        resilience-and-rate-limiting.md # Server lag/DoS prevention & query hardening guide
.claude/
  commands/
    audit-website-security.md           # Thin Claude Code invocation bridge
AGENTS.md                 # Agent instructions (single source of truth)
CLAUDE.md                 # Claude Code config (imports AGENTS.md)
README.md                 # Documentation & usage guide
```

---

## Scope & Safety Notice

- **Defensive Static Source Code Analysis Only** — This template is strictly designed for auditing local source code you own or are authorized to review, and applying defensive code patches.
- **No Offensive Exploitation or Live Traffic Flooding** — This skill never generates weaponized exploit payloads or sends automated stress/DoS traffic against live servers.
