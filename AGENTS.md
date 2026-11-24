# Website Security & Resilience Audit Template

## What This Is
A reusable defensive workspace template for auditing your web application's local source code for security vulnerabilities (OWASP Top 10) and server performance/resilience bottlenecks (missing rate limits, unbounded queries, memory leaks, missing timeouts) using AI coding agents.

## Scope & Safety Principles
- **Defensive Static Source Code Review Only** — all analysis operates strictly on local source code, configuration files, and dependency manifests.
- **No Offensive Payloads or Live Traffic Flooding** — never generate functional exploit payloads or send automated load/DoS traffic against live servers.
- **Actionable Patching** — every finding includes exact file/line references, root-cause analysis, and production-ready defensive code fixes.

## Project Structure
```text
docs/
  security-audit/
    <project>/
      surface-map.md     # Inventory of routes, auth boundaries, and data sinks
      report.md          # Full vulnerability & resilience audit report with patches
.agents/
  skills/
    audit-website-security/
      SKILL.md           # Canonical 4-stage defensive audit & hardening workflow
      references/
        owasp-code-review.md            # OWASP Top 10 source code checklist
        resilience-and-rate-limiting.md # Server lag/DoS prevention & query hardening guide
.claude/
  commands/
    audit-website-security.md # Thin command invocation bridge
```

## Agent Workflow
- Use `.agents/skills/audit-website-security/SKILL.md` when the user provides a local project folder or source code to audit and harden.
- Save audit outputs under `docs/security-audit/<project>/`.
