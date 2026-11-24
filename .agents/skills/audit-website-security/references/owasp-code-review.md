# OWASP Static Source Code Review Guide

Use this checklist when inspecting local application source code for security flaws. Always cite exact file paths and line ranges.

## 1. Access Control & Authentication (OWASP A01 / A07)

- **Route & Action Guards**: Verify every protected API route, controller, or Server Action checks authentication *inside* the handler, not just in UI components or client-side redirects.
- **Object-Level Authorization (IDOR)**: When a route accepts an ID (`params.id`, `req.body.accountId`), verify the database query scopes the lookup or update by the authenticated user/tenant (e.g., `WHERE id = $1 AND owner_id = $2`).
- **Session & Cookie Security**:
  - Check cookie attributes: `httpOnly: true`, `secure: true`, `sameSite: 'lax'` or `'strict'`.
  - Verify JWT verification checks algorithm (`alg`) explicitly and uses a strong secret from environment variables, never a hardcoded fallback (`process.env.JWT_SECRET || 'secret'`).

## 2. Injection, XSS & SSRF (OWASP A03 / A10)

- **SQL / NoSQL Injection**:
  - Flag string interpolation in SQL (`SELECT * FROM users WHERE email = '${email}'`, `$queryRawUnsafe`).
  - Flag unsanitized object keys in NoSQL filters (e.g., MongoDB `$where`, `$gt`, `$ne` passed directly from `req.body`).
- **Cross-Site Scripting (XSS)**:
  - Flag `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, or `document.write` fed by user-controlled data without a strict sanitizer (e.g., `DOMPurify`).
  - Flag unvalidated `href` or `src` attributes that could accept `javascript:` or `data:` URLs.
- **Server-Side Request Forgery (SSRF)**:
  - If the server fetches a user-supplied URL (webhooks, image proxies, link previews), ensure it validates the protocol (`https:`), checks against an allowlist or blocks private/loopback IP ranges (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`, `localhost`).

## 3. Secrets, Headers & Misconfiguration (OWASP A02 / A05)

- **Client-Exposed Secrets**:
  - Search for secrets or private keys committed in code or exposed via client-bundled prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`).
- **CORS Policy**:
  - Flag `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, or dynamic origin reflection without an explicit origin allowlist.
- **HTTP Security Headers**:
  - Check framework configuration (`next.config.ts`, `helmet`, Nginx/Vercel config) for:
    - `Content-Security-Policy`
    - `Strict-Transport-Security` (`max-age=63072000; includeSubDomains; preload`)
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY` or `frame-ancestors 'none'`
    - `Referrer-Policy: strict-origin-when-cross-origin`
