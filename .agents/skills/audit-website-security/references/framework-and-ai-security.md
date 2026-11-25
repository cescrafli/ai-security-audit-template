# Framework-Specific, API, WebSocket & AI/LLM Security Guide

Generic OWASP checklists often miss framework-specific security pitfalls. Use this reference during Stage 2 to audit the target codebase according to its actual technology stack and modern architectural patterns.

---

## 1. Next.js (App Router & Pages Router) & React

- **Server Actions (`'use server'`) Exposure (`CWE-862`, `CWE-20`)**:
  - Every exported function in a `'use server'` file is compiled into a public HTTP `POST` endpoint invokable by any client with arbitrary JSON arguments.
  - Verify **every single exported Server Action** independently authenticates the session (`auth()` / `getServerSession()`), checks authorization, and validates all arguments with a strict schema (`zod`) before touching the database.
- **React Server Components (RSC) Serialization Leaks (`CWE-200`)**:
  - When a Server Component passes props to a Client Component (`'use client'`), the entire prop object is serialized into the HTML/RSC payload sent to the browser.
  - Flag passing full ORM user/account objects (`<UserProfile user={dbUser} />`) without stripping sensitive fields (`passwordHash`, `twoFactorSecret`, `stripeCustomerId`, `internalNotes`) via a Data Transfer Object (DTO) or Prisma `select`/`omit`.
- **Middleware (`middleware.ts`) Pitfalls & `CVE-2025-29927` (`CWE-285`, `CWE-287`)**:
  - Verify Next.js is patched against **`CVE-2025-29927`** (critical Next.js middleware authorization bypass via forged `x-middleware-subrequest` header; requires Next.js `>= 15.2.3`, `>= 14.2.25`, `>= 13.5.9`, or `>= 12.3.5`, or stripping `x-middleware-subrequest` at the reverse proxy).
  - Do not rely solely on `middleware.ts` for authorization; follow a **Data Access Layer (DAL)** pattern where data-fetching helpers enforce auth at the point of query.
  - Inspect `export const config = { matcher: [...] }` for regex flaws that exclude `/api/...` routes or dynamic segments.
- **`next/image` SSRF & Image Optimizer DoS (`CWE-918`, `CWE-400`)**:
  - Inspect `next.config.js` / `next.config.ts` `images.remotePatterns`. Flag wildcard hostnames (`hostname: '**'`) which allow attackers to force the Next.js server to fetch and resize arbitrary external images.
- **Environment Variable Leaks (`CWE-200`)**:
  - Ensure no server secret uses the `NEXT_PUBLIC_` prefix and verify server-only modules import `'server-only'` to prevent accidental client bundling.

---

## 2. Node.js, Express, NestJS & Prisma / MongoDB

- **Reverse Proxy & `X-Forwarded-For` IP Spoofing (`CWE-290`, `CWE-770`)**:
  - If rate limiting relies on `req.ip` or `req.headers['x-forwarded-for']`, verify `app.set('trust proxy', ...)` is accurately configured for the actual deployment proxy hop count. Without this, attackers can spoof `X-Forwarded-For` on every request to completely bypass IP-based rate limiting.
- **Prototype Pollution (`CWE-1321`)**:
  - Flag recursive object merge, clone, or path-assignment utilities that process user JSON without blocking `__proto__`, `constructor`, and `prototype` keys.
- **ORM Data Over-Exposure & Raw Queries (`CWE-200`, `CWE-89`)**:
  - In Prisma/TypeORM/Sequelize, flag returning the result of `findUnique`/`findMany`/`create`/`update` directly in `res.json()` when the model contains sensitive columns.
  - Flag `$queryRawUnsafe`, `$executeRawUnsafe`, and Sequelize `sequelize.query()` with template literals.
- **Unhandled Promise Rejections & Process Crashes (`CWE-755`)**:
  - In Express 4, async route handlers (`app.get('/x', async (req, res) => ...)`) that throw an uncaught error without `try/catch` or an async wrapper can crash the Node.js process.

---

## 3. PHP, Laravel & WordPress (Application & Core Engine Security)

- **PHP Core Engine & Runtime RCE — "PHP2Shell" (`CVE-2026-109618`, `CVE-2026-109619`) & CGI (`CVE-2024-4577`)**:
  - Core PHP engine vulnerabilities in memory management and error handling (`PHP2Shell`: `CVE-2026-109618` and `CVE-2026-109619`) allow **unauthenticated Remote Code Execution (RCE)** across PHP 5 through PHP 8—even when the application's own PHP source code has zero flaws.
  - Inspect `Dockerfile` (`FROM php:...`), `docker-compose.yml`, `.github/workflows/*.yml`, `composer.json` (`require.php`), `composer.lock`, and the local/server runtime (`php -v`).
  - **Mandatory Minimum Patched PHP Versions** (flag any lower version or EOL branch as **Critical / CVSS 9.8–10.0**):
    - **PHP 8.5.x**: Must be **`>= 8.5.12`**
    - **PHP 8.4.x**: Must be **`>= 8.4.27`**
    - **PHP 8.3.x**: Must be **`>= 8.3.36`**
    - **PHP 8.2.x**: Must be **`>= 8.2.35`**
    - **PHP <= 8.1.x, 7.x, 5.x**: Unsupported / End-of-Life and critically vulnerable to `PHP2Shell`; require immediate upgrade to a patched branch.
  - **PHP Runtime & `php.ini` Hardening**:
    - Enforce `expose_php = Off` (removes `X-Powered-By: PHP/x.y.z` header to prevent automated botnet fingerprinting).
    - Enforce `display_errors = Off`, `display_startup_errors = Off`, and `log_errors = On` in production to avoid triggering verbose error-handling paths or leaking internal memory/stack state.
    - Enforce `allow_url_include = Off` and disable dangerous OS execution primitives via `disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec` unless explicitly required.
- **Eloquent Column-Name SQL Injection (`CWE-89`)**:
  - Laravel parameterizes query *values*, NOT column names or sort directions. Flag `->where($request->input('field'), $val)` or `->orderBy($request->input('sort'), $request->input('dir'))` without strict `in_array()` allowlist validation.
  - Flag `DB::raw()`, `whereRaw()`, `selectRaw()`, `orderByRaw()`, and `havingRaw()` with string concatenation/interpolation.
- **Mass Assignment (`CWE-915`)**:
  - Flag Models with `protected $guarded = [];` combined with `Model::create($request->all())` or `$model->update($request->all())`. Require `$request->validated()` or explicit `$request->only([...])`.
- **Blade XSS & Livewire Property Tampering (`CWE-79`, `CWE-639`)**:
  - Flag `{!! $data !!}` in `.blade.php` files unless `$data` has been purified with an allowlist HTML sanitizer.
  - In Livewire components, public properties are serialized to the browser and can be modified by the client between requests. Ensure model IDs or sensitive state properties use the `#[Locked]` attribute (Livewire v3) or re-verify ownership inside action methods.
- **Configuration & Storage Exposure (`CWE-200`, `CWE-434`)**:
  - Verify `APP_DEBUG=false` in production templates, `.env` and `storage/logs/laravel.log` are inaccessible from `public/`, and file uploads use `$file->hashName()` + strict MIME/magic-byte validation (`mimes:jpg,png,pdf|max:2048`) rather than `$file->getClientOriginalName()`.

---

## 4. Python (FastAPI, Django, Flask)

- **FastAPI Response Model Leaks & Async Event-Loop Blocking (`CWE-200`, `CWE-400`)**:
  - Flag FastAPI endpoints that return SQLAlchemy/ORM models directly without a strict Pydantic `response_model` (which strips password hashes and internal fields).
  - Flag `async def` FastAPI routes that call synchronous blocking libraries (`requests.get`, synchronous `psycopg2`/SQLAlchemy session, `time.sleep`, CPU-bound work), which freeze the entire Uvicorn event loop for all concurrent users.
- **Django Security Pitfalls (`CWE-89`, `CWE-79`, `CWE-352`)**:
  - Flag `Model.objects.raw()`, `.extra()`, `cursor.execute(f"...")`, `mark_safe()`, `format_html()` with unescaped format strings, unnecessary `@csrf_exempt`, and `ALLOWED_HOSTS = ['*']`.
- **Unsafe Deserialization & SSTI (`CWE-502`, `CWE-1336`)**:
  - Flag `pickle.loads`, `yaml.load` (without `SafeLoader`), and `render_template_string(user_input)` (Server-Side Template Injection in Jinja2).

---

## 5. GraphQL, WebSockets & Multi-Tenant SaaS

- **GraphQL Introspection, Batching & Depth DoS (`CWE-400`, `CWE-200`)**:
  - Verify production GraphQL servers disable introspection (unless public by design), enforce **query depth limits** (<= 7–10), **query cost/complexity limits**, and **batch/alias limits** (blocks sending 1000 aliased mutations or login attempts in a single HTTP request to bypass rate limiting).
  - Verify field-level authorization inside nested resolvers (e.g., `user.orders.invoice`) and DataLoader usage to prevent N+1 query explosions.
- **WebSockets / Socket.io Security (`CWE-346`, `CWE-400`)**:
  - Verify WebSocket handshake checks the `Origin` header (prevents Cross-Site WebSocket Hijacking / CSWSH), authenticates the connection token during handshake, re-validates authorization on every incoming message event, and enforces maximum message payload size and per-socket event rate limits.

---

## 6. AI / LLM Integration Security (OWASP LLM Top 10)

When the audited application integrates OpenAI, Anthropic, Gemini, or local LLMs:
- **Indirect Prompt Injection & Unauthorized Tool Execution (`LLM01`, `LLM07`)**:
  - If an LLM agent has access to tools/functions (database queries, email sending, webhook calls), verify tool execution requires explicit server-side user authorization and never relies on the LLM to enforce tenant isolation (`userId` must be injected by backend session code, never chosen by the LLM prompt!).
- **Insecure Output Handling / LLM-to-XSS (`LLM02`, `CWE-79`)**:
  - Flag rendering LLM-generated Markdown or HTML without sanitization (`rehype-sanitize`, `DOMPurify`), or executing LLM-generated SQL/code without a sandboxed read-only role.
- **Unbounded Consumption / Denial of Wallet (`LLM04`, `CWE-770`)**:
  - Verify LLM endpoints enforce strict authentication, per-user token/request quotas, prompt character length caps, and `max_tokens` limits so attackers cannot drain API billing credits.
