# Server Resilience, Performance Bottleneck & DoS Protection Guide

Use this reference during Stage 2 to identify why a web server, database, or worker process could lag, run out of memory (OOM), exhaust connection pools, or crash under heavy load—by analyzing the application's source code and architecture.

---

## 1. Rate Limiting & Cost-Amplification Controls (`CWE-770`, `CWE-799`)

- **Unthrottled High-Risk Endpoints**:
  - Inspect authentication (`/login`, `/register`, `/forgot-password`, `/verify-otp`), search/autocomplete, file uploads, comment/form submissions, and webhook endpoints.
  - Verify multi-tiered rate limiting:
    1. **Strict tier** (e.g., 5–10 req/min per IP + account identifier) for auth, OTP, and password reset.
    2. **Resource tier** (e.g., 20–30 req/min per user/IP) for expensive writes, uploads, PDF generation, and AI/LLM endpoints.
    3. **General API tier** (e.g., 100–300 req/min) for standard reads.
- **Fail-Fast Rejection**:
  - Ensure rate limiting executes *before* database queries, session lookups, or expensive payload parsing, returning `429 Too Many Requests` with a `Retry-After` header.
- **Third-Party & Billing Amplification (Wallet / Quota Exhaustion)**:
  - Flag endpoints that trigger paid external APIs (SMS/WhatsApp OTPs, OpenAI/Anthropic calls, email dispatches, geocoding) without strict per-user daily quotas, CAPTCHA/proof-of-work gates, or debouncing.

---

## 2. Database & Memory Exhaustion Risks (`CWE-400`, `CWE-770`)

- **Unbounded Queries & Missing Pagination**:
  - Flag `findMany()`, `SELECT *`, `Model::all()`, or `QuerySet.all()` without a hard `take`/`LIMIT` clause.
  - Flag pagination logic that trusts client-provided `limit` or `pageSize` without an upper bound (e.g., `?limit=1000000`). Enforce `const take = Math.min(Math.max(Number(limit) || 20, 1), 100)`.
  - Flag deep `OFFSET` pagination on large tables; recommend cursor-based pagination for high-traffic feeds.
- **N+1 Query Loops**:
  - Flag `await db.query(...)` or ORM lazy-loading inside `for`, `for...of`, or `Promise.all(items.map(...))` loops. Replace with batch queries (`WHERE id IN (...)`), `include`/`with` eager loading, or DataLoader batching.
- **Missing Database Indexes & Full Table Scans**:
  - Cross-check ORM queries (`WHERE`, `ORDER BY`, foreign keys, soft-delete `deleted_at` filters) against `schema.prisma`, Drizzle schemas, or SQL migrations. Flag unindexed columns queried on hot paths and unindexed `LIKE '%term%'` wildcard searches on large tables.
- **Unbounded In-Memory State & Memory Leaks**:
  - Flag module-level `Map`, `Set`, or `Array` caches that grow indefinitely without a max-size LRU eviction policy or TTL cleanup.
  - Flag unremoved `EventEmitter` listeners, unclosed WebSocket subscriptions, or `setInterval` timers created inside per-request handlers.

---

## 3. CPU, Event-Loop & Worker Thread Starvation (`CWE-1333`, `CWE-400`)

- **Regular Expression Denial of Service — ReDoS (`CWE-1333`)**:
  - Inspect custom regexes applied to user input (emails, URLs, slugs, markdown parsers). Flag nested quantifiers like `(a+)+`, `([a-zA-Z0-9]+)*`, or overlapping alternations without input length caps (`input.length <= 255`).
- **Synchronous Event-Loop Blocking**:
  - In Node.js/async runtimes, flag synchronous operations inside request handlers: `fs.readFileSync`, `crypto.pbkdf2Sync`, `bcrypt.hashSync`, `zlib.gzipSync`, or `JSON.parse`/`JSON.stringify` on multi-megabyte objects.
- **Payload, Upload & Decompression Bombs (`CWE-409`)**:
  - Verify body parsers enforce strict byte limits (e.g., `100kb`–`1mb` for JSON APIs) and reject deeply nested JSON/GraphQL queries (enforce max depth <= 7–10 and query cost complexity limits).
  - Verify file upload handlers stream files or enforce strict size caps before buffering into RAM.
  - When processing images (`sharp`, `GD`, `Pillow`) or archives (`.zip`, `.tar.gz`), verify code checks max pixel dimensions (e.g., `<= 4096x4096`) and max uncompressed byte size to prevent decompression bombs.

---

## 4. Cascading Failures, Timeouts & Connection Pools (`CWE-400`)

- **Missing Outbound Timeouts**:
  - Flag every `fetch()`, `axios()`, `curl_exec()`, or `requests.get()` call that lacks an explicit timeout (e.g., `signal: AbortSignal.timeout(5000)`). A slow upstream dependency without a timeout will hang worker threads and take the entire server down.
- **Database Connection Pool Exhaustion**:
  - In serverless/Next.js environments, verify Prisma/database clients use the `globalThis` singleton pattern in development and bounded pool sizes (`connection_limit`, PgBouncer) in production.
  - Verify long-running external API calls (`fetch` to LLM or payment gateway) are **never** executed *inside* an open database transaction (`prisma.$transaction`), which holds database locks and exhausts the connection pool.
- **Synchronous Heavy Work in Request Cycle**:
  - Flag request handlers that synchronously send multiple emails, generate PDFs, process video, or scrape URLs before returning an HTTP response. Recommend offloading to an asynchronous job queue with bounded worker concurrency.

---

## Reference Defensive Code Blueprints (Stage 3 Patching)

### 1. Bounded Pagination & Timeout-Guarded External Fetch Outside DB Transactions
```ts
export async function listOrdersAndSyncStatus(reqUrl: URL, userId: string) {
  // 1. Hard pagination cap (prevents unbounded SELECT memory exhaustion)
  const rawLimit = Number(reqUrl.searchParams.get('limit')) || 20;
  const take = Math.min(Math.max(rawLimit, 1), 100);
  const cursorId = reqUrl.searchParams.get('cursor') || undefined;

  // 2. Perform external HTTP calls OUTSIDE database transactions with strict timeout
  const gatewayRes = await fetch('https://api.payment.example/v1/status', {
    signal: AbortSignal.timeout(4000),
    headers: { Accept: 'application/json' },
  });
  const gatewayData = gatewayRes.ok ? await gatewayRes.json() : null;

  // 3. Bounded indexed query scoped to authenticated user
  const orders = await db.order.findMany({
    where: { userId },
    take,
    ...(cursorId ? { skip: 1, cursor: { id: cursorId } } : {}),
    orderBy: { createdAt: 'desc' },
    select: { id: true, totalCents: true, status: true, createdAt: true },
  });

  return { orders, gatewayStatus: gatewayData?.status ?? 'unknown' };
}
```
