# Server Resilience & DoS Protection Code Review

Use this guide to identify why a web server or API might lag, run out of memory, or go down under heavy traffic—solely by inspecting the application's source code and architecture.

## 1. Rate Limiting & Abuse Prevention

- **High-Risk Endpoints**: Check whether authentication (`/login`, `/register`, `/otp`), password reset, file upload, search, and AI/third-party billing routes enforce per-IP and per-user rate limits.
- **Defensive Pattern**:
  - Use token-bucket or sliding-window rate limiting middleware (e.g., Redis/Upstash ratelimit, `express-rate-limit`, or edge WAF rules).
  - Return HTTP `429 Too Many Requests` with a `Retry-After` header before executing database or CPU-heavy work.

## 2. Database & Memory Exhaustion Risks

- **Unbounded Queries**:
  - Flag `findMany()`, `SELECT *`, or collection scans that lack a hard `take`/`LIMIT` cap, or allow the client to pass an arbitrarily large `limit` query parameter (`?limit=999999`).
  - Enforce a strict maximum page size in code: `Math.min(Number(req.query.limit) || 20, 100)`.
- **N+1 Query Loops**:
  - Flag `await db.query(...)` inside `for` / `.map()` loops. Replace with batch queries (`WHERE id IN (...)`) or relation joins.
- **Missing Indexes**:
  - Check Prisma/Drizzle/SQL schemas for fields frequently used in `WHERE`, `ORDER BY`, or foreign-key joins that lack database indexes.
- **Payload & Upload Size Limits**:
  - Verify JSON body parsers and multipart file upload handlers enforce strict maximum byte sizes and validate MIME types before buffering files into RAM.

## 3. Event Loop Blocking & External Timeouts

- **Synchronous CPU Blocking**:
  - Flag synchronous file/crypto/compression calls (`fs.readFileSync`, `pbkdf2Sync`, ` zlib.gzipSync`) or catastrophic regex backtracking (ReDoS) inside request handlers.
- **Missing Outbound Timeouts**:
  - Flag `fetch()` or HTTP client calls to external APIs that do not specify `signal: AbortSignal.timeout(5000)`. Hanging upstream services can exhaust server worker pools.
- **Database Connection Pooling**:
  - In serverless or containerized environments, verify the database client uses a singleton pattern and bounded connection pool settings so concurrent requests do not exhaust database connections.
