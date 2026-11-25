# OWASP Top 10 & ASVS Static Source Code Review Guide

Use this reference during Stage 2 to perform an in-depth static security audit of local application source code. Cite exact file paths, line ranges, CWE IDs, and OWASP categories for every finding.

---

## A01: Broken Access Control & API Authorization (`CWE-284`, `CWE-639`, `CWE-352`, `CWE-22`, `API1`, `API3`, `API5`)

- **Missing Server-Side Auth Guards & BFLA (`CWE-862`, `API5`)**:
  - Verify every protected API route, controller, GraphQL resolver, and **Next.js Server Action (`'use server'`)** validates the session and role *inside* the function body. Client-side route guards or UI hiding provide zero security.
  - Check middleware matcher patterns (e.g., Next.js `config.matcher`) to ensure API routes or dynamic segments aren't accidentally excluded.
- **Insecure Direct Object References / BOLA (`CWE-639`, `API1`)**:
  - Whenever an endpoint reads, updates, or deletes a record by ID (`req.params.id`, `req.body.orderId`), verify the database query filters by the authenticated user or organization (`WHERE id = $1 AND user_id = $2`).
- **Broken Object Property Level Authorization — Mass Assignment & Excessive Data Exposure (`CWE-915`, `CWE-200`, `API3`)**:
  - Flag passing raw `req.body` or `$request->all()` directly into ORM create/update calls (`prisma.user.update({ data: req.body })`, `User::create($request->all())`).
  - Ensure sensitive fields (`role`, `isAdmin`, `balance`, `emailVerified`, `tenantId`) are excluded via allowlisted DTOs/schemas (`zod`, Laravel `$fillable`), and strip internal columns (`passwordHash`, `resetToken`, `twoFactorSecret`) before returning objects in JSON responses.
- **Path Traversal & Zip Slip (`CWE-22`)**:
  - Flag file reads/writes/downloads that concatenate user input into paths (`path.join(UPLOAD_DIR, req.query.file)`). Require `path.basename()` or verify `resolvedPath.startsWith(ALLOWED_ROOT)`.
  - When extracting archives (`.zip`, `.tar`), verify each entry's resolved target path stays inside the destination directory to prevent Zip Slip overwrites.
- **Cross-Site Request Forgery (`CWE-352`) & CORS (`CWE-942`)**:
  - Verify state-changing cookie-authenticated endpoints enforce CSRF tokens or strict `SameSite` policies + Origin header verification.
  - Flag `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true`, or dynamic `Origin` reflection without a strict allowlist.

---

## A02: Cryptographic Failures & Secrets Exposure (`CWE-327`, `CWE-798`, `CWE-330`)

- **Hardcoded & Client-Exposed Secrets (`CWE-798`, `CWE-200`)**:
  - Scan for hardcoded API keys, database URLs, JWT secrets, or private keys in source files.
  - Check for server secrets accidentally prefixed with client-bundled environment prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`).
- **Weak Password Hashing (`CWE-916`)**:
  - Flag `md5`, `sha1`, `sha256`, or fast unsalted hashes for passwords. Require `argon2id`, `bcrypt` (cost >= 10), or `scrypt`.
- **Insecure Randomness (`CWE-330`)**:
  - Flag `Math.random()`, `mt_rand()`, or `random.random()` used for password reset tokens, OTPs, session IDs, or CSRF tokens. Require CSPRNG (`crypto.randomBytes`, `crypto.randomUUID`, `random_bytes`, `secrets.token_urlsafe`).
- **Weak Encryption & Timing Leaks (`CWE-327`, `CWE-208`)**:
  - Flag ECB mode, static/hardcoded IVs, or missing authentication tags (prefer `AES-256-GCM`).
  - Require constant-time comparison (`crypto.timingSafeEqual`, `hash_equals`, `hmac.compare_digest`) when comparing HMACs, API keys, or OTPs.

---

## A03: Injection & Cross-Site Scripting (`CWE-89`, `CWE-79`, `CWE-78`, `CWE-94`)

- **SQL & NoSQL Injection (`CWE-89`, `CWE-943`)**:
  - Flag string interpolation in SQL (`$queryRawUnsafe`, `sequelize.query`, `DB::raw`, `cursor.execute(f"...")`), especially in `ORDER BY`, `LIMIT`, or table/column identifiers that cannot use standard bind parameters (must be validated against a strict enum allowlist).
  - Flag unvalidated object inputs in MongoDB/NoSQL queries (`User.find({ email: req.body.email })` where `req.body.email` can be `{ "$ne": null }` or `$where`).
- **OS Command & Code Injection (`CWE-78`, `CWE-94`)**:
  - Flag `child_process.exec`, `execSync`, `os.system`, `subprocess.Popen(..., shell=True)`, `eval()`, `new Function()`, or PHP `exec`/`shell_exec`/`passthru` receiving user input. Use `execFile` with an argument array and strict input validation.
- **Cross-Site Scripting — XSS (`CWE-79`) & XXE (`CWE-611`)**:
  - Flag `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `{!! $var !!}`, or `mark_safe` without strict HTML sanitization (`DOMPurify`, `sanitize-html`).
  - Flag user-controlled URLs rendered in `<a href={url}>` or `<iframe src={url}>` without verifying the protocol is `http:` or `https:` (blocks `javascript:` and `data:` URIs).
  - In XML/SOAP/SAML/SVG/DOCX parsers (`libxml`, `DOMDocument`, `lxml`), verify external entity resolution (`LIBXML_NOENT`, DTD loading) is disabled to prevent XML External Entity (`XXE`) file reads and SSRF.

---

## A04: Insecure Design, Business Logic & Race Conditions (`CWE-362`, `CWE-840`)

- **Race Conditions / TOCTOU (`CWE-362`)**:
  - Inspect financial transfers, wallet balance deductions, coupon/voucher redemptions, inventory decrements, and vote/like counters.
  - Flag check-then-act patterns (`const user = await getBalance(); if (user.balance >= amount) await updateBalance(user.balance - amount)`).
  - Require atomic database updates (`UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1`) inside a transaction or pessimistic row lock (`SELECT ... FOR UPDATE`).
- **Client-Side Trust & Price Tampering (`CWE-602`)**:
  - Verify checkout/payment handlers recalculate prices, discounts, tax, and shipping from server-side database records rather than trusting `price` or `total` fields sent in `req.body`.
- **Multi-Step Workflow Bypass (`CWE-841`)**:
  - Verify sequential flows (e.g., KYC verification -> withdrawal, or OTP verification -> password reset) validate server-side state completion rather than relying on client-supplied flags.

---

## A05 & A06: Misconfiguration & Supply Chain (`CWE-16`, `CWE-1104`)

- **HTTP Security Headers**:
  - Verify framework/middleware configures:
    - `Content-Security-Policy` (restrict `script-src`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors`)
    - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY` (or `SAMEORIGIN`)
    - `Referrer-Policy: strict-origin-when-cross-origin`
    - `Permissions-Policy` (disable unused camera, microphone, geolocation)
- **Dependency & Lockfile Hygiene (`CWE-1104`)**:
  - Check lockfiles (`package-lock.json`, `composer.lock`, `poetry.lock`) and run native vulnerability scanners (`npm audit`, `composer audit`) when available.

---

## A07: Identification & Authentication Failures (`CWE-287`, `CWE-384`, `CWE-613`)

- **Cookie & Session Security (`CWE-614`, `CWE-1004`)**:
  - Verify session cookies set `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`), and reasonable `Max-Age`/`Expires`.
  - Verify session IDs are regenerated upon login/privilege change (`req.session.regenerate()`) and destroyed server-side on logout.
- **JWT Implementation Flaws (`CWE-347`)**:
  - Verify `jwt.verify()` (never `jwt.decode()` alone) enforces an explicit algorithm allowlist (`algorithms: ['HS256']` or `['RS256']`), checks `exp`/`iss`/`aud`, and fails closed if `process.env.JWT_SECRET` is missing.
  - Inspect JWT header handling: ensure `kid` (Key ID) is never concatenated into file paths or SQL queries, and `jku`/`x5u`/`jwk` headers are never trusted dynamically without a pinned server-side keyset.
- **Host Header Injection & Password Reset Poisoning (`CWE-640`, `CWE-444`)**:
  - When generating password reset links, magic login links, or OAuth callback URLs, never build the URL from untrusted request headers (`req.headers.host`, `X-Forwarded-Host`). Always use a canonical environment variable (`process.env.APP_URL` / `config('app.url')`).
- **Account Enumeration & Password Reset (`CWE-204`, `CWE-640`)**:
  - Verify login and forgot-password endpoints return generic responses and consistent timing whether an email exists or not, and single-use reset tokens expire quickly (<= 15–30 minutes) and are hashed in the database.

---

## A08, A09 & A10: Integrity, Logging & SSRF (`CWE-345`, `CWE-502`, `CWE-532`, `CWE-918`)

- **Webhook & Data Integrity (`CWE-345`, `CWE-502`)**:
  - Verify incoming webhooks (Stripe, Midtrans, Xendit, GitHub, Clerk) verify cryptographic signatures against the raw request body (`crypto.timingSafeEqual`) and enforce timestamp tolerance + idempotency keys to prevent replay attacks.
  - Flag unsafe deserialization (`unserialize()`, `pickle.loads()`, `yaml.load()` without `SafeLoader`).
- **File Upload Validation (`CWE-434`)**:
  - Verify uploads validate actual file magic bytes (not just client `Content-Type` or extension), generate random storage filenames (UUID), disallow executable extensions (`.php`, `.html`, `.svg` with inline scripts), and store files outside the public webroot or on isolated object storage with `Content-Disposition: attachment`.
- **Sensitive Data in Logs & Error Responses (`CWE-532`, `CWE-209`)**:
  - Flag `console.log(req.body)`, logging Authorization headers/tokens/passwords, or returning raw `err.stack` / database error messages to clients in production.
- **Server-Side Request Forgery — SSRF (`CWE-918`)**:
  - When the backend fetches a user-supplied URL (avatars, webhooks, link previews, PDF generators), verify it restricts schemes to `https:`, resolves DNS and blocks loopback/private/link-local/cloud-metadata IPs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `::1`), and disables automatic redirects to untrusted hosts.

---

## Reference Defensive Code Blueprints (Stage 3 Patching)

### 1. Authenticated, Schema-Validated & BOLA-Safe Handler (TypeScript / Next.js)
```ts
const UpdateOrderSchema = z.object({
  orderId: z.string().uuid(),
  shippingAddress: z.string().trim().min(5).max(300),
});

export async function updateOrderAddress(rawInput: unknown) {
  const session = await auth();
  if (!session?.user?.id) throw new Error('Unauthorized');

  const input = UpdateOrderSchema.parse(rawInput);

  // Enforce object-level ownership (BOLA/IDOR defense) in the WHERE clause
  const updated = await db.order.updateMany({
    where: { id: input.orderId, userId: session.user.id, status: 'PENDING' },
    data: { shippingAddress: input.shippingAddress },
  });

  if (updated.count === 0) throw new Error('Order not found or not editable');
  return { ok: true };
}
```

### 2. SSRF-Safe Outbound URL Validator & Fetch Wrapper (Node.js)
```ts
import dns from 'node:dns/promises';
import net from 'node:net';

function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.toLowerCase().replace(/^::ffff:/, '');
  if (net.isIPv4(normalized)) {
    return (
      /^(127\.|10\.|0\.|169\.254\.|192\.168\.)/.test(normalized) ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(normalized) ||
      /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./.test(normalized)
    );
  }
  return (
    normalized === '::1' ||
    normalized === '::' ||
    /^(fc|fd|fe8|fe9|fea|feb)/.test(normalized)
  );
}

export async function safeExternalFetch(rawUrl: string): Promise<Response> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:') throw new Error('Only HTTPS URLs are allowed');

  // Resolve ALL A/AAAA records to prevent round-robin & IPv4-mapped IPv6 bypasses
  const records = await dns.lookup(parsed.hostname, { all: true, verbatim: true });
  if (records.length === 0 || records.some((r) => !net.isIP(r.address) || isPrivateOrReservedIp(r.address))) {
    throw new Error('Blocked private, loopback, or reserved destination IP');
  }

  // Disable automatic redirects (blocks 302 -> 169.254.169.254); pin resolved IP on custom agent for TTL-0 rebinding defense
  return await fetch(parsed, {
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  });
}
```
