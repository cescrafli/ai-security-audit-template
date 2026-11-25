# BaaS (Supabase / Firebase), OAuth/MFA, Financial Ledger & Client-Side Security Guide

Use this reference during Stage 2 to audit Backend-as-a-Service (BaaS) row-level security, modern authentication flows (OAuth2/OIDC, MFA, Passkeys), payment/financial logic, and browser/client-side storage security.

---

## 1. BaaS & Database Row-Level Security (Supabase, PostgreSQL RLS, Firebase)

- **Missing or Permissive PostgreSQL / Supabase RLS (`CWE-284`, `CWE-862`)**:
  - In Supabase or Postgres migrations (`supabase/migrations/*.sql`), verify **every table in the `public` schema** executes `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;`.
  - Flag overly permissive RLS policies such as `USING (true)` or `WITH CHECK (true)` on `INSERT`, `UPDATE`, or `DELETE`, or on `SELECT` tables containing private user/tenant data.
  - Verify RLS policies strictly bind rows to `auth.uid()` or the user's verified organization membership (`auth.uid() = user_id`), and check that `SECURITY DEFINER` SQL functions set an explicit `SET search_path = public` and verify caller permissions internally.
- **Leaked Service-Role / Admin SDK Keys (`CWE-798`)**:
  - Flag `SUPABASE_SERVICE_ROLE_KEY`, Firebase Admin private keys, or Appwrite API keys imported in client-bundled files or exposed via `NEXT_PUBLIC_` / `VITE_`. The `service_role` key bypasses all RLS policies!
- **Firebase Firestore & Storage Security Rules (`firestore.rules`, `storage.rules`)**:
  - Flag `allow read, write: if true;` or `allow read, write: if request.auth != null;` without verifying document ownership (`request.auth.uid == resource.data.ownerId`) and schema field constraints.

---

## 2. Advanced Authentication: OAuth2 / OIDC, MFA & Account Lifecycle

- **OAuth2 / OIDC Flow Vulnerabilities (`CWE-352`, `CWE-601`, `CWE-287`)**:
  - **Missing `state` Verification**: Verify custom OAuth flows generate a cryptographically random, session-bound `state` parameter and validate it on the callback to prevent OAuth CSRF and account-linking hijacking.
  - **Pre-Account Takeover via Unverified Email Linking**: When linking an OAuth login (e.g., Google/GitHub) to an existing password-based account with the same email address, verify the provider explicitly returned `email_verified === true` AND require email confirmation if the existing account was unverified.
  - **Open Redirect in `callbackUrl` / `redirect_uri` (`CWE-601`)**: Verify post-login redirect parameters (`?next=`, `?redirect=`, `?callbackUrl=`) only allow relative paths starting with a single `/` (reject `//evil.com`, `https://evil.com`, and `javascript:`).
- **Multi-Factor Authentication (MFA / 2FA) Bypass (`CWE-287`, `CWE-307`)**:
  - Verify password login does not issue a full authenticated session cookie/JWT before the MFA step is completed (issue a short-lived, scope-restricted `mfa_pending` token instead).
  - Verify 6-digit TOTP / SMS OTP verification endpoints enforce strict per-account attempt limits (e.g., lock/invalidate challenge after 5 failed attempts) so a 6-digit code (`000000`–`999999`) cannot be brute-forced.
  - Verify MFA recovery/backup codes are hashed in the database and atomically marked as used upon redemption.
- **Session Revocation & Password/Privilege Change (`CWE-613`)**:
  - Verify changing a password, resetting a password, enabling MFA, or revoking a user's role immediately invalidates all existing active sessions and refresh tokens for that user.

---

## 3. Financial, Payment Gateway, E-Commerce & Ledger Security (`CWE-840`, `CWE-362`, `CWE-682`)

- **Negative Amount & Quantity Injection (`CWE-20`, `CWE-840`)**:
  - In wallet transfers, cart item quantities, withdrawal requests, and refund calculations, verify inputs enforce strict positive bounds (`amount > 0`, `Number.isSafeInteger(quantity) && quantity >= 1`). Transferring `-100` from User A to User B must never credit User A's balance!
- **Floating-Point Precision & Currency Rounding Flaws (`CWE-682`)**:
  - Flag standard IEEE 754 floating-point math (`number` / `float` / `DOUBLE`) used for monetary balances, prices, or fee splits. Require smallest currency integer units (e.g., cents/satoshi as `BigInt`/`INTEGER`) or fixed-precision `DECIMAL(18, 2)` / `Decimal.js`.
- **Payment Webhook Idempotency & Signature Verification (`CWE-345`, `CWE-362`)**:
  - For Stripe, Midtrans, Xendit, PayPal, or crypto payment webhooks:
    1. Verify cryptographic signature against the raw payload before parsing trust.
    2. Verify the paid amount and currency in the webhook payload match the expected order total in the database.
    3. Enforce **database-level idempotency** (e.g., a `UNIQUE` constraint on `payment_event_id` or `UPDATE orders SET status = 'PAID' WHERE id = $1 AND status = 'PENDING'`) inside a transaction so concurrent duplicate webhook deliveries never credit a user's wallet or ship an order twice.

---

## 4. Client-Side Browser, DOM & Privacy Security

- **Sensitive Data in Browser Storage & URLs (`CWE-922`, `CWE-598`)**:
  - Flag storing high-privilege JWTs, refresh tokens, API keys, or raw PII in `localStorage` or `sessionStorage` (accessible to any XSS payload). Prefer `HttpOnly; Secure; SameSite` cookies.
  - Flag passing session tokens, password reset tokens, or PII in URL query strings where they leak via `Referer` headers, browser history, and access logs (or ensure `Referrer-Policy: no-referrer` is set on reset pages).
- **Insecure `postMessage` & DOM Clobbering (`CWE-346`, `CWE-79`)**:
  - Flag `window.addEventListener('message', ...)` handlers that do not strictly verify `event.origin` against an explicit origin allowlist, or `targetWindow.postMessage(secretData, '*')`.
- **Third-Party Script Integrity & Reverse Tabnabbing (`CWE-829`, `CWE-1022`)**:
  - Flag external CDN `<script>` tags lacking `integrity="sha384-..."` (Subresource Integrity / SRI).
  - Flag dynamic `window.open(url, '_blank')` calls lacking `'noopener,noreferrer'`.

---

## Reference Defensive Code Blueprints (Stage 3 Patching)

### 1. Atomic Ledger Deduction & Idempotent Webhook Processing (SQL / Prisma)
```ts
// Prevent TOCTOU Race Conditions (CWE-362) & Negative Amount Injection (CWE-840)
export async function withdrawWalletBalance(userId: string, amountCents: number) {
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) {
    throw new Error('Amount must be a positive integer in cents');
  }

  return await db.$transaction(async (tx) => {
    // Atomic conditional decrement: only succeeds if balance >= amountCents
    const updated = await tx.$executeRaw`
      UPDATE wallets
      SET balance_cents = balance_cents - ${amountCents}, updated_at = NOW()
      WHERE user_id = ${userId} AND balance_cents >= ${amountCents}
    `;
    if (updated !== 1) throw new Error('Insufficient balance');

    return await tx.ledgerEntry.create({
      data: { userId, amountCents: -amountCents, type: 'WITHDRAWAL' },
    });
  });
}
```

### 2. Strict PostgreSQL / Supabase Row-Level Security (RLS) Migration
```sql
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents FORCE ROW LEVEL SECURITY;

CREATE POLICY "Users can only read their own documents"
  ON public.documents FOR SELECT
  TO authenticated
  USING ((SELECT auth.uid()) = user_id);

CREATE POLICY "Users can only insert their own documents"
  ON public.documents FOR INSERT
  TO authenticated
  WITH CHECK ((SELECT auth.uid()) = user_id);
```
