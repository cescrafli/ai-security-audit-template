# Real-World Mass Breach Playbooks, Classic Flaws & High-Impact CVEs

Modern codebases frequently focus on cloud and framework abstractions while accidentally re-introducing **foundational classic vulnerabilities** inside new wrappers (microservices, serverless functions, custom parsers, or AI tool handlers). Use this reference during Stage 1 and Stage 2 to audit against both **classic foundational breach vectors** and **modern mass-compromise CVEs**.

---

## 1. Why Foundational Classic Vulnerabilities Still Breach Modern Systems

| Vulnerability Class | Classic Mechanism | How It Surfaces in Modern Codebases |
| :--- | :--- | :--- |
| **CLI Argument & Shell Injection (`CWE-88`, `CWE-78`)** | Shell metacharacters, CLI flag injection, `%00` string truncation. | Passing user strings starting with `-` (`--upload-pack=...`, `--checkpoint-action=exec=...`) to `spawn`/`execFile` (`git`, `tar`, `ffmpeg`, `curl`) without `--`; **Dynamic `import(userInput)` / `include($page)` (`CWE-98`)**; **SMTP/HTTP CRLF Header Injection (`CWE-113`)**. |
| **SQLi, Webshell Uploads & XXE (`CWE-89`, `CWE-434`, `CWE-611`)** | Unparameterized SQL, Second-Order SQLi, `shell.php.jpg` / `.user.ini` upload execution, external XML entities. | **Second-Order SQLi & ORM Raw Queries (`whereRaw`, `$queryRawUnsafe`, Eloquent column-name injection)**; **Uploading `.htaccess`, `.user.ini`, or `.svg` with inline JS (`CWE-434`)**; **XXE in SAML/SOAP/DOCX/SVG parsers (`CWE-611`)**; **Session Fixation (`CWE-384`)**. |
| **Memory Over-Read, Deserialization, Type Juggling & Cloud SSRF (`CWE-908`, `CWE-502`, `CWE-918`)** | Heartbleed-style memory over-read, unsafe object deserialization (`unserialize`, `pickle`, `phar://`), SSTI (`{{7*7}}`), PHP Type Juggling (`==`), Cloud IMDSv1 (`169.254.169.254`). | **Node.js `Buffer.allocUnsafe(userSize)` heap memory leak (`CWE-908`)**; **PHP `phar://` deserialization via `file_exists()` / `getimagesize()` (`CWE-502`)**; **Type Juggling / Array Parameter Pollution (`?token[]=`, `CWE-843`)**; **Headless browser / PDF SSRF to `169.254.169.254` (`CWE-918`)**. |
| **Supply Chain, BaaS, AI/LLM & Core Engine CVEs** | CI/CD script injection, CDN hijack, missing Supabase RLS, Next.js `x-middleware-subrequest`, LLM prompt-to-tool injection, core PHP engine memory/error RCE. | **Unpatched PHP runtimes vulnerable to `PHP2Shell` (`CVE-2026-109618` / `109619`)**; **Next.js `< 15.2.3`/`14.2.25` middleware bypass (`CVE-2025-29927`)**; **Supabase tables without `ENABLE ROW LEVEL SECURITY`**; **GitHub Actions `${{ }}` injection in `run:`**; **LLM tool calls without server-enforced `userId`**. |

---

## 2. Foundational Vulnerabilities That Frequently Resurface in Modern Codebases

### A. CLI Argument Injection (`CWE-88`)
- **Why Developers Miss It**: Developers learn that `exec()` is dangerous and switch to `child_process.execFile()` or `spawn('git', ['clone', userUrl])` thinking an argument array prevents injection.
- **The Exploit**: If `userUrl` starts with a hyphen (e.g., `--upload-pack=touch /tmp/pwn` in `git`, `--checkpoint-action=exec=...` in `tar`, or `-o /var/www/shell.php` in `curl`), the binary interprets the user data as a command-line flag!
- **Audit Check**: Verify every `execFile` / `spawn` / `Process` call validates that user arguments do not start with `-`, and places the `--` (end-of-options) delimiter before positional user arguments.

### B. Dynamic File Inclusion (`LFI/RFI`) & Modern Dynamic `import()` (`CWE-98`)
- **The Exploit**: Classic PHP `include($_GET['view'] . '.php')` or modern Node.js/Webpack/Vite `await import(\`./locales/\${userLang}.js\`)` allows directory traversal (`../../...`) or loading arbitrary internal modules.
- **Audit Check**: Never pass user-controlled strings directly into `include`, `require`, `require_once`, `fs.readFile`, or dynamic `import()`. Map allowed keys via an explicit static dictionary object.

### C. PHP `phar://` Metadata Deserialization & Type Juggling (`CWE-502`, `CWE-843`)
- **The Exploit**:
  - **Phar Deserialization**: Even if a PHP app never calls `unserialize()`, passing a user-supplied URI like `phar://./uploads/avatar.jpg/test` to innocent filesystem functions (`file_exists()`, `is_dir()`, `filesize()`, `file_get_contents()`, `getimagesize()`) automatically deserializes the Phar archive's metadata and triggers POP gadget chains (e.g., Monolog/Guzzle RCE).
  - **Type Juggling & Magic Hashes**: Using loose comparison (`==` or `!=` instead of `===`) on password hashes, OTPs, or HMACs allows bypass via JSON booleans (`{"otp": true}`), arrays (`?token[]=1`), or `"0e..."` scientific-notation strings.
- **Audit Check**: Verify file operations validate the protocol/path starts with an allowed local directory (blocking `phar://`, `php://`, `ftp://`, `data://`), and enforce strict comparisons (`===`, `hash_equals()`, `in_array($x, $arr, true)`).

### D. Double-Extension, `.htaccess` / `.user.ini` & SVG/XML Upload Exploits (`CWE-434`, `CWE-611`)
- **The Exploit**:
  - Uploading `.htaccess` (`AddType application/x-httpd-php .jpg`) or `.user.ini` (`auto_prepend_file=avatar.jpg`) into a directory served by Apache or PHP-FPM turns harmless image files into PHP webshells.
  - Uploading `.svg` files containing `<script>` or external XML entity (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) triggers Stored XSS or XXE when viewed or rasterized.
- **Audit Check**: Never preserve client filenames (`getClientOriginalName()` / `file.originalname`). Generate a random UUID filename with a strict allowlisted extension, block `.svg`/`.html`/`.htaccess`/`.user.ini`, and serve user uploads from a separate domain/bucket with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.

### E. Heartbleed-Style Uninitialized Memory Over-Read in Node.js (`CWE-908`)
- **The Exploit**: Calling `Buffer.allocUnsafe(Number(req.query.size))` or `new Buffer(Number(req.body.len))` allocates raw unzeroed RAM from the V8 heap. If returned to the client, it leaks fragments of previous HTTP requests, JWTs, database passwords, and TLS keys (identical in impact to OpenSSL Heartbleed `CVE-2014-0160`).
- **Audit Check**: Flag `Buffer.allocUnsafe()`, `Buffer.allocUnsafeSlow()`, and deprecated `new Buffer()` across all JavaScript/TypeScript files.

### F. HTTP Response Splitting, CRLF & SMTP Mail Header Injection (`CWE-113`, `CWE-93`)
- **The Exploit**: Injecting `\r\n` (`%0d%0a`) into unvalidated headers, cookie values, or contact-form `From` / `Subject` fields passed to `mail()` / SMTP libraries allows attackers to inject arbitrary HTTP headers, split responses to poison caches, or inject `Bcc:` headers to turn the server into a spam relay.
- **Audit Check**: Strip `\r` and `\n` from all user strings used in HTTP headers, redirects, log lines, and email headers.

---

## 3. High-Impact Modern Mass-Breach Playbooks & CVEs

### A. PHP, Laravel & WordPress Mass-Compromise Vectors
- **PHP2Shell Core Engine RCE (`CVE-2026-109618` & `CVE-2026-109619`)**:
  - **Root Cause**: Memory management and error-handling flaws inside the core PHP engine (affecting PHP 5 through PHP 8) allowing unauthenticated Remote Code Execution (RCE) even when application code is completely secure.
  - **Audit Check**: Inspect `php -v`, `Dockerfile` (`FROM php:...`), `composer.json`, and CI/CD configs. Require **`>= 8.5.12`**, **`>= 8.4.27`**, **`>= 8.3.36`**, or **`>= 8.2.35`**. Set `expose_php = Off` and `display_errors = Off` in `php.ini`.
- **PHP-CGI Windows Unicode Argument Injection (`CVE-2024-4577`)**:
  - **Root Cause**: On Windows servers (Apache/XAMPP/Laragon running PHP-CGI), Best-Fit character encoding converts soft-hyphen (`%AD`) into `-` (`0x2D`), allowing attackers to inject `-d allow_url_include=1 -d auto_prepend_file=php://input` for instant RCE.
- **Nginx + PHP-FPM `fastcgi_split_path_info` RCE (`CVE-2019-11043`)**:
  - **Audit Check**: Inspect `nginx.conf` `location ~ \.php$` blocks and ensure `try_files $uri =404;` is present before `fastcgi_pass`.
- **Laravel `APP_DEBUG=true` Ignition RCE (`CVE-2021-3129`) & `APP_KEY` Deserialization RCE (`CVE-2018-15133`)**:
  - **Audit Check**: Verify `APP_DEBUG=false` in production, upgrade `facade/ignition` to `spatie/laravel-ignition` (`>= 2.x`, dev-only), and ensure `APP_KEY` is never committed or exposed.
- **Livewire Snapshot / File Upload Tampering (`CVE-2024-21546`, `CVE-2024-47823`)** & **WordPress Mass Exploits** (block `xmlrpc.php`, restrict `/wp-json/wp/v2/users`, disable PHP execution in `wp-content/uploads/`).

### B. Next.js, React, Node.js & Frontend Mass-Compromise Vectors
- **Next.js Middleware Authorization Bypass (`CVE-2025-29927`)**:
  - **Root Cause**: Sending a single forged HTTP header (`x-middleware-subrequest`) causes Next.js (`< 15.2.3`, `< 14.2.25`, `< 13.5.9`, `< 12.3.5`) to skip running `middleware.ts` entirely.
  - **Audit Check**: Upgrade Next.js to patched versions, strip `x-middleware-subrequest` at the edge proxy, and enforce auth inside the Data Access Layer / API handlers / Server Actions.
- **Next.js Server Action SSRF & Cache Poisoning (`CVE-2024-34351`, `CVE-2024-46982`)**.
- **Magecart / Third-Party CDN Supply Chain Hijack (`polyfill.io`, `bootcdn.net`, `bootcss.com`, `staticfile.org`)**:
  - Flag these domains as **Critical** and require Subresource Integrity (`integrity="sha384-..."`) on external scripts.
- **Node.js `vm` / `vm2` Sandbox Escape RCE (`CVE-2023-37466`, `CVE-2023-37903`)**.

### C. Cloud, BaaS & Automated Botnet Harvesting Vectors
- **Exposed `.env`, `.git`, `/phpinfo.php`, `/storage/logs/laravel.log`, and `/actuator/heapdump` Harvesting**.
- **Cloud Metadata SSRF to Full Account Takeover (`169.254.169.254` — Capital One Pattern)**.
- **Supabase / Firebase "Anon Key + Missing RLS" Mass Database Dump**:
  - Flag every `CREATE TABLE` in `supabase/migrations/*.sql` lacking `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` and strict `auth.uid()` policies as **Critical**.
- **Unauthenticated Redis (`6379`) / MongoDB (`27017`) / PostgreSQL (`5432`) Port Exposure**.
- **Log4Shell (`CVE-2021-44228`), Spring4Shell (`CVE-2022-22965`), `libwebp` (`CVE-2023-4863`), `ImageTragick` (`CVE-2016-3714`), and `ExifTool` (`CVE-2021-22204`)**.
