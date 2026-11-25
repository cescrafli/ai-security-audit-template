# Infrastructure, Docker, CI/CD, Reverse Proxy & Supply Chain Security Guide

Use this reference during Stage 2 to audit container configurations, CI/CD pipelines, web server / reverse proxy configs, deployment manifests, and third-party dependencies.

---

## 1. Docker & Container Security (`Dockerfile`, `docker-compose.yml`)

- **Root Privilege Execution (`CWE-250`)**:
  - Flag `Dockerfile` definitions that do not switch to a non-root user (`USER node`, `USER appuser`, or numeric UID `USER 10001`) before `CMD`/`ENTRYPOINT`.
  - In `docker-compose.yml` or Kubernetes manifests, flag `privileged: true`, `network_mode: host`, or mounting the host Docker socket (`/var/run/docker.sock`).
- **Secrets Baked into Image Layers (`CWE-522`, `CWE-798`)**:
  - Flag `ARG` or `ENV` instructions in `Dockerfile` that accept or set private keys, database passwords, or API tokens (they persist in `docker history`). Use BuildKit secret mounts (`--mount=type=secret`) or runtime environment injection.
  - Verify `.dockerignore` excludes `.env*`, `.git`, `node_modules`, `storage/logs`, `*.pem`, `*.key`, and local SQL dumps so secrets are never copied via `COPY . .`.
- **Exposed Internal Services, Vulnerable Runtime Engines & Unpinned Images (`CWE-668`, `CWE-1104`)**:
  - In `docker-compose.yml`, flag database/Redis/internal cache ports bound to all interfaces (`ports: - "5432:5432"` or `"6379:6379"`). Bind local-only ports to loopback (`"127.0.0.1:5432:5432"`) or keep them on an internal Docker network without host port mapping.
  - Flag mutable `:latest` tags on base images; recommend pinned version tags or SHA256 digests, and enforce container memory/CPU limits (`deploy.resources.limits`).
  - **Runtime Base Image CVE Verification**:
    - For PHP images (`FROM php:<tag>`), verify the image version is patched against **PHP2Shell (`CVE-2026-109618` & `CVE-2026-109619`)** — requiring **`>= 8.5.12`**, **`>= 8.4.27`**, **`>= 8.3.36`**, or **`>= 8.2.35`**. Flag any older PHP 5/7/8 image tag as **Critical**.
    - For Node.js/Python images, verify active LTS/supported runtime versions with current security patches.

---

## 2. CI/CD Pipeline Security (`.github/workflows/*.yml`, `.gitlab-ci.yml`)

- **GitHub Actions Script / Command Injection (`CWE-78`)**:
  - Flag untrusted GitHub event context variables interpolated directly inside `run:` shell blocks:
    - `${{ github.event.issue.title }}`, `${{ github.event.issue.body }}`, `${{ github.event.pull_request.title }}`, `${{ github.event.pull_request.head.ref }}`, `${{ github.event.comment.body }}`, `${{ github.head_ref }}`.
  - **Defensive Fix**: Pass the expression via an intermediate `env:` variable (`TITLE: ${{ github.event.issue.title }}`) and reference `"$TITLE"` safely inside the shell script.
- **Dangerous `pull_request_target` & Fork Poisoning (`CWE-269`)**:
  - Flag workflows triggered by `pull_request_target` or `workflow_run` that checkout and execute code from the untrusted PR head (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`) while having access to repository secrets or `write` permissions.
- **Overly Permissive `GITHUB_TOKEN` & Unpinned Actions (`CWE-250`, `CWE-829`)**:
  - Verify workflows declare least-privilege top-level permissions (`permissions: contents: read`).
  - Flag third-party GitHub Actions pinned to mutable branches (`@main`, `@master`) instead of immutable commit SHAs or strict release tags.

---

## 3. Web Server, Reverse Proxy & Cloud Deployment (`nginx.conf`, `.htaccess`, `vercel.json`)

- **Dotfile, Backup & Sensitive Path Exposure (`CWE-538`, `CWE-552`)**:
  - Verify Nginx / Apache / Caddy blocks public access to hidden files (`.git`, `.env`, `.svn`, `.DS_Store`), backup archives (`*.sql`, `*.bak`, `*.zip`, `*.tar.gz`), and configuration files (`composer.json`, `package.json`, `phpinfo.php`).
  - Verify script execution (e.g., `.php`) is explicitly disabled inside user-writable upload directories (`/uploads`, `/storage`).
- **TLS, Proxy Headers, Web Cache Poisoning & Client Body Limits (`CWE-295`, `CWE-444`, `CWE-525`)**:
  - Verify reverse proxy restricts TLS to `TLSv1.2` and `TLSv1.3`, sets `client_max_body_size` appropriately, configures proxy read/send timeouts, and overwrites (rather than blindly appending to) spoofed `X-Forwarded-For`, `X-Forwarded-Host`, and `x-middleware-subrequest` headers at the edge.
  - **Web Cache Poisoning & Cache Deception**: Verify authenticated API/SSR responses explicitly set `Cache-Control: private, no-store` (or `Vary: Cookie, Authorization`) so CDN/edge caches never serve User A's private session data to User B.
- **Native Binary & Media/PDF Processor CVEs (`wkhtmltopdf`, `ImageMagick`, `Ghostscript`, `libwebp`, `FFmpeg`)**:
  - Flag rendering untrusted HTML in `wkhtmltopdf` or headless browsers without network isolation (enables internal SSRF and `file://` local file disclosure).
  - Verify `sharp`/`libvips`, `ImageMagick`, `Pillow`, and `FFmpeg` are updated to patched releases and disable risky coders (MVG, EPS, PS, PDF, SVG with external references) via `policy.xml`.

---

## 4. Software Supply Chain & Dependency Integrity (`CWE-1104`, `CWE-829`)

- **Lockfile & Registry Integrity**:
  - Verify lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock`, `poetry.lock`) are committed, synchronized with manifests, and use HTTPS registry URLs with integrity hashes (`sha512-...`).
- **Dependency Confusion & Lifecycle Scripts**:
  - Inspect `.npmrc` / `pip.conf` / `composer.json` for private package scopes to ensure public registries cannot hijack internal package names.
  - Check `package.json` `scripts` (`preinstall`, `postinstall`) for suspicious shell downloads (`curl | sh`) or obfuscated code.
