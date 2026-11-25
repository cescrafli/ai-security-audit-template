#!/usr/bin/env node
/**
 * 360° Defensive Static Security, Architecture & Runtime CVE Recon Scanner
 * Usage: node <path-to-skill>/scripts/audit-recon.mjs <target-project-path>
 *
 * Performs a read-only, non-destructive static inventory of:
 * 1. Tech stack, frameworks, BaaS/payment integrations, infrastructure & complete entry-point file inventory
 * 2. Exact lockfile & runtime CVE checks (PHP2Shell CVE-2026-109618 / CVE-2026-109619, Next.js CVE-2025-29927, Laravel Ignition CVE-2021-3129)
 * 3. Git-tracked secret file detection (git ls-files), multi-stage Dockerfile final-USER checks, and cross-migration Supabase per-table RLS verification
 * 4. High-signal source code sinks with partial secret masking, grouped by severity (CRITICAL, HIGH, MEDIUM)
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const targetDir = path.resolve(process.argv[2] || process.cwd());

if (!fs.existsSync(targetDir)) {
  console.error(`[ERROR] Target path does not exist: ${targetDir}`);
  process.exit(1);
}

const MAX_DEPTH = 25;
const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MB cap to prevent OOM on large dumps

const IGNORED_DIRS = new Set([
  'node_modules', '.git', '.agents', '.agent', '.claude', '.next', 'dist', 'build', 'out', 'vendor',
  '__pycache__', '.venv', 'venv', 'storage', '.idea', '.vscode', 'coverage', 'tmp', 'temp'
]);

const CODE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.php', '.py', '.rb', '.go', '.java',
  '.sql', '.yml', '.yaml', '.json', '.conf', '.htaccess', '.rules', '.prisma'
]);

const SINK_PATTERNS = [
  // CRITICAL
  { id: 'CLIENT_SECRET', severity: 'CRITICAL', domain: 'Secret Exposure (A02)', cwe: 'CWE-798', regex: /(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_)[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|DATABASE_URL|ADMIN_KEY)/ },
  { id: 'BAAS_RLS_BYPASS', severity: 'CRITICAL', domain: 'BaaS / RLS Bypass (A01)', cwe: 'CWE-284', regex: /(SUPABASE_SERVICE_ROLE_KEY|USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\)|allow\s+read\s*,\s*write\s*:\s*if\s+true)/i },
  { id: 'CMD_EXEC', severity: 'CRITICAL', domain: 'OS Command / Code Exec (A03)', cwe: 'CWE-78/94', regex: /\b(execSync|child_process\.exec|shell_exec|passthru|proc_open|popen|os\.system|subprocess\.Popen\([^)]*shell\s*=\s*True|\beval\s*\(|new\s+Function\s*\()/ },
  { id: 'DESERIALIZE', severity: 'CRITICAL', domain: 'Unsafe Deserialization (A08)', cwe: 'CWE-502', regex: /\b(unserialize\s*\(|pickle\.loads?\s*\(|yaml\.load\s*\(|phar:\/\/)/ },
  { id: 'POLYFILL_CDN', severity: 'CRITICAL', domain: 'Supply Chain Hijack (Magecart)', cwe: 'CWE-829', regex: /(cdn\.polyfill\.io|polyfill\.io|bootcss\.com|bootcdn\.net|staticfile\.org)/i },
  { id: 'VM_SANDBOX', severity: 'CRITICAL', domain: 'Sandbox Escape RCE (CVE-2023-37466)', cwe: 'CWE-94', regex: /\b(require\s*\(\s*['"]vm2?['"]\s*\)|from\s+['"]vm2?['"]|new\s+VM\s*\()/ },
  { id: 'CICD_INJECT', severity: 'CRITICAL', domain: 'CI/CD Script Injection (INF)', cwe: 'CWE-78', regex: /\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion|commits|head_ref)[^}]*\}\}/ },
  { id: 'CLASSIC_LFI_IMPORT', severity: 'CRITICAL', domain: 'Foundational LFI / Dynamic Include (A03)', cwe: 'CWE-98', regex: /\b((include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)|import\s*\(\s*`[^`]*\$\{)/ },

  // HIGH
  { id: 'SQL_RAW', severity: 'HIGH', domain: 'Raw SQL / Query Injection (A03)', cwe: 'CWE-89', regex: /(\$queryRawUnsafe|\$executeRawUnsafe|DB::raw\(|whereRaw\(|orderByRaw\(|selectRaw\(|\.extra\(|\.raw\(|mysqli_query\()/ },
  { id: 'XSS_SINK', severity: 'HIGH', domain: 'Cross-Site Scripting / SSTI (A03)', cwe: 'CWE-79/1336', regex: /(dangerouslySetInnerHTML|v-html|\{!!\s*\$.*!!\}|\bmark_safe\s*\(|innerHTML\s*=|render_template_string\s*\()/ },
  { id: 'JWT_WEAK_VERIFY', severity: 'HIGH', domain: 'JWT Auth Bypass (A07)', cwe: 'CWE-347', regex: /\b(jwt\.decode\s*\(|algorithms\s*:\s*\[\s*['"]none['"])/ },
  { id: 'MASS_ASSIGN', severity: 'HIGH', domain: 'Mass Assignment / BOPLA (A01/API3)', cwe: 'CWE-915', regex: /(\$guarded\s*=\s*\[\s*\]|::create\(\s*\$request->all\(\)|->update\(\s*\$request->all\(\))/ },
  { id: 'LARAVEL_DEBUG', severity: 'HIGH', domain: 'Debug / Ignition Exposure (CVE-2021-3129)', cwe: 'CWE-489', regex: /(APP_DEBUG\s*=\s*true|['"]debug['"]\s*=>\s*true)/i },
  { id: 'EXPOSED_DB_PORT', severity: 'HIGH', domain: 'Public DB/Cache Port Binding (INF)', cwe: 'CWE-668', regex: /(?<!127\.0\.0\.1:)(?<!localhost:)\b(0\.0\.0\.0:)?(5432:5432|3306:3306|6379:6379|27017:27017|9200:9200)\b/ },
  { id: 'PDF_HEADLESS_SSRF', severity: 'HIGH', domain: 'PDF/Headless Browser SSRF & LFI (A10)', cwe: 'CWE-918', regex: /\b(wkhtmltopdf|puppeteer\.launch|playwright\.chromium|dompdf|Browsershot)/i },
  { id: 'BUFFER_UNSAFE_MEM', severity: 'HIGH', domain: 'Uninitialized Heap Memory Leak (A02)', cwe: 'CWE-908', regex: /\b(Buffer\.allocUnsafe(Slow)?\s*\(|new\s+Buffer\s*\()/ },
  { id: 'PHP_TYPE_JUGGLE', severity: 'HIGH', domain: 'Type Juggling / Loose Auth Check (A07)', cwe: 'CWE-843', regex: /(strcmp\s*\([^)]*\$_(GET|POST|REQUEST)|(\$password|\$token|\$otp|\$hash|\$signature)\s*==\s*[^=])/i },
  { id: 'UPLOAD_ORIG_NAME', severity: 'HIGH', domain: 'Unsafe Upload Filename / Webshell Risk (A08)', cwe: 'CWE-434', regex: /\b(getClientOriginalName\s*\(|getClientOriginalExtension\s*\(|move_uploaded_file\s*\()/ },
  { id: 'XXE_PARSER', severity: 'HIGH', domain: 'XML External Entity — XXE (A05)', cwe: 'CWE-611', regex: /\b(LIBXML_NOENT|LIBXML_DTDLOAD|simplexml_load_string|DOMDocument|etree\.fromstring)/ },
  { id: 'CLI_ARG_SPAWN', severity: 'HIGH', domain: 'CLI Argument Injection Check (A03)', cwe: 'CWE-88', regex: /\b(execFile|execFileSync|spawn|spawnSync)\s*\(/ },

  // MEDIUM
  { id: 'WEAK_CRYPTO_RNG', severity: 'MEDIUM', domain: 'Weak Hashing / Predictable RNG (A02)', cwe: 'CWE-330/916', regex: /\b(Math\.random\s*\(|mt_rand\s*\(|md5\s*\(|sha1\s*\()/ },
  { id: 'STORAGE_TOKEN', severity: 'MEDIUM', domain: 'Token in localStorage/sessionStorage (DOM)', cwe: 'CWE-922', regex: /(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*['"][^'"]*(token|jwt|auth|secret|session)/i },
  { id: 'OUTBOUND_HTTP', severity: 'MEDIUM', domain: 'Outbound HTTP (Verify SSRF & Timeout)', cwe: 'CWE-918/400', regex: /\b(fetch\s*\(|axios\.(get|post|put|delete|request)\s*\(|Http::(get|post)\s*\(|curl_exec\s*\(|requests\.(get|post)\s*\()/ },
  { id: 'WP_EXPOSURE', severity: 'MEDIUM', domain: 'WordPress Hardening Check (A05)', cwe: 'CWE-284', regex: /(xmlrpc\.php|wp-json\/wp\/v2\/users|DISALLOW_FILE_EDIT['"]?\s*,\s*false)/i },
  { id: 'POSTMESSAGE_WILDCARD', severity: 'MEDIUM', domain: 'Insecure postMessage Origin (DOM)', cwe: 'CWE-346', regex: /(\.postMessage\s*\([^,]+,\s*['"]\*['"]|addEventListener\s*\(\s*['"]message['"])/ }
];

function parseSemver(verStr) {
  const str = String(verStr).trim();
  const full = str.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (full) return { major: Number(full[1]), minor: Number(full[2]), patch: Number(full[3] || 0), majorOnly: false };
  const majOnly = str.match(/^[~^>=<\s]*(\d+)(?:[-a-zA-Z]|$)/);
  if (majOnly) return { major: Number(majOnly[1]), minor: null, patch: null, majorOnly: true };
  return null;
}

function checkPhp2ShellVersion(verStr) {
  const raw = String(verStr).trim();
  if (/^latest\b|^alpine\b|^fpm\b|^apache\b|^cli\b/i.test(raw)) {
    return { vulnerable: true, reason: `Unpinned PHP tag '${raw}' — must pin >= 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 against PHP2Shell (CVE-2026-109618 / CVE-2026-109619)` };
  }
  const v = parseSemver(raw);
  if (!v) return { vulnerable: null, reason: `Could not parse PHP version '${raw}'` };
  if (v.major < 8) {
    return { vulnerable: true, reason: `PHP ${v.major}.x is EOL and vulnerable to PHP2Shell (CVE-2026-109618 / CVE-2026-109619)` };
  }
  if (v.majorOnly) {
    return { vulnerable: true, reason: `Major-only PHP tag '${raw}' — pin exact version >= 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 against PHP2Shell` };
  }
  if (v.major === 8 && v.minor <= 1) {
    return { vulnerable: true, reason: `PHP 8.${v.minor}.${v.patch} is EOL and vulnerable to PHP2Shell (CVE-2026-109618 / CVE-2026-109619)` };
  }
  const minPatched = { 2: 35, 3: 36, 4: 27, 5: 12 };
  if (v.major === 8 && minPatched[v.minor] !== undefined) {
    if (v.patch < minPatched[v.minor]) {
      return {
        vulnerable: true,
        reason: `PHP 8.${v.minor}.${v.patch} < 8.${v.minor}.${minPatched[v.minor]} (Vulnerable to PHP2Shell CVE-2026-109618 / CVE-2026-109619)`
      };
    }
    return { vulnerable: false, reason: `PHP 8.${v.minor}.${v.patch} meets minimum patch 8.${v.minor}.${minPatched[v.minor]}` };
  }
  return { vulnerable: false, reason: `PHP ${v.major}.${v.minor}.${v.patch} detected` };
}

function checkNextJsCve202529927(verStr) {
  const raw = String(verStr).trim();
  if (raw === 'latest' || raw === '*') {
    return `Unpinned Next.js version '${raw}' — verify installed lockfile version >= 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 against CVE-2025-29927`;
  }
  const v = parseSemver(raw);
  if (!v) return null;
  if (v.major < 12) return `Next.js ${v.major}.x is EOL and vulnerable to CVE-2025-29927`;
  if (v.majorOnly && v.major <= 15) {
    return `Major-only Next.js range '${raw}' — verify lockfile version >= 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 against CVE-2025-29927`;
  }
  const { major: maj, minor: min, patch } = v;
  if (maj === 12 && (min < 3 || (min === 3 && patch < 5))) return `Next.js ${maj}.${min}.${patch} < 12.3.5 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  if (maj === 13 && (min < 5 || (min === 5 && patch < 9))) return `Next.js ${maj}.${min}.${patch} < 13.5.9 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  if (maj === 14 && (min < 2 || (min === 2 && patch < 25))) return `Next.js ${maj}.${min}.${patch} < 14.2.25 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  if (maj === 15 && (min < 2 || (min === 2 && patch < 3))) return `Next.js ${maj}.${min}.${patch} < 15.2.3 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  return null;
}

function maskSensitiveSnippet(snippet) {
  return snippet.replace(
    /((?:SECRET|PRIVATE|PASSWORD|TOKEN|KEY|SERVICE_ROLE|DATABASE_URL)[A-Z0-9_]*\s*[:=]\s*['"`])([^'"`\s]{10,})(['"`])/gi,
    (_, prefix, val, suffix) => `${prefix}${val.slice(0, 4)}****${val.slice(-4)}${suffix}`
  );
}

function isCommentLine(trimmed, ext) {
  if (!trimmed) return true;
  if (ext === '.sql') return trimmed.startsWith('--');
  if (ext === '.py' || ext === '.yml' || ext === '.yaml' || ext === '.conf' || ext === '.htaccess') {
    return trimmed.startsWith('#');
  }
  return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

let skippedLargeFiles = 0;

function walkFiles(dir, fileList = [], depth = 0) {
  if (depth > MAX_DEPTH) return fileList;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return fileList;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, fileList, depth + 1);
    } else if (
      CODE_EXTENSIONS.has(path.extname(entry.name).toLowerCase()) ||
      entry.name.startsWith('Dockerfile') ||
      entry.name.startsWith('.env.example')
    ) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

function resolveNpmLockedVersion(pkgName) {
  const lockPath = path.join(targetDir, 'package-lock.json');
  if (!fs.existsSync(lockPath)) return null;
  try {
    const stat = fs.statSync(lockPath);
    if (stat.size > 10 * 1024 * 1024) return null;
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    if (lock.packages && lock.packages[`node_modules/${pkgName}`]?.version) {
      return lock.packages[`node_modules/${pkgName}`].version;
    }
    if (lock.dependencies && lock.dependencies[pkgName]?.version) {
      return lock.dependencies[pkgName].version;
    }
  } catch {
    return null;
  }
  return null;
}

function resolveComposerLockedMap() {
  const lockPath = path.join(targetDir, 'composer.lock');
  const map = {};
  if (!fs.existsSync(lockPath)) return map;
  try {
    const stat = fs.statSync(lockPath);
    if (stat.size > 10 * 1024 * 1024) return map;
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    for (const pkg of [...(lock.packages || []), ...(lock['packages-dev'] || [])]) {
      if (pkg?.name && pkg?.version) map[pkg.name] = pkg.version;
    }
  } catch {
    return map;
  }
  return map;
}

console.log(`=== 360° STATIC SECURITY & ARCHITECTURE RECON: ${targetDir} ===\n`);

const detectedStack = new Set();
const hits = [];
const entryPoints = {
  routesAndControllers: [],
  serverActions: [],
  middlewares: [],
  webhooks: []
};

// 0. Check git-tracked secret files (git ls-files)
if (fs.existsSync(path.join(targetDir, '.git'))) {
  try {
    const trackedOut = execFileSync('git', ['ls-files'], {
      cwd: targetDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    for (const trackedFile of trackedOut.split(/\r?\n/)) {
      const clean = trackedFile.trim();
      if (!clean) continue;
      const base = path.basename(clean);
      const isExampleEnv = /^\.env\.(example|sample|template|dist|test)$/i.test(base);
      const isTrackedSecret =
        (/^\.env(\..+)?$/i.test(base) && !isExampleEnv) ||
        /\.(pem|key|p12|pfx|keystore)$/i.test(base) ||
        /^(id_rsa|id_ed25519)$/i.test(base) ||
        /service[-_]?account.*\.json$/i.test(base);
      if (isTrackedSecret) {
        hits.push({
          id: 'GIT_TRACKED_SECRET_FILE',
          severity: 'CRITICAL',
          domain: 'Secret File Tracked in Git (A02)',
          cwe: 'CWE-540',
          location: `${clean}:L1`,
          snippet: `Sensitive credential/key file '${clean}' is tracked in Git index`
        });
      }
    }
  } catch {
    // git CLI unavailable or not a valid git worktree
  }
}

// 1. Check composer.json / composer.lock & local PHP runtime
const composerPath = path.join(targetDir, 'composer.json');
if (fs.existsSync(composerPath)) {
  detectedStack.add('PHP / Composer');
  const composerLocked = resolveComposerLockedMap();
  try {
    const comp = JSON.parse(fs.readFileSync(composerPath, 'utf8'));
    const allDeps = { ...(comp.require || {}), ...(comp['require-dev'] || {}), ...composerLocked };
    if (allDeps['laravel/framework']) detectedStack.add(`Laravel (${allDeps['laravel/framework']})`);
    if (allDeps['livewire/livewire']) detectedStack.add(`Livewire (${allDeps['livewire/livewire']})`);
    if (allDeps['facade/ignition']) {
      hits.push({
        id: 'LARAVEL_IGNITION_CVE',
        severity: 'CRITICAL',
        domain: 'Laravel Ignition RCE (CVE-2021-3129)',
        cwe: 'CWE-502',
        location: 'composer.json:L1',
        snippet: `Legacy 'facade/ignition' (${allDeps['facade/ignition']}) detected — upgrade to spatie/laravel-ignition`
      });
    }
  } catch {
    // ignore malformed composer.json
  }

  try {
    const phpOut = execFileSync('php', ['-v'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\n')[0];
    const check = checkPhp2ShellVersion(phpOut);
    console.log(`[RUNTIME] Local PHP: ${phpOut}`);
    console.log(`          PHP2Shell Status: ${check.vulnerable ? 'CRITICAL VULNERABLE' : 'OK'} — ${check.reason}\n`);
    if (check.vulnerable) {
      hits.push({
        id: 'PHP2SHELL_RUNTIME',
        severity: 'CRITICAL',
        domain: 'PHP Core Engine RCE (CVE-2026-109618/109619)',
        cwe: 'CWE-119',
        location: 'Runtime (php -v)',
        snippet: check.reason
      });
    }
  } catch {
    console.log(`[RUNTIME] composer.json detected, but 'php' CLI is not in PATH.\n`);
  }
}

// 2. Check package.json / package-lock.json & dependencies
const pkgJsonPath = path.join(targetDir, 'package.json');
if (fs.existsSync(pkgJsonPath)) {
  detectedStack.add('Node.js / npm');
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (allDeps.next) {
      const resolvedNext = resolveNpmLockedVersion('next') || allDeps.next;
      detectedStack.add(`Next.js (${resolvedNext})`);
      const nextVuln = checkNextJsCve202529927(resolvedNext);
      if (nextVuln) {
        hits.push({
          id: 'NEXTJS_MIDDLEWARE_CVE',
          severity: 'CRITICAL',
          domain: 'Next.js Auth Bypass (CVE-2025-29927)',
          cwe: 'CWE-287',
          location: fs.existsSync(path.join(targetDir, 'package-lock.json')) ? 'package-lock.json:L1' : 'package.json:L1',
          snippet: nextVuln
        });
      }
    }
    if (allDeps.react) detectedStack.add('React');
    if (allDeps.express) detectedStack.add('Express');
    if (allDeps['@nestjs/core']) detectedStack.add('NestJS');
    if (allDeps['@prisma/client'] || allDeps.prisma) detectedStack.add('Prisma ORM');
    if (allDeps['drizzle-orm']) detectedStack.add('Drizzle ORM');
    if (allDeps['@supabase/supabase-js']) detectedStack.add('Supabase');
    if (allDeps.firebase || allDeps['firebase-admin']) detectedStack.add('Firebase');
    if (allDeps.stripe) detectedStack.add('Stripe');
    if (allDeps.openai || allDeps['@anthropic-ai/sdk'] || allDeps['@google/generative-ai'] || allDeps.ai) {
      detectedStack.add('AI / LLM SDK');
    }
  } catch {
    // ignore malformed package.json
  }
}

// 3. Walk files and perform structural + cross-migration RLS + line-level sink analysis
const files = walkFiles(targetDir);
const sqlCreatedTables = new Map(); // tableName -> relPath:line
const sqlRlsEnabledTables = new Set();

for (const file of files) {
  const relPath = path.relative(targetDir, file).replace(/\\/g, '/');
  const baseName = path.basename(file);
  const ext = path.extname(file).toLowerCase();

  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    continue;
  }
  if (stat.size > MAX_FILE_BYTES) {
    skippedLargeFiles++;
    continue;
  }

  let content = '';
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    continue;
  }

  // Classify entry point files for negative-control (missing auth/rate-limit) auditing
  if (/(^|\/)(middleware|proxy)\.(ts|js|mjs|php|py)$/i.test(relPath) || /Middleware\.php$/i.test(relPath)) {
    entryPoints.middlewares.push(relPath);
  }
  if (/webhook/i.test(relPath)) {
    entryPoints.webhooks.push(relPath);
  }
  if (/\/api\/|routes\/|controllers\/|route\.(ts|js)$/i.test(relPath)) {
    entryPoints.routesAndControllers.push(relPath);
  }
  if (/^\s*['"]use server['"]/m.test(content)) {
    entryPoints.serverActions.push(relPath);
  }

  // Structural check 1: Multi-stage Dockerfile checks (PHP2Shell & Final-Stage USER)
  if (baseName.startsWith('Dockerfile')) {
    detectedStack.add('Docker');
    const fromPhpMatches = content.matchAll(/^\s*FROM\s+php:([^\s#]+)/gim);
    for (const match of fromPhpMatches) {
      const check = checkPhp2ShellVersion(match[1]);
      if (check.vulnerable) {
        hits.push({
          id: 'PHP2SHELL_IMAGE',
          severity: 'CRITICAL',
          domain: 'PHP Core Engine RCE (CVE-2026-109618/109619)',
          cwe: 'CWE-1104',
          location: `${relPath}:L1`,
          snippet: `FROM php:${match[1]} (${check.reason})`
        });
      }
    }

    const stages = content.split(/^\s*FROM\s+/im).slice(1);
    const finalStage = stages.length > 0 ? stages[stages.length - 1] : content;
    const userDirectives = [...finalStage.matchAll(/^\s*USER\s+([^\s#]+)/gim)].map((m) => m[1].trim());
    const effectiveUser = userDirectives.length > 0 ? userDirectives[userDirectives.length - 1] : null;
    if (!effectiveUser || /^(root|0(?::0)?)$/i.test(effectiveUser)) {
      hits.push({
        id: 'DOCKER_ROOT_USER',
        severity: 'MEDIUM',
        domain: 'Container Final Stage Runs as Root (INF)',
        cwe: 'CWE-250',
        location: `${relPath}:L1`,
        snippet: effectiveUser
          ? `Final Dockerfile stage ends with 'USER ${effectiveUser}'`
          : 'Final Dockerfile stage lacks a non-root USER instruction before CMD/ENTRYPOINT'
      });
    }
  }

  // Structural check 2: Collect per-table CREATE TABLE vs ENABLE ROW LEVEL SECURITY in Supabase migrations
  if (ext === '.sql' && /supabase\/migrations/i.test(relPath)) {
    detectedStack.add('Supabase SQL Migrations');
    const createMatches = content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["`]?([a-zA-Z0-9_]+)["`]?/gi);
    for (const m of createMatches) {
      const tbl = m[1].toLowerCase();
      if (!sqlCreatedTables.has(tbl)) sqlCreatedTables.set(tbl, `${relPath}:L1`);
    }
    const rlsMatches = content.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?:public\.)?["`]?([a-zA-Z0-9_]+)["`]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi);
    for (const m of rlsMatches) {
      sqlRlsEnabledTables.add(m[1].toLowerCase());
    }
  }

  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 500) continue;
    const trimmed = line.trim();
    if (isCommentLine(trimmed, ext)) continue;

    for (const pattern of SINK_PATTERNS) {
      if (pattern.regex.test(line)) {
        hits.push({
          id: pattern.id,
          severity: pattern.severity,
          domain: pattern.domain,
          cwe: pattern.cwe,
          location: `${relPath}:L${i + 1}`,
          snippet: maskSensitiveSnippet(trimmed.slice(0, 140))
        });
      }
    }
  }
}

for (const [tbl, loc] of sqlCreatedTables.entries()) {
  if (!sqlRlsEnabledTables.has(tbl)) {
    hits.push({
      id: 'SUPABASE_MISSING_RLS',
      severity: 'CRITICAL',
      domain: 'Supabase Table Missing RLS (A01)',
      cwe: 'CWE-284',
      location: loc,
      snippet: `Table 'public.${tbl}' is created without ALTER TABLE ... ENABLE ROW LEVEL SECURITY across migrations`
    });
  }
}

const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
hits.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
for (const h of hits) counts[h.severity] = (counts[h.severity] || 0) + 1;

console.log(`[STACK] Detected Technologies: ${detectedStack.size ? Array.from(detectedStack).join(', ') : 'Generic / Custom'}`);
console.log(
  `[SURFACE] Files Scanned: ${files.length}` +
  (skippedLargeFiles ? ` (Skipped >2MB: ${skippedLargeFiles})` : '') +
  ` | Routes/Controllers: ${entryPoints.routesAndControllers.length}` +
  ` | Server Actions: ${entryPoints.serverActions.length}` +
  ` | Middlewares: ${entryPoints.middlewares.length}` +
  ` | Webhooks: ${entryPoints.webhooks.length}`
);

const allEntryFiles = [
  ...entryPoints.middlewares.map((f) => `[Middleware] ${f}`),
  ...entryPoints.webhooks.map((f) => `[Webhook] ${f}`),
  ...entryPoints.serverActions.map((f) => `[ServerAction] ${f}`),
  ...entryPoints.routesAndControllers.map((f) => `[Route/Ctrl] ${f}`)
];
if (allEntryFiles.length > 0) {
  console.log(`\n[ENTRY_POINTS] Mandatory Auth/AuthZ/Validation/Rate-Limit Review Checklist (${allEntryFiles.length} file(s)):`);
  for (const ep of allEntryFiles.slice(0, 60)) {
    console.log(`  - ${ep}`);
  }
  if (allEntryFiles.length > 60) {
    console.log(`  ...and ${allEntryFiles.length - 60} more entry-point file(s).`);
  }
}

console.log(`\n[SUMMARY] Candidate Sinks & Issues Found: ${hits.length} (CRITICAL: ${counts.CRITICAL} | HIGH: ${counts.HIGH} | MEDIUM: ${counts.MEDIUM})\n`);

for (const hit of hits.slice(0, 120)) {
  console.log(`- [${hit.severity}] [${hit.id}] (${hit.domain} | ${hit.cwe}) @ ${hit.location}`);
  console.log(`    ${hit.snippet}`);
}
if (hits.length > 120) {
  console.log(`\n...and ${hits.length - 120} additional candidate sink(s).`);
}
