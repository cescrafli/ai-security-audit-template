#!/usr/bin/env node
/**
 * 360° Defensive Static Security, Architecture & Runtime CVE Recon Scanner
 * Usage: node .agents/skills/audit-website-security/scripts/audit-recon.mjs <target-project-path>
 *
 * Performs a read-only, non-destructive static inventory of:
 * 1. Tech stack, frameworks, BaaS/payment integrations, infrastructure & entry-point counts
 * 2. Runtime & framework CVE checks (PHP2Shell CVE-2026-109618 / CVE-2026-109619, Next.js CVE-2025-29927, Laravel Ignition CVE-2021-3129)
 * 3. File-level structural checks (SQL tables missing ENABLE ROW LEVEL SECURITY, Dockerfile running as root)
 * 4. High-signal source code sinks grouped by severity (CRITICAL, HIGH, MEDIUM) for Source-to-Sink Taint Tracing
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const targetDir = path.resolve(process.argv[2] || process.cwd());

if (!fs.existsSync(targetDir)) {
  console.error(`[ERROR] Target path does not exist: ${targetDir}`);
  process.exit(1);
}

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
  { id: 'EXPOSED_DB_PORT', severity: 'HIGH', domain: 'Public DB/Cache Port Binding (INF)', cwe: 'CWE-668', regex: /['"]?(0\.0\.0\.0:)?(5432:5432|3306:3306|6379:6379|27017:27017|9200:9200)['"]?/ },
  { id: 'PDF_HEADLESS_SSRF', severity: 'HIGH', domain: 'PDF/Headless Browser SSRF & LFI (A10)', cwe: 'CWE-918', regex: /\b(wkhtmltopdf|puppeteer\.launch|playwright\.chromium|dompdf|Browsershot)/i },
  { id: 'BUFFER_UNSAFE_MEM', severity: 'HIGH', domain: 'Uninitialized Heap Memory Leak (A02)', cwe: 'CWE-908', regex: /\b(Buffer\.allocUnsafe(Slow)?\s*\(|new\s+Buffer\s*\()/ },
  { id: 'PHP_TYPE_JUGGLE', severity: 'HIGH', domain: 'Type Juggling / Loose Auth Check (A07)', cwe: 'CWE-843', regex: /(strcmp\s*\([^)]*\$_(GET|POST|REQUEST)|(\$password|\$token|\$otp|\$hash|\$signature)\s*==\s*[^=])/i },
  { id: 'UPLOAD_ORIG_NAME', severity: 'HIGH', domain: 'Unsafe Upload Filename / Webshell Risk (A08)', cwe: 'CWE-434', regex: /\b(getClientOriginalName\s*\(|getClientOriginalExtension\s*\(|move_uploaded_file\s*\()/ },
  { id: 'XXE_PARSER', severity: 'HIGH', domain: 'XML External Entity — XXE (A05)', cwe: 'CWE-611', regex: /\b(LIBXML_NOENT|LIBXML_DTDLOAD|simplexml_load_string|DOMDocument|etree\.fromstring)/ },
  { id: 'CLI_ARG_SPAWN', severity: 'HIGH', domain: 'CLI Argument Injection Check (A03)', cwe: 'CWE-88', regex: /\b(execFile| execFileSync|child_process\.spawn|spawnSync)\s*\(/ },

  // MEDIUM
  { id: 'WEAK_CRYPTO_RNG', severity: 'MEDIUM', domain: 'Weak Hashing / Predictable RNG (A02)', cwe: 'CWE-330/916', regex: /\b(Math\.random\s*\(|mt_rand\s*\(|md5\s*\(|sha1\s*\()/ },
  { id: 'STORAGE_TOKEN', severity: 'MEDIUM', domain: 'Token in localStorage/sessionStorage (DOM)', cwe: 'CWE-922', regex: /(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*['"][^'"]*(token|jwt|auth|secret|session)/i },
  { id: 'OUTBOUND_HTTP', severity: 'MEDIUM', domain: 'Outbound HTTP (Verify SSRF & Timeout)', cwe: 'CWE-918/400', regex: /\b(fetch\s*\(|axios\.(get|post|put|delete|request)\s*\(|Http::(get|post)\s*\(|curl_exec\s*\(|requests\.(get|post)\s*\()/ },
  { id: 'WP_EXPOSURE', severity: 'MEDIUM', domain: 'WordPress Hardening Check (A05)', cwe: 'CWE-284', regex: /(xmlrpc\.php|wp-json\/wp\/v2\/users|DISALLOW_FILE_EDIT['"]?\s*,\s*false)/i },
  { id: 'POSTMESSAGE_WILDCARD', severity: 'MEDIUM', domain: 'Insecure postMessage Origin (DOM)', cwe: 'CWE-346', regex: /(\.postMessage\s*\([^,]+,\s*['"]\*['"]|addEventListener\s*\(\s*['"]message['"])/ }
];

function parseSemver(verStr) {
  const m = String(verStr).match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] || 0)] : null;
}

function checkPhp2ShellVersion(verStr) {
  const v = parseSemver(verStr);
  if (!v) return { vulnerable: null, reason: 'Could not parse PHP version' };
  const [maj, min, patch] = v;
  if (maj < 8 || (maj === 8 && min <= 1)) {
    return { vulnerable: true, reason: `PHP ${maj}.${min}.${patch} is EOL and vulnerable to PHP2Shell (CVE-2026-109618 / CVE-2026-109619)` };
  }
  const minPatched = { 2: 35, 3: 36, 4: 27, 5: 12 };
  if (maj === 8 && minPatched[min] !== undefined) {
    if (patch < minPatched[min]) {
      return {
        vulnerable: true,
        reason: `PHP ${maj}.${min}.${patch} is below 8.${min}.${minPatched[min]} and vulnerable to PHP2Shell (CVE-2026-109618 / CVE-2026-109619)`
      };
    }
    return { vulnerable: false, reason: `PHP ${maj}.${min}.${patch} meets minimum patch 8.${min}.${minPatched[min]}` };
  }
  return { vulnerable: false, reason: `PHP ${maj}.${min}.${patch} detected` };
}

function checkNextJsCve202529927(verStr) {
  const v = parseSemver(verStr);
  if (!v) return null;
  const [maj, min, patch] = v;
  if (maj < 12) return `Next.js ${maj}.${min}.${patch} is EOL and vulnerable to CVE-2025-29927`;
  if (maj === 12 && (min < 3 || (min === 3 && patch < 5))) return `Next.js ${maj}.${min}.${patch} < 12.3.5 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  if (maj === 13 && (min < 5 || (min === 5 && patch < 9))) return `Next.js ${maj}.${min}.${patch} < 13.5.9 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  if (maj === 14 && (min < 2 || (min === 2 && patch < 25))) return `Next.js ${maj}.${min}.${patch} < 14.2.25 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  if (maj === 15 && (min < 2 || (min === 2 && patch < 3))) return `Next.js ${maj}.${min}.${patch} < 15.2.3 (Vulnerable to CVE-2025-29927 Middleware Auth Bypass)`;
  return null;
}

function isCommentLine(trimmed, ext) {
  if (!trimmed) return true;
  if (ext === '.sql') return trimmed.startsWith('--');
  if (ext === '.py' || ext === '.yml' || ext === '.yaml' || ext === '.conf' || ext === '.htaccess') {
    return trimmed.startsWith('#');
  }
  return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

function walkFiles(dir, fileList = []) {
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return fileList;
  }
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, fileList);
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

console.log(`=== 360° STATIC SECURITY & ARCHITECTURE RECON: ${targetDir} ===\n`);

const detectedStack = new Set();
const hits = [];
let entryPointCounts = { apiRoutes: 0, serverActions: 0, webhooks: 0, sqlMigrations: 0 };

// 1. Check composer.json & local PHP runtime
const composerPath = path.join(targetDir, 'composer.json');
if (fs.existsSync(composerPath)) {
  detectedStack.add('PHP / Composer');
  try {
    const comp = JSON.parse(fs.readFileSync(composerPath, 'utf8'));
    const allDeps = { ...(comp.require || {}), ...(comp['require-dev'] || {}) };
    if (allDeps['laravel/framework']) detectedStack.add(`Laravel (${allDeps['laravel/framework']})`);
    if (allDeps['livewire/livewire']) detectedStack.add(`Livewire (${allDeps['livewire/livewire']})`);
    if (allDeps['facade/ignition']) {
      hits.push({
        id: 'LARAVEL_IGNITION_CVE',
        severity: 'CRITICAL',
        domain: 'Laravel Ignition RCE (CVE-2021-3129)',
        cwe: 'CWE-502',
        location: 'composer.json:1',
        snippet: `Legacy 'facade/ignition' (${allDeps['facade/ignition']}) detected — upgrade to spatie/laravel-ignition`
      });
    }
  } catch {
    // ignore malformed composer.json
  }

  try {
    const phpOut = execSync('php -v', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\n')[0];
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

// 2. Check package.json & dependencies
const pkgJsonPath = path.join(targetDir, 'package.json');
if (fs.existsSync(pkgJsonPath)) {
  detectedStack.add('Node.js / npm');
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (allDeps.next) {
      detectedStack.add(`Next.js (${allDeps.next})`);
      const nextVuln = checkNextJsCve202529927(allDeps.next);
      if (nextVuln) {
        hits.push({
          id: 'NEXTJS_MIDDLEWARE_CVE',
          severity: 'CRITICAL',
          domain: 'Next.js Auth Bypass (CVE-2025-29927)',
          cwe: 'CWE-287',
          location: 'package.json:1',
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

// 3. Walk files and perform structural + line-level sink analysis
const files = walkFiles(targetDir);

for (const file of files) {
  const relPath = path.relative(targetDir, file).replace(/\\/g, '/');
  const baseName = path.basename(file);
  const ext = path.extname(file).toLowerCase();
  let content = '';
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    continue;
  }

  // Count entry points
  if (/\/api\/|routes\/|controllers\//i.test(relPath)) entryPointCounts.apiRoutes++;
  if (/['"]use server['"]/.test(content)) entryPointCounts.serverActions++;
  if (/webhook/i.test(relPath)) entryPointCounts.webhooks++;

  // Structural check 1: Dockerfile checks (PHP2Shell & Missing USER non-root)
  if (baseName.startsWith('Dockerfile')) {
    detectedStack.add('Docker');
    const fromPhp = content.match(/FROM\s+php:([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
    if (fromPhp) {
      const check = checkPhp2ShellVersion(fromPhp[1]);
      if (check.vulnerable) {
        hits.push({
          id: 'PHP2SHELL_IMAGE',
          severity: 'CRITICAL',
          domain: 'PHP Core Engine RCE (CVE-2026-109618/109619)',
          cwe: 'CWE-1104',
          location: `${relPath}:L1`,
          snippet: `${fromPhp[0]} (${check.reason})`
        });
      }
    }
    if (!/^\s*USER\s+(?!root\b)\S+/m.test(content)) {
      hits.push({
        id: 'DOCKER_ROOT_USER',
        severity: 'MEDIUM',
        domain: 'Container Runs as Root (INF)',
        cwe: 'CWE-250',
        location: `${relPath}:L1`,
        snippet: 'Dockerfile lacks a non-root USER instruction before CMD/ENTRYPOINT'
      });
    }
  }

  // Structural check 2: SQL migration creating tables without ENABLE ROW LEVEL SECURITY
  if (ext === '.sql' && /supabase\/migrations/i.test(relPath)) {
    entryPointCounts.sqlMigrations++;
    if (/CREATE\s+TABLE\b/i.test(content) && !/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(content)) {
      hits.push({
        id: 'SUPABASE_MISSING_RLS',
        severity: 'CRITICAL',
        domain: 'Supabase Table Missing RLS (A01)',
        cwe: 'CWE-284',
        location: `${relPath}:L1`,
        snippet: 'SQL migration creates table(s) without ALTER TABLE ... ENABLE ROW LEVEL SECURITY'
      });
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
          snippet: trimmed.slice(0, 140)
        });
      }
    }
  }
}

const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
hits.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
for (const h of hits) counts[h.severity] = (counts[h.severity] || 0) + 1;

console.log(`[STACK] Detected Technologies: ${detectedStack.size ? Array.from(detectedStack).join(', ') : 'Generic / Custom'}`);
console.log(`[SURFACE] Files Scanned: ${files.length} | Route/Controller Files: ${entryPointCounts.apiRoutes} | Server Action Files: ${entryPointCounts.serverActions} | Webhook Files: ${entryPointCounts.webhooks}`);
console.log(`[SUMMARY] Candidate Sinks Found: ${hits.length} (CRITICAL: ${counts.CRITICAL} | HIGH: ${counts.HIGH} | MEDIUM: ${counts.MEDIUM})\n`);

for (const hit of hits.slice(0, 120)) {
  console.log(`- [${hit.severity}] [${hit.id}] (${hit.domain} | ${hit.cwe}) @ ${hit.location}`);
  console.log(`    ${hit.snippet}`);
}
if (hits.length > 120) {
  console.log(`\n...and ${hits.length - 120} additional candidate sink(s).`);
}
