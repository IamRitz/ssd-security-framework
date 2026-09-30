// Runs `npm audit` once per npm dependency root (dependency-roots.mjs) and
// writes one report per root for the source gate.
//
//   node npm-audit-roots.mjs [--repo-dir .] [--output-dir reports]
//
// Per root, exactly:
//
//   npm audit --json --package-lock-only --prefix <root>     (cwd: <root>)
//
// --package-lock-only: reads the lockfile; installs nothing, runs no lifecycle
// script, writes no file. --prefix is REQUIRED, not cosmetic: without it npm
// walks up from the working directory and, for a root with no package.json of
// its own or one that is an npm workspace member, silently audits the ANCESTOR
// project instead (verified with npm 10). The process is started with execFile
// — an argument vector, never a shell — so a repository path is never parsed as
// shell syntax.
//
// Reports:
//   <output>/npm-audit.json         the repository-root project, byte-for-byte
//                                   what npm wrote (unchanged contract)
//   <output>/npm-audit-nested.json  every root below the repository root:
//                                   { schemaVersion, scanner, roots: [
//                                     { root, lockfile, status, attempts,
//                                       report, error? } ] }
//
// Isolation: every root is audited even when another fails, and each keeps its
// own report and status, so one malformed project can neither suppress another's
// findings nor hide its own failure. The process exits 1 when ANY root failed,
// or when any root was refused as unsafe: missing evidence is never success.
// The gate independently re-derives the roots and requires a valid report for
// each (security-gate.mjs), so a root this script skipped fails closed there too.
import { execFile } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { discoverNpmRoots } from './dependency-roots.mjs';
import { validateNpmAuditReport } from './validate-dependency-report.mjs';

export const NESTED_REPORT = 'npm-audit-nested.json';
export const ROOT_REPORT = 'npm-audit.json';
export const NESTED_SCHEMA_VERSION = 1;

export function npmAuditArguments(prefix) {
  return ['audit', '--json', '--package-lock-only', '--prefix', prefix];
}

// Default process seam: npm with an argument vector and an explicit cwd.
// Resolves with the exit status and stdout whatever the status: npm audit exits
// 1 when it finds vulnerabilities, so the REPORT, not the status, is judged.
export function runNpm(args, { cwd }) {
  return new Promise((resolvePromise) => {
    execFile(
      'npm',
      args,
      { cwd, maxBuffer: 256 * 1024 * 1024, timeout: 10 * 60 * 1000, shell: false },
      (error, stdout, stderr) => {
        const status = error ? (typeof error.code === 'number' ? error.code : 1) : 0;
        resolvePromise({ status, stdout: stdout ?? '', stderr: stderr ?? '', spawnError: error && typeof error.code !== 'number' ? String(error.message) : null });
      }
    );
  });
}

const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

// Audits ONE root with bounded retries (a registry hiccup produces an invalid
// report; a retry is how the previous single-root step handled it too).
async function auditRoot(repoRoot, entry, { runAudit, attempts, retryDelayMs, log }) {
  const directory = entry.root === '.' ? repoRoot : join(repoRoot, ...entry.root.split('/'));
  let last = { raw: '', error: 'npm audit did not run' };
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const result = await runAudit(npmAuditArguments(directory), { cwd: directory, root: entry.root });
    const raw = typeof result?.stdout === 'string' ? result.stdout : '';
    try {
      const report = JSON.parse(raw);
      const summary = validateNpmAuditReport(report);
      log(`npm audit [${entry.root}] ${entry.lockfile}: ${summary} (scanner exit ${result?.status})`);
      return { status: 'valid', attempts: attempt, report, raw };
    } catch (error) {
      const why = raw.trim() === '' ? `no report written${result?.spawnError ? ` (${result.spawnError})` : ''}` : error.message;
      last = { raw, error: why };
      log(`npm audit [${entry.root}] attempt ${attempt} produced no valid report: ${why}`);
      if (attempt < attempts) {
        await sleep(retryDelayMs);
      }
    }
  }
  return { status: 'invalid', attempts, report: null, raw: last.raw, error: last.error };
}

export async function auditNpmRoots({
  repoDir = '.',
  outputDir = 'reports',
  runAudit = runNpm,
  attempts = 3,
  retryDelayMs = 15000,
  log = console.log
} = {}) {
  const repoRoot = resolve(repoDir);
  const { roots, rejected } = await discoverNpmRoots(repoRoot);
  await mkdir(outputDir, { recursive: true });
  // Never leave a stale report from an earlier invocation to stand in for this one.
  await rm(join(outputDir, ROOT_REPORT), { force: true });
  await rm(join(outputDir, NESTED_REPORT), { force: true });

  for (const entry of rejected) {
    log(`npm audit REFUSED ${entry.path}: ${entry.reason}`);
  }
  if (roots.length === 0) {
    log('No npm dependency roots (tracked package-lock.json / npm-shrinkwrap.json); npm audit skipped. OSV-Scanner still runs.');
  }

  const results = [];
  for (const entry of roots) {
    results.push({ ...entry, ...(await auditRoot(repoRoot, entry, { runAudit, attempts, retryDelayMs, log })) });
  }

  const top = results.find((entry) => entry.root === '.');
  if (top) {
    // Exactly what npm wrote, as the single-root step always did; an invalid
    // report stays invalid for the gate to reject.
    await writeFile(join(outputDir, ROOT_REPORT), top.raw);
  }
  const nested = results.filter((entry) => entry.root !== '.');
  if (nested.length > 0 || rejected.length > 0) {
    const record = {
      schemaVersion: NESTED_SCHEMA_VERSION,
      scanner: 'npm-audit',
      roots: nested.map(({ root, lockfile, status, attempts: tries, report, error }) => ({
        root,
        lockfile,
        status,
        attempts: tries,
        report,
        ...(error ? { error } : {})
      })),
      ...(rejected.length > 0 ? { rejected } : {})
    };
    await writeFile(join(outputDir, NESTED_REPORT), `${JSON.stringify(record, null, 2)}\n`);
  }

  const failed = results.filter((entry) => entry.status !== 'valid');
  return { roots: results, rejected, ok: failed.length === 0 && rejected.length === 0 };
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--repo-dir' && value) {
      options.repoDir = value;
    } else if (flag === '--output-dir' && value) {
      options.outputDir = value;
    } else {
      throw new Error(`unknown or incomplete argument ${flag}`);
    }
    index += 1;
  }
  const delay = process.env.SSD_NPM_AUDIT_RETRY_DELAY_MS;
  if (delay !== undefined && /^\d+$/.test(delay)) {
    options.retryDelayMs = Number(delay);
  }
  return options;
}

async function main() {
  let result;
  try {
    result = await auditNpmRoots(parseArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(`NPM AUDIT FAILED: ${error.message}`);
    process.exitCode = 1;
    return;
  }
  const failed = result.roots.filter((entry) => entry.status !== 'valid');
  for (const entry of failed) {
    console.error(`NPM AUDIT FAILED for dependency root '${entry.root}' (${entry.lockfile}): ${entry.error}`);
  }
  if (result.rejected.length > 0) {
    console.error(`NPM AUDIT FAILED: ${result.rejected.length} dependency root(s) refused as unsafe; they are audited by nothing.`);
  }
  if (result.ok) {
    console.log(`npm audit produced a valid report for ${result.roots.length} dependency root(s).`);
  }
  process.exitCode = result.ok ? 0 : 1;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
