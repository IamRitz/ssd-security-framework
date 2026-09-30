// OSV-Scanner over EXACTLY the lockfiles of the npm dependency roots
// (dependency-roots.mjs), each named explicitly:
//
//   docker run --rm -v <checkout>:/repo:ro <pinned image> \
//     scan source --allow-no-lockfiles --format=json \
//     -L package-lock.json:/repo/<lockfile>  [-L ... per root]
//
//   node osv-npm-roots.mjs --image <pinned image> [--repo-dir .] [--output-dir reports]
//
// WHY A SECOND, EXPLICIT SCAN. The recursive OSV-Scanner step (the
// cross-ecosystem backstop, unchanged) honours .gitignore even for TRACKED
// files: a force-added, gitignored package-lock.json — OWASP Juice Shop's
// layout — is skipped by it (verified against the pinned digest). Turning that
// filtering off globally would let the scanner's own walk decide the dependency
// inventory. Instead the inventory is the framework's: the tracked, confined
// lockfiles discoverNpmRoots() returns, named one by one. A file the discovery
// does not return is never passed here, so an untracked lockfile can never be
// scanned into trust by this step.
//
// Pinned-image facts this relies on (tools/verify-scanner-behaviour.mjs § 3):
//   - `-L` reads a tracked lockfile even when .gitignore lists it;
//   - the `package-lock.json:` parse-as prefix is always passed: without it a
//     ':' inside the path is read as a format prefix (`/repo/a:b/...` became
//     format `/repo/a`, path `b/...`); with it the rest of the value is the
//     path verbatim, and it reads npm-shrinkwrap.json too;
//   - `-L` cannot be combined with a directory argument in one invocation
//     (that exits 127), hence a separate run;
//   - a lockfile with no vulnerable package is ABSENT from `results`, so the
//     report cannot show what was scanned — the envelope below declares it.
//
// Output: <output>/osv-scanner-npm-roots.json
//   { schemaVersion: 1, scanner: 'osv-scanner', lockfiles: [<repo paths>],
//     exitCode, report: <OSV JSON> }
// The gate re-derives the roots and requires `lockfiles` to equal them and
// every reported source to be one of them (security-gate.mjs).
//
// The exit status is judged with the report exactly like the recursive step
// (check-scanner-exit.mjs): 0/1 must agree with the findings, anything else
// fails. No npm root: nothing runs, nothing is written, exit 0.
import { execFile } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { assessScannerExit, countReportFindings } from './check-scanner-exit.mjs';
import { discoverNpmRoots } from './dependency-roots.mjs';
import { validateOsvReport } from './validate-dependency-report.mjs';

export const OSV_NPM_REPORT = 'osv-scanner-npm-roots.json';
export const OSV_NPM_SCHEMA_VERSION = 1;
const MOUNT = '/repo';
const PINNED = /^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$/;

// The docker argument vector: every lockfile its own `-L` element, never a
// shell word.
export function osvDockerArguments({ checkout, image, lockfiles }) {
  return [
    'run', '--rm', '-v', `${checkout}:${MOUNT}:ro`, image,
    'scan', 'source', '--allow-no-lockfiles', '--format=json',
    ...lockfiles.flatMap((lockfile) => ['-L', `package-lock.json:${MOUNT}/${lockfile}`])
  ];
}

export function runDocker(args) {
  return new Promise((resolvePromise) => {
    execFile('docker', args, { maxBuffer: 256 * 1024 * 1024, timeout: 20 * 60 * 1000, shell: false }, (error, stdout, stderr) => {
      const status = error ? (typeof error.code === 'number' ? error.code : null) : 0;
      resolvePromise({ status, stdout: stdout ?? '', stderr: stderr ?? '' });
    });
  });
}

export async function scanNpmRootsWithOsv({ repoDir = '.', outputDir = 'reports', image, runScanner = runDocker, log = console.log } = {}) {
  if (typeof image !== 'string' || !PINNED.test(image)) {
    throw new Error(`the OSV-Scanner image must be pinned by digest, got ${JSON.stringify(image)}`);
  }
  const checkout = resolve(repoDir);
  const { roots, rejected } = await discoverNpmRoots(checkout);
  await mkdir(outputDir, { recursive: true });
  await rm(join(outputDir, OSV_NPM_REPORT), { force: true });
  if (rejected.length > 0) {
    return {
      ok: false,
      message: `npm dependency root(s) refused, so OSV-Scanner cannot be pointed at them: ${rejected.map((entry) => `${entry.path} (${entry.reason})`).join('; ')}`
    };
  }
  if (roots.length === 0) {
    return { ok: true, message: 'No npm dependency roots; the explicit OSV-Scanner lockfile scan is skipped.' };
  }
  const lockfiles = roots.map((entry) => entry.lockfile);
  const run = await runScanner(osvDockerArguments({ checkout, image, lockfiles }));
  let report;
  try {
    report = JSON.parse(run.stdout);
    validateOsvReport(report);
  } catch (error) {
    return {
      ok: false,
      message: `OSV-Scanner (npm dependency roots) exited ${run.status} without a valid report: ${run.stdout.trim() === '' ? 'no output' : error.message}. ${run.stderr.trim().split('\n').slice(-3).join(' ')}`
    };
  }
  const verdict = assessScannerExit({ scanner: 'osv-scanner', exitCode: run.status, findingCount: countReportFindings('osv-scanner', report) });
  await writeFile(
    join(outputDir, OSV_NPM_REPORT),
    `${JSON.stringify({ schemaVersion: OSV_NPM_SCHEMA_VERSION, scanner: 'osv-scanner', lockfiles, exitCode: run.status, report }, null, 2)}\n`
  );
  log(`OSV-Scanner read ${lockfiles.length} npm dependency-root lockfile(s): ${lockfiles.join(', ')}`);
  return { ok: verdict.ok, message: verdict.message };
}

function parseArguments(argv) {
  const options = {};
  const names = { '--repo-dir': 'repoDir', '--output-dir': 'outputDir', '--image': 'image' };
  for (let index = 0; index < argv.length; index += 2) {
    const key = names[argv[index]];
    if (!key || argv[index + 1] === undefined) {
      throw new Error(`unknown or incomplete argument ${argv[index]}`);
    }
    options[key] = argv[index + 1];
  }
  return options;
}

async function main() {
  try {
    const result = await scanNpmRootsWithOsv(parseArguments(process.argv.slice(2)));
    (result.ok ? console.log : console.error)(`${result.ok ? '' : 'OSV-SCANNER (NPM ROOTS) FAILED: '}${result.message}`);
    process.exitCode = result.ok ? 0 : 1;
  } catch (error) {
    console.error(`OSV-SCANNER (NPM ROOTS) FAILED: ${error.message}`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
