#!/usr/bin/env node
// Re-verifies, against the framework's PINNED scanner images, the scanner
// behaviour ssd-onboard's coverage model and generated configs depend on.
// Run it whenever a scanner digest in _source-security.yml changes.
//
//   1. Semgrep scope: regenerates the observations in
//      test/fixtures/scanner-behaviour/semgrep-scope.json and fails if the
//      pinned image no longer behaves as recorded (the unit tests check
//      ssd-onboard's scope model against that fixture).
//   2. Gitleaks: a secret only a BUILT-IN rule detects and a secret only a
//      CUSTOM rule detects must BOTH be found with the config ssd-onboard
//      generates — and a rules-only config (no [extend] useDefault) must miss
//      the built-in one, which is why existing configs need review.
//   3. OSV-Scanner: the recursive backstop (workflow arguments) skips a tracked
//      lockfile .gitignore lists; the explicit npm-root run (osv-npm-roots.mjs)
//      reads every npm dependency-root lockfile — root, nested, shrinkwrap,
//      gitignored — and never an untracked one.
//
// Requires docker and git.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { renderGitleaksToml, renderSemgrepignore } from '../onboarding/lib/render.mjs';
import { discoverNpmRoots } from '../security/scripts/dependency-roots.mjs';
import { osvDockerArguments } from '../security/scripts/osv-npm-roots.mjs';
import { config } from '../test/support/onboarding-fixtures.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE_SECURITY = readFileSync(join(ROOT, '.github/workflows/_source-security.yml'), 'utf8');
const pinned = (name) => {
  const match = new RegExp(`(${name.replace('/', '\\/')}@sha256:[0-9a-f]{64})`).exec(SOURCE_SECURITY);
  if (!match) {
    throw new Error(`no pinned ${name} image in _source-security.yml`);
  }
  return match[1];
};
const SEMGREP = pinned('semgrep/semgrep');
const GITLEAKS = pinned('ghcr.io/gitleaks/gitleaks');
const OSV = pinned('ghcr.io/google/osv-scanner');
// The OSV-Scanner arguments exactly as the workflow passes them, /repo mount included.
const OSV_ARGS = (() => {
  const match = /osv-scanner@sha256:[0-9a-f]{64} \\\n\s+(scan source [^\n\\]+?)\s*\\?\n/.exec(SOURCE_SECURITY);
  if (!match) {
    throw new Error('no OSV-Scanner invocation in _source-security.yml');
  }
  return match[1].trim().split(/\s+/);
})();
const FIXTURE = join(ROOT, 'test/fixtures/scanner-behaviour/semgrep-scope.json');
const update = process.argv.includes('--update');

const work = mkdtempSync(join(tmpdir(), 'ssd-scanner-behaviour-'));
const git = (cwd, ...args) => execFileSync('git', ['-C', cwd, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
function repo(name) {
  const dir = join(work, name);
  mkdirSync(dir, { recursive: true });
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'user.email', 'verify@example.invalid');
  git(dir, 'config', 'user.name', 'verify');
  git(dir, 'config', 'commit.gpgsign', 'false');
  return dir;
}
const commit = (dir) => {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '--allow-empty', '-m', 'x');
};
let failures = 0;
const check = (ok, message) => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${message}`);
  failures += ok ? 0 : 1;
};

try {
  // ---- 1. Semgrep scope ---------------------------------------------------------
  console.log(`== Semgrep scope (${SEMGREP.split('@')[1]}) ==`);
  const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  const sg = repo('semgrep');
  for (const file of fixture.tracked) {
    mkdirSync(dirname(join(sg, file)), { recursive: true });
    writeFileSync(join(sg, file), 'eval(user_input)\n');
  }
  mkdirSync(join(sg, 'ignored_untracked'), { recursive: true });
  writeFileSync(join(sg, 'ignored_untracked/a.py'), 'eval(user_input)\n');
  writeFileSync(join(sg, '.gitignore'), fixture.gitignore.map((p) => `${p}\n`).join(''));
  writeFileSync(
    join(sg, 'rule.yml'),
    'rules:\n- id: no-eval\n  pattern: eval(...)\n  message: eval\n  languages: [python]\n  severity: ERROR\n'
  );
  git(sg, 'add', '-A');
  git(sg, 'add', '-f', 'ignored_tracked/a.py');
  git(sg, 'commit', '-q', '-m', 'x');
  const semgrepScan = (semgrepignore) => {
    rmSync(join(sg, '.semgrepignore'), { force: true });
    if (semgrepignore !== null) {
      writeFileSync(join(sg, '.semgrepignore'), semgrepignore);
    }
    commit(sg);
    const result = spawnSync('docker', [
      'run', '--rm', '-v', `${sg}:/src`, '-w', '/src', '-e', 'HOME=/tmp',
      '-e', 'GIT_CONFIG_COUNT=1', '-e', 'GIT_CONFIG_KEY_0=safe.directory', '-e', 'GIT_CONFIG_VALUE_0=/src',
      SEMGREP, 'semgrep', 'scan', '--config', 'rule.yml', '--json', '--metrics=off', '--disable-version-check', '.'
    ], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    return JSON.parse(result.stdout);
  };
  const observations = [];
  for (const observation of fixture.observations) {
    const report = semgrepScan(observation.semgrepignore);
    const scanned = report.results.map((r) => r.path).sort();
    observations.push({ ...observation, scanned });
    check(JSON.stringify(scanned) === JSON.stringify(observation.scanned), `${observation.case}: ${scanned.length} file(s) scanned as recorded`);
    fixture.version = report.version;
  }
  // The files ssd-onboard actually renders must scan exactly as recorded.
  const byCase = Object.fromEntries(fixture.observations.map((o) => [o.case, o.scanned]));
  const rendered = (patterns) =>
    semgrepScan(renderSemgrepignore(config('source-only', { semgrep: { ignore: { managed: true, patterns } } })))
      .results.map((r) => r.path).sort();
  check(JSON.stringify(rendered([])) === JSON.stringify(byCase['empty .semgrepignore']), 'rendered .semgrepignore with no patterns scans exactly what an empty file scans');
  check(
    JSON.stringify(rendered(['dist/', 'node_modules/'])) === JSON.stringify(byCase['generated with two confirmed exclusions']),
    'rendered .semgrepignore with two confirmed patterns excludes exactly those'
  );
  if (update) {
    writeFileSync(FIXTURE, `${JSON.stringify({ ...fixture, image: SEMGREP, observations }, null, 2)}\n`);
    console.log(`  updated ${FIXTURE}`);
  }

  // ---- 2. Gitleaks default-rule inheritance ------------------------------------
  console.log(`== Gitleaks (${GITLEAKS.split('@')[1]}) ==`);
  const gl = repo('gitleaks');
  // A value only the built-in aws-access-token rule matches, and one only the
  // consumer's custom rule matches. Synthetic, never real credentials.
  writeFileSync(join(gl, 'builtin.txt'), 'aws_key = "AKIAQYLPMN5HHHFPZAM2"\n');
  writeFileSync(join(gl, 'custom.txt'), 'token = "ACME_0123456789ABCDEFGHIJKLMNOPQRSTUV"\n');
  const managed = config('source-only', {
    gitleaks: { mode: 'managed', path: '.gitleaks.toml', customRules: [{ id: 'acme-token', description: 'ACME token', regex: 'ACME_[A-Z0-9]{32}' }] }
  });
  writeFileSync(join(gl, 'generated.toml'), renderGitleaksToml(managed));
  writeFileSync(join(gl, 'rules-only.toml'), "[[rules]]\nid = \"acme-token\"\nregex = '''ACME_[A-Z0-9]{32}'''\n");
  commit(gl);
  mkdirSync(join(gl, 'out'), { recursive: true });
  const scan = (configFile) => {
    spawnSync('docker', [
      'run', '--rm', '-v', `${gl}:/repo:ro`, '-v', `${join(gl, 'out')}:/out`, GITLEAKS,
      'git', '/repo', '--config', `/repo/${configFile}`, '--no-banner', '--report-format', 'json', '--report-path', `/out/${configFile}.json`, '--exit-code', '0'
    ], { encoding: 'utf8' });
    return JSON.parse(readFileSync(join(gl, 'out', `${configFile}.json`), 'utf8')).map((f) => `${f.RuleID}@${f.File}`).sort();
  };
  const generated = scan('generated.toml');
  check(generated.includes('aws-access-token@builtin.txt'), 'generated config: the built-in-only secret is found');
  check(generated.includes('acme-token@custom.txt'), 'generated config: the custom-only secret is found');
  const rulesOnly = scan('rules-only.toml');
  check(!rulesOnly.some((f) => f.startsWith('aws-access-token')), 'a rules-only config (no [extend] useDefault) misses the built-in secret — existing configs need review');

  // ---- 3. OSV-Scanner reads every npm dependency root's lockfile ---------------
  // ssd-onboard says `native+osv` for the lockfile of every npm dependency root
  // (root or nested, package-lock.json or npm-shrinkwrap.json, tracked even when
  // .gitignore lists it). The recursive backstop (workflow arguments, verbatim)
  // skips a tracked-but-gitignored lockfile; the explicit npm-root run
  // (osv-npm-roots.mjs, its own argument builder over the real discovery)
  // must read every root lockfile and nothing the discovery did not return.
  console.log(`== OSV-Scanner npm dependency roots (${OSV.split('@')[1]}) ==`);
  const osvRepo = repo('osv');
  const lock = JSON.stringify({
    name: 'x',
    lockfileVersion: 3,
    requires: true,
    packages: { '': { name: 'x', dependencies: { minimist: '1.2.5' } }, 'node_modules/minimist': { version: '1.2.5' } }
  });
  const lockfiles = ['package-lock.json', 'frontend/package-lock.json', 'apps/api/npm-shrinkwrap.json', 'ignored/package-lock.json', 'odd:dir/package-lock.json'];
  for (const file of [...lockfiles, 'untracked/package-lock.json']) {
    mkdirSync(dirname(join(osvRepo, file)), { recursive: true });
    writeFileSync(join(osvRepo, file), lock);
  }
  writeFileSync(join(osvRepo, '.gitignore'), 'ignored/package-lock.json\nuntracked/\n');
  git(osvRepo, 'add', '-A');
  git(osvRepo, 'add', '-f', 'ignored/package-lock.json');
  git(osvRepo, 'commit', '-q', '-m', 'x');
  const sourcesOf = (args) => {
    const result = spawnSync('docker', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    return { status: result.status, sources: (JSON.parse(result.stdout).results ?? []).map((r) => r.source.path.replace(/^\/repo\//, '')).sort() };
  };
  const recursive = sourcesOf(['run', '--rm', '-v', `${osvRepo}:/repo:ro`, OSV, ...OSV_ARGS]);
  check(!recursive.sources.includes('ignored/package-lock.json'), `recursive backstop (${OSV_ARGS.join(' ')}) skips the tracked-but-gitignored lockfile — why the explicit run exists`);
  const { roots } = await discoverNpmRoots(osvRepo);
  const declared = roots.map((r) => r.lockfile);
  check(JSON.stringify([...declared].sort()) === JSON.stringify([...lockfiles].sort()), `discovery returns exactly the tracked root lockfiles (untracked excluded): ${declared.join(', ')}`);
  const explicit = sourcesOf(osvDockerArguments({ checkout: osvRepo, image: OSV, lockfiles: declared }));
  check(
    explicit.status === 1 && JSON.stringify(explicit.sources) === JSON.stringify([...lockfiles].sort()),
    `explicit npm-root run reads every root lockfile — nested, shrinkwrap, gitignored, ':' in the path — and nothing else: ${explicit.sources.join(', ')}`
  );
  const unprefixed = spawnSync('docker', ['run', '--rm', '-v', `${osvRepo}:/repo:ro`, OSV, 'scan', 'source', '--allow-no-lockfiles', '--format=json', '-L', '/repo/odd:dir/package-lock.json'], { encoding: 'utf8' });
  check(unprefixed.status !== 0 && unprefixed.status !== 1, `without the package-lock.json: parse-as prefix a ':' in the path is misread as a format prefix (exit ${unprefixed.status}) — why the prefix is always passed`);
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nPINNED SCANNER BEHAVIOUR VERIFIED.' : `\n${failures} CHECK(S) FAILED`);
process.exitCode = failures === 0 ? 0 : 1;
