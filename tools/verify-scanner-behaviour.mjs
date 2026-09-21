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
//
// Requires docker and git.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { renderGitleaksToml, renderSemgrepignore } from '../onboarding/lib/render.mjs';
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
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nPINNED SCANNER BEHAVIOUR VERIFIED.' : `\n${failures} CHECK(S) FAILED`);
process.exitCode = failures === 0 ? 0 : 1;
