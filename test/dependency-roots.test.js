// npm dependency roots, end to end: discovery (tracked files, confinement),
// onboarding classification, the per-root npm audit runner (injected process
// seam AND the real workflow step with a stub `npm` on PATH), and the source
// gate that re-derives the roots and requires one valid report per root.
//
// The invariant under test:
//
//   onboarding says `native+osv` for an npm lockfile
//     iff CI runs npm audit for that lockfile's root AND OSV-Scanner reads it,
//
// and a root that is not audited, or audited without a valid report, can never
// pass the gate as trusted.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { classifyManifests, dependencyFindings } from '../onboarding/lib/coverage.mjs';
import { inspectRepository } from '../onboarding/lib/inspect.mjs';
import { discoverNpmRoots, npmDependencyRoots, requireNpmRoots } from '../security/scripts/dependency-roots.mjs';
import { NESTED_REPORT, ROOT_REPORT, auditNpmRoots, npmAuditArguments } from '../security/scripts/npm-audit-roots.mjs';
import { OSV_NPM_REPORT, scanNpmRootsWithOsv } from '../security/scripts/osv-npm-roots.mjs';
import { buildReport, renderMarkdown } from '../security/scripts/format-findings.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';
import { deriveScanControlResults } from '../security/scripts/source-control-results.mjs';
import { stepScript } from './support/workflow-steps.mjs';
import { FRAMEWORK, capture, commitAll, config, makeRepo, tempDir, write } from './support/onboarding-fixtures.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';

const FRAMEWORK_ROOT = resolve('.');
const FIXTURES = join(FRAMEWORK_ROOT, 'security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const git = (cwd, ...args) => execFileSync('git', ['-C', cwd, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();

const LOCK = JSON.stringify({ name: 'x', lockfileVersion: 3, requires: true, packages: { '': { name: 'x' } } });
const PKG = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.20' } });

// An npm audit v2 report with the named vulnerable packages.
function npmReport(vulnerable = {}) {
  const vulnerabilities = Object.fromEntries(
    Object.entries(vulnerable).map(([name, severity]) => [
      name,
      { name, severity, via: [{ title: `${name} advisory`, url: `https://github.com/advisories/GHSA-${name}` }], fixAvailable: true }
    ])
  );
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const severity of Object.values(vulnerable)) counts[severity] += 1;
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: { ...counts, total: Object.keys(vulnerable).length } } };
}

const classify = (files, options) => {
  const texts = Object.fromEntries(Object.entries(files).filter(([, v]) => typeof v === 'string'));
  const { manifests } = classifyManifests(Object.keys(files), (path) => texts[path] ?? null, options);
  return Object.fromEntries(manifests.map((m) => [m.path, m.coverage]));
};

const JUICE_SHOP = {
  'package.json': PKG,
  'package-lock.json': LOCK,
  'frontend/package.json': JSON.stringify({ name: 'frontend', dependencies: { '@angular/core': '^20.0.0' } }),
  'frontend/package-lock.json': LOCK,
  'server.ts': 'export const x = 1\n',
  'frontend/src/main.ts': 'export const y = 2\n'
};

// ---------------------------------------------------------------- discovery ---

describe('dependency roots: discovery from repository paths', () => {
  it('1. a root npm project is the root dependency root', () => {
    assert.deepEqual(npmDependencyRoots(['package.json', 'package-lock.json']).roots, [{ root: '.', lockfile: 'package-lock.json' }]);
  });

  it('2. a nested npm project is its own dependency root', () => {
    assert.deepEqual(npmDependencyRoots(['frontend/package.json', 'frontend/package-lock.json']).roots, [
      { root: 'frontend', lockfile: 'frontend/package-lock.json' }
    ]);
  });

  it('3. two nested roots at arbitrary depth, no special-cased directory names', () => {
    assert.deepEqual(npmDependencyRoots(['apps/web/package-lock.json', 'apps/api/package-lock.json', 'services/web/x/package-lock.json']).roots, [
      { root: 'apps/api', lockfile: 'apps/api/package-lock.json' },
      { root: 'apps/web', lockfile: 'apps/web/package-lock.json' },
      { root: 'services/web/x', lockfile: 'services/web/x/package-lock.json' }
    ]);
  });

  it('4. root + nested: every root, repository root first', () => {
    assert.deepEqual(
      npmDependencyRoots(['frontend/package-lock.json', 'package-lock.json', '-odd/package-lock.json']).roots.map((r) => r.root),
      ['.', '-odd', 'frontend']
    );
  });

  it('12. traversal-looking, absolute and malformed paths are REJECTED, never used as roots', () => {
    const hostile = [
      '../evil/package-lock.json',
      'a/../../evil/package-lock.json',
      '/etc/package-lock.json',
      'C:/x/package-lock.json',
      'a//package-lock.json',
      'a/./package-lock.json',
      'a\\..\\b/package-lock.json',
      'a\nb/package-lock.json'
    ];
    const result = npmDependencyRoots(hostile);
    assert.deepEqual(result.roots, []);
    assert.deepEqual(result.rejected.map((r) => r.path).sort(), [...hostile].sort());
  });

  it('14. duplicates and input order never change the result', () => {
    const files = ['b/package-lock.json', 'package-lock.json', 'a/package-lock.json'];
    const once = npmDependencyRoots(files);
    assert.deepEqual(npmDependencyRoots([...files, ...files].reverse()), once);
    assert.equal(once.roots.length, 3);
  });

  it('node_modules lockfiles are never roots; a shrinkwrap is the root lockfile and shadows package-lock.json', () => {
    const result = npmDependencyRoots(['node_modules/x/package-lock.json', 'a/node_modules/y/package-lock.json', 'svc/npm-shrinkwrap.json', 'svc/package-lock.json']);
    assert.deepEqual(result.roots, [{ root: 'svc', lockfile: 'svc/npm-shrinkwrap.json' }]);
    assert.deepEqual(result.shadowed, [{ path: 'svc/package-lock.json', by: 'svc/npm-shrinkwrap.json' }]);
  });
});

describe('dependency roots: tracked repository state and confinement', () => {
  it('7. an ignored or untracked lockfile is not a root; force-adding it makes it one', async (t) => {
    const root = makeRepo(t, { 'package.json': PKG, 'package-lock.json': LOCK, '.gitignore': 'ignored/package-lock.json\n' });
    write(root, 'ignored/package.json', PKG);
    write(root, 'ignored/package-lock.json', LOCK);
    write(root, 'untracked/package-lock.json', LOCK);
    assert.deepEqual((await discoverNpmRoots(root)).roots.map((r) => r.root), ['.']);
    git(root, 'add', '-f', 'ignored/package-lock.json', 'untracked/package-lock.json');
    assert.deepEqual((await discoverNpmRoots(root)).roots.map((r) => r.root), ['.', 'ignored', 'untracked']);
  });

  it('13. a root directory swapped for a symbolic link out of the checkout is refused, and requireNpmRoots fails closed', async (t) => {
    const outside = tempDir(t, 'ssd-outside-');
    write(outside, 'package-lock.json', LOCK);
    const root = makeRepo(t, { 'package-lock.json': LOCK, 'frontend/package-lock.json': LOCK });
    execFileSync('rm', ['-rf', join(root, 'frontend')]);
    symlinkSync(outside, join(root, 'frontend'));
    const result = await discoverNpmRoots(root);
    assert.deepEqual(result.roots.map((r) => r.root), ['.']);
    assert.equal(result.rejected.length, 1);
    assert.match(result.rejected[0].reason, /'frontend' is a symbolic link/);
    await assert.rejects(requireNpmRoots(root), /refused.*frontend\/package-lock\.json/);
  });

  it('13. a tracked lockfile that is itself a symbolic link is refused', async (t) => {
    const outside = tempDir(t, 'ssd-outside-');
    write(outside, 'package-lock.json', LOCK);
    const root = makeRepo(t, { 'web/package.json': PKG });
    symlinkSync(join(outside, 'package-lock.json'), join(root, 'web/package-lock.json'));
    commitAll(root, 'linked lockfile');
    const result = await discoverNpmRoots(root);
    assert.deepEqual(result.roots, []);
    assert.match(result.rejected[0].reason, /web\/package-lock\.json' is a symbolic link/);
  });
});

// ----------------------------------------------------------- classification ---

describe('onboarding classification follows the dependency roots', () => {
  it('1-4. root, nested, two nested, root + nested: every lockfile native+osv, every manifest covered by it', () => {
    assert.deepEqual(classify({ 'package.json': PKG, 'package-lock.json': LOCK }), {
      'package-lock.json': 'native+osv',
      'package.json': 'covered-by-lockfile'
    });
    assert.deepEqual(classify({ 'frontend/package.json': PKG, 'frontend/package-lock.json': LOCK }), {
      'frontend/package-lock.json': 'native+osv',
      'frontend/package.json': 'covered-by-lockfile'
    });
    assert.deepEqual(classify({ 'apps/api/package-lock.json': LOCK, 'apps/web/package-lock.json': LOCK }), {
      'apps/api/package-lock.json': 'native+osv',
      'apps/web/package-lock.json': 'native+osv'
    });
    assert.deepEqual(dependencyFindings(classifyManifests(Object.keys(JUICE_SHOP), (p) => JUICE_SHOP[p] ?? null).manifests).blocking, []);
  });

  it('5. a nested package.json with dependencies and no lockfile is uncovered and blocks', () => {
    const { manifests } = classifyManifests(['package-lock.json', 'frontend/package.json'], (p) => (p === 'frontend/package.json' ? PKG : LOCK));
    assert.equal(manifests.find((m) => m.path === 'frontend/package.json').coverage, 'uncovered');
    assert.deepEqual(dependencyFindings(manifests).blocking.map((m) => m.path), ['frontend/package.json']);
  });

  it('6. a nested lockfile without a manifest follows the root policy: npm audit --prefix audits exactly that lockfile', () => {
    // At the repository root a lone package-lock.json has always been npm-audited.
    // With --prefix, npm audits the nested lockfile itself (verified with npm 10;
    // WITHOUT --prefix it would silently audit the ancestor project, which is why
    // the runner always passes it — asserted in the runner tests below).
    assert.equal(classify({ 'lonely/package-lock.json': LOCK })['lonely/package-lock.json'], 'native+osv');
    assert.deepEqual(npmAuditArguments('/w/lonely'), ['audit', '--json', '--package-lock-only', '--prefix', '/w/lonely']);
  });

  it('7. an untracked lockfile covers nothing: the lockfile and the manifest it would cover both block', () => {
    const result = classify({ 'frontend/package.json': PKG, 'frontend/package-lock.json': LOCK }, { tracked: ['frontend/package.json'] });
    assert.equal(result['frontend/package-lock.json'], 'uncovered');
    assert.equal(result['frontend/package.json'], 'uncovered');
  });

  it('10. a lockfile whose root npm audit does not run is never native+osv (shadowed, refused)', () => {
    assert.equal(classify({ 'svc/npm-shrinkwrap.json': LOCK, 'svc/package-lock.json': LOCK })['svc/package-lock.json'], 'osv-only');
    const refused = classify(
      { 'frontend/package-lock.json': LOCK },
      { npmRoots: { roots: [], rejected: [{ path: 'frontend/package-lock.json', reason: 'symbolic link' }], shadowed: [] } }
    );
    assert.equal(refused['frontend/package-lock.json'], 'osv-only');
  });

  it('inspect on a real checkout: untracked nested lockfile blocks, ignored one is invisible, tracked one is native+osv', async (t) => {
    const root = makeRepo(t, { 'package.json': PKG, 'package-lock.json': LOCK, 'frontend/package.json': PKG, '.gitignore': 'frontend/package-lock.json\n' });
    write(root, 'frontend/package-lock.json', LOCK);
    let facts = await inspectRepository(root);
    let byPath = Object.fromEntries(facts.manifests.map((m) => [m.path, m.coverage]));
    assert.equal(byPath['frontend/package-lock.json'], undefined, 'an ignored lockfile is not even listed');
    assert.equal(byPath['frontend/package.json'], 'uncovered');

    write(root, '.gitignore', '');
    facts = await inspectRepository(root);
    byPath = Object.fromEntries(facts.manifests.map((m) => [m.path, m.coverage]));
    assert.equal(byPath['frontend/package-lock.json'], 'uncovered', 'untracked (not ignored) still covers nothing');
    assert.equal(byPath['frontend/package.json'], 'uncovered');

    git(root, 'add', 'frontend/package-lock.json');
    facts = await inspectRepository(root);
    byPath = Object.fromEntries(facts.manifests.map((m) => [m.path, m.coverage]));
    assert.equal(byPath['frontend/package-lock.json'], 'native+osv');
    assert.equal(byPath['frontend/package.json'], 'covered-by-lockfile');
  });

  it('13. inspect refuses a symlinked lockfile exactly as the scanner does, and it blocks', async (t) => {
    const outside = tempDir(t, 'ssd-outside-');
    write(outside, 'package-lock.json', LOCK);
    const root = makeRepo(t, { 'web/package.json': PKG });
    symlinkSync(join(outside, 'package-lock.json'), join(root, 'web/package-lock.json'));
    commitAll(root, 'linked');
    const facts = await inspectRepository(root);
    const lock = facts.manifests.find((m) => m.path === 'web/package-lock.json');
    assert.equal(lock.coverage, 'osv-only');
    assert.match(lock.why.join(' '), /npm audit refuses this dependency root: .*symbolic link/);
    assert.ok(dependencyFindings(facts.manifests).blocking.some((m) => m.path === 'web/package-lock.json'));
  });
});

describe('tracked lockfiles that .gitignore lists: blocked unless OSV-Scanner reads them by name', () => {
  const RUST = { 'Cargo.toml': '[package]\nname = "x"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n', 'Cargo.lock': 'version = 3\n', 'src/main.rs': 'fn main() {}\n' };
  const coverageOf = async (root) => Object.fromEntries((await inspectRepository(root)).manifests.map((m) => [m.path, m]));
  async function cli(root, args) {
    const c = capture();
    const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io });
    return { code, out: `${c.text()}\n${c.errors()}` };
  }
  const configure = (root) => write(root, '.ssd/onboarding.yml', serializeConfig(config('source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/rust'] } })));

  it('tracked + gitignored Cargo.lock: not covered, blocks, and says why in inspect and render', async (t) => {
    const root = makeRepo(t, { ...RUST, '.gitignore': 'Cargo.lock\n' });
    git(root, 'add', '-f', 'Cargo.lock');
    commitAll(root, 'force-add Cargo.lock');
    const lock = (await coverageOf(root))['Cargo.lock'];
    assert.equal(lock.coverage, 'osv-skipped');
    assert.deepEqual(lock.why, ['tracked lockfile is ignored by Git rules and recursive OSV would skip it']);
    assert.ok(dependencyFindings((await inspectRepository(root)).manifests).blocking.some((m) => m.path === 'Cargo.lock'));
    const inspect = await cli(root, ['inspect']);
    assert.match(inspect.out, /Cargo\.lock\s+osv-skipped\s+tracked lockfile is ignored by Git rules and recursive OSV would skip it/);
    configure(root);
    const render = await cli(root, ['render']);
    assert.equal(render.code, 1);
    assert.match(render.out, /Cargo\.lock: tracked, but ignored by Git rules — the recursive OSV-Scanner walk skips it \(tracked lockfile is ignored by Git rules and recursive OSV would skip it\)/);
    assert.match(render.out, /Not fully covered: Cargo\.lock \(osv-skipped, UNSUPPORTED/);
    assert.ok(!existsSync(join(root, '.github/workflows/security.yml')), 'nothing generated');
  });

  it('tracked + non-ignored Cargo.lock: covered by OSV exactly as before, generation proceeds', async (t) => {
    const root = makeRepo(t, RUST);
    const byPath = await coverageOf(root);
    assert.equal(byPath['Cargo.lock'].coverage, 'osv');
    assert.deepEqual(byPath['Cargo.lock'].why, []);
    assert.equal(byPath['Cargo.toml'].coverage, 'covered-by-lockfile');
    configure(root);
    const render = await cli(root, ['render']);
    assert.equal(render.code, 0, render.out);
  });

  it('tracked + gitignored package-lock.json: native+osv, because the explicit npm-root OSV run names it', async (t) => {
    // OWASP Juice Shop's own layout: both lockfiles gitignored and force-added.
    const root = makeRepo(t, { ...JUICE_SHOP, '.gitignore': 'package-lock.json\n' });
    git(root, 'add', '-f', 'package-lock.json', 'frontend/package-lock.json');
    commitAll(root, 'force-add lockfiles');
    const byPath = await coverageOf(root);
    assert.equal(byPath['package-lock.json'].coverage, 'native+osv');
    assert.equal(byPath['frontend/package-lock.json'].coverage, 'native+osv');
    assert.deepEqual(dependencyFindings(Object.values(byPath)).blocking, []);
  });

  it('a gitignored npm lockfile that is NOT a dependency root gets no exemption', () => {
    const result = classify(
      { 'svc/npm-shrinkwrap.json': LOCK, 'svc/package-lock.json': LOCK, 'yarn.lock': '' },
      { ignoredTracked: ['svc/package-lock.json', 'yarn.lock', 'svc/npm-shrinkwrap.json'] }
    );
    assert.equal(result['svc/npm-shrinkwrap.json'], 'native+osv', 'the root lockfile is named to OSV-Scanner');
    assert.equal(result['svc/package-lock.json'], 'osv-skipped', 'shadowed: never named, and the walk skips it');
    assert.equal(result['yarn.lock'], 'osv-skipped');
  });

  it('a gitignored root requirements.txt is blocked too: pip-audit reads it, OSV-Scanner does not', () => {
    assert.equal(classify({ 'requirements.txt': '' }, { ignoredTracked: ['requirements.txt'] })['requirements.txt'], 'osv-skipped');
  });

  it('an untracked, ignored lockfile is irrelevant to coverage', async (t) => {
    const root = makeRepo(t, { ...RUST, '.gitignore': 'scratch/\n' });
    write(root, 'scratch/Cargo.lock', 'version = 3\n');
    write(root, 'scratch/package-lock.json', LOCK);
    const byPath = await coverageOf(root);
    assert.equal(byPath['scratch/Cargo.lock'], undefined);
    assert.equal(byPath['scratch/package-lock.json'], undefined);
    assert.equal(byPath['Cargo.lock'].coverage, 'osv');
    assert.deepEqual(dependencyFindings(Object.values(byPath)).blocking, []);
    assert.deepEqual((await discoverNpmRoots(root)).roots, []);
  });
});

describe('Juice Shop-shaped repository (root + frontend npm projects)', () => {
  async function cli(root, args) {
    const c = capture();
    const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io });
    return { code, out: c.text(), err: c.errors() };
  }

  it('inspect: both lockfiles native+osv, both manifests covered by their own lockfile', async (t) => {
    const root = makeRepo(t, JUICE_SHOP);
    const { code, out } = await cli(root, ['inspect']);
    assert.equal(code, 0);
    const lines = out.slice(out.indexOf('Dependency manifests:')).split('\n').slice(1, 5).map((l) => l.trim().split(/\s+/).slice(0, 2));
    assert.deepEqual(lines, [
      ['frontend/package-lock.json', 'native+osv'],
      ['frontend/package.json', 'covered-by-lockfile'],
      ['package-lock.json', 'native+osv'],
      ['package.json', 'covered-by-lockfile']
    ]);
  });

  it('validate/render: no dependency coverage error, "Not fully covered: none"', async (t) => {
    const root = makeRepo(t, JUICE_SHOP);
    write(root, '.ssd/onboarding.yml', serializeConfig(config('source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/typescript'] } })));
    const validate = await cli(root, ['validate']);
    assert.doesNotMatch(validate.out + validate.err, /UNSUPPORTED by the current framework/);
    assert.match(validate.out, /Not fully covered: none/);
    const render = await cli(root, ['render']);
    assert.equal(render.code, 0, render.out + render.err);
    assert.ok(existsSync(join(root, '.github/workflows/security.yml')));
  });

  it('the same layout with an UNTRACKED frontend lockfile is still blocked', async (t) => {
    const { 'frontend/package-lock.json': _, ...tracked } = JUICE_SHOP;
    const root = makeRepo(t, tracked);
    write(root, 'frontend/package-lock.json', LOCK);
    write(root, '.ssd/onboarding.yml', serializeConfig(config('source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/typescript'] } })));
    const render = await cli(root, ['render']);
    assert.equal(render.code, 1);
    assert.match(render.out + render.err, /frontend\/package-lock\.json: NOT SCANNED .*not tracked by git/);
  });
});

// ------------------------------------------------------------------ runtime ---

// A scripted npm: records every call, answers per root from `answers`
// (root -> array of stdout strings, one per attempt; the last repeats).
function scriptedNpm(answers) {
  const calls = [];
  const runAudit = async (args, { cwd, root }) => {
    calls.push({ args, cwd, root });
    const list = answers[root] ?? [JSON.stringify(npmReport())];
    const attempt = calls.filter((c) => c.root === root).length;
    return { status: 1, stdout: list[Math.min(attempt, list.length) - 1] };
  };
  return { calls, runAudit };
}

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

describe('npm audit runner: once per root, isolated, fail closed', () => {
  it('invokes npm audit exactly once per root, with cwd AND --prefix set to that root, and aggregates reports', async (t) => {
    const root = makeRepo(t, { ...JUICE_SHOP, 'apps/api/package-lock.json': LOCK });
    const out = tempDir(t, 'ssd-reports-');
    const npm = scriptedNpm({
      '.': [JSON.stringify(npmReport({ lodash: 'critical' }))],
      frontend: [JSON.stringify(npmReport({ minimist: 'high' }))],
      'apps/api': [JSON.stringify(npmReport({ lodash: 'high' }))]
    });
    const result = await auditNpmRoots({ repoDir: root, outputDir: out, runAudit: npm.runAudit, retryDelayMs: 0, log: () => {} });
    assert.equal(result.ok, true);
    const abs = (r) => (r === '.' ? resolve(root) : join(resolve(root), r));
    assert.deepEqual(
      npm.calls.map((c) => [c.root, c.cwd, c.args]),
      ['.', 'apps/api', 'frontend'].map((r) => [r, abs(r), ['audit', '--json', '--package-lock-only', '--prefix', abs(r)]])
    );
    assert.deepEqual(Object.keys(readJson(join(out, ROOT_REPORT)).vulnerabilities), ['lodash']);
    const nested = readJson(join(out, NESTED_REPORT));
    assert.deepEqual(nested.roots.map((r) => [r.root, r.lockfile, r.status, Object.keys(r.report.vulnerabilities)]), [
      ['apps/api', 'apps/api/package-lock.json', 'valid', ['lodash']],
      ['frontend', 'frontend/package-lock.json', 'valid', ['minimist']]
    ]);
  });

  it('8/9. a malformed or failing root does not suppress another root, and fails the run', async (t) => {
    const root = makeRepo(t, { 'apps/api/package-lock.json': '{ not json', 'apps/web/package-lock.json': LOCK });
    const out = tempDir(t, 'ssd-reports-');
    const npmError = JSON.stringify({ error: { code: 'EJSONPARSE', summary: 'Invalid package-lock.json' } });
    const npm = scriptedNpm({ 'apps/api': [npmError], 'apps/web': [JSON.stringify(npmReport({ minimist: 'high' }))] });
    const result = await auditNpmRoots({ repoDir: root, outputDir: out, runAudit: npm.runAudit, retryDelayMs: 0, log: () => {} });
    assert.equal(result.ok, false);
    assert.equal(npm.calls.filter((c) => c.root === 'apps/api').length, 3, 'the failing root is retried');
    assert.equal(npm.calls.filter((c) => c.root === 'apps/web').length, 1, 'the healthy root still runs, once');
    const nested = readJson(join(out, NESTED_REPORT));
    const byRoot = Object.fromEntries(nested.roots.map((r) => [r.root, r]));
    assert.equal(byRoot['apps/api'].status, 'invalid');
    assert.match(byRoot['apps/api'].error, /Invalid package-lock\.json/);
    assert.equal(byRoot['apps/web'].status, 'valid');
    assert.deepEqual(Object.keys(byRoot['apps/web'].report.vulnerabilities), ['minimist']);
    assert.ok(!existsSync(join(out, ROOT_REPORT)), 'no root project, no root report');
  });

  it('a refused root fails the run and is recorded; a stale report is never left behind', async (t) => {
    const outside = tempDir(t, 'ssd-outside-');
    write(outside, 'package-lock.json', LOCK);
    const root = makeRepo(t, { 'web/package.json': PKG });
    symlinkSync(join(outside, 'package-lock.json'), join(root, 'web/package-lock.json'));
    commitAll(root, 'linked');
    const out = tempDir(t, 'ssd-reports-');
    write(out, ROOT_REPORT, JSON.stringify(npmReport()));
    const npm = scriptedNpm({});
    const result = await auditNpmRoots({ repoDir: root, outputDir: out, runAudit: npm.runAudit, retryDelayMs: 0, log: () => {} });
    assert.equal(result.ok, false);
    assert.equal(npm.calls.length, 0, 'npm never runs through a symbolic link');
    assert.ok(!existsSync(join(out, ROOT_REPORT)), 'the stale root report was removed');
    assert.equal(readJson(join(out, NESTED_REPORT)).rejected[0].path, 'web/package-lock.json');
  });
});

describe('npm audit workflow step (real run: script, stub npm on PATH)', () => {
  const STEP = 'Run npm audit per dependency root (report only)';
  // Records "<cwd>|<args>" and answers from $STUB_ANSWERS/<key>.json, where key
  // is the --prefix path relative to the workspace with '/' as '_' ('_root' for
  // the repository root). Exits 1, as npm audit does when it finds anything.
  const STUB = [
    '#!/usr/bin/env bash',
    'printf "%s|%s\\n" "$PWD" "$*" >> "$STUB_CALLS"',
    'prefix=""; prev=""',
    'for a in "$@"; do [ "$prev" = "--prefix" ] && prefix="$a"; prev="$a"; done',
    'rel="${prefix#"$STUB_WORKSPACE"}"; rel="${rel#/}"',
    'key="${rel//\\//_}"; [ -n "$key" ] || key=_root',
    'cat "$STUB_ANSWERS/$key.json" 2>/dev/null',
    'exit 1',
    ''
  ].join('\n');

  function runStepIn(t, files, answers) {
    const workspace = resolve(makeRepo(t, files));
    const bin = tempDir(t, 'ssd-npm-stub-');
    writeFileSync(join(bin, 'npm'), STUB);
    chmodSync(join(bin, 'npm'), 0o755);
    const answerDir = tempDir(t, 'ssd-npm-answers-');
    for (const [name, text] of Object.entries(answers)) writeFileSync(join(answerDir, `${name}.json`), text);
    const calls = join(bin, 'calls');
    writeFileSync(calls, '');
    mkdirSync(join(workspace, 'reports'), { recursive: true });
    const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript(join(FRAMEWORK_ROOT, '.github/workflows/_source-security.yml'), STEP)], {
      cwd: workspace,
      env: {
        PATH: `${bin}:${process.env.PATH}`,
        HOME: process.env.HOME,
        SSD_TOOLKIT: join(FRAMEWORK_ROOT, 'security'),
        SSD_NPM_AUDIT_RETRY_DELAY_MS: '0',
        STUB_CALLS: calls,
        STUB_ANSWERS: answerDir,
        STUB_WORKSPACE: realpathSync(workspace)
      },
      encoding: 'utf8'
    });
    return {
      code: result.status,
      out: `${result.stdout}${result.stderr}`,
      calls: readFileSync(calls, 'utf8').split('\n').filter(Boolean).map((line) => line.split('|')),
      workspace
    };
  }

  it('runs npm audit exactly once in every root (root + nested), each with its own cwd and --prefix', (t) => {
    const { code, out, calls, workspace } = runStepIn(t, JUICE_SHOP, {
      _root: JSON.stringify(npmReport({ express: 'high' })),
      frontend: JSON.stringify(npmReport({ minimist: 'high' }))
    });
    assert.equal(code, 0, out);
    const real = realpathSync(workspace);
    assert.deepEqual(calls, [
      [real, `audit --json --package-lock-only --prefix ${real}`],
      [join(real, 'frontend'), `audit --json --package-lock-only --prefix ${join(real, 'frontend')}`]
    ]);
    assert.deepEqual(Object.keys(readJson(join(workspace, 'reports', ROOT_REPORT)).vulnerabilities), ['express']);
    const nested = readJson(join(workspace, 'reports', NESTED_REPORT));
    assert.deepEqual(nested.roots.map((r) => [r.root, r.status, Object.keys(r.report.vulnerabilities)]), [['frontend', 'valid', ['minimist']]]);
  });

  it('root-only scanning cannot pass: a nested root that produces no report fails the step, the root report is kept', (t) => {
    const { code, out, workspace } = runStepIn(t, JUICE_SHOP, { _root: JSON.stringify(npmReport()) });
    assert.equal(code, 1);
    assert.match(out, /NPM AUDIT FAILED for dependency root 'frontend'/);
    assert.equal(readJson(join(workspace, 'reports', ROOT_REPORT)).auditReportVersion, 2);
  });

  it('every root valid -> step passes; one nested root failing -> step fails, others kept', (t) => {
    const files = { 'apps/api/package-lock.json': LOCK, 'apps/web/package-lock.json': LOCK };
    const good = runStepIn(t, files, { apps_api: JSON.stringify(npmReport()), apps_web: JSON.stringify(npmReport({ minimist: 'high' })) });
    assert.equal(good.code, 0, good.out);
    assert.equal(good.calls.length, 2, 'exactly once per root');
    assert.match(good.out, /valid report for 2 dependency root\(s\)/);

    const bad = runStepIn(t, files, { apps_web: JSON.stringify(npmReport({ minimist: 'high' })) });
    assert.equal(bad.code, 1);
    assert.match(bad.out, /NPM AUDIT FAILED for dependency root 'apps\/api'/);
    const nested = readJson(join(bad.workspace, 'reports', NESTED_REPORT));
    assert.deepEqual(nested.roots.map((r) => [r.root, r.status]), [['apps/api', 'invalid'], ['apps/web', 'valid']]);
  });

  it('no npm root at all is a clean skip: npm never runs, no report is written', (t) => {
    const { code, calls, workspace } = runStepIn(t, { 'README.md': '# hi\n' }, {});
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
    assert.ok(!existsSync(join(workspace, 'reports', ROOT_REPORT)));
    assert.ok(!existsSync(join(workspace, 'reports', NESTED_REPORT)));
  });
});

// Scripted docker: records the argument vector, answers with a fixed OSV report
// and exit status.
function scriptedDocker(report, status = report?.results?.length ? 1 : 0) {
  const calls = [];
  const runScanner = async (args) => {
    calls.push(args);
    return { status, stdout: report === null ? '' : JSON.stringify(report), stderr: '' };
  };
  return { calls, runScanner };
}
const OSV_IMAGE = /ghcr\.io\/google\/osv-scanner@sha256:[0-9a-f]{64}/.exec(readFileSync(join(FRAMEWORK_ROOT, '.github/workflows/_source-security.yml'), 'utf8'))[0];
const osvResult = (lockfile, pkg = 'minimist') => ({
  source: { path: `/repo/${lockfile}`, type: 'lockfile' },
  packages: [
    {
      package: { name: pkg, version: '1.2.5', ecosystem: 'npm' },
      vulnerabilities: [
        {
          id: `GHSA-${pkg}`,
          affected: [{ package: { ecosystem: 'npm', name: pkg }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.6' }] }] }],
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }]
        }
      ],
      groups: [{ ids: [`GHSA-${pkg}`], aliases: [`GHSA-${pkg}`], max_severity: '9.8' }]
    }
  ]
});

describe('OSV-Scanner over the declared npm root lockfiles (explicit -L, never a global --no-ignore)', () => {
  it('names exactly the tracked root lockfiles, a tracked-but-gitignored one included and an untracked one never', async (t) => {
    const root = makeRepo(t, { 'package-lock.json': LOCK, 'frontend/package.json': PKG, '.gitignore': 'frontend/package-lock.json\nuntracked/\n' });
    write(root, 'frontend/package-lock.json', LOCK);
    git(root, 'add', '-f', 'frontend/package-lock.json');
    write(root, 'untracked/package-lock.json', LOCK);
    write(root, 'loose/package-lock.json', LOCK);
    const out = tempDir(t, 'ssd-reports-');
    const docker = scriptedDocker({ results: [osvResult('frontend/package-lock.json')] });
    const result = await scanNpmRootsWithOsv({ repoDir: root, outputDir: out, image: OSV_IMAGE, runScanner: docker.runScanner, log: () => {} });
    assert.equal(result.ok, true, result.message);
    assert.equal(docker.calls.length, 1);
    assert.deepEqual(docker.calls[0], [
      'run', '--rm', '-v', `${resolve(root)}:/repo:ro`, OSV_IMAGE,
      'scan', 'source', '--allow-no-lockfiles', '--format=json',
      '-L', 'package-lock.json:/repo/package-lock.json',
      '-L', 'package-lock.json:/repo/frontend/package-lock.json'
    ]);
    assert.ok(!docker.calls[0].includes('--no-ignore'));
    assert.ok(!docker.calls[0].includes('--recursive'));
    assert.deepEqual(readJson(join(out, OSV_NPM_REPORT)).lockfiles, ['package-lock.json', 'frontend/package-lock.json']);
  });

  it('judges the exit status with the report, fails on no report, refuses an unpinned image, never scans a refused root', async (t) => {
    const root = makeRepo(t, { 'package-lock.json': LOCK });
    const out = tempDir(t, 'ssd-reports-');
    const run = (docker, image = OSV_IMAGE) => scanNpmRootsWithOsv({ repoDir: root, outputDir: out, image, runScanner: docker.runScanner, log: () => {} });
    assert.equal((await run(scriptedDocker({ results: null }, 0))).ok, true, 'clean');
    assert.equal((await run(scriptedDocker({ results: [osvResult('package-lock.json')] }, 1))).ok, true, 'findings');
    assert.equal((await run(scriptedDocker({ results: null }, 1))).ok, false, 'exit 1 with no findings disagrees');
    assert.equal((await run(scriptedDocker(null, 127))).ok, false, 'no report');
    assert.ok(!existsSync(join(out, OSV_NPM_REPORT)), 'a failed scan leaves no report behind');
    await assert.rejects(run(scriptedDocker({ results: null }), 'ghcr.io/google/osv-scanner:latest'), /pinned by digest/);

    const outside = tempDir(t, 'ssd-outside-');
    write(outside, 'package-lock.json', LOCK);
    const linked = makeRepo(t, { 'web/package.json': PKG });
    symlinkSync(join(outside, 'package-lock.json'), join(linked, 'web/package-lock.json'));
    commitAll(linked, 'linked');
    const docker = scriptedDocker({ results: null });
    const refused = await scanNpmRootsWithOsv({ repoDir: linked, outputDir: out, image: OSV_IMAGE, runScanner: docker.runScanner, log: () => {} });
    assert.equal(refused.ok, false);
    assert.equal(docker.calls.length, 0);
  });

  it('the workflow steps: the recursive backstop is unchanged (no --no-ignore), the explicit step names each root lockfile', (t) => {
    const workspace = realpathSync(makeRepo(t, { 'package-lock.json': LOCK, 'frontend/package-lock.json': LOCK, '.gitignore': 'package-lock.json\n' }));
    git(workspace, 'add', '-f', 'package-lock.json', 'frontend/package-lock.json');
    mkdirSync(join(workspace, 'reports'));
    const bin = tempDir(t, 'ssd-docker-stub-');
    const calls = join(bin, 'calls');
    writeFileSync(calls, '');
    writeFileSync(
      join(bin, 'docker'),
      ['#!/usr/bin/env bash', 'printf "%s\\x1f" "$@" >> "$STUB_CALLS"; printf "\\n" >> "$STUB_CALLS"', `cat ${JSON.stringify(join(CLEAN, 'osv-scanner.json'))}`, 'exit 0', ''].join('\n')
    );
    chmodSync(join(bin, 'docker'), 0o755);
    const env = { PATH: `${bin}:${process.env.PATH}`, HOME: process.env.HOME, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: join(workspace, 'out'), SSD_TOOLKIT: join(FRAMEWORK_ROOT, 'security'), STUB_CALLS: calls };
    for (const step of ['Run OSV-Scanner (report only)', 'Run OSV-Scanner on each npm dependency root lockfile (report only)']) {
      const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript(join(FRAMEWORK_ROOT, '.github/workflows/_source-security.yml'), step)], { cwd: workspace, env, encoding: 'utf8' });
      assert.equal(result.status, 0, `${step}: ${result.stdout}${result.stderr}`);
    }
    const [recursive, explicit] = readFileSync(calls, 'utf8').split('\n').filter(Boolean).map((line) => line.split('\x1f').filter(Boolean));
    assert.deepEqual(recursive.slice(recursive.indexOf('scan')), ['scan', 'source', '--recursive', '--allow-no-lockfiles', '/repo', '--format=json']);
    assert.deepEqual(explicit.slice(explicit.indexOf('scan')), [
      'scan', 'source', '--allow-no-lockfiles', '--format=json',
      '-L', 'package-lock.json:/repo/package-lock.json', '-L', 'package-lock.json:/repo/frontend/package-lock.json'
    ]);
    assert.equal(explicit[explicit.indexOf('scan') - 1], recursive[recursive.indexOf('scan') - 1], 'both runs use the same pinned image');
    assert.ok(recursive.includes(`${workspace}:/repo:ro`) && explicit.includes(`${workspace}:/repo:ro`));
  });
});

// --------------------------------------------------------------------- gate ---

async function gateFor(t, repoFiles, reports) {
  const repoDir = tempDir(t, 'ssd-gate-repo-');
  for (const [path, content] of Object.entries(repoFiles)) write(repoDir, path, content);
  const dir = tempDir(t, 'ssd-gate-reports-');
  const paths = {
    policy: join(FRAMEWORK_ROOT, 'security/policy.yaml'),
    repoDir,
    gitleaks: join(CLEAN, 'gitleaks.json'),
    trufflehog: join(CLEAN, 'trufflehog.json'),
    osv: join(CLEAN, 'osv-scanner.json'),
    semgrep: join(CLEAN, 'semgrep.json'),
    baseline: join(CLEAN, 'semgrep-baseline.json'),
    npmAudit: join(dir, 'npm-audit.json'),
    npmAuditNested: join(dir, 'npm-audit-nested.json'),
    osvNpmRoots: join(dir, 'osv-scanner-npm-roots.json'),
    pipAudit: join(dir, 'pip-audit.json'),
    output: join(dir, 'security-gate.json'),
    exceptions: join(dir, 'gate-exceptions.json')
  };
  // Unless a test says otherwise: a clean explicit OSV run over exactly the roots.
  const declared = npmDependencyRoots(Object.keys(repoFiles)).roots.map((r) => r.lockfile);
  const effective = { ...(declared.length > 0 ? { osvNpmRoots: osvEnvelope(declared) } : {}), ...reports };
  for (const [key, value] of Object.entries(effective)) {
    if (value === null) {
      paths[key] = join(dir, `absent-${key}.json`);
    } else {
      // Always a file of this test's own: never overwrite a shared fixture.
      paths[key] = join(dir, `given-${key}.json`);
      writeFileSync(paths[key], typeof value === 'string' ? value : JSON.stringify(value));
    }
  }
  return runSecurityGate(paths);
}

const osvEnvelope = (lockfiles, results = null) => ({ schemaVersion: 1, scanner: 'osv-scanner', lockfiles, exitCode: results ? 1 : 0, report: { results } });
const nestedRecord = (roots) => ({ schemaVersion: 1, scanner: 'npm-audit', roots });
const integrity = (result) => result.findings.find((f) => f.policyRule === 'gate.report_integrity');
const TWO_ROOTS = { 'package-lock.json': LOCK, 'frontend/package-lock.json': LOCK };

describe('source gate: one valid npm audit report per dependency root', () => {
  it('15. findings from two roots keep their lockfile as location, even for the same package', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: npmReport({ lodash: 'critical' }),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport({ lodash: 'high', minimist: 'critical' }) }])
    });
    assert.equal(integrity(result), undefined);
    const npm = result.findings.filter((f) => f.source === 'npm-audit').map((f) => [f.id, f.location, f.severity]);
    assert.deepEqual(npm, [
      ['lodash', 'package-lock.json', 'critical'],
      ['lodash', 'frontend/package-lock.json', 'high'],
      ['minimist', 'frontend/package-lock.json', 'critical']
    ]);
    assert.deepEqual(result.dependencyRoots.npm, [
      { root: '.', lockfile: 'package-lock.json', report: 'npm-audit.json' },
      { root: 'frontend', lockfile: 'frontend/package-lock.json', report: 'npm-audit-nested.json' }
    ]);
  });

  it('10. OSV present but the nested npm audit report missing: untrusted, never a clean pass', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, { npmAudit: npmReport(), npmAuditNested: null });
    assert.equal(result.verdict, 'BLOCK');
    assert.equal(integrity(result).control, 'dependency-scan');
    assert.match(integrity(result).reason, /nested dependency roots.*missing report/);
    const controls = deriveScanControlResults({ jobResults: { 'secret-scan': 'success', 'dependency-scan': 'success', sast: 'success' }, gate: result });
    assert.equal(controls['dependency-scan'].result, 'untrusted');
  });

  it('10. a nested report that omits one of the roots is untrusted', async (t) => {
    const result = await gateFor(t, { 'apps/api/package-lock.json': LOCK, 'apps/web/package-lock.json': LOCK }, {
      npmAudit: null,
      npmAuditNested: nestedRecord([{ root: 'apps/web', lockfile: 'apps/web/package-lock.json', status: 'valid', report: npmReport() }])
    });
    assert.match(integrity(result).reason, /dependency root 'apps\/api' \(apps\/api\/package-lock\.json\) is missing/);
  });

  it('9. a root whose npm audit failed makes the dependency control untrusted', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: npmReport(),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'invalid', report: null, error: 'npm audit failed: Invalid package-lock.json' }])
    });
    assert.equal(integrity(result).control, 'dependency-scan');
    assert.match(integrity(result).reason, /'frontend'.*Invalid package-lock\.json/);
  });

  it('8. a malformed per-root report is an integrity failure that names the root', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: npmReport(),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: { auditReportVersion: 2 } }])
    });
    assert.match(integrity(result).reason, /dependency root 'frontend' \(frontend\/package-lock\.json\)/);
  });

  it('a report for a root the checkout does not have, or listed twice, is a disagreement, not extra coverage', async (t) => {
    const extra = await gateFor(t, { 'package-lock.json': LOCK }, {
      npmAudit: npmReport(),
      npmAuditNested: nestedRecord([{ root: 'ghost', lockfile: 'ghost/package-lock.json', status: 'valid', report: npmReport() }])
    });
    assert.match(integrity(extra).reason, /this checkout does not have: ghost/);
    const entry = { root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport() };
    const twice = await gateFor(t, TWO_ROOTS, { npmAudit: npmReport(), npmAuditNested: nestedRecord([entry, entry]) });
    assert.match(integrity(twice).reason, /more than once/);
  });

  it('the root report is still required for the root project (root-only scanning cannot pass for nested, nor nested for root)', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: null,
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport() }])
    });
    assert.match(integrity(result).reason, /npm audit: missing report file/);
  });

  it('11. npm audit present for every root but OSV missing: untrusted', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: npmReport(),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport() }]),
      osv: null
    });
    assert.equal(integrity(result).control, 'dependency-scan');
    assert.match(integrity(result).reason, /OSV-Scanner: missing report file/);
  });

  it('13. a dependency root reached through a symbolic link fails the dependency control closed', async (t) => {
    // Filesystem fallback (not a git checkout): a symlinked directory is not
    // descended, so plant a linked LOCKFILE, which is listed and refused.
    const repoDir = tempDir(t, 'ssd-gate-repo-');
    const outside = tempDir(t, 'ssd-outside-');
    write(outside, 'package-lock.json', LOCK);
    mkdirSync(join(repoDir, 'web'));
    symlinkSync(join(outside, 'package-lock.json'), join(repoDir, 'web/package-lock.json'));
    const result = await runSecurityGate({
      policy: join(FRAMEWORK_ROOT, 'security/policy.yaml'),
      repoDir,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      osv: join(CLEAN, 'osv-scanner.json'),
      semgrep: join(CLEAN, 'semgrep.json'),
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      npmAudit: join(repoDir, 'none.json'),
      npmAuditNested: join(repoDir, 'none-nested.json'),
      output: join(tempDir(t, 'ssd-out-'), 'gate.json'),
      exceptions: join(tempDir(t, 'ssd-out-'), 'exceptions.json')
    });
    assert.equal(integrity(result).control, 'dependency-scan');
    assert.match(integrity(result).reason, /refused.*web\/package-lock\.json.*symbolic link/);
  });

  it('explicit OSV run missing while npm roots exist: untrusted', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: npmReport(),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport() }]),
      osvNpmRoots: null
    });
    assert.equal(integrity(result).control, 'dependency-scan');
    assert.match(integrity(result).reason, /OSV-Scanner \(npm dependency roots\): missing report file/);
  });

  it('explicit OSV run that skipped a root lockfile: untrusted', async (t) => {
    const result = await gateFor(t, TWO_ROOTS, {
      npmAudit: npmReport(),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport() }]),
      osvNpmRoots: osvEnvelope(['package-lock.json'])
    });
    assert.match(integrity(result).reason, /OSV-Scanner did not scan npm dependency-root lockfile\(s\): frontend\/package-lock\.json/);
  });

  it('merged results: a lockfile both OSV runs reported yields its findings once', async (t) => {
    const result = await gateFor(t, { 'package-lock.json': LOCK }, {
      npmAudit: npmReport(),
      osv: { results: [osvResult('package-lock.json')] },
      osvNpmRoots: osvEnvelope(['package-lock.json'], [osvResult('package-lock.json')])
    });
    assert.equal(integrity(result), undefined);
    assert.equal(result.findings.filter((f) => f.source === 'osv-scanner').length, 1);
  });

  it('runner output feeds the gate: a Juice Shop-shaped checkout is audited per root and gated with provenance', async (t) => {
    const root = makeRepo(t, JUICE_SHOP);
    const out = tempDir(t, 'ssd-reports-');
    const npm = scriptedNpm({ '.': [JSON.stringify(npmReport({ express: 'high' }))], frontend: [JSON.stringify(npmReport({ '@angular/core': 'moderate' }))] });
    assert.equal((await auditNpmRoots({ repoDir: root, outputDir: out, runAudit: npm.runAudit, retryDelayMs: 0, log: () => {} })).ok, true);
    const docker = scriptedDocker({ results: [osvResult('frontend/package-lock.json', 'minimist')] });
    assert.equal((await scanNpmRootsWithOsv({ repoDir: root, outputDir: out, image: OSV_IMAGE, runScanner: docker.runScanner, log: () => {} })).ok, true);
    const result = await runSecurityGate({
      policy: join(FRAMEWORK_ROOT, 'security/policy.yaml'),
      repoDir: root,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      osv: join(CLEAN, 'osv-scanner.json'),
      semgrep: join(CLEAN, 'semgrep.json'),
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      npmAudit: join(out, ROOT_REPORT),
      npmAuditNested: join(out, NESTED_REPORT),
      osvNpmRoots: join(out, OSV_NPM_REPORT),
      output: join(out, 'security-gate.json'),
      exceptions: join(out, 'gate-exceptions.json')
    });
    assert.equal(integrity(result), undefined);
    assert.equal(result.integrity.trusted, true);
    assert.deepEqual(result.findings.filter((f) => f.source === 'osv-scanner').map((f) => f.package), ['minimist']);
    assert.deepEqual(
      result.findings.filter((f) => f.source === 'npm-audit').map((f) => [f.id, f.location]),
      [['express', 'package-lock.json'], ['@angular/core', 'frontend/package-lock.json']]
    );
  });
});

describe('source gate: tracked-but-gitignored is trusted, untracked never creates coverage or evidence trust', () => {
  async function gitGate(t, root, { osv = { results: null }, osvNpmRoots, npmAudit = npmReport(), npmAuditNested } = {}) {
    const dir = tempDir(t, 'ssd-gate-reports-');
    const file = (name, value) => {
      if (value === undefined) return join(dir, `absent-${name}`);
      writeFileSync(join(dir, name), JSON.stringify(value));
      return join(dir, name);
    };
    return runSecurityGate({
      policy: join(FRAMEWORK_ROOT, 'security/policy.yaml'),
      repoDir: root,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      semgrep: join(CLEAN, 'semgrep.json'),
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      osv: file('osv.json', osv),
      osvNpmRoots: file('osv-npm-roots.json', osvNpmRoots),
      npmAudit: file('npm-audit.json', npmAudit),
      npmAuditNested: file('npm-audit-nested.json', npmAuditNested),
      output: join(dir, 'security-gate.json'),
      exceptions: join(dir, 'gate-exceptions.json')
    });
  }

  it('tracked-but-gitignored lockfile: npm-audited, OSV-scanned by the explicit run (the recursive walk skipped it), trusted', async (t) => {
    const root = makeRepo(t, { 'package-lock.json': LOCK, '.gitignore': 'frontend/package-lock.json\n' });
    write(root, 'frontend/package-lock.json', LOCK);
    git(root, 'add', '-f', 'frontend/package-lock.json');
    const result = await gitGate(t, root, {
      osv: { results: null }, // the recursive backstop honoured .gitignore and saw nothing
      osvNpmRoots: osvEnvelope(['package-lock.json', 'frontend/package-lock.json'], [osvResult('frontend/package-lock.json')]),
      npmAuditNested: nestedRecord([{ root: 'frontend', lockfile: 'frontend/package-lock.json', status: 'valid', report: npmReport({ minimist: 'critical' }) }])
    });
    assert.equal(integrity(result), undefined);
    assert.equal(result.integrity.trusted, true);
    assert.deepEqual(result.dependencyRoots.npm.map((r) => r.lockfile), ['package-lock.json', 'frontend/package-lock.json']);
    assert.deepEqual(
      result.findings.filter((f) => f.source !== 'security-gate').map((f) => [f.source, f.package ?? f.id, f.location ?? null]),
      [['npm-audit', 'minimist', 'frontend/package-lock.json'], ['osv-scanner', 'minimist', null]]
    );
    const observed = result.dependencyEvidence.observations.map((o) => o.source);
    assert.deepEqual(observed, ['frontend/package-lock.json']);
  });

  it('untracked lockfile: not a root, no report required for it, and it cannot be declared into the explicit OSV run', async (t) => {
    const root = makeRepo(t, { 'package-lock.json': LOCK });
    write(root, 'loose/package-lock.json', LOCK);
    // No nested npm report and no OSV entry for it: still trusted, because it is not inventory.
    const clean = await gitGate(t, root, { osvNpmRoots: osvEnvelope(['package-lock.json']) });
    assert.equal(integrity(clean), undefined);
    assert.deepEqual(clean.dependencyRoots.npm.map((r) => r.lockfile), ['package-lock.json']);
    // A run that declares it scanned the untracked file is a disagreement, not extra coverage.
    const declared = await gitGate(t, root, { osvNpmRoots: osvEnvelope(['package-lock.json', 'loose/package-lock.json']) });
    assert.match(integrity(declared).reason, /does not declare: loose\/package-lock\.json/);
    // An explicit run that REPORTS an undeclared file is refused outright.
    const reported = await gitGate(t, root, { osvNpmRoots: osvEnvelope(['package-lock.json'], [osvResult('loose/package-lock.json')]) });
    assert.match(integrity(reported).reason, /reported "\/repo\/loose\/package-lock\.json", which is not a declared npm dependency-root lockfile/);
    // An npm audit report for it is refused the same way.
    const audited = await gitGate(t, root, {
      osvNpmRoots: osvEnvelope(['package-lock.json']),
      npmAuditNested: nestedRecord([{ root: 'loose', lockfile: 'loose/package-lock.json', status: 'valid', report: npmReport() }])
    });
    assert.match(integrity(audited).reason, /this checkout does not have: loose/);
  });
});

describe('developer-facing output: provenance kept, presentation unchanged for the repository root', () => {
  const finding = (location) => ({
    source: 'npm-audit', id: 'lodash', severity: 'critical', fixAvailable: true, fixedVersion: '4.17.21',
    title: 'Prototype pollution in lodash', action: 'BLOCK', policyRule: 'dependencies.critical_with_fix', reason: 'critical npm advisory; fix available',
    ...(location === undefined ? {} : { location })
  });
  const report = (...findings) => buildReport({ gate: { verdict: 'BLOCK', findings, breakGlass: { eligible: false } }, context: {} });

  it('a repository-root npm finding renders exactly as before the location existed', () => {
    const before = report(finding());
    const after = report(finding('package-lock.json'));
    assert.equal(after.cards[0].location, null);
    assert.equal(after.cards[0].reproduce, 'npm audit --package-lock-only');
    assert.equal(renderMarkdown(after), renderMarkdown(before));
  });

  it('a nested root shows its lockfile and reproduces with --prefix <root>', () => {
    const nested = report(finding('frontend/package-lock.json'));
    assert.deepEqual(nested.cards[0].location, { path: 'frontend/package-lock.json', line: null });
    assert.equal(nested.cards[0].reproduce, 'npm audit --package-lock-only --prefix frontend');
    assert.match(renderMarkdown(nested), /frontend\/package-lock\.json/);
    const odd = report(finding('apps/my app:v2/package-lock.json'));
    assert.equal(odd.cards[0].reproduce, "npm audit --package-lock-only --prefix 'apps/my app:v2'");
    assert.equal(odd.cards[0].location.path, 'apps/my app:v2/package-lock.json', 'a colon in the root is not read as a line number');
  });
});
