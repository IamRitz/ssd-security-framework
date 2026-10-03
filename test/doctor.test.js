// `ssd-onboard doctor`: operational readiness as a READ-ONLY projection of the
// same analysis `validate` decides from. These tests pin the behavioural
// contract — statuses and exit codes per repository state, that every
// validation error surfaces as a FAIL, that doctor adds no FAIL of its own,
// that external governance is NOT VERIFIED rather than guessed, and that the
// repository is byte-for-byte untouched.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { after, describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { analyze, hasDrift, isBlocking } from '../onboarding/lib/analyze.mjs';
import { scopeDigestFor } from '../onboarding/lib/baseline.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { contractProblems } from '../onboarding/lib/contract.mjs';
import { FAIL, NOT_VERIFIED, PASS, WARN, describeSourceBoundary, diagnose, githubSettingsUrl, routeEntry } from '../onboarding/lib/doctor.mjs';
import { withMarker } from '../onboarding/lib/files.mjs';
import { inspectRepository, parseGithubSlug, parseRemoteHost } from '../onboarding/lib/inspect.mjs';
import { renderAll } from '../onboarding/lib/render.mjs';
import { FRAMEWORK, SAMPLE_BASELINE, capture, commitAll, config, deepMerge, makeRepo, read, write } from './support/onboarding-fixtures.mjs';

// PATH shims that record any aws / gh invocation. Tests assert they stay empty.
const SHIM_DIR = mkdtempSync(join(tmpdir(), 'ssd-doctor-shims-'));
const SHIM_LOG = join(SHIM_DIR, 'calls.log');
for (const tool of ['aws', 'gh']) {
  writeFileSync(join(SHIM_DIR, tool), `#!/bin/sh\necho "${tool} $*" >> "${SHIM_LOG}"\nexit 97\n`);
  chmodSync(join(SHIM_DIR, tool), 0o755);
}
const ORIGINAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${ORIGINAL_PATH}`;
after(() => {
  process.env.PATH = ORIGINAL_PATH;
  rmSync(SHIM_DIR, { recursive: true, force: true });
});
const shimCalls = () => (existsSync(SHIM_LOG) ? readFileSync(SHIM_LOG, 'utf8').trim().split('\n').filter(Boolean) : []);

const BASELINE = 'security/baseline/semgrep-baseline.json';
const CODEOWNERS = ['/.ssd/ @acme/sec', '/.github/workflows/ @acme/sec', `/${BASELINE} @acme/sec`, '/.semgrepignore @acme/sec', ''].join('\n');
const PY_REPO = {
  'src/app.py': 'print("hi")\n',
  'tests/test_app.py': 'def test(): pass\n',
  'requirements.txt': 'requests==2.32.5\n'
};

async function cli(root, args, io = {}) {
  const c = capture();
  const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io, ...io });
  return { code, out: c.text(), err: c.errors() };
}

async function doctorJson(root, io) {
  const result = await cli(root, ['doctor', '--json'], io);
  return { ...result, report: result.out ? JSON.parse(result.out) : null };
}

const statusOf = (report, id) => report.checks.find((c) => c.id === id)?.status;
const checkOf = (report, id) => report.checks.find((c) => c.id === id);

// The config for a lifecycle stage, with acceptedScope recorded as `baseline
// accept` records it (a missing one is a legitimate WARN of its own).
function stageConfig(profile, { gateMode = 'log-only', state = 'absent', overrides = {} } = {}) {
  const stage = (baseline) => deepMerge(overrides, { rollout: { gateMode }, semgrep: { baseline } });
  const base = config(profile, stage({ state }));
  if (state !== 'accepted') {
    return base;
  }
  return config(profile, stage({ state, acceptedScope: scopeDigestFor(base, null) }));
}

// A consumer that ran init/render/accept as documented and committed the
// result: the state doctor is meant to judge.
async function consumer(t, { profile = 'source-only', gateMode = 'enforce', state = 'accepted', files = {}, codeowners = true, overrides = {} } = {}) {
  const container = profile === 'source-only' ? {} : { Dockerfile: 'FROM python:3.13-slim\n' };
  const root = makeRepo(t, {
    ...PY_REPO,
    ...container,
    ...(state === 'accepted' ? { [BASELINE]: JSON.stringify(SAMPLE_BASELINE) } : {}),
    ...(codeowners ? { '.github/CODEOWNERS': CODEOWNERS } : {}),
    ...files
  });
  write(root, '.ssd/onboarding.yml', serializeConfig(stageConfig(profile, { gateMode, state, overrides })));
  const rendered = await cli(root, ['render']);
  assert.equal(rendered.code, 0, rendered.out + rendered.err);
  commitAll(root, 'onboard');
  return root;
}

// Everything observable about the checkout: git's view (tracked, untracked,
// ignored), refs, and every file's bytes, mode and mtime outside .git — a
// rewrite of identical bytes still changes the mtime.
function snapshot(root) {
  const git = (...args) => execFileSync('git', ['-C', root, ...args]).toString();
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.name === '.git' && dir === root) {
        continue;
      }
      if (entry.isDirectory()) {
        walk(full);
      } else {
        const info = lstatSync(full);
        files.push(`${relative(root, full)} ${info.mode} ${info.mtimeMs} ${createHash('sha256').update(readFileSync(full)).digest('hex')}`);
      }
    }
  };
  walk(root);
  return {
    status: git('status', '--porcelain=v1', '--untracked-files=all', '--ignored'),
    refs: git('for-each-ref', '--format=%(refname) %(objectname)') + git('rev-parse', 'HEAD'),
    files: files.sort().join('\n')
  };
}

// The attribution contract, over a successfully analyzed repository.
async function assertAttribution(root, framework = FRAMEWORK) {
  const facts = await inspectRepository(root);
  const { parseConfig } = await import('../onboarding/lib/config.mjs');
  const { config: cfg, errors, warnings } = parseConfig(read(root, '.ssd/onboarding.yml'));
  const result = await analyze({ root, config: cfg, configErrors: errors, configWarnings: warnings, facts, framework });
  const report = diagnose({ result, facts });
  const evidence = report.checks.flatMap((c) => c.evidence.map((e) => ({ ...e, status: c.status })));
  // No analyze entry is dropped or double-counted.
  assert.equal(evidence.length, result.errors.length + result.warnings.length);
  // Every blocking error is a FAIL.
  for (const error of result.errors) {
    const found = evidence.find((e) => e.severity === 'error' && e.message === error.message);
    assert.ok(found, `error not represented: ${error.message}`);
    assert.equal(found.status, FAIL, error.message);
  }
  // Every warning is at least a WARN.
  for (const warning of evidence.filter((e) => e.severity === 'warning')) {
    assert.ok([WARN, FAIL].includes(warning.status), warning.message);
  }
  // Doctor adds no FAIL semantics of its own: a FAIL exists only where
  // validate would exit 1 (an error, or drift).
  if (report.checks.some((c) => c.status === FAIL)) {
    assert.ok(isBlocking(result) || hasDrift(result), 'doctor FAILed where validate passes');
  }
  return { result, report };
}

describe('doctor: readiness per repository state', () => {
  it('healthy source-only, accepted baseline, enforce: exit 0, local controls PASS, governance NOT VERIFIED', async (t) => {
    const root = await consumer(t);
    const { code, report } = await doctorJson(root);
    assert.equal(code, 0);
    for (const id of ['configuration', 'identity', 'framework-pin', 'workflow-contract', 'generated-files', 'baseline', 'gate-mode', 'bootstrap', 'source-boundary', 'semgrep', 'secret-scanning', 'dependencies', 'container']) {
      assert.equal(statusOf(report, id), PASS, `${id}: ${JSON.stringify(checkOf(report, id))}`);
    }
    // A security-gate job exists in the committed workflow, and that proves
    // nothing about merge rules.
    assert.match(read(root, '.github/workflows/security.yml'), /name: security-gate/);
    assert.equal(statusOf(report, 'github-governance'), NOT_VERIFIED);
    assert.match(checkOf(report, 'github-governance').expected.join('\n'), /requires the stable `security-gate` status check/);
    // The CODEOWNERS matcher is a heuristic: coverage is never claimed.
    assert.equal(statusOf(report, 'codeowners'), NOT_VERIFIED);
    assert.ok(!report.checks.some((c) => c.id === 'aws-delivery'), 'no AWS check for source-only');
    assert.equal(report.outcome, 'READY (LOCAL CHECKS)');
    assert.equal(report.counts[FAIL], 0);
    await assertAttribution(root);
  });

  it('accepted baseline in log-only: Gate mode WARN, exit 0, and nothing is promoted', async (t) => {
    const root = await consumer(t, { gateMode: 'log-only' });
    const before = read(root, '.ssd/onboarding.yml');
    const { code, report } = await doctorJson(root);
    assert.equal(code, 0);
    const gate = checkOf(report, 'gate-mode');
    assert.equal(gate.status, WARN);
    assert.match(gate.why, /reported and NOT enforced/);
    assert.match(gate.remediation.join('\n'), /ssd-onboard promote --enforce/);
    assert.equal(statusOf(report, 'baseline'), PASS);
    assert.equal(report.outcome, 'READY WITH WARNINGS');
    assert.equal(read(root, '.ssd/onboarding.yml'), before, 'doctor never promotes');
    await assertAttribution(root);
  });

  it('state accepted but the baseline file is missing: Semgrep baseline FAIL, exit 1', async (t) => {
    const root = await consumer(t);
    unlinkSync(join(root, BASELINE));
    commitAll(root, 'lose the baseline');
    const { code, report } = await doctorJson(root);
    assert.equal(code, 1);
    const baseline = checkOf(report, 'baseline');
    assert.equal(baseline.status, FAIL);
    assert.match(baseline.evidence.map((e) => e.message).join('\n'), /is 'accepted' but .* does not exist/);
    assert.equal(report.outcome, 'NOT READY');
    assert.equal((await cli(root, ['validate'])).code, 1, 'validate agrees');
    await assertAttribution(root);
  });

  it('state absent with no baseline file is a VALID onboarding state, not corruption', async (t) => {
    const root = await consumer(t, { gateMode: 'log-only', state: 'absent' });
    const { code, report } = await doctorJson(root);
    assert.equal(code, 0);
    const baseline = checkOf(report, 'baseline');
    assert.equal(baseline.status, WARN, 'not production-ready, but not FAIL');
    assert.match(baseline.observed.join('\n'), /rollout state: onboarding/);
    assert.match(baseline.observed.join('\n'), /valid onboarding lifecycle state/);
    assert.deepEqual(baseline.evidence, [], 'no validation error or warning');
    // The bootstrap input belongs to exactly this stage.
    assert.equal(statusOf(report, 'bootstrap'), PASS);
    assert.match(checkOf(report, 'bootstrap').observed.join('\n'), /bootstrap_baseline dispatch input present/);
    await assertAttribution(root);
  });

  it('an accepted baseline carries no bootstrap wiring', async (t) => {
    const root = await consumer(t);
    const { report } = await doctorJson(root);
    assert.match(checkOf(report, 'bootstrap').observed.join('\n'), /no bootstrap input/);
    assert.doesNotMatch(read(root, '.github/workflows/security.yml'), /bootstrap_baseline/);
  });

  it('generated workflow drift: FAIL with the render remediation, and nothing is rewritten', async (t) => {
    const root = await consumer(t);
    write(root, '.ssd/onboarding.yml', serializeConfig(stageConfig('source-only', { gateMode: 'enforce', state: 'accepted', overrides: { semgrep: { rulesets: ['p/owasp-top-ten', 'p/python', 'p/secrets'] } } })));
    const before = snapshot(root);
    const { code, report } = await doctorJson(root);
    assert.equal(code, 1);
    const generated = checkOf(report, 'generated-files');
    assert.equal(generated.status, FAIL);
    assert.match(generated.observed.join('\n'), /update: \.github\/workflows\/security\.yml/);
    assert.match(generated.remediation.join('\n'), /Run `ssd-onboard render`, review the diff, and commit the generated files\./);
    // Dependent checks are unproven, not passed.
    assert.equal(statusOf(report, 'bootstrap'), NOT_VERIFIED);
    assert.equal(statusOf(report, 'source-boundary'), NOT_VERIFIED);
    assert.deepEqual(snapshot(root), before, 'doctor wrote nothing');
    assert.equal((await cli(root, ['render', '--check'])).code, 1, 'render --check agrees');
    await assertAttribution(root);
  });

  it('an uncovered dependency layout is a FAIL, using the existing coverage classes', async (t) => {
    const root = await consumer(t);
    write(root, 'services/py/requirements.txt', 'requests==2.19.1\n');
    commitAll(root, 'nested requirements');
    const { code, report } = await doctorJson(root);
    assert.equal(code, 1);
    const deps = checkOf(report, 'dependencies');
    assert.equal(deps.status, FAIL);
    assert.match(deps.observed.join('\n'), /services\/py\/requirements\.txt: osv-only/);
    assert.match(deps.evidence[0].message, /UNSUPPORTED by the current framework/);
    await assertAttribution(root);
  });

  it('a framework pin the CLI is not bound to: Framework pin FAIL; the contract is NOT VERIFIED, never passed', async (t) => {
    const root = await consumer(t);
    const other = { ...FRAMEWORK, sha: 'b'.repeat(40) };
    const { code, report } = await doctorJson(root, { framework: other });
    assert.equal(code, 1);
    assert.equal(statusOf(report, 'framework-pin'), FAIL);
    assert.match(checkOf(report, 'framework-pin').evidence[0].message, /is not the commit this ssd-onboard runs from/);
    assert.equal(statusOf(report, 'workflow-contract'), NOT_VERIFIED);
    assert.equal(statusOf(report, 'source-boundary'), NOT_VERIFIED);
    await assertAttribution(root, other);
  });

  for (const [label, framework, pattern] of [
    ['a dirty checkout', { ...FRAMEWORK, clean: false, dirtyPaths: ['onboarding/lib/render.mjs'] }, /uncommitted changes/],
    ['another framework repository', { ...FRAMEWORK, slug: 'someone/fork' }, /origin is someone\/fork/],
    ['no framework checkout', null, /cannot determine the framework commit/]
  ]) {
    it(`a framework checkout that is ${label} is a Framework pin FAIL, exactly as validate treats it`, async (t) => {
      const root = await consumer(t);
      const { code, report } = await doctorJson(root, { framework });
      assert.equal(code, 1);
      assert.equal(statusOf(report, 'framework-pin'), FAIL);
      assert.match(checkOf(report, 'framework-pin').evidence.map((e) => e.message).join('\n'), pattern);
      assert.equal((await cli(root, ['validate'], { framework })).code, 1);
    });
  }

  it('a configured identity that is not the origin: Repository identity FAIL', async (t) => {
    const root = await consumer(t);
    write(root, '.ssd/onboarding.yml', serializeConfig(stageConfig('source-only', { gateMode: 'enforce', state: 'accepted', overrides: { repository: { slug: 'acme/other' } } })));
    const { code, report } = await doctorJson(root);
    assert.equal(code, 1);
    assert.equal(statusOf(report, 'identity'), FAIL);
    assert.match(checkOf(report, 'identity').evidence[0].message, /repository\.slug is acme\/other but origin points at acme\/app/);
    await assertAttribution(root);
  });

  it('an identity git cannot establish is a WARN, never a new fail-closed rule', async (t) => {
    const root = await consumer(t);
    execFileSync('git', ['-C', root, 'remote', 'remove', 'origin']);
    const { code, report } = await doctorJson(root);
    assert.equal(code, 0, 'validate does not block on an unknown fact, so neither does doctor');
    const identity = checkOf(report, 'identity');
    assert.equal(identity.status, WARN);
    assert.match(identity.observed.join('\n'), /identity not established: origin is absent/);
    assert.equal((await cli(root, ['validate'])).code, 0);
  });

  it('a look-alike GitHub host is not a confirmed identity: WARN, never PASS, never a block', async (t) => {
    for (const url of ['https://github.com.evil.example/acme/app.git', 'git@github.com.evil.example:acme/app.git', 'https://notgithub.com/acme/app.git', 'https://example.com/github.com/acme/app.git']) {
      const root = await consumer(t);
      execFileSync('git', ['-C', root, 'remote', 'set-url', 'origin', url]);
      const { code, report } = await doctorJson(root);
      assert.equal(code, 0, url);
      const identity = checkOf(report, 'identity');
      assert.equal(identity.status, WARN, url);
      assert.match(identity.observed.join('\n'), /origin \(not a GitHub remote, or none\)/, url);
      assert.match(identity.observed.join('\n'), /identity not established: origin is absent or is not a GitHub remote/, url);
      assert.equal((await cli(root, ['validate'])).code, 0, `${url}: an unknown identity does not block`);
    }
  });

  it('a mixed-case or ported github.com origin is a confirmed identity', async (t) => {
    for (const url of ['git@GitHub.com:ACME/App.git', 'ssh://git@github.com:22/acme/app.git']) {
      const root = await consumer(t);
      execFileSync('git', ['-C', root, 'remote', 'set-url', 'origin', url]);
      const { report } = await doctorJson(root);
      assert.equal(statusOf(report, 'identity'), PASS, url);
    }
  });

  it('a non-git directory: identity not established (WARN)', async (t) => {
    const root = await consumer(t);
    rmSync(join(root, '.git'), { recursive: true, force: true });
    const { report } = await doctorJson(root);
    assert.equal(statusOf(report, 'identity'), WARN);
    assert.match(checkOf(report, 'identity').observed.join('\n'), /not a git repository/);
  });

  it('no CODEOWNERS: WARN naming every protected path', async (t) => {
    const root = await consumer(t, { codeowners: false });
    const { code, report } = await doctorJson(root);
    assert.equal(code, 0);
    const owners = checkOf(report, 'codeowners');
    assert.equal(owners.status, WARN);
    assert.deepEqual(owners.expected, ['.ssd/', '.github/workflows/', BASELINE, '.semgrepignore']);
    assert.match(owners.evidence[0].message, /no CODEOWNERS file/);
  });

  it('CODEOWNERS the heuristic considers complete is still NOT VERIFIED, never PASS', async (t) => {
    const root = await consumer(t, { files: { '.github/CODEOWNERS': '* @acme/sec\n' } });
    const { report } = await doctorJson(root);
    assert.equal(statusOf(report, 'codeowners'), NOT_VERIFIED);
    assert.match(checkOf(report, 'codeowners').observed.join('\n'), /heuristic coverage is not proof/);
  });

  it('`/*` is not recursive: the nested security paths are a CODEOWNERS WARN, not coverage', async (t) => {
    // GitHub matches `/*` against root-level files only.
    const root = await consumer(t, { files: { '.github/CODEOWNERS': '/* @acme/sec\n' } });
    const { code, report } = await doctorJson(root);
    assert.equal(code, 0);
    const owners = checkOf(report, 'codeowners');
    assert.equal(owners.status, WARN);
    assert.match(owners.evidence.map((e) => e.message).join('\n'), /does not cover: \.ssd\/ \.github\/workflows\/ security\/baseline\/semgrep-baseline\.json/);
  });

  it('a later ownerless rule un-owns a security path: WARN, never PASS', async (t) => {
    const root = await consumer(t, { files: { '.github/CODEOWNERS': '* @acme/sec\n.ssd/onboarding.yml\n' } });
    const { report } = await doctorJson(root);
    const owners = checkOf(report, 'codeowners');
    assert.equal(owners.status, WARN);
    assert.match(owners.evidence.map((e) => e.message).join('\n'), /does not cover: \.ssd\/$/);
  });
});

describe('doctor: the source workflow boundary', () => {
  it('a hand-edited `secrets: inherit` is explained, and is a FAIL only through the existing drift', async (t) => {
    const root = await consumer(t);
    const path = '.github/workflows/security.yml';
    const edited = read(root, path).replace(
      '    permissions:\n      contents: read\n      pull-requests: write\n',
      '    permissions:\n      contents: read\n      pull-requests: write\n      id-token: write\n    secrets: inherit\n'
    );
    assert.notEqual(edited, read(root, path), 'fixture edit applied');
    // Even a re-sealed marker (the digest is not a signature) is still drift.
    write(root, path, withMarker(edited.split('\n').slice(3).join('\n')));
    commitAll(root, 'hand edit');
    const { code, report } = await doctorJson(root);
    assert.equal(code, 1);
    assert.equal(statusOf(report, 'generated-files'), FAIL);
    const boundary = checkOf(report, 'source-boundary');
    assert.equal(boundary.status, FAIL);
    const observed = boundary.observed.join('\n');
    assert.match(observed, /passes `secrets: inherit`, handing EVERY repository secret/);
    assert.match(observed, /is granted id-token: write/);
    await assertAttribution(root);
  });

  it('when the existing contract rejects `secrets: inherit` in a render, doctor explains that same problem', async (t) => {
    const root = await consumer(t);
    const facts = await inspectRepository(root);
    const cfg = stageConfig('source-only', { gateMode: 'enforce', state: 'accepted' });
    const result = await analyze({ root, config: cfg, facts, framework: FRAMEWORK });
    // Feed the real contract check a render carrying `secrets: inherit`, and
    // record its verdict in the result exactly as analyze records one.
    const entry = result.plan.find((e) => e.path === cfg.workflows.security);
    entry.content = entry.content.replace('    with:\n', '    secrets: inherit\n    with:\n');
    const contract = await contractProblems([{ ...entry, kind: 'workflow' }], cfg, FRAMEWORK.readWorkflow);
    assert.ok(contract.problems.some((p) => /job source-security passes secret '0'/.test(p)), 'the existing, awkward rejection');
    contract.problems.forEach((message) => result.errors.push({ area: 'framework', message }));
    result.framework.contract.problems.push(...contract.problems);
    const report = diagnose({ result, facts });
    const boundary = checkOf(report, 'source-boundary');
    assert.equal(boundary.status, FAIL);
    assert.match(boundary.observed.join('\n'), /rendered .*passes `secrets: inherit`/);
    assert.equal(statusOf(report, 'workflow-contract'), PASS, 'source-security problems are attributed to the boundary check');
  });

  it('describeSourceBoundary only describes: a rendered source-security job raises nothing', () => {
    for (const profile of ['source-only', 'container-self-managed', 'container-ecr-framework-gated']) {
      for (const file of renderAll(stageConfig(profile, { gateMode: 'enforce', state: 'accepted' })).filter((f) => f.kind === 'workflow')) {
        assert.deepEqual(describeSourceBoundary(file.content), [], `${profile} ${file.path}`);
      }
    }
  });
});

describe('doctor: attribution never drops or invents a FAIL', () => {
  it('an error in an area doctor has no check for lands in a catch-all FAIL', async (t) => {
    const root = await consumer(t);
    const facts = await inspectRepository(root);
    const result = await analyze({ root, config: stageConfig('source-only', { gateMode: 'enforce', state: 'accepted' }), facts, framework: FRAMEWORK });
    result.errors.push({ area: 'future-area', message: 'a problem a later analyze may report' });
    result.errors.push({ area: 'framework', message: 'a framework problem neither binding nor contract recorded' });
    result.warnings.push({ area: 'future-area', message: 'a later warning' });
    const report = diagnose({ result, facts });
    const other = checkOf(report, 'other');
    assert.equal(other.status, FAIL);
    assert.deepEqual(other.evidence.map((e) => e.message), ['a problem a later analyze may report', 'a framework problem neither binding nor contract recorded', 'a later warning']);
    assert.equal(report.counts[FAIL], 1);
  });

  it('routeEntry sends framework errors by analyze\'s own record, not by re-running the checks', () => {
    const result = { plan: [], framework: { binding: ['bind'], contract: { problems: ['x job other passes'], unverified: ['unread'], staticGrants: [] } } };
    assert.equal(routeEntry({ area: 'framework', message: 'bind' }, result), 'framework-pin');
    assert.equal(routeEntry({ area: 'framework', message: 'x job other passes' }, result), 'workflow-contract');
    assert.equal(routeEntry({ area: 'framework', message: 'unread' }, result), 'workflow-contract');
    assert.equal(routeEntry({ area: 'framework', message: 'unknown' }, result), 'other');
    assert.equal(routeEntry({ area: 'config', message: 'rollout.gateMode: log-only: …' }, result), 'gate-mode');
    assert.equal(routeEntry({ area: 'nope', message: '' }, result), 'other');
    const withPlan = { ...result, plan: [{ path: 'w.yml', kind: 'workflow' }] };
    assert.equal(routeEntry({ area: 'permissions', message: 'LIMITATION: w.yml job source-security grants id-token' }, withPlan), 'source-boundary');
    assert.equal(routeEntry({ area: 'permissions', message: 'LIMITATION: w.yml job ecr-collect grants id-token' }, withPlan), 'workflow-contract');
  });

  it('every profile and lifecycle stage, rendered and committed, has no FAIL (doctor adds no policy)', async (t) => {
    for (const profile of ['source-only', 'container-self-managed', 'container-ecr-framework-gated']) {
      for (const [gateMode, state] of [['log-only', 'absent'], ['log-only', 'accepted'], ['enforce', 'accepted']]) {
        const root = await consumer(t, { profile, gateMode, state, overrides: profile === 'source-only' ? {} : { notifications: { slack: { enabled: true, githubSecretName: 'TEAM_SLACK' } } } });
        const { code, report } = await doctorJson(root);
        assert.equal(code, 0, `${profile} ${gateMode} ${state}: ${JSON.stringify(report.checks.filter((c) => c.status === FAIL))}`);
        assert.equal(statusOf(report, 'github-governance'), NOT_VERIFIED);
        assert.equal(statusOf(report, 'source-boundary'), PASS, `${profile} ${gateMode} ${state}`);
        // The ECR delivery job's static id-token grant is a known framework
        // limitation validate warns about; it is not the source boundary.
        assert.ok([PASS, WARN].includes(statusOf(report, 'workflow-contract')));
        assert.equal(Boolean(checkOf(report, 'aws-delivery')), profile === 'container-ecr-framework-gated');
        if (checkOf(report, 'aws-delivery')) {
          assert.equal(statusOf(report, 'aws-delivery'), NOT_VERIFIED);
        }
        if (profile !== 'source-only') {
          assert.equal(statusOf(report, 'slack-secret'), NOT_VERIFIED);
        }
        await assertAttribution(root);
      }
    }
  });
});

describe('doctor: command behaviour', () => {
  it('human output: compact status list, then What / Why / Expected / How for every non-PASS check', async (t) => {
    const root = await consumer(t, { gateMode: 'log-only' });
    const { code, out } = await cli(root, ['doctor']);
    assert.equal(code, 0);
    assert.match(out, /^SSD Doctor\n/);
    assert.match(out, /^ {2}Profile +source-only$/m);
    // Status symbol AND word on every check row, aligned.
    assert.match(out, /^ {2}! WARN {10}Gate mode$/m);
    assert.match(out, /^ {2}\? NOT VERIFIED {2}GitHub merge governance$/m);
    assert.match(out, /^ {2}✓ PASS {10}Configuration$/m);
    // Details only for non-PASS checks, each What / Why / Expected / How.
    const details = out.slice(out.indexOf('\nDetails\n'), out.indexOf('\nResult\n'));
    assert.match(details, /^ {2}! WARN +Gate mode\n +What +rollout\.gateMode: log-only$/m);
    assert.match(details, /^ +Why +\S/m);
    assert.match(details, /^ +Expected +\S/m);
    assert.match(details, /^ +How +\S/m);
    assert.doesNotMatch(details, /Configuration/, 'no detail block for a PASS');
    // The outcome is the machine outcome, verbatim.
    assert.match(out, /^Result\n {2}! READY WITH WARNINGS {2}0 FAIL · /m);
  });

  it('--json and the human output come from one structured model', async (t) => {
    const root = await consumer(t);
    const { report } = await doctorJson(root);
    assert.equal(report.command, 'doctor');
    assert.equal(report.schemaVersion, 1);
    for (const c of report.checks) {
      assert.deepEqual(Object.keys(c).sort(), ['evidence', 'expected', 'id', 'observed', 'remediation', 'status', 'title', 'why']);
    }
    const human = (await cli(root, ['doctor'])).out;
    for (const c of report.checks) {
      assert.ok(human.includes(`${c.status.padEnd(14)}${c.title}`), c.title);
    }
  });

  it('source-only, container and ECR profiles never run aws or gh', async (t) => {
    const before = shimCalls().length;
    for (const profile of ['source-only', 'container-self-managed', 'container-ecr-framework-gated']) {
      const root = await consumer(t, { profile });
      await cli(root, ['doctor']);
      await cli(root, ['doctor', '--json']);
      // detectFramework (not injected) runs real read-only git only.
      await cli(root, ['doctor'], { framework: undefined });
    }
    assert.deepEqual(shimCalls().slice(before), []);
  });

  it('is read-only: the checkout is byte-for-byte unchanged in healthy, drifted, failing and invalid states', async (t) => {
    const root = await consumer(t, { gateMode: 'log-only', state: 'absent' });
    const cases = [
      () => {},
      () => write(root, '.ssd/onboarding.yml', serializeConfig(stageConfig('source-only', { overrides: { semgrep: { rulesets: ['p/python'] } } }))),
      () => write(root, '.github/workflows/security.yml', 'hand: edited\n'),
      () => unlinkSync(join(root, '.github/workflows/security.yml')),
      () => write(root, '.ssd/onboarding.yml', 'profile: [unclosed\n'),
      () => unlinkSync(join(root, '.ssd/onboarding.yml'))
    ];
    for (const change of cases) {
      change();
      const before = snapshot(root);
      await cli(root, ['doctor']);
      await cli(root, ['doctor', '--json']);
      assert.deepEqual(snapshot(root), before);
    }
    // Specifically: nothing was rendered back into place.
    assert.ok(!existsSync(join(root, '.github/workflows/security.yml')));
    assert.ok(!existsSync(join(root, '.ssd/candidates')));
  });

  it('a clean consumer: `git status --porcelain` is identical before and after', async (t) => {
    const root = await consumer(t);
    const porcelain = () => execFileSync('git', ['-C', root, 'status', '--porcelain']).toString();
    const before = porcelain();
    assert.equal(before, '');
    assert.equal((await cli(root, ['doctor'])).code, 0);
    assert.equal(porcelain(), before);
  });

  it('a schema-invalid config: only Configuration FAIL (nothing else is claimed), exit 1', async (t) => {
    const root = await consumer(t);
    write(root, '.ssd/onboarding.yml', `${read(root, '.ssd/onboarding.yml')}\ngateMod: enforce\n`);
    const { code, report } = await doctorJson(root);
    assert.equal(code, 1);
    assert.equal(statusOf(report, 'configuration'), FAIL);
    assert.match(checkOf(report, 'configuration').evidence.map((e) => e.message).join('\n'), /gateMod: unknown key/);
    assert.ok(!report.checks.some((c) => c.status === PASS), 'no check passes over an invalid config');
  });

  it('a missing or malformed config is a deterministic exit 1, as for every other command', async (t) => {
    const root = await consumer(t);
    write(root, '.ssd/onboarding.yml', 'profile: [unclosed\n');
    const malformed = await cli(root, ['doctor']);
    assert.equal(malformed.code, 1);
    assert.match(malformed.err, /^ssd-onboard: /);
    assert.equal((await cli(root, ['validate'])).code, 1);
    unlinkSync(join(root, '.ssd/onboarding.yml'));
    const missing = await cli(root, ['doctor']);
    assert.equal(missing.code, 1);
    assert.match(missing.err, /does not exist\. Run `ssd-onboard init` first/);
  });

  it('--json with no diagnosis possible: one structured ERROR document, exit 1', async (t) => {
    const root = await consumer(t);
    const before = snapshot(root);
    unlinkSync(join(root, '.ssd/onboarding.yml'));
    const missing = await cli(root, ['doctor', '--json']);
    assert.equal(missing.code, 1);
    assert.equal(missing.err, '', 'nothing on the plain-text error path');
    const envelope = JSON.parse(missing.out);
    assert.deepEqual(Object.keys(envelope), ['schemaVersion', 'command', 'outcome', 'error']);
    assert.equal(envelope.schemaVersion, 1);
    assert.equal(envelope.command, 'doctor');
    assert.equal(envelope.outcome, 'ERROR');
    assert.equal(envelope.error.kind, 'config-missing');
    assert.match(envelope.error.message, /onboarding\.yml does not exist\. Run `ssd-onboard init` first/);

    write(root, '.ssd/onboarding.yml', 'profile: [unclosed\n');
    const malformed = await cli(root, ['doctor', '--json']);
    assert.equal(malformed.code, 1);
    assert.equal(malformed.err, '');
    assert.deepEqual(JSON.parse(malformed.out).error, { kind: 'config-malformed', message: 'line 1: flow collections are not supported: [unclosed' });

    // Nothing was written or committed in either case.
    assert.equal(snapshot(root).refs, before.refs);
    assert.ok(!existsSync(join(root, '.ssd/candidates')));
    assert.equal(read(root, '.ssd/onboarding.yml'), 'profile: [unclosed\n');
  });

  it('--json usage errors stay on the shared plain-text path with exit 2 (the parser rejects them before doctor runs)', async (t) => {
    const root = await consumer(t);
    const result = await cli(root, ['doctor', '--json', '--bogus']);
    assert.equal(result.code, 2);
    assert.equal(result.out, '');
    assert.match(result.err, /Unknown option '--bogus'[\s\S]*Usage:/);
  });

  it('exit 2 is reserved for command-line usage errors', async (t) => {
    const root = await consumer(t);
    const result = await cli(root, ['doctor', '--bogus']);
    assert.equal(result.code, 2);
    assert.match(result.err, /Usage:/);
  });

  it('`aws apply` without its flags is a usage error and contacts nothing', async (t) => {
    const root = await consumer(t);
    const before = shimCalls().length;
    const result = await cli(root, ['aws', 'apply']);
    assert.equal(result.code, 2);
    assert.match(result.err, /requires --plan-id, --account and --region/);
    assert.deepEqual(shimCalls().slice(before), []);
  });

  it('doctor imports no write-side helper and no filesystem or process API', () => {
    const source = readFileSync(new URL('../onboarding/lib/doctor.mjs', import.meta.url), 'utf8');
    const imports = [...source.matchAll(/^import\s+(?:\{([^}]*)\}|\*\s+as\s+\w+|\w+)\s+from\s+'([^']+)';/gm)];
    assert.ok(imports.length > 0);
    const names = imports.flatMap((m) => (m[1] ?? '').split(',').map((n) => n.trim()).filter(Boolean));
    const modules = imports.map((m) => m[2]);
    for (const forbidden of ['applyWrites', 'planWrites', 'removeFile', 'safeWriteFile', 'safeRemove', 'installBaseline', 'installCandidate', 'prepareCandidate', 'serializeConfig', 'renderAll']) {
      assert.ok(!names.includes(forbidden), `doctor imports ${forbidden}`);
    }
    for (const module of modules) {
      assert.ok(!/^node:|files\.mjs$|safe-path\.mjs$|cli\.mjs$/.test(module), `doctor imports ${module}`);
    }
    assert.doesNotMatch(source, /\bimport\s*\(/, 'no dynamic import');
    // The command routes to the read-only projection only.
    const cli = readFileSync(new URL('../onboarding/cli.mjs', import.meta.url), 'utf8');
    const body = /async function cmdDoctor[\s\S]*?\n}\n/.exec(cli)[0];
    assert.doesNotMatch(body, /applyWrites|removeFile|writeConfig|safeWriteFile|installBaseline|prepareCandidate/);
  });
});

describe('doctor: governance guidance is host-neutral', () => {
  const setOrigin = (root, url) => execFileSync('git', ['-C', root, 'remote', 'set-url', 'origin', url]);
  const remediation = (report, id) => checkOf(report, id).remediation.join('\n');

  it('github.com origin naming the configured repository: host-neutral steps plus the settings link', async (t) => {
    for (const url of ['https://github.com/acme/app.git', 'git@github.com:acme/app.git', 'ssh://git@github.com/acme/app.git']) {
      const root = await consumer(t, { overrides: { notifications: { slack: { enabled: true, githubSecretName: 'TEAM_SLACK' } } } });
      setOrigin(root, url);
      const { report } = await doctorJson(root);
      assert.match(remediation(report, 'github-governance'), /^In the repository settings, open Rules → Rulesets\.$/m, url);
      assert.match(remediation(report, 'github-governance'), /Protect the default branch main and require the stable `security-gate` check\. \(https:\/\/github\.com\/acme\/app\/settings\/rules\)/, url);
      assert.match(remediation(report, 'slack-secret'), /\(https:\/\/github\.com\/acme\/app\/settings\/secrets\/actions\)/, url);
    }
  });

  it('any other host — Enterprise, a look-alike, or no origin — gets the steps and NO link', async (t) => {
    for (const url of ['https://ghe.example.com/acme/app.git', 'git@ghe.example.com:acme/app.git', 'https://notgithub.com/acme/app.git', 'https://github.com.evil.example/acme/app.git', null]) {
      const root = await consumer(t, { overrides: { notifications: { slack: { enabled: true, githubSecretName: 'TEAM_SLACK' } } } });
      if (url === null) {
        execFileSync('git', ['-C', root, 'remote', 'remove', 'origin']);
      } else {
        setOrigin(root, url);
      }
      const { report } = await doctorJson(root);
      assert.match(remediation(report, 'github-governance'), /open Rules → Rulesets[\s\S]*require the stable `security-gate` check\./, String(url));
      assert.doesNotMatch(JSON.stringify(report), /https?:\/\//, `${url}: no URL rendered anywhere`);
      assert.equal(statusOf(report, 'github-governance'), NOT_VERIFIED);
    }
  });

  it('a github.com origin for ANOTHER repository gets no link to it', async (t) => {
    const root = await consumer(t);
    setOrigin(root, 'https://github.com/acme/other.git');
    const { report } = await doctorJson(root);
    assert.doesNotMatch(remediation(report, 'github-governance'), /https:/);
  });

  it('parseRemoteHost is exact; githubSettingsUrl requires the exact host and the configured slug', () => {
    assert.equal(parseRemoteHost('https://github.com/acme/app.git'), 'github.com');
    assert.equal(parseRemoteHost('git@GitHub.com:acme/app.git'), 'github.com');
    assert.equal(parseRemoteHost('ssh://git@github.com:22/acme/app.git'), 'github.com');
    assert.equal(parseRemoteHost('https://notgithub.com/acme/app.git'), 'notgithub.com');
    assert.equal(parseRemoteHost('https://github.com.evil.example/acme/app'), 'github.com.evil.example');
    assert.equal(parseRemoteHost('/srv/git/app.git'), null);
    assert.equal(parseRemoteHost(null), null);
    const cfg = config('source-only');
    assert.equal(githubSettingsUrl(cfg, { git: { host: 'github.com', slug: 'ACME/app' } }, 'rules'), 'https://github.com/acme/app/settings/rules');
    assert.equal(githubSettingsUrl(cfg, { git: { host: 'notgithub.com', slug: 'acme/app' } }, 'rules'), null);
    assert.equal(githubSettingsUrl(cfg, { git: { host: 'github.com', slug: null } }, 'rules'), null);
  });

  it('parseGithubSlug requires the exact github.com host', () => {
    for (const [url, slug] of [
      ['https://github.com/acme/app.git', 'acme/app'],
      ['http://github.com/acme/app.git', 'acme/app'],
      ['https://github.com/acme/app', 'acme/app'],
      ['ssh://git@github.com/acme/app.git', 'acme/app'],
      ['ssh://git@github.com:22/acme/app.git', 'acme/app'],
      ['git@github.com:acme/app.git', 'acme/app'],
      ['git@GitHub.com:ACME/App.git', 'ACME/App'],
      ['https://GITHUB.COM/acme/app.git', 'acme/app']
    ]) {
      assert.equal(parseGithubSlug(url), slug, url);
    }
    for (const url of [
      'https://notgithub.com/acme/app.git',
      'https://github.com.evil.example/acme/app.git',
      'git@github.com.evil.example:acme/app.git',
      'https://example.com/github.com/acme/app.git',
      'https://evil.example/x/github.com:acme/app.git',
      'git@evil.example:github.com/acme/app.git',
      'file://github.com/acme/app.git',
      'https://github.com/acme/app/extra',
      'https://ghe.example.com/acme/app.git',
      '/srv/git/app.git',
      '',
      null,
      undefined
    ]) {
      assert.equal(parseGithubSlug(url), null, String(url));
    }
  });
});
