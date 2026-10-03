// `ssd-onboard github plan` end to end against the stateful fake GitHub
// (support/github-fake.mjs), which refuses every argv outside the wrapper's
// read allowlist. No test talks to GitHub.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { GhCliError } from '../onboarding/github/gh-cli.mjs';
import { githubPlan } from '../onboarding/github/plan.mjs';
import { planDirOf } from '../onboarding/github/record.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { FRAMEWORK, capture, config, tempDir, write } from './support/onboarding-fixtures.mjs';
import { BRANCH, COMPLETE_CODEOWNERS, SECRET, contentsDoc, facts, fixture, githubFake, githubWorld, repositoryDoc, rulesetDetail } from './support/github-fake.mjs';

const SLACK = { notifications: { slack: { enabled: true, githubSecretName: SECRET } } };
const CFG = config('source-only', SLACK);
const ESC = '\u001b';

async function plan(t, { world = githubWorld(), scope = 'protection', cfg = CFG, f = facts(), root = tempDir(t), framework = FRAMEWORK } = {}) {
  const fake = githubFake(world, { mutations: [] });
  const report = await githubPlan({ config: cfg, facts: f, scope, framework, root, exec: fake.exec, env: {} });
  assert.deepEqual(fake.unexpected, [], 'no call outside the read allowlist');
  assert.equal(fake.mutationCalls().length, 0, 'github plan never mutates');
  return { report, fake, root };
}

function listFiles(root, dir = root) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? listFiles(root, join(dir, e.name)) : [relative(root, join(dir, e.name))]));
}
const kinds = (r) => r.findings.map((f) => f.kind);
const readPlanJson = (root, id) => readFileSync(join(root, planDirOf(id), 'plan.json'), 'utf8');

// A consumer directory for the CLI: the config, nothing else.
function consumer(t, cfg = CFG) {
  const root = tempDir(t);
  write(root, '.ssd/onboarding.yml', serializeConfig(cfg));
  return root;
}
async function cli(root, args, { world = githubWorld(), f = facts(), framework = FRAMEWORK, color = false } = {}) {
  const c = capture();
  const fake = githubFake(world, { mutations: [] });
  const code = await main(['github', ...args, '--repo', root], { ...c.io, ghExec: fake.exec, githubFacts: f, framework, env: {}, color });
  return { code, out: c.text(), err: c.errors(), fake };
}

describe('github plan: read-only', () => {
  for (const scope of ['secrets', 'protection']) {
    it(`--scope ${scope}: only allowlisted GETs; the only write is plan.json`, async (t) => {
      const root = tempDir(t);
      write(root, 'README.md', 'x');
      const { report, fake } = await plan(t, { scope, root });
      assert.equal(report.outcome, 'PLANNED');
      assert.ok(fake.calls.every((c) => c.argv[0] === 'api' && c.argv[2] === 'GET'), 'GET only');
      assert.deepEqual(listFiles(root).sort(), ['README.md', `${planDirOf(report.plan.id)}/plan.json`].sort());
    });
  }

  it('the same state plans the same id; an identical existing plan is reused, never overwritten', async (t) => {
    const root = tempDir(t);
    const a = await plan(t, { root });
    const b = await plan(t, { root });
    assert.equal(a.report.plan.id, b.report.plan.id);
    assert.equal(b.report.plan.recorded, 'existing');
  });

  it('a CLI not bound to framework.ref is BLOCKED before GitHub is contacted', async (t) => {
    const { report, fake } = await plan(t, { framework: { ...FRAMEWORK, clean: false, dirtyPaths: ['x'] } });
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(fake.calls.length, 0);
  });
});

describe('github plan: repository identity', () => {
  it('the configured repository verified by GitHub', async (t) => {
    const { report } = await plan(t);
    assert.equal(report.findings[0].kind, 'identity');
    assert.equal(report.repository.github.fullName, 'acme/app');
  });

  for (const [what, opts, kind] of [
    ['GitHub resolves another repository', { world: githubWorld({ repository: repositoryDoc({ full_name: 'acme/renamed' }) }) }, 'identity-mismatch'],
    ['GitHub reports another default branch', { world: githubWorld({ repository: repositoryDoc({ default_branch: 'trunk' }) }) }, 'default-branch-mismatch'],
    ['the local origin names another repository', { f: facts({ slug: 'evil/app' }) }, 'origin-mismatch'],
    ['the local origin/HEAD names another branch', { f: facts({ defaultBranch: 'trunk' }) }, 'origin-default-branch-mismatch'],
    ['the repository is archived', { world: githubWorld({ repository: repositoryDoc({ archived: true }) }) }, 'archived'],
    ['the repository is not visible to the token', { world: githubWorld({ repository: { status: 404, message: 'Not Found' } }) }, 'repository-not-accessible']
  ]) {
    it(`${what}: BLOCKED, no plan`, async (t) => {
      const { report, root } = await plan(t, opts);
      assert.equal(report.outcome, 'BLOCKED');
      assert.ok(kinds(report).includes(kind), kinds(report).join());
      assert.equal(report.plan, null);
      assert.deepEqual(listFiles(root), []);
    });
  }

  it('an unknown local origin is a WARN for plan (apply refuses it)', async (t) => {
    const { report } = await plan(t, { f: facts({ slug: null, isGit: false }) });
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(report.findings.find((x) => x.kind === 'origin-unknown').severity, 'WARN');
  });

  it('a different-case slug is the same GitHub repository', async (t) => {
    const { report } = await plan(t, { world: githubWorld({ repository: repositoryDoc({ full_name: 'Acme/App' }) }) });
    assert.equal(report.outcome, 'PLANNED');
  });
});

describe('github plan: authentication and permissions', () => {
  it('no GitHub authentication fails closed (the run ends)', async (t) => {
    const world = githubWorld({ user: { status: 401, message: 'Bad credentials' } });
    const fake = githubFake(world, { mutations: [] });
    await assert.rejects(githubPlan({ config: CFG, facts: facts(), scope: 'protection', framework: FRAMEWORK, root: tempDir(t), exec: fake.exec, env: {} }), (e) => e instanceof GhCliError && e.kind === 'authentication');
    const r = await cli(consumer(t), ['plan', '--scope', 'secrets', '--json'], { world });
    assert.equal(r.code, 1);
    assert.equal(JSON.parse(r.out).outcome, 'ERROR');
    assert.equal(JSON.parse(r.out).error.kind, 'authentication');
  });

  it('secrets the token may not list: NOT VERIFIED, no plan', async (t) => {
    const world = githubWorld({ overrides: { 'repos/acme/app/actions/secrets?per_page=100&page=1': { status: 403, message: 'Resource not accessible by personal access token' } } });
    const { report } = await plan(t, { world, scope: 'secrets' });
    assert.equal(report.outcome, 'NOT_VERIFIED');
    assert.equal(report.secrets.state, 'unverified');
    assert.equal(report.plan, null);
  });

  it('protection needed but the token is not admin: NOT VERIFIED, no plan', async (t) => {
    const world = githubWorld({ repository: repositoryDoc({ permissions: { admin: false, maintain: false, push: true, triage: true, pull: true } }) });
    const { report } = await plan(t, { world });
    assert.equal(report.outcome, 'NOT_VERIFIED');
    assert.ok(kinds(report).includes('cannot-plan-ruleset'));
  });

  it('protected branch whose settings need admin: requirements NOT VERIFIED, never compliant', async (t) => {
    const world = githubWorld({ protectionError: { status: 404, message: 'Not Found' }, rulesets: [] });
    const { report } = await plan(t, { world });
    assert.equal(report.protection.evaluation.governance, 'unverified');
    assert.notEqual(report.protection.status, 'COMPLIANT');
  });

  it('an unverifiable GitHub Actions identity: the check cannot be pinned, nothing is claimed', async (t) => {
    const world = githubWorld({ actionsApp: { id: 1, slug: 'github-actions', owner: { login: 'github' } }, rulesets: [rulesetDetail()] });
    const { report } = await plan(t, { world });
    assert.equal(report.outcome, 'NOT_VERIFIED');
    assert.equal(report.protection.evaluation.requirements.find((r) => r.id === 'status-check').state, 'unverified');
  });
});

describe('github plan: the Slack secret', () => {
  it('Slack disabled: nothing to plan and GitHub is not contacted', async (t) => {
    const { report, fake } = await plan(t, { scope: 'secrets', cfg: config('source-only') });
    assert.equal(report.outcome, 'NOTHING_TO_PLAN');
    assert.deepEqual(report.operations, []);
    assert.equal(fake.calls.length, 0);
  });

  it('enabled + absent: create is planned; the plan names the secret only', async (t) => {
    const { report, root } = await plan(t, { scope: 'secrets' });
    assert.equal(report.secrets.state, 'absent');
    assert.deepEqual(report.operations, [{ type: 'actions-secret-set', name: SECRET, action: 'create' }]);
    const text = readPlanJson(root, report.plan.id);
    assert.doesNotMatch(text, /hooks\.slack|https?:/);
  });

  it('enabled + present: the value is unknowable and never read; rotate is planned', async (t) => {
    const world = githubWorld({ secrets: fixture('doc-secrets-present.json').secrets });
    const { report, fake } = await plan(t, { scope: 'secrets', world });
    assert.equal(report.secrets.state, 'present');
    assert.equal(report.operations[0].action, 'rotate');
    // Only the metadata list is read: no per-secret, public-key or value endpoint.
    const secretCalls = fake.endpoints().filter((e) => e.includes('secrets'));
    assert.deepEqual(secretCalls, ['GET repos/acme/app/actions/secrets?per_page=100&page=1']);
    const c = await cli(consumer(t), ['plan', '--scope', 'secrets'], { world });
    assert.match(c.out, /present — value unknowable/);
    assert.doesNotMatch(c.out, /verified value|value verified/i);
  });

  it('a secret on page 2 is found (pagination)', async (t) => {
    const many = Array.from({ length: 100 }, (_, i) => ({ name: `OTHER_${i}` }));
    const world = githubWorld({ secrets: [...many, { name: SECRET, updated_at: '2026-01-01T00:00:00Z' }] });
    const { report } = await plan(t, { scope: 'secrets', world });
    assert.equal(report.secrets.state, 'present');
  });
});

describe('github plan: protection', () => {
  const codeownersMissing = { contents: {} };

  it('an existing compliant ruleset + complete CODEOWNERS: COMPLIANT, nothing planned (no duplicate)', async (t) => {
    const { report, root } = await plan(t, { world: githubWorld({ rulesets: [rulesetDetail()] }) });
    assert.equal(report.outcome, 'COMPLIANT');
    assert.deepEqual(report.operations, []);
    assert.deepEqual(listFiles(root), []);
  });

  it('nothing applies: one new ruleset with both groups is planned', async (t) => {
    const { report } = await plan(t);
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(report.operations.length, 1);
    assert.deepEqual(report.operations[0].groups, ['pull_request', 'required_status_checks']);
    assert.deepEqual(report.operations[0].body.bypass_actors, []);
  });

  it('a bypass actor: not compliant; the additive ruleset is planned', async (t) => {
    const world = githubWorld({ rulesets: [rulesetDetail({ bypass_actors: [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }], current_user_can_bypass: 'always' })] });
    const { report } = await plan(t, { world });
    assert.equal(report.protection.status, 'INCOMPLETE');
    assert.equal(report.outcome, 'PLANNED');
  });

  it('unknown bypass: status NOT VERIFIED (never compliant); the additive ruleset is planned', async (t) => {
    const world = githubWorld({ rulesets: [rulesetDetail()], hideBypass: [42] });
    const { report } = await plan(t, { world });
    assert.equal(report.protection.status, 'NOT VERIFIED');
    assert.equal(report.outcome, 'PLANNED');
  });

  it('unrelated rules are preserved: the plan creates a new ruleset and touches nothing else', async (t) => {
    const unrelated = rulesetDetail({ id: 9, name: 'tag protection', rules: [{ type: 'deletion', parameters: {} }, { type: 'non_fast_forward', parameters: {} }] });
    const world = githubWorld({ rulesets: [unrelated] });
    const { report } = await plan(t, { world });
    assert.equal(report.operations.length, 1);
    assert.equal(report.operations[0].type, 'ruleset-create');
    assert.equal(report.operations[0].name, 'ssd-merge-governance');
  });

  it('a conflicting SSD-named ruleset: BLOCKED with an explicit conflict, nothing planned', async (t) => {
    const drifted = rulesetDetail({ id: 7, name: 'ssd-merge-governance', bypass_actors: [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }] });
    const { report } = await plan(t, { world: githubWorld({ rulesets: [drifted] }) });
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(report).includes('ssd-ruleset-drifted'));
    assert.deepEqual(report.operations, []);
  });

  it('CODEOWNERS missing on GitHub with compliant rules: INCOMPLETE, protection never claimed', async (t) => {
    const { report } = await plan(t, { world: githubWorld({ rulesets: [rulesetDetail()], ...codeownersMissing }) });
    assert.equal(report.outcome, 'INCOMPLETE');
    assert.equal(report.protection.codeowners.state, 'incomplete');
  });

  it('local CODEOWNERS heuristically complete but GitHub does not require code-owner review: not compliant', async (t) => {
    const d = rulesetDetail();
    d.rules = d.rules.map((r) => (r.type === 'pull_request' ? { ...r, parameters: { ...r.parameters, require_code_owner_review: false } } : r));
    const { report } = await plan(t, { world: githubWorld({ rulesets: [d] }) });
    assert.equal(report.protection.codeowners.state, 'complete');
    assert.equal(report.protection.evaluation.requirements.find((r) => r.id === 'code-owner-review').state, 'missing');
    assert.notEqual(report.protection.status, 'COMPLIANT');
    assert.deepEqual(report.operations[0].groups, ['pull_request']);
  });

  it('GitHub uses the first CODEOWNERS location: .github/ wins over root and docs/', async (t) => {
    const world = githubWorld({ rulesets: [rulesetDetail()], contents: { '.github/CODEOWNERS': contentsDoc('/.ssd/ @a\n'), CODEOWNERS: contentsDoc(COMPLETE_CODEOWNERS, 'CODEOWNERS') } });
    const { report } = await plan(t, { world });
    assert.equal(report.protection.codeowners.path, '.github/CODEOWNERS');
    assert.equal(report.protection.codeowners.state, 'incomplete', 'judged on the file GitHub uses');
  });

  it('a root CODEOWNERS is used when .github/ has none; docs/ last', async (t) => {
    const root = await plan(t, { world: githubWorld({ rulesets: [rulesetDetail()], contents: { CODEOWNERS: contentsDoc(COMPLETE_CODEOWNERS, 'CODEOWNERS'), 'docs/CODEOWNERS': contentsDoc('x', 'docs/CODEOWNERS') } }), f: facts({ codeowners: 'CODEOWNERS' }) });
    assert.equal(root.report.protection.codeowners.path, 'CODEOWNERS');
    const docs = await plan(t, { world: githubWorld({ rulesets: [rulesetDetail()], contents: { 'docs/CODEOWNERS': contentsDoc(COMPLETE_CODEOWNERS, 'docs/CODEOWNERS') } }), f: facts({ codeowners: 'docs/CODEOWNERS' }) });
    assert.equal(docs.report.protection.codeowners.path, 'docs/CODEOWNERS');
    assert.equal(docs.report.outcome, 'COMPLIANT');
  });

  it('GitHub-reported CODEOWNERS errors make protection INCOMPLETE', async (t) => {
    const world = githubWorld({ rulesets: [rulesetDetail()], codeownersErrors: fixture('doc-codeowners-errors.json') });
    const { report } = await plan(t, { world });
    assert.equal(report.outcome, 'INCOMPLETE');
  });
});

describe('github plan: untrusted GitHub data', () => {
  for (const [what, override] of [
    ['truncated JSON', { 'repos/acme/app': { raw: '{"full_name":"acme/app","id":42' } }],
    ['not JSON', { 'repos/acme/app/rules/branches/main?per_page=100&page=1': { raw: '<html>oops</html>' } }],
    ['the wrong schema (rules as an object)', { 'repos/acme/app/rules/branches/main?per_page=100&page=1': { body: { rules: [] } } }],
    ['a status check context that is not a string', { 'repos/acme/app/rules/branches/main?per_page=100&page=1': { body: [{ type: 'required_status_checks', ruleset_id: 1, ruleset_source_type: 'Repository', ruleset_source: 'acme/app', parameters: { required_status_checks: [{ context: 7 }] } }] } }],
    ['bypass_actors that is not a list', null],
    ['a timeout', { 'apps/github-actions': { timeout: true } }]
  ]) {
    it(`${what}: ERROR, fail closed, no plan`, async (t) => {
      const world = override ? githubWorld({ overrides: override }) : githubWorld({ rulesets: [rulesetDetail({ bypass_actors: 'none' })] });
      const root = consumer(t);
      const r = await cli(root, ['plan', '--scope', 'protection', '--json'], { world });
      assert.equal(r.code, 1);
      const doc = JSON.parse(r.out);
      assert.equal(doc.outcome, 'ERROR');
      assert.deepEqual(listFiles(root), ['.ssd/onboarding.yml']);
      assert.deepEqual(r.fake.unexpected, []);
    });
  }
});

describe('github plan: output', () => {
  const hostile = () =>
    githubWorld({
      rulesets: [rulesetDetail({ name: `evil${ESC}[31mRED${ESC}]0;title\u0007‮gnp.exe`, bypass_actors: [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }], current_user_can_bypass: 'always' })],
      codeownersErrors: { errors: [{ line: 1, kind: `Unknown${ESC}[2J`, message: `owner\r\nFAKE ✓ PASS`, path: '.github/CODEOWNERS' }] }
    });

  it('terminal-control data from GitHub is shown escaped, never executed', async (t) => {
    const r = await cli(consumer(t), ['plan', '--scope', 'protection'], { world: hostile() });
    assert.ok(!r.out.includes(ESC), 'no raw ESC');
    assert.ok(!r.out.includes('\u0007') && !r.out.includes('‮') && !r.out.includes('\r'));
    assert.match(r.out, /\\x1b\[31mRED/);
    assert.match(r.out, /\\u202e/);
  });

  it('--json keeps GitHub data as exact JSON values, unsanitized, one document', async (t) => {
    const r = await cli(consumer(t), ['plan', '--scope', 'protection', '--json'], { world: hostile() });
    const doc = JSON.parse(r.out);
    assert.equal(doc.schemaVersion, 1);
    assert.equal(doc.protection.evaluation.sources[0].label, `ruleset evil${ESC}[31mRED${ESC}]0;title\u0007‮gnp.exe`);
    assert.equal(r.out, `${JSON.stringify(doc, null, 2)}\n`, 'byte-for-byte the report');
  });

  it('human output separates the sections; NO_COLOR-style plain output for an injected writer', async (t) => {
    const r = await cli(consumer(t), ['plan', '--scope', 'protection'], { f: facts({ slug: null, isGit: false }) });
    for (const title of ['Repository', 'Current GitHub state', 'Planned changes', 'Protection status', 'Warnings', 'Next action', 'Result']) {
      assert.match(r.out, new RegExp(`^${title}$`, 'm'), title);
    }
    assert.ok(!r.out.includes(ESC), 'no ANSI unless colour was asked for');
    const coloured = await cli(consumer(t), ['plan', '--scope', 'protection'], { color: true });
    assert.ok(coloured.out.includes(`${ESC}[`), 'colour only when enabled');
  });

  it('blocking problems get their own section', async (t) => {
    const r = await cli(consumer(t), ['plan', '--scope', 'protection'], { f: facts({ slug: 'evil/app' }) });
    assert.equal(r.code, 1);
    assert.match(r.out, /^Blocking problems$/m);
  });
});

describe('github CLI contract', () => {
  it('plan requires --scope; apply requires --plan-id and --slug; there is no protect', async (t) => {
    const root = consumer(t);
    for (const args of [['plan'], ['plan', '--scope', 'everything'], ['apply', '--plan-id', 'a'.repeat(64)], ['apply', '--slug', 'acme/app'], ['apply', '--plan-id', 'nope', '--slug', 'acme/app'], ['apply', '--plan-id', 'a'.repeat(64), '--slug', 'not a slug'], ['protect'], ['plan', '--scope', 'secrets', '--slug', 'acme/app'], ['apply', '--scope', 'secrets', '--plan-id', 'a'.repeat(64), '--slug', 'acme/app']]) {
      const r = await cli(root, args);
      assert.equal(r.code, 2, args.join(' '));
      assert.equal(r.fake.calls.length, 0, 'nothing contacted');
    }
  });

  it('github --help is exit 0 and names no immediate-mutation verb', async (t) => {
    const r = await cli(consumer(t), ['--help']);
    assert.equal(r.code, 0);
    assert.match(r.out, /plan --scope secrets\|protection/);
    assert.doesNotMatch(r.out, /^\s+protect\b/m);
  });

  it('an invalid configuration is an ERROR before GitHub', async (t) => {
    const root = tempDir(t);
    write(root, '.ssd/onboarding.yml', 'schemaVersion: "1"\n');
    const r = await cli(root, ['plan', '--scope', 'secrets', '--json']);
    assert.equal(r.code, 1);
    assert.equal(JSON.parse(r.out).outcome, 'ERROR');
    assert.equal(r.fake.calls.length, 0);
  });
});

describe('the fake GitHub', () => {
  it('refuses, independently, every argv outside the allowlist it was given', async () => {
    const fake = githubFake(githubWorld(), { mutations: [] });
    const r = await fake.exec(['secret', 'set', SECRET, '--repo', 'github.com/acme/app', '--app', 'actions'], { stdin: Buffer.from('x') });
    assert.equal(r.exitCode, 1);
    await fake.exec(['api', '--method', 'GET', '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', 'repos/evil/app']);
    assert.equal(fake.unexpected.length, 2);
  });
});
