// `ssd-onboard github apply` end to end: a REAL plan is recorded first
// (githubPlan against the fake), then applied against the same stateful fake
// GitHub, which permits exactly the plan's one mutation argv. Covers plan
// integrity, intent and identity drift, time-of-check/time-of-use, the secret
// dataflow (argv, environment, logs, plan files, records, errors), the
// additive ruleset and the CLI. No test talks to GitHub.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { githubApply } from '../onboarding/github/apply.mjs';
import { githubPlan } from '../onboarding/github/plan.mjs';
import { canonicalJson, planDirOf } from '../onboarding/github/record.mjs';
import { SecretInputError, readSecret, validateWebhook } from '../onboarding/github/secret-input.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { scriptedPrompter } from '../onboarding/lib/prompt.mjs';
import { FRAMEWORK, capture, config, tempDir, write } from './support/onboarding-fixtures.mjs';
import { SECRET, facts, githubFake, githubWorld, repositoryDoc, rulesetDetail } from './support/github-fake.mjs';

const SLACK = { notifications: { slack: { enabled: true, githubSecretName: SECRET } } };
const CFG = config('source-only', SLACK);
const WEBHOOK = 'https://hooks.slack.com/services/T0DISTINCT/B0DISTINCT/zzSecretValue42zz';
const NEEDLES = [WEBHOOK, 'zzSecretValue42zz', 'T0DISTINCT'];

async function planned(t, { world = githubWorld(), scope = 'secrets', cfg = CFG, f = facts() } = {}) {
  const root = tempDir(t);
  write(root, '.ssd/onboarding.yml', serializeConfig(cfg));
  const fake = githubFake(world, { mutations: [] });
  const report = await githubPlan({ config: cfg, facts: f, scope, framework: FRAMEWORK, root, exec: fake.exec, env: {} });
  assert.equal(report.outcome, 'PLANNED', JSON.stringify(report.findings));
  return { root, planId: report.plan.id, world, scope };
}

async function apply(p, { cfg = CFG, f = facts(), slug = 'acme/app', yes = true, confirm = null, secret = WEBHOOK, framework = FRAMEWORK, env = {}, readSecretImpl } = {}) {
  const fake = githubFake(p.world, { mutations: p.scope === 'secrets' ? ['secret'] : ['ruleset'] });
  const given = [];
  const readSecretFn =
    readSecretImpl ??
    (async () => {
      const b = Buffer.from(secret);
      given.push(b);
      return b;
    });
  const report = await githubApply({ config: cfg, facts: f, planId: p.planId, slug, yes, confirm, readSecret: readSecretFn, framework, root: p.root, exec: fake.exec, env });
  assert.deepEqual(fake.unexpected, [], 'no call outside the plan\'s allowlist');
  return { report, fake, given };
}

const kinds = (r) => r.findings.map((f) => f.kind);
const refused = (r, kind) => {
  assert.equal(r.report.outcome, 'REFUSED', JSON.stringify(r.report.findings));
  if (kind) assert.ok(kinds(r.report).includes(kind), `${kind} in ${kinds(r.report)}`);
  assert.equal(r.fake.mutationCalls().length, 0, 'no mutation');
};
const filesUnder = (root, dir) => readdirSync(join(root, dir)).map((n) => readFileSync(join(root, dir, n), 'utf8'));
const noSecret = (text, where) => NEEDLES.forEach((n) => assert.ok(!String(text).includes(n), `secret in ${where}`));

describe('github apply: the secret dataflow', () => {
  it('applies: one `gh secret set`, value on stdin only, never in argv / env / report / records', async (t) => {
    const p = await planned(t);
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLIED');
    const [m] = r.fake.mutationCalls();
    assert.deepEqual(m.argv, ['secret', 'set', SECRET, '--repo', 'github.com/acme/app', '--app', 'actions']);
    assert.equal(m.stdin.toString(), WEBHOOK, 'stdin carries the value');
    noSecret(m.argv.join(' '), 'argv');
    noSecret(JSON.stringify(m.env), 'environment');
    for (const c of r.fake.calls.filter((c) => c !== m)) assert.equal(c.stdin, null, 'no other call receives stdin');
    noSecret(JSON.stringify(r.report), 'report');
    filesUnder(p.root, planDirOf(p.planId)).forEach((text) => noSecret(text, 'plan directory'));
    assert.ok(r.given[0].every((b) => b === 0), 'the value buffer is zeroed after use');
    assert.equal(r.report.verification.state, 'observed');
  });

  it('rotating a present secret: the new value travels the same way; the old one was never read', async (t) => {
    const p = await planned(t, { world: githubWorld({ secrets: [{ name: SECRET, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' }] }) });
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLIED');
    assert.equal(r.report.operation.action, 'rotate');
    assert.ok(!r.fake.endpoints().some((e) => /secrets\/[A-Z_]+|public-key/.test(e)), 'no per-secret read');
  });

  it('GitHub echoing the value in an error: redacted everywhere (logs, report, records)', async (t) => {
    const p = await planned(t);
    p.world.overrides['secret set'] = { status: 422, message: `Invalid webhook ${WEBHOOK}` };
    const c = capture();
    const fake = githubFake(p.world, { mutations: ['secret'] });
    const code = await main(['github', 'apply', '--plan-id', p.planId, '--slug', 'acme/app', '--yes', '--repo', p.root], { ...c.io, ghExec: fake.exec, githubFacts: facts(), framework: FRAMEWORK, env: {}, readSecret: async () => Buffer.from(WEBHOOK) });
    assert.equal(code, 1);
    noSecret(c.text(), 'stdout');
    noSecret(c.errors(), 'stderr');
    filesUnder(p.root, planDirOf(p.planId)).forEach((text) => noSecret(text, 'records'));
    assert.match(c.text(), /APPLY FAILED/);
  });

  it('the human and JSON output of a successful apply never contain the value', async (t) => {
    for (const json of [false, true]) {
      const p = await planned(t);
      const c = capture();
      const fake = githubFake(p.world, { mutations: ['secret'] });
      const code = await main(['github', 'apply', '--plan-id', p.planId, '--slug', 'acme/app', '--yes', '--repo', p.root, ...(json ? ['--json'] : [])], { ...c.io, ghExec: fake.exec, githubFacts: facts(), framework: FRAMEWORK, env: {}, readSecret: async () => Buffer.from(WEBHOOK) });
      assert.equal(code, 0);
      noSecret(c.text() + c.errors(), json ? 'json output' : 'human output');
    }
  });

  it('the value is read only AFTER confirmation; a wrong confirmation never reads it', async (t) => {
    const p = await planned(t);
    let read = 0;
    const r = await apply(p, { yes: false, confirm: async () => 'acme/other', readSecretImpl: async () => (read++, Buffer.from(WEBHOOK)) });
    refused(r, 'not-confirmed');
    assert.equal(read, 0);
  });

  it('an invalid value is refused without quoting it', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { readSecretImpl: async () => { const v = Buffer.from('https://example.com/zzSecretValue42zz'); validateWebhook(v); return v; } });
    refused(r, 'secret-input');
    noSecret(JSON.stringify(r.report), 'refusal');
  });
});

describe('github apply: secret input', () => {
  const ttyIn = () => Object.assign(new PassThrough(), { isTTY: true, rawModes: [], setRawMode(on) { this.rawModes.push(on); } });

  it('piped stdin: one trailing newline stripped, value returned as a Buffer', async () => {
    const input = new PassThrough();
    input.end(`${WEBHOOK}\n`);
    const value = await readSecret({ input, output: new PassThrough() });
    assert.ok(Buffer.isBuffer(value));
    assert.equal(value.toString(), WEBHOOK);
  });

  it('hidden TTY input: raw mode on then off, nothing echoed, Backspace edits', async () => {
    const input = ttyIn();
    const output = new PassThrough();
    const echoed = [];
    output.on('data', (c) => echoed.push(c.toString()));
    const pending = readSecret({ input, output });
    input.write(`${WEBHOOK}X\u007f\r`);
    const value = await pending;
    assert.equal(value.toString(), WEBHOOK);
    assert.deepEqual(input.rawModes, [true, false]);
    noSecret(echoed.join(''), 'terminal echo');
  });

  it('Ctrl-C aborts without a value; errors never quote the input', async () => {
    const input = ttyIn();
    const pending = readSecret({ input, output: new PassThrough() });
    input.write('https://hooks.slack.com/services/zzSecretValue42zz\u0003');
    await assert.rejects(pending, (e) => e instanceof SecretInputError && e.kind === 'aborted' && !e.message.includes('zzSecret'));
    for (const bad of ['', 'not a url zzSecretValue42zz', 'http://hooks.slack.com/services/T/B/zzSecretValue42zz', `${WEBHOOK} trailing`, `${WEBHOOK}\u001b[2J`]) {
      assert.throws(() => validateWebhook(Buffer.from(bad)), (e) => e instanceof SecretInputError && !e.message.includes('zzSecret'));
    }
  });

  it('a terminal that cannot hide input is refused', async () => {
    const input = Object.assign(new PassThrough(), { isTTY: true });
    await assert.rejects(readSecret({ input, output: new PassThrough() }), (e) => e.kind === 'no-hidden-input');
  });

  it('CLI: a secret piped on stdin requires --yes (stdin cannot also confirm)', async (t) => {
    const p = await planned(t);
    const c = capture();
    const fake = githubFake(p.world, { mutations: ['secret'] });
    const stdin = new PassThrough();
    stdin.end(WEBHOOK);
    const code = await main(['github', 'apply', '--plan-id', p.planId, '--slug', 'acme/app', '--repo', p.root], { ...c.io, ghExec: fake.exec, githubFacts: facts(), framework: FRAMEWORK, env: {}, stdin });
    assert.equal(code, 1);
    assert.match(c.text(), /confirmation/);
    assert.equal(fake.mutationCalls().length, 0);
  });

  it('CLI: piped stdin with --yes applies through the real reader', async (t) => {
    const p = await planned(t);
    const c = capture();
    const fake = githubFake(p.world, { mutations: ['secret'] });
    const stdin = new PassThrough();
    stdin.end(`${WEBHOOK}\n`);
    const code = await main(['github', 'apply', '--plan-id', p.planId, '--slug', 'acme/app', '--yes', '--repo', p.root], { ...c.io, ghExec: fake.exec, githubFacts: facts(), framework: FRAMEWORK, env: {}, stdin });
    assert.equal(code, 0, c.text());
    assert.equal(fake.mutationCalls()[0].stdin.toString(), WEBHOOK);
  });

  it('CLI: typed confirmation through the prompter', async (t) => {
    const p = await planned(t);
    const c = capture();
    const fake = githubFake(p.world, { mutations: ['secret'] });
    const prompter = scriptedPrompter({ confirmRepository: 'acme/app' });
    const code = await main(['github', 'apply', '--plan-id', p.planId, '--slug', 'acme/app', '--repo', p.root], { ...c.io, ghExec: fake.exec, githubFacts: facts(), framework: FRAMEWORK, env: {}, prompter, readSecret: async () => Buffer.from(WEBHOOK) });
    assert.equal(code, 0);
    assert.deepEqual(prompter.asked, ['confirmRepository']);
  });
});

describe('github apply: intent and drift (refused, nothing changed)', () => {
  it('--slug naming another repository is refused before GitHub', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { slug: 'evil/app' });
    refused(r, 'slug-mismatch');
    assert.equal(r.fake.calls.length, 0);
  });

  it('a configuration changed since the plan is refused before GitHub', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { cfg: config('source-only', { ...SLACK, rollout: { gateMode: 'log-only' }, semgrep: { rulesets: ['p/owasp-top-ten', 'p/python', 'p/javascript'] } }) });
    refused(r, 'config-changed');
    assert.equal(r.fake.calls.length, 0);
  });

  it('repository.defaultBranch changed since the plan is refused before GitHub', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { cfg: config('source-only', { ...SLACK, repository: { slug: 'acme/app', defaultBranch: 'trunk' } }) });
    refused(r, 'default-branch-changed');
    assert.equal(r.fake.calls.length, 0);
  });

  it('repository.slug changed since the plan is refused before GitHub', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { cfg: config('source-only', { ...SLACK, repository: { slug: 'acme/other', defaultBranch: 'main' } }), slug: 'acme/other' });
    refused(r, 'repository-mismatch');
    assert.equal(r.fake.calls.length, 0);
  });

  it('a framework checkout not bound to framework.ref is refused before GitHub', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { framework: { ...FRAMEWORK, sha: 'f'.repeat(40) } });
    refused(r, 'framework-binding');
    assert.equal(r.fake.calls.length, 0);
  });

  for (const [what, edit, kind] of [
    ['GitHub now reports another default branch', (w) => { w.repository = repositoryDoc({ default_branch: 'trunk' }); }, 'default-branch-mismatch'],
    ['the repository was renamed', (w) => { w.repository = repositoryDoc({ full_name: 'acme/renamed' }); }, 'identity-mismatch'],
    ['the repository was recreated (new id)', (w) => { w.repository = repositoryDoc({ id: 99 }); }, 'state-changed'],
    ['the secret was set by someone else meanwhile', (w) => { w.secrets.push({ name: SECRET, created_at: 'x', updated_at: 'x' }); }, 'state-changed']
  ]) {
    it(`${what}: refused`, async (t) => {
      const p = await planned(t);
      edit(p.world);
      const r = await apply(p);
      refused(r);
      assert.ok(kinds(r.report).includes(kind) || kinds(r.report).includes('identity'), kinds(r.report).join());
    });
  }

  it('an unknown local origin blocks apply (never mutate an unresolved identity)', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { f: facts({ slug: null }) });
    refused(r, 'origin-unknown');
  });

  it('a local origin naming another repository blocks apply', async (t) => {
    const p = await planned(t);
    refused(await apply(p, { f: facts({ slug: 'evil/app' }) }), 'origin-mismatch');
  });

  it('a change DURING confirmation is caught by the time-of-use re-check', async (t) => {
    const p = await planned(t);
    const r = await apply(p, {
      yes: false,
      confirm: async () => {
        p.world.secrets.push({ name: SECRET, created_at: 'y', updated_at: 'y' });
        return 'acme/app';
      }
    });
    refused(r, 'state-changed');
    assert.match(r.report.findings.at(-1).message, /immediately before the change/);
  });

  it('without --yes and without a terminal: refused', async (t) => {
    const p = await planned(t);
    refused(await apply(p, { yes: false, confirm: null }), 'confirmation-required');
  });
});

describe('github apply: plan integrity', () => {
  const edit = (p, fn) => {
    const path = join(p.root, planDirOf(p.planId), 'plan.json');
    writeFileSync(path, canonicalJson(fn(JSON.parse(readFileSync(path, 'utf8')))));
  };

  for (const [what, fn] of [
    ['edited operations', (plan) => ({ ...plan, planIdInput: { ...plan.planIdInput, operations: [{ ...plan.planIdInput.operations[0], name: 'OTHER' }] } })],
    ['an edited repository', (plan) => ({ ...plan, planIdInput: { ...plan.planIdInput, repository: { ...plan.planIdInput.repository, slug: 'evil/app' } } })],
    ['edited observed state', (plan) => ({ ...plan, observed: { secret: { ...plan.observed.secret, state: 'present' } } })],
    ['another schema version', (plan) => ({ ...plan, schemaVersion: 2 })]
  ]) {
    it(`${what} is refused with no GitHub call`, async (t) => {
      const p = await planned(t);
      edit(p, fn);
      const r = await apply(p);
      refused(r, 'plan-not-applicable');
      assert.equal(r.fake.calls.length, 0);
    });
  }

  it('a plan is applied at most once', async (t) => {
    const p = await planned(t);
    assert.equal((await apply(p)).report.outcome, 'APPLIED');
    const again = await apply(p);
    refused(again, 'already-applied');
    assert.equal(again.fake.calls.length, 0);
  });

  it('a missing plan is refused', async (t) => {
    const p = await planned(t);
    refused(await apply({ ...p, planId: 'e'.repeat(64) }), 'plan-not-applicable');
  });
});

describe('github apply: protection', () => {
  it('creates exactly the planned ruleset, once, by POST; a re-plan is then COMPLIANT (no duplicate)', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    const plan = JSON.parse(readFileSync(join(p.root, planDirOf(p.planId), 'plan.json'), 'utf8'));
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLIED', JSON.stringify(r.report.findings));
    const [m] = r.fake.mutationCalls();
    assert.equal(r.fake.mutationCalls().length, 1);
    assert.deepEqual(m.argv.slice(0, 3), ['api', '--method', 'POST']);
    assert.deepEqual(JSON.parse(m.stdin.toString()), plan.planIdInput.operations[0].body);
    assert.ok(r.fake.calls.every((c) => c === m || c.argv[2] === 'GET'), 'no PUT / PATCH / DELETE');
    assert.equal(r.report.verification.state, 'observed');
    const fake = githubFake(p.world, { mutations: [] });
    const again = await githubPlan({ config: CFG, facts: facts(), scope: 'protection', framework: FRAMEWORK, root: p.root, exec: fake.exec, env: {} });
    assert.equal(again.outcome, 'COMPLIANT');
    assert.equal(p.world.rulesets.filter((d) => d.name === 'ssd-merge-governance').length, 1);
  });

  it('unrelated rulesets survive apply byte for byte', async (t) => {
    const unrelated = rulesetDetail({ id: 9, name: 'tag protection', rules: [{ type: 'deletion', parameters: {} }] });
    const p = await planned(t, { scope: 'protection', world: githubWorld({ rulesets: [unrelated] }) });
    const before = JSON.stringify(unrelated);
    assert.equal((await apply(p)).report.outcome, 'APPLIED');
    assert.equal(JSON.stringify(p.world.rulesets.find((d) => d.id === 9)), before);
  });

  it('a ruleset added between plan and apply: refused (state changed)', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    p.world.rulesets.push(rulesetDetail({ id: 50, name: 'someone else' }));
    refused(await apply(p), 'state-changed');
  });

  it('admin permission lost between plan and apply: refused', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    p.world.repository = repositoryDoc({ permissions: { admin: false, maintain: true, push: true, triage: true, pull: true } });
    refused(await apply(p), 'state-changed');
  });

  it('GitHub refusing the POST: APPLY FAILED (outcome known)', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    p.world.overrides['POST rulesets'] = { status: 403, message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' };
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.outcomeKnown, true);
  });

  it('a POST that times out: APPLY FAILED with the outcome UNKNOWN, said explicitly', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    p.world.overrides['POST rulesets'] = { timeout: true };
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.outcomeKnown, false);
    assert.match(r.report.findings.at(-1).message, /UNKNOWN/);
  });

  it('a POST answered 5xx: APPLY FAILED with the outcome UNKNOWN (GitHub may have created it)', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    p.world.overrides['POST rulesets'] = { status: 502, message: 'Bad Gateway' };
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.outcomeKnown, false);
  });

  it('a protection plan can never set a secret, and a secrets plan can never create a ruleset', async (t) => {
    const p = await planned(t, { scope: 'protection' });
    const fake = githubFake(p.world, { mutations: ['ruleset'] });
    const report = await githubApply({ config: CFG, facts: facts(), planId: p.planId, slug: 'acme/app', yes: true, readSecret: async () => assert.fail('a protection plan never reads a secret'), framework: FRAMEWORK, root: p.root, exec: fake.exec, env: {} });
    assert.equal(report.outcome, 'APPLIED');
    assert.ok(fake.calls.every((c) => c.argv[0] === 'api'));
  });
});

describe('github apply: records never hold a secret', () => {
  it('writeApplyRecord refuses text containing the exact value being applied (any shape)', async (t) => {
    const { writeApplyRecord, PlanRecordError } = await import('../onboarding/github/record.mjs');
    const p = await planned(t);
    const value = Buffer.from('opaque-not-a-url-value');
    await assert.rejects(writeApplyRecord(p.root, p.planId, 'apply.json', `{"x":"opaque-not-a-url-value"}`, { env: {}, secrets: [value] }), (e) => e instanceof PlanRecordError && e.kind === 'secret-in-plan' && !e.message.includes('opaque'));
    await assert.rejects(writeApplyRecord(p.root, p.planId, 'apply.json', `{"x":"${WEBHOOK}"}`, { env: {} }), (e) => e.kind === 'secret-in-plan');
  });
});
