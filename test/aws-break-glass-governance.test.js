// Phase 3D (C5): the break-glass governance stack — the framework policy file,
// admission, the template and scope, `aws plan --scope break-glass-governance`,
// apply intent, `aws verify --scope break-glass-governance` and the CLI.
// No test talks to AWS or to another commit through real git.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { parseFrameworkPolicy } from '../broker/identity/framework-policy.mjs';
import { main } from '../onboarding/cli.mjs';
import { assertBreakGlassPlanning, assertGovernancePlanning, assertGovernanceRead } from '../onboarding/aws/aws-cli.mjs';
import { awsApply } from '../onboarding/aws/apply.mjs';
import { checkIntent, checkPlanRecord } from '../onboarding/aws/apply/plan-check.mjs';
import { admissionFindings, bindingProblems } from '../onboarding/aws/break-glass/admission.mjs';
import { FrameworkPolicyConfigError, frameworkPolicyValue, parseFrameworkPolicyConfig, validateFrameworkPolicyConfig } from '../onboarding/aws/break-glass/framework-policy-config.mjs';
import { awsPlanBreakGlassGovernance } from '../onboarding/aws/break-glass/governance-plan.mjs';
import { awsVerifyBreakGlassGovernance } from '../onboarding/aws/break-glass/governance-verify.mjs';
import { planDirOf, readPlan } from '../onboarding/aws/plan/record.mjs';
import { ScopeError, assertChangeScope, assertTemplateScope } from '../onboarding/aws/plan/scope.mjs';
import { breakGlassEnvironmentOf, breakGlassKindOf } from '../onboarding/aws/stack-names.mjs';
import { renderGovernanceTemplate } from '../onboarding/aws/templates/break-glass-governance.mjs';
import { FRAMEWORK, capture, tempDir } from './support/onboarding-fixtures.mjs';
import { fakeAws, ok } from './support/aws-fake.mjs';
import { applyWorld, mutations } from './support/aws-apply-fake.mjs';
import { withStack } from './support/aws-plan-fake.mjs';
import { OPERATOR_YAML, operator, tagsFor } from './support/break-glass-fake.mjs';
import {
  ACCOUNT,
  BOUND_WORKFLOW,
  CANDIDATE_BOUND,
  MAIN,
  MERGED_BOUND,
  MERGED_UNBOUND,
  MISSING,
  REGION,
  UNBOUND_WORKFLOW,
  deployedGovernance,
  existingParameter,
  fakeGit,
  greenfieldGovernance,
  parameterArn,
  policy,
  policyYaml,
  rawPolicy
} from './support/governance-fake.mjs';

const quiet = async () => {};
const kinds = (findings) => findings.map((f) => f.kind);
const NAME = (env) => `/ssd/break-glass/${env}/governance/allowed-framework-shas`;
const STACK = (env) => `ssd-break-glass-${env}-governance`;
const refusedBy = (assertFn, argv) => assert.throws(() => assertFn(argv), (e) => e.kind === 'refused', argv.join(' '));

async function plan(t, world, { environment = 'synthetic', pol = policy(environment), op = operator(), framework = FRAMEWORK, git = fakeGit(), region = null, root = tempDir(t) } = {}) {
  const f = fakeAws(world, { allowlist: assertGovernancePlanning });
  const report = await awsPlanBreakGlassGovernance({ operator: op, policy: pol, environment, region, exec: f.exec, env: {}, framework, git, root, sleep: quiet });
  assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
  return { report, f, root, git, unit: report.units[0], created: world.__changeSets?.created ?? [] };
}

describe('governance: the framework policy file', () => {
  it('accepts a valid set and renders the canonical, sorted value the broker parses', () => {
    const p = policy('synthetic', [CANDIDATE_BOUND, MERGED_BOUND]);
    assert.deepEqual(p.allowedFrameworkShas, [MERGED_BOUND, CANDIDATE_BOUND], 'held sorted, whatever the file order');
    assert.equal(frameworkPolicyValue(p), `{"schemaVersion":1,"environment":"synthetic","shas":["${MERGED_BOUND}","${CANDIDATE_BOUND}"]}`);
    assert.equal(parseFrameworkPolicy(frameworkPolicyValue(p), 'synthetic').state, 'valid');
    assert.ok(Object.isFrozen(p) && Object.isFrozen(p.allowedFrameworkShas));
  });

  it('an empty list is valid and admits nothing', () => {
    const p = parseFrameworkPolicyConfig(policyYaml('production', []), { environment: 'production' });
    assert.deepEqual(p.allowedFrameworkShas, []);
    assert.equal(frameworkPolicyValue(p), '{"schemaVersion":1,"environment":"production","shas":[]}');
  });

  const refused = (raw, options = { environment: 'synthetic' }) => assert.throws(() => validateFrameworkPolicyConfig(raw, options), FrameworkPolicyConfigError, JSON.stringify(raw).slice(0, 120));
  it('refuses duplicates, bad SHAs, more than 64, wrong kind/version, unknown keys and missing keys', () => {
    refused(rawPolicy('synthetic', [MERGED_BOUND, MERGED_BOUND]));
    for (const bad of [MERGED_BOUND.toUpperCase(), MERGED_BOUND.slice(0, 39), `${MERGED_BOUND}0`, 'v1', 'main', 7]) refused(rawPolicy('synthetic', [bad]));
    refused(rawPolicy('synthetic', Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(40, '0'))));
    assert.equal(validateFrameworkPolicyConfig(rawPolicy('synthetic', Array.from({ length: 64 }, (_, i) => i.toString(16).padStart(40, '0'))), { environment: 'synthetic' }).allowedFrameworkShas.length, 64);
    refused(rawPolicy('synthetic', [MERGED_BOUND], { kind: 'break-glass-repository' }));
    refused(rawPolicy('synthetic', [MERGED_BOUND], { schemaVersion: 1 }));
    refused({ ...rawPolicy(), approvers: [] });
    const { allowedFrameworkShas, ...missing } = rawPolicy();
    refused(missing);
    refused(rawPolicy('synthetic', 'aaaa'));
  });

  it('the file must name --environment: a production file never plans synthetic, nor the reverse', () => {
    refused(rawPolicy('production', [MERGED_BOUND]), { environment: 'synthetic' });
    refused(rawPolicy('synthetic', [MERGED_BOUND]), { environment: 'production' });
    refused(rawPolicy('staging', [MERGED_BOUND]), {});
  });

  it('refuses a credential-shaped value, naming the shape and never echoing it', () => {
    for (const raw of [rawPolicy('synthetic', [MERGED_BOUND], { note: 'AKIAABCDEFGHIJKLMNOP' }), rawPolicy('synthetic', ['AKIAABCDEFGHIJKLMNOP'])]) {
      assert.throws(() => validateFrameworkPolicyConfig(raw, { environment: 'synthetic' }), (e) => e instanceof FrameworkPolicyConfigError && e.problems.length > 0 && e.problems.every((p) => /looks like a/.test(p)) && !e.message.includes('AKIAABCDEFGHIJKLMNOP'));
    }
  });
});

describe('governance: admission', () => {
  it('the committed workflow binds itself; the pre-3D one does not', () => {
    assert.deepEqual(bindingProblems(BOUND_WORKFLOW), []);
    const problems = bindingProblems(UNBOUND_WORKFLOW);
    assert.ok(problems.some((p) => p.includes('inputs.toolkit_ref')));
    assert.ok(problems.some((p) => p.includes('no step with id bind-framework-commit')));
    assert.deepEqual(bindingProblems(null), ['.github/workflows/_break-glass-lambda.yml does not exist at this commit']);
  });

  it('refuses a binding step that is not first, a checkout before it, a second unbound checkout, or a duplicate binding id', () => {
    const notFirst = BOUND_WORKFLOW.replace('    steps:\n', '    steps:\n      - name: Something first\n        run: echo hi\n\n');
    assert.ok(bindingProblems(notFirst).some((p) => p.includes("not the job's first step")));
    const checkoutFirst = BOUND_WORKFLOW.replace('    steps:\n', '    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ steps.bind-framework-commit.outputs.sha }}\n\n');
    assert.ok(bindingProblems(checkoutFirst).some((p) => p.includes('runs before')));
    const second = `${BOUND_WORKFLOW}\n      - name: Another\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: main\n`;
    assert.ok(bindingProblems(second).some((p) => p.includes('a checkout that is not at')));
    const twice = BOUND_WORKFLOW.replace('id: bind-framework-commit', 'id: bind-framework-commit\n        # duplicate\n        id: bind-framework-commit');
    assert.ok(bindingProblems(twice).some((p) => p.includes('more than one')));
  });

  it('production: merged and bound is admitted; unmerged, unbound and missing are refused; origin/main is recorded', async () => {
    const r = await admissionFindings({ environment: 'production', shas: [MERGED_BOUND, CANDIDATE_BOUND, MERGED_UNBOUND, MISSING], git: fakeGit() });
    assert.equal(r.originMain, MAIN);
    assert.deepEqual(r.findings.map((f) => [f.severity, f.kind, f.message.slice(0, 40)]).sort(), [
      ['FAIL', 'binding-missing', MERGED_UNBOUND],
      ['FAIL', 'binding-missing', MERGED_UNBOUND],
      ['FAIL', 'binding-missing', MERGED_UNBOUND],
      ['FAIL', 'commit-missing', MISSING],
      ['FAIL', 'not-merged', CANDIDATE_BOUND]
    ].sort());
    assert.ok(r.observed.includes(`${MERGED_BOUND}: admitted`));
  });

  it('synthetic: an unmerged, bound candidate is admitted (and no ancestry is asked)', async () => {
    const git = fakeGit();
    const r = await admissionFindings({ environment: 'synthetic', shas: [CANDIDATE_BOUND], git });
    assert.deepEqual(r.findings, []);
    assert.equal(r.originMain, null);
    assert.ok(!git.asked.some(([q]) => q === 'isAncestor' || q === 'resolve'));
  });

  it('synthetic still refuses an unbound or missing commit', async () => {
    const r = await admissionFindings({ environment: 'synthetic', shas: [MERGED_UNBOUND, MISSING], git: fakeGit() });
    assert.ok(kinds(r.findings).includes('binding-missing') && kinds(r.findings).includes('commit-missing'));
  });

  it('production without a resolvable origin/main refuses; a git that cannot answer is NOT VERIFIED (never admitted)', async () => {
    const noMain = await admissionFindings({ environment: 'production', shas: [MERGED_BOUND], git: fakeGit({ originMain: null }) });
    assert.ok(kinds(noMain.findings).includes('origin-main-unknown'));
    const mute = await admissionFindings({ environment: 'synthetic', shas: [CANDIDATE_BOUND], git: fakeGit({ unanswerable: [CANDIDATE_BOUND] }) });
    assert.deepEqual(mute.findings.map((f) => f.severity), ['NOT VERIFIED']);
  });

  it('an empty set needs no git at all', async () => {
    const git = fakeGit();
    assert.deepEqual((await admissionFindings({ environment: 'production', shas: [], git })).findings, []);
    assert.deepEqual(git.asked, []);
  });
});

describe('governance: template and scope', () => {
  for (const environment of ['production', 'synthetic']) {
    it(`${environment}: exactly one retained String/Standard/text parameter with the canonical value`, () => {
      const p = policy(environment, environment === 'production' ? [] : [CANDIDATE_BOUND]);
      const { template } = renderGovernanceTemplate({ policy: p, environment });
      assert.deepEqual(Object.keys(template), ['AWSTemplateFormatVersion', 'Description', 'Resources']);
      assert.deepEqual(Object.keys(template.Resources), ['AllowedFrameworkShas']);
      const r = template.Resources.AllowedFrameworkShas;
      assert.equal(r.Type, 'AWS::SSM::Parameter');
      assert.equal(r.DeletionPolicy, 'Retain');
      assert.equal(r.UpdateReplacePolicy, 'Retain');
      assert.equal(r.Properties.Name, NAME(environment));
      assert.equal(r.Properties.Type, 'String');
      assert.equal(r.Properties.Tier, 'Standard');
      assert.equal(r.Properties.DataType, 'text');
      assert.equal(r.Properties.Value, frameworkPolicyValue(p));
      assert.deepEqual(r.Properties.Tags, Object.fromEntries(tagsFor(environment).map((tag) => [tag.Key, tag.Value])));
      assertTemplateScope(`break-glass-governance-${environment}`, template);
    });
  }

  it('a policy of the other environment cannot be rendered', () => {
    assert.throws(() => renderGovernanceTemplate({ policy: policy('production', []), environment: 'synthetic' }));
  });

  it('the governance kind holds only its parameter; the shared kind never holds one', () => {
    const { template } = renderGovernanceTemplate({ policy: policy('synthetic', []), environment: 'synthetic' });
    const kind = 'break-glass-governance-synthetic';
    const extra = (id, type) => ({ ...template, Resources: { ...template.Resources, [id]: { Type: type, DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain', Properties: {} } } });
    assert.throws(() => assertTemplateScope(kind, extra('Role', 'AWS::IAM::Role')), ScopeError);
    assert.throws(() => assertTemplateScope(kind, extra('Other', 'AWS::SSM::Parameter')), ScopeError);
    assert.throws(() => assertTemplateScope(kind, { ...template, Resources: { AllowedFrameworkShas: { ...template.Resources.AllowedFrameworkShas, DeletionPolicy: 'Delete' } } }), ScopeError);
    assert.throws(() => assertTemplateScope('break-glass-synthetic', template), ScopeError);
    assert.throws(() => assertChangeScope(kind, [{ logicalId: 'AllowedFrameworkShas', type: 'AWS::IAM::Role' }]), ScopeError);
    assert.throws(() => assertTemplateScope('break-glass-governance-staging', template), ScopeError);
  });

  it('stack kinds are exact: never inferred from a prefix', () => {
    assert.deepEqual(breakGlassKindOf('break-glass-governance-synthetic'), { family: 'governance', environment: 'synthetic' });
    assert.deepEqual(breakGlassKindOf('break-glass-production'), { family: 'shared', environment: 'production' });
    for (const k of ['break-glass-governance-staging', 'break-glass-governance', 'break-glass-governance-production-x', 'repo', null]) assert.equal(breakGlassKindOf(k), null, String(k));
    assert.equal(breakGlassEnvironmentOf('break-glass-governance-production'), 'production');
  });
});

describe('governance: the allowlists', () => {
  it('the governance planner reaches only governance stacks and the governance parameter', () => {
    const body = JSON.stringify({ Resources: {} });
    const tags = JSON.stringify(tagsFor('synthetic'));
    const cs = (stack, extra = []) => ['cloudformation', 'create-change-set', '--stack-name', stack, '--change-set-name', `ssd-plan-${'0'.repeat(64)}`, '--change-set-type', 'CREATE', '--template-body', body, '--tags', tags, ...extra];
    assertGovernancePlanning(cs(STACK('synthetic')));
    assertGovernancePlanning(['ssm', 'get-parameter', '--name', NAME('production')]);
    for (const argv of [
      cs('ssd-break-glass-synthetic'),
      cs('ssd-break-glass-synthetic-repo-1001'),
      cs(STACK('synthetic'), ['--capabilities', 'CAPABILITY_NAMED_IAM']),
      cs(STACK('synthetic')).map((v) => (v === 'CREATE' ? 'IMPORT' : v)),
      ['cloudformation', 'execute-change-set', '--stack-name', STACK('synthetic'), '--change-set-name', 'x'],
      ['ssm', 'put-parameter', '--name', NAME('synthetic')],
      ['ssm', 'get-parameter', '--name', '/ssd/break-glass/synthetic/approvers/1001'],
      ['ssm', 'get-parameter', '--name', NAME('synthetic'), '--with-decryption'],
      ['ssm', 'get-parameters-by-path', '--path', '/ssd/break-glass/'],
      ['iam', 'get-role', '--role-name', 'x'],
      ['secretsmanager', 'describe-secret', '--secret-id', 'ssd/break-glass/synthetic/slack-bot-token']
    ]) refusedBy(assertGovernancePlanning, argv);
    // ... and the shared break-glass planner never reaches a governance stack.
    refusedBy(assertBreakGlassPlanning, cs(STACK('production')).concat([]));
  });

  it('governance verify reads exactly: one-name describe-parameters, simulation of the execution roles only, no write', () => {
    const filter = (values, extra = {}) => JSON.stringify([{ Key: 'Name', Option: 'Equals', Values: values, ...extra }]);
    assertGovernanceRead(['ssm', 'describe-parameters', '--parameter-filters', filter([NAME('synthetic')])]);
    assertGovernanceRead(['iam', 'simulate-principal-policy', '--policy-source-arn', `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-production-ci-execution`, '--action-names', '["ssm:GetParameter"]', '--resource-arns', '["x"]']);
    for (const argv of [
      ['ssm', 'describe-parameters', '--parameter-filters', filter(['/ssd/break-glass/'])],
      ['ssm', 'describe-parameters', '--parameter-filters', filter([NAME('synthetic'), NAME('production')])],
      ['ssm', 'describe-parameters', '--parameter-filters', JSON.stringify([{ Key: 'Name', Option: 'BeginsWith', Values: [NAME('synthetic')] }])],
      ['ssm', 'describe-parameters'],
      ['iam', 'simulate-principal-policy', '--policy-source-arn', `arn:aws:iam::${ACCOUNT}:role/admin`, '--action-names', '[]', '--resource-arns', '[]'],
      ['ssm', 'put-parameter', '--name', NAME('synthetic')],
      ['cloudformation', 'create-change-set', '--stack-name', STACK('synthetic')]
    ]) refusedBy(assertGovernanceRead, argv);
  });
});

describe('aws plan --scope break-glass-governance', () => {
  it('a framework checkout not bound to framework.ref blocks before AWS (and before admission)', async (t) => {
    const { report, f, git } = await plan(t, greenfieldGovernance(), { framework: { ...FRAMEWORK, sha: 'f'.repeat(40) } });
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(report.findings).includes('framework-binding'));
    assert.equal(f.calls.length, 0);
    assert.deepEqual(git.asked, []);
  });

  it('an inadmissible commit blocks before AWS is contacted', async (t) => {
    for (const [environment, shas, kind] of [
      ['production', [CANDIDATE_BOUND], 'not-merged'],
      ['synthetic', [MERGED_UNBOUND], 'binding-missing'],
      ['synthetic', [MISSING], 'commit-missing']
    ]) {
      const { report, f, created } = await plan(t, greenfieldGovernance(environment), { environment, pol: policy(environment, shas) });
      assert.equal(report.outcome, 'BLOCKED', `${environment} ${kind}`);
      assert.ok(kinds(report.findings).includes(kind));
      assert.equal(f.calls.length, 0);
      assert.equal(created.length, 0);
    }
    const mute = await plan(t, greenfieldGovernance(), { git: fakeGit({ unanswerable: [CANDIDATE_BOUND] }), pol: policy('synthetic', [CANDIDATE_BOUND]) });
    assert.equal(mute.report.outcome, 'BLOCKED', 'NOT VERIFIED admission blocks too');
  });

  it('synthetic greenfield: one CREATE change set, no IAM capability, the canonical value, the admission recorded', async (t) => {
    const p = policy('synthetic', [CANDIDATE_BOUND]);
    const { report, unit, created, root } = await plan(t, greenfieldGovernance('synthetic'), { pol: p });
    assert.equal(report.outcome, 'PLANNED', JSON.stringify(report.units[0]?.findings ?? report.findings));
    assert.equal(created.length, 1);
    const cs = created[0];
    assert.equal(cs.stackName, STACK('synthetic'));
    assert.equal(cs.type, 'CREATE');
    assert.deepEqual(cs.capabilities, []);
    assert.ok(!cs.argv.includes('--capabilities'));
    assert.deepEqual(cs.tags, tagsFor('synthetic'));
    assert.deepEqual(Object.keys(cs.template.Resources), ['AllowedFrameworkShas']);
    assert.equal(cs.template.Resources.AllowedFrameworkShas.Properties.Value, frameworkPolicyValue(p));
    const planJson = JSON.parse(readFileSync(join(root, planDirOf(unit.planId), 'plan.json'), 'utf8'));
    assert.equal(planJson.scope, 'break-glass');
    assert.equal(planJson.stackKind, 'break-glass-governance-synthetic');
    assert.equal(planJson.repository, null);
    assert.deepEqual(planJson.admission, { environment: 'synthetic', shas: [CANDIDATE_BOUND], originMain: null });
    const read = await readPlan(root, unit.planId);
    assert.deepEqual(checkPlanRecord(read).findings, []);
  });

  it('production: a merged commit plans and the origin/main it was checked against is recorded; [] plans too', async (t) => {
    const merged = await plan(t, greenfieldGovernance('production'), { environment: 'production', pol: policy('production', [MERGED_BOUND]) });
    assert.equal(merged.report.outcome, 'PLANNED');
    const planJson = JSON.parse(readFileSync(join(merged.root, planDirOf(merged.unit.planId), 'plan.json'), 'utf8'));
    assert.deepEqual(planJson.admission, { environment: 'production', shas: [MERGED_BOUND], originMain: MAIN });
    const empty = await plan(t, greenfieldGovernance('production'), { environment: 'production', pol: policy('production', []) });
    assert.equal(empty.report.outcome, 'PLANNED');
    assert.equal(empty.created[0].template.Resources.AllowedFrameworkShas.Properties.Value, '{"schemaVersion":1,"environment":"production","shas":[]}');
  });

  it('a parameter that merely has the name is never adopted', async (t) => {
    for (const owner of [null, 'ssd-break-glass-synthetic', 'some-other-stack', STACK('production')]) {
      const world = existingParameter(greenfieldGovernance('synthetic'), 'synthetic', { stackName: owner });
      const { report, created } = await plan(t, world);
      assert.equal(report.outcome, 'BLOCKED', String(owner));
      assert.ok(kinds(report.units[0].findings).includes('exists-not-owned'), String(owner));
      assert.equal(created.length, 0);
    }
  });

  it("a stack of that name tagged for the other environment, or unsettled, is never updated", async (t) => {
    for (const [tags, status] of [[tagsFor('production'), 'CREATE_COMPLETE'], [tagsFor('synthetic'), 'UPDATE_ROLLBACK_FAILED'], [[], 'CREATE_COMPLETE']]) {
      const world = withStack(greenfieldGovernance('synthetic'), { name: STACK('synthetic'), tags, status, resources: [] });
      const { report, created } = await plan(t, world);
      assert.equal(report.outcome, 'BLOCKED');
      assert.ok(kinds(report.units[0].findings).includes('stack-not-plannable'));
      assert.equal(created.length, 0);
    }
  });

  it('an owned stack: the value change is an UPDATE of the same parameter', async (t) => {
    const world = withStack(greenfieldGovernance('synthetic'), { name: STACK('synthetic'), tags: tagsFor('synthetic'), resources: [{ logicalId: 'AllowedFrameworkShas', physicalId: NAME('synthetic'), type: 'AWS::SSM::Parameter' }] });
    world[`ssm get-parameter --name ${NAME('synthetic')}`] = ok({ Parameter: { Name: NAME('synthetic'), Type: 'String', Value: '{}', ARN: parameterArn('synthetic'), DataType: 'text' } });
    const { report, created } = await plan(t, world);
    assert.equal(report.outcome, 'PLANNED', JSON.stringify(report.units[0]?.findings));
    assert.equal(created[0].type, 'UPDATE');
  });

  it('a policy of another environment is refused outright', async (t) => {
    await assert.rejects(plan(t, greenfieldGovernance('synthetic'), { pol: policy('production', []) }), (e) => e.kind === 'environment-mismatch');
  });
});

describe('aws apply of a governance plan', () => {
  async function planned(t, pol = policy('synthetic', [CANDIDATE_BOUND])) {
    const r = await plan(t, greenfieldGovernance('synthetic'), { pol });
    assert.equal(r.report.outcome, 'PLANNED');
    return { root: r.root, planId: r.unit.planId, pol };
  }

  it('applies exactly the reviewed change set once, with the files it was planned from', async (t) => {
    const p = await planned(t);
    const w = applyWorld({ root: p.root, planId: p.planId });
    const report = await awsApply({ operator: operator(), policy: p.pol, planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
    assert.equal(report.outcome, 'APPLIED', JSON.stringify(report.findings));
    assert.equal(mutations(w.fake), 1);
    assert.ok(report.nextSteps.some((s) => s.includes('aws verify --scope break-glass-governance --environment synthetic')));
  });

  it('refuses without the policy, with a changed policy, or with a policy of the other environment', async (t) => {
    const p = await planned(t);
    const { plan: planJson } = await readPlan(p.root, p.planId);
    const intent = (extra) => kinds(checkIntent({ plan: planJson, operator: operator(), framework: FRAMEWORK, account: ACCOUNT, region: REGION, ...extra }));
    assert.deepEqual(intent({ policy: p.pol }), []);
    assert.deepEqual(intent({}), ['config-kind-mismatch']);
    assert.deepEqual(intent({ policy: policy('synthetic', [CANDIDATE_BOUND, MERGED_BOUND]) }), ['config-changed']);
    assert.deepEqual(intent({ policy: policy('synthetic', []) }), ['config-changed']);
    assert.ok(intent({ policy: policy('production', []) }).includes('environment-mismatch'));
    assert.deepEqual(intent({ policy: p.pol, operator: operator({ aws: { accountId: ACCOUNT, region: 'eu-west-1' } }) }).sort(), ['config-changed', 'region-mismatch']);
    // Nothing was executed by any refusal.
    const w = applyWorld({ root: p.root, planId: p.planId });
    const report = await awsApply({ operator: operator(), planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
    assert.equal(report.outcome, 'REFUSED');
    assert.equal(w.fake.calls.length, 0);
  });

  it('a shared-stack plan is never applied with a policy file', () => {
    const shared = { scope: 'break-glass', stackKind: 'break-glass-synthetic', stackName: 'ssd-break-glass-synthetic', account: ACCOUNT, region: REGION };
    assert.deepEqual(kinds(checkIntent({ plan: shared, operator: operator(), policy: policy('synthetic', []), framework: FRAMEWORK, account: ACCOUNT, region: REGION })), ['config-kind-mismatch']);
  });
});

describe('aws verify --scope break-glass-governance', () => {
  async function verify(world, { environment = 'synthetic', pol = policy(environment), git = fakeGit(), framework = FRAMEWORK } = {}) {
    const f = fakeAws(world, { allowlist: assertGovernanceRead });
    const report = await awsVerifyBreakGlassGovernance({ operator: operator(), policy: pol, environment, exec: f.exec, env: {}, framework, git });
    assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
    return { report, f, byId: Object.fromEntries(report.checks.map((c) => [c.id, c])) };
  }
  const status = (byId, id) => byId[id]?.status;

  for (const environment of ['production', 'synthetic']) {
    it(`${environment}: the deployed stack verifies; only the non-enumerable writers stay advisory`, async () => {
      const pol = policy(environment, environment === 'production' ? [MERGED_BOUND] : [CANDIDATE_BOUND]);
      const { report, byId, f } = await verify(deployedGovernance(environment, pol), { environment, pol });
      const notPass = report.checks.filter((c) => c.status !== 'PASS').map((c) => `${c.id}:${c.status}`);
      assert.deepEqual(notPass, ['bg.gov.other-writers:NOT VERIFIED'], JSON.stringify(report.checks.filter((c) => c.status !== 'PASS').map((c) => c.findings)));
      assert.equal(byId['bg.gov.other-writers'].required, false);
      assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS');
      assert.ok(!f.operations().some((op) => /put|delete|create|execute/.test(op.split(' ')[1])));
    });
  }

  it('value drift FAILs, and an emergency revoke is reported as drift (never as PASS)', async () => {
    const world = deployedGovernance();
    world.__parameter.Value = '{"schemaVersion":1,"environment":"synthetic","shas":[]}';
    const { byId, report } = await verify(world);
    assert.equal(status(byId, 'bg.gov.parameter'), 'FAIL');
    assert.ok(byId['bg.gov.parameter'].findings.some((x) => x.message.includes('emergency revoke')));
    assert.equal(status(byId, 'bg.gov.parser'), 'PASS', 'the broker accepts it: it admits nothing');
    assert.equal(report.outcome, 'FAILED');
    const reordered = deployedGovernance();
    reordered.__parameter.Value = reordered.__parameter.Value.replace('{"schemaVersion":1,', '{ "schemaVersion":1,');
    const r2 = await verify(reordered);
    assert.equal(status(r2.byId, 'bg.gov.parameter'), 'FAIL', 'byte-equal, not JSON-equal');
    assert.equal(status(r2.byId, 'bg.gov.parser'), 'PASS');
  });

  it("another environment's value is refused by the parser and admits nothing", async () => {
    const world = deployedGovernance();
    world.__parameter.Value = frameworkPolicyValue(policy('production', [MERGED_BOUND]));
    const { byId } = await verify(world);
    assert.equal(status(byId, 'bg.gov.parser'), 'FAIL');
    assert.equal(status(byId, 'bg.gov.parameter'), 'FAIL');
    assert.equal(status(byId, 'bg.gov.admission'), 'NOT VERIFIED');
  });

  it('wrong Type, DataType, Tier, ARN, or a missing parameter FAIL', async () => {
    for (const [mutate, kind] of [
      [(w) => (w.__parameter.Type = 'SecureString'), 'parameter-type'],
      [(w) => (w.__parameter.Type = 'StringList'), 'parameter-type'],
      [(w) => (w.__parameter.DataType = 'aws:ec2:image'), 'managed-drift'],
      [(w) => (w.__tier = 'Advanced'), 'managed-drift'],
      [(w) => (w.__parameter.ARN = parameterArn('production')), 'parameter-location'],
      [(w) => (w.__parameter = null), 'parameter-missing']
    ]) {
      const world = deployedGovernance();
      mutate(world);
      const { byId } = await verify(world);
      assert.equal(status(byId, 'bg.gov.parameter'), 'FAIL', kind);
      assert.ok(kinds(byId['bg.gov.parameter'].findings).includes(kind), kind);
    }
  });

  it('the stack must be ours: tags, status, exact resources and physical id', async () => {
    for (const [mutate, kind] of [
      [(w) => (w.__stack.Tags = tagsFor('production')), 'stack-not-owned'],
      [(w) => (w.__stack.StackStatus = 'UPDATE_ROLLBACK_FAILED'), 'stack-unsettled'],
      [(w) => w.__resources.push({ ...w.__resources[0], LogicalResourceId: 'Extra', PhysicalResourceId: '/x' }), 'unexpected-resource'],
      [(w) => w.__resources.push({ ...w.__resources[0], LogicalResourceId: 'Role', ResourceType: 'AWS::IAM::Role' }), 'unexpected-resource'],
      [(w) => (w.__resources[0].PhysicalResourceId = NAME('production')), 'physical-id'],
      [(w) => (w.__resources = []), 'resource-missing']
    ]) {
      const world = deployedGovernance();
      mutate(world);
      const { byId } = await verify(world);
      assert.equal(status(byId, 'bg.gov.stack'), 'FAIL', kind);
      assert.ok(kinds(byId['bg.gov.stack'].findings).includes(kind), kind);
    }
  });

  it('every LIVE commit is admission-checked; no framework checkout is NOT VERIFIED (required)', async () => {
    const unbound = deployedGovernance('synthetic', policy('synthetic', [MERGED_UNBOUND]));
    const r1 = await verify(unbound, { pol: policy('synthetic', [MERGED_UNBOUND]) });
    assert.equal(status(r1.byId, 'bg.gov.admission'), 'FAIL');
    const prod = deployedGovernance('production', policy('production', [CANDIDATE_BOUND]));
    const r2 = await verify(prod, { environment: 'production', pol: policy('production', [CANDIDATE_BOUND]) });
    assert.ok(kinds(r2.byId['bg.gov.admission'].findings).includes('not-merged'));
    const r3 = await verify(deployedGovernance(), { git: null, framework: null });
    assert.equal(status(r3.byId, 'bg.gov.admission'), 'NOT VERIFIED');
    assert.equal(r3.report.outcome, 'NOT_VERIFIED');
  });

  it("readers: this environment's roles must read it; a missing grant FAILs", async () => {
    const world = deployedGovernance();
    const ci = `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-synthetic-ci-execution`;
    world.__roles[ci] = { ...world.__roles[ci], Statement: world.__roles[ci].Statement.filter((s) => s.Sid !== 'ReadFrameworkPolicy') };
    const { byId } = await verify(world);
    assert.equal(status(byId, 'bg.gov.ci-reads'), 'FAIL');
    assert.equal(status(byId, 'bg.gov.interactions-reads'), 'PASS');
  });

  it('writers and the other environment: any write, or a cross-environment read, FAILs', async () => {
    const own = deployedGovernance();
    const ci = `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-synthetic-interactions-execution`;
    own.__roles[ci].Statement.push({ Sid: 'Bad', Effect: 'Allow', Action: 'ssm:PutParameter', Resource: parameterArn('synthetic') });
    assert.equal(status((await verify(own)).byId, 'bg.gov.interactions-never-writes'), 'FAIL');
    for (const action of ['ssm:GetParameter', 'ssm:DeleteParameter']) {
      const cross = deployedGovernance();
      const prodCi = `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-production-ci-execution`;
      cross.__roles[prodCi].Statement.push({ Sid: 'Bad', Effect: 'Allow', Action: action, Resource: 'arn:aws:ssm:*:*:parameter/ssd/break-glass/*' });
      assert.equal(status((await verify(cross)).byId, 'bg.gov.production-ci-separated'), 'FAIL', action);
    }
  });

  it("the other environment not deployed (NoSuchEntity) proves its denial; an absent OWN role is never a pass", async () => {
    const world = deployedGovernance();
    world.__absentRoles = ['ci', 'interactions'].map((r) => `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-production-${r}-execution`);
    const { byId, report } = await verify(world);
    assert.equal(status(byId, 'bg.gov.production-ci-separated'), 'PASS');
    assert.match(byId['bg.gov.production-ci-separated'].observed[0], /does not exist/);
    assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS');
    const own = deployedGovernance();
    own.__absentRoles = [`arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-synthetic-ci-execution`];
    const r2 = await verify(own);
    assert.equal(status(r2.byId, 'bg.gov.ci-reads'), 'NOT VERIFIED');
    assert.equal(status(r2.byId, 'bg.gov.ci-never-writes'), 'NOT VERIFIED');
    assert.equal(r2.report.outcome, 'NOT_VERIFIED');
    // Any other simulator failure is never read as absence.
    const denied = deployedGovernance();
    const base = denied['iam simulate-principal-policy *'];
    denied['iam simulate-principal-policy *'] = (argv) => (argv.includes(`arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-production-ci-execution`) ? { stdout: '', stderr: '\nAn error occurred (AccessDenied) when calling the SimulatePrincipalPolicy operation: no\n', exitCode: 254 } : base(argv));
    assert.equal(status((await verify(denied)).byId, 'bg.gov.production-ci-separated'), 'NOT VERIFIED');
  });

  it('a policy file of the other environment is refused before AWS', async () => {
    await assert.rejects(awsVerifyBreakGlassGovernance({ operator: operator(), policy: policy('production', []), environment: 'synthetic', exec: async () => { throw new Error('no AWS'); }, env: {} }), (e) => e.kind === 'configuration');
  });
});

describe('ssd-onboard aws … --scope break-glass-governance (CLI)', () => {
  const files = (t, { environment = 'synthetic', shas = [CANDIDATE_BOUND] } = {}) => {
    const dir = tempDir(t);
    writeFileSync(join(dir, 'break-glass.yml'), OPERATOR_YAML);
    writeFileSync(join(dir, 'policy.yml'), policyYaml(environment, shas));
    return dir;
  };
  const cli = async (args, extra = {}) => {
    const c = capture();
    const code = await main(['aws', ...args], { ...c.io, framework: FRAMEWORK, frameworkGit: fakeGit(), env: {}, awsSleep: quiet, ...extra });
    return { code, out: c.out.join('\n'), err: c.err.join('\n') };
  };

  it('usage: --policy-config is required for governance and refused elsewhere', async (t) => {
    const dir = files(t);
    const op = join(dir, 'break-glass.yml');
    const pol = join(dir, 'policy.yml');
    assert.equal((await cli(['plan', '--scope', 'break-glass-governance', '--environment', 'synthetic', '--operator-config', op])).code, 2);
    assert.equal((await cli(['plan', '--scope', 'break-glass', '--environment', 'synthetic', '--operator-config', op, '--policy-config', pol])).code, 2);
    assert.equal((await cli(['plan', '--policy-config', pol])).code, 2);
    assert.equal((await cli(['verify', '--scope', 'break-glass-governance', '--operator-config', op, '--policy-config', pol])).code, 2);
    assert.equal((await cli(['apply', '--plan-id', '0'.repeat(64), '--account', ACCOUNT, '--region', REGION, '--policy-config', pol, '--yes'])).code, 2);
  });

  it('a policy file for another environment is a configuration error (exit 1, AWS never contacted)', async (t) => {
    const dir = files(t, { environment: 'production', shas: [] });
    let called = false;
    const r = await cli(['plan', '--scope', 'break-glass-governance', '--environment', 'synthetic', '--operator-config', join(dir, 'break-glass.yml'), '--policy-config', join(dir, 'policy.yml'), '--repo', dir], { awsExec: async () => { called = true; throw new Error('no AWS'); } });
    assert.equal(r.code, 1);
    assert.match(r.err, /not --environment 'synthetic'/);
    assert.equal(called, false);
  });

  it('plans end to end from the two files, as JSON', async (t) => {
    const dir = files(t);
    const f = fakeAws(greenfieldGovernance('synthetic'), { allowlist: assertGovernancePlanning });
    const c = capture();
    const code = await main(['aws', 'plan', '--scope', 'break-glass-governance', '--environment', 'synthetic', '--operator-config', join(dir, 'break-glass.yml'), '--policy-config', join(dir, 'policy.yml'), '--repo', dir, '--json'], { ...c.io, framework: FRAMEWORK, frameworkGit: fakeGit(), awsExec: f.exec, env: {}, awsSleep: quiet });
    assert.equal(code, 0, c.errors());
    const json = JSON.parse(c.text());
    assert.equal(json.outcome, 'PLANNED');
    assert.equal(json.units[0].stackName, STACK('synthetic'));
    assert.equal(readdirSync(join(dir, '.ssd', 'aws-plans')).length, 1);
  });
});
