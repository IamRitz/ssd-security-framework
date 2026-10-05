// `ssd-onboard aws apply` end to end: a REAL plan is recorded first (awsPlan
// against the planning fake), then applied against a stateful model of what
// AWS holds afterwards (support/aws-apply-fake.mjs). Covers plan integrity,
// intent and identity, change-set and stack time-of-check/time-of-use,
// destructive counts, confirmation, the mutation boundary, execution outcomes,
// the apply record and the CLI. No test talks to AWS.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { awsApply } from '../onboarding/aws/apply.mjs';
import { checkStack } from '../onboarding/aws/apply/live.mjs';
import { awsPlan } from '../onboarding/aws/plan.mjs';
import { verifyAws } from '../onboarding/aws/verify.mjs';
import { PlanRecordError, planDirOf, writeApplyRecord } from '../onboarding/aws/plan/record.mjs';
import { canonicalJson, sha256 } from '../onboarding/aws/templates/common.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { scriptedPrompter } from '../onboarding/lib/prompt.mjs';
import { FRAMEWORK, capture, commitAll, config, makeRepo, tempDir, write } from './support/onboarding-fixtures.mjs';
import { CALLER, awsError, ok } from './support/aws-fake.mjs';
import { ACCOUNT, MANAGED, REGION, changeSets, greenfieldWorld, modify, ownedWorld, planFake } from './support/aws-plan-fake.mjs';
import { EXECUTE, applyWorld, firstMutation, mutations, readPlanJson } from './support/aws-apply-fake.mjs';

const ECR = 'container-ecr-framework-gated';
const CONFIG = config(ECR, MANAGED);
const quiet = async () => {};
const OTHER_STACK_ID = (name) => `arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/${name}/99999999-8888-7777-6666-555555555555`;
const replaceN = (n) => (template) => modify(template).map((c, i) => (i < n ? { ...c, ResourceChange: { ...c.ResourceChange, Replacement: 'True' } } : c));
const kinds = (report) => report.findings.map((f) => f.kind);
const dirFiles = (p) => readdirSync(join(p.root, planDirOf(p.planId))).sort();

// Record a real plan. kind CREATE: greenfield; UPDATE: an owned stack.
async function planned(t, { kind = 'CREATE', changes = null, root = tempDir(t), world = null } = {}) {
  const w = world ?? (kind === 'CREATE' ? changeSets(greenfieldWorld(), changes ? { changes } : {}) : changeSets(ownedWorld(), { changes: changes ?? modify }));
  const f = planFake(w);
  const report = await awsPlan({ config: CONFIG, exec: f.exec, env: {}, framework: FRAMEWORK, root, sleep: quiet });
  assert.deepEqual(f.unexpected, []);
  return { root, planId: report.units[0].planId, report };
}

async function apply(p, { world = {}, account = ACCOUNT, region = REGION, yes = true, allowDestructive = null, confirm = null, framework = FRAMEWORK, cfg = CONFIG, env = {}, now, waitMs } = {}) {
  const w = applyWorld({ root: p.root, planId: p.planId, ...world });
  const report = await awsApply({ config: cfg, planId: p.planId, account, region, yes, allowDestructive, confirm, exec: w.fake.exec, env, framework, root: p.root, sleep: quiet, now, waitMs });
  assert.deepEqual(w.fake.unexpected, [], 'no unrecorded AWS call');
  return { report, ...w };
}

// Rewrite one plan file and re-seal plan.json's hash for it, so the tamper
// reaches the cross-checks (plan/plan-check.mjs) instead of the hash check.
function reseal(p, name, edit) {
  const dir = join(p.root, planDirOf(p.planId));
  const plan = JSON.parse(readFileSync(join(dir, 'plan.json'), 'utf8'));
  if (name === 'plan.json') {
    writeFileSync(join(dir, 'plan.json'), canonicalJson(edit(plan)));
    return;
  }
  const text = canonicalJson(edit(JSON.parse(readFileSync(join(dir, name), 'utf8'))));
  writeFileSync(join(dir, name), text);
  plan.files[name] = sha256(text);
  writeFileSync(join(dir, 'plan.json'), canonicalJson(plan));
}

const refusedWithoutMutation = (r, kind) => {
  assert.equal(r.report.outcome, 'REFUSED', JSON.stringify(r.report.findings));
  if (kind) assert.ok(kinds(r.report).includes(kind), `${kind} in ${kinds(r.report)}`);
  assert.equal(mutations(r.fake), 0, 'no execute-change-set');
  assert.equal(r.state.executions, 0);
};

describe('aws apply: plan integrity (refused before AWS)', () => {
  it('a complete, valid CREATE plan is applied', async (t) => {
    const p = await planned(t);
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLIED');
    assert.equal(r.report.execution.finalStackStatus, 'CREATE_COMPLETE');
    assert.equal(mutations(r.fake), 1);
  });

  for (const [what, damage] of [
    ['missing plan.json', (dir) => rmSync(join(dir, 'plan.json'))],
    ['missing artifact (policies.json)', (dir) => rmSync(join(dir, 'policies.json'))],
    ['malformed plan.json', (dir) => writeFileSync(join(dir, 'plan.json'), '{nope')],
    ['changed template.json', (dir) => writeFileSync(join(dir, 'template.json'), `${readFileSync(join(dir, 'template.json'), 'utf8')} `)],
    ['changed parameters.json', (dir) => writeFileSync(join(dir, 'parameters.json'), '[{"ParameterKey":"X"}]\n')],
    ['changed policies.json', (dir) => writeFileSync(join(dir, 'policies.json'), '{}\n')],
    ['changed change-set.json', (dir) => writeFileSync(join(dir, 'change-set.json'), '{}\n')],
    ['changed tags', (dir) => {
      const plan = JSON.parse(readFileSync(join(dir, 'plan.json'), 'utf8'));
      plan.tags = plan.tags.filter((tag) => tag.Key !== 'ssd:consumer-repository');
      writeFileSync(join(dir, 'plan.json'), canonicalJson(plan));
    }],
    ['unknown schema version', (dir) => {
      const plan = JSON.parse(readFileSync(join(dir, 'plan.json'), 'utf8'));
      plan.schemaVersion = 2;
      writeFileSync(join(dir, 'plan.json'), canonicalJson(plan));
    }]
  ]) {
    it(`${what} is refused with no AWS call`, async (t) => {
      const p = await planned(t);
      damage(join(p.root, planDirOf(p.planId)));
      const r = await apply(p);
      refusedWithoutMutation(r, 'plan-not-applicable');
      assert.equal(r.fake.calls.length, 0);
    });
  }

  it('a no-change plan is refused', async (t) => {
    const p = await planned(t, { world: changeSets(ownedWorld(), { status: 'FAILED', reason: 'No updates are to be performed.' }) });
    assert.equal(p.report.outcome, 'NO_CHANGES');
    const r = await apply(p);
    refusedWithoutMutation(r, 'plan-not-applicable');
    assert.match(r.report.findings[0].message, /no-changes/);
    assert.equal(r.fake.calls.length, 0);
  });

  for (const [what, file, edit] of [
    ['a changeSetArn not the recorded change set', 'plan.json', (plan) => ({ ...plan, changeSetArn: plan.changeSetArn.replace(/\/[0-9a-f-]+$/, '/00000000-0000-0000-0000-000000000000') })],
    ['a lowered destructive count', 'plan.json', (plan) => ({ ...plan, destructive: 0 })],
    ['a copy differing from the plan id (stackName)', 'plan.json', (plan) => ({ ...plan, stackName: 'ssd-shared-github-oidc' })],
    ['a change set recorded as not executable', 'change-set.json', (cs) => ({ ...cs, ExecutionStatus: 'UNAVAILABLE' })],
    ['a change set for another stack id', 'change-set.json', (cs) => ({ ...cs, StackId: OTHER_STACK_ID('ssd-delivery-x-00000000') })],
    ['a recorded change list that differs from plan.json', 'change-set.json', (cs) => ({ ...cs, Changes: cs.Changes.slice(1) })]
  ]) {
    it(`a resealed record with ${what} is refused`, async (t) => {
      const p = await planned(t, { kind: 'UPDATE', changes: replaceN(1) });
      reseal(p, file, edit);
      const r = await apply(p, { allowDestructive: 1 });
      refusedWithoutMutation(r, 'plan-inconsistent');
      assert.equal(r.fake.calls.length, 0);
    });
  }

  // The reviewed change set's tags are bound EXACTLY, before any AWS call:
  // change-set.json must carry precisely plan.json's SSD tags (no extra, none
  // missing), and plan.json's tags are themselves bound by the plan id.
  for (const [what, file, edit, kind] of [
    ['an extra tag on the recorded change set', 'change-set.json', (cs) => ({ ...cs, Tags: [...cs.Tags, { Key: 'owner', Value: 'someone-else' }] }), 'plan-inconsistent'],
    ['a required SSD tag missing from the recorded change set', 'change-set.json', (cs) => ({ ...cs, Tags: cs.Tags.filter((tag) => tag.Key !== 'ssd:managed-by') }), 'plan-inconsistent'],
    ['plan.json tags that are not the SSD tags the plan id binds', 'plan.json', (plan) => ({ ...plan, tags: plan.tags.map((tag) => (tag.Key === 'ssd:managed-by' ? { ...tag, Value: 'terraform' } : tag)) }), 'plan-not-applicable']
  ]) {
    it(`a resealed CREATE record with ${what} is refused before AWS`, async (t) => {
      const p = await planned(t);
      reseal(p, file, edit);
      const r = await apply(p);
      refusedWithoutMutation(r, kind);
      assert.equal(r.fake.calls.length, 0, 'no AWS call at all');
    });
  }

  it('an already-applied plan is refused and never executed twice', async (t) => {
    const p = await planned(t);
    assert.equal((await apply(p)).report.outcome, 'APPLIED');
    const again = await apply(p);
    refusedWithoutMutation(again, 'already-applied');
    assert.equal(again.fake.calls.length, 0);
  });

  it('apply-started.json alone (an interrupted apply) blocks a rerun', async (t) => {
    const p = await planned(t);
    writeFileSync(join(p.root, planDirOf(p.planId), 'apply-started.json'), '{}\n');
    const r = await apply(p);
    refusedWithoutMutation(r, 'already-applied');
  });
});

describe('aws apply: intent and identity', () => {
  it('--account / --region that differ from the plan are refused before AWS', async (t) => {
    const p = await planned(t);
    for (const [options, kind] of [[{ account: '999999999999' }, 'account-mismatch'], [{ region: 'eu-west-1' }, 'region-mismatch']]) {
      const r = await apply(p, options);
      refusedWithoutMutation(r, kind);
      assert.equal(r.fake.calls.length, 0);
    }
  });

  it('a configuration changed since the plan is refused before AWS', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { cfg: config(ECR, { ...MANAGED, delivery: { ...MANAGED.delivery, environment: 'staging' } }) });
    refusedWithoutMutation(r, 'config-changed');
    assert.equal(r.fake.calls.length, 0);
  });

  it('a configuration for another account or region is refused before AWS', async (t) => {
    const p = await planned(t);
    const other = config(ECR, {
      ...MANAGED,
      delivery: { ...MANAGED.delivery, aws: { accountId: '999999999999', region: REGION }, roles: { ...MANAGED.delivery.roles, pushScanRoleArn: 'arn:aws:iam::999999999999:role/app-ecr-push-scan', deployRoleArn: 'arn:aws:iam::999999999999:role/app-deploy' } }
    });
    const r = await apply(p, { cfg: other });
    refusedWithoutMutation(r, 'account-mismatch');
    assert.equal(r.fake.calls.length, 0);
  });

  it('a framework checkout not bound to the plan\'s framework.ref is refused before AWS', async (t) => {
    const p = await planned(t);
    for (const framework of [null, { ...FRAMEWORK, clean: false, dirtyPaths: ['onboarding/aws/apply.mjs'] }, { ...FRAMEWORK, sha: 'f'.repeat(40) }, { ...FRAMEWORK, slug: 'evil/fork' }]) {
      const r = await apply(p, { framework });
      refusedWithoutMutation(r, 'framework-binding');
      assert.equal(r.fake.calls.length, 0);
    }
  });

  it('a live account mismatch or the root user: only sts was called', async (t) => {
    const p = await planned(t);
    for (const caller of [
      { Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'AROAEXAMPLEEXAMPLE01:y' },
      { Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root`, UserId: ACCOUNT }
    ]) {
      const r = await apply(p, { world: { caller } });
      refusedWithoutMutation(r);
      assert.deepEqual(r.fake.operations(), ['sts get-caller-identity']);
    }
  });

  it('a credential failure ends the run as an error with no mutation', async (t) => {
    const p = await planned(t);
    const w = applyWorld({ root: p.root, planId: p.planId });
    w.world['sts get-caller-identity'] = { stdout: '', stderr: 'Unable to locate credentials.', exitCode: 253 };
    await assert.rejects(awsApply({ config: CONFIG, planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet }), (error) => error.kind === 'authentication');
    assert.equal(mutations(w.fake), 0);
    assert.deepEqual(dirFiles(p).filter((f) => f.startsWith('apply')), []);
  });

  it('another non-root principal of the account may apply (D.11); both ARNs are recorded', async (t) => {
    const p = await planned(t);
    const bob = `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/bob`;
    const r = await apply(p, { world: { caller: { Account: ACCOUNT, Arn: bob, UserId: 'AROAEXAMPLEEXAMPLE01:bob' } } });
    assert.equal(r.report.outcome, 'APPLIED');
    const record = readPlanJson(p.root, p.planId, 'apply.json');
    assert.equal(record.callerArn, bob);
    assert.equal(record.plannedByArn, CALLER);
  });
});

describe('aws apply: change-set time-of-check / time-of-use', () => {
  for (const [what, rewrite, kind] of [
    ['a different (newer) change-set id', (d) => ({ ...d, ChangeSetId: d.ChangeSetId.replace(/\/[0-9a-f-]+$/, '/00000000-0000-0000-0000-000000000000') }), 'change-set-replaced'],
    ['a different stack id', (d) => ({ ...d, StackId: OTHER_STACK_ID(d.StackName) }), 'change-set-changed'],
    ['changed capabilities', (d) => ({ ...d, Capabilities: [] }), 'change-set-changed'],
    ['changed parameters', (d) => ({ ...d, Parameters: [{ ParameterKey: 'X', ParameterValue: 'y' }] }), 'change-set-changed'],
    ['changed tags', (d) => ({ ...d, Tags: d.Tags.slice(1) }), 'change-set-changed'],
    ['a changed change list', (d) => ({ ...d, Changes: d.Changes.slice(1) }), 'change-set-changed'],
    ['nested stacks', (d) => ({ ...d, IncludeNestedStacks: true }), 'change-set-changed'],
    ['importing existing resources', (d) => ({ ...d, ImportExistingResources: true }), 'change-set-changed'],
    ['a field that was not recorded', (d) => ({ ...d, RoleARN: `arn:aws:iam::${ACCOUNT}:role/elsewhere` }), 'change-set-changed'],
    ['ExecutionStatus UNAVAILABLE', (d) => ({ ...d, ExecutionStatus: 'UNAVAILABLE' }), 'change-set-not-executable'],
    ['ExecutionStatus EXECUTE_COMPLETE', (d) => ({ ...d, ExecutionStatus: 'EXECUTE_COMPLETE' }), 'change-set-not-executable'],
    ['Status FAILED', (d) => ({ ...d, Status: 'FAILED' }), 'change-set-not-executable'],
    ['Status DELETE_COMPLETE', (d) => ({ ...d, Status: 'DELETE_COMPLETE' }), 'change-set-not-executable'],
    ['a deleted change set', () => null, 'change-set-missing']
  ]) {
    it(`${what} is refused before any mutation`, async (t) => {
      const p = await planned(t);
      refusedWithoutMutation(await apply(p, { world: { changeSet: rewrite } }), kind);
    });
  }

  it("a change set whose template is not template.json is refused", async (t) => {
    const p = await planned(t);
    const r = await apply(p, { world: { template: (body) => ({ ...body, Description: 'swapped' }) } });
    refusedWithoutMutation(r, 'template-changed');
  });
});

describe('aws apply: the template is read from the change set, never the deployed stack', () => {
  // The deployed stack's template differs from the planned one (that is what
  // an UPDATE is). The fake answers a stack-template read with it, so apply
  // would refuse if it ever compared the deployed template.
  function deployedDiffers(w, template) {
    const deployed = { ...template, Description: 'the template deployed before this plan' };
    for (const key of [`cloudformation get-template --stack-name ${w.binding.stackName}`, `cloudformation get-template --stack-name ${w.binding.stackName} --template-stage Original`]) {
      w.world[key] = ok({ TemplateBody: deployed, StagesAvailable: ['Original', 'Processed'] });
    }
    return deployed;
  }

  for (const [what, changeSetTemplate, outcome] of [
    ['the change set holds template.json: apply proceeds', (body) => body, 'APPLIED'],
    ['the change set holds another template: apply refuses', (body) => ({ ...body, Description: 'swapped after review' }), 'REFUSED']
  ]) {
    it(`UPDATE, deployed template != planned template, ${what}`, async (t) => {
      const p = await planned(t, { kind: 'UPDATE' });
      const planText = readFileSync(join(p.root, planDirOf(p.planId), 'template.json'), 'utf8');
      const w = applyWorld({ root: p.root, planId: p.planId, template: changeSetTemplate });
      const deployed = deployedDiffers(w, JSON.parse(planText));
      assert.notEqual(canonicalJson(deployed), planText, 'the deployed template really differs from the plan');
      const report = await awsApply({ config: CONFIG, planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
      assert.deepEqual(w.fake.unexpected, []);
      assert.equal(report.outcome, outcome, JSON.stringify(report.findings));
      // The exact argv: the recorded change set's ORIGINAL template, by ARN.
      const reads = w.fake.calls.map((c) => c.argv).filter((argv) => argv[1] === 'get-template');
      assert.ok(reads.length >= 1);
      for (const argv of reads) {
        assert.deepEqual(argv, ['cloudformation', 'get-template', '--stack-name', w.binding.stackName, '--change-set-name', w.binding.changeSetArn, '--template-stage', 'Original', '--region', REGION, '--output', 'json', '--no-cli-pager']);
      }
      if (outcome === 'APPLIED') {
        assert.equal(mutations(w.fake), 1);
        assert.equal(reads.length, 2, 'once in the pre-flight, once immediately before execution');
      } else {
        assert.ok(report.findings.some((f) => f.kind === 'template-changed'));
        assert.equal(mutations(w.fake), 0);
      }
    });
  }
});

describe('aws apply: stack time-of-check / time-of-use', () => {
  it('an unchanged UPDATE base stack is applied', async (t) => {
    const p = await planned(t, { kind: 'UPDATE' });
    const r = await apply(p);
    assert.equal(r.report.outcome, 'APPLIED');
    assert.equal(r.report.execution.finalStackStatus, 'UPDATE_COMPLETE');
  });

  it('an UPDATE stack changed since the plan is refused (another deployment, same AVAILABLE change set)', async (t) => {
    const p = await planned(t, { kind: 'UPDATE' });
    for (const rewrite of [(s) => ({ ...s, LastUpdatedTime: '2026-09-30T00:00:00.000Z' }), (s) => ({ ...s, StackStatus: 'UPDATE_COMPLETE' }), (s) => ({ ...s, StackStatus: 'UPDATE_IN_PROGRESS' })]) {
      refusedWithoutMutation(await apply(p, { world: { stack: rewrite } }), 'stack-changed');
    }
  });

  // AWS contract observed live (Phase 3C synthetic apply, 2026-10-05): a first
  // CREATE change set is CREATE_COMPLETE/AVAILABLE and carries the SSD tags;
  // its REVIEW_IN_PROGRESS placeholder has the change set's StackId and Tags: [].
  // The tags reach the stack only when the change set executes.
  it('a first CREATE applies against the untagged REVIEW_IN_PROGRESS placeholder AWS creates', async (t) => {
    const p = await planned(t);
    const recorded = readPlanJson(p.root, p.planId, 'change-set.json');
    assert.deepEqual(recorded.Tags, readPlanJson(p.root, p.planId).tags, 'the reviewed change set carries the SSD tags');
    const r = await apply(p, { world: { stack: (s) => ({ ...s, StackId: recorded.StackId, StackStatus: 'REVIEW_IN_PROGRESS', Tags: [] }) } });
    assert.equal(r.report.outcome, 'APPLIED');
    assert.ok(r.report.verification.some((v) => v.id === 'stack' && v.status === 'PASS'));
    assert.equal(r.report.execution.finalStackStatus, 'CREATE_COMPLETE');
  });

  it('a CREATE placeholder that carries exactly the SSD ownership tags is also accepted', async (t) => {
    const p = await planned(t);
    const tags = readPlanJson(p.root, p.planId).tags;
    assert.equal((await apply(p, { world: { stack: (s) => ({ ...s, Tags: tags }) } })).report.outcome, 'APPLIED');
  });

  it('anything but the recorded CREATE placeholder at that name is refused', async (t) => {
    const p = await planned(t);
    const tags = readPlanJson(p.root, p.planId).tags;
    for (const [rewrite, kind] of [
      [(s) => ({ ...s, StackId: OTHER_STACK_ID(s.StackName) }), 'stack-replaced'],
      [(s) => ({ ...s, StackName: `${s.StackName}-other` }), 'stack-replaced'],
      [(s) => ({ ...s, StackStatus: 'CREATE_COMPLETE' }), 'stack-changed'],
      [(s) => ({ ...s, StackStatus: 'CREATE_IN_PROGRESS' }), 'stack-changed'],
      [(s) => ({ ...s, StackStatus: 'ROLLBACK_COMPLETE' }), 'stack-changed'],
      [(s) => ({ ...s, Tags: tags.map((tag) => (tag.Key === 'ssd:consumer-repository' ? { ...tag, Value: 'evil/app' } : tag)) }), 'stack-not-owned'],
      [(s) => ({ ...s, Tags: [{ Key: 'owner', Value: 'someone-else' }] }), 'stack-not-owned'],
      [() => null, 'stack-missing']
    ]) {
      refusedWithoutMutation(await apply(p, { world: { stack: rewrite } }), kind);
    }
  });

  it('a CREATE whose live change set no longer carries the reviewed SSD tags is refused', async (t) => {
    const p = await planned(t);
    for (const rewrite of [(d) => ({ ...d, Tags: [] }), (d) => ({ ...d, Tags: d.Tags.map((tag) => (tag.Key === 'ssd:managed-by' ? { ...tag, Value: 'someone-else' } : tag)) })]) {
      refusedWithoutMutation(await apply(p, { world: { changeSet: rewrite } }), 'change-set-changed');
    }
  });

  it('an UPDATE stack must still carry the SSD ownership tags (unchanged by the CREATE rule)', async (t) => {
    const p = await planned(t, { kind: 'UPDATE' });
    for (const rewrite of [(s) => ({ ...s, Tags: [] }), (s) => ({ ...s, Tags: s.Tags.map((tag) => (tag.Key === 'ssd:consumer-repository' ? { ...tag, Value: 'evil/app' } : tag)) })]) {
      refusedWithoutMutation(await apply(p, { world: { stack: rewrite } }), 'stack-not-owned');
    }
  });
});

// checkStack directly, over the exact shapes AWS returned for the Phase 3C
// synthetic CREATE (2026-10-05).
describe('aws apply: checkStack over the observed CREATE contract', () => {
  const STACK_ID = 'arn:aws:cloudformation:us-east-1:157328692276:stack/ssd-break-glass-synthetic/4dcc71e0-c08a-11f1-8ffc-0ef7e0e36b7f';
  const NAME = 'ssd-break-glass-synthetic';
  const CHANGE_SET_TAGS = [
    { Key: 'ssd:framework', Value: 'ssd-security-framework' },
    { Key: 'ssd:environment', Value: 'synthetic' },
    { Key: 'ssd:managed-by', Value: 'ssd-onboard' }
  ];
  const record = ({ operation = 'CREATE', base = { state: 'absent' }, tags = CHANGE_SET_TAGS } = {}) => ({
    plan: { scope: 'break-glass', stackKind: 'break-glass-synthetic', baseStack: base },
    operation,
    binding: { stackName: NAME, stackId: STACK_ID },
    changeSet: { StackId: STACK_ID, Status: 'CREATE_COMPLETE', ExecutionStatus: 'AVAILABLE', Tags: tags }
  });
  const placeholder = (overrides = {}) => ({ state: 'present', value: { name: NAME, stackId: STACK_ID, status: 'REVIEW_IN_PROGRESS', tags: [], lastUpdatedTime: null, ...overrides } });
  const kinds = (findings) => findings.map((f) => f.kind);
  const asTags = (list) => list.map((t) => ({ key: t.Key, value: t.Value }));

  it('PASS: tagged change set + REVIEW_IN_PROGRESS placeholder with Tags [] + matching StackId', () => {
    assert.deepEqual(checkStack({ record: record(), stack: placeholder(), slug: null }), []);
  });

  it('PASS: a placeholder carrying exactly the SSD tags', () => {
    assert.deepEqual(checkStack({ record: record(), stack: placeholder({ tags: asTags(CHANGE_SET_TAGS) }), slug: null }), []);
  });

  for (const [what, tags] of [
    ['no tags', []],
    ['the production environment tag', CHANGE_SET_TAGS.map((t) => (t.Key === 'ssd:environment' ? { ...t, Value: 'production' } : t))],
    ['another manager', CHANGE_SET_TAGS.map((t) => (t.Key === 'ssd:managed-by' ? { ...t, Value: 'terraform' } : t))],
    ['a consumer repository on a shared break-glass stack', [...CHANGE_SET_TAGS, { Key: 'ssd:consumer-repository', Value: 'acme/app' }]]
  ]) {
    it(`REFUSED: the reviewed change set with ${what}`, () => {
      assert.ok(kinds(checkStack({ record: record({ tags }), stack: placeholder(), slug: null })).includes('change-set-not-owned'));
    });
  }

  it('REFUSED: a reviewed change set with no Tags field at all', () => {
    const untagged = record();
    delete untagged.changeSet.Tags;
    assert.ok(kinds(checkStack({ record: untagged, stack: placeholder(), slug: null })).includes('change-set-not-owned'));
  });

  for (const [what, overrides, kind] of [
    ['a different StackId', { stackId: STACK_ID.replace('4dcc71e0', '00000000') }, 'stack-replaced'],
    ['a different stack name', { name: 'ssd-break-glass-production' }, 'stack-replaced'],
    ['status CREATE_COMPLETE', { status: 'CREATE_COMPLETE' }, 'stack-changed'],
    ['status ROLLBACK_COMPLETE', { status: 'ROLLBACK_COMPLETE' }, 'stack-changed'],
    ['foreign tags on the placeholder', { tags: [{ key: 'owner', value: 'someone-else' }] }, 'stack-not-owned'],
    ['the other environment\'s SSD tags on the placeholder', { tags: asTags(CHANGE_SET_TAGS.map((t) => (t.Key === 'ssd:environment' ? { ...t, Value: 'production' } : t))) }, 'stack-not-owned']
  ]) {
    it(`REFUSED: ${what}`, () => {
      assert.ok(kinds(checkStack({ record: record(), stack: placeholder(overrides), slug: null })).includes(kind));
    });
  }

  it('REFUSED: the placeholder is gone', () => {
    assert.deepEqual(kinds(checkStack({ record: record(), stack: { state: 'absent' }, slug: null })), ['stack-missing']);
  });

  it('a plan made against an existing placeholder keeps its revision protection', () => {
    const base = { state: 'present', stackId: STACK_ID, stackStatus: 'REVIEW_IN_PROGRESS', lastUpdatedTime: '2026-10-05T06:59:00.000Z' };
    assert.deepEqual(checkStack({ record: record({ base }), stack: placeholder({ lastUpdatedTime: '2026-10-05T06:59:00.000Z' }), slug: null }), []);
    for (const lastUpdatedTime of ['2026-10-05T07:30:00.000Z', null]) {
      assert.ok(kinds(checkStack({ record: record({ base }), stack: placeholder({ lastUpdatedTime }), slug: null })).includes('stack-changed'));
    }
  });

  it('UPDATE is unchanged: the live stack itself must carry the SSD tags', () => {
    const base = { state: 'present', stackId: STACK_ID, stackStatus: 'CREATE_COMPLETE', lastUpdatedTime: '2026-10-05T07:00:00.000Z' };
    const settled = (tags) => ({ state: 'present', value: { name: NAME, stackId: STACK_ID, status: 'CREATE_COMPLETE', tags, lastUpdatedTime: '2026-10-05T07:00:00.000Z' } });
    assert.deepEqual(checkStack({ record: record({ operation: 'UPDATE', base }), stack: settled(asTags(CHANGE_SET_TAGS)), slug: null }), []);
    assert.ok(kinds(checkStack({ record: record({ operation: 'UPDATE', base }), stack: settled([]), slug: null })).includes('stack-not-owned'));
  });
});

describe('aws apply: destructive changes', () => {
  it('no destructive change needs no flag; a stated 0 is accepted; any other count is refused', async (t) => {
    const p = await planned(t, { kind: 'UPDATE' });
    refusedWithoutMutation(await apply(p, { allowDestructive: 1 }), 'destructive-count-mismatch');
    assert.equal((await apply(p, { allowDestructive: 0 })).report.outcome, 'APPLIED');
  });

  it('2 destructive: no flag and a wrong count are refused before AWS; the exact count applies', async (t) => {
    const p = await planned(t, { kind: 'UPDATE', changes: replaceN(2) });
    assert.equal(readPlanJson(p.root, p.planId).destructive, 2);
    for (const [allowDestructive, kind] of [[null, 'destructive-unconfirmed'], [1, 'destructive-count-mismatch'], [3, 'destructive-count-mismatch']]) {
      const r = await apply(p, { allowDestructive });
      refusedWithoutMutation(r, kind);
      assert.equal(r.fake.calls.length, 0);
    }
    const r = await apply(p, { allowDestructive: 2 });
    assert.equal(r.report.outcome, 'APPLIED');
    assert.equal(r.report.changes.destructive, 2);
  });

  it('a fresh describe with more destructive changes than reviewed is refused', async (t) => {
    const p = await planned(t, { kind: 'UPDATE', changes: replaceN(1) });
    const r = await apply(p, { allowDestructive: 1, world: { changeSet: (d) => ({ ...d, Changes: replaceN(2)(JSON.parse(readFileSync(join(p.root, planDirOf(p.planId), 'template.json'), 'utf8'))) }) } });
    refusedWithoutMutation(r, 'change-set-changed');
  });
});

describe('aws apply: confirmation', () => {
  const typed = (account, region) => async () => ({ account, region });

  it('the exact typed account and region execute', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { yes: false, confirm: typed(ACCOUNT, REGION) });
    assert.equal(r.report.outcome, 'APPLIED');
    assert.ok(r.report.verification.some((v) => v.id === 'confirmation' && v.status === 'PASS'));
  });

  for (const [what, answer] of [['a wrong account', [ACCOUNT.replace(/.$/, '0'), REGION]], ['a wrong region', [ACCOUNT, 'us-east-2']], ['"yes"', ['yes', 'yes']], ['Enter', ['', '']]]) {
    it(`${what} executes nothing (after a read-only pre-flight)`, async (t) => {
      const p = await planned(t);
      const r = await apply(p, { yes: false, confirm: typed(...answer) });
      refusedWithoutMutation(r, 'confirmation-mismatch');
      assert.ok(r.fake.calls.length > 0, 'the pre-flight ran');
      assert.deepEqual(dirFiles(p).filter((f) => f.startsWith('apply')), []);
    });
  }

  it('without --yes and without a confirmer, nothing is contacted', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { yes: false, confirm: null });
    refusedWithoutMutation(r, 'confirmation-required');
    assert.equal(r.fake.calls.length, 0);
  });

  it('the live checks are repeated after confirmation, immediately before execution', async (t) => {
    const p = await planned(t);
    let w;
    const confirm = async () => {
      // The stack is updated by someone else while the operator types.
      w.state.stack = { ...w.state.stack, StackStatus: 'CREATE_COMPLETE' };
      return { account: ACCOUNT, region: REGION };
    };
    w = applyWorld({ root: p.root, planId: p.planId });
    const report = await awsApply({ config: CONFIG, planId: p.planId, account: ACCOUNT, region: REGION, confirm, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
    assert.equal(report.outcome, 'REFUSED');
    assert.ok(report.findings.some((f) => f.kind === 'stack-changed'));
    assert.equal(mutations(w.fake), 0);
  });
});

describe('aws apply: mutation boundary', () => {
  it('every call before the single execute is a read; execute follows the full re-verification and apply-started.json', async (t) => {
    const p = await planned(t);
    const w = applyWorld({ root: p.root, planId: p.planId, execute: (state) => {
      assert.ok(existsSync(join(p.root, planDirOf(p.planId), 'apply-started.json')), 'apply-started.json precedes execute');
      state.changeSet = { ...state.changeSet, ExecutionStatus: 'EXECUTE_IN_PROGRESS' };
      return { stdout: '', stderr: '', exitCode: 0 };
    } });
    const report = await awsApply({ config: CONFIG, planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
    assert.equal(report.outcome, 'APPLIED');
    const keys = w.fake.keys();
    const at = firstMutation(w.fake);
    assert.equal(mutations(w.fake), 1, 'execute-change-set exactly once');
    assert.equal(keys[at], `${EXECUTE} --stack-name ${w.binding.stackName} --change-set-name ${w.binding.changeSetArn}`);
    const ops = keys.slice(0, at).map((k) => k.split(' ').slice(0, 2).join(' '));
    assert.deepEqual([...new Set(ops)].sort(), ['cloudformation describe-change-set', 'cloudformation describe-stacks', 'cloudformation get-template', 'sts get-caller-identity']);
    // Two full verification passes: pre-flight and immediately before execution.
    assert.equal(ops.filter((o) => o === 'sts get-caller-identity').length, 2);
    assert.deepEqual(ops.slice(-4), ['sts get-caller-identity', 'cloudformation describe-change-set', 'cloudformation get-template', 'cloudformation describe-stacks']);
    assert.ok(keys.slice(at + 1).every((k) => !k.startsWith(EXECUTE)));
    assert.ok(!keys.some((k) => /create-change-set|create-stack|update-stack|delete-stack|delete-change-set/.test(k)));
  });
});

describe('aws apply: the fake harness', () => {
  it('enforces the apply allowlist of this exact plan, independently of the code under test', async (t) => {
    const p = await planned(t);
    const w = applyWorld({ root: p.root, planId: p.planId });
    const suffix = ['--region', REGION, '--output', 'json', '--no-cli-pager'];
    for (const call of [['cloudformation', 'create-change-set', '--stack-name', w.binding.stackName], ['cloudformation', 'delete-stack', '--stack-name', w.binding.stackName], ['cloudformation', 'execute-change-set', '--stack-name', w.binding.stackName, '--change-set-name', w.binding.changeSetArn.replace(/[0-9a-f]{64}/, 'b'.repeat(64))]]) {
      await assert.rejects(w.fake.exec([...call, ...suffix]), /non-allowlisted/);
    }
    assert.equal(w.state.executions, 0);
  });
});

describe('aws apply: execution outcomes', () => {
  it('CREATE -> CREATE_COMPLETE and UPDATE -> UPDATE_COMPLETE are APPLIED', async (t) => {
    assert.equal((await apply(await planned(t))).report.outcome, 'APPLIED');
    assert.equal((await apply(await planned(t, { kind: 'UPDATE' }))).report.outcome, 'APPLIED');
  });

  for (const [kind, sequence] of [
    ['CREATE', ['CREATE_IN_PROGRESS', 'CREATE_FAILED']],
    ['CREATE', ['CREATE_IN_PROGRESS', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_COMPLETE']],
    ['CREATE', ['ROLLBACK_FAILED']],
    ['CREATE', ['DELETE_COMPLETE']],
    ['UPDATE', ['UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE']],
    ['UPDATE', ['UPDATE_ROLLBACK_FAILED']],
    ['UPDATE', ['UPDATE_FAILED']],
    ['UPDATE', ['IMPORT_COMPLETE']],
    ['UPDATE', ['CREATE_COMPLETE']]
  ]) {
    it(`${kind} ending ${sequence.at(-1)} is APPLY_FAILED, never success`, async (t) => {
      const p = await planned(t, { kind });
      const r = await apply(p, { world: { sequence } });
      assert.equal(r.report.outcome, 'APPLY_FAILED');
      assert.equal(r.report.execution.finalStackStatus, sequence.at(-1));
      assert.equal(r.report.execution.observed, true);
      assert.equal(readPlanJson(p.root, p.planId, 'apply.json').outcome, 'APPLY_FAILED');
    });
  }

  it('an UPDATE stack that never leaves its base revision is not mistaken for success', async (t) => {
    const p = await planned(t, { kind: 'UPDATE' });
    const base = readPlanJson(p.root, p.planId).baseStack;
    let clock = 0;
    const r = await apply(p, {
      now: () => (clock += 1_000),
      waitMs: 60_000,
      world: { poll: (_n, state) => ok({ Stacks: [{ ...state.stack, StackStatus: base.stackStatus, LastUpdatedTime: base.lastUpdatedTime }] }) }
    });
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.observed, false);
  });

  it('a stack that does not settle in time is APPLY_FAILED (unconfirmed)', async (t) => {
    const p = await planned(t);
    let clock = 0;
    const r = await apply(p, { now: () => (clock += 10_000), waitMs: 120_000, world: { sequence: ['CREATE_IN_PROGRESS'] } });
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.observed, false);
    assert.match(r.report.execution.reason, /did not settle/);
  });

  it('credentials lost after execute: never APPLIED', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { world: { poll: () => awsError('ExpiredToken', 'DescribeStacks', 'The security token included in the request is expired') } });
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.observed, false);
    assert.equal(r.report.execution.accepted, true);
    assert.match(r.report.execution.reason, /authentication/);
  });

  it('a different stack id while polling fails closed', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { world: { poll: (_n, state) => ok({ Stacks: [{ ...state.stack, StackId: OTHER_STACK_ID(state.stack.StackName), StackStatus: 'CREATE_COMPLETE' }] }) } });
    assert.equal(r.report.outcome, 'APPLY_FAILED');
  });

  it('a rejected execute-change-set is APPLY_FAILED, not polled, and spends the plan', async (t) => {
    const p = await planned(t);
    const r = await apply(p, { world: { execute: () => awsError('InvalidChangeSetStatus', 'ExecuteChangeSet', 'ChangeSet is in an invalid state') } });
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    assert.equal(r.report.execution.accepted, false);
    assert.equal(r.state.polls, 0);
    assert.deepEqual(dirFiles(p).filter((f) => f.startsWith('apply')), ['apply-started.json', 'apply.json']);
    refusedWithoutMutation(await apply(p), 'already-applied');
  });
});

describe('aws apply: the apply record', () => {
  it('a successful apply records non-secret evidence, including outputs and resources', async (t) => {
    const p = await planned(t);
    const outputs = [{ OutputKey: 'Repo', OutputValue: 'app' }];
    const r = await apply(p, { world: { outputs } });
    assert.equal(r.report.outcome, 'APPLIED');
    assert.deepEqual(dirFiles(p).filter((f) => f.startsWith('apply')), ['apply-started.json', 'apply.json']);
    const record = readPlanJson(p.root, p.planId, 'apply.json');
    for (const key of ['schemaVersion', 'planId', 'appliedAt', 'account', 'region', 'callerArn', 'stackName', 'stackId', 'changeSetId', 'changeSetName', 'operation', 'finalStackStatus', 'outputs', 'destructiveCount', 'counts', 'resources']) {
      assert.ok(Object.hasOwn(record, key), key);
    }
    assert.equal(record.outcome, 'APPLIED');
    assert.equal(record.finalStackStatus, 'CREATE_COMPLETE');
    assert.equal(record.changeSetId, r.binding.changeSetArn);
    assert.deepEqual(record.outputs, [{ key: 'Repo', value: 'app', exportName: null }]);
    assert.deepEqual(record.resources.map((x) => x.logicalId).sort(), ['DeployRole', 'EcrRepository', 'PushScanRole']);
  });

  it('a failed pre-flight writes no record', async (t) => {
    const p = await planned(t);
    await apply(p, { account: '999999999999' });
    await apply(p, { world: { changeSet: (d) => ({ ...d, ExecutionStatus: 'UNAVAILABLE' }) } });
    assert.deepEqual(dirFiles(p).filter((f) => f.startsWith('apply')), []);
  });

  it('credential values in AWS text never reach the report or apply.json', async (t) => {
    const p = await planned(t);
    const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const env = { AWS_SECRET_ACCESS_KEY: secret, AWS_SESSION_TOKEN: 'FwoGZXIvYXdzEXAMPLEsessiontoken' };
    const r = await apply(p, {
      env,
      world: { sequence: ['CREATE_FAILED'], poll: (_n, state) => ok({ Stacks: [{ ...state.stack, StackStatus: 'CREATE_FAILED', StackStatusReason: `denied for ${secret} token ${env.AWS_SESSION_TOKEN} eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.c2lnbmF0dXJlMTIz` }] }) }
    });
    assert.equal(r.report.outcome, 'APPLY_FAILED');
    for (const text of [JSON.stringify(r.report), readFileSync(join(p.root, planDirOf(p.planId), 'apply.json'), 'utf8')]) {
      assert.ok(!text.includes(secret) && !text.includes(env.AWS_SESSION_TOKEN) && !text.includes('eyJhbGci'));
    }
  });

  it('writeApplyRecord is exclusive, confined to the two apply records, and secret-checked', async (t) => {
    const p = await planned(t);
    await writeApplyRecord(p.root, p.planId, 'apply.json', '{"first":true}\n', {});
    await assert.rejects(writeApplyRecord(p.root, p.planId, 'apply.json', '{"second":true}\n', {}), (error) => error instanceof PlanRecordError && error.kind === 'apply-record-exists');
    assert.equal(readFileSync(join(p.root, planDirOf(p.planId), 'apply.json'), 'utf8'), '{"first":true}\n');
    await assert.rejects(writeApplyRecord(p.root, p.planId, 'plan.json', '{}\n', {}), (error) => error.kind === 'invalid-input');
    await assert.rejects(writeApplyRecord(p.root, p.planId, 'apply-started.json', '{"t":"AKIAIOSFODNN7EXAMPLE"}\n', {}), (error) => error.kind === 'secret-in-plan');
    assert.ok(!existsSync(join(p.root, planDirOf(p.planId), 'apply-started.json')));
  });

  it('an existing apply.json is never overwritten', async (t) => {
    const p = await planned(t);
    const path = join(p.root, planDirOf(p.planId), 'apply.json');
    writeFileSync(path, '{"keep":true}\n');
    refusedWithoutMutation(await apply(p), 'already-applied');
    assert.equal(readFileSync(path, 'utf8'), '{"keep":true}\n');
  });
});

describe('aws apply: CLI', () => {
  function consumer(t) {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n', Dockerfile: 'FROM scratch\n' });
    write(root, '.ssd/onboarding.yml', serializeConfig(CONFIG));
    commitAll(root, 'config');
    return root;
  }
  async function planVia(t) {
    const root = consumer(t);
    const c = capture();
    const f = planFake(greenfieldWorld());
    assert.equal(await main(['aws', 'plan', '--json', '--repo', root], { framework: FRAMEWORK, awsExec: f.exec, awsSleep: quiet, env: {}, ...c.io }), 0);
    return { root, planId: JSON.parse(c.text()).units[0].planId };
  }
  async function cli(p, args, { prompter, world = {} } = {}) {
    const c = capture();
    const w = applyWorld({ root: p.root, planId: p.planId, ...world });
    const code = await main(['aws', 'apply', ...args, '--repo', p.root], { framework: FRAMEWORK, awsExec: w.fake.exec, awsSleep: quiet, env: {}, prompter, ...c.io });
    return { code, out: c.text(), err: c.errors(), ...w };
  }
  const flags = (p) => ['--plan-id', p.planId, '--account', ACCOUNT, '--region', REGION];

  it('--yes with both flags applies; human output has every section, words not color, and no repository file changes', async (t) => {
    const p = await planVia(t);
    const configBefore = readFileSync(join(p.root, '.ssd/onboarding.yml'), 'utf8');
    const r = await cli(p, [...flags(p), '--yes']);
    assert.equal(r.code, 0, r.err);
    for (const expected of ['SSD AWS Apply', 'Target', 'Verification', '✓ PASS', 'Changes', 'ADD', 'Destructive changes', 'Applying', 'Executing the reviewed change set', 'Execution', 'CREATE_COMPLETE', '✓ APPLIED', 'Next steps', 'aws doctor']) {
      assert.ok(r.out.includes(expected), expected);
    }
    assert.ok(!r.out.includes('\x1b'));
    assert.equal(readFileSync(join(p.root, '.ssd/onboarding.yml'), 'utf8'), configBefore);
    const status = execFileSync('git', ['-C', p.root, 'status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' });
    const changed = status.split('\n').filter(Boolean).map((l) => l.slice(3));
    assert.ok(changed.every((path) => path.startsWith('.ssd/aws-plans/')), changed.join(', '));
  });

  it('--yes without --account or --region is a usage refusal; nothing is contacted', async (t) => {
    const p = await planVia(t);
    for (const args of [['--plan-id', p.planId, '--yes'], ['--plan-id', p.planId, '--region', REGION, '--yes'], ['--plan-id', p.planId, '--account', ACCOUNT, '--yes']]) {
      const r = await cli(p, args);
      assert.equal(r.code, 2);
      assert.match(r.err, /--yes never stands in/);
      assert.equal(r.fake.calls.length, 0);
    }
  });

  it('interactive: the typed account and region execute; "y" does not', async (t) => {
    const p = await planVia(t);
    const no = await cli(p, flags(p), { prompter: scriptedPrompter({ confirmAccount: 'y', confirmRegion: 'y' }) });
    assert.equal(no.code, 1);
    assert.equal(mutations(no.fake), 0);
    assert.match(no.out, /REFUSED/);
    const prompter = scriptedPrompter({ confirmAccount: ACCOUNT, confirmRegion: REGION });
    const yes = await cli(p, flags(p), { prompter });
    assert.equal(yes.code, 0, yes.out);
    assert.deepEqual(prompter.asked, ['confirmAccount', 'confirmRegion']);
    assert.equal(mutations(yes.fake), 1);
  });

  it('--json is one machine document; APPLY_FAILED exits 1', async (t) => {
    const p = await planVia(t);
    const r = await cli(p, [...flags(p), '--yes', '--json'], { world: { sequence: ['ROLLBACK_COMPLETE'] } });
    assert.equal(r.code, 1);
    const doc = JSON.parse(r.out);
    assert.equal(doc.command, 'aws apply');
    assert.equal(doc.outcome, 'APPLY_FAILED');
    assert.ok(!r.out.includes('✓'));
  });

  it('usage: malformed ids, counts and apply-only flags elsewhere exit 2 with no AWS call', async (t) => {
    const p = await planVia(t);
    for (const args of [
      ['--plan-id', 'abc', '--account', ACCOUNT, '--region', REGION],
      ['--plan-id', p.planId, '--account', '12345', '--region', REGION],
      ['--plan-id', p.planId, '--account', ACCOUNT, '--region', 'mars'],
      [...flags(p), '--allow-destructive', 'all'],
      [...flags(p), '--allow-destructive', '-1'],
      [...flags(p), '--scope', 'repo']
    ]) {
      const r = await cli(p, args);
      assert.equal(r.code, 2, args.join(' '));
      assert.equal(r.fake.calls.length, 0);
    }
    const c = capture();
    assert.equal(await main(['aws', 'doctor', '--plan-id', p.planId, '--repo', p.root], { framework: FRAMEWORK, env: {}, ...c.io }), 2);
  });

  it('a refused plan prints the refusal and exits 1', async (t) => {
    const p = await planVia(t);
    const r = await cli(p, [...flags(p).slice(0, 3), '999999999999', '--region', REGION, '--yes']);
    assert.equal(r.code, 1);
    assert.match(r.out, /REFUSED/);
    assert.match(r.out, /account-mismatch|must all be equal/);
  });

  it('verify (Phase 2D) can never reach the apply mutation: its wrapper refuses execute-change-set', async () => {
    const executed = [];
    const aws = verifyAws({ region: 'us-east-1', exec: async (argv) => (executed.push(argv), { stdout: '{}', stderr: '', exitCode: 0 }) });
    assert.equal(aws.executeChangeSet, undefined);
    await assert.rejects(aws(['cloudformation', 'execute-change-set', '--stack-name', 'x', '--change-set-name', 'y']), (error) => error.kind === 'refused');
    assert.deepEqual(executed, []);
  });
});

