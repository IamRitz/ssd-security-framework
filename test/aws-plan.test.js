// `ssd-onboard aws plan` end to end against recorded AWS behaviour: the order
// of checks, ownership, CREATE vs UPDATE, the change-set lifecycle and its
// classification, the plan id, the plan directory and the persisted-secret
// check, the shared scope, and the CLI. No test talks to AWS.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { awsPlan, REGISTRY_SCANNING_UNSUPPORTED } from '../onboarding/aws/plan.mjs';
import { ChangeSetError, classifyChanges, countChanges, isNoChangeReason } from '../onboarding/aws/plan/change-set.mjs';
import { PLAN_FILES, PlanRecordError, assertPersistable, inspectPlanDirectory, planDirOf, planIdInput, planIdOf, writePlanDirectory } from '../onboarding/aws/plan/record.mjs';
import { ScopeError } from '../onboarding/aws/plan/scope.mjs';
import { SHARED_STACKS } from '../onboarding/aws/stack-names.mjs';
import { PathConfinementError, safeWriteFile } from '../onboarding/lib/safe-path.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { FRAMEWORK, capture, commitAll, config, makeRepo, tempDir, write } from './support/onboarding-fixtures.mjs';
import { awsError, ok, readyWorld } from './support/aws-fake.mjs';
import { ACCOUNT, DEPLOY_ROLE, EXPECTED_STACK, MANAGED, OWNED, PROVIDER, REPOSITORY, SHARED_TAGS, SSD_STACK_TAGS, STACK_POLICY, changeSets, greenfieldWorld, modify, ownedWorld, planFake, rolePolicies, stackIdOf, withStack } from './support/aws-plan-fake.mjs';

const ECR = 'container-ecr-framework-gated';
const quiet = async () => {};
async function run(t, world, { overrides = MANAGED, scope = 'repo', framework = FRAMEWORK, env = {}, root = tempDir(t), region = null, sleep = quiet, now, deadlineMs } = {}) {
  const f = planFake(world);
  const report = await awsPlan({ config: config(ECR, overrides), scope, region, exec: f.exec, env, framework, root, sleep, now, deadlineMs });
  assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
  return { report, f, root, created: world.__changeSets?.created ?? [], unit: report.units[0] };
}

const planDirs = (root) => {
  try {
    return readdirSync(join(root, '.ssd/aws-plans'));
  } catch {
    return [];
  }
};
const readPlan = (root, id) => JSON.parse(readFileSync(join(root, planDirOf(id), 'plan.json'), 'utf8'));
const kinds = (findings) => findings.map((f) => f.kind);

describe('aws plan: preconditions block before any change set', () => {
  it('a framework checkout not bound to framework.ref blocks before AWS is contacted', async (t) => {
    for (const framework of [null, { ...FRAMEWORK, clean: false, dirtyPaths: ['x'] }, { ...FRAMEWORK, sha: 'f'.repeat(40) }, { ...FRAMEWORK, slug: 'evil/fork' }]) {
      const { report, f } = await run(t, greenfieldWorld(), { framework });
      assert.equal(report.outcome, 'BLOCKED');
      assert.ok(kinds(report.findings).includes('framework-binding'));
      assert.equal(f.calls.length, 0, 'no AWS call at all');
    }
  });

  it('a --region that differs from delivery.aws.region blocks before AWS is contacted', async (t) => {
    const { report, f } = await run(t, greenfieldWorld(), { region: 'eu-west-1' });
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(f.calls.length, 0);
  });

  it('a wrong account or the root user: only sts was called, no change set', async (t) => {
    for (const caller of [
      { Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'AROAEXAMPLEEXAMPLE01:y' },
      { Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root`, UserId: ACCOUNT }
    ]) {
      const world = greenfieldWorld();
      world['sts get-caller-identity'] = ok(caller);
      const { report, f, created, root } = await run(t, world);
      assert.equal(report.outcome, 'BLOCKED');
      assert.deepEqual(f.operations(), ['sts get-caller-identity']);
      assert.equal(created.length, 0);
      assert.deepEqual(planDirs(root), []);
    }
  });

  it('authentication loss ends the run with no plan', async (t) => {
    const world = greenfieldWorld();
    world['sts get-caller-identity'] = { stdout: '', stderr: 'Unable to locate credentials.', exitCode: 253 };
    await assert.rejects(run(t, world), (error) => error.kind === 'authentication');
  });

  it('an unsupported scope is refused', async (t) => {
    await assert.rejects(run(t, greenfieldWorld(), { scope: 'everything' }), (error) => error.kind === 'unsupported-scope');
  });
});

describe('aws plan --scope repo: CREATE, UPDATE and ownership', () => {
  it('an absent stack plans CREATE with every managed resource and a complete plan directory', async (t) => {
    const { report, unit, root, created, f } = await run(t, greenfieldWorld());
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(unit.changeSetType, 'CREATE');
    assert.deepEqual(unit.baseStack, { state: 'absent' });
    assert.equal(created.length, 1);
    assert.equal(created[0].type, 'CREATE');
    assert.equal(created[0].stackName, EXPECTED_STACK);
    assert.equal(created[0].name, `ssd-plan-${unit.planId}`);
    assert.deepEqual(created[0].capabilities, ['CAPABILITY_NAMED_IAM']);
    assert.deepEqual(created[0].tags, [...SSD_STACK_TAGS].sort((a, b) => (a.Key < b.Key ? -1 : 1)));
    assert.deepEqual(Object.keys(created[0].template.Resources).sort(), ['DeployRole', 'EcrRepository', 'PushScanRole']);
    assert.deepEqual(unit.counts, { CREATE: 3, UPDATE: 0, DELETE: 0, REPLACE: 0 });
    assert.deepEqual(readdirSync(join(root, unit.directory)).sort(), [...PLAN_FILES].sort());
    const plan = readPlan(root, unit.planId);
    for (const key of ['schemaVersion', 'planId', 'scope', 'repository', 'account', 'region', 'callerArn', 'stackName', 'changeSetArn', 'templateSha256', 'parametersSha256', 'framework', 'createdFromConfigDigest', 'changes', 'counts', 'destructive', 'baseStack', 'planIdInput', 'files', 'outcome']) {
      assert.ok(Object.hasOwn(plan, key), key);
    }
    assert.equal(plan.outcome, 'changes');
    assert.equal(plan.framework.ref, FRAMEWORK.sha);
    assert.equal(planIdOf(plan.planIdInput), plan.planId);
    assert.deepEqual(await inspectPlanDirectory(root, unit.planId).then((r) => [r.applicable, r.reason]), [true, null]);
    assert.ok(!f.operations().includes('cloudformation execute-change-set'));
  });

  it('the exact SSD-owned stack plans UPDATE, with its base revision recorded', async (t) => {
    const world = changeSets(ownedWorld(), { changes: modify });
    const { report, unit, root } = await run(t, world);
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(unit.changeSetType, 'UPDATE');
    assert.deepEqual(unit.baseStack, { state: 'present', stackId: stackIdOf(EXPECTED_STACK), stackStatus: 'CREATE_COMPLETE', lastUpdatedTime: '2026-09-01T10:00:00.000Z' });
    assert.deepEqual(unit.counts, { CREATE: 0, UPDATE: 3, DELETE: 0, REPLACE: 0 });
    assert.equal(readPlan(root, unit.planId).planIdInput.baseStack.stackId, stackIdOf(EXPECTED_STACK));
    // Before/after from the live role: its trust and the stack's own inline policy.
    const push = unit.iam.find((i) => i.logicalId === 'PushScanRole');
    assert.equal(push.created, false);
    assert.deepEqual(push.unmanaged, []);
    assert.ok(!kinds(unit.findings).some((k) => k === 'unmanaged-policy' || k === 'policies-unverified'));
  });

  it('an owned managed role with an extra managed policy attached directly: planning refused, policy named, nothing detached', async (t) => {
    const world = ownedWorld();
    const extra = `arn:aws:iam::${ACCOUNT}:policy/legacy-admin`;
    rolePolicies(world, 'app-deploy', { inline: { 'ssd-deploy': STACK_POLICY }, attached: [{ name: 'legacy-admin', arn: extra }, { name: 'AmazonS3FullAccess', arn: 'arn:aws:iam::aws:policy/AmazonS3FullAccess' }] });
    const { report, unit, created, root, f } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    const found = unit.findings.filter((x) => x.kind === 'unmanaged-policy');
    assert.equal(found.length, 2);
    assert.equal(found[0].severity, 'FAIL');
    assert.match(found[0].message, new RegExp(`${DEPLOY_ROLE} exists and is owned by ${EXPECTED_STACK}`));
    assert.match(found[0].message, /legacy-admin/);
    assert.ok(found[0].message.includes(extra));
    assert.match(found[0].message, /Planning is refused/);
    assert.match(found[0].message, /remove it manually, or adopt\/model it explicitly in a future workflow/);
    assert.ok(found[1].message.includes('arn:aws:iam::aws:policy/AmazonS3FullAccess'));
    assert.equal(created.length, 0, 'no change set');
    assert.deepEqual(planDirs(root), []);
    assert.ok(f.operations().every((op) => !/^iam (detach|delete|put|attach)/.test(op)), 'nothing detached or modified');
  });

  it('an owned managed role with an inline policy the stack does not define: planning refused', async (t) => {
    const world = ownedWorld();
    rolePolicies(world, 'app-ecr-push-scan', { inline: { 'ssd-push-scan': STACK_POLICY, 'break-glass-extra': STACK_POLICY } });
    const { report, unit, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    const found = unit.findings.find((x) => x.kind === 'unmanaged-policy');
    assert.equal(found.severity, 'FAIL');
    assert.match(found.message, /inline policy 'break-glass-extra' is not the stack's ssd-push-scan/);
    assert.equal(created.length, 0);
  });

  it("an inline policy with another name replacing the stack's own is still unmanaged", async (t) => {
    const world = ownedWorld();
    rolePolicies(world, 'app-deploy', { inline: { deploy: STACK_POLICY } });
    const { report, unit } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.match(unit.findings.find((x) => x.kind === 'unmanaged-policy').message, /inline policy 'deploy'/);
  });

  it("an owned role whose policies cannot all be read is refused (an unmanaged attachment can't be ruled out)", async (t) => {
    const world = ownedWorld();
    world['iam list-attached-role-policies --role-name app-deploy'] = awsError('AccessDenied', 'ListAttachedRolePolicies');
    const { report, unit, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(unit.findings.find((x) => x.kind === 'policies-unverified').severity, 'FAIL');
    assert.equal(created.length, 0);
  });

  it('a role that is NOT stack-owned is still never adopted, even with the stack\'s policy name and SSD tags', async (t) => {
    const world = greenfieldWorld();
    world['iam get-role --role-name app-deploy'] = ok({ Role: { Arn: DEPLOY_ROLE, RoleName: 'app-deploy', AssumeRolePolicyDocument: {}, Tags: SSD_STACK_TAGS } });
    rolePolicies(world, 'app-deploy', { inline: { 'ssd-deploy': STACK_POLICY } });
    const { report, unit, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(unit.findings).includes('exists-not-owned'));
    assert.equal(unit.resources.find((r) => r.logicalId === 'DeployRole').ownership, 'exists-not-owned');
    assert.equal(created.length, 0);
  });

  it('an untagged stack with the expected name is never updated', async (t) => {
    const world = ownedWorld({ tags: [] });
    const { report, created, unit } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(unit.findings).includes('stack-not-plannable'));
    assert.equal(created.length, 0);
  });

  it('a failed SSD-tagged stack holding no resources (a rolled-back create) is never planned', async (t) => {
    for (const status of ['ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'CREATE_IN_PROGRESS', 'DELETE_FAILED']) {
      const { report, created, unit } = await run(t, withStack(greenfieldWorld(), { status, resources: [] }));
      assert.equal(report.outcome, 'BLOCKED', status);
      assert.ok(kinds(unit.findings).includes('stack-not-plannable'), status);
      assert.equal(created.length, 0, status);
    }
  });

  it('a failed or unsettled stack proves nothing and is never planned', async (t) => {
    for (const status of ['ROLLBACK_COMPLETE', 'UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_FAILED', 'DELETE_IN_PROGRESS', 'CREATE_FAILED']) {
      const { report, created } = await run(t, ownedWorld({ status }));
      assert.equal(report.outcome, 'BLOCKED', status);
      assert.equal(created.length, 0, status);
    }
  });

  it('an existing-but-not-owned resource with the desired name blocks: never adopted', async (t) => {
    const world = greenfieldWorld();
    world[`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`] = readyWorld()[`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`];
    // SSD-looking tags alone prove nothing.
    world[`ecr list-tags-for-resource --resource-arn arn:aws:ecr:us-east-1:${ACCOUNT}:repository/${REPOSITORY}`] = ok({ tags: SSD_STACK_TAGS });
    const { report, unit, created, root } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    const f = unit.findings.find((x) => x.kind === 'exists-not-owned');
    assert.ok(f, 'exists-not-owned');
    assert.match(f.message, /import flow is needed|import flow \(not implemented/);
    assert.equal(unit.resources.find((r) => r.logicalId === 'EcrRepository').ownership, 'exists-not-owned');
    assert.equal(created.length, 0);
    assert.deepEqual(planDirs(root), []);
  });

  it('a resource owned by a DIFFERENT ssd stack does not prove ownership', async (t) => {
    const world = greenfieldWorld();
    world['iam get-role --role-name app-deploy'] = readyWorld()['iam get-role --role-name app-deploy'];
    withStack(world, { name: 'ssd-delivery-acme-other-12345678', resources: [{ logicalId: 'DeployRole', physicalId: 'app-deploy', type: 'AWS::IAM::Role' }] });
    const { report, unit, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(unit.findings).includes('exists-not-owned'));
    assert.equal(created.length, 0);
  });

  it('existing-mode resources are discovered but never in the template', async (t) => {
    const world = greenfieldWorld();
    world['iam get-role --role-name app-ecr-push-scan'] = readyWorld()['iam get-role --role-name app-ecr-push-scan'];
    const { report, created, unit } = await run(t, world, { overrides: { delivery: { environment: 'production', ecr: { ownership: 'managed' }, roles: { pushScanOwnership: 'existing', deployOwnership: 'managed' } } } });
    assert.equal(report.outcome, 'PLANNED');
    assert.deepEqual(Object.keys(created[0].template.Resources).sort(), ['DeployRole', 'EcrRepository']);
    assert.equal(unit.resources.find((r) => r.logicalId === 'PushScanRole').mode, 'existing');
  });

  it('a resource switched to existing leaves the stack as a counted DELETE (retained)', async (t) => {
    const world = changeSets(ownedWorld(), {
      changes: (template) => [
        ...modify(template),
        { Type: 'Resource', ResourceChange: { Action: 'Remove', LogicalResourceId: 'DeployRole', PhysicalResourceId: 'app-deploy', ResourceType: 'AWS::IAM::Role', PolicyAction: 'Retain', Scope: [], Details: [] } }
      ]
    });
    const { unit } = await run(t, world, { overrides: { delivery: { environment: 'production', ecr: { ownership: 'managed' }, roles: { pushScanOwnership: 'managed', deployOwnership: 'existing' } } } });
    assert.ok(kinds(unit.findings).includes('leaves-stack'));
    assert.equal(unit.counts.DELETE, 1);
    assert.equal(unit.destructive, 1);
  });

  it('push and deploy roles whose names differ only in case block (IAM names are case-insensitive)', async (t) => {
    const world = greenfieldWorld();
    world['iam get-role --role-name App-Deploy'] = awsError('NoSuchEntity', 'GetRole');
    const { report, unit, created } = await run(t, world, { overrides: { delivery: { ...MANAGED.delivery, roles: { pushScanRoleArn: `arn:aws:iam::${ACCOUNT}:role/App-Deploy`, deployRoleArn: DEPLOY_ROLE, pushScanOwnership: 'managed', deployOwnership: 'managed' } } } });
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(unit.findings).includes('role-separation'));
    assert.equal(created.length, 0);
  });

  it('a live role whose name matches case-insensitively is a collision, not ours', async (t) => {
    const world = greenfieldWorld();
    world['iam get-role --role-name app-deploy'] = ok({ Role: { Arn: `arn:aws:iam::${ACCOUNT}:role/App-Deploy`, RoleName: 'App-Deploy', AssumeRolePolicyDocument: {}, Tags: [] } });
    const { report, unit, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(unit.findings).includes('role-name-collision'));
    assert.equal(created.length, 0);
  });

  it('an unknown registry scan type blocks a managed push role (its inspector2 statement is undecidable)', async (t) => {
    const world = greenfieldWorld();
    world['ecr get-registry-scanning-configuration'] = awsError('AccessDeniedException', 'GetRegistryScanningConfiguration');
    const { report, unit, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(unit.findings).includes('scan-type-unknown'));
    assert.equal(created.length, 0);
  });

  it('nothing managed and no stack: nothing to plan, no AWS object created', async (t) => {
    const world = changeSets(readyWorld());
    world[`cloudformation describe-stacks --stack-name ${EXPECTED_STACK}`] = awsError('ValidationError', 'DescribeStacks', `Stack with id ${EXPECTED_STACK} does not exist`);
    const { report, created } = await run(t, world, { overrides: { delivery: { environment: 'production' } } });
    assert.equal(report.outcome, 'NOTHING_TO_PLAN');
    assert.equal(created.length, 0);
  });

  it('repo scope never touches registry scanning, Inspector or the OIDC provider', async (t) => {
    const { f, created } = await run(t, greenfieldWorld());
    const text = JSON.stringify(created[0].template);
    for (const type of ['RegistryScanningConfiguration', 'OIDCProvider', 'Inspector']) {
      assert.ok(!text.includes(type), type);
    }
    assert.ok(f.operations().every((op) => !/^(ecr put|inspector2 (enable|disable)|iam create)/.test(op)));
  });
});

describe('aws plan: the REVIEW_IN_PROGRESS placeholder', () => {
  it('an SSD-tagged placeholder (left by an earlier CREATE) plans CREATE again, deterministically', async (t) => {
    const placeholder = () => changeSets(withStack(greenfieldWorld(), { status: 'REVIEW_IN_PROGRESS', resources: [], lastUpdatedTime: null }));
    const a = await run(t, placeholder());
    const b = await run(t, placeholder());
    assert.equal(a.unit.changeSetType, 'CREATE');
    assert.deepEqual(a.unit.baseStack, { state: 'present', stackId: stackIdOf(EXPECTED_STACK), stackStatus: 'REVIEW_IN_PROGRESS', lastUpdatedTime: null });
    assert.equal(a.unit.planId, b.unit.planId);
    const absent = await run(t, greenfieldWorld());
    assert.notEqual(absent.unit.planId, a.unit.planId, 'absent and placeholder are different bases');
  });

  it('a placeholder without SSD tags is never planned', async (t) => {
    const { report, created } = await run(t, withStack(greenfieldWorld(), { status: 'REVIEW_IN_PROGRESS', tags: [{ Key: 'owner', Value: 'someone' }], resources: [] }));
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(created.length, 0);
  });
});

describe('aws plan: plan id', () => {
  it('is deterministic for the same inputs', async (t) => {
    const a = await run(t, greenfieldWorld());
    const b = await run(t, greenfieldWorld());
    assert.equal(a.unit.planId, b.unit.planId);
    assert.match(a.unit.planId, /^[0-9a-f]{64}$/);
  });

  it('a different base StackId or LastUpdatedTime is a different plan', async (t) => {
    const base = await run(t, changeSets(ownedWorld(), { changes: modify }));
    const updated = await run(t, changeSets(ownedWorld({ lastUpdatedTime: '2026-09-02T10:00:00.000Z' }), { changes: modify }));
    assert.notEqual(updated.unit.planId, base.unit.planId);
    const recreated = changeSets(ownedWorld(), { changes: modify });
    const other = 'arn:aws:cloudformation:us-east-1:012345678901:stack/' + EXPECTED_STACK + '/99999999-2222-3333-4444-555555555555';
    const stack = JSON.parse(recreated[`cloudformation describe-stacks --stack-name ${EXPECTED_STACK}`].stdout);
    stack.Stacks[0].StackId = other;
    recreated[`cloudformation describe-stacks --stack-name ${EXPECTED_STACK}`] = ok(stack);
    const replaced = await run(t, recreated);
    assert.notEqual(replaced.unit.planId, base.unit.planId);
  });

  it('binds template, parameters, tags, account, region, scope, stack, type, framework and repository', () => {
    const input = {
      account: ACCOUNT, region: 'us-east-1', scope: 'repo', stackKind: 'repo', stackName: EXPECTED_STACK, changeSetType: 'CREATE', baseStack: { state: 'absent' },
      templateSha256: 'a'.repeat(64), parametersSha256: 'b'.repeat(64), tagsSha256: 'c'.repeat(64), capabilities: ['CAPABILITY_NAMED_IAM'],
      framework: { repository: 'IamRitz/ssd-security-framework', ref: 'd'.repeat(40) }, repository: 'acme/app'
    };
    const id = planIdOf(planIdInput(input));
    for (const [key, value] of [
      ['account', '999999999999'], ['region', 'eu-west-1'], ['scope', 'shared'], ['stackName', 'ssd-shared-github-oidc'], ['changeSetType', 'UPDATE'],
      ['templateSha256', 'e'.repeat(64)], ['parametersSha256', 'e'.repeat(64)], ['tagsSha256', 'e'.repeat(64)], ['capabilities', []],
      ['framework', { repository: 'IamRitz/ssd-security-framework', ref: 'e'.repeat(40) }], ['repository', 'acme/other'],
      ['baseStack', { state: 'present', stackId: 'x', stackStatus: 'CREATE_COMPLETE', lastUpdatedTime: null }]
    ]) {
      assert.notEqual(planIdOf(planIdInput({ ...input, [key]: value })), id, key);
    }
    assert.throws(() => planIdInput({ ...input, baseStack: undefined }), PlanRecordError, 'base stack state is never implicit');
  });
});

describe('aws plan: the change set', () => {
  it('polls with bounded backoff until CREATE_COMPLETE', async (t) => {
    const waits = [];
    const { report } = await run(t, changeSets(greenfieldWorld(), { pending: 3 }), { sleep: async (ms) => waits.push(ms) });
    assert.equal(report.outcome, 'PLANNED');
    assert.deepEqual(waits, [1000, 2000, 3000]);
  });

  it('the overall deadline bounds the wait and fails closed', async (t) => {
    let clock = 0;
    const world = changeSets(greenfieldWorld(), { pending: 1000 });
    const root = tempDir(t);
    await assert.rejects(run(t, world, { root, now: () => clock, deadlineMs: 30_000, sleep: async (ms) => (clock += ms) }), (error) => error.kind === 'deadline');
    assert.deepEqual(planDirs(root), []);
  });

  it('FAILED with the no-change reason records outcome no-changes, which is never applicable', async (t) => {
    const world = changeSets(ownedWorld(), { status: 'FAILED', reason: "The submitted information didn't contain changes. Submit different information to create a change set." });
    const { report, unit, root } = await run(t, world);
    assert.equal(report.outcome, 'NO_CHANGES');
    assert.equal(unit.status, 'no-changes');
    const plan = readPlan(root, unit.planId);
    assert.equal(plan.outcome, 'no-changes');
    assert.equal(plan.changeSet.status, 'FAILED');
    const inspected = await inspectPlanDirectory(root, unit.planId);
    assert.equal(inspected.applicable, false);
    assert.match(inspected.reason, /no-changes/);
    assert.ok(isNoChangeReason('No updates are to be performed.'));
    assert.ok(!isNoChangeReason('Template format error: no changes here'));
  });

  it('any other FAILED, or an unexpected status, is an error and records nothing', async (t) => {
    const noStatus = (doc) => {
      const { Status, ...rest } = doc;
      return rest;
    };
    for (const [options, kind] of [
      [{ status: 'FAILED', reason: 'Resource handler returned message: "Invalid request"' }, 'change-set-failed'],
      [{ status: 'DELETE_COMPLETE' }, 'unexpected-state'],
      [{ describe: noStatus }, 'unexpected-state']
    ]) {
      const root = tempDir(t);
      await assert.rejects(run(t, changeSets(greenfieldWorld(), options), { root }), (error) => error instanceof ChangeSetError && error.kind === kind, JSON.stringify(options));
      assert.deepEqual(planDirs(root), []);
    }
  });

  it('DELETE and REPLACE (True and Conditional) are counted as destructive', () => {
    const changes = classifyChanges([
      { Type: 'Resource', ResourceChange: { Action: 'Add', LogicalResourceId: 'A', ResourceType: 'AWS::IAM::Role' } },
      { Type: 'Resource', ResourceChange: { Action: 'Modify', Replacement: 'False', LogicalResourceId: 'B', ResourceType: 'AWS::IAM::Role' } },
      { Type: 'Resource', ResourceChange: { Action: 'Modify', Replacement: 'True', LogicalResourceId: 'C', ResourceType: 'AWS::ECR::Repository' } },
      { Type: 'Resource', ResourceChange: { Action: 'Modify', Replacement: 'Conditional', LogicalResourceId: 'D', ResourceType: 'AWS::IAM::Role' } },
      { Type: 'Resource', ResourceChange: { Action: 'Remove', LogicalResourceId: 'E', ResourceType: 'AWS::IAM::Role' } }
    ]);
    assert.deepEqual(changes.map((c) => c.action), ['CREATE', 'UPDATE', 'REPLACE', 'REPLACE', 'DELETE']);
    assert.equal(changes[3].conditional, true);
    assert.deepEqual(countChanges(changes), { counts: { CREATE: 1, UPDATE: 1, DELETE: 1, REPLACE: 2 }, destructive: 3 });
  });

  it('Dynamic, Import and unknown actions fail closed', () => {
    for (const Action of ['Dynamic', 'Import', 'SyncWithActual', undefined]) {
      assert.throws(() => classifyChanges([{ Type: 'Resource', ResourceChange: { Action, LogicalResourceId: 'A', ResourceType: 'AWS::IAM::Role' } }]), ChangeSetError, String(Action));
    }
    assert.throws(() => classifyChanges([{ Type: 'Resource', ResourceChange: { Action: 'Modify', Replacement: 'Maybe', LogicalResourceId: 'A', ResourceType: 'AWS::IAM::Role' } }]), ChangeSetError);
    assert.throws(() => classifyChanges([{ Type: 'Hook' }]), ChangeSetError);
  });

  it('a replacement is recorded and shown as destructive', async (t) => {
    const world = changeSets(ownedWorld(), {
      changes: (template) => modify(template).map((c) => (c.ResourceChange.LogicalResourceId === 'PushScanRole' ? { ...c, ResourceChange: { ...c.ResourceChange, Replacement: 'True' } } : c))
    });
    const { unit, root } = await run(t, world);
    assert.equal(unit.counts.REPLACE, 1);
    assert.equal(readPlan(root, unit.planId).destructive, 1);
  });

  it('a malformed or mismatched describe-change-set fails closed and records nothing', async (t) => {
    for (const describe of [
      (doc) => ({ ...doc, Changes: undefined }),
      (doc) => ({ ...doc, ChangeSetId: 'arn:aws:cloudformation:us-east-1:012345678901:changeSet/other/1' }),
      (doc) => ({ ...doc, NextToken: 'more' }),
      (doc) => ({ ...doc, ImportExistingResources: true }),
      (doc) => ({ ...doc, IncludeNestedStacks: true }),
      (doc) => ({ ...doc, Tags: [] }),
      (doc) => ({ ...doc, Capabilities: ['CAPABILITY_AUTO_EXPAND'] }),
      (doc) => ({ ...doc, ExecutionStatus: 'EXECUTE_COMPLETE' })
    ]) {
      const root = tempDir(t);
      await assert.rejects(run(t, changeSets(greenfieldWorld(), { describe }), { root }), ChangeSetError);
      assert.deepEqual(planDirs(root), []);
    }
  });

  it('the post-describe scope assertion catches a change AWS reports outside the stack scope', async (t) => {
    const root = tempDir(t);
    const world = changeSets(greenfieldWorld(), {
      changes: (template) => [
        ...Object.entries(template.Resources).map(([id, r]) => ({ Type: 'Resource', ResourceChange: { Action: 'Add', LogicalResourceId: id, ResourceType: r.Type } })),
        { Type: 'Resource', ResourceChange: { Action: 'Add', LogicalResourceId: 'Sneaky', ResourceType: 'AWS::IAM::OIDCProvider' } }
      ]
    });
    await assert.rejects(run(t, world, { root }), ScopeError);
    assert.deepEqual(planDirs(root), []);
  });

  it('a template CloudFormation rejects fails closed', async (t) => {
    const world = changeSets(greenfieldWorld(), { validate: () => awsError('ValidationError', 'ValidateTemplate', 'Template format error') });
    await assert.rejects(run(t, world), (error) => error.kind === 'template-invalid');
    assert.equal(world.__changeSets.created.length, 0);
  });

  it('an existing change set of the same name (directory lost) is refused, not replaced', async (t) => {
    const world = greenfieldWorld();
    world['cloudformation create-change-set *'] = awsError('AlreadyExistsException', 'CreateChangeSet', 'ChangeSet ssd-plan-x already exists');
    await assert.rejects(run(t, world), (error) => error.kind === 'change-set-exists');
  });
});

describe('aws plan: the plan directory', () => {
  it('an existing plan is never overwritten; the second run creates no change set', async (t) => {
    const root = tempDir(t);
    const world = greenfieldWorld();
    await run(t, world, { root });
    const before = world.__changeSets.created.length;
    await assert.rejects(run(t, world, { root }), (error) => error.kind === 'plan-exists');
    assert.equal(world.__changeSets.created.length, before, 'refused before create-change-set');
  });

  it('a symbolic link in the plan path is refused before any change set', async (t) => {
    for (const link of ['.ssd', '.ssd/aws-plans']) {
      const root = tempDir(t);
      const outside = tempDir(t);
      if (link === '.ssd/aws-plans') {
        mkdirSync(join(root, '.ssd'));
      }
      symlinkSync(outside, join(root, link));
      const world = greenfieldWorld();
      await assert.rejects(run(t, world, { root }), PathConfinementError, link);
      assert.equal(world.__changeSets.created.length, 0, link);
      assert.deepEqual(readdirSync(outside), [], 'nothing written through the link');
    }
  });

  it('a plan id can never name a path outside .ssd/aws-plans', () => {
    for (const id of ['../../etc', '..', 'a/b', '', 'A'.repeat(64), `${'a'.repeat(63)}/`]) {
      assert.throws(() => planDirOf(id), PlanRecordError, id);
    }
  });

  it('plan.json is written last; a directory interrupted before it is never applicable', async (t) => {
    const root = tempDir(t);
    const id = 'a'.repeat(64);
    const files = Object.fromEntries(PLAN_FILES.map((name) => [name, `${name}\n`]));
    const order = [];
    await assert.rejects(
      writePlanDirectory(root, id, files, {}, {
        write: async (r, path, data, options) => {
          order.push(path.split('/').pop());
          if (path.endsWith('policies.json')) {
            throw new Error('disk full');
          }
          return safeWriteFile(r, path, data, options);
        }
      }),
      /disk full/
    );
    assert.deepEqual(order, ['template.json', 'parameters.json', 'change-set.json', 'policies.json']);
    assert.equal(PLAN_FILES.at(-1), 'plan.json');
    const inspected = await inspectPlanDirectory(root, id);
    assert.equal(inspected.applicable, false);
    assert.match(inspected.reason, /plan\.json is missing/);
  });

  it('a plan.json whose sibling file is missing is incomplete, never applicable', async (t) => {
    const { root, unit } = await run(t, greenfieldWorld());
    rmSync(join(root, unit.directory, 'change-set.json'));
    const inspected = await inspectPlanDirectory(root, unit.planId);
    assert.equal(inspected.applicable, false);
    assert.match(inspected.reason, /incomplete: change-set\.json is missing/);
  });

  it('a tampered file, or a plan.json that does not bind its id, is not applicable', async (t) => {
    const { root, unit } = await run(t, greenfieldWorld());
    const dir = join(root, unit.directory);
    writeFileSync(join(dir, 'template.json'), '{}\n');
    assert.match((await inspectPlanDirectory(root, unit.planId)).reason, /template\.json does not match/);
    const other = await run(t, greenfieldWorld());
    const plan = readPlan(other.root, other.unit.planId);
    writeFileSync(join(other.root, other.unit.directory, 'plan.json'), JSON.stringify({ ...plan, planIdInput: { ...plan.planIdInput, region: 'eu-west-1' } }));
    assert.match((await inspectPlanDirectory(other.root, other.unit.planId)).reason, /does not bind/);
  });
});

describe('aws plan: persisted data is secret-free', () => {
  const CREDENTIALS = {
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    AWS_SESSION_TOKEN: 'IQoJb3JpZ2luX2VjEXAMPLESESSIONTOKENVALUE1234567890',
    GITHUB_TOKEN: 'ghp_' + 'A'.repeat(36)
  };
  const SHAPES = [
    /\bAKIA[0-9A-Z]{16}\b/,
    /aws_secret_access_key|aws_session_token/i,
    /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
    /hooks\.slack\.com\//,
    /\bgh[pousr]_[A-Za-z0-9]{30,}|github_pat_/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/
  ];

  it('no credential value or shape in any file of the plan directory (recursive scan)', async (t) => {
    const { root } = await run(t, greenfieldWorld(), { env: CREDENTIALS });
    const files = [];
    const walk = (dir) => readdirSync(dir).forEach((name) => (statSync(join(dir, name)).isDirectory() ? walk(join(dir, name)) : files.push(join(dir, name))));
    walk(join(root, '.ssd/aws-plans'));
    assert.equal(files.length, PLAN_FILES.length);
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      for (const value of Object.values(CREDENTIALS)) {
        assert.ok(!text.includes(value), `${file} holds a credential value`);
      }
      for (const shape of SHAPES) {
        assert.doesNotMatch(text, shape, file);
      }
    }
  });

  it('a credential-like value entering plan data refuses the plan; nothing is written or redacted', async (t) => {
    for (const leak of ['AKIAIOSFODNN7EXAMPLE', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl', 'https://hooks.slack.com/services/T000/B000/XXXX', '-----BEGIN RSA PRIVATE KEY-----', 'ghp_' + 'B'.repeat(36), CREDENTIALS.AWS_SESSION_TOKEN]) {
      const root = tempDir(t);
      const world = changeSets(greenfieldWorld(), { describe: (doc) => ({ ...doc, Description: `note ${leak}` }) });
      await assert.rejects(run(t, world, { root, env: CREDENTIALS }), (error) => error instanceof PlanRecordError && error.kind === 'secret-in-plan' && !error.message.includes(leak), leak);
      assert.deepEqual(planDirs(root), [], leak);
    }
  });

  it('commit SHAs and plan hashes are not mistaken for secret keys', () => {
    assert.doesNotThrow(() => assertPersistable({ 'plan.json': JSON.stringify({ ref: 'f'.repeat(40), sha: '0123456789abcdef'.repeat(4) }) }, {}));
    assert.throws(() => assertPersistable({ 'x.json': `"${CREDENTIALS.AWS_SECRET_ACCESS_KEY}"` }, {}), PlanRecordError);
  });
});

describe('aws plan --scope shared', () => {
  const shared = (extra = {}) => ({ delivery: { environment: 'production', ...extra } });

  it('existing OIDC provider and registry scanning: reported, nothing planned', async (t) => {
    const { report, created } = await run(t, greenfieldWorld(), { scope: 'shared', overrides: shared() });
    assert.equal(report.outcome, 'NOTHING_TO_PLAN');
    assert.equal(created.length, 0);
    assert.deepEqual(report.units.map((u) => [u.stackKind, u.mode]), [['shared-github-oidc', 'report-only'], ['shared-ecr-scanning', 'report-only']]);
  });

  it('a managed, absent OIDC provider plans only the shared OIDC stack — never a repo resource', async (t) => {
    const world = greenfieldWorld();
    world['iam list-open-id-connect-providers'] = ok({ OpenIDConnectProviderList: [] });
    const { report, created, unit } = await run(t, world, { scope: 'shared', overrides: shared({ oidcProvider: 'managed' }) });
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(created.length, 1, 'one plan id per stack');
    assert.equal(created[0].stackName, SHARED_STACKS.githubOidc);
    assert.deepEqual(Object.values(created[0].template.Resources).map((r) => r.Type), ['AWS::IAM::OIDCProvider']);
    assert.deepEqual(created[0].capabilities, []);
    assert.deepEqual(created[0].tags, [...SHARED_TAGS].sort((a, b) => (a.Key < b.Key ? -1 : 1)));
    assert.equal(unit.stackKind, 'shared-github-oidc');
  });

  it('an existing provider that is not owned by the shared stack blocks', async (t) => {
    const { report, created } = await run(t, greenfieldWorld(), { scope: 'shared', overrides: shared({ oidcProvider: 'managed' }) });
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(report.units[0].findings).includes('exists-not-owned'));
    assert.equal(created.length, 0);
  });

  it('the provider owned by the exact shared stack plans UPDATE', async (t) => {
    const world = withStack(greenfieldWorld(), { name: SHARED_STACKS.githubOidc, tags: SHARED_TAGS, resources: [{ logicalId: 'GitHubOidcProvider', physicalId: PROVIDER, type: 'AWS::IAM::OIDCProvider' }] });
    changeSets(world, { changes: modify });
    const { report, unit } = await run(t, world, { scope: 'shared', overrides: shared({ oidcProvider: 'managed' }) });
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(unit.changeSetType, 'UPDATE');
  });

  it('a repo resource reported in the shared change set fails the scope assertion', async (t) => {
    const world = greenfieldWorld();
    world['iam list-open-id-connect-providers'] = ok({ OpenIDConnectProviderList: [] });
    changeSets(world, { changes: () => [{ Type: 'Resource', ResourceChange: { Action: 'Add', LogicalResourceId: 'GitHubOidcProvider', ResourceType: 'AWS::ECR::Repository' } }] });
    await assert.rejects(run(t, world, { scope: 'shared', overrides: shared({ oidcProvider: 'managed' }) }), ScopeError);
  });

  it('managed registry scanning is not planned in Phase 2B: it blocks with the reason, and nothing is created', async (t) => {
    const world = greenfieldWorld();
    world['iam list-open-id-connect-providers'] = ok({ OpenIDConnectProviderList: [] });
    const { report, created } = await run(t, world, { scope: 'shared', overrides: shared({ oidcProvider: 'managed', registryScanning: 'managed' }) });
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(report.units[1].findings[0].message, REGISTRY_SCANNING_UNSUPPORTED);
    assert.equal(created.length, 0, 'the OIDC unit is not planned either: the run blocks as a whole');
  });

  it('existing registry scanning that does not cover the repository: the proposal keeps every current rule', async (t) => {
    const world = greenfieldWorld();
    world['ecr get-registry-scanning-configuration'] = ok({ registryId: ACCOUNT, scanningConfiguration: { scanType: 'ENHANCED', rules: [{ scanFrequency: 'CONTINUOUS_SCAN', repositoryFilters: [{ filter: 'prod-*', filterType: 'WILDCARD' }] }] } });
    world[`inspector2 batch-get-account-status --account-ids ${ACCOUNT}`] = ok({ accounts: [{ accountId: ACCOUNT, state: { status: 'ENABLED' }, resourceState: { ecr: { status: 'ENABLED' } } }] });
    const { report } = await run(t, world, { scope: 'shared', overrides: shared() });
    const unit = report.units[1];
    assert.equal(unit.proposal.changed, true);
    assert.deepEqual(unit.proposal.proposed, { scanType: 'ENHANCED', rules: [{ frequency: 'CONTINUOUS_SCAN', filters: [{ filter: 'prod-*', type: 'WILDCARD' }, { filter: 'app', type: 'WILDCARD' }] }] });
    assert.match(unit.residual[0], /Inspector ECR scanning is ENABLED/);
  });
});

describe('aws plan: CLI', () => {
  function consumer(t, overrides = MANAGED) {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n', Dockerfile: 'FROM scratch\n' });
    write(root, '.ssd/onboarding.yml', serializeConfig(config(ECR, overrides)));
    commitAll(root, 'config');
    return root;
  }
  async function cli(root, args, world = greenfieldWorld()) {
    const c = capture();
    const f = planFake(world);
    const code = await main([...args, '--repo', root], { framework: FRAMEWORK, awsExec: f.exec, awsSleep: quiet, env: {}, ...c.io });
    return { code, out: c.text(), err: c.errors(), f, world };
  }

  it('`aws plan` is `aws plan --scope repo`; human output shows target, changes, destructive, plan; no ANSI', async (t) => {
    const root = consumer(t);
    const configBefore = readFileSync(join(root, '.ssd/onboarding.yml'), 'utf8');
    const { code, out, err } = await cli(root, ['aws', 'plan']);
    assert.equal(code, 0, err);
    for (const expected of ['SSD AWS Plan', 'Scope       repo', 'Change set  CREATE', '+ CREATE  AWS::ECR::Repository', 'Destructive', '✓ PASS', 'none', 'IAM (semantic diff)', '+ subject Allow StringEquals repo:acme/app:ref:refs/heads/main', 'REVIEW_IN_PROGRESS', 'PLANNED']) {
      assert.ok(out.includes(expected), expected);
    }
    assert.ok(!out.includes('\x1b'));
    assert.equal(readFileSync(join(root, '.ssd/onboarding.yml'), 'utf8'), configBefore, '.ssd/onboarding.yml is never modified');
    const second = await cli(consumer(t), ['aws', 'plan', '--scope', 'repo']);
    assert.equal(second.code, 0);
  });

  it('an unmanaged attachment on an owned role is shown as a refusal with the exact policy', async (t) => {
    const world = ownedWorld();
    rolePolicies(world, 'app-deploy', { inline: { 'ssd-deploy': STACK_POLICY }, attached: [{ name: 'legacy-admin', arn: `arn:aws:iam::${ACCOUNT}:policy/legacy-admin` }] });
    const { code, out } = await cli(consumer(t), ['aws', 'plan'], world);
    assert.equal(code, 1);
    for (const expected of ['✗ FAIL', `arn:aws:iam::${ACCOUNT}:policy/legacy-admin`, 'Planning is refused', 'no change set was created', 'BLOCKED']) {
      assert.ok(out.includes(expected), expected);
    }
  });

  it('destructive changes are impossible to miss in human output', async (t) => {
    const world = changeSets(ownedWorld(), {
      changes: (template) => modify(template).map((c, i) => (i === 0 ? { ...c, ResourceChange: { ...c.ResourceChange, Replacement: 'True' } } : c))
    });
    const { code, out } = await cli(consumer(t), ['aws', 'plan'], world);
    assert.equal(code, 0);
    assert.ok(out.includes('✗ FAIL'));
    assert.ok(out.includes('DESTRUCTIVE: 1 (0 DELETE, 1 REPLACE)'));
    assert.ok(out.includes('! REPLACE'));
  });

  it('--json is one machine document; a blocked plan exits 1', async (t) => {
    const { code, out } = await cli(consumer(t), ['aws', 'plan', '--json']);
    assert.equal(code, 0);
    const doc = JSON.parse(out);
    assert.equal(doc.command, 'aws plan');
    assert.equal(doc.scope, 'repo');
    assert.equal(doc.outcome, 'PLANNED');
    assert.ok(!out.includes('✓'));
    assert.ok(doc.awsCalls.every((c) => !c.includes('"Resources"')), 'the template body is not echoed into the call log');
    const world = greenfieldWorld();
    world['sts get-caller-identity'] = ok({ Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root`, UserId: ACCOUNT });
    const blocked = await cli(consumer(t), ['aws', 'plan', '--json'], world);
    assert.equal(blocked.code, 1);
    assert.equal(JSON.parse(blocked.out).outcome, 'BLOCKED');
  });

  it('a run-ending error is one typed JSON document, exit 1', async (t) => {
    const world = changeSets(greenfieldWorld(), { status: 'FAILED', reason: 'Something broke' });
    const { code, out } = await cli(consumer(t), ['aws', 'plan', '--json'], world);
    assert.equal(code, 1);
    const doc = JSON.parse(out);
    assert.equal(doc.outcome, 'ERROR');
    assert.equal(doc.error.kind, 'change-set-failed');
  });

  it('usage: an unknown scope exits 2; doctor does not accept --scope', async (t) => {
    const root = consumer(t);
    assert.equal((await cli(root, ['aws', 'plan', '--scope', 'all'])).code, 2);
    const doctor = await cli(root, ['aws', 'doctor', '--scope', 'repo']);
    assert.equal(doctor.code, 2);
    assert.equal(doctor.f.calls.length, 0);
  });

  it('apply without its flags is a usage error and contacts nothing', async (t) => {
    const apply = await cli(consumer(t), ['aws', 'apply']);
    assert.equal(apply.code, 2);
    assert.match(apply.err, /requires --plan-id, --account and --region/);
    assert.equal(apply.f.calls.length, 0);
  });

  it('a non-ECR profile is a configuration error', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    write(root, '.ssd/onboarding.yml', serializeConfig(config('source-only')));
    commitAll(root, 'config');
    const { code, err } = await cli(root, ['aws', 'plan']);
    assert.equal(code, 1);
    assert.match(err, /aws plan plans the AWS delivery/);
  });
});
