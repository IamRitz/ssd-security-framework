// Phase 3C: `aws plan --scope break-glass` and `aws apply` of its plan, end to
// end against recorded AWS behaviour — preconditions, ownership (including the
// OTHER environment's stack), the artifact, the plan record, destructive
// classification, the allowlists, apply intent, and the CLI. No test talks to AWS.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { assertBreakGlassPlanning, assertBreakGlassRead, assertPlanning, assertReadOnly } from '../onboarding/aws/aws-cli.mjs';
import { awsApply } from '../onboarding/aws/apply.mjs';
import { checkIntent, checkPlanRecord } from '../onboarding/aws/apply/plan-check.mjs';
import { awsPlanBreakGlass } from '../onboarding/aws/break-glass/plan.mjs';
import { breakGlassNames } from '../onboarding/aws/break-glass/names.mjs';
import { planDirOf, readPlan } from '../onboarding/aws/plan/record.mjs';
import { FRAMEWORK, capture, config, tempDir } from './support/onboarding-fixtures.mjs';
import { awsError, fakeAws, ok } from './support/aws-fake.mjs';
import { applyWorld, mutations } from './support/aws-apply-fake.mjs';
import { changeSets, stackIdOf, withStack } from './support/aws-plan-fake.mjs';
import { ACCOUNT, ARTIFACT, CHANNELS, OPERATOR_YAML, REGION, accountConcurrency, artifactReads, deployedBreakGlass, existingResource, greenfieldBreakGlass, operator, tagsFor } from './support/break-glass-fake.mjs';

const quiet = async () => {};
const planFake = (world) => fakeAws(world, { allowlist: assertBreakGlassPlanning });
async function run(t, world, { environment = 'production', op = operator(), framework = FRAMEWORK, region = null, root = tempDir(t) } = {}) {
  const f = planFake(world);
  const report = await awsPlanBreakGlass({ operator: op, environment, region, exec: f.exec, env: {}, framework, root, sleep: quiet });
  assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
  return { report, f, root, unit: report.units[0], created: world.__changeSets?.created ?? [] };
}
const kinds = (findings) => findings.map((f) => f.kind);
const planFiles = (root, planId) => Object.fromEntries(readdirSync(join(root, planDirOf(planId))).map((n) => [n, readFileSync(join(root, planDirOf(planId), n), 'utf8')]));

describe('aws plan --scope break-glass: preconditions block before any change set', () => {
  it('a framework checkout not bound to the operator framework.ref blocks before AWS is contacted', async (t) => {
    for (const framework of [null, { ...FRAMEWORK, clean: false, dirtyPaths: ['x'] }, { ...FRAMEWORK, sha: 'f'.repeat(40) }]) {
      const { report, f } = await run(t, greenfieldBreakGlass(), { framework });
      assert.equal(report.outcome, 'BLOCKED');
      assert.ok(kinds(report.findings).includes('framework-binding'));
      assert.equal(f.calls.length, 0);
    }
  });

  it('a --region that differs from aws.region blocks before AWS is contacted', async (t) => {
    const { report, f } = await run(t, greenfieldBreakGlass(), { region: 'eu-west-1' });
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(f.calls.length, 0);
  });

  it('a wrong account: only sts was called', async (t) => {
    const world = greenfieldBreakGlass();
    world['sts get-caller-identity'] = ok({ Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'AROAEXAMPLEEXAMPLE01:y' });
    const { report, f, created } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.deepEqual(f.operations(), ['sts get-caller-identity']);
    assert.equal(created.length, 0);
  });

  it('an unknown environment is refused', async (t) => {
    await assert.rejects(run(t, greenfieldBreakGlass(), { environment: 'staging' }), (e) => e.kind === 'unsupported-environment');
  });
});

describe('aws plan --scope break-glass: a greenfield plan', () => {
  for (const environment of ['production', 'synthetic']) {
    it(`${environment}: one CREATE change set on its own stack, tagged for its own environment`, async (t) => {
      const { report, unit, created, root } = await run(t, greenfieldBreakGlass(environment), { environment });
      assert.equal(report.outcome, 'PLANNED', JSON.stringify(report.units[0]?.findings ?? report.findings));
      assert.equal(created.length, 1);
      const cs = created[0];
      assert.equal(cs.stackName, `ssd-break-glass-${environment}`);
      assert.equal(cs.type, 'CREATE');
      assert.deepEqual(cs.capabilities, ['CAPABILITY_NAMED_IAM']);
      assert.deepEqual(cs.tags, tagsFor(environment));
      assert.deepEqual(cs.template.Resources.RequestTable.Properties.TimeToLiveSpecification, { AttributeName: 'ttl', Enabled: true });
      const plan = JSON.parse(planFiles(root, unit.planId)['plan.json']);
      assert.equal(plan.scope, 'break-glass');
      assert.equal(plan.stackKind, `break-glass-${environment}`);
      assert.equal(plan.repository, null);
      assert.deepEqual(plan.framework, { repository: 'IamRitz/ssd-security-framework', ref: FRAMEWORK.sha });
      assert.equal(unit.iam.length, 2);
      assert.ok(unit.iam.every((i) => i.created), 'both execution roles are created');
    });
  }

  it('production and synthetic plans differ (plan id, stack, change set)', async (t) => {
    const p = await run(t, greenfieldBreakGlass('production'));
    const s = await run(t, greenfieldBreakGlass('synthetic'), { environment: 'synthetic' });
    assert.notEqual(p.unit.planId, s.unit.planId);
    assert.notEqual(p.created[0].stackName, s.created[0].stackName);
  });

  it('no secret material in any plan file or the plan report; the Lambda code is the pinned object version', async (t) => {
    const { report, unit, root } = await run(t, greenfieldBreakGlass());
    const files = planFiles(root, unit.planId);
    const all = Object.values(files).join('\n') + JSON.stringify(report);
    assert.doesNotMatch(all, /SecretString|GenerateSecretString|xox[abpr]-|ghp_|github_pat_|-----BEGIN/);
    const template = JSON.parse(files['template.json']);
    for (const id of ['CiFunction', 'InteractionsFunction']) {
      assert.deepEqual(template.Resources[id].Properties.Code, { S3Bucket: ARTIFACT.bucket, S3Key: ARTIFACT.key, S3ObjectVersion: ARTIFACT.versionId });
    }
    assert.ok(unit.residual.some((r) => r.includes('file:///dev/stdin')));
  });

  it('the template reserves the interaction function\'s concurrency, and the account has room for it', async (t) => {
    const { report, created } = await run(t, greenfieldBreakGlass());
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(created[0].template.Resources.InteractionsFunction.Properties.ReservedConcurrentExecutions, 5);
    assert.equal(created[0].template.Resources.CiFunction.Properties.ReservedConcurrentExecutions, undefined);
  });
});

describe('aws plan --scope break-glass: what blocks', () => {
  const blocked = async (t, world, kind, opts) => {
    const { report, created, root } = await run(t, world, opts);
    assert.equal(report.outcome, 'BLOCKED', JSON.stringify(report.units[0]?.findings));
    assert.ok(kinds(report.units[0].findings).includes(kind), `${kind} in ${JSON.stringify(kinds(report.units[0].findings))}`);
    assert.equal(created.length, 0);
    assert.deepEqual(readdirSync(root), []);
  };

  it('a production-named table owned by the SYNTHETIC stack (cross-environment reuse)', async (t) => {
    await blocked(t, existingResource(greenfieldBreakGlass('production'), { kind: 'table', environment: 'production', stackName: 'ssd-break-glass-synthetic' }), 'exists-not-owned');
  });

  it('a production-named function that exists outside any stack (a name is never ownership)', async (t) => {
    await blocked(t, existingResource(greenfieldBreakGlass('production'), { kind: 'ciFunction', environment: 'production', stackName: null }), 'exists-not-owned');
  });

  it('the production stack name carrying the synthetic environment tag', async (t) => {
    const world = withStack(greenfieldBreakGlass('production'), { name: 'ssd-break-glass-production', tags: tagsFor('synthetic') });
    await blocked(t, world, 'stack-not-plannable');
  });

  it('a stack tagged for a consumer repository', async (t) => {
    const world = withStack(greenfieldBreakGlass('production'), { name: 'ssd-break-glass-production', tags: [...tagsFor('production'), { Key: 'ssd:consumer-repository', Value: 'acme/app' }] });
    await blocked(t, world, 'stack-not-plannable');
  });

  for (const [what, options, kind] of [
    ['an unversioned bucket', { versioning: 'Suspended' }, 'bucket-not-versioned'],
    ['a bucket without a public access block', { publicAccess: false }, 'bucket-public-access'],
    ['a public bucket policy', { policyPublic: true }, 'bucket-public'],
    ['an S3 checksum that is not the configured sha256', { checksum: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }, 'artifact-digest-mismatch']
  ]) {
    it(`the artifact: ${what}`, async (t) => {
      await blocked(t, artifactReads(greenfieldBreakGlass(), options), kind);
    });
  }

  // The configured sha256 is trusted only once S3's full-object SHA-256 of the
  // exact object version equals it: anything less blocks the change set.
  for (const [what, options] of [
    ['S3 stores no SHA-256 for the version', { checksum: null }],
    ['S3\'s SHA-256 is COMPOSITE (multipart)', { checksum: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=-2', checksumType: 'COMPOSITE' }],
    ['S3 reports a COMPOSITE type even for a digest-shaped value', { checksumType: 'COMPOSITE' }],
    ['S3 reports no checksum type', { checksumType: null }]
  ]) {
    it(`the artifact: ${what}`, async (t) => {
      const kind = options.checksum === null ? 'artifact-checksum-absent' : 'artifact-checksum-not-full-object';
      await blocked(t, artifactReads(greenfieldBreakGlass(), options), kind);
    });
  }

  it('the account cannot fit the interaction function\'s reserved concurrency (Lambda keeps 100 unreserved)', async (t) => {
    await blocked(t, accountConcurrency(greenfieldBreakGlass(), { limit: 10, unreserved: 10 }), 'concurrency-quota');
    await blocked(t, accountConcurrency(greenfieldBreakGlass(), { limit: 1000, unreserved: 104 }), 'concurrency-quota');
  });

  it('the artifact: a public access block with one setting off', async (t) => {
    const world = greenfieldBreakGlass();
    world[`s3api get-public-access-block --bucket ${ARTIFACT.bucket}`] = ok({ PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: false, RestrictPublicBuckets: true } });
    await blocked(t, world, 'bucket-public-access');
  });

  it('the artifact version cannot be read (access denied is never "fine")', async (t) => {
    const world = greenfieldBreakGlass();
    world[`s3api head-object --bucket ${ARTIFACT.bucket} --key ${ARTIFACT.key} --version-id ${ARTIFACT.versionId} --checksum-mode ENABLED`] = awsError('403', 'HeadObject', 'Forbidden');
    await blocked(t, world, 'artifact-unreadable');
  });
});

describe('aws plan --scope break-glass: concurrency quota', () => {
  it('exactly 100 left unreserved fits; a reservation already held is not counted twice', async (t) => {
    const { report } = await run(t, accountConcurrency(greenfieldBreakGlass(), { unreserved: 105 }));
    assert.equal(report.outcome, 'PLANNED');
  });

  it('an unreadable account setting is NOT VERIFIED (apply would roll back), not a silent pass', async (t) => {
    const world = greenfieldBreakGlass();
    world['lambda get-account-settings'] = awsError('AccessDeniedException', 'GetAccountSettings', 'denied');
    const { report, unit } = await run(t, world);
    assert.equal(report.outcome, 'PLANNED');
    assert.ok(unit.findings.some((f) => f.kind === 'concurrency-quota-unverified' && f.severity === 'NOT VERIFIED'));
  });
});

describe('aws plan --scope break-glass: replacement and deletion are surfaced', () => {
  // The deployed stack, owned by this plan's stack, and a change set that
  // REPLACES the CI broker and the table.
  function ownedWorld(environment, changes) {
    const world = deployedBreakGlass(environment);
    const name = breakGlassNames(environment).stack;
    world[`cloudformation describe-stacks --stack-name ${stackIdOf(name)}`] = world[`cloudformation describe-stacks --stack-name ${name}`];
    for (const r of world.__stackResources) {
      world[`cloudformation describe-stack-resources --physical-resource-id ${r.PhysicalResourceId}`] = ok({ StackResources: [r] });
    }
    return changeSets(world, { changes });
  }

  it('a REPLACE is counted as destructive in the plan, and apply needs --allow-destructive', async (t) => {
    const changes = () => [
      { Type: 'Resource', ResourceChange: { Action: 'Modify', Replacement: 'True', LogicalResourceId: 'CiFunction', ResourceType: 'AWS::Lambda::Function', Scope: ['Properties'], Details: [] } },
      { Type: 'Resource', ResourceChange: { Action: 'Modify', Replacement: 'False', LogicalResourceId: 'RequestTable', ResourceType: 'AWS::DynamoDB::Table', Scope: ['Properties'], Details: [] } }
    ];
    const { report, unit, created } = await run(t, ownedWorld('production', changes));
    assert.equal(report.outcome, 'PLANNED', JSON.stringify(unit.findings));
    assert.equal(created[0].type, 'UPDATE');
    assert.equal(unit.destructive, 1);
    assert.ok(unit.iam.every((i) => i.unmanaged.length === 0));
  });

  it('an execution role with an unmanaged attachment blocks the plan', async (t) => {
    const world = ownedWorld('production');
    world.__roles['ssd-break-glass-production-ci-execution'].attached = [{ PolicyName: 'AdministratorAccess', PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }];
    world['iam get-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess'] = ok({ Policy: { DefaultVersionId: 'v1' } });
    world['iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --version-id v1'] = ok({ PolicyVersion: { Document: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } } });
    const { report } = await run(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.ok(kinds(report.units[0].findings).includes('unmanaged-policy'));
  });
});

describe('the break-glass allowlists', () => {
  const refused = (fn) => assert.throws(fn, (e) => e.kind === 'refused');

  it('break-glass planning creates change sets only on the two break-glass stacks, and never executes', () => {
    const body = JSON.stringify({ Resources: {} });
    const create = (stack) => ['cloudformation', 'create-change-set', '--stack-name', stack, '--change-set-name', `ssd-plan-${'a'.repeat(64)}`, '--change-set-type', 'CREATE', '--template-body', body, '--tags', '[{"Key":"ssd:environment","Value":"production"}]'];
    assert.doesNotThrow(() => assertBreakGlassPlanning(create('ssd-break-glass-production')));
    refused(() => assertBreakGlassPlanning(create('ssd-shared-github-oidc')));
    refused(() => assertBreakGlassPlanning(create('ssd-delivery-acme-app-12345678')));
    refused(() => assertPlanning(create('ssd-break-glass-synthetic')), 'the delivery planner cannot reach break-glass stacks');
    refused(() => assertBreakGlassPlanning(['cloudformation', 'execute-change-set', '--stack-name', 'ssd-break-glass-production', '--change-set-name', 'x']));
  });

  it('break-glass planning never imports (no IMPORT type, no --import-existing-resources): nothing is adopted by name', () => {
    const body = JSON.stringify({ Resources: {} });
    const base = ['cloudformation', 'create-change-set', '--stack-name', 'ssd-break-glass-synthetic', '--change-set-name', `ssd-plan-${'b'.repeat(64)}`, '--template-body', body];
    refused(() => assertBreakGlassPlanning([...base, '--change-set-type', 'IMPORT']));
    refused(() => assertBreakGlassPlanning([...base, '--change-set-type', 'CREATE', '--import-existing-resources']));
    refused(() => assertBreakGlassPlanning([...base, '--change-set-type', 'CREATE', '--tags', '[{"Key":"owner","Value":"x"}]']));
  });

  it('nothing uploads, writes a secret, or reads a secret value or function code', () => {
    for (const argv of [
      ['s3api', 'put-object', '--bucket', 'b', '--key', 'k'],
      ['s3', 'cp', 'a', 'b'],
      ['secretsmanager', 'put-secret-value', '--secret-id', 'ssd/break-glass/production/slack-bot-token'],
      ['secretsmanager', 'get-secret-value', '--secret-id', 'ssd/break-glass/production/slack-bot-token'],
      ['lambda', 'get-function', '--function-name', 'ssd-break-glass-production-ci'],
      ['lambda', 'update-function-code', '--function-name', 'ssd-break-glass-production-ci'],
      ['dynamodb', 'update-time-to-live', '--table-name', 'ssd-break-glass-production-requests']
    ]) {
      refused(() => assertBreakGlassPlanning(argv));
      refused(() => assertBreakGlassRead(argv));
    }
  });

  it('break-glass reads are confined to break-glass names, and doctor keeps none of them', () => {
    assert.doesNotThrow(() => assertBreakGlassRead(['secretsmanager', 'describe-secret', '--secret-id', 'ssd/break-glass/synthetic/github-token']));
    refused(() => assertBreakGlassRead(['secretsmanager', 'describe-secret', '--secret-id', 'prod/database-password']));
    refused(() => assertBreakGlassRead(['dynamodb', 'describe-table', '--table-name', 'orders']));
    refused(() => assertBreakGlassRead(['lambda', 'get-policy', '--function-name', 'payments']));
    refused(() => assertReadOnly(['dynamodb', 'describe-table', '--table-name', 'ssd-break-glass-production-requests']));
  });
});

describe('aws apply of a break-glass plan', () => {
  async function planned(t, environment = 'production') {
    const root = tempDir(t);
    const { unit } = await run(t, greenfieldBreakGlass(environment), { environment, root });
    return { root, planId: unit.planId };
  }
  const apply = async (p, extra = {}) => {
    const w = applyWorld({ root: p.root, planId: p.planId });
    const report = await awsApply({ operator: operator(), planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet, ...extra });
    return { report, w };
  };

  it('applies exactly the reviewed change set, once, and says what to do out of band', async (t) => {
    const p = await planned(t);
    const { report, w } = await apply(p);
    assert.equal(report.outcome, 'APPLIED', JSON.stringify(report.findings));
    assert.equal(mutations(w.fake), 1);
    assert.ok(report.nextSteps.some((s) => s.includes('file:///dev/stdin') && s.includes('ssd/break-glass/production/slack-bot-token')));
    assert.ok(report.nextSteps.some((s) => s.includes('aws verify --scope break-glass --environment production')));
  });

  it('refuses a changed operator config, a delivery config, or no config at all', async (t) => {
    const p = await planned(t);
    const changed = operator({ environments: { ...operator().environments, production: { ...operator().environments.production, slackChannelId: 'C0OTHERCHAN1' } } });
    for (const [extra, kind] of [
      [{ operator: changed }, 'config-changed'],
      [{ operator: null, config: config('container-ecr-framework-gated') }, 'config-kind-mismatch'],
      [{ operator: null }, 'config-kind-mismatch']
    ]) {
      const { report, w } = await apply(p, extra);
      assert.equal(report.outcome, 'REFUSED');
      assert.ok(kinds(report.findings).includes(kind), `${kind}: ${JSON.stringify(report.findings)}`);
      assert.equal(mutations(w.fake), 0);
    }
  });

  it('a plan whose recorded tags were moved to the other environment is inconsistent', async (t) => {
    const p = await planned(t, 'synthetic');
    const read = await readPlan(p.root, p.planId);
    const tampered = { ...read, plan: { ...read.plan, tags: tagsFor('production'), planIdInput: read.plan.planIdInput } };
    assert.ok(kinds(checkPlanRecord(tampered).findings).includes('plan-inconsistent'));
    const asProduction = { ...read.plan, stackName: 'ssd-break-glass-production' };
    assert.ok(kinds(checkIntent({ plan: asProduction, operator: operator(), framework: FRAMEWORK, account: ACCOUNT, region: REGION })).includes('stack-mismatch'));
  });

  it('a delivery plan is never applied with --operator-config', () => {
    const plan = { scope: 'repo', stackKind: 'repo', account: ACCOUNT, region: REGION };
    assert.ok(kinds(checkIntent({ plan, operator: operator(), framework: FRAMEWORK, account: ACCOUNT, region: REGION })).includes('config-kind-mismatch'));
  });
});

describe('CLI: break-glass flags', () => {
  const cli = async (t, args, { world = greenfieldBreakGlass(), root = tempDir(t), allowlist = assertBreakGlassPlanning } = {}) => {
    const c = capture();
    const f = fakeAws(world, { allowlist });
    const code = await main(['aws', ...args, '--repo', root], { framework: FRAMEWORK, awsExec: f.exec, awsSleep: quiet, env: {}, ...c.io });
    return { code, out: c.text(), err: c.errors(), f, root };
  };
  const operatorFile = (t) => {
    const dir = tempDir(t);
    const path = join(dir, 'break-glass.yml');
    writeFileSync(path, OPERATOR_YAML);
    return path;
  };

  it('usage errors (exit 2, AWS never contacted)', async (t) => {
    const file = operatorFile(t);
    for (const args of [
      ['plan', '--scope', 'break-glass', '--operator-config', file],
      ['plan', '--scope', 'break-glass', '--environment', 'staging', '--operator-config', file],
      ['plan', '--scope', 'break-glass', '--environment', 'production'],
      ['plan', '--environment', 'production'],
      ['doctor', '--operator-config', file],
      ['verify', '--scope', 'repo'],
      ['apply', '--plan-id', 'a'.repeat(64), '--account', ACCOUNT, '--region', REGION, '--environment', 'production']
    ]) {
      const { code, f } = await cli(t, args);
      assert.equal(code, 2, args.join(' '));
      assert.equal(f.calls.length, 0);
    }
  });

  it('plans from the operator file; .ssd/onboarding.yml is not needed or read', async (t) => {
    const { code, out, root } = await cli(t, ['plan', '--scope', 'break-glass', '--environment', 'synthetic', '--operator-config', operatorFile(t), '--json'], { world: greenfieldBreakGlass('synthetic') });
    assert.equal(code, 0);
    const report = JSON.parse(out);
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(report.target.environment, 'synthetic');
    assert.deepEqual(readdirSync(join(root, '.ssd')), ['aws-plans']);
  });

  it('human output names the environment and the operator region, not a repository', async (t) => {
    const { code, out } = await cli(t, ['plan', '--scope', 'break-glass', '--environment', 'production', '--operator-config', operatorFile(t)]);
    assert.equal(code, 0);
    assert.match(out, /Break-glass\s+production/);
    assert.match(out, /\(aws\.region\)/);
    assert.doesNotMatch(out, /Repository|delivery\.aws\.region/);
  });

  it('a credential in the operator file is refused before AWS', async (t) => {
    const dir = tempDir(t);
    const path = join(dir, 'break-glass.yml');
    writeFileSync(path, OPERATOR_YAML.replace(CHANNELS.production, 'xoxb-123456789012-abcdefghijkl'));
    const { code, f, err } = await cli(t, ['plan', '--scope', 'break-glass', '--environment', 'production', '--operator-config', path]);
    assert.equal(code, 1);
    assert.equal(f.calls.length, 0);
    assert.doesNotMatch(err, /xoxb-123456789012/);
  });
});
