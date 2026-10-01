// The planning allowlist (Phase 2B) and its separation from doctor's.
//
// doctor keeps exactly the Phase 2A read-only allowlist; `aws plan` gets a
// SEPARATE wrapper whose only additions are the CloudFormation calls a plan
// needs. Neither can execute a change set, create/update/delete a stack, or
// mutate IAM, ECR, Inspector, SSM or Secrets Manager — refused before anything
// is executed.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { FakeAwsError } from './support/aws-fake.mjs';
import { planFake } from './support/aws-plan-fake.mjs';
import { AwsCliError, MAX_TEMPLATE_BODY, PLANNING_OPERATIONS, READ_ONLY_OPERATIONS, assertPlanning, assertReadOnly, planningAws, readOnlyAws } from '../onboarding/aws/aws-cli.mjs';

const refused = (fn) => assert.throws(fn, (error) => error instanceof AwsCliError && error.kind === 'refused');
const ok = (value) => ({ stdout: JSON.stringify(value), stderr: '', exitCode: 0 });
const STACK = 'ssd-delivery-acme-app-98d9fc12';
const CS = `ssd-plan-${'a'.repeat(64)}`;
const BODY = JSON.stringify({ Resources: { R: { Type: 'AWS::ECR::Repository' } } });
const TAGS = JSON.stringify([{ Key: 'ssd:managed-by', Value: 'ssd-onboard' }]);
const create = (...extra) => ['cloudformation', 'create-change-set', '--stack-name', STACK, '--change-set-name', CS, '--change-set-type', 'CREATE', '--template-body', BODY, '--tags', TAGS, ...extra];

// Phase 2A's allowlist, verbatim. Any change to doctor's operations or flags
// fails here.
const PHASE_2A = {
  sts: { 'get-caller-identity': [] },
  iam: {
    'list-open-id-connect-providers': [],
    'get-open-id-connect-provider': ['--open-id-connect-provider-arn'],
    'get-role': ['--role-name'],
    'list-role-policies': ['--role-name'],
    'get-role-policy': ['--role-name', '--policy-name'],
    'list-attached-role-policies': ['--role-name'],
    'get-policy': ['--policy-arn'],
    'get-policy-version': ['--policy-arn', '--version-id'],
    'get-instance-profile': ['--instance-profile-name'],
    'simulate-principal-policy': ['--policy-source-arn', '--action-names', '--resource-arns']
  },
  ecr: {
    'describe-repositories': ['--registry-id', '--repository-names'],
    'get-lifecycle-policy': ['--registry-id', '--repository-name'],
    'get-repository-policy': ['--registry-id', '--repository-name'],
    'get-registry-scanning-configuration': [],
    'list-tags-for-resource': ['--resource-arn']
  },
  inspector2: { 'batch-get-account-status': ['--account-ids'], 'list-coverage': ['--filter-criteria'] },
  ssm: { 'describe-instance-information': ['--filters'] },
  ec2: { 'describe-instances': ['--instance-ids'] },
  cloudformation: { 'describe-stack-resources': ['--physical-resource-id'], 'describe-stacks': ['--stack-name'] }
};

const FORBIDDEN = [
  ['cloudformation', 'execute-change-set', '--stack-name', STACK, '--change-set-name', CS],
  ['cloudformation', 'create-stack', '--stack-name', STACK, '--template-body', BODY],
  ['cloudformation', 'update-stack', '--stack-name', STACK, '--template-body', BODY],
  ['cloudformation', 'delete-stack', '--stack-name', STACK],
  ['cloudformation', 'delete-change-set', '--stack-name', STACK, '--change-set-name', CS],
  ['cloudformation', 'continue-update-rollback', '--stack-name', STACK],
  ['cloudformation', 'get-template', '--stack-name', STACK],
  ['iam', 'create-role', '--role-name', 'x', '--assume-role-policy-document', '{}'],
  ['iam', 'put-role-policy', '--role-name', 'x', '--policy-name', 'p', '--policy-document', '{}'],
  ['iam', 'update-assume-role-policy', '--role-name', 'x', '--policy-document', '{}'],
  ['iam', 'delete-role', '--role-name', 'x'],
  ['iam', 'create-open-id-connect-provider', '--url', 'https://token.actions.githubusercontent.com'],
  ['ecr', 'create-repository', '--repository-name', 'app'],
  ['ecr', 'delete-repository', '--repository-name', 'app'],
  ['ecr', 'put-registry-scanning-configuration', '--scan-type', 'BASIC'],
  ['ecr', 'put-image-tag-mutability', '--repository-name', 'app', '--image-tag-mutability', 'MUTABLE'],
  ['inspector2', 'enable', '--resource-types', 'ECR'],
  ['inspector2', 'disable', '--resource-types', 'ECR'],
  ['ssm', 'send-command', '--instance-ids', 'i-0123456789abcdef0'],
  ['ssm', 'put-parameter', '--name', 'x', '--value', 'y'],
  ['secretsmanager', 'put-secret-value', '--secret-id', 'x', '--secret-string', 'y']
];

describe('doctor keeps the Phase 2A read-only allowlist', () => {
  it('READ_ONLY_OPERATIONS is exactly the Phase 2A table', () => {
    const actual = Object.fromEntries(Object.entries(READ_ONLY_OPERATIONS).map(([s, ops]) => [s, Object.fromEntries(Object.entries(ops).map(([op, flags]) => [op, Object.keys(flags)]))]));
    assert.deepEqual(actual, PHASE_2A);
    for (const ops of Object.values(READ_ONLY_OPERATIONS)) {
      for (const flags of Object.values(ops)) {
        assert.ok(Object.values(flags).every((v) => v === true || v === false), 'doctor flags take any value; no planning predicate leaked in');
      }
    }
  });

  it('doctor cannot call any planning operation (refused before execution)', async () => {
    const planningOnly = [
      ['cloudformation', 'validate-template', '--template-body', BODY],
      create(),
      ['cloudformation', 'describe-change-set', '--stack-name', STACK, '--change-set-name', CS],
      ['cloudformation', 'describe-stack-resources', '--stack-name', STACK]
    ];
    let executed = 0;
    const aws = readOnlyAws({ region: 'us-east-1', exec: async () => (executed += 1, ok({})) });
    for (const argv of planningOnly) {
      refused(() => assertReadOnly(argv));
      await assert.rejects(aws(argv), (error) => error.kind === 'refused' && /read-only allowlist|read operation/.test(error.message));
      assert.doesNotThrow(() => assertPlanning(argv), argv.join(' '));
    }
    assert.equal(executed, 0);
  });
});

describe('the planning allowlist', () => {
  it('is the read-only table plus exactly the planning CloudFormation calls', () => {
    const extra = [];
    for (const [service, ops] of Object.entries(PLANNING_OPERATIONS)) {
      for (const [op, flags] of Object.entries(ops)) {
        const ro = READ_ONLY_OPERATIONS[service]?.[op];
        for (const flagName of Object.keys(flags)) {
          if (!ro || !Object.hasOwn(ro, flagName)) {
            extra.push(`${service} ${op} ${flagName}`);
          }
        }
        if (ro) {
          for (const flagName of Object.keys(ro)) {
            assert.ok(Object.hasOwn(flags, flagName), `${service} ${op} keeps ${flagName}`);
          }
        }
      }
    }
    assert.deepEqual(extra.sort(), [
      'cloudformation create-change-set --capabilities',
      'cloudformation create-change-set --change-set-name',
      'cloudformation create-change-set --change-set-type',
      'cloudformation create-change-set --stack-name',
      'cloudformation create-change-set --tags',
      'cloudformation create-change-set --template-body',
      'cloudformation describe-change-set --change-set-name',
      'cloudformation describe-change-set --stack-name',
      'cloudformation describe-stack-resources --stack-name',
      'cloudformation validate-template --template-body'
    ]);
  });

  it('cannot execute a change set or mutate any resource (refused before execution)', async () => {
    let executed = 0;
    const aws = planningAws({ region: 'us-east-1', exec: async () => (executed += 1, ok({})) });
    for (const argv of FORBIDDEN) {
      refused(() => assertPlanning(argv));
      await assert.rejects(aws(argv), (error) => error.kind === 'refused' && /planning allowlist/.test(error.message), argv.join(' '));
    }
    assert.equal(executed, 0);
  });

  it('refuses IMPORT change sets and every adoption flag', () => {
    refused(() => assertPlanning(create().map((v) => (v === 'CREATE' ? 'IMPORT' : v))));
    refused(() => assertPlanning(create('--resources-to-import', '[{"ResourceType":"AWS::ECR::Repository"}]')));
    refused(() => assertPlanning(create('--import-existing-resources')));
    refused(() => assertPlanning(create('--import-existing-resources', 'true')));
  });

  it('refuses every create-change-set flag that changes where content or authority comes from', () => {
    for (const extra of [
      ['--template-url', 'https://bucket.s3.amazonaws.com/t.json'],
      ['--use-previous-template'],
      ['--role-arn', 'arn:aws:iam::012345678901:role/admin'],
      ['--notification-arns', 'arn:aws:sns:us-east-1:012345678901:t'],
      ['--include-nested-stacks'],
      ['--on-stack-failure', 'DO_NOTHING'],
      ['--parameters', '[]'],
      ['--rollback-configuration', '{}'],
      ['--endpoint-url', 'https://evil.example'],
      ['--profile', 'other'],
      ['--region', 'eu-west-1']
    ]) {
      refused(() => assertPlanning(create(...extra)));
    }
  });

  it('checks the VALUES a plan may send', () => {
    assert.doesNotThrow(() => assertPlanning(create('--capabilities', 'CAPABILITY_NAMED_IAM')));
    assert.doesNotThrow(() => assertPlanning(create().map((v) => (v === 'CREATE' ? 'UPDATE' : v))));
    for (const bad of [
      create('--capabilities', 'CAPABILITY_AUTO_EXPAND'),
      create().map((v) => (v === STACK ? 'someone-elses-stack' : v)),
      create().map((v) => (v === CS ? 'ssd-plan-short' : v)),
      create().map((v) => (v === BODY ? 'file://template.json' : v)),
      create().map((v) => (v === BODY ? 'fileb://template.json' : v)),
      create().map((v) => (v === BODY ? 'https://example.com/t.json' : v)),
      create().map((v) => (v === BODY ? 'Resources: {}' : v)),
      create().map((v) => (v === BODY ? `{"x":"${'a'.repeat(MAX_TEMPLATE_BODY)}"}` : v)),
      create().map((v) => (v === TAGS ? JSON.stringify([{ Key: 'owner', Value: 'x' }]) : v)),
      create().map((v) => (v === TAGS ? '[]' : v)),
      ['cloudformation', 'validate-template', '--template-body', 'file:///etc/passwd'],
      ['cloudformation', 'describe-stack-resources', '--stack-name', 'other-stack']
    ]) {
      refused(() => assertPlanning(bad));
    }
  });

  it('the planning fake enforces the planning allowlist itself, independently of the planner', async () => {
    const suffix = ['--region', 'us-east-1', '--output', 'json', '--no-cli-pager'];
    const f = planFake({ 'cloudformation execute-change-set *': ok({}), 'cloudformation describe-change-set *': ok({}) });
    for (const argv of [FORBIDDEN[0], create('--import-existing-resources'), create().map((v) => (v === 'CREATE' ? 'IMPORT' : v))]) {
      await assert.rejects(f.exec([...argv, ...suffix]), (error) => error instanceof FakeAwsError && /non-allowlisted/.test(error.message), argv[1]);
    }
    await assert.doesNotReject(f.exec(['cloudformation', 'describe-change-set', '--stack-name', STACK, '--change-set-name', CS, ...suffix]));
  });

  it('keeps the wrapper contract: explicit region, fixed suffix, run deadline', async () => {
    refused(() => planningAws({ exec: async () => ok({}) }));
    const seen = [];
    let t = 0;
    const aws = planningAws({ region: 'eu-west-1', exec: async (argv) => (seen.push(argv), ok({})), deadlineMs: 1_000, now: () => t });
    await aws(['sts', 'get-caller-identity']);
    assert.deepEqual(seen[0], ['sts', 'get-caller-identity', '--region', 'eu-west-1', '--output', 'json', '--no-cli-pager']);
    assert.equal(aws.remainingMs(), 1_000);
    t = 1_000;
    await assert.rejects(aws(['sts', 'get-caller-identity']), (error) => error.kind === 'deadline');
  });
});
