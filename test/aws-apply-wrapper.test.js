// The apply allowlist (Phase 2C). applyAws() is built for ONE recorded plan:
// its reads take only that plan's exact stack name / stack id / change-set ARN,
// and its single mutation is executeChangeSet() — a fixed argv, at most once.
// Nothing else — no create/update/delete, no other change set, no role ARN,
// no file/URL reference — can be expressed. doctor and plan stay unchanged.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { AwsCliError, PLANNING_OPERATIONS, READ_ONLY_OPERATIONS, applyAws, applyOperations, assertApply, assertPlanning, assertReadOnly, executeArgv } from '../onboarding/aws/aws-cli.mjs';

const refused = (fn) => assert.throws(fn, (error) => error instanceof AwsCliError && error.kind === 'refused');
const STACK = 'ssd-delivery-acme-app-98d9fc12';
const STACK_ID = `arn:aws:cloudformation:us-east-1:012345678901:stack/${STACK}/11111111-2222-3333-4444-555555555555`;
const CS = `ssd-plan-${'a'.repeat(64)}`;
const ARN = `arn:aws:cloudformation:us-east-1:012345678901:changeSet/${CS}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`;
const OTHER_ARN = ARN.replace('a'.repeat(64), 'b'.repeat(64));
const binding = { stackName: STACK, stackId: STACK_ID, changeSetArn: ARN };
const BODY = JSON.stringify({ Resources: { R: { Type: 'AWS::ECR::Repository' } } });

function recorder(response = { stdout: '{}', stderr: '', exitCode: 0 }) {
  const calls = [];
  return { calls, exec: async (argv) => (calls.push(argv), response) };
}

describe('the apply allowlist', () => {
  it('allows exactly the plan\'s reads, with exact values', () => {
    const check = assertApply(binding);
    for (const argv of [
      ['sts', 'get-caller-identity'],
      ['cloudformation', 'describe-stacks', '--stack-name', STACK],
      ['cloudformation', 'describe-stacks', '--stack-name', STACK_ID],
      ['cloudformation', 'describe-change-set', '--stack-name', STACK, '--change-set-name', ARN],
      ['cloudformation', 'get-template', '--stack-name', STACK, '--change-set-name', ARN, '--template-stage', 'Original'],
      ['cloudformation', 'describe-stack-resources', '--stack-name', STACK_ID]
    ]) {
      assert.doesNotThrow(() => check(argv), argv.join(' '));
    }
    assert.deepEqual(Object.keys(applyOperations(binding)).sort(), ['cloudformation', 'sts']);
    assert.deepEqual(Object.keys(applyOperations(binding).cloudformation).sort(), ['describe-change-set', 'describe-stack-resources', 'describe-stacks', 'get-template']);
  });

  it('refuses every other operation, value and flag', () => {
    const check = assertApply(binding);
    for (const argv of [
      ['cloudformation', 'create-change-set', '--stack-name', STACK, '--change-set-name', CS, '--change-set-type', 'UPDATE', '--template-body', BODY],
      ['cloudformation', 'create-stack', '--stack-name', STACK, '--template-body', BODY],
      ['cloudformation', 'update-stack', '--stack-name', STACK, '--template-body', BODY],
      ['cloudformation', 'delete-stack', '--stack-name', STACK],
      ['cloudformation', 'delete-change-set', '--change-set-name', ARN],
      ['cloudformation', 'import-stacks-to-stack-set', '--stack-set-name', STACK],
      ['cloudformation', 'set-stack-policy', '--stack-name', STACK],
      ['cloudformation', 'update-termination-protection', '--stack-name', STACK],
      ['cloudformation', 'continue-update-rollback', '--stack-name', STACK],
      ['cloudformation', 'cancel-update-stack', '--stack-name', STACK],
      ['cloudformation', 'validate-template', '--template-body', BODY],
      ['iam', 'get-role', '--role-name', 'x'],
      // Other stacks / change sets, by name or ARN.
      ['cloudformation', 'describe-stacks', '--stack-name', 'ssd-shared-github-oidc'],
      ['cloudformation', 'describe-change-set', '--stack-name', STACK, '--change-set-name', CS],
      ['cloudformation', 'describe-change-set', '--stack-name', STACK, '--change-set-name', OTHER_ARN],
      ['cloudformation', 'get-template', '--stack-name', 'ssd-shared-github-oidc'],
      ['cloudformation', 'get-template', '--stack-name', STACK, '--change-set-name', ARN, '--template-stage', 'Processed'],
      // execute-change-set: anything but the exact recorded argv.
      ['cloudformation', 'execute-change-set', '--stack-name', STACK, '--change-set-name', OTHER_ARN],
      ['cloudformation', 'execute-change-set', '--stack-name', STACK, '--change-set-name', CS],
      ['cloudformation', 'execute-change-set', '--change-set-name', ARN],
      [...executeArgv(binding), '--role-arn', 'arn:aws:iam::012345678901:role/admin'],
      [...executeArgv(binding), '--client-request-token', 'x'],
      [...executeArgv(binding), '--disable-rollback'],
      [...executeArgv(binding), '--endpoint-url', 'https://evil.example'],
      ['cloudformation', 'describe-stacks', '--stack-name', `file://${STACK}`],
      ['cloudformation', 'describe-stacks', '--stack-name', STACK, '--profile', 'other']
    ]) {
      refused(() => check(argv));
    }
  });

  it('exact execute argv shape', () => {
    assert.deepEqual(executeArgv(binding), ['cloudformation', 'execute-change-set', '--stack-name', STACK, '--change-set-name', ARN]);
    assert.doesNotThrow(() => assertApply(binding)(executeArgv(binding)));
  });

  it('cannot be built without the exact recorded binding', () => {
    for (const bad of [null, {}, { ...binding, stackName: 'other-stack' }, { ...binding, stackId: STACK_ID.replace(STACK, 'ssd-shared-github-oidc') }, { ...binding, changeSetArn: 'file://cs' }, { ...binding, changeSetArn: CS }, { ...binding, stackName: '--endpoint-url' }]) {
      refused(() => applyOperations(bad));
      refused(() => applyAws({ region: 'us-east-1', binding: bad, exec: async () => ({}) }));
    }
  });

  it('doctor and plan still cannot execute a change set; their tables are unchanged by apply', () => {
    refused(() => assertReadOnly(executeArgv(binding)));
    refused(() => assertPlanning(executeArgv(binding)));
    assert.ok(!Object.hasOwn(READ_ONLY_OPERATIONS.cloudformation, 'get-template'));
    assert.ok(!Object.hasOwn(PLANNING_OPERATIONS.cloudformation, 'execute-change-set'));
    assert.ok(!Object.hasOwn(PLANNING_OPERATIONS.cloudformation, 'get-template'));
  });
});

describe('applyAws()', () => {
  it('the generic call path can never execute; executeChangeSet issues the fixed argv once', async () => {
    const r = recorder({ stdout: '', stderr: '', exitCode: 0 });
    const aws = applyAws({ region: 'us-east-1', binding, exec: r.exec });
    await assert.rejects(aws(executeArgv(binding)), (error) => error.kind === 'refused');
    await assert.rejects(aws(['cloudformation', 'create-change-set', '--stack-name', STACK]), (error) => error.kind === 'refused');
    assert.equal(r.calls.length, 0, 'nothing reached the executor');
    assert.deepEqual(await aws.executeChangeSet(), {}, 'empty CLI output is accepted for execute only');
    await assert.rejects(aws.executeChangeSet(), (error) => error.kind === 'refused' && /at most once/.test(error.message));
    assert.equal(r.calls.length, 1);
    assert.deepEqual(r.calls[0], [...executeArgv(binding), '--region', 'us-east-1', '--output', 'json', '--no-cli-pager']);
  });

  it('a read still requires a JSON object; no run() escape hatch is exposed', async () => {
    const r = recorder({ stdout: '', stderr: '', exitCode: 0 });
    const aws = applyAws({ region: 'us-east-1', binding, exec: r.exec });
    await assert.rejects(aws(['sts', 'get-caller-identity']), (error) => error.kind === 'malformed-json');
    assert.equal(aws.run, undefined);
    refused(() => applyAws({ binding, exec: r.exec }));
  });
});
