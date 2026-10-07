// The AWS CLI execution boundary (onboarding/aws/aws-cli.mjs): one wrapper,
// execFile with an argv array and no shell, an explicit read-only allowlist
// checked BEFORE anything runs, bounded output, deterministic timeouts, and
// error text that can never carry a credential.
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';

import * as awsCli from '../onboarding/aws/aws-cli.mjs';
import { AwsCliError, EMPTY_SUCCESS_OPERATIONS, READ_ONLY_OPERATIONS, assertReadOnly, breakGlassReadAws, classifyFailure, execAws, readOnlyAws, redact } from '../onboarding/aws/aws-cli.mjs';
import { accessDenied, awsError, fakeAws, ok } from './support/aws-fake.mjs';

// A real `aws` on PATH that reports exactly what it received.
const SHIM = mkdtempSync(join(tmpdir(), 'ssd-aws-shim-'));
writeFileSync(
  join(SHIM, 'aws'),
  `#!${process.execPath}\n` +
    `if (process.env.SSD_SHIM_SLEEP) { setTimeout(() => {}, 10000); } else {\n` +
    `  process.stdout.write(JSON.stringify({ argv: process.argv.slice(2), pager: process.env.AWS_PAGER, prompt: process.env.AWS_CLI_AUTO_PROMPT, endpoints: process.env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS }));\n` +
    `}\n`
);
chmodSync(join(SHIM, 'aws'), 0o755);
const EMPTY = mkdtempSync(join(tmpdir(), 'ssd-aws-empty-'));
after(() => {
  rmSync(SHIM, { recursive: true, force: true });
  rmSync(EMPTY, { recursive: true, force: true });
});

const refused = (fn) => assert.throws(fn, (error) => error instanceof AwsCliError && error.kind === 'refused');

describe('read-only allowlist', () => {
  it('an allowed read executes with the exact argv plus the wrapper suffix', async () => {
    const f = fakeAws({ 'iam get-role --role-name app-deploy': ok({ Role: {} }) });
    const aws = readOnlyAws({ region: 'eu-west-1', exec: f.exec });
    assert.deepEqual(await aws(['iam', 'get-role', '--role-name', 'app-deploy']), { Role: {} });
    assert.deepEqual(f.calls.map((c) => c.argv), [['iam', 'get-role', '--role-name', 'app-deploy', '--region', 'eu-west-1', '--output', 'json', '--no-cli-pager']]);
  });

  it('every mutating verb family is refused before the executor is reached', async () => {
    const f = fakeAws({});
    const aws = readOnlyAws({ region: 'us-east-1', exec: f.exec });
    const attempts = [
      ['ecr', 'put-image', '--repository-name', 'app'],
      ['ecr', 'put-registry-scanning-configuration'],
      ['ecr', 'put-image-tag-mutability', '--repository-name', 'app'],
      ['ecr', 'set-repository-policy', '--repository-name', 'app'],
      ['ecr', 'batch-delete-image', '--repository-name', 'app'],
      ['ecr', 'delete-repository', '--repository-name', 'app'],
      ['ecr', 'create-repository', '--repository-name', 'app'],
      ['ecr', 'tag-resource', '--resource-arn', 'x'],
      ['ecr', 'untag-resource', '--resource-arn', 'x'],
      ['iam', 'create-role', '--role-name', 'x'],
      ['iam', 'update-assume-role-policy', '--role-name', 'x'],
      ['iam', 'attach-role-policy', '--role-name', 'x'],
      ['iam', 'detach-role-policy', '--role-name', 'x'],
      ['iam', 'put-role-policy', '--role-name', 'x'],
      ['iam', 'delete-role', '--role-name', 'x'],
      ['iam', 'tag-role', '--role-name', 'x'],
      ['iam', 'untag-role', '--role-name', 'x'],
      ['iam', 'add-client-id-to-open-id-connect-provider', '--open-id-connect-provider-arn', 'x'],
      ['iam', 'update-open-id-connect-provider-thumbprint', '--open-id-connect-provider-arn', 'x'],
      ['iam', 'set-default-policy-version', '--policy-arn', 'x'],
      ['ssm', 'send-command', '--instance-ids', 'i-1'],
      ['ssm', 'put-parameter', '--name', 'x'],
      ['cloudformation', 'create-change-set', '--stack-name', 'x'],
      ['cloudformation', 'execute-change-set', '--change-set-name', 'x'],
      ['cloudformation', 'delete-stack', '--stack-name', 'x'],
      ['cloudformation', 'update-stack', '--stack-name', 'x'],
      ['inspector2', 'enable', '--resource-types', 'ECR'],
      ['sts', 'assume-role', '--role-arn', 'x'],
      ['ec2', 'terminate-instances', '--instance-ids', 'i-1']
    ];
    for (const argv of attempts) {
      await assert.rejects(aws(argv), (error) => error.kind === 'refused', argv.join(' '));
    }
    assert.deepEqual(f.calls, [], 'no mutating call reached the executor');
  });

  it('a read that is not listed is refused as firmly as a write (no verb-prefix trust)', () => {
    for (const argv of [
      ['ssm', 'get-parameter', '--name', 'x'],
      ['secretsmanager', 'get-secret-value', '--secret-id', 'x'],
      ['s3', 'ls'],
      ['ecr', 'get-login-password'],
      ['ecr', 'get-authorization-token'],
      ['iam', 'list-users'],
      ['IAM', 'get-role', '--role-name', 'x'],
      ['iam', 'GET-ROLE', '--role-name', 'x'],
      ['iam ', 'get-role', '--role-name', 'x'],
      ['iam', 'get-role ', '--role-name', 'x'],
      ['iam get-role', '--role-name', 'x'],
      ['__proto__', 'constructor'],
      ['iam', 'hasOwnProperty'],
      ['iam', 'toString']
    ]) {
      refused(() => assertReadOnly(argv));
    }
  });

  it('parameters outside the operation\'s list are refused: endpoints, profiles, debug, input files', () => {
    for (const extra of [
      ['--endpoint-url', 'https://evil.example'],
      ['--profile', 'admin'],
      ['--debug'],
      ['--no-verify-ssl'],
      ['--ca-bundle', '/tmp/x'],
      ['--cli-input-json', '{"RoleName":"x"}'],
      ['--cli-input-yaml', 'RoleName: x'],
      ['--generate-cli-skeleton'],
      ['--region', 'eu-west-1'],
      ['--output', 'text'],
      ['--query', 'Role'],
      ['--no-cli-pager'],
      ['--role-name=x'],
      ['--role-name', 'a', '--role-name', 'b'],
      ['--role-name', '--debug'],
      ['--role-name', '-x'],
      ['--role-name', ''],
      ['--role-name'],
      ['stray']
    ]) {
      refused(() => assertReadOnly(['iam', 'get-role', ...(extra[0] === '--role-name' || extra[0].startsWith('--role-name') ? [] : ['--role-name', 'x']), ...extra]));
    }
  });

  it('M1: a value the AWS CLI would resolve (file://, fileb://, http(s)://) is refused before spawning aws', async () => {
    const f = fakeAws({});
    const aws = readOnlyAws({ region: 'us-east-1', exec: f.exec });
    const hostile = ['file:///etc/passwd', 'fileb:///tmp/x', 'https://example.com/x', 'http://127.0.0.1/x', 'FILE:///etc/passwd', 'Https://example.com/x', 'file://relative/path'];
    const targets = [
      (v) => ['iam', 'get-role', '--role-name', v],
      (v) => ['iam', 'get-policy', '--policy-arn', v],
      (v) => ['cloudformation', 'describe-stacks', '--stack-name', v],
      (v) => ['iam', 'get-role-policy', '--role-name', 'app', '--policy-name', v]
    ];
    for (const value of hostile) {
      for (const build of targets) {
        await assert.rejects(aws(build(value)), (error) => error.kind === 'refused' && /file:\/\/ \/ fileb:\/\/ \/ http\(s\):\/\//.test(error.message), build(value).join(' '));
      }
    }
    assert.deepEqual(f.calls, [], 'nothing was spawned');
  });

  it('M1: ordinary values are unaffected — ARNs, repository paths, IDs, JSON, values merely containing a scheme', async () => {
    const values = [
      ['iam', 'get-policy', '--policy-arn', 'arn:aws:iam::012345678901:policy/app-pull'],
      ['iam', 'get-open-id-connect-provider', '--open-id-connect-provider-arn', 'arn:aws:iam::012345678901:oidc-provider/token.actions.githubusercontent.com'],
      ['cloudformation', 'describe-stacks', '--stack-name', 'arn:aws:cloudformation:us-east-1:012345678901:stack/ssd-app/1'],
      ['ecr', 'describe-repositories', '--registry-id', '012345678901', '--repository-names', 'team/app'],
      ['ec2', 'describe-instances', '--instance-ids', 'i-0123456789abcdef0'],
      ['inspector2', 'batch-get-account-status', '--account-ids', '012345678901'],
      ['ssm', 'describe-instance-information', '--filters', '[{"Key":"InstanceIds","Values":["i-0123456789abcdef0"]}]'],
      ['iam', 'get-role', '--role-name', 'role-named-file'],
      ['cloudformation', 'describe-stack-resources', '--physical-resource-id', 'x-https://not-at-start']
    ];
    for (const argv of values) {
      assert.doesNotThrow(() => assertReadOnly(argv), argv.join(' '));
    }
    const f = fakeAws({ 'iam get-role --role-name role-named-file': ok({ Role: {} }) });
    await readOnlyAws({ region: 'eu-west-1', exec: f.exec })(['iam', 'get-role', '--role-name', 'role-named-file']);
    assert.deepEqual(f.calls[0].argv.slice(-5), ['--region', 'eu-west-1', '--output', 'json', '--no-cli-pager'], 'the region value is the wrapper\'s own, never checked as a caller value');
  });

  it('M1: the scheme check applies to values only — command and flag positions are judged by the allowlist', () => {
    // A scheme-shaped service/operation/flag is refused as unlisted, not as a value.
    for (const argv of [['file://iam', 'get-role'], ['iam', 'https://get-role'], ['iam', 'get-role', 'file://--role-name', 'x']]) {
      assert.throws(() => assertReadOnly(argv), (error) => error.kind === 'refused' && !/would resolve/.test(error.message), argv.join(' '));
    }
  });

  it('non-argv input is refused', () => {
    for (const argv of [null, undefined, 'iam get-role --role-name x', ['sts'], [], ['sts', 'get-caller-identity', 3]]) {
      refused(() => assertReadOnly(argv));
    }
  });

  it('the allowlist names no mutating operation, and there is no mutating wrapper', () => {
    const MUTATING = /^(put|create|update|delete|attach|detach|tag|untag|set|execute|send|start|stop|enable|disable|register|deregister|import|modify|run|terminate|reboot|batch-delete|upload|complete|initiate|add|remove|reset|associate|disassociate|cancel|restore|replace)-/;
    for (const table of [READ_ONLY_OPERATIONS, awsCli.BREAK_GLASS_READ_OPERATIONS, awsCli.GOVERNANCE_READ_OPERATIONS]) {
      for (const [service, operations] of Object.entries(table)) {
        for (const operation of Object.keys(operations)) {
          assert.doesNotMatch(operation, MUTATING, `${service} ${operation}`);
        }
      }
    }
    // The only factories are the read-only one (doctor), the planning one
    // (aws plan, test/aws-plan-wrapper.test.js), the per-plan apply one
    // (aws apply, test/aws-apply-wrapper.test.js) and the two Phase 3C
    // break-glass ones (read-only verify and planning,
    // test/aws-break-glass-plan.test.js) and the two Phase 3D governance ones
    // (test/aws-break-glass-governance.test.js); there is no generic mutating wrapper.
    assert.deepEqual(Object.keys(awsCli).sort(), [
      'AwsCliError', 'BREAK_GLASS_PLANNING_OPERATIONS', 'BREAK_GLASS_READ_OPERATIONS', 'DEFAULT_DEADLINE_MS', 'DEFAULT_MAX_BUFFER', 'DEFAULT_TIMEOUT_MS', 'EMPTY_SUCCESS_OPERATIONS', 'GOVERNANCE_PLANNING_OPERATIONS', 'GOVERNANCE_READ_OPERATIONS', 'MAX_TEMPLATE_BODY', 'PLANNING_OPERATIONS', 'READ_ONLY_OPERATIONS',
      'applyAws', 'applyOperations', 'assertApply', 'assertBreakGlassPlanning', 'assertBreakGlassRead', 'assertGovernancePlanning', 'assertGovernanceRead', 'assertPlanning', 'assertReadOnly', 'breakGlassPlanningAws', 'breakGlassReadAws', 'classifyFailure', 'execAws', 'executeArgv', 'governancePlanningAws', 'governanceReadAws', 'planningAws', 'readOnlyAws', 'redact'
    ]);
  });

  it('no wrapper exists without an explicit region', () => {
    refused(() => readOnlyAws({ exec: async () => ok({}) }));
    refused(() => readOnlyAws({ region: '', exec: async () => ok({}) }));
  });
});

describe('execution (real execFile, argv array, no shell)', () => {
  const env = { PATH: `${SHIM}:/usr/bin:/bin` };

  it('shell metacharacters in repository-controlled values stay one argv element', async () => {
    const hostile = 'app;touch /tmp/pwned $(id) `whoami` | cat && echo "x" > /tmp/y \'q\' * ~ \\n';
    const aws = readOnlyAws({ region: 'us-east-1', env });
    const out = await aws(['iam', 'get-role', '--role-name', hostile]);
    assert.deepEqual(out.argv, ['iam', 'get-role', '--role-name', hostile, '--region', 'us-east-1', '--output', 'json', '--no-cli-pager']);
  });

  it('never a pager, an interactive prompt, or an endpoint URL from AWS config', async () => {
    const out = await readOnlyAws({ region: 'us-east-1', env })(['sts', 'get-caller-identity']);
    assert.equal(out.pager, '');
    assert.equal(out.prompt, 'off');
    assert.equal(out.endpoints, 'true');
  });

  it('a call that outlives the timeout fails as `timeout`', async () => {
    const aws = readOnlyAws({ region: 'us-east-1', env: { ...env, SSD_SHIM_SLEEP: '1' }, timeoutMs: 300 });
    await assert.rejects(aws(['sts', 'get-caller-identity']), (error) => error.kind === 'timeout');
  });

  it('no aws executable is `command-unavailable`', async () => {
    const aws = readOnlyAws({ region: 'us-east-1', env: { PATH: EMPTY } });
    await assert.rejects(aws(['sts', 'get-caller-identity']), (error) => error.kind === 'command-unavailable');
  });

  it('output beyond the buffer is `output-too-large`', async () => {
    const result = await execAws(['sts', 'get-caller-identity'], { env, maxBuffer: 8 });
    assert.equal(classifyFailure(result).kind, 'output-too-large');
  });
});

describe('results and errors', () => {
  const run = async (response, argv = ['iam', 'get-role', '--role-name', 'x']) => readOnlyAws({ region: 'us-east-1', exec: async () => response, env: {} })(argv);

  it('stdout that is not one JSON object is `malformed-json`', async () => {
    for (const stdout of ['', 'not json', '[1,2]', 'null', '"x"', '{"a":1}{"b":2}']) {
      await assert.rejects(run({ stdout, stderr: '', exitCode: 0 }), (error) => error.kind === 'malformed-json', stdout);
    }
  });

  it('AWS error codes map to the taxonomy', async () => {
    const cases = [
      [accessDenied('GetRole', 'iam:GetRole'), 'authorization', 'AccessDenied'],
      [awsError('AccessDeniedException', 'ListCoverage'), 'authorization', 'AccessDeniedException'],
      [awsError('UnauthorizedOperation', 'DescribeInstances'), 'authorization', 'UnauthorizedOperation'],
      [awsError('NoSuchEntity', 'GetRole'), 'not-found', 'NoSuchEntity'],
      [awsError('RepositoryNotFoundException', 'DescribeRepositories'), 'not-found', 'RepositoryNotFoundException'],
      [awsError('InvalidInstanceID.NotFound', 'DescribeInstances'), 'not-found', 'InvalidInstanceID.NotFound'],
      [awsError('ValidationError', 'DescribeStackResources', 'Stack for app does not exist'), 'not-found', 'ValidationError'],
      [awsError('ValidationError', 'DescribeStacks', 'something else is wrong'), 'aws-error', 'ValidationError'],
      [awsError('ExpiredToken', 'GetCallerIdentity'), 'authentication', 'ExpiredToken'],
      [awsError('InvalidClientTokenId', 'GetCallerIdentity'), 'authentication', 'InvalidClientTokenId'],
      [awsError('ThrottlingException', 'GetRole'), 'aws-error', 'ThrottlingException']
    ];
    for (const [response, kind, code] of cases) {
      await assert.rejects(run(response), (error) => error.kind === kind && error.code === code, code);
    }
  });

  it('missing credentials are `authentication` and quote nothing from the provider', async () => {
    const stderr = '\nError when retrieving credentials from custom-process: SECRET-PROCESS-OUTPUT wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n';
    await assert.rejects(run({ stdout: '', stderr, exitCode: 253 }), (error) => error.kind === 'authentication' && !/SECRET-PROCESS-OUTPUT|wJalr/.test(error.message));
    await assert.rejects(run({ stdout: '', stderr: '\nUnable to locate credentials. You can configure credentials by running "aws configure".\n', exitCode: 253 }), (error) => error.kind === 'authentication');
    await assert.rejects(run(awsError('ExpiredToken', 'GetCallerIdentity', 'token FwoGZXIvYXdzEBQaDOPAQUE expired')), (error) => !/FwoGZXIv/.test(error.message));
  });

  it('credential values never survive into an error message', () => {
    const env = { AWS_SECRET_ACCESS_KEY: 'super-secret-value-123', AWS_SESSION_TOKEN: 'session-token-value-456', AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE' };
    const message = redact('boom super-secret-value-123 and session-token-value-456 key AKIAIOSFODNN7EXAMPLE aws_secret_access_key=abc ASIAABCDEFGHIJKLMNOP', env);
    for (const leaked of ['super-secret-value-123', 'session-token-value-456', 'AKIAIOSFODNN7EXAMPLE', 'aws_secret_access_key=abc', 'ASIAABCDEFGHIJKLMNOP']) {
      assert.ok(!message.includes(leaked), leaked);
    }
    const failure = classifyFailure({ stderr: 'An error occurred (AccessDenied) when calling the GetRole operation: super-secret-value-123' }, env);
    assert.ok(!failure.message.includes('super-secret-value-123'));
    assert.ok(redact('x'.repeat(2000)).length <= 501, 'bounded');
  });
});

describe('results: an empty successful response', () => {
  // Live AWS (Phase 3C, 2026-10-05): get-function-concurrency on a function with
  // no reservation exits 0 and prints nothing. Only that operation may do so.
  const concurrency = ['lambda', 'get-function-concurrency', '--function-name', 'ssd-break-glass-production-ci'];
  const run = (response, argv) => breakGlassReadAws({ region: 'us-east-1', exec: async () => response, env: {} })(argv);

  it('get-function-concurrency with empty stdout is {} (no reservation configured)', async () => {
    assert.deepEqual(await run({ stdout: '', stderr: '', exitCode: 0 }, concurrency), {});
    assert.deepEqual(await run({ stdout: '\n', stderr: '', exitCode: 0 }, concurrency), {});
  });

  it('an explicit reservation is returned as is', async () => {
    assert.deepEqual(await run({ stdout: '{"ReservedConcurrentExecutions":5}', stderr: '', exitCode: 0 }, concurrency), { ReservedConcurrentExecutions: 5 });
  });

  it('non-empty, non-object output is still malformed', async () => {
    for (const stdout of ['not json', '[]', 'null', '"x"']) {
      await assert.rejects(run({ stdout, stderr: '', exitCode: 0 }, concurrency), (error) => error.kind === 'malformed-json', stdout);
    }
  });

  it('every other read with empty stdout is still malformed', async () => {
    for (const argv of [['lambda', 'get-function-configuration', '--function-name', 'ssd-break-glass-production-ci'], ['lambda', 'get-function-event-invoke-config', '--function-name', 'ssd-break-glass-production-interactions']]) {
      await assert.rejects(run({ stdout: '', stderr: '', exitCode: 0 }, argv), (error) => error.kind === 'malformed-json', argv.join(' '));
    }
    assert.deepEqual([...EMPTY_SUCCESS_OPERATIONS], ['lambda get-function-concurrency']);
  });

  it('a failed call with empty stdout is never read as empty success', async () => {
    await assert.rejects(run({ stdout: '', stderr: '\nAn error occurred (AccessDeniedException) when calling the GetFunctionConcurrency operation: denied\n', exitCode: 254 }, concurrency), (error) => error.kind === 'authorization');
  });
});

describe('L5: overall run deadline', () => {
  const clock = (start = 1_000) => {
    let t = start;
    return { now: () => t, advance: (ms) => (t += ms) };
  };

  it('each call gets min(per-call timeout, remaining budget)', async () => {
    const c = clock();
    const f = fakeAws({ 'sts get-caller-identity': ok({}) });
    const aws = readOnlyAws({ region: 'us-east-1', exec: f.exec, timeoutMs: 60_000, deadlineMs: 100_000, now: c.now });
    await aws(['sts', 'get-caller-identity']);
    c.advance(70_000);
    await aws(['sts', 'get-caller-identity']);
    assert.deepEqual(f.calls.map((call) => call.options.timeoutMs), [60_000, 30_000]);
  });

  it('once the budget is spent, a call fails as `deadline` before anything is spawned', async () => {
    const c = clock();
    const f = fakeAws({ 'sts get-caller-identity': ok({}) });
    const aws = readOnlyAws({ region: 'us-east-1', exec: f.exec, deadlineMs: 5_000, now: c.now });
    c.advance(5_000);
    await assert.rejects(aws(['sts', 'get-caller-identity']), (error) => error.kind === 'deadline' && error.operation === 'sts get-caller-identity');
    assert.deepEqual(f.calls, []);
  });

  it('a call cut short by the remaining budget is `deadline`; one that used its own full timeout is `timeout`', async () => {
    const killed = { stdout: '', stderr: '', exitCode: null, error: Object.assign(new Error('killed'), { killed: true, signal: 'SIGTERM' }) };
    const short = readOnlyAws({ region: 'us-east-1', exec: async () => killed, timeoutMs: 60_000, deadlineMs: 10_000, now: clock().now });
    await assert.rejects(short(['sts', 'get-caller-identity']), (error) => error.kind === 'deadline');
    const full = readOnlyAws({ region: 'us-east-1', exec: async () => killed, timeoutMs: 60_000, deadlineMs: 300_000, now: clock().now });
    await assert.rejects(full(['sts', 'get-caller-identity']), (error) => error.kind === 'timeout');
  });
});

describe('L3: IAM Identity Center (SSO) failures are authentication', () => {
  const run = (response) => readOnlyAws({ region: 'us-east-1', exec: async () => response, env: {} })(['sts', 'get-caller-identity']);

  it('a missing or expired SSO token is `authentication`, with no CLI text', async () => {
    for (const stderr of [
      '\nError loading SSO Token: Token for my-sso-session does not exist\n',
      '\nThe SSO session associated with this profile has expired or is otherwise invalid. To refresh this SSO session run aws sso login with the corresponding profile.\n',
      '\nUnable to refresh SSO token: secret-ish-detail\n'
    ]) {
      await assert.rejects(run({ stdout: '', stderr, exitCode: 255 }), (error) => error.kind === 'authentication' && /aws sso login/.test(error.message) && !/my-sso-session|secret-ish-detail/.test(error.message), stderr);
    }
  });

  it('an error from the SSO credential operations is `authentication`, not `authorization`', async () => {
    await assert.rejects(run(awsError('UnauthorizedException', 'GetRoleCredentials', 'Session token not found or invalid')), (error) => error.kind === 'authentication' && error.code === 'UnauthorizedException');
    await assert.rejects(run(awsError('ForbiddenException', 'GetRoleCredentials', 'No access')), (error) => error.kind === 'authentication');
    // The same code from a resource API is still an authorization answer.
    await assert.rejects(run(awsError('UnauthorizedException', 'ListCoverage', 'no')), (error) => error.kind === 'authorization');
  });
});

describe('L4: credential values in the environment and in token shapes', () => {
  it('the container credential token and JWT-shaped tokens are redacted', () => {
    const env = { AWS_CONTAINER_AUTHORIZATION_TOKEN: 'container-auth-token-value' };
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOmFjbWUvYXBwIn0.c2lnbmF0dXJlLXZhbHVl';
    const message = redact(`failed with container-auth-token-value and ${jwt}`, env);
    assert.ok(!message.includes('container-auth-token-value'));
    assert.ok(!message.includes(jwt));
    assert.ok(!message.includes('eyJzdWIi'));
  });

  it('variables that only name a file are not treated as secrets (and the file is never read)', () => {
    const env = { AWS_WEB_IDENTITY_TOKEN_FILE: '/var/run/secrets/eks.amazonaws.com/serviceaccount/token' };
    assert.equal(redact('see /var/run/secrets/eks.amazonaws.com/serviceaccount/token', env), 'see /var/run/secrets/eks.amazonaws.com/serviceaccount/token');
  });
});
