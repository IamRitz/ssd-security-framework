// tools/break-glass-live.mjs, the Phase 3E live driver
// (docs/break-glass-validation.md § The live driver). Its scenarios run here
// against the REAL interaction handler and broker (test/support/broker-env.mjs),
// with the driver's fetch routed into the handler, and its AWS target checks
// against recorded answers. Nothing here reaches AWS or Slack.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';

import {
  LiveRefused,
  LiveUsageError,
  STALE_SECONDS,
  main,
  normalizeFunctionUrl,
  parseArgs,
  readSigningSecret,
  resolveTarget,
  runScenario,
  signInteraction
} from '../tools/break-glass-live.mjs';
import { NOW_MS, SIGNING_SECRET, brokerEnv, fileRequest } from './support/broker-env.mjs';
import { SLACK_A, SLACK_B, approversById } from './support/fake-approvers.mjs';
import { REPO_A } from './support/jwt-fixtures.mjs';

const ACCOUNT = '111122223333';
const FUNCTION_ARN = `arn:aws:lambda:us-east-1:111122223333:function:ssd-break-glass-synthetic-interactions`;
const fnConfig = (variables) => ({ FunctionName: 'ssd-break-glass-synthetic-interactions', FunctionArn: FUNCTION_ARN, Role: 'arn:aws:iam::111122223333:role/ssd-break-glass-synthetic-interactions-execution', Environment: { Variables: variables } });
const URL = 'https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.us-east-1.on.aws/';
const OPERATOR = { aws: { accountId: ACCOUNT, region: 'us-east-1' } };
const REQUEST = '0b3e8f6c-1d2a-4c5b-9e7f-0123456789ab';
const base = ['--environment', 'synthetic', '--operator-config', 'ops.yml', '--function-url', URL, '--request-id', REQUEST];

const stdinOf = (text, { isTTY = false } = {}) => Object.assign(Readable.from([Buffer.from(text)]), { isTTY });

// Recorded AWS answers for the three reads the driver makes. `over` replaces one.
function fakeAws(over = {}) {
  const calls = [];
  const answers = {
    'sts get-caller-identity': { UserId: 'AIDAEXAMPLE', Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:user/operator` },
    'lambda get-function-configuration': fnConfig({ BREAK_GLASS_ENVIRONMENT: 'synthetic' }),
    'lambda get-function-url-config': { FunctionUrl: URL, AuthType: 'NONE', FunctionArn: FUNCTION_ARN },
    ...over
  };
  const exec = async (argv) => {
    calls.push(argv);
    const answer = answers[`${argv[0]} ${argv[1]}`];
    if (answer instanceof Error) return { exitCode: 254, stdout: '', stderr: answer.message };
    return answer === undefined ? { exitCode: 254, stdout: '', stderr: 'unexpected call' } : { exitCode: 0, stdout: JSON.stringify(answer), stderr: '' };
  };
  return { exec, calls };
}

// The driver's fetch, delivered to the real Function URL handler.
function fetchInto(env) {
  const sent = [];
  const fetchImpl = async (url, init) => {
    sent.push({ url, init });
    const response = await env.interactions({ requestContext: { http: { method: init.method } }, headers: init.headers, body: init.body, isBase64Encoded: false });
    return { status: response.statusCode, headers: { get: (name) => response.headers?.[name.toLowerCase()] ?? null } };
  };
  return { fetchImpl, sent };
}

async function filed() {
  const env = brokerEnv({ approvers: approversById({ [REPO_A.repositoryId]: [SLACK_A, SLACK_B] }) });
  const requestId = await fileRequest(env);
  return { env, requestId, status: () => JSON.parse(env.requests()[0].doc.S).status };
}
const nowSeconds = () => Math.floor(NOW_MS / 1000);
const options = (scenario, requestId, extra = {}) => ({ scenario, environment: 'synthetic', functionUrl: URL, requestId, user: SLACK_A, action: 'approve', ...extra });

describe('break-glass-live: arguments', () => {
  it('parses a synthetic click and normalizes the Function URL', () => {
    const o = parseArgs(['click', ...base.slice(0, 5), URL.slice(0, -1), ...base.slice(6), '--user', SLACK_A]);
    assert.deepEqual([o.scenario, o.environment, o.functionUrl, o.requestId, o.user, o.action], ['click', 'synthetic', URL, REQUEST, SLACK_A, 'approve']);
  });

  for (const environment of ['production', 'Synthetic', '']) {
    it(`refuses --environment '${environment}': synthetic only`, () => {
      const argv = ['click', ...base, '--user', SLACK_A];
      argv[argv.indexOf('synthetic')] = environment;
      assert.throws(() => parseArgs(argv), LiveUsageError);
    });
  }
  it('refuses a missing --environment', () => {
    assert.throws(() => parseArgs(['click', ...base.slice(2), '--user', SLACK_A]), /--environment must be 'synthetic'/);
  });

  for (const flag of ['--signing-secret', '--secret', '--slack-token', '--password']) {
    it(`refuses ${flag}: the secret is never an argument`, () => {
      assert.throws(() => parseArgs(['click', ...base, '--user', SLACK_A, flag, 's3cr3t']), /read from stdin only/);
    });
  }

  for (const [name, argv, pattern] of [
    ['an unknown scenario', ['approve-all', ...base], /scenario must be one of/],
    ['a URL that is not a Function URL', ['click', ...base.slice(0, 5), 'https://hooks.slack.com/x', ...base.slice(6), '--user', SLACK_A], /Function URL/],
    ['an http Function URL', ['click', ...base.slice(0, 5), URL.replace('https', 'http'), ...base.slice(6), '--user', SLACK_A], /Function URL/],
    ['a request id that is not a UUID', ['click', ...base.slice(0, 7), 'r-1', '--user', SLACK_A], /request id/],
    ['a user that is not a Slack id', ['click', ...base, '--user', 'alice'], /Slack user id/],
    ['an unknown action', ['click', ...base, '--user', SLACK_A, '--action', 'override'], /approve or deny/],
    ['a race with one user', ['race', ...base, '--users', SLACK_A], /two different approvers/],
    ['a race with the same user twice', ['race', ...base, '--users', `${SLACK_A},${SLACK_A}`], /two different approvers/],
    ['a repeated flag', ['click', ...base, '--user', SLACK_A, '--user', SLACK_B], /given twice/],
    ['an unknown flag', ['click', ...base, '--user', SLACK_A, '--yes', 'x'], /unknown argument/]
  ]) {
    it(`refuses ${name}`, () => assert.throws(() => parseArgs(argv), pattern));
  }
});

describe('break-glass-live: the signing secret comes from a piped stdin only', () => {
  it('reads it and drops one trailing newline', async () => {
    assert.equal(await readSigningSecret(stdinOf('abc123\n')), 'abc123');
  });
  for (const [name, stdin] of [
    ['a terminal', stdinOf('abc', { isTTY: true })],
    ['empty stdin', stdinOf('')],
    ['whitespace inside', stdinOf('abc def\n')],
    ['an oversized input', stdinOf('x'.repeat(300))]
  ]) {
    it(`refuses ${name}`, async () => assert.rejects(readSigningSecret(stdin), LiveUsageError));
  }
});

describe('break-glass-live: AWS must prove the target is the synthetic interaction function', () => {
  it('resolves the synthetic Function URL with read-only calls only', async () => {
    const aws = fakeAws();
    const target = await resolveTarget({ operator: OPERATOR, functionUrl: URL, exec: aws.exec });
    assert.deepEqual(target, { account: ACCOUNT, region: 'us-east-1', functionName: 'ssd-break-glass-synthetic-interactions', functionUrl: URL });
    assert.deepEqual(aws.calls.map((c) => `${c[0]} ${c[1]}`), ['sts get-caller-identity', 'lambda get-function-configuration', 'lambda get-function-url-config']);
    for (const call of aws.calls.slice(1)) assert.equal(call[call.indexOf('--function-name') + 1], 'ssd-break-glass-synthetic-interactions', 'only the synthetic function is read');
  });

  for (const [name, over, pattern] of [
    ['another account', { 'sts get-caller-identity': { UserId: 'X', Account: '444455556666', Arn: 'arn:aws:iam::444455556666:user/op' } }, /444455556666/],
    ['the root user', { 'sts get-caller-identity': { UserId: 'X', Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root` } }, /root/],
    ['a function that serves production', { 'lambda get-function-configuration': fnConfig({ BREAK_GLASS_ENVIRONMENT: 'production' }) }, /BREAK_GLASS_ENVIRONMENT=synthetic/],
    ['a function with no environment', { 'lambda get-function-configuration': fnConfig({}) }, /BREAK_GLASS_ENVIRONMENT=synthetic/],
    ['a different Function URL', { 'lambda get-function-url-config': { FunctionUrl: 'https://zzzz.lambda-url.us-east-1.on.aws/', AuthType: 'NONE', FunctionArn: FUNCTION_ARN } }, /not the Function URL/],
    ['an unreadable Function URL', { 'lambda get-function-url-config': new Error('An error occurred (AccessDeniedException) when calling the GetFunctionUrlConfig operation: denied') }, /could not be read/],
    ['an absent function', { 'lambda get-function-configuration': new Error('An error occurred (ResourceNotFoundException) when calling the GetFunctionConfiguration operation: Function not found') }, /could not be read/]
  ]) {
    it(`refuses ${name}`, async () => {
      await assert.rejects(resolveTarget({ operator: OPERATOR, functionUrl: URL, exec: fakeAws(over).exec }), (error) => {
        assert.ok(error instanceof LiveRefused || error.name !== 'LiveUsageError', String(error));
        assert.match(error.message, pattern);
        return true;
      });
    });
  }
});

describe('break-glass-live: scenarios against the real interaction handler', () => {
  it('click: one signed click decides the request', async () => {
    const { env, requestId, status } = await filed();
    const run = await runScenario(options('click', requestId), { secret: SIGNING_SECRET, fetchImpl: fetchInto(env).fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'PASS', run.reasons.join('; '));
    assert.deepEqual(run.results.map((r) => [r.httpStatus, r.outcome]), [[200, 'claimed']]);
    assert.equal(status(), 'approved');
  });

  it('race: approve and deny at once -> exactly one claimed, one duplicate', async () => {
    const { env, requestId, status } = await filed();
    const run = await runScenario(options('race', requestId, { users: [SLACK_A, SLACK_B] }), { secret: SIGNING_SECRET, fetchImpl: fetchInto(env).fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'PASS', run.reasons.join('; '));
    assert.deepEqual(run.results.map((r) => r.outcome).sort(), ['claimed', 'duplicate']);
    const winner = run.results.find((r) => r.outcome === 'claimed');
    assert.equal(status(), winner.action === 'approve' ? 'approved' : 'denied');
  });

  it('race: two claims would be a FAIL', async () => {
    const fetchImpl = async () => ({ status: 200, headers: { get: () => 'claimed' } });
    const run = await runScenario(options('race', REQUEST, { users: [SLACK_A, SLACK_B] }), { secret: SIGNING_SECRET, fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'FAIL');
    assert.match(run.reasons[0], /exactly one click may decide/);
  });

  it('repeat: a click on a decided request is a duplicate and changes nothing', async () => {
    const { env, requestId, status } = await filed();
    const { fetchImpl } = fetchInto(env);
    await runScenario(options('click', requestId, { action: 'deny' }), { secret: SIGNING_SECRET, fetchImpl, nowSeconds });
    const run = await runScenario(options('repeat', requestId, { user: SLACK_B, action: 'approve' }), { secret: SIGNING_SECRET, fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'PASS', run.reasons.join('; '));
    assert.equal(status(), 'denied');
  });

  it('repeat: a click that still decides is a FAIL', async () => {
    const { env, requestId } = await filed();
    const run = await runScenario(options('repeat', requestId), { secret: SIGNING_SECRET, fetchImpl: fetchInto(env).fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'FAIL');
  });

  it('signature: four forgeries are 401 with no state change, then a valid click still decides', async () => {
    const { env, requestId, status } = await filed();
    const pending = [];
    const { fetchImpl: deliver } = fetchInto(env);
    const fetchImpl = async (url, init) => {
      pending.push(status());
      return deliver(url, init);
    };
    const run = await runScenario(options('signature', requestId), { secret: SIGNING_SECRET, fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'PASS', run.reasons.join('; '));
    assert.deepEqual(run.results.map((r) => [r.label, r.httpStatus, r.outcome]), [
      ['wrong-secret', 401, null],
      ['stale-timestamp', 401, null],
      ['tampered-body', 401, null],
      ['unsigned', 401, null],
      ['valid-after-forgeries', 200, 'claimed']
    ]);
    assert.deepEqual(pending, ['pending', 'pending', 'pending', 'pending', 'pending'], 'no forgery changed the request');
    assert.equal(status(), 'approved');
  });

  it('signature: a forgery that is accepted is a FAIL', async () => {
    const fetchImpl = async () => ({ status: 200, headers: { get: () => 'claimed' } });
    const run = await runScenario(options('signature', REQUEST), { secret: SIGNING_SECRET, fetchImpl, nowSeconds });
    assert.equal(run.verdict, 'FAIL');
    assert.equal(run.reasons.length, 4);
  });

  it('the stale forgery is older than Slack\'s five-minute window, and correctly signed otherwise', () => {
    assert.ok(STALE_SECONDS > 300);
    const signed = signInteraction({ secret: 's', requestId: REQUEST, userId: SLACK_A, action: 'approve', timestamp: 1000 });
    assert.equal(signed.headers['x-slack-request-timestamp'], '1000');
    assert.match(signed.headers['x-slack-signature'], /^v0=[0-9a-f]{64}$/);
    assert.ok(!signed.body.includes('response_url'), 'no reply is sent anywhere');
  });
});

describe('break-glass-live: main', () => {
  const SECRET = SIGNING_SECRET;

  it('PASS: evidence names the target and the outcomes, never the secret', async () => {
    const { env, requestId } = await filed();
    const { fetchImpl, sent } = fetchInto(env);
    const { evidence, exitCode } = await main(['click', ...base.slice(0, 7), requestId, '--user', SLACK_A], {
      stdin: stdinOf(`${SECRET}\n`), exec: fakeAws().exec, fetchImpl, now: () => new Date(NOW_MS), load: async () => OPERATOR
    });
    assert.equal(exitCode, 0, JSON.stringify(evidence));
    assert.deepEqual([evidence.verdict, evidence.environment, evidence.functionName, evidence.account], ['PASS', 'synthetic', 'ssd-break-glass-synthetic-interactions', ACCOUNT]);
    assert.equal(sent.length, 1);
    assert.ok(!JSON.stringify(evidence).includes(SECRET), 'the secret is never in the evidence');
    assert.ok(sent.every(({ init }) => !JSON.stringify(init.headers).includes(SECRET) && !init.body.includes(SECRET)), 'nor on the wire');
  });

  it('REFUSED before anything is sent when AWS does not prove the target', async () => {
    let fetched = 0;
    const { evidence, exitCode } = await main(['click', ...base, '--user', SLACK_A], {
      stdin: stdinOf(SECRET), exec: fakeAws({ 'lambda get-function-url-config': { FunctionUrl: 'https://other.lambda-url.us-east-1.on.aws/', AuthType: 'NONE', FunctionArn: FUNCTION_ARN } }).exec,
      fetchImpl: async () => { fetched += 1; }, load: async () => OPERATOR
    });
    assert.equal(exitCode, 1);
    assert.equal(evidence.verdict, 'REFUSED');
    assert.equal(fetched, 0, 'no interaction is sent to an unproven target');
    assert.ok(!JSON.stringify(evidence).includes(SECRET));
  });

  it('REFUSED without AWS when stdin is a terminal', async () => {
    const aws = fakeAws();
    const { evidence, exitCode } = await main(['click', ...base, '--user', SLACK_A], { stdin: stdinOf(SECRET, { isTTY: true }), exec: aws.exec, load: async () => OPERATOR });
    assert.deepEqual([exitCode, evidence.verdict, aws.calls.length], [1, 'REFUSED', 0]);
  });

  it('USAGE (exit 2) for production, before reading stdin or AWS', async () => {
    const aws = fakeAws();
    const argv = ['click', ...base, '--user', SLACK_A];
    argv[argv.indexOf('synthetic')] = 'production';
    const { evidence, exitCode } = await main(argv, { stdin: stdinOf(SECRET), exec: aws.exec, load: async () => OPERATOR });
    assert.deepEqual([exitCode, evidence.verdict, aws.calls.length], [2, 'USAGE', 0]);
  });

  it('normalizes a URL without its trailing slash', () => {
    assert.equal(normalizeFunctionUrl(URL.slice(0, -1)), URL);
    assert.equal(normalizeFunctionUrl(URL), URL);
  });
});
