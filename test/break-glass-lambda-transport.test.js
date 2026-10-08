import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { URL } from 'node:url';

import { createLambdaInvoker, lambdaInvokerFromEnv } from '../security/scripts/break-glass-lambda-invoke.mjs';
import { notifyBreakGlass } from '../security/scripts/break-glass-notify.mjs';
import { mintBreakGlassIdentityToken } from '../security/scripts/break-glass-oidc-token.mjs';
import { pollBreakGlass } from '../security/scripts/break-glass-poll.mjs';

const gate = {
  verdict: 'BLOCK',
  // The gate always records whether a synthetic fixture was injected; the
  // Lambda request's environment is derived from it (Phase 3E).
  synthetic: { active: false, fixture: null },
  breakGlass: {
    eligible: true,
    eligibleFindings: [{ id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }],
    ineligibleFindings: []
  }
};
const context = { repository: 'owner/repo', commitSha: 'abc123', pullRequest: '7' };
// Stands in for the `ssd-break-glass` GitHub OIDC token (break-glass-oidc-token.mjs).
const IDENTITY_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJpZGVudGl0eSI6InRlc3QifQ.c2lnbmF0dXJl';
let minted = 0;
const mintIdentityToken = async () => {
  minted += 1;
  return IDENTITY_TOKEN;
};

// Stands in for the AWS CLI: records argv, reads the payload file, writes a response.
function fakeAws(respond, meta = { StatusCode: 200 }) {
  const calls = [];
  const execFileImpl = async (command, args) => {
    const payloadPath = args[args.indexOf('--payload') + 1].replace('fileb://', '');
    const event = JSON.parse(await readFile(payloadPath, 'utf8'));
    calls.push({ command, args, event });
    await writeFile(args.at(-1), JSON.stringify(respond(event)));
    return { stdout: JSON.stringify(meta) };
  };
  return { calls, execFileImpl };
}

describe('break-glass Lambda transport (OIDC direct invoke)', () => {
  it('is off unless explicitly selected, so the n8n HTTP path is untouched', () => {
    assert.equal(lambdaInvokerFromEnv({}), null);
    assert.equal(lambdaInvokerFromEnv({ BREAK_GLASS_TRANSPORT: 'http' }), null);
    assert.throws(() => lambdaInvokerFromEnv({ BREAK_GLASS_TRANSPORT: 'lambda', AWS_REGION: 'us-east-1' }), /FUNCTION_NAME/);
    assert.throws(
      () => lambdaInvokerFromEnv({ BREAK_GLASS_TRANSPORT: 'lambda', BREAK_GLASS_FUNCTION_NAME: 'break-glass-ci' }),
      /region/
    );
  });

  it('notify needs no endpoint and no shared secret, and sends the payload via a file', async () => {
    const aws = fakeAws(() => ({
      ok: true,
      statusCode: 201,
      body: { requestId: 'r-1', status: 'pending', createdAt: 'c', expiresAt: 'e' }
    }));
    const invoke = createLambdaInvoker({ functionName: 'break-glass-ci', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    const result = await notifyBreakGlass({ gate, context, timeoutSeconds: 120, invoke, mintIdentityToken });
    assert.equal(result.requestId, 'r-1');
    const [call] = aws.calls;
    assert.equal(call.command, 'aws');
    assert.deepEqual(call.args.slice(0, 6), ['lambda', 'invoke', '--function-name', 'break-glass-ci', '--region', 'us-east-1']);
    assert.equal(call.event.action, 'notify');
    assert.equal(call.event.payload.timeoutSeconds, 120);
    assert.match(call.event.payload.gateDigest, /^[a-f0-9]{64}$/);
    assert.ok(!call.args.some((arg) => arg.includes('demo.rule')), 'payload must not be passed in argv');
    // The identity token travels beside the payload — never in argv, never inside it.
    assert.equal(call.event.identityToken, IDENTITY_TOKEN);
    assert.ok(!call.args.some((arg) => arg.includes(IDENTITY_TOKEN)), 'the identity token must not be passed in argv');
    assert.ok(!JSON.stringify(call.event.payload).includes(IDENTITY_TOKEN), 'the token is not part of the payload');
    assert.ok(!JSON.stringify(result).includes(IDENTITY_TOKEN), 'the recorded request never holds the token');
  });

  it('the Lambda transport refuses to notify or poll without an identity token minter', async () => {
    const aws = fakeAws(() => ({ ok: true }));
    const invoke = createLambdaInvoker({ functionName: 'break-glass-ci', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    await assert.rejects(notifyBreakGlass({ gate, context, invoke }), /identity token minter/);
    await assert.rejects(
      pollBreakGlass({ request: { requestId: 'r', gateDigest: 'g' }, invoke, sleep: async () => {} }),
      /identity token minter/
    );
    assert.equal(aws.calls.length, 0);
  });

  it('still refuses an ineligible gate before any invocation', async () => {
    const aws = fakeAws(() => ({ ok: true }));
    const invoke = createLambdaInvoker({ functionName: 'break-glass-ci', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    const hardBlock = { ...gate, breakGlass: { ...gate.breakGlass, ineligibleFindings: [{ id: 'secret' }] } };
    await assert.rejects(notifyBreakGlass({ gate: hardBlock, context, invoke, mintIdentityToken }), /hard-block/);
    assert.equal(aws.calls.length, 0);
  });

  it('fails closed on a broker rejection or a function error', async () => {
    const rejected = fakeAws(() => ({ ok: false, statusCode: 400, error: 'payload contains a non-overridable finding' }));
    await assert.rejects(
      notifyBreakGlass({
        gate,
        context,
        invoke: createLambdaInvoker({ functionName: 'f', region: 'us-east-1', execFileImpl: rejected.execFileImpl }),
        mintIdentityToken
      }),
      /rejected notify: payload contains a non-overridable finding/
    );
    const crashed = fakeAws(() => ({ errorMessage: 'boom' }), { StatusCode: 200, FunctionError: 'Unhandled' });
    await assert.rejects(
      notifyBreakGlass({
        gate,
        context,
        invoke: createLambdaInvoker({ functionName: 'f', region: 'us-east-1', execFileImpl: crashed.execFileImpl }),
        mintIdentityToken
      }),
      /broker failed: Unhandled/
    );
  });

  it('poll reads terminal status over invoke and times out (a timeout, not a denial)', async () => {
    const request = { requestId: 'r-1', gateDigest: 'd'.repeat(64) };
    let status = 'pending';
    const aws = fakeAws((event) => ({
      ok: true,
      statusCode: 200,
      body: { requestId: event.requestId, gateDigest: request.gateDigest, status, approver: status === 'approved' ? { id: 'U-A' } : null }
    }));
    const invoke = createLambdaInvoker({ functionName: 'break-glass-ci', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    let clock = 0;
    minted = 0;
    const timedOut = await pollBreakGlass({
      request,
      invoke,
      mintIdentityToken,
      timeoutSeconds: 30,
      intervalMilliseconds: 10_000,
      sleep: async (ms) => {
        clock += ms;
      },
      now: () => clock
    });
    assert.equal(timedOut.status, 'timeout');
    assert.equal(aws.calls[0].event.action, 'status');
    // Every status call carries its OWN freshly minted token.
    assert.equal(minted, aws.calls.length);
    assert.ok(aws.calls.every((call) => call.event.identityToken === IDENTITY_TOKEN));

    status = 'approved';
    const approved = await pollBreakGlass({ request, invoke, mintIdentityToken, sleep: async () => {} });
    assert.equal(approved.status, 'approved');
  });

  it('poll treats an unknown request as an error', async () => {
    const aws = fakeAws(() => ({ ok: false, statusCode: 404, error: 'unknown_request' }));
    const invoke = createLambdaInvoker({ functionName: 'f', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    await assert.rejects(
      pollBreakGlass({ request: { requestId: 'r', gateDigest: 'g' }, invoke, mintIdentityToken, sleep: async () => {} }),
      /rejected status: unknown_request/
    );
  });
});

describe('break-glass identity token minting (runner OIDC, audience ssd-break-glass)', () => {
  const ENV = {
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://pipelines.actions.example/idtoken/abc?api-version=2.0',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-request-token'
  };
  const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ.c2ln';

  it('requests the ssd-break-glass audience with the runner request token, and masks before returning', async () => {
    const seen = [];
    const masked = [];
    const value = await mintBreakGlassIdentityToken({
      env: ENV,
      fetchImpl: async (url, init) => {
        seen.push({ url: new URL(String(url)), init });
        assert.equal(masked.length, 0, 'nothing is masked before the token exists');
        return { ok: true, json: async () => ({ value: JWT }) };
      },
      mask: (token) => masked.push(token)
    });
    assert.equal(value, JWT);
    assert.deepEqual(masked, [JWT]);
    assert.equal(seen[0].url.searchParams.get('audience'), 'ssd-break-glass');
    assert.equal(seen[0].url.searchParams.get('api-version'), '2.0');
    assert.equal(seen[0].init.headers.authorization, 'bearer runner-request-token');
  });

  for (const [name, options, pattern] of [
    ['no id-token permission', { env: {} }, /needs `id-token: write`/],
    ['a non-HTTPS request URL', { env: { ...ENV, ACTIONS_ID_TOKEN_REQUEST_URL: 'http://x.example/t' } }, /must use HTTPS/],
    ['an HTTP error', { env: ENV, fetchImpl: async () => ({ ok: false, status: 403 }) }, /returned HTTP 403/],
    ['a transport error', { env: ENV, fetchImpl: async () => { throw new Error(`boom ${ENV.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`); } }, /request failed \(Error\)/],
    ['a response without a token', { env: ENV, fetchImpl: async () => ({ ok: true, json: async () => ({ value: 'not-a-jwt' }) }) }, /carries no token/]
  ]) {
    it(`fails closed on ${name}, naming neither token`, async () => {
      const masked = [];
      await assert.rejects(mintBreakGlassIdentityToken({ mask: (t) => masked.push(t), ...options }), (error) => {
        assert.match(error.message, pattern);
        assert.doesNotMatch(error.message, /runner-request-token|not-a-jwt/);
        return true;
      });
      assert.deepEqual(masked, []);
    });
  }
});
