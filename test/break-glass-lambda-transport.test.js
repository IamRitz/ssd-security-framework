import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

import { createLambdaInvoker, lambdaInvokerFromEnv } from '../security/scripts/break-glass-lambda-invoke.mjs';
import { notifyBreakGlass } from '../security/scripts/break-glass-notify.mjs';
import { pollBreakGlass } from '../security/scripts/break-glass-poll.mjs';

const gate = {
  verdict: 'BLOCK',
  breakGlass: {
    eligible: true,
    eligibleFindings: [{ id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }],
    ineligibleFindings: []
  }
};
const context = { repository: 'owner/repo', commitSha: 'abc123', pullRequest: '7' };

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
    const result = await notifyBreakGlass({ gate, context, timeoutSeconds: 120, invoke });
    assert.equal(result.requestId, 'r-1');
    const [call] = aws.calls;
    assert.equal(call.command, 'aws');
    assert.deepEqual(call.args.slice(0, 6), ['lambda', 'invoke', '--function-name', 'break-glass-ci', '--region', 'us-east-1']);
    assert.equal(call.event.action, 'notify');
    assert.equal(call.event.payload.timeoutSeconds, 120);
    assert.match(call.event.payload.gateDigest, /^[a-f0-9]{64}$/);
    assert.ok(!call.args.some((arg) => arg.includes('demo.rule')), 'payload must not be passed in argv');
  });

  it('still refuses an ineligible gate before any invocation', async () => {
    const aws = fakeAws(() => ({ ok: true }));
    const invoke = createLambdaInvoker({ functionName: 'break-glass-ci', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    const hardBlock = { ...gate, breakGlass: { ...gate.breakGlass, ineligibleFindings: [{ id: 'secret' }] } };
    await assert.rejects(notifyBreakGlass({ gate: hardBlock, context, invoke }), /hard-block/);
    assert.equal(aws.calls.length, 0);
  });

  it('fails closed on a broker rejection or a function error', async () => {
    const rejected = fakeAws(() => ({ ok: false, statusCode: 400, error: 'payload contains a non-overridable finding' }));
    await assert.rejects(
      notifyBreakGlass({
        gate,
        context,
        invoke: createLambdaInvoker({ functionName: 'f', region: 'us-east-1', execFileImpl: rejected.execFileImpl })
      }),
      /rejected notify: payload contains a non-overridable finding/
    );
    const crashed = fakeAws(() => ({ errorMessage: 'boom' }), { StatusCode: 200, FunctionError: 'Unhandled' });
    await assert.rejects(
      notifyBreakGlass({
        gate,
        context,
        invoke: createLambdaInvoker({ functionName: 'f', region: 'us-east-1', execFileImpl: crashed.execFileImpl })
      }),
      /broker failed: Unhandled/
    );
  });

  it('poll reads terminal status over invoke and times out to a denial', async () => {
    const request = { requestId: 'r-1', gateDigest: 'd'.repeat(64) };
    let status = 'pending';
    const aws = fakeAws((event) => ({
      ok: true,
      statusCode: 200,
      body: { requestId: event.requestId, gateDigest: request.gateDigest, status, approver: status === 'approved' ? { id: 'U-A' } : null }
    }));
    const invoke = createLambdaInvoker({ functionName: 'break-glass-ci', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    let clock = 0;
    const timedOut = await pollBreakGlass({
      request,
      invoke,
      timeoutSeconds: 30,
      intervalMilliseconds: 10_000,
      sleep: async (ms) => {
        clock += ms;
      },
      now: () => clock
    });
    assert.equal(timedOut.status, 'timeout');
    assert.equal(aws.calls[0].event.action, 'status');

    status = 'approved';
    const approved = await pollBreakGlass({ request, invoke, sleep: async () => {} });
    assert.equal(approved.status, 'approved');
  });

  it('poll treats an unknown request as a denial', async () => {
    const aws = fakeAws(() => ({ ok: false, statusCode: 404, error: 'unknown_request' }));
    const invoke = createLambdaInvoker({ functionName: 'f', region: 'us-east-1', execFileImpl: aws.execFileImpl });
    await assert.rejects(
      pollBreakGlass({ request: { requestId: 'r', gateDigest: 'g' }, invoke, sleep: async () => {} }),
      /rejected status: unknown_request/
    );
  });
});
