import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as sleepTimer } from 'node:timers/promises';
import { fileURLToPath, URL } from 'node:url';

import { lambdaInvokerFromEnv } from './break-glass-lambda-invoke.mjs';

const TERMINAL = new Set(['approved', 'denied', 'expired']);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function requireHttps(value, label) {
  assert(typeof value === 'string' && value !== '', `${label} is not configured`);
  const url = new URL(value);
  assert(url.protocol === 'https:', `${label} must use HTTPS`);
  return url;
}

export async function pollBreakGlass({
  request,
  endpoint,
  sharedSecret,
  timeoutSeconds = 900,
  intervalMilliseconds = 10_000,
  fetchImpl = globalThis.fetch,
  sleep = sleepTimer,
  now = () => Date.now(),
  // Direct IAM (GitHub OIDC) invocation instead of the shared-secret webhook.
  invoke = null
}) {
  assert(typeof request?.requestId === 'string' && request.requestId !== '', 'requestId is required');
  assert(typeof request.gateDigest === 'string' && request.gateDigest !== '', 'gateDigest is required');
  let fetchStatus;
  if (invoke) {
    fetchStatus = async () => {
      const result = await invoke({ action: 'status', requestId: request.requestId });
      assert(result?.ok === true, `break-glass broker rejected status: ${result?.error ?? 'no response'}`);
      return result.body;
    };
  } else {
    const url = requireHttps(endpoint, 'BREAK_GLASS_STATUS_URL');
    assert(typeof sharedSecret === 'string' && sharedSecret !== '', 'shared secret is not configured');
    fetchStatus = async () => {
      url.searchParams.set('requestId', request.requestId);
      const response = await fetchImpl(url, {
        headers: { 'x-break-glass-token': sharedSecret },
        signal: globalThis.AbortSignal.timeout(15_000)
      });
      assert(response.ok, `status endpoint returned HTTP ${response.status}`);
      return response.json();
    };
  }
  const deadline = now() + timeoutSeconds * 1000;

  while (now() < deadline) {
    const status = await fetchStatus();
    assert(status.requestId === request.requestId, 'status response requestId mismatch');
    assert(status.gateDigest === request.gateDigest, 'status response gateDigest mismatch');
    assert(
      ['pending', 'processing', 'approved', 'denied', 'expired'].includes(status.status),
      `unsupported break-glass status ${status.status}`
    );
    if (TERMINAL.has(status.status)) return status;
    await sleep(intervalMilliseconds);
  }

  return {
    requestId: request.requestId,
    gateDigest: request.gateDigest,
    status: 'timeout',
    reason: 'No authorized decision arrived before the CI timeout'
  };
}

// The one human-readable line the poll step logs, per outcome. Terminal states
// and failures stay distinct: only `denied` is a denial. A timeout, an expiry,
// or an exception (transport, broker rejection, malformed or mismatched
// response, unreadable request) is NOT a decision by anyone. The machine-readable
// status is break-glass-result.mjs's, derived from the decision file; this line
// is for the person reading the log.
export function describePollOutcome({ result = null, error = null } = {}) {
  if (error) {
    return { approved: false, line: `BREAK-GLASS: ERROR (${error.message ?? String(error)}) — no verified decision was obtained; the BLOCK stands` };
  }
  const requestId = result?.requestId ?? 'unknown';
  switch (result?.status) {
    case 'approved':
      return { approved: true, line: `BREAK-GLASS: APPROVED by verified approver ${result.approver?.username}` };
    case 'denied':
      return { approved: false, line: `BREAK-GLASS: DENIED (request ${requestId} was denied by an approver) — the BLOCK stands` };
    case 'expired':
      return { approved: false, line: `BREAK-GLASS: EXPIRED (request ${requestId} expired at the broker without a decision) — the BLOCK stands` };
    case 'timeout':
      return { approved: false, line: `BREAK-GLASS: TIMEOUT (no authorized decision for request ${requestId} before the CI timeout) — the BLOCK stands` };
    default:
      return { approved: false, line: `BREAK-GLASS: ERROR (request ${requestId} ended with unrecognized status '${result?.status}') — the BLOCK stands` };
  }
}

// The poll step, with its I/O injectable. Exit code 0 only for `approved`.
export async function runPoll({
  requestPath,
  outputPath,
  env = process.env,
  poll = pollBreakGlass,
  log = console
}) {
  let outcome;
  try {
    const request = JSON.parse(await readFile(requestPath, 'utf8'));
    const result = await poll({
      request,
      endpoint: env.BREAK_GLASS_STATUS_URL,
      sharedSecret: env.BREAK_GLASS_SHARED_SECRET,
      timeoutSeconds: Number(env.BREAK_GLASS_TIMEOUT_SECONDS || 900),
      intervalMilliseconds: Number(env.BREAK_GLASS_POLL_INTERVAL_MS || 10_000),
      invoke: lambdaInvokerFromEnv(env)
    });
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`);
    outcome = describePollOutcome({ result });
  } catch (error) {
    outcome = describePollOutcome({ error });
  }
  if (outcome.approved) {
    log.log(outcome.line);
    return 0;
  }
  log.error(outcome.line);
  return 1;
}

async function main() {
  process.exitCode = await runPoll({
    requestPath: process.argv[2] || 'reports/break-glass-request.json',
    outputPath: process.argv[3] || 'reports/break-glass-decision.json'
  });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) await main();
