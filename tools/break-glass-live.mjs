#!/usr/bin/env node
// The Phase 3E live driver (docs/break-glass-validation.md § The live driver):
// sends Slack-signed interactions to the SYNTHETIC interaction Function URL and
// prints one JSON evidence document.
//
//   node tools/break-glass-live.mjs <click|race|repeat|signature> \
//     --environment synthetic --operator-config <file> --function-url <url> \
//     --request-id <uuid> [--user <U…>] [--action approve|deny] \
//     [--users <U…>,<U…>] [--region <r>]  < signing-secret
//
// Never production, never a guess:
//   - --environment must be `synthetic`; there is no other value;
//   - before anything is sent, AWS (the read-only break-glass allowlist) must
//     show the caller is the configured account, that
//     ssd-break-glass-synthetic-interactions carries
//     BREAK_GLASS_ENVIRONMENT=synthetic, and that its Function URL is exactly
//     --function-url;
//   - the signing secret is read from stdin only (piped, never a terminal),
//     never from argv, a file name or the environment, and is never printed,
//     logged or written. Evidence carries outcomes, never the secret.
//
// It decides nothing itself: every outcome is the broker's own
// (x-break-glass-outcome), and the verdict compares it with the scenario's
// expectation. Exit 0 PASS, 1 FAIL or refused, 2 usage.
import { Buffer } from 'node:buffer';
import { createHmac, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SLACK_USER_ID } from '../broker/authorize/approvers.mjs';
import { breakGlassReadAws } from '../onboarding/aws/aws-cli.mjs';
import { discoverFunction, discoverFunctionUrl } from '../onboarding/aws/break-glass/discover.mjs';
import { breakGlassNames } from '../onboarding/aws/break-glass/names.mjs';
import { describeError } from '../onboarding/aws/discover/result.mjs';
import { accountCheck, callerIdentity, principalCheck, resolveRegion } from '../onboarding/aws/identity.mjs';
import { loadOperatorConfig } from '../onboarding/lib/operator-file.mjs';

export const ENVIRONMENT = 'synthetic';
export const SCENARIOS = Object.freeze(['click', 'race', 'repeat', 'signature']);
const ACTIONS = ['approve', 'deny'];
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FUNCTION_URL = /^https:\/\/[a-z0-9]{1,64}\.lambda-url\.[a-z0-9-]{1,32}\.on\.aws\/$/;
// Slack refuses a timestamp older than five minutes; a forgery is ten minutes old.
export const STALE_SECONDS = 600;
const MAX_SECRET_BYTES = 256;
const unread = (result) => (result.state === 'absent' ? 'it does not exist' : describeError(result));

export class LiveUsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LiveUsageError';
  }
}

export class LiveRefused extends Error {
  constructor(message) {
    super(message);
    this.name = 'LiveRefused';
  }
}

// A Function URL as Lambda prints it: https, one trailing slash.
export const normalizeFunctionUrl = (url) => (typeof url === 'string' && !url.endsWith('/') ? `${url}/` : url);

const VALUE_FLAGS = new Set(['--environment', '--operator-config', '--function-url', '--request-id', '--user', '--action', '--users', '--region']);

// argv (after the script) -> options. The signing secret has no flag.
export function parseArgs(argv) {
  const [scenario, ...rest] = argv;
  if (!SCENARIOS.includes(scenario)) throw new LiveUsageError(`scenario must be one of ${SCENARIOS.join(', ')} (got '${scenario ?? ''}')`);
  const values = {};
  for (let i = 0; i < rest.length; i += 1) {
    const flag = rest[i];
    if (/secret|token|password/i.test(flag)) throw new LiveUsageError(`${flag}: the signing secret is read from stdin only, never from an argument`);
    if (!VALUE_FLAGS.has(flag)) throw new LiveUsageError(`unknown argument ${flag}`);
    const value = rest[i + 1];
    if (value === undefined || value.startsWith('--')) throw new LiveUsageError(`${flag} requires a value`);
    if (Object.hasOwn(values, flag)) throw new LiveUsageError(`${flag} given twice`);
    values[flag] = value;
    i += 1;
  }
  if (values['--environment'] !== ENVIRONMENT) {
    throw new LiveUsageError(`--environment must be '${ENVIRONMENT}': this driver never targets any other environment (got '${values['--environment'] ?? ''}')`);
  }
  for (const flag of ['--operator-config', '--function-url', '--request-id']) {
    if (!values[flag]) throw new LiveUsageError(`${flag} is required`);
  }
  const functionUrl = normalizeFunctionUrl(values['--function-url']);
  if (!FUNCTION_URL.test(functionUrl)) throw new LiveUsageError('--function-url must be a Lambda Function URL (https://<id>.lambda-url.<region>.on.aws/)');
  if (!REQUEST_ID.test(values['--request-id'])) throw new LiveUsageError('--request-id must be a broker request id (a lower-case UUID)');
  const options = { scenario, environment: ENVIRONMENT, operatorConfig: values['--operator-config'], functionUrl, requestId: values['--request-id'], region: values['--region'] ?? null };
  const user = (value, flag) => {
    if (!SLACK_USER_ID.test(value ?? '')) throw new LiveUsageError(`${flag} must be a Slack user id (U… or W…)`);
    return value;
  };
  if (scenario === 'race') {
    const users = (values['--users'] ?? '').split(',');
    if (users.length !== 2 || users[0] === users[1]) throw new LiveUsageError('race needs --users <U…>,<U…>: two different approvers');
    options.users = users.map((u) => user(u, '--users'));
  } else {
    options.user = user(values['--user'], '--user');
    options.action = values['--action'] ?? 'approve';
    if (!ACTIONS.includes(options.action)) throw new LiveUsageError(`--action must be approve or deny (got '${options.action}')`);
  }
  return options;
}

// The signing secret, from a PIPED stdin only. One trailing newline is
// dropped; nothing else is altered.
export async function readSigningSecret(stdin) {
  if (stdin.isTTY) throw new LiveUsageError('pipe the signing secret on stdin (a terminal would echo it)');
  const chunks = [];
  let size = 0;
  for await (const chunk of stdin) {
    size += chunk.length;
    if (size > MAX_SECRET_BYTES) throw new LiveUsageError('stdin is longer than a Slack signing secret');
    chunks.push(chunk);
  }
  const secret = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
  if (secret === '' || /\s/.test(secret)) throw new LiveUsageError('stdin holds no signing secret (empty, or it contains whitespace)');
  return secret;
}

// AWS must prove the target before anything is sent. Read-only, through the
// break-glass read allowlist.
export async function resolveTarget({ operator, functionUrl, region: explicitRegion = null, exec, env = process.env }) {
  const { region } = resolveRegion({ explicit: explicitRegion, configured: operator.aws.region });
  const aws = breakGlassReadAws({ region, exec, env });
  const caller = await callerIdentity(aws);
  for (const c of [accountCheck(caller, operator.aws.accountId), principalCheck(caller)]) {
    if (c.status === 'FAIL') throw new LiveRefused(c.findings.map((f) => f.message).join('; '));
  }
  const name = breakGlassNames(ENVIRONMENT).functions.interactions;
  const fn = await discoverFunction(aws, name);
  if (fn.state !== 'present') throw new LiveRefused(`${name} could not be read (${unread(fn)})`);
  if (fn.value.variables.BREAK_GLASS_ENVIRONMENT !== ENVIRONMENT) {
    throw new LiveRefused(`${name} does not carry BREAK_GLASS_ENVIRONMENT=${ENVIRONMENT} (found '${fn.value.variables.BREAK_GLASS_ENVIRONMENT ?? ''}')`);
  }
  const url = await discoverFunctionUrl(aws, name);
  if (url.state !== 'present') throw new LiveRefused(`the Function URL of ${name} could not be read (${unread(url)})`);
  if (normalizeFunctionUrl(url.value.url) !== functionUrl) {
    throw new LiveRefused(`--function-url is not the Function URL of ${name}: refusing to send signed interactions anywhere else`);
  }
  return { account: caller.account, region, functionName: name, functionUrl };
}

// One Slack block_actions interaction, signed as Slack signs it. No
// response_url: the broker then sends no ephemeral reply anywhere.
export function signInteraction({ secret, requestId, userId, action, timestamp }) {
  const interaction = {
    type: 'block_actions',
    user: { id: userId, username: `live-${userId}` },
    actions: [{ action_id: `breakglass:${requestId}:${action}` }]
  };
  const body = `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
  const ts = String(timestamp);
  const signature = `v0=${createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex')}`;
  return { headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-slack-signature': signature, 'x-slack-request-timestamp': ts }, body };
}

async function send(fetchImpl, url, { headers, body }) {
  const response = await fetchImpl(url, { method: 'POST', headers, body, redirect: 'error', signal: globalThis.AbortSignal.timeout(10_000) });
  return { httpStatus: response.status, outcome: response.headers.get('x-break-glass-outcome') ?? null };
}

// -> { results[], verdict, reasons[] }. `nowSeconds` and `fetchImpl` are injectable.
export async function runScenario(options, { secret, fetchImpl = globalThis.fetch, nowSeconds = () => Math.floor(Date.now() / 1000) }) {
  const { scenario, functionUrl: url, requestId } = options;
  const results = [];
  const reasons = [];
  const click = async (label, userId, action, signed = signInteraction({ secret, requestId, userId, action, timestamp: nowSeconds() })) => {
    const r = { label, user: userId, action, ...(await send(fetchImpl, url, signed)) };
    results.push(r);
    return r;
  };
  const expect = (ok, reason) => {
    if (!ok) reasons.push(reason);
  };

  if (scenario === 'click') {
    const r = await click('click', options.user, options.action);
    expect(r.httpStatus === 200 && r.outcome !== null, `the click was not answered with an outcome (HTTP ${r.httpStatus})`);
  } else if (scenario === 'repeat') {
    const r = await click('repeat', options.user, options.action);
    expect(r.httpStatus === 200 && r.outcome === 'duplicate', `a click on a decided request must be 'duplicate' (got HTTP ${r.httpStatus}, ${r.outcome})`);
  } else if (scenario === 'race') {
    const [a, b] = options.users;
    const both = await Promise.all([click('race-approve', a, 'approve'), click('race-deny', b, 'deny')]);
    const outcomes = both.map((r) => r.outcome).sort();
    expect(both.every((r) => r.httpStatus === 200), `every racing click must be answered (HTTP ${both.map((r) => r.httpStatus).join(', ')})`);
    expect(JSON.stringify(outcomes) === JSON.stringify(['claimed', 'duplicate']), `exactly one click may decide: expected claimed + duplicate, got ${outcomes.join(' + ')}`);
  } else {
    const { user, action } = options;
    const valid = (timestamp) => signInteraction({ secret, requestId, userId: user, action, timestamp });
    const fresh = valid(nowSeconds());
    const wrongSecret = signInteraction({ secret: randomBytes(32).toString('hex'), requestId, userId: user, action, timestamp: nowSeconds() });
    const stale = valid(nowSeconds() - STALE_SECONDS);
    const tampered = { headers: fresh.headers, body: fresh.body.replace(encodeURIComponent(':'), encodeURIComponent(':x')) };
    const unsigned = { headers: { 'content-type': fresh.headers['content-type'] }, body: fresh.body };
    for (const [label, signed] of [['wrong-secret', wrongSecret], ['stale-timestamp', stale], ['tampered-body', tampered], ['unsigned', unsigned]]) {
      const r = await click(label, user, action, signed);
      expect(r.httpStatus === 401 && r.outcome === null, `${label} must be refused 401 before any state change (got HTTP ${r.httpStatus}, ${r.outcome})`);
    }
    const r = await click('valid-after-forgeries', user, action);
    expect(r.httpStatus === 200 && r.outcome === 'claimed', `after the forgeries the request must still be decidable: expected 'claimed', got HTTP ${r.httpStatus}, ${r.outcome}`);
  }
  return { results, verdict: reasons.length === 0 ? 'PASS' : 'FAIL', reasons };
}

// The whole run -> { evidence, exitCode }. Every dependency is injectable.
export async function main(argv, { stdin = process.stdin, exec, env = process.env, fetchImpl = globalThis.fetch, now = () => new Date(), load = loadOperatorConfig } = {}) {
  const startedAt = now().toISOString();
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    return { evidence: { schemaVersion: 1, tool: 'break-glass-live', verdict: 'USAGE', reasons: [error.message] }, exitCode: 2 };
  }
  const evidence = { schemaVersion: 1, tool: 'break-glass-live', scenario: options.scenario, environment: ENVIRONMENT, requestId: options.requestId, startedAt };
  try {
    const secret = await readSigningSecret(stdin);
    const operator = await load(resolve(options.operatorConfig));
    const target = await resolveTarget({ operator, functionUrl: options.functionUrl, region: options.region, exec, env });
    Object.assign(evidence, { account: target.account, region: target.region, functionName: target.functionName, functionUrl: target.functionUrl });
    Object.assign(evidence, await runScenario(options, { secret, fetchImpl, nowSeconds: () => Math.floor(now().getTime() / 1000) }));
  } catch (error) {
    Object.assign(evidence, { verdict: 'REFUSED', reasons: [error.message] });
  }
  evidence.finishedAt = now().toISOString();
  return { evidence, exitCode: evidence.verdict === 'PASS' ? 0 : evidence.verdict === 'USAGE' ? 2 : 1 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { evidence, exitCode } = await main(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  process.exitCode = exitCode;
}
