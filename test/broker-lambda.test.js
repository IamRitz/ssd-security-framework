import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import { describe, it } from 'node:test';

import { createJwksCache, verifyGithubOidcToken } from '../broker/identity/github-oidc.mjs';
import { createBroker } from '../broker/lambda/broker.mjs';
import { createDynamoStore } from '../broker/lambda/dynamodb-store.mjs';
import { createCiHandler, createInteractionsHandler } from '../broker/lambda/handlers.mjs';
import { SLACK_A, SLACK_B, approversById, fakeApproverSource } from './support/fake-approvers.mjs';
import { createFakeDynamo } from './support/fake-dynamodb.mjs';
import { fakeFrameworkPolicy } from './support/fake-framework-policy.mjs';
import { REPO_A as ID_A, REPO_B as ID_B, SHA_A, createSigningKey, fakeJwksFetch, githubClaims, signToken } from './support/jwt-fixtures.mjs';

const SIGNING_SECRET = 'test-signing-secret';
const REPO_A = ID_A.repository;
// One SSM approver parameter per immutable repository_id (Phase 3B).
const APPROVERS = { [ID_A.repositoryId]: [SLACK_A], [ID_B.repositoryId]: [SLACK_B] };
const KEY = createSigningKey();
const RESPONSE_URL = 'https://hooks.slack.com/actions/T0/1/abc';

const eligiblePayload = (overrides = {}) => ({
  schemaVersion: 1,
  environment: 'production',
  gateDigest: 'a'.repeat(64),
  timeoutSeconds: 900,
  context: { repository: REPO_A, commitSha: SHA_A, pullRequest: '51' },
  findings: [{ source: 'semgrep', id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }],
  ...overrides
});

function fakeSlack({ failPost = false } = {}) {
  const calls = { postMessage: [], update: [], respond: [] };
  return {
    calls,
    postMessage: async (m) => {
      calls.postMessage.push(m);
      if (failPost) throw new Error('Slack chat.postMessage failed: not_in_channel');
      return { ok: true, channel: 'C-TEST', ts: '1726300000.000100' };
    },
    update: async (m) => calls.update.push(m),
    respond: async (url, m) => calls.respond.push({ url, message: m })
  };
}

function fakeGithub() {
  const calls = [];
  return { calls, postComment: async (repo, pr, body) => calls.push({ repo, pr, body }) };
}

function setup({ approvers = approversById(APPROVERS), slack = fakeSlack(), now = () => new Date() } = {}) {
  const dynamo = createFakeDynamo();
  const github = fakeGithub();
  const jwks = createJwksCache({ fetchImpl: fakeJwksFetch([KEY]).fetchImpl, now: () => now().getTime() });
  const broker = createBroker({
    store: createDynamoStore({ client: dynamo.client, tableName: 'break-glass-test' }),
    slack,
    github,
    signingSecret: SIGNING_SECRET,
    approverSource: approvers.source,
    verifyIdentity: (token) => verifyGithubOidcToken(token, { jwks, now: () => now().getTime() }),
    frameworkPolicy: fakeFrameworkPolicy().policy,
    environment: 'production',
    slackChannelId: 'C-TEST',
    now,
    log: () => {}
  });
  const enqueued = [];
  const interactions = createInteractionsHandler({
    getBroker: async () => broker,
    enqueue: async (job) => enqueued.push(job)
  });
  const ci = createCiHandler({ getBroker: async () => broker });
  // A fresh GitHub token for repo A's PR 51 run, minted at the broker's clock.
  const token = (claims = {}) =>
    signToken(githubClaims({ nowSeconds: Math.floor(now().getTime() / 1000), ...claims }), { key: KEY });
  const notify = (payload = eligiblePayload(), claims) =>
    ci({ action: 'notify', payload, identityToken: token(claims) });
  const status = (requestId, claims) => ci({ action: 'status', requestId, identityToken: token(claims) });
  const requestItems = () => [...dynamo.table.keys()].filter((key) => !key.startsWith('oidc-jti:'));
  return { dynamo, slack, github, broker, interactions, ci, enqueued, token, notify, status, requestItems };
}

function urlEvent(interaction, { secret = SIGNING_SECRET, timestamp, body, base64 = false } = {}) {
  const ts = timestamp ?? String(Math.floor(Date.now() / 1000));
  const rawBody = body ?? `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
  const signature = `v0=${createHmac('sha256', secret).update(`v0:${ts}:${rawBody}`).digest('hex')}`;
  return {
    requestContext: { http: { method: 'POST' } },
    headers: { 'X-Slack-Signature': signature, 'X-Slack-Request-Timestamp': ts },
    body: base64 ? Buffer.from(rawBody).toString('base64') : rawBody,
    isBase64Encoded: base64
  };
}

const click = (requestId, { userId = SLACK_A, action = 'approve' } = {}) => ({
  type: 'block_actions',
  user: { id: userId, username: `user-${userId}` },
  actions: [{ action_id: `breakglass:${requestId}:${action}` }],
  response_url: RESPONSE_URL
});

async function createRequest(env, payload = eligiblePayload()) {
  const result = await env.notify(payload);
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.body.requestId;
}

const statusOf = async (env, requestId) => (await env.status(requestId)).body.status;

describe('Lambda broker — CI function (direct invoke only)', () => {
  it('stores a pending request, posts the approval message, and records the message ref', async () => {
    const env = setup();
    const result = await env.notify();
    assert.equal(result.ok, true);
    assert.equal(result.statusCode, 201);
    assert.equal(result.body.status, 'pending');
    assert.equal(env.slack.calls.postMessage.length, 1);
    const item = env.dynamo.table.get(result.body.requestId);
    assert.equal(item.status.S, 'pending');
    assert.equal(item.slackTs.S, '1726300000.000100');
    // TTL is physical cleanup a week past logical expiry, not the expiry itself.
    const expiresEpoch = Math.floor(new Date(item.expiresAt.S).getTime() / 1000);
    assert.equal(Number(item.ttl.N), expiresEpoch + 7 * 24 * 3600);
  });

  it('rejects non-overridable findings before touching state or Slack', async () => {
    const env = setup();
    for (const policyRule of ['secrets.verified', 'dependencies.malicious_package', 'integrity.untrusted']) {
      const payload = eligiblePayload({
        findings: [{ id: 'x', action: 'BLOCK', policyRule, reason: 'hard block' }]
      });
      const result = await env.notify(payload);
      assert.equal(result.ok, false);
      assert.equal(result.statusCode, 400);
    }
    // Refused before identity is even checked: no request and no token record.
    assert.equal(env.dynamo.table.size, 0);
    assert.equal(env.slack.calls.postMessage.length, 0);
  });

  it('fails closed and rolls back when Slack refuses the message', async () => {
    const env = setup({ slack: fakeSlack({ failPost: true }) });
    const result = await env.notify();
    assert.equal(result.ok, false);
    assert.equal(result.statusCode, 502);
    // The request is rolled back; the spent token's one-shot record remains.
    assert.deepEqual(env.requestItems(), []);
  });

  it('returns unknown_request for an unknown id and expires an elapsed pending request', async () => {
    let clock = new Date();
    const env = setup({ now: () => clock });
    assert.deepEqual(await env.status('nope'), {
      ok: false,
      statusCode: 404,
      error: 'unknown_request'
    });
    const requestId = await createRequest(env);
    clock = new Date(clock.getTime() + 901_000);
    const status = await env.status(requestId);
    assert.equal(status.body.status, 'expired');
    assert.equal(env.dynamo.table.get(requestId).status.S, 'expired');
  });

  it('refuses URL/HTTP-shaped events and unknown actions', async () => {
    const env = setup();
    assert.equal((await env.ci({ requestContext: { http: { method: 'POST' } } })).error, 'direct_invoke_only');
    assert.equal((await env.ci({ headers: {}, action: 'notify' })).error, 'direct_invoke_only');
    assert.equal((await env.ci({ action: 'approve' })).error, 'unknown_action');
  });
});

describe('Lambda broker — Slack signature verification at the Function URL', () => {
  it('accepts a genuinely signed request (plain and base64-encoded bodies)', async () => {
    const env = setup();
    const requestId = await createRequest(env, eligiblePayload());
    const plain = await env.interactions(urlEvent(click(requestId, { userId: 'UNOBODY0001' })));
    assert.equal(plain.statusCode, 200);
    const encoded = await env.interactions(urlEvent(click(requestId, { userId: 'UNOBODY0001' }), { base64: true }));
    assert.equal(encoded.statusCode, 200);
  });

  it('rejects tampered, stale, wrong-secret, and unsigned requests with 401 and no state change', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    const genuine = urlEvent(click(requestId));
    const tampered = { ...genuine, body: `payload=${encodeURIComponent(JSON.stringify(click(requestId, { action: 'deny' })))}` };
    const stale = urlEvent(click(requestId), { timestamp: String(Math.floor(Date.now() / 1000) - 301) });
    const wrongSecret = urlEvent(click(requestId), { secret: 'attacker-secret' });
    const unsigned = { ...genuine, headers: {} };
    for (const event of [tampered, stale, wrongSecret, unsigned]) {
      const response = await env.interactions(event);
      assert.equal(response.statusCode, 401);
      assert.equal(response.headers['x-break-glass-outcome'], undefined);
    }
    assert.equal(await statusOf(env, requestId), 'pending');
    assert.equal(env.enqueued.length, 0);
  });

  it('rejects a signed but malformed payload with 400', async () => {
    const env = setup();
    assert.equal((await env.interactions(urlEvent(null, { body: 'payload=%7Bnot-json' }))).statusCode, 400);
    assert.equal((await env.interactions(urlEvent(null, { body: 'nothing=here' }))).statusCode, 400);
  });

  it('rejects non-POST methods', async () => {
    const env = setup();
    const event = { ...urlEvent(click('x')), requestContext: { http: { method: 'GET' } } };
    assert.equal((await env.interactions(event)).statusCode, 405);
  });
});

describe('Lambda broker — decisions', () => {
  it('approves end to end: finalized before ack, side effects deferred and delivered once', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    const response = await env.interactions(urlEvent(click(requestId)));
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers['x-break-glass-outcome'], 'claimed');
    // State is final BEFORE any side effect ran.
    assert.equal(await statusOf(env, requestId), 'approved');
    assert.equal(env.github.calls.length, 0);
    assert.deepEqual(env.enqueued, [{ kind: 'side-effects', requestId }]);

    // Async follow-up arrives as a non-URL event.
    assert.equal((await env.interactions(env.enqueued[0])).done, true);
    assert.equal(env.github.calls.length, 1);
    assert.equal(env.github.calls[0].repo, REPO_A);
    assert.equal(env.github.calls[0].pr, '51');
    assert.match(env.github.calls[0].body, /Break-glass decision: \*\*APPROVED\*\*/);
    assert.match(env.github.calls[0].body, /Verified approver: \*\*user-UAPPROVERA1\*\* \(ID: `UAPPROVERA1`\)/);
    assert.match(env.github.calls[0].body, /Overridden finding\(s\): sast.high_new: demo.rule/);
    // Buttons removed: the message is replaced in place with no actions block.
    assert.equal(env.slack.calls.update.length, 1);
    assert.equal(env.slack.calls.update[0].ts, '1726300000.000100');
    assert.ok(env.slack.calls.update[0].blocks.every((block) => block.type !== 'actions'));

    // A redelivered follow-up posts nothing twice.
    assert.equal((await env.interactions(env.enqueued[0])).done, false);
    assert.equal(env.github.calls.length, 1);
    const status = (await env.status(requestId)).body;
    assert.equal(status.approver.id, SLACK_A);
  });

  it('denies', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    await env.interactions(urlEvent(click(requestId, { action: 'deny' })));
    assert.equal(await statusOf(env, requestId), 'denied');
  });

  it('an unauthorized user changes nothing and gets an ephemeral reply', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    const response = await env.interactions(urlEvent(click(requestId, { userId: 'USTRANGER01' })));
    assert.equal(response.headers['x-break-glass-outcome'], 'unauthorized');
    assert.equal(await statusOf(env, requestId), 'pending');
    assert.equal(env.enqueued[0].kind, 'ephemeral');
    await env.interactions(env.enqueued[0]);
    assert.match(env.slack.calls.respond[0].message.text, /not an authorized/);
    assert.equal(env.github.calls.length, 0);
  });

  it('per-repo scoping: a repo-B approver is rejected on a repo-A request', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    const response = await env.interactions(urlEvent(click(requestId, { userId: SLACK_B })));
    assert.equal(response.headers['x-break-glass-outcome'], 'unauthorized');
    assert.equal(await statusOf(env, requestId), 'pending');
  });

  it('a malformed approver parameter authorizes nobody', async () => {
    const env = setup({ approvers: fakeApproverSource({ '/ssd/break-glass/production/approvers/1001': '{not json' }) });
    const requestId = await createRequest(env);
    await env.interactions(urlEvent(click(requestId)));
    assert.equal(await statusOf(env, requestId), 'pending');
  });

  it('a click after expiry is refused and marks the request expired', async () => {
    let clock = new Date();
    const env = setup({ now: () => clock });
    const requestId = await createRequest(env);
    clock = new Date(clock.getTime() + 901_000);
    const event = urlEvent(click(requestId), { timestamp: String(Math.floor(clock.getTime() / 1000)) });
    const response = await env.interactions(event);
    assert.equal(response.headers['x-break-glass-outcome'], 'expired');
    assert.equal(env.dynamo.table.get(requestId).status.S, 'expired');
  });

  it('forged follow-up events cannot run through the Function URL', async () => {
    const env = setup();
    const event = urlEvent(null, { body: JSON.stringify({ kind: 'side-effects', requestId: 'x' }) });
    assert.equal((await env.interactions(event)).statusCode, 400);
    await assert.rejects(
      env.broker.runFollowUp({ kind: 'ephemeral', responseUrl: 'https://evil.example/x', text: 'hi' }),
      /non-Slack response_url/
    );
  });

  it('runs side effects inline when the async enqueue fails', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    const handler = createInteractionsHandler({
      getBroker: async () => env.broker,
      enqueue: async () => {
        throw new Error('throttled');
      }
    });
    const originalError = console.error;
    console.error = () => {};
    try {
      await handler(urlEvent(click(requestId)));
    } finally {
      console.error = originalError;
    }
    assert.equal(env.github.calls.length, 1);
  });
});

describe('Lambda broker — the conditional claim under real concurrency', () => {
  it('25 concurrent clicks that all read `pending` produce exactly one committed decision', async () => {
    const env = setup();
    const requestId = await createRequest(env);
    const events = Array.from({ length: 25 }, (_, index) =>
      urlEvent(click(requestId, { action: index % 2 ? 'deny' : 'approve' }))
    );
    const responses = await Promise.all(events.map((event) => env.interactions(event)));
    const outcomes = responses.map((response) => response.headers['x-break-glass-outcome']);
    assert.equal(outcomes.filter((outcome) => outcome === 'claimed').length, 1, outcomes.join(','));
    assert.equal(outcomes.filter((outcome) => outcome === 'duplicate').length, 24);

    // The fake interleaves: every click's GetItem ran before the first conditional write.
    const firstUpdate = env.dynamo.log.indexOf('UpdateItem', env.dynamo.log.indexOf('UpdateItem') + 1);
    const getsBeforeClaim = env.dynamo.log.slice(0, firstUpdate).filter((op) => op === 'GetItem').length;
    assert.ok(getsBeforeClaim >= 25, `expected interleaved reads, saw ${getsBeforeClaim}`);

    const sideEffects = env.enqueued.filter((job) => job.kind === 'side-effects');
    assert.equal(sideEffects.length, 1);
    await Promise.all(env.enqueued.map((job) => env.interactions(job)));
    assert.equal(env.github.calls.length, 1);
    assert.ok(['approved', 'denied'].includes(await statusOf(env, requestId)));
  });
});
