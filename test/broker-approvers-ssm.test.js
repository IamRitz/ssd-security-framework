// Per-repository break-glass approvers in SSM (Phase 3B, architecture E.3).
//
//   /ssd/break-glass/<environment>/approvers/<repository_id>  ->  ["U…", …]
//
// Contract: missing, malformed or empty -> nobody; an SSM failure is UNVERIFIED
// (nobody, and never reported as "absent"); the repository_id is the stored
// request's VERIFIED identity, never the payload; and only that repository's
// parameter is ever consulted. These tests drive the real approver source and
// the real broker; only SSM itself is faked.
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  BREAK_GLASS_ENVIRONMENTS,
  MAX_APPROVERS,
  approverParameterName,
  createApproverSource,
  parseApproverList
} from '../broker/authorize/approvers.mjs';
import { createJwksCache, verifyGithubOidcToken } from '../broker/identity/github-oidc.mjs';
import { createBroker } from '../broker/lambda/broker.mjs';
import { createDynamoStore } from '../broker/lambda/dynamodb-store.mjs';
import { createCiHandler, createInteractionsHandler } from '../broker/lambda/handlers.mjs';
import { SLACK_A, SLACK_B, approverParameter, approversById, fakeApproverSource, ssmError } from './support/fake-approvers.mjs';
import { createFakeDynamo } from './support/fake-dynamodb.mjs';
import { fakeFrameworkPolicy } from './support/fake-framework-policy.mjs';
import { REPO_A, REPO_B, SHA_A, SHA_B, createSigningKey, fakeJwksFetch, githubClaims, signToken } from './support/jwt-fixtures.mjs';

const PARAM_A = '/ssd/break-glass/production/approvers/1001';
const PARAM_B = '/ssd/break-glass/production/approvers/1002';

// =================================================================================
describe('approver parameter name', () => {
  it('is /ssd/break-glass/<environment>/approvers/<repository_id>', () => {
    assert.equal(approverParameterName('production', '1001'), PARAM_A);
    assert.equal(approverParameterName('synthetic', '1001'), '/ssd/break-glass/synthetic/approvers/1001');
    assert.deepEqual(BREAK_GLASS_ENVIRONMENTS, ['production', 'synthetic']);
  });

  for (const environment of ['', 'staging', 'Production', 'production/../synthetic', 'production/approvers', undefined, null]) {
    it(`refuses environment ${JSON.stringify(environment)}`, () => {
      assert.equal(approverParameterName(environment, '1001'), null);
    });
  }

  for (const repositoryId of ['', '0', '01001', '-1', 'owner/repo-a', '1001/../1002', '1001 ', '1'.repeat(21), 1001, undefined]) {
    it(`refuses repository_id ${JSON.stringify(repositoryId)}`, () => {
      assert.equal(approverParameterName('production', repositoryId), null);
    });
  }
});

describe('approver list value', () => {
  it('a JSON array of distinct Slack user IDs is present', () => {
    const parsed = parseApproverList(JSON.stringify([SLACK_A, 'W0123456789']));
    assert.equal(parsed.state, 'present');
    assert.deepEqual([...parsed.userIds], [SLACK_A, 'W0123456789']);
  });

  it('an empty list is `empty`: nobody', () => {
    assert.deepEqual(parseApproverList('[]'), { state: 'empty', reason: 'the approver list is empty', userIds: null });
  });

  for (const [name, value] of [
    ['not JSON', '{not json'],
    ['a JSON object (the old map shape)', JSON.stringify({ 1001: [SLACK_A] })],
    ['a JSON string', JSON.stringify(SLACK_A)],
    ['a comma-separated string', `${SLACK_A},${SLACK_B}`],
    ['null', 'null'],
    ['a non-string entry', JSON.stringify([SLACK_A, 42])],
    ['a nested list', JSON.stringify([[SLACK_A]])],
    ['an entry that is not a Slack ID', JSON.stringify([SLACK_A, 'alice'])],
    ['a wildcard entry', JSON.stringify(['*'])],
    ['a lower-case ID', JSON.stringify(['uapprovera1'])],
    ['an ID with whitespace', JSON.stringify([` ${SLACK_A}`])],
    ['a channel ID, not a user', JSON.stringify(['C0123456789'])],
    ['a duplicate', JSON.stringify([SLACK_A, SLACK_A])],
    ['too many approvers', JSON.stringify(Array.from({ length: MAX_APPROVERS + 1 }, (_, i) => `U${String(i).padStart(10, '0')}`))],
    ['an oversized value', JSON.stringify([SLACK_A]).padEnd(5000, ' ')],
    ['not a string', undefined]
  ]) {
    it(`is malformed, and authorizes nobody, when it is ${name}`, () => {
      const parsed = parseApproverList(value);
      assert.equal(parsed.state, 'malformed');
      assert.equal(parsed.userIds, null);
    });
  }

  it('one bad entry rejects the whole list rather than being filtered out', () => {
    const parsed = parseApproverList(JSON.stringify([SLACK_A, 'not-an-id', SLACK_B]));
    assert.equal(parsed.state, 'malformed');
    assert.equal(parsed.userIds, null);
    // ...and says why, so an operator fixes the entry rather than hunting a duplicate.
    assert.equal(parsed.reason, 'an entry is not a Slack user ID');
    assert.equal(parseApproverList(JSON.stringify([SLACK_A, SLACK_A])).reason, 'duplicate approver');
  });
});

describe('approver source (SSM GetParameter)', () => {
  it('asks for exactly the one parameter the repository_id names, unencrypted String', async () => {
    const fake = fakeApproverSource({ [PARAM_A]: JSON.stringify([SLACK_A]) });
    const found = await fake.source.approversFor('1001');
    assert.equal(found.state, 'present');
    assert.deepEqual(fake.requested, [PARAM_A]);
  });

  it('a missing parameter is `absent`: nobody', async () => {
    const fake = fakeApproverSource({});
    assert.equal((await fake.source.approversFor('1001')).state, 'absent');
  });

  for (const errorName of ['AccessDeniedException', 'ThrottlingException', 'TimeoutError', 'AbortError', 'InternalServerError']) {
    it(`an SSM ${errorName} is \`unverified\` (never "absent"): nobody`, async () => {
      const fake = fakeApproverSource({ [PARAM_A]: ssmError(errorName) });
      const found = await fake.source.approversFor('1001');
      assert.equal(found.state, 'unverified');
      assert.equal(found.userIds, null);
      assert.match(found.reason, new RegExp(errorName));
    });
  }

  it('an error without a name is unverified too', async () => {
    const source = createApproverSource({ environment: 'production', getParameter: async () => { throw 'boom'; } });
    assert.equal((await source.approversFor('1001')).state, 'unverified');
  });

  for (const type of ['SecureString', 'StringList', undefined]) {
    it(`a parameter of type ${type} is malformed`, async () => {
      const fake = fakeApproverSource({ [PARAM_A]: { Type: type, Value: JSON.stringify([SLACK_A]) } });
      assert.equal((await fake.source.approversFor('1001')).state, 'malformed');
    });
  }

  it('an invalid environment or repository_id is `misconfigured` and makes no SSM call', async () => {
    const bad = fakeApproverSource({}, { environment: 'staging' });
    assert.equal((await bad.source.approversFor('1001')).state, 'misconfigured');
    const fake = fakeApproverSource({ [PARAM_A]: JSON.stringify([SLACK_A]) });
    assert.equal((await fake.source.approversFor('owner/repo-a')).state, 'misconfigured');
    assert.equal((await fake.source.approversFor('1001/../1002')).state, 'misconfigured');
    assert.deepEqual([...bad.requested, ...fake.requested], []);
  });

  it('production and synthetic read different parameters', async () => {
    const parameters = {
      [approverParameter('1001', 'production')]: JSON.stringify([SLACK_A]),
      [approverParameter('1001', 'synthetic')]: JSON.stringify([SLACK_B])
    };
    const production = fakeApproverSource(parameters, { environment: 'production' });
    const synthetic = fakeApproverSource(parameters, { environment: 'synthetic' });
    assert.ok((await production.source.approversFor('1001')).userIds.has(SLACK_A));
    assert.ok(!(await production.source.approversFor('1001')).userIds.has(SLACK_B));
    assert.ok((await synthetic.source.approversFor('1001')).userIds.has(SLACK_B));
  });
});

// =================================================================================
// Through the real broker: notify (verified identity) -> Slack click -> lookup.

const SIGNING_SECRET = 'approvers-test-signing-secret';
const KEY = createSigningKey();
const NOW_MS = Date.UTC(2026, 9, 3, 12, 0, 0);

function brokerEnv(approvers = approversById({ [REPO_A.repositoryId]: [SLACK_A], [REPO_B.repositoryId]: [SLACK_B] })) {
  const clock = NOW_MS;
  const dynamo = createFakeDynamo();
  const store = createDynamoStore({ client: dynamo.client, tableName: 't' });
  const logs = [];
  const jwks = createJwksCache({ fetchImpl: fakeJwksFetch([KEY]).fetchImpl, now: () => clock });
  const broker = createBroker({
    store,
    slack: {
      postMessage: async () => ({ ok: true, channel: 'C', ts: '1.2' }),
      update: async () => {},
      respond: async () => {}
    },
    github: { postComment: async () => {} },
    signingSecret: SIGNING_SECRET,
    approverSource: approvers.source,
    verifyIdentity: (token) => verifyGithubOidcToken(token, { jwks, now: () => clock }),
    frameworkPolicy: fakeFrameworkPolicy().policy,
    environment: 'production',
    slackChannelId: 'C',
    now: () => new Date(clock),
    log: (entry) => logs.push(entry)
  });
  const ci = createCiHandler({ getBroker: async () => broker });
  const interactions = createInteractionsHandler({ getBroker: async () => broker, enqueue: async () => {} });

  async function file(repo = REPO_A, sha = SHA_A) {
    const identityToken = signToken(githubClaims({ repo, sha, nowSeconds: Math.floor(clock / 1000) }), { key: KEY });
    const payload = {
      schemaVersion: 1,
      environment: 'production',
      gateDigest: 'a'.repeat(64),
      timeoutSeconds: 900,
      context: { repository: repo.repository, commitSha: sha, pullRequest: '51' },
      findings: [{ id: 'r', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }]
    };
    const result = await ci({ action: 'notify', payload, identityToken });
    assert.equal(result.statusCode, 201, JSON.stringify(result));
    return result.body.requestId;
  }

  async function click(requestId, userId) {
    const interaction = {
      type: 'block_actions',
      user: { id: userId, username: `user-${userId}` },
      actions: [{ action_id: `breakglass:${requestId}:approve` }],
      response_url: 'https://hooks.slack.com/actions/T0/1/abc'
    };
    const ts = String(Math.floor(clock / 1000));
    const body = `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
    const signature = `v0=${createHmac('sha256', SIGNING_SECRET).update(`v0:${ts}:${body}`).digest('hex')}`;
    const response = await interactions({
      requestContext: { http: { method: 'POST' } },
      headers: { 'X-Slack-Signature': signature, 'X-Slack-Request-Timestamp': ts },
      body,
      isBase64Encoded: false
    });
    return response.headers['x-break-glass-outcome'];
  }

  const statusOf = async (requestId) => (await store.get(requestId))?.status;
  return { approvers, dynamo, store, logs, file, click, statusOf };
}

describe('broker: the click is authorized against the verified repository\'s parameter', () => {
  it('the listed approver decides', async () => {
    const env = brokerEnv();
    const requestId = await env.file();
    assert.equal(await env.click(requestId, SLACK_A), 'claimed');
    assert.equal(await env.statusOf(requestId), 'approved');
    assert.deepEqual(env.approvers.requested, [PARAM_A]);
  });

  it('an approver listed only for another repository is a no-op, and only this repository\'s parameter is read', async () => {
    const env = brokerEnv();
    const requestId = await env.file();
    assert.equal(await env.click(requestId, SLACK_B), 'unauthorized');
    assert.equal(await env.statusOf(requestId), 'pending');
    assert.deepEqual(env.approvers.requested, [PARAM_A], 'repo B\'s parameter is never consulted');
  });

  for (const [name, parameters, state] of [
    ['missing parameter', {}, 'absent'],
    ['malformed JSON', { [PARAM_A]: '{not json' }, 'malformed'],
    ['empty list', { [PARAM_A]: '[]' }, 'empty'],
    ['the old name-keyed map shape', { [PARAM_A]: JSON.stringify({ [REPO_A.repository]: [SLACK_A] }) }, 'malformed'],
    ['a SecureString parameter', { [PARAM_A]: { Type: 'SecureString', Value: JSON.stringify([SLACK_A]) } }, 'malformed'],
    ['SSM access denied', { [PARAM_A]: ssmError('AccessDeniedException') }, 'unverified'],
    ['SSM timeout', { [PARAM_A]: ssmError('TimeoutError') }, 'unverified'],
    ['another repository\'s parameter only', { [PARAM_B]: JSON.stringify([SLACK_A]) }, 'absent']
  ]) {
    it(`${name} -> nobody authorized, logged as ${state}`, async () => {
      const env = brokerEnv(fakeApproverSource(parameters));
      const requestId = await env.file();
      assert.equal(await env.click(requestId, SLACK_A), 'unauthorized');
      assert.equal(await env.statusOf(requestId), 'pending');
      const entry = env.logs.find((e) => e.event === 'unauthorized');
      assert.equal(entry.approverList, state);
      assert.equal(entry.repositoryId, REPO_A.repositoryId);
    });
  }

  it('the lookup uses the stored VERIFIED repository_id, even if the stored display context was altered', async () => {
    const env = brokerEnv();
    const requestId = await env.file();
    const item = env.dynamo.table.get(requestId);
    const doc = JSON.parse(item.doc.S);
    doc.context = { ...doc.context, repository: REPO_B.repository, repositoryId: REPO_B.repositoryId };
    env.dynamo.table.set(requestId, { ...item, doc: { S: JSON.stringify(doc) } });
    assert.equal(await env.click(requestId, SLACK_B), 'unauthorized');
    assert.equal(await env.click(requestId, SLACK_A), 'claimed');
    assert.deepEqual(env.approvers.requested, [PARAM_A, PARAM_A]);
  });

  it('a request with no verified identity makes no SSM call and authorizes nobody', async () => {
    const env = brokerEnv();
    const requestId = await env.file();
    const item = env.dynamo.table.get(requestId);
    const doc = JSON.parse(item.doc.S);
    delete doc.identity;
    env.dynamo.table.set(requestId, { ...item, doc: { S: JSON.stringify(doc) } });
    assert.equal(await env.click(requestId, SLACK_A), 'unauthorized');
    assert.deepEqual(env.approvers.requested, []);
    assert.equal(env.logs.find((e) => e.event === 'unauthorized').approverList, 'misconfigured');
  });

  it('read at click time: removing an approver takes effect on the next click', async () => {
    const env = brokerEnv();
    const first = await env.file();
    const second = await env.file(REPO_A, SHA_A);
    env.approvers.parameters[PARAM_A] = JSON.stringify([SLACK_B]); // SLACK_A revoked
    assert.equal(await env.click(first, SLACK_A), 'unauthorized');
    assert.equal(await env.click(second, SLACK_B), 'claimed');
  });

  it('repo B requests use repo B\'s parameter', async () => {
    const env = brokerEnv();
    const requestId = await env.file(REPO_B, SHA_B);
    assert.equal(await env.click(requestId, SLACK_A), 'unauthorized');
    assert.equal(await env.click(requestId, SLACK_B), 'claimed');
    assert.deepEqual(env.approvers.requested, [PARAM_B, PARAM_B]);
  });
});
