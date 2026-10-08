// The in-process break-glass broker used by the broker and scenario tests: the
// REAL verifier (RS256 over keys generated here, served by a fake of GitHub's
// fixed JWKS endpoint), broker, store and Lambda handlers, over fakes of
// DynamoDB, SSM (approvers, framework policy), Slack and GitHub.
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { createJwksCache, verifyGithubOidcToken } from '../../broker/identity/github-oidc.mjs';
import { createBroker } from '../../broker/lambda/broker.mjs';
import { createDynamoStore } from '../../broker/lambda/dynamodb-store.mjs';
import { createCiHandler, createInteractionsHandler } from '../../broker/lambda/handlers.mjs';
import { SLACK_A, SLACK_B, approversById } from './fake-approvers.mjs';
import { createFakeDynamo } from './fake-dynamodb.mjs';
import { fakeFrameworkPolicy } from './fake-framework-policy.mjs';
import { REPO_A, REPO_B, SHA_A, createSigningKey, fakeJwksFetch, githubClaims, signToken } from './jwt-fixtures.mjs';

export const KEY = createSigningKey({ kid: 'github-key-1' });
export const NOW_MS = Date.UTC(2026, 9, 3, 12, 0, 0);
export const NOW = Math.floor(NOW_MS / 1000);

export function verifier({ keys = [KEY], fail = false, clock = () => NOW_MS } = {}) {
  const jwksFetch = fakeJwksFetch(keys, { fail });
  const jwks = createJwksCache({ fetchImpl: jwksFetch.fetchImpl, now: clock });
  return { jwksFetch, jwks, verify: (token, options = {}) => verifyGithubOidcToken(token, { jwks, now: clock, ...options }) };
}

export const SIGNING_SECRET = 'identity-test-signing-secret';
export const RESPONSE_URL = 'https://hooks.slack.com/actions/T0/1/abc';
export const APPROVERS = { [REPO_A.repositoryId]: [SLACK_A], [REPO_B.repositoryId]: [SLACK_B] };

// `environment` is the framework-derived request environment (Phase 3E).
export const payloadFor = (repo = REPO_A, { pullRequest = '51', sha = SHA_A, environment = 'production', ...context } = {}) => ({
  schemaVersion: 1,
  environment,
  gateDigest: 'a'.repeat(64),
  timeoutSeconds: 900,
  context: { repository: repo.repository, commitSha: sha, pullRequest, ...context },
  findings: [{ source: 'semgrep', id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }]
});

// `environment` is the broker's BREAK_GLASS_ENVIRONMENT (default production);
// the approver and framework-policy fakes serve that environment's parameters.
export function brokerEnv(options = {}) {
  const { environment = 'production', events = null } = options;
  const approvers = options.approvers ?? approversById(APPROVERS, { environment });
  const framework = options.framework ?? fakeFrameworkPolicy({ events, environment });
  let clock = NOW_MS;
  const now = () => new Date(clock);
  const dynamo = createFakeDynamo();
  // Failure injection for the ordering tests: `failNext.put` fails the next
  // request PutItem, `failNext.delete` the next DeleteItem, `failNext.slack`
  // the next chat.postMessage (after Slack may or may not have posted it).
  const failNext = { put: 0, delete: 0, slack: 0 };
  const call = dynamo.client.call;
  dynamo.client.call = async (operation, input) => {
    const key = (input.Key ?? input.Item)?.requestId?.S ?? '';
    // Ordering log (optional): every store call, with replay records marked.
    events?.push(`${operation}${key.startsWith('oidc-jti:') ? ':jti' : ''}`);
    if (operation === 'PutItem' && !key.startsWith('oidc-jti:') && failNext.put > 0) {
      failNext.put -= 1;
      throw new Error('ProvisionedThroughputExceededException');
    }
    if (operation === 'DeleteItem' && failNext.delete > 0) {
      failNext.delete -= 1;
      throw new Error('InternalServerError');
    }
    return call(operation, input);
  };
  const slack = { posted: [], updated: [], responded: [] };
  const github = [];
  const logs = [];
  const v = verifier({ clock: () => clock });
  const store = createDynamoStore({ client: dynamo.client, tableName: 't' });
  const broker = createBroker({
    store,
    slack: {
      postMessage: async (m) => {
        events?.push('slack');
        if (failNext.slack > 0) {
          failNext.slack -= 1;
          throw new Error('Slack chat.postMessage failed: not_in_channel');
        }
        slack.posted.push(m);
        return { ok: true, channel: 'C', ts: '1.2' };
      },
      update: async (m) => slack.updated.push(m),
      respond: async (url, m) => slack.responded.push({ url, m })
    },
    github: { postComment: async (repo, pr, body) => github.push({ repo, pr, body }) },
    signingSecret: SIGNING_SECRET,
    approverSource: approvers.source,
    verifyIdentity: 'verifyIdentity' in options ? options.verifyIdentity : async (identityToken) => {
      events?.push('verify');
      return v.verify(identityToken);
    },
    frameworkPolicy: 'frameworkPolicy' in options ? options.frameworkPolicy : framework.policy,
    environment: 'brokerEnvironment' in options ? options.brokerEnvironment : environment,
    slackChannelId: 'C',
    now,
    log: (entry) => logs.push(entry)
  });
  const ci = createCiHandler({ getBroker: async () => broker });
  const enqueued = [];
  const interactions = createInteractionsHandler({ getBroker: async () => broker, enqueue: async (job) => enqueued.push(job) });
  const tokenFor = (overrides = {}) => signToken(githubClaims({ nowSeconds: Math.floor(clock / 1000), ...overrides }), { key: KEY });
  return {
    dynamo, store, slack, github, logs, ci, interactions, enqueued, broker, failNext, framework, approvers, environment,
    advance: (ms) => (clock += ms),
    tokenFor,
    notify: (payload, identityToken) => ci({ action: 'notify', payload, identityToken }),
    status: (requestId, identityToken) => ci({ action: 'status', requestId, identityToken }),
    requests: () => [...dynamo.table.values()].filter((item) => item.doc),
    tokenRecords: () => [...dynamo.table.values()].filter((item) => item.kind?.S === 'oidc-jti')
  };
}

export async function fileRequest(env, { repo = REPO_A, runId = '700001', runAttempt = '1', pullRequest = '51', sha = SHA_A, environment = env.environment } = {}) {
  const result = await env.notify(
    payloadFor(repo, { pullRequest, sha, environment }),
    env.tokenFor({ repo, runId, runAttempt, pullRequest, sha })
  );
  assert.equal(result.statusCode, 201, JSON.stringify(result));
  return result.body.requestId;
}

export function signedClick(requestId, userId, action = 'approve') {
  const interaction = {
    type: 'block_actions',
    user: { id: userId, username: `user-${userId}` },
    actions: [{ action_id: `breakglass:${requestId}:${action}` }],
    response_url: RESPONSE_URL
  };
  const ts = String(NOW);
  const rawBody = `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
  const signature = `v0=${createHmac('sha256', SIGNING_SECRET).update(`v0:${ts}:${rawBody}`).digest('hex')}`;
  return {
    requestContext: { http: { method: 'POST' } },
    headers: { 'X-Slack-Signature': signature, 'X-Slack-Request-Timestamp': ts },
    body: rawBody,
    isBase64Encoded: false
  };
}
