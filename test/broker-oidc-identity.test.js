// Break-glass broker identity (Phase 3A, architecture E.2).
//
// Before this, the CI broker believed the repository named in its payload, so
// any principal allowed to invoke it could file a request "for" another
// repository: wrong approvers paged, and the broker's audit comment posted on
// another repository's pull request. Every CI request now carries a GitHub OIDC
// token for the `ssd-break-glass` audience. These tests drive the REAL verifier
// (RS256 over keys generated here, served by a fake of GitHub's fixed JWKS
// endpoint) through the real broker, store and handler.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  ALLOWED_JOB_WORKFLOW_PATHS,
  FRAMEWORK_REPOSITORY,
  GITHUB_OIDC_JWKS_URL,
  IdentityRejected,
  JWKS_MIN_REFRESH_INTERVAL_MS,
  JWKS_TTL_MS,
  createJwksCache,
  parseJobWorkflowRef,
  pullRequestFromIdentity,
  verifyGithubOidcToken
} from '../broker/identity/github-oidc.mjs';
import { createBroker } from '../broker/lambda/broker.mjs';
import { TOKEN_RECORD_GRACE_SECONDS, createDynamoStore } from '../broker/lambda/dynamodb-store.mjs';
import { createCiHandler, createInteractionsHandler } from '../broker/lambda/handlers.mjs';
import { notifyBreakGlass } from '../security/scripts/break-glass-notify.mjs';
import { describePollOutcome, pollBreakGlass } from '../security/scripts/break-glass-poll.mjs';
import { deriveBreakGlassResult } from '../security/scripts/break-glass-result.mjs';
import { explainBreakGlass } from '../security/scripts/conformance.mjs';
import { decideSourceGate } from '../security/scripts/final-gate.mjs';
import { SLACK_A, SLACK_B, approversById } from './support/fake-approvers.mjs';
import { createFakeDynamo } from './support/fake-dynamodb.mjs';
import { fakeFrameworkPolicy } from './support/fake-framework-policy.mjs';
import {
  FRAMEWORK_SHA,
  REPO_A,
  REPO_B,
  SHA_A,
  SHA_B,
  createSigningKey,
  fakeJwksFetch,
  githubClaims,
  hs256Token,
  signToken,
  unsignedToken
} from './support/jwt-fixtures.mjs';

const KEY = createSigningKey({ kid: 'github-key-1' });
const ROTATED = createSigningKey({ kid: 'github-key-2' });
const ATTACKER = createSigningKey({ kid: 'github-key-1' }); // same kid, different key
const SMALL = createSigningKey({ kid: 'small-key', bits: 1024 });
const NOW_MS = Date.UTC(2026, 9, 3, 12, 0, 0);
const NOW = Math.floor(NOW_MS / 1000);

const rejects = async (promise, code) => {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof IdentityRejected, `expected IdentityRejected, got ${error}`);
    assert.equal(error.code, code);
    return true;
  });
};

function verifier({ keys = [KEY], fail = false, clock = () => NOW_MS } = {}) {
  const jwksFetch = fakeJwksFetch(keys, { fail });
  const jwks = createJwksCache({ fetchImpl: jwksFetch.fetchImpl, now: clock });
  return { jwksFetch, jwks, verify: (token, options = {}) => verifyGithubOidcToken(token, { jwks, now: clock, ...options }) };
}

const claims = (overrides = {}) => githubClaims({ nowSeconds: NOW, ...overrides });
const token = (overrides = {}, key = KEY) => signToken(claims(overrides), { key });

// =================================================================================
describe('verifyGithubOidcToken: what a valid token proves', () => {
  it('accepts a correctly signed token and returns the identity from its claims', async () => {
    const { verify } = verifier();
    const identity = await verify(token({ jti: 'jti-1' }));
    assert.deepEqual(identity, {
      repository: REPO_A.repository,
      repositoryId: REPO_A.repositoryId,
      repositoryOwnerId: REPO_A.ownerId,
      ref: 'refs/pull/51/merge',
      sha: SHA_A,
      runId: '700001',
      runAttempt: '1',
      eventName: 'pull_request',
      jobWorkflow: { repository: FRAMEWORK_REPOSITORY, path: '.github/workflows/_break-glass-lambda.yml', ref: FRAMEWORK_SHA, sha: FRAMEWORK_SHA },
      jti: 'jti-1',
      exp: NOW + 300,
      iat: NOW
    });
  });

  it('accepts only _break-glass-lambda.yml: the legacy in-job _source-security.yml is refused (Phase 3D)', async () => {
    const { verify } = verifier();
    assert.deepEqual(ALLOWED_JOB_WORKFLOW_PATHS, ['.github/workflows/_break-glass-lambda.yml']);
    await rejects(verify(token({ jobWorkflowPath: '.github/workflows/_source-security.yml' })), 'job_workflow_path_not_allowed');
  });
});

describe('verifyGithubOidcToken: issuer, audience, time', () => {
  for (const [name, overrides, code] of [
    ['wrong issuer', { iss: 'https://token.actions.githubusercontent.com.evil.example' }, 'issuer_mismatch'],
    ['enterprise-scoped issuer (not supported)', { iss: 'https://token.actions.githubusercontent.com/acme' }, 'issuer_mismatch'],
    ['missing issuer', { iss: undefined }, 'issuer_mismatch'],
    ['wrong audience (the AWS STS token)', { aud: 'sts.amazonaws.com' }, 'audience_mismatch'],
    ['audience array containing ours', { aud: ['ssd-break-glass', 'other'] }, 'audience_mismatch'],
    ['expired', { exp: NOW }, 'token_expired'],
    ['expired long ago', { iat: NOW - 4000, nbf: NOW - 4300, exp: NOW - 3700 }, 'token_expired'],
    ['not yet valid (nbf beyond skew)', { nbf: NOW + 120 }, 'token_not_yet_valid'],
    ['issued in the future', { iat: NOW + 120 }, 'token_issued_in_future'],
    ['too old even though exp is later', { iat: NOW - 301, exp: NOW + 100 }, 'token_too_old'],
    ['non-numeric exp', { exp: String(NOW + 300) }, 'claim_exp_invalid'],
    ['non-integer nbf', { nbf: 1.5 }, 'claim_nbf_invalid']
  ]) {
    it(`rejects: ${name}`, async () => {
      await rejects(verifier().verify(token(overrides)), code);
    });
  }

  it('tolerates the observed nbf = iat - 300 and an absent nbf', async () => {
    const { verify } = verifier();
    await verify(token({ nbf: NOW - 300 }));
    await verify(token({ nbf: undefined }));
  });
});

describe('verifyGithubOidcToken: required claims', () => {
  const REQUIRED = [
    'repository', 'repository_id', 'repository_owner_id', 'ref', 'sha', 'run_id', 'run_attempt',
    'event_name', 'job_workflow_ref', 'job_workflow_sha', 'jti', 'exp', 'iat'
  ];
  for (const name of REQUIRED) {
    it(`rejects a token without ${name}`, async () => {
      const incomplete = claims();
      delete incomplete[name];
      await rejects(verifier().verify(signToken(incomplete, { key: KEY })), `claim_${name}_invalid`);
    });
  }
  for (const [name, value] of [
    ['repository_id', 'owner/repo-a'],
    ['repository_id', '0'],
    ['repository_id', 1001],
    ['run_id', '12a'],
    ['run_attempt', ''],
    ['sha', 'abc123'],
    ['repository', 'no-slash'],
    ['jti', 'x'.repeat(300)]
  ]) {
    it(`rejects a malformed ${name} (${JSON.stringify(value).slice(0, 20)})`, async () => {
      await rejects(verifier().verify(token({ [name]: value })), `claim_${name}_invalid`);
    });
  }
});

describe('verifyGithubOidcToken: signature and algorithm', () => {
  it('rejects alg none without fetching any key', async () => {
    const v = verifier();
    await rejects(v.verify(unsignedToken(claims(), KEY.kid)), 'token_malformed');
    // Even with a non-empty "signature", alg none is refused by name.
    const [h, p] = unsignedToken(claims(), KEY.kid).split('.');
    await rejects(v.verify(`${h}.${p}.AAAA`), 'alg_not_allowed');
    assert.equal(v.jwksFetch.calls.length, 0);
  });

  it('rejects HS256 signed with the public key (algorithm confusion)', async () => {
    await rejects(verifier().verify(hs256Token(claims(), KEY)), 'alg_not_allowed');
  });

  for (const alg of ['RS512', 'PS256', 'ES256', 'rs256', 'RS256 ']) {
    it(`rejects alg ${JSON.stringify(alg)}`, async () => {
      await rejects(verifier().verify(signToken(claims(), { key: KEY, alg })), 'alg_not_allowed');
    });
  }

  it('rejects a token signed by a different RSA key under a trusted kid', async () => {
    await rejects(verifier().verify(token({}, ATTACKER)), 'signature_invalid');
  });

  it('rejects a token whose payload was altered after signing (repo A re-labelled repo B)', async () => {
    const [h, , s] = token().split('.');
    const forged = Buffer.from(JSON.stringify(claims({ repo: REPO_B }))).toString('base64url');
    await rejects(verifier().verify(`${h}.${forged}.${s}`), 'signature_invalid');
  });

  it('rejects a truncated or swapped signature', async () => {
    const [h, p, s] = token().split('.');
    await rejects(verifier().verify(`${h}.${p}.${s.slice(0, -4)}`), 'signature_invalid');
    const [, , other] = token({ jti: 'other' }).split('.');
    await rejects(verifier().verify(`${h}.${p}.${other}`), 'signature_invalid');
  });

  for (const parameter of ['jku', 'x5u', 'jwk', 'x5c', 'crit']) {
    it(`rejects a header carrying ${parameter} and never fetches it`, async () => {
      const v = verifier();
      const header = { [parameter]: parameter === 'jwk' ? ATTACKER.jwk : 'https://evil.example/jwks' };
      await rejects(v.verify(signToken(claims(), { key: ATTACKER, header })), 'header_parameter_not_allowed');
      assert.deepEqual(v.jwksFetch.foreignUrls, []);
      assert.equal(v.jwksFetch.calls.length, 0);
    });
  }

  it('rejects typ other than JWT', async () => {
    await rejects(verifier().verify(signToken(claims(), { key: KEY, header: { typ: 'at+jwt' } })), 'typ_not_allowed');
  });

  for (const [name, value, code] of [
    ['absent', undefined, 'token_missing'],
    ['empty', '', 'token_missing'],
    ['not a string', { token: 'x' }, 'token_missing'],
    ['two segments', 'a.b', 'token_malformed'],
    ['four segments', 'a.b.c.d', 'token_malformed'],
    ['non-base64url characters', 'a+b.c/d.e=f', 'token_malformed'],
    ['oversized', `${'a'.repeat(9000)}.b.c`, 'token_malformed'],
    ['header not JSON', 'bm90LWpzb24.e30.c2ln', 'header_malformed'],
    ['header a JSON array', `${Buffer.from('[1]').toString('base64url')}.e30.c2ln`, 'header_malformed']
  ]) {
    it(`rejects a malformed JWT: ${name}`, async () => {
      await rejects(verifier().verify(value), code);
    });
  }

  it('rejects a signed payload that is not a JSON object', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: KEY.kid, typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from('"just a string"').toString('base64url');
    const signature = sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), KEY.privateKey).toString('base64url');
    await rejects(verifier().verify(`${header}.${payload}.${signature}`), 'payload_malformed');
  });
});

describe('verifyGithubOidcToken: job_workflow_ref is parsed, not prefix-matched', () => {
  for (const [name, overrides, code] of [
    ['another repository', { jobWorkflowRepository: 'attacker/ssd-security-framework' }, 'job_workflow_repository_not_allowed'],
    ['a look-alike repository', { jobWorkflowRepository: 'IamRitz/ssd-security-framework-fork' }, 'job_workflow_repository_not_allowed'],
    ['the consumer repository itself', { jobWorkflowRepository: REPO_A.repository }, 'job_workflow_repository_not_allowed'],
    ['another framework workflow', { jobWorkflowPath: '.github/workflows/_source-scan.yml' }, 'job_workflow_path_not_allowed'],
    ['an allowlisted name in another directory', { jobWorkflowPath: 'evil/.github/workflows/_break-glass-lambda.yml' }, 'job_workflow_path_not_allowed'],
    ['a path suffix trick', { jobWorkflowPath: '.github/workflows/_break-glass-lambda.yml.evil' }, 'job_workflow_path_not_allowed'],
    ['the legacy in-job workflow', { jobWorkflowPath: '.github/workflows/_source-security.yml' }, 'job_workflow_path_not_allowed'],
    ['the path in another case', { jobWorkflowPath: '.github/workflows/_Break-glass-lambda.yml' }, 'job_workflow_path_not_allowed'],
    ['an empty ref', { jobWorkflowRefName: '' }, 'job_workflow_ref_malformed'],
    ['a ref with whitespace', { jobWorkflowRefName: 'refs/heads/a b' }, 'job_workflow_ref_malformed'],
    ['a ref with a control character', { jobWorkflowRefName: 'refs/heads/a\nb' }, 'job_workflow_ref_malformed'],
    ['an over-long ref', { jobWorkflowRefName: `refs/heads/${'x'.repeat(250)}` }, 'job_workflow_ref_malformed'],
    ['a short job_workflow_sha', { jobWorkflowSha: 'f'.repeat(7), jobWorkflowRefName: FRAMEWORK_SHA }, 'claim_job_workflow_sha_invalid'],
    ['an uppercase job_workflow_sha', { jobWorkflowSha: 'F'.repeat(40), jobWorkflowRefName: FRAMEWORK_SHA }, 'claim_job_workflow_sha_invalid'],
    ['a job_workflow_sha that is a ref', { jobWorkflowSha: 'refs/tags/v1', jobWorkflowRefName: 'refs/tags/v1' }, 'claim_job_workflow_sha_invalid'],
    ['a missing job_workflow_sha', { job_workflow_sha: undefined }, 'claim_job_workflow_sha_invalid']
  ]) {
    it(`rejects ${name}`, async () => {
      await rejects(verifier().verify(token(overrides)), code);
    });
  }

  // Phase 3D: the commit is job_workflow_sha; the ref part is how the caller
  // spelled it, recorded and never authorized.
  for (const [name, refName] of [
    ['a tag ref', 'refs/tags/v1'],
    ['a branch ref', 'refs/heads/main'],
    ['a ref that is a different SHA', 'e'.repeat(40)]
  ]) {
    it(`accepts ${name}: the authorized commit is still job_workflow_sha`, async () => {
      const identity = await verifier().verify(token({ jobWorkflowRefName: refName }));
      assert.equal(identity.jobWorkflow.sha, FRAMEWORK_SHA);
      assert.equal(identity.jobWorkflow.ref, refName);
    });
  }

  it('compares the framework repository case-insensitively', async () => {
    const identity = await verifier().verify(token({ jobWorkflowRepository: 'iamritz/SSD-Security-Framework' }));
    assert.equal(identity.jobWorkflow.sha, FRAMEWORK_SHA);
  });

  it('parses into exactly repository, path and ref', () => {
    assert.deepEqual(
      parseJobWorkflowRef(`IamRitz/ssd-security-framework/.github/workflows/_break-glass-lambda.yml@${FRAMEWORK_SHA}`),
      { repository: 'IamRitz/ssd-security-framework', path: '.github/workflows/_break-glass-lambda.yml', ref: FRAMEWORK_SHA }
    );
    assert.equal(parseJobWorkflowRef('IamRitz/ssd-security-framework/.github/workflows/_break-glass-lambda.yml@refs/tags/v1').ref, 'refs/tags/v1');
    assert.throws(() => parseJobWorkflowRef('IamRitz/ssd-security-framework/.github/workflows/_break-glass-lambda.yml'), IdentityRejected);
    assert.throws(() => parseJobWorkflowRef('IamRitz/ssd-security-framework'), IdentityRejected);
  });
});

// =================================================================================
describe('JWKS: fixed location, bounded cache, fail closed', () => {
  it('fetches only the fixed GitHub JWKS URL, once, and caches it', async () => {
    const v = verifier();
    await v.verify(token());
    await v.verify(token());
    assert.deepEqual(v.jwksFetch.calls, [GITHUB_OIDC_JWKS_URL]);
  });

  it('refreshes after the TTL and never serves an expired cache', async () => {
    let clock = NOW_MS;
    const jwksFetch = fakeJwksFetch([KEY]);
    const jwks = createJwksCache({ fetchImpl: jwksFetch.fetchImpl, now: () => clock });
    await jwks.getKey(KEY.kid);
    clock += JWKS_TTL_MS;
    jwksFetch.fail = true;
    await rejects(jwks.getKey(KEY.kid), 'jwks_unavailable');
    assert.equal(jwksFetch.calls.length, 2);
  });

  it('a key rotated in is found by one forced refresh', async () => {
    let clock = NOW_MS;
    const jwksFetch = fakeJwksFetch([KEY]);
    const jwks = createJwksCache({ fetchImpl: jwksFetch.fetchImpl, now: () => clock });
    await jwks.getKey(KEY.kid);
    jwksFetch.keys = [KEY, ROTATED];
    clock += JWKS_MIN_REFRESH_INTERVAL_MS;
    await jwks.getKey(ROTATED.kid);
    assert.equal(jwksFetch.calls.length, 2);
  });

  it('an unknown kid forces at most one refresh per interval, then fails closed', async () => {
    let clock = NOW_MS;
    const jwksFetch = fakeJwksFetch([KEY]);
    const jwks = createJwksCache({ fetchImpl: jwksFetch.fetchImpl, now: () => clock });
    await jwks.getKey(KEY.kid);
    clock += JWKS_MIN_REFRESH_INTERVAL_MS;
    await rejects(jwks.getKey('attacker-kid-1'), 'unknown_kid');
    assert.equal(jwksFetch.calls.length, 2, 'one forced refresh');
    for (let i = 2; i < 50; i += 1) await rejects(jwks.getKey(`attacker-kid-${i}`), 'unknown_kid');
    assert.equal(jwksFetch.calls.length, 2, 'a stream of invented kids cannot amplify fetches');
  });

  it('an unknown kid on first use (cold cache) fetches once and fails closed', async () => {
    const v = verifier();
    await rejects(v.verify(token({}, ROTATED)), 'unknown_kid');
    assert.equal(v.jwksFetch.calls.length, 1);
  });

  it('concurrent cold-cache lookups share one fetch', async () => {
    const v = verifier();
    await Promise.all(Array.from({ length: 10 }, () => v.verify(token())));
    assert.equal(v.jwksFetch.calls.length, 1);
  });

  for (const [name, fail, code] of [
    ['network failure', true, 'jwks_unavailable'],
    ['HTTP 503', 'http', 'jwks_unavailable']
  ]) {
    it(`JWKS unavailable (${name}) fails closed`, async () => {
      await rejects(verifier({ fail }).verify(token()), code);
    });
  }

  it('a malformed or oversized JWKS document fails closed', async () => {
    for (const body of ['not json', '{"keys":"nope"}', JSON.stringify({ keys: [] }).padEnd(70_000, ' ')]) {
      const jwks = createJwksCache({ fetchImpl: async () => ({ ok: true, text: async () => body }), now: () => NOW_MS });
      await assert.rejects(jwks.getKey(KEY.kid), IdentityRejected);
    }
  });

  it('skips keys it must not trust: undersized RSA, wrong use, wrong alg, non-RSA', async () => {
    const encKey = { ...ROTATED.jwk, kid: 'enc', use: 'enc' };
    const rs512 = { ...ROTATED.jwk, kid: 'rs512', alg: 'RS512' };
    const ec = { kty: 'EC', kid: 'ec', crv: 'P-256', x: 'x', y: 'y' };
    const v = verifier({ keys: [SMALL, encKey, rs512, ec, KEY] });
    await rejects(v.verify(token({}, SMALL)), 'unknown_kid');
    for (const kid of ['enc', 'rs512', 'ec']) {
      await rejects(v.verify(signToken(claims(), { key: { ...ROTATED, kid } })), 'unknown_kid');
    }
    await v.verify(token()); // the good key in the same document still works
  });

  it('fetches with redirects refused', async () => {
    let options;
    const jwks = createJwksCache({
      fetchImpl: async (_url, init) => {
        options = init;
        return { ok: true, text: async () => JSON.stringify({ keys: [KEY.jwk] }) };
      },
      now: () => NOW_MS
    });
    await jwks.getKey(KEY.kid);
    assert.equal(options.redirect, 'error');
  });
});

// =================================================================================
describe('pull-request binding: the PR number comes from the verified ref', () => {
  const identity = (eventName, ref) => ({ eventName, ref });
  it('derives N from refs/pull/N/merge on pull_request', () => {
    assert.equal(pullRequestFromIdentity(identity('pull_request', 'refs/pull/51/merge')), '51');
  });
  for (const eventName of ['workflow_dispatch', 'push', 'schedule', 'pull_request_target', 'workflow_run', 'merge_group']) {
    it(`refuses a production request from ${eventName}`, () => {
      assert.throws(() => pullRequestFromIdentity(identity(eventName, 'refs/pull/51/merge')), { code: 'event_not_allowed' });
    });
  }
  for (const ref of ['refs/pull/51/head', 'refs/pull/0/merge', 'refs/pull/051/merge', 'refs/pull/abc/merge',
    'refs/pull/51/merge/x', 'refs/pull//merge', 'refs/heads/main', 'refs/pull/51/merge ', '']) {
    it(`refuses a malformed PR ref ${JSON.stringify(ref)}`, () => {
      assert.throws(() => pullRequestFromIdentity(identity('pull_request', ref)), { code: 'pull_request_ref_malformed' });
    });
  }
});

// =================================================================================
// Broker integration: the real verifier, store, handler and decision path.

const SIGNING_SECRET = 'identity-test-signing-secret';
const RESPONSE_URL = 'https://hooks.slack.com/actions/T0/1/abc';
const APPROVERS = { [REPO_A.repositoryId]: [SLACK_A], [REPO_B.repositoryId]: [SLACK_B] };

const payloadFor = (repo = REPO_A, { pullRequest = '51', sha = SHA_A, ...context } = {}) => ({
  schemaVersion: 1,
  gateDigest: 'a'.repeat(64),
  timeoutSeconds: 900,
  context: { repository: repo.repository, commitSha: sha, pullRequest, ...context },
  findings: [{ source: 'semgrep', id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }]
});

function brokerEnv(options = {}) {
  const { approvers = approversById(APPROVERS), events = null } = options;
  const framework = options.framework ?? fakeFrameworkPolicy({ events });
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
    slackChannelId: 'C',
    now,
    log: (entry) => logs.push(entry)
  });
  const ci = createCiHandler({ getBroker: async () => broker });
  const enqueued = [];
  const interactions = createInteractionsHandler({ getBroker: async () => broker, enqueue: async (job) => enqueued.push(job) });
  const tokenFor = (overrides = {}) => signToken(githubClaims({ nowSeconds: Math.floor(clock / 1000), ...overrides }), { key: KEY });
  return {
    dynamo, store, slack, github, logs, ci, interactions, enqueued, broker, failNext, framework,
    advance: (ms) => (clock += ms),
    tokenFor,
    notify: (payload, identityToken) => ci({ action: 'notify', payload, identityToken }),
    status: (requestId, identityToken) => ci({ action: 'status', requestId, identityToken }),
    requests: () => [...dynamo.table.values()].filter((item) => item.doc),
    tokenRecords: () => [...dynamo.table.values()].filter((item) => item.kind?.S === 'oidc-jti')
  };
}

async function fileRequest(env, { repo = REPO_A, runId = '700001', runAttempt = '1', pullRequest = '51', sha = SHA_A } = {}) {
  const result = await env.notify(
    payloadFor(repo, { pullRequest, sha }),
    env.tokenFor({ repo, runId, runAttempt, pullRequest, sha })
  );
  assert.equal(result.statusCode, 201, JSON.stringify(result));
  return result.body.requestId;
}

function signedClick(requestId, userId, action = 'approve') {
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

describe('notify: identity is derived from the verified token', () => {
  it('stores the verified identity separately from display context, all derived from the token', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    const [item] = env.requests();
    const stored = JSON.parse(item.doc.S);
    assert.equal(stored.requestId, requestId);
    assert.deepEqual(stored.identity, {
      repositoryId: REPO_A.repositoryId,
      repository: REPO_A.repository,
      repositoryOwnerId: REPO_A.ownerId,
      pullRequest: '51',
      sha: SHA_A,
      ref: 'refs/pull/51/merge',
      eventName: 'pull_request',
      runId: '700001',
      runAttempt: '1',
      jobWorkflowRef: `IamRitz/ssd-security-framework/.github/workflows/_break-glass-lambda.yml@${FRAMEWORK_SHA}`,
      jobWorkflowSha: FRAMEWORK_SHA,
      jti: stored.identity.jti
    });
    assert.deepEqual(stored.context, {
      repository: REPO_A.repository,
      repositoryId: REPO_A.repositoryId,
      pullRequest: '51',
      commitSha: SHA_A,
      runId: '700001',
      runAttempt: '1',
      runUrl: `https://github.com/${REPO_A.repository}/actions/runs/700001`,
      ciSystem: null
    });
  });

  it('repo A cannot claim repo B: refused, nothing stored, nobody paged, no comment', async () => {
    const env = brokerEnv();
    const forged = await env.notify(payloadFor(REPO_B, { sha: SHA_A }), env.tokenFor({ repo: REPO_A }));
    assert.equal(forged.statusCode, 403);
    assert.match(forged.error, /payload_disagrees_with_token: repository/);
    assert.deepEqual(env.requests(), []);
    assert.equal(env.slack.posted.length, 0);
    assert.equal(env.github.length, 0);
    const rejection = env.logs.find((entry) => entry.event === 'identity_rejected');
    assert.equal(rejection.repositoryId, REPO_A.repositoryId, 'the log names who REALLY asked');
    assert.equal(rejection.claimedRepository, REPO_B.repository, 'and what they claimed');
  });

  for (const [field, context] of [
    ['repositoryId', { repositoryId: REPO_B.repositoryId }],
    ['commitSha', { sha: SHA_B }],
    ['pullRequest', { pullRequest: '52' }],
    ['runId', { runId: '999' }],
    ['runAttempt', { runAttempt: '2' }],
    ['runUrl', { runUrl: 'https://evil.example/phish' }],
    ['ciSystem', { ciSystem: '<https://evil.example|click me>' }]
  ]) {
    it(`a payload ${field} that disagrees with the token is refused`, async () => {
      const env = brokerEnv();
      const result = await env.notify(payloadFor(REPO_A, context), env.tokenFor());
      assert.equal(result.statusCode, 403, JSON.stringify(result));
      assert.match(result.error, new RegExp(`payload_disagrees_with_token: ${field}`));
      assert.deepEqual(env.requests(), []);
    });
  }

  it('a payload context field outside the contract is refused', async () => {
    const env = brokerEnv();
    const result = await env.notify(payloadFor(REPO_A, { identity: { repositoryId: REPO_B.repositoryId } }), env.tokenFor());
    assert.equal(result.statusCode, 403);
    assert.match(result.error, /payload_context_field_not_allowed: identity/);
  });

  it('agreeing optional context (as the v1 client sends it, plus run fields) is accepted', async () => {
    const env = brokerEnv();
    const payload = payloadFor(REPO_A, {
      runUrl: `https://github.com/${REPO_A.repository}/actions/runs/700001`,
      ciSystem: 'github-actions',
      repositoryId: REPO_A.repositoryId,
      runId: '700001',
      runAttempt: '1'
    });
    assert.equal((await env.notify(payload, env.tokenFor())).statusCode, 201);
  });

  for (const eventName of ['workflow_dispatch', 'push', 'schedule', 'pull_request_target']) {
    it(`a production request from ${eventName} is refused even with a pr_number in the payload`, async () => {
      const env = brokerEnv();
      const result = await env.notify(payloadFor(REPO_A), env.tokenFor({ eventName }));
      assert.equal(result.statusCode, 403);
      assert.match(result.error, /event_not_allowed/);
      assert.deepEqual(env.requests(), []);
    });
  }

  it('a malformed PR ref is refused', async () => {
    const env = brokerEnv();
    const result = await env.notify(payloadFor(REPO_A), env.tokenFor({ ref: 'refs/pull/51/head' }));
    assert.equal(result.statusCode, 403);
    assert.match(result.error, /pull_request_ref_malformed/);
  });

  for (const [name, identityToken, code] of [
    ['no token (a pre-3A client)', undefined, 'token_missing'],
    ['an unsigned token', unsignedToken(githubClaims({ nowSeconds: NOW })), 'token_malformed'],
    ['a token for the AWS audience', signToken(githubClaims({ nowSeconds: NOW, aud: 'sts.amazonaws.com' }), { key: KEY }), 'audience_mismatch'],
    ['a token from another workflow in the repository', signToken(githubClaims({ nowSeconds: NOW, jobWorkflowRepository: REPO_A.repository, jobWorkflowPath: '.github/workflows/security.yml' }), { key: KEY }), 'job_workflow_repository_not_allowed']
  ]) {
    it(`${name} is refused with 401 and changes nothing`, async () => {
      const env = brokerEnv();
      const result = await env.notify(payloadFor(REPO_A), identityToken);
      assert.deepEqual(result, { ok: false, statusCode: 401, error: `identity_rejected: ${code}` });
      assert.equal(env.dynamo.table.size, 0);
      assert.equal(env.slack.posted.length, 0);
    });
  }

  it('an expired (stale) token cannot be replayed later', async () => {
    const env = brokerEnv();
    const stale = env.tokenFor();
    env.advance(301_000);
    const result = await env.notify(payloadFor(REPO_A), stale);
    assert.equal(result.statusCode, 401);
    assert.match(result.error, /token_expired/);
  });

  it('a verifier that is not configured fails closed', async () => {
    const env = brokerEnv({ verifyIdentity: null });
    const result = await env.notify(payloadFor(REPO_A), 'a.b.c');
    assert.match(result.error, /verifier_not_configured/);
  });
});

describe('replay: a token is accepted once', () => {
  it('the same token cannot file a second request', async () => {
    const env = brokerEnv();
    const once = env.tokenFor();
    assert.equal((await env.notify(payloadFor(REPO_A), once)).statusCode, 201);
    const replay = await env.notify(payloadFor(REPO_A), once);
    assert.deepEqual(replay, { ok: false, statusCode: 401, error: 'identity_rejected: token_replayed' });
    assert.equal(env.requests().length, 1);
    assert.equal(env.slack.posted.length, 1);
  });

  it('20 concurrent uses of one token: exactly one succeeds', async () => {
    const env = brokerEnv();
    const once = env.tokenFor();
    const results = await Promise.all(Array.from({ length: 20 }, () => env.notify(payloadFor(REPO_A), once)));
    assert.equal(results.filter((r) => r.statusCode === 201).length, 1);
    assert.equal(results.filter((r) => r.error === 'identity_rejected: token_replayed').length, 19);
    assert.equal(env.requests().length, 1);
  });

  it('a notify token cannot be re-used for status, nor a status token twice', async () => {
    const env = brokerEnv();
    const notifyToken = env.tokenFor();
    const requestId = (await env.notify(payloadFor(REPO_A), notifyToken)).body.requestId;
    assert.match((await env.status(requestId, notifyToken)).error, /token_replayed/);
    const statusToken = env.tokenFor();
    assert.equal((await env.status(requestId, statusToken)).statusCode, 200);
    assert.match((await env.status(requestId, statusToken)).error, /token_replayed/);
  });

  it('a decided request cannot be re-requested with its token', async () => {
    const env = brokerEnv();
    const once = env.tokenFor();
    const requestId = (await env.notify(payloadFor(REPO_A), once)).body.requestId;
    await env.interactions(signedClick(requestId, SLACK_A));
    assert.match((await env.notify(payloadFor(REPO_A), once)).error, /token_replayed/);
  });

  it('the replay record is minimal, keyed by a hash of jti, and cleaned up only after the token is dead', async () => {
    const env = brokerEnv();
    const jti = 'replay-jti-1';
    await env.notify(payloadFor(REPO_A), env.tokenFor({ jti }));
    const [record] = env.tokenRecords();
    assert.deepEqual(Object.keys(record).sort(), ['action', 'kind', 'repositoryId', 'requestId', 'runAttempt', 'runId', 'tokenExp', 'ttl']);
    assert.match(record.requestId.S, /^oidc-jti:[0-9a-f]{64}$/);
    assert.ok(!record.requestId.S.includes(jti));
    assert.equal(Number(record.ttl.N), NOW + 300 + TOKEN_RECORD_GRACE_SECONDS);
    assert.ok(Number(record.ttl.N) > Number(record.tokenExp.N), 'never deleted while the token could still verify');
  });

  it('a replay record can never be read back as a request', async () => {
    const env = brokerEnv();
    await env.notify(payloadFor(REPO_A), env.tokenFor());
    const [record] = env.tokenRecords();
    assert.equal(await env.store.get(record.requestId.S), undefined, 'the store itself refuses to parse it');
    assert.equal(await env.broker.status(record.requestId.S, env.tokenFor()).then((r) => r.statusCode), 404);
    const click = await env.interactions(signedClick(record.requestId.S, SLACK_A));
    assert.notEqual(click.headers['x-break-glass-outcome'], 'claimed');
  });
});

// notify writes in this order, and nothing earlier writes at all:
//   1. payload shape check, token verification          (no writes)
//   2. replay claim: conditional PutItem on the jti     (first write)
//   3. identity binding: payload must agree with token  (no writes)
//   4. putPending: conditional PutItem, fresh UUID
//   5. Slack chat.postMessage, then setSlackRef
//      on failure: deletePending (rollback, best effort) -> 502
// The client never retries notify itself; a retry is a NEW token (new step or
// job attempt) or an AWS-CLI-level resend of the SAME event.
describe('notify ordering: replay claim -> request -> Slack, under failure', () => {
  const live = (env) => env.requests().filter((item) => item.slackTs && JSON.parse(item.doc.S).status === 'pending');

  it('a resend of the SAME event after success (lost response, transport retry) is refused, not duplicated', async () => {
    const env = brokerEnv();
    const event = { payload: payloadFor(REPO_A), token: env.tokenFor() };
    assert.equal((await env.notify(event.payload, event.token)).statusCode, 201);
    assert.match((await env.notify(event.payload, event.token)).error, /token_replayed/);
    assert.equal(env.requests().length, 1);
    assert.equal(env.slack.posted.length, 1);
  });

  it('a storage failure at putPending leaves no request; the spent token cannot be reused; a new token files exactly one', async () => {
    const env = brokerEnv();
    const first = env.tokenFor();
    env.failNext.put = 1;
    await assert.rejects(env.notify(payloadFor(REPO_A), first), /ProvisionedThroughputExceeded/);
    assert.deepEqual(env.requests(), []);
    assert.equal(env.slack.posted.length, 0, 'nobody was paged');
    assert.match((await env.notify(payloadFor(REPO_A), first)).error, /token_replayed/);
    assert.equal((await env.notify(payloadFor(REPO_A), env.tokenFor())).statusCode, 201);
    assert.equal(env.requests().length, 1);
    assert.equal(live(env).length, 1);
  });

  it('a Slack failure rolls the request back; a retry with a new token leaves exactly one request and one message', async () => {
    const env = brokerEnv();
    env.failNext.slack = 1;
    assert.equal((await env.notify(payloadFor(REPO_A), env.tokenFor())).statusCode, 502);
    assert.deepEqual(env.requests(), []);
    assert.equal((await env.notify(payloadFor(REPO_A), env.tokenFor())).statusCode, 201);
    assert.equal(env.requests().length, 1);
    assert.equal(env.slack.posted.length, 1);
    assert.equal(env.tokenRecords().length, 2, 'both tokens are spent');
  });

  it('if the rollback itself fails, the orphan has no approval message, cannot be approved, and only expires', async () => {
    const env = brokerEnv();
    env.failNext.slack = 1;
    env.failNext.delete = 1;
    assert.equal((await env.notify(payloadFor(REPO_A), env.tokenFor())).statusCode, 502);
    const [orphan] = env.requests();
    assert.equal(orphan.slackTs, undefined, 'no Slack message was ever posted for it');
    assert.equal((await env.notify(payloadFor(REPO_A), env.tokenFor())).statusCode, 201);
    assert.equal(env.requests().length, 2, 'two stored items');
    assert.equal(live(env).length, 1, 'but exactly one request has an approval message');
    assert.equal(env.slack.posted.length, 1);
    // Its id was never published, so no click names it; it lapses at expiresAt
    // like any request (logical expiry is enforced in code, not by TTL).
    env.advance(901_000);
    const orphanId = orphan.requestId.S;
    assert.equal((await env.status(orphanId, env.tokenFor())).body.status, 'expired');
    assert.equal(JSON.parse(env.dynamo.table.get(orphanId).doc.S).status, 'expired');
  });

  it('a payload that disagrees still spends the token, so a corrected retry needs a new one', async () => {
    const env = brokerEnv();
    const once = env.tokenFor();
    assert.equal((await env.notify(payloadFor(REPO_A, { pullRequest: '52' }), once)).statusCode, 403);
    assert.match((await env.notify(payloadFor(REPO_A), once)).error, /token_replayed/);
    assert.deepEqual(env.requests(), []);
  });
});

describe('status: bound to the run that filed the request', () => {
  it('the filing run (same repository, run and attempt) can read it', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    const result = await env.status(requestId, env.tokenFor());
    assert.equal(result.statusCode, 200);
    assert.equal(result.body.status, 'pending');
  });

  for (const [name, claims] of [
    ['repo A token -> repo B request', { repo: REPO_A }],
    ['same repository, different run', { repo: REPO_B, runId: '700099' }],
    ['same run, different attempt', { repo: REPO_B, runAttempt: '2' }]
  ]) {
    it(`denied: ${name}`, async () => {
      const env = brokerEnv();
      const requestId = await fileRequest(env, { repo: REPO_B, sha: SHA_B, pullRequest: '9' });
      const result = await env.status(requestId, env.tokenFor({ ...claims, sha: SHA_B, pullRequest: '9' }));
      assert.deepEqual(result, { ok: false, statusCode: 403, error: 'request_identity_mismatch' });
      assert.ok(env.logs.some((entry) => entry.event === 'status_identity_mismatch' && entry.requestId === requestId));
    });
  }

  it('denied: the right run asking for a request it did not file', async () => {
    const env = brokerEnv();
    const mine = await fileRequest(env, { runId: '1' });
    const theirs = await fileRequest(env, { runId: '2' });
    assert.equal((await env.status(mine, env.tokenFor({ runId: '1' }))).statusCode, 200);
    assert.equal((await env.status(theirs, env.tokenFor({ runId: '1' }))).statusCode, 403);
  });

  it('status without a token is refused before any lookup', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    const before = env.dynamo.log.length;
    assert.deepEqual(await env.status(requestId, undefined), { ok: false, statusCode: 401, error: 'identity_rejected: token_missing' });
    assert.equal(env.dynamo.log.length, before);
  });

  it('an unknown or non-UUID request id is unknown', async () => {
    const env = brokerEnv();
    assert.equal((await env.status('00000000-0000-4000-8000-000000000000', env.tokenFor())).statusCode, 404);
    assert.equal((await env.status('../../etc', env.tokenFor())).statusCode, 404);
  });
});

describe('approval and audit: keyed by the verified repository_id', () => {
  it('the right approver decides, and the audit comment goes to the token repository and PR', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env, { pullRequest: '77' });
    const response = await env.interactions(signedClick(requestId, SLACK_A));
    assert.equal(response.headers['x-break-glass-outcome'], 'claimed');
    await env.interactions(env.enqueued.find((job) => job.kind === 'side-effects'));
    assert.deepEqual(env.github.map(({ repo, pr }) => ({ repo, pr })), [{ repo: REPO_A.repository, pr: '77' }]);
    assert.match(env.github[0].body, new RegExp(`Request: \`${requestId}\` \\(repository id ${REPO_A.repositoryId}, run 700001 attempt 1\\)`));
    const decided = env.logs.find((entry) => entry.event === 'decided');
    assert.equal(decided.repositoryId, REPO_A.repositoryId);
  });

  it('an approver authorized only for another repository is a no-op', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    const response = await env.interactions(signedClick(requestId, SLACK_B));
    assert.equal(response.headers['x-break-glass-outcome'], 'unauthorized');
    assert.equal(JSON.parse(env.requests()[0].doc.S).status, 'pending');
    assert.ok(env.logs.some((entry) => entry.event === 'unauthorized' && entry.repositoryId === REPO_A.repositoryId));
  });

  it('a request stored before this hardening (no identity) is unusable: no status, no approval, no comment', async () => {
    const env = brokerEnv();
    const requestId = '11111111-1111-4111-8111-111111111111';
    const legacy = {
      requestId,
      gateDigest: 'a'.repeat(64),
      status: 'pending',
      createdAt: new Date(NOW_MS).toISOString(),
      expiresAt: new Date(NOW_MS + 900_000).toISOString(),
      context: { repository: REPO_A.repository, pullRequest: '51', commitSha: SHA_A },
      findings: []
    };
    env.dynamo.table.set(requestId, {
      requestId: { S: requestId },
      status: { S: 'pending' },
      expiresAt: { S: legacy.expiresAt },
      doc: { S: JSON.stringify(legacy) }
    });
    assert.equal((await env.status(requestId, env.tokenFor())).statusCode, 403);
    assert.equal((await env.interactions(signedClick(requestId, SLACK_A))).headers['x-break-glass-outcome'], 'unauthorized');
    // Even if such a request were somehow decided, the audit comment refuses it.
    env.dynamo.table.set(requestId, {
      ...env.dynamo.table.get(requestId),
      status: { S: 'approved' },
      doc: { S: JSON.stringify({ ...legacy, status: 'approved' }) }
    });
    await assert.rejects(env.broker.runFollowUp({ kind: 'side-effects', requestId }), /without verified identity/);
    assert.equal(env.github.length, 0);
  });
});

describe('framework commit policy: checked after verification, before the token is spent (Phase 3D)', () => {
  const OTHER_SHA = 'e'.repeat(40);

  it('notify: verify -> policy -> replay claim -> request -> Slack, in that order', async () => {
    const events = [];
    const env = brokerEnv({ events });
    await fileRequest(env);
    assert.deepEqual(events, ['verify', 'policy', 'PutItem:jti', 'PutItem', 'slack', 'UpdateItem']);
    assert.deepEqual(env.framework.requested, ['/ssd/break-glass/production/governance/allowed-framework-shas']);
  });

  it('notify: a commit not in the set is 403 and writes nothing, pages nobody, spends no token', async () => {
    const events = [];
    const env = brokerEnv({ events });
    env.framework.allow([OTHER_SHA]);
    const identityToken = env.tokenFor();
    const refused = await env.notify(payloadFor(REPO_A), identityToken);
    assert.deepEqual(refused, { ok: false, statusCode: 403, error: 'framework_rejected: framework_sha_not_allowed' });
    assert.deepEqual(events, ['verify', 'policy']);
    assert.equal(env.dynamo.table.size, 0, 'no request and no replay record');
    assert.equal(env.slack.posted.length, 0);
    const logged = env.logs.find((entry) => entry.event === 'framework_rejected');
    assert.equal(logged.state, 'not_allowed');
    assert.equal(logged.frameworkSha, FRAMEWORK_SHA);
    assert.equal(logged.repositoryId, REPO_A.repositoryId);
    // The token was not spent: once the commit is admitted, the SAME token works.
    env.framework.allow([FRAMEWORK_SHA]);
    assert.equal((await env.notify(payloadFor(REPO_A), identityToken)).statusCode, 201);
  });

  it('an empty set admits nothing', async () => {
    const env = brokerEnv();
    env.framework.allow([]);
    assert.equal((await env.notify(payloadFor(REPO_A), env.tokenFor())).error, 'framework_rejected: framework_sha_not_allowed');
  });

  const unavailable = {
    absent: (env) => env.framework.remove(),
    malformed: (env) => env.framework.set('["not","canonical"]'),
    'malformed (another environment\'s value)': (env) => env.framework.set(JSON.stringify({ schemaVersion: 1, environment: 'synthetic', shas: [FRAMEWORK_SHA] })),
    'malformed (not a String parameter)': (env) => env.framework.set({ Type: 'SecureString', Value: JSON.stringify({ schemaVersion: 1, environment: 'production', shas: [FRAMEWORK_SHA] }) }),
    unverified: (env) => env.framework.set(Object.assign(new Error('denied'), { name: 'AccessDeniedException' }))
  };
  for (const [name, arrange] of Object.entries(unavailable)) {
    it(`notify: a policy that is ${name} is 503 and writes nothing`, async () => {
      const env = brokerEnv();
      arrange(env);
      const refused = await env.notify(payloadFor(REPO_A), env.tokenFor());
      assert.equal(refused.statusCode, 503);
      assert.equal(refused.error, `framework_policy_unavailable: ${name.split(' ')[0]}`);
      assert.equal(env.dynamo.table.size, 0);
      assert.equal(env.slack.posted.length, 0);
    });
  }

  for (const [name, frameworkPolicy, state] of [
    ['no policy configured', undefined, 'misconfigured'],
    ['a policy whose check throws', { check: async () => { throw new Error('boom'); } }, 'unverified'],
    ['a policy answering an unknown state', { check: async () => ({ state: 'ALLOWED' }) }, 'misconfigured'],
    ['a policy answering nothing', { check: async () => undefined }, 'misconfigured'],
    ['a policy answering a truthy non-object', { check: async () => 'allowed' }, 'misconfigured']
  ]) {
    it(`notify: ${name} never becomes allowed (${state})`, async () => {
      const env = brokerEnv({ frameworkPolicy });
      const refused = await env.notify(payloadFor(REPO_A), env.tokenFor());
      assert.equal(refused.error, `framework_policy_unavailable: ${state}`);
      assert.equal(env.dynamo.table.size, 0);
    });
  }

  it('status: checked on EVERY call; a removed commit is refused without spending the token', async () => {
    const events = [];
    const env = brokerEnv({ events });
    const requestId = await fileRequest(env);
    events.length = 0;
    assert.equal((await env.status(requestId, env.tokenFor())).statusCode, 200);
    assert.deepEqual(events.slice(0, 3), ['verify', 'policy', 'PutItem:jti']);
    env.framework.allow([OTHER_SHA]);
    const records = env.tokenRecords().length;
    events.length = 0;
    const statusToken = env.tokenFor();
    assert.deepEqual(await env.status(requestId, statusToken), { ok: false, statusCode: 403, error: 'framework_rejected: framework_sha_not_allowed' });
    assert.deepEqual(events, ['verify', 'policy']);
    assert.equal(env.tokenRecords().length, records, 'the refused status token was not spent');
    env.framework.remove();
    assert.equal((await env.status(requestId, statusToken)).error, 'framework_policy_unavailable: absent');
  });

  it('a tag-spelled call is decided by the commit it resolved to', async () => {
    const env = brokerEnv();
    const viaTag = (sha) => env.tokenFor({ jobWorkflowRefName: 'refs/tags/v1', jobWorkflowSha: sha });
    assert.equal((await env.notify(payloadFor(REPO_A), viaTag(FRAMEWORK_SHA))).statusCode, 201);
    // @v1 moved to a commit nobody admitted:
    assert.equal((await env.notify(payloadFor(REPO_A), viaTag(OTHER_SHA))).error, 'framework_rejected: framework_sha_not_allowed');
    const stored = JSON.parse(env.requests()[0].doc.S);
    assert.equal(stored.identity.jobWorkflowRef, 'IamRitz/ssd-security-framework/.github/workflows/_break-glass-lambda.yml@refs/tags/v1');
    assert.equal(stored.identity.jobWorkflowSha, FRAMEWORK_SHA);
  });
});

describe('framework commit policy at click time: removing a commit revokes its pending requests', () => {
  const OTHER_SHA = 'e'.repeat(40);
  const status = (env) => JSON.parse(env.requests()[0].doc.S).status;

  it('an approver click on a revoked commit is refused before any claim; re-admitting restores it', async () => {
    const events = [];
    const env = brokerEnv({ events });
    const requestId = await fileRequest(env);
    env.framework.allow([OTHER_SHA]);
    events.length = 0;
    const response = await env.interactions(signedClick(requestId, SLACK_A));
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers['x-break-glass-outcome'], 'revoked');
    assert.ok(events.includes('policy'));
    assert.ok(!events.includes('UpdateItem'), 'no claim, no state transition');
    assert.equal(status(env), 'pending');
    assert.ok(!env.enqueued.some((job) => job.kind === 'side-effects'), 'no audit comment, no Slack update');
    assert.match(env.enqueued.find((job) => job.kind === 'ephemeral').text, /no longer allowed/);
    const logged = env.logs.find((entry) => entry.event === 'framework_revoked');
    assert.deepEqual([logged.state, logged.frameworkSha, logged.userId], ['not_allowed', FRAMEWORK_SHA, SLACK_A]);

    env.framework.allow([FRAMEWORK_SHA]);
    events.length = 0;
    assert.equal((await env.interactions(signedClick(requestId, SLACK_A))).headers['x-break-glass-outcome'], 'claimed');
    assert.ok(events.indexOf('policy') < events.indexOf('UpdateItem'), 'the commit is checked before the claim');
  });

  for (const [name, arrange] of [
    ['absent', (env) => env.framework.remove()],
    ['unverified', (env) => env.framework.set(Object.assign(new Error('slow'), { name: 'TimeoutError' }))],
    ['malformed', (env) => env.framework.set('{}')]
  ]) {
    it(`a click while the policy is ${name} is revoked, not decided`, async () => {
      const env = brokerEnv();
      const requestId = await fileRequest(env);
      arrange(env);
      assert.equal((await env.interactions(signedClick(requestId, SLACK_A))).headers['x-break-glass-outcome'], 'revoked');
      assert.equal(status(env), 'pending');
    });
  }

  it('a stored request without a recorded commit is never decided', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    const [item] = env.requests();
    const doc = JSON.parse(item.doc.S);
    delete doc.identity.jobWorkflowSha;
    item.doc = { S: JSON.stringify(doc) };
    assert.equal((await env.interactions(signedClick(requestId, SLACK_A))).headers['x-break-glass-outcome'], 'revoked');
    assert.equal(status(env), 'pending');
  });

  it('a non-approver learns nothing about the policy: unauthorized comes first', async () => {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    env.framework.allow([OTHER_SHA]);
    assert.equal((await env.interactions(signedClick(requestId, SLACK_B))).headers['x-break-glass-outcome'], 'unauthorized');
    assert.ok(!env.logs.some((entry) => entry.event === 'framework_revoked'));
  });
});

describe('`revoked` never reaches CI as anything but a non-approval (Phase 3D)', () => {
  // `revoked` is an interaction OUTCOME only (the x-break-glass-outcome header
  // and an ephemeral reply). It is never stored: the request stays `pending`.
  // CI then either cannot read status (the commit is refused) or keeps seeing
  // `pending` until its timeout. Every CI-side reader is a closed set in which
  // only `approved` succeeds; these tests drive the real ones.
  const OTHER_SHA = 'e'.repeat(40);
  const DIGEST = 'a'.repeat(64);
  const PREFLIGHT = { accepted: true, gateDigest: DIGEST, synthetic: false, route: 'production' };
  const approvedFacts = {
    sourceResult: 'failure', verdict: 'BLOCK', gateMode: 'enforce', integrityTrusted: 'true',
    breakGlassEligible: 'true', breakGlassDelegated: 'true', secretScanResult: 'success',
    dependencyScanResult: 'success', sastResult: 'success', sourceGateDigest: DIGEST,
    breakGlassResult: 'success', breakGlassDecision: 'approved', breakGlassDelivered: 'true', breakGlassGateDigest: DIGEST
  };
  const sourceGate = { status: 'failure', verdict: 'BLOCK', gate_mode: 'enforce', integrity_trusted: 'true', break_glass_eligible: 'true', gate_digest: DIGEST };
  const approvedEvidence = { status: 'success', decision: 'approved', request_delivered: 'true', gate_digest: DIGEST, delegated: 'true' };

  async function revokedRequest() {
    const env = brokerEnv();
    const requestId = await fileRequest(env);
    env.framework.allow([OTHER_SHA]);
    const click = await env.interactions(signedClick(requestId, SLACK_A));
    assert.equal(click.headers['x-break-glass-outcome'], 'revoked');
    const stored = JSON.parse(env.requests()[0].doc.S);
    assert.equal(stored.status, 'pending', 'revoked is never stored');
    assert.ok(!('decidedAt' in stored) && !('approver' in stored));
    return { env, requestId };
  }
  const poller = (env, requestId, { timeoutSeconds = 60 } = {}) => {
    let clock = 0;
    return pollBreakGlass({
      request: { requestId, gateDigest: DIGEST },
      invoke: (event) => env.ci(event),
      mintIdentityToken: async () => env.tokenFor(),
      timeoutSeconds,
      intervalMilliseconds: 10_000,
      now: () => clock,
      sleep: async (ms) => {
        clock += ms;
      }
    });
  };

  it('still revoked: the CI poll is refused, the result is error, the gate and conformance stay BLOCK', async () => {
    const { env, requestId } = await revokedRequest();
    let pollError;
    await poller(env, requestId).catch((error) => {
      pollError = error;
    });
    assert.match(pollError?.message ?? '', /framework_rejected: framework_sha_not_allowed/);
    assert.equal(describePollOutcome({ error: pollError }).approved, false);
    const result = deriveBreakGlassResult({
      preflightOutcome: 'success', requestOutcome: 'success', pollOutcome: 'failure',
      preflight: PREFLIGHT, request: { requestId, gateDigest: DIGEST }, decision: null
    });
    assert.deepEqual([result.decisionStatus, result.controlResult], ['error', 'failure']);
    assert.equal(decideSourceGate({ ...approvedFacts, breakGlassResult: 'failure', breakGlassDecision: result.decisionStatus }).outcome, 'block');
    assert.equal(explainBreakGlass({ ...approvedEvidence, status: 'failure', decision: result.decisionStatus }, sourceGate).passed, false);
  });

  it('re-admitted after a revoked click: status is still pending, and an undecided poll ends in timeout', async () => {
    const { env, requestId } = await revokedRequest();
    env.framework.allow([FRAMEWORK_SHA]);
    const polled = await poller(env, requestId, { timeoutSeconds: 30 });
    assert.equal(polled.status, 'timeout');
    assert.equal(describePollOutcome({ result: polled }).approved, false);
    const result = deriveBreakGlassResult({
      preflightOutcome: 'success', requestOutcome: 'success', pollOutcome: 'failure',
      preflight: PREFLIGHT, request: { requestId, gateDigest: DIGEST }, decision: polled
    });
    assert.deepEqual([result.decisionStatus, result.controlResult], ['timeout', 'failure']);
  });

  it('defence in depth: a `revoked` status, wherever it came from, is never success in any reader', async () => {
    // The poll's status set is closed: an unknown status is an error, not a wait or a pass.
    await assert.rejects(
      pollBreakGlass({
        request: { requestId: 'r-1', gateDigest: DIGEST },
        invoke: async () => ({ ok: true, body: { requestId: 'r-1', gateDigest: DIGEST, status: 'revoked' } }),
        mintIdentityToken: async () => 'token',
        sleep: async () => {}
      }),
      /unsupported break-glass status revoked/
    );
    assert.equal(describePollOutcome({ result: { requestId: 'r-1', status: 'revoked' } }).approved, false);
    // The result switch defaults to error, even with a successful poll step.
    const result = deriveBreakGlassResult({
      preflightOutcome: 'success', requestOutcome: 'success', pollOutcome: 'success',
      preflight: PREFLIGHT, request: { requestId: 'r-1', gateDigest: DIGEST },
      decision: { requestId: 'r-1', gateDigest: DIGEST, status: 'revoked', approver: { username: 'x' } }
    });
    assert.deepEqual([result.decisionStatus, result.controlResult], ['error', 'failure']);
    // The final gate and conformance accept only `approved`, even with every other fact in place.
    assert.equal(decideSourceGate(approvedFacts).outcome, 'overridden-block', 'fixture sanity: approved overrides');
    assert.equal(decideSourceGate({ ...approvedFacts, breakGlassDecision: 'revoked' }).outcome, 'block');
    assert.equal(explainBreakGlass(approvedEvidence, { ...sourceGate, override: 'approved' }).passed, true, 'fixture sanity: approved passes');
    assert.equal(explainBreakGlass({ ...approvedEvidence, decision: 'revoked' }, { ...sourceGate, override: 'approved' }).passed, false);
  });
});

describe('no token leaks into state, logs or responses', () => {
  it('the token never appears in a stored item, a log entry or a response', async () => {
    const env = brokerEnv();
    const notifyToken = env.tokenFor();
    const notified = await env.notify(payloadFor(REPO_A), notifyToken);
    const statusToken = env.tokenFor();
    const polled = await env.status(notified.body.requestId, statusToken);
    const rejectedToken = env.tokenFor({ aud: 'wrong' });
    const rejected = await env.notify(payloadFor(REPO_A), rejectedToken);
    const forgedToken = env.tokenFor();
    const forged = await env.notify(payloadFor(REPO_B), forgedToken);
    await env.notify(payloadFor(REPO_A), notifyToken); // replay
    const everything = JSON.stringify({
      table: [...env.dynamo.table.values()],
      logs: env.logs,
      responses: [notified, polled, rejected, forged],
      slack: env.slack
    });
    for (const secret of [notifyToken, statusToken, rejectedToken, forgedToken]) {
      for (const segment of secret.split('.')) assert.ok(!everything.includes(segment), 'no token segment persisted or logged');
    }
  });
});

// =================================================================================
describe('the OIDC boundary is unchanged by Phase 3A', () => {
  const read = (path) => readFileSync(path, 'utf8');
  const grants = (text) => text.split('\n').filter((line) => /^\s*id-token:\s*write\s*$/.test(line)).length;

  it('_source-scan.yml still grants no id-token anywhere', () => {
    const text = read('.github/workflows/_source-scan.yml');
    assert.equal(grants(text), 0);
    assert.doesNotMatch(text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n'), /id-token/);
  });

  it('_break-glass-lambda.yml keeps exactly its one dedicated grant', () => {
    assert.equal(grants(read('.github/workflows/_break-glass-lambda.yml')), 1);
  });

  it('legacy _source-security.yml keeps exactly its one existing grant', () => {
    assert.equal(grants(read('.github/workflows/_source-security.yml')), 1);
  });

  it('no workflow references the identity-token minter directly; only the notify/poll scripts do', () => {
    for (const file of ['_source-scan.yml', '_source-security.yml']) {
      assert.doesNotMatch(read(`.github/workflows/${file}`), /break-glass-oidc-token|ACTIONS_ID_TOKEN_REQUEST/);
    }
    assert.doesNotMatch(read('.github/workflows/_break-glass-lambda.yml'), /break-glass-oidc-token/);
  });

  it('_break-glass-lambda.yml mints inline only in its binding step, and only for the inert audience', () => {
    // Phase 3D: the first step reads job_workflow_sha from a token whose
    // audience neither AWS (sts.amazonaws.com) nor the broker (ssd-break-glass)
    // accepts. Broker tokens still come only from the notify/poll scripts.
    const text = read('.github/workflows/_break-glass-lambda.yml');
    const bindStart = text.indexOf("      - name: Bind to this workflow's own framework commit\n");
    const bindEnd = text.indexOf('\n      - name: ', bindStart + 1);
    assert.ok(bindStart > 0 && bindEnd > bindStart);
    const uses = [...text.matchAll(/ACTIONS_ID_TOKEN_REQUEST/g)].map((match) => match.index);
    assert.ok(uses.length > 0 && uses.every((at) => at > bindStart && at < bindEnd), 'the OIDC request variables are read only by the binding step');
    const binding = text.slice(bindStart, bindEnd).split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
    assert.match(binding, /\n {10}BINDING_AUDIENCE: ssd-framework-binding\n/);
    assert.doesNotMatch(binding, /ssd-break-glass\b(?!-)|sts\.amazonaws\.com\n|audience=ssd-break-glass/);
  });

  it('the HTTP transport (the only one _source-scan.yml runs in-job) never mints a token', async () => {
    let minted = 0;
    const gate = {
      verdict: 'BLOCK',
      breakGlass: {
        eligible: true,
        eligibleFindings: [{ id: 'r', action: 'BLOCK', policyRule: 'sast.high_new' }],
        ineligibleFindings: []
      }
    };
    await notifyBreakGlass({
      gate,
      endpoint: 'https://broker.example/notify',
      sharedSecret: 's',
      context: { repository: 'a/b', commitSha: 'c' },
      fetchImpl: async () => ({ ok: true, json: async () => ({ requestId: 'r', status: 'pending' }) }),
      mintIdentityToken: async () => {
        minted += 1;
        return 'x.y.z';
      }
    });
    assert.equal(minted, 0);
  });
});
