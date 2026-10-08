// GitHub OIDC token fixtures for broker tests. Every RSA key is GENERATED at
// test time; no private key is ever committed. Tokens are signed with the real
// algorithm (RS256 via node:crypto) so the verifier under test does real
// cryptography, not a stub.
import { Buffer } from 'node:buffer';
import { createHmac, generateKeyPairSync, sign } from 'node:crypto';

import { GITHUB_OIDC_ISSUER, GITHUB_OIDC_JWKS_URL } from '../../broker/identity/github-oidc.mjs';

export const FRAMEWORK_SHA = 'f'.repeat(40);
export const REPO_A = { repository: 'owner/repo-a', repositoryId: '1001', ownerId: '26003726' };
export const REPO_B = { repository: 'owner/repo-b', repositoryId: '1002', ownerId: '26003726' };
export const SHA_A = 'a1'.repeat(20);
export const SHA_B = 'b2'.repeat(20);

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

export function createSigningKey({ kid = 'test-kid-1', bits = 2048 } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  return { kid, privateKey, publicKey, jwk };
}

// The claims GitHub emitted in the Phase 3A live probe, for a pull_request run
// of `repo` calling the framework's _break-glass-lambda.yml by exact SHA.
export function githubClaims({
  repo = REPO_A,
  pullRequest = '51',
  sha = SHA_A,
  runId = '700001',
  runAttempt = '1',
  eventName = 'pull_request',
  ref,
  jobWorkflowPath = '.github/workflows/_break-glass-lambda.yml',
  jobWorkflowRepository = 'IamRitz/ssd-security-framework',
  jobWorkflowSha = FRAMEWORK_SHA,
  // The ref part of job_workflow_ref as the caller spelled it (an exact SHA by
  // default; a tag or branch is legal, and authorizes nothing).
  jobWorkflowRefName = jobWorkflowSha,
  nowSeconds = Math.floor(Date.now() / 1000),
  jti = globalThis.crypto.randomUUID(),
  ...overrides
} = {}) {
  return {
    jti,
    sub: `repo:${repo.repository}:pull_request`,
    aud: 'ssd-break-glass',
    ref: ref ?? (eventName === 'pull_request' ? `refs/pull/${pullRequest}/merge` : 'refs/heads/main'),
    sha,
    repository: repo.repository,
    repository_owner: repo.repository.split('/')[0],
    repository_owner_id: repo.ownerId,
    run_id: runId,
    run_number: '7',
    run_attempt: runAttempt,
    repository_visibility: 'private',
    repository_id: repo.repositoryId,
    actor_id: '42',
    actor: 'developer',
    workflow: 'Security',
    head_ref: 'feature',
    base_ref: 'main',
    event_name: eventName,
    ref_protected: 'false',
    ref_type: 'branch',
    workflow_ref: `${repo.repository}/.github/workflows/security.yml@refs/pull/${pullRequest}/merge`,
    workflow_sha: sha,
    job_workflow_ref: `${jobWorkflowRepository}/${jobWorkflowPath}@${jobWorkflowRefName}`,
    job_workflow_sha: jobWorkflowSha,
    runner_environment: 'github-hosted',
    iss: GITHUB_OIDC_ISSUER,
    nbf: nowSeconds - 300,
    exp: nowSeconds + 300,
    iat: nowSeconds,
    ...overrides
  };
}

export function signToken(claims, { key, header = {}, alg = 'RS256' } = {}) {
  const head = { alg, kid: key?.kid, typ: 'JWT', x5t: 'test', ...header };
  const input = `${b64(head)}.${b64(claims)}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), key.privateKey).toString('base64url')}`;
}

export function unsignedToken(claims, kid = 'test-kid-1') {
  return `${b64({ alg: 'none', kid, typ: 'JWT' })}.${b64(claims)}.`;
}

// The classic RS256->HS256 confusion: HMAC-sign with the PUBLIC key's bytes.
export function hs256Token(claims, key) {
  const input = `${b64({ alg: 'HS256', kid: key.kid, typ: 'JWT' })}.${b64(claims)}`;
  const secret = key.publicKey.export({ format: 'pem', type: 'spki' });
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

// A fetch stand-in for GitHub's JWKS endpoint that REFUSES any other URL, so a
// test also proves the verifier never fetches a token-controlled location.
export function fakeJwksFetch(initialKeys, { fail = false } = {}) {
  const state = { keys: initialKeys, fail, calls: [], foreignUrls: [] };
  state.fetchImpl = async (url) => {
    const href = String(url);
    state.calls.push(href);
    if (href !== GITHUB_OIDC_JWKS_URL) {
      state.foreignUrls.push(href);
      throw new Error(`unexpected fetch ${href}`);
    }
    if (state.fail === 'http') return { ok: false, status: 503, text: async () => '' };
    if (state.fail) throw new Error('network down');
    return { ok: true, status: 200, text: async () => JSON.stringify({ keys: state.keys.map((k) => k.jwk ?? k) }) };
  };
  return state;
}
