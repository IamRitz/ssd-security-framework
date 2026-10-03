// Verified GitHub Actions identity for break-glass requests.
//
// Lambda direct invocation does not tell the function WHICH IAM principal
// invoked it, so before this module the broker believed whatever repository the
// payload named — any principal allowed to invoke it could file a request "for"
// another repository, page that repository's approvers, and make the broker post
// its audit comment on that repository's pull request (architecture E.2).
//
// Every CI request now carries a GitHub OIDC token minted for the dedicated
// audience `ssd-break-glass`. This module verifies it cryptographically and
// returns the identity the broker acts on. Nothing about identity is taken from
// the payload; the payload can only AGREE with the token (broker/request.mjs).
//
// Fixed, never caller-controlled:
//   issuer    https://token.actions.githubusercontent.com
//   JWKS      https://token.actions.githubusercontent.com/.well-known/jwks
//   audience  ssd-break-glass
//   alg       RS256 (the only algorithm GitHub's discovery document advertises)
//   workflow  IamRitz/ssd-security-framework/.github/workflows/<allowlisted file>@<40-hex SHA>
//
// Live evidence (Phase 3A probe, ssd-scratch-consumer runs 37118241635,
// 37118245381, 37118248911, calling the framework by exact SHA): GitHub emitted
// job_workflow_ref `IamRitz/ssd-security-framework/.github/workflows/<file>@<sha>`
// with the 40-character SHA and job_workflow_sha equal to it, a 300-second
// lifetime (exp - iat), nbf = iat - 300, a unique jti per mint, a 2048-bit RSA
// key with use=sig, and ref `refs/pull/<n>/merge` on pull_request.
//
// Every failure is an IdentityRejected with a fixed code. Messages never carry
// any part of the token.
import { Buffer } from 'node:buffer';
import { createPublicKey, verify } from 'node:crypto';

export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
export const GITHUB_OIDC_JWKS_URL = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`;
export const BREAK_GLASS_AUDIENCE = 'ssd-break-glass';
export const FRAMEWORK_REPOSITORY = 'IamRitz/ssd-security-framework';
// The only framework workflows whose jobs may file a break-glass request: the
// dedicated Lambda job, and the legacy v1 in-job path.
export const ALLOWED_JOB_WORKFLOW_PATHS = Object.freeze([
  '.github/workflows/_break-glass-lambda.yml',
  '.github/workflows/_source-security.yml'
]);

// GitHub tokens live 300 s (observed). A token older than that is refused even
// if `exp` were somehow later; iat/nbf may sit at most SKEW in the future.
export const MAX_TOKEN_AGE_SECONDS = 300;
export const CLOCK_SKEW_SECONDS = 30;

export const JWKS_TTL_MS = 10 * 60 * 1000;
// A token with an unknown `kid` may force at most one JWKS refetch per interval,
// so a stream of invented kids cannot turn the broker into a fetch amplifier.
export const JWKS_MIN_REFRESH_INTERVAL_MS = 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 5000;
const JWKS_MAX_BYTES = 64 * 1024;
const MIN_RSA_BITS = 2048;
const MAX_TOKEN_LENGTH = 8192;

export class IdentityRejected extends Error {
  constructor(code) {
    super(`identity_rejected: ${code}`);
    this.name = 'IdentityRejected';
    this.code = code;
  }
}

const reject = (code) => {
  throw new IdentityRejected(code);
};

const B64URL = /^[A-Za-z0-9_-]+$/;
const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;
const COMMIT_SHA = /^[0-9a-f]{40}$/;
// owner/repo/<path>@<ref>. Owner and repository names cannot contain '/' or
// '@'; the path is everything up to the single '@'.
const JOB_WORKFLOW_REF = /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/([^@]+)@([^@]+)$/;
const PULL_REQUEST_MERGE_REF = /^refs\/pull\/([1-9][0-9]{0,9})\/merge$/;

// Header parameters that point at, or embed, key material. GitHub never sends
// them, the verifier never uses them, and their presence means someone is
// trying to steer key selection — so they are refused rather than ignored.
const FORBIDDEN_HEADER_PARAMETERS = ['jku', 'jwk', 'x5u', 'x5c', 'crit'];

function decodeJsonSegment(segment, code) {
  try {
    const value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject(code);
    return value;
  } catch (error) {
    if (error instanceof IdentityRejected) throw error;
    return reject(code);
  }
}

// --- JWKS -------------------------------------------------------------------

function importJwk(jwk) {
  if (!jwk || typeof jwk !== 'object') return null;
  if (jwk.kty !== 'RSA' || typeof jwk.kid !== 'string' || jwk.kid === '') return null;
  if (jwk.alg !== undefined && jwk.alg !== 'RS256') return null;
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return null;
  try {
    const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < MIN_RSA_BITS) return null;
    return key;
  } catch {
    return null;
  }
}

// Fetches GitHub's JWKS from the FIXED url. `fetchImpl` is injectable for
// tests; the url is not. Keys are cached for JWKS_TTL_MS; after that the cache
// is dropped, never served stale, so an unreachable JWKS fails closed.
export function createJwksCache({
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
  ttlMs = JWKS_TTL_MS,
  minRefreshIntervalMs = JWKS_MIN_REFRESH_INTERVAL_MS
} = {}) {
  let keys = null; // Map<kid, KeyObject>
  let fetchedAt = 0;
  let lastAttemptAt = -Infinity;
  let inFlight = null;

  async function load() {
    lastAttemptAt = now();
    let body;
    try {
      const response = await fetchImpl(GITHUB_OIDC_JWKS_URL, {
        redirect: 'error',
        headers: { accept: 'application/json' },
        signal: globalThis.AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS)
      });
      if (!response.ok) reject('jwks_unavailable');
      body = await response.text();
    } catch (error) {
      if (error instanceof IdentityRejected) throw error;
      reject('jwks_unavailable');
    }
    if (typeof body !== 'string' || body.length > JWKS_MAX_BYTES) reject('jwks_malformed');
    let document;
    try {
      document = JSON.parse(body);
    } catch {
      reject('jwks_malformed');
    }
    if (!document || !Array.isArray(document.keys)) reject('jwks_malformed');
    const next = new Map();
    for (const jwk of document.keys) {
      const key = importJwk(jwk);
      if (key) next.set(jwk.kid, key);
    }
    keys = next;
    fetchedAt = now();
  }

  function refresh() {
    inFlight ??= load().finally(() => {
      inFlight = null;
    });
    return inFlight;
  }

  return {
    async getKey(kid) {
      if (!keys || now() - fetchedAt >= ttlMs) {
        keys = null;
        await refresh();
      } else if (!keys.has(kid)) {
        if (now() - lastAttemptAt < minRefreshIntervalMs) reject('unknown_kid');
        await refresh();
      }
      return keys.get(kid) ?? reject('unknown_kid');
    }
  };
}

// --- token ------------------------------------------------------------------

function requireString(claims, name, pattern) {
  const value = claims[name];
  if (typeof value !== 'string' || value === '' || (pattern && !pattern.test(value))) {
    reject(`claim_${name}_invalid`);
  }
  return value;
}

function requireNumericDate(claims, name) {
  const value = claims[name];
  if (!Number.isInteger(value) || value <= 0) reject(`claim_${name}_invalid`);
  return value;
}

// job_workflow_ref -> { repository, path, sha }, or rejection. Parsed and
// compared component by component — never a prefix or suffix match.
export function parseJobWorkflowRef(value) {
  const match = typeof value === 'string' ? JOB_WORKFLOW_REF.exec(value) : null;
  if (!match) reject('job_workflow_ref_malformed');
  const [, repository, path, ref] = match;
  // GitHub owner/repository names are case-insensitive; the path is not.
  if (repository.toLowerCase() !== FRAMEWORK_REPOSITORY.toLowerCase()) reject('job_workflow_repository_not_allowed');
  if (!ALLOWED_JOB_WORKFLOW_PATHS.includes(path)) reject('job_workflow_path_not_allowed');
  // Observed live: a caller pinned by SHA yields the bare 40-hex SHA. A tag or
  // branch ref (`refs/tags/v1`, `refs/heads/main`) is a moving reference and is
  // refused.
  if (!COMMIT_SHA.test(ref)) reject('job_workflow_ref_not_sha');
  return { repository, path, sha: ref };
}

// Verifies `token` and returns the GitHub identity it proves. Async only for
// the JWKS lookup. Order matters: nothing in the payload segment is trusted, or
// even parsed, before the signature has been verified.
export async function verifyGithubOidcToken(
  token,
  { jwks, now = () => Date.now(), maxAgeSeconds = MAX_TOKEN_AGE_SECONDS, skewSeconds = CLOCK_SKEW_SECONDS }
) {
  if (typeof token !== 'string' || token === '') reject('token_missing');
  if (token.length > MAX_TOKEN_LENGTH) reject('token_malformed');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((part) => B64URL.test(part))) reject('token_malformed');
  const [headerSegment, payloadSegment, signatureSegment] = parts;

  const header = decodeJsonSegment(headerSegment, 'header_malformed');
  if (header.alg !== 'RS256') reject('alg_not_allowed');
  if (header.typ !== undefined && header.typ !== 'JWT') reject('typ_not_allowed');
  if (FORBIDDEN_HEADER_PARAMETERS.some((name) => Object.hasOwn(header, name))) reject('header_parameter_not_allowed');
  if (typeof header.kid !== 'string' || header.kid === '' || header.kid.length > 128) reject('kid_invalid');

  const key = await jwks.getKey(header.kid);
  const signed = verify(
    'RSA-SHA256',
    Buffer.from(`${headerSegment}.${payloadSegment}`, 'ascii'),
    key,
    Buffer.from(signatureSegment, 'base64url')
  );
  if (!signed) reject('signature_invalid');

  const claims = decodeJsonSegment(payloadSegment, 'payload_malformed');
  if (claims.iss !== GITHUB_OIDC_ISSUER) reject('issuer_mismatch');
  // GitHub sends a single-string audience; an array (even one containing ours)
  // is not the shape this broker was issued and is refused.
  if (claims.aud !== BREAK_GLASS_AUDIENCE) reject('audience_mismatch');

  const nowSeconds = Math.floor(now() / 1000);
  const exp = requireNumericDate(claims, 'exp');
  const iat = requireNumericDate(claims, 'iat');
  if (exp <= nowSeconds) reject('token_expired');
  if (iat > nowSeconds + skewSeconds) reject('token_issued_in_future');
  if (nowSeconds - iat > maxAgeSeconds) reject('token_too_old');
  if (claims.nbf !== undefined) {
    const nbf = requireNumericDate(claims, 'nbf');
    if (nbf > nowSeconds + skewSeconds) reject('token_not_yet_valid');
  }

  const jobWorkflow = parseJobWorkflowRef(requireString(claims, 'job_workflow_ref'));
  const jobWorkflowSha = requireString(claims, 'job_workflow_sha', COMMIT_SHA);
  if (jobWorkflowSha !== jobWorkflow.sha) reject('job_workflow_sha_mismatch');

  return {
    repository: requireString(claims, 'repository', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    repositoryId: requireString(claims, 'repository_id', DECIMAL_ID),
    repositoryOwnerId: requireString(claims, 'repository_owner_id', DECIMAL_ID),
    ref: requireString(claims, 'ref'),
    sha: requireString(claims, 'sha', COMMIT_SHA),
    runId: requireString(claims, 'run_id', DECIMAL_ID),
    runAttempt: requireString(claims, 'run_attempt', DECIMAL_ID),
    eventName: requireString(claims, 'event_name'),
    jobWorkflow,
    jti: requireString(claims, 'jti', /^[A-Za-z0-9_.:-]{1,256}$/),
    exp,
    iat
  };
}

// A production break-glass request exists only for a pull request, and its
// number comes from the verified ref — never from an input or the payload.
// push, schedule, workflow_dispatch and pull_request_target are refused: any
// non-PR route (e.g. synthetic testing) needs its own, explicitly separate
// contract.
export function pullRequestFromIdentity(identity) {
  if (identity?.eventName !== 'pull_request') reject('event_not_allowed');
  const match = PULL_REQUEST_MERGE_REF.exec(identity.ref);
  if (!match) reject('pull_request_ref_malformed');
  return match[1];
}
