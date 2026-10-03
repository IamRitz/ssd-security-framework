#!/usr/bin/env node
// Mutation check for the break-glass broker identity invariants (Phase 3A).
//
// Each mutation breaks exactly one property that stops one repository, run or
// workflow from acting as another; the broker and client tests must FAIL for
// every one. A surviving or stale mutation fails this script. The runner is the
// onboarding harness's (same temp-workspace lifecycle, same reporting).
//
//   node tools/mutation-check-broker.mjs
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runMutationCheck } from './mutation-check-onboarding.mjs';

export const TESTS = [
  'test/broker-oidc-identity.test.js',
  'test/broker-lambda.test.js',
  'test/broker-authorize.test.js',
  'test/break-glass-lambda-transport.test.js',
  'test/break-glass-ux.test.js',
  'test/break-glass-oidc-boundary.test.js'
];

const OIDC = 'broker/identity/github-oidc.mjs';
const REQUEST = 'broker/request.mjs';
const BROKER = 'broker/lambda/broker.mjs';
const STORE = 'broker/lambda/dynamodb-store.mjs';

// [invariant, file, search, replace]
export const MUTATIONS = [
  // --- the token is GitHub's, for this audience, and current ------------------
  ['signature verification cannot be bypassed', OIDC, "  if (!signed) reject('signature_invalid');\n", ''],
  ['the issuer is checked', OIDC, "  if (claims.iss !== GITHUB_OIDC_ISSUER) reject('issuer_mismatch');\n", ''],
  ['the audience is checked', OIDC, "  if (claims.aud !== BREAK_GLASS_AUDIENCE) reject('audience_mismatch');\n", ''],
  ['only RS256 is accepted', OIDC, "  if (header.alg !== 'RS256') reject('alg_not_allowed');", "  if (!['RS256', 'HS256', 'none'].includes(header.alg)) reject('alg_not_allowed');"],
  ['key-location header parameters are refused', OIDC, "  if (FORBIDDEN_HEADER_PARAMETERS.some((name) => Object.hasOwn(header, name))) reject('header_parameter_not_allowed');\n", ''],
  ['an expired token is refused', OIDC, "  if (exp <= nowSeconds) reject('token_expired');\n", ''],
  ['a token past its maximum age is refused', OIDC, "  if (nowSeconds - iat > maxAgeSeconds) reject('token_too_old');\n", ''],
  ['a not-yet-valid token is refused', OIDC, "    if (nbf > nowSeconds + skewSeconds) reject('token_not_yet_valid');\n", ''],
  ['a token issued in the future is refused', OIDC, "  if (iat > nowSeconds + skewSeconds) reject('token_issued_in_future');\n", ''],
  ['repository_id is required', OIDC, "    repositoryId: requireString(claims, 'repository_id', DECIMAL_ID),", '    repositoryId: claims.repository_id,'],
  // --- the token came from an allowlisted framework workflow at an exact SHA ---
  ['job_workflow_ref repository is checked', OIDC, "  if (repository.toLowerCase() !== FRAMEWORK_REPOSITORY.toLowerCase()) reject('job_workflow_repository_not_allowed');\n", ''],
  ['job_workflow_ref path is checked', OIDC, "  if (!ALLOWED_JOB_WORKFLOW_PATHS.includes(path)) reject('job_workflow_path_not_allowed');\n", ''],
  ['job_workflow_ref must be an exact SHA', OIDC, "  if (!COMMIT_SHA.test(ref)) reject('job_workflow_ref_not_sha');\n", ''],
  ['job_workflow_sha must equal the ref', OIDC, "  if (jobWorkflowSha !== jobWorkflow.sha) reject('job_workflow_sha_mismatch');\n", ''],
  // --- JWKS is bounded and fails closed --------------------------------------
  ['an unknown kid cannot amplify JWKS fetches', OIDC, "        if (now() - lastAttemptAt < minRefreshIntervalMs) reject('unknown_kid');\n", ''],
  ['the JWKS cache expires', OIDC, '      if (!keys || now() - fetchedAt >= ttlMs) {', '      if (!keys) {'],
  ['undersized RSA keys are not trusted', OIDC, 'key.asymmetricKeyDetails.modulusLength < MIN_RSA_BITS', 'key.asymmetricKeyDetails.modulusLength < 512'],
  // --- the payload cannot be identity ------------------------------------------
  ['the repository is not derived from the payload', REQUEST, '    repository: verified.repository,\n    repositoryId: verified.repositoryId,\n    pullRequest,', '    repository: supplied.repository,\n    repositoryId: verified.repositoryId,\n    pullRequest,'],
  ['the PR number is not derived from the payload', REQUEST, '  const pullRequest = pullRequestFromIdentity(verified);', '  const pullRequest = String(payload.context.pullRequest);'],
  ['a production request needs a pull_request event', OIDC, "  if (identity?.eventName !== 'pull_request') reject('event_not_allowed');\n", ''],
  ['a payload that disagrees with the token is rejected', REQUEST, '    if (given !== undefined && given !== null && String(given) !== value) disagree(field);\n', ''],
  ['an unknown context field is rejected', REQUEST, "    if (!CONTEXT_FIELDS.has(field)) throw new IdentityRejected(`payload_context_field_not_allowed: ${field}`);\n", ''],
  ['approvers are looked up by the verified repository_id', BROKER, '      repo: stored?.identity?.repositoryId,', '      repo: stored?.context?.repository,'],
  ['the audit comment refuses a request without verified identity', BROKER, "    if (!request?.identity) throw new Error('refusing side effects for a request without verified identity');\n", ''],
  ['an unconfigured verifier fails closed', BROKER, "      if (typeof verifyIdentity !== 'function') throw new IdentityRejected('verifier_not_configured');\n", "      if (typeof verifyIdentity !== 'function') return { identity: {} };\n"],
  // --- status is bound to the filing run --------------------------------------
  ['status is bound to repository_id', BROKER, '      owner.repositoryId !== auth.identity.repositoryId ||\n', ''],
  ['status is bound to run_id', BROKER, '      owner.runId !== auth.identity.runId ||\n', ''],
  ['status is bound to run_attempt', BROKER, '      owner.runId !== auth.identity.runId ||\n      owner.runAttempt !== auth.identity.runAttempt', '      owner.runId !== auth.identity.runId'],
  ['status requires a verified token', BROKER, "    const auth = await authenticate('status', identityToken, null);\n    if (auth.rejected) return auth.rejected;\n", "    const auth = { identity: {} };\n"],
  // --- a token is used once ---------------------------------------------------
  ['the replay record is a conditional write', STORE, "          ConditionExpression: 'attribute_not_exists(requestId)'\n        });\n        return true;", '        });\n        return true;'],
  ['a replayed token is refused', BROKER, '    if (!fresh) {', '    if (false) {'],
  ['a replay record is never read as a request', STORE, "  if (!item || typeof item.doc?.S !== 'string') return undefined;", '  if (!item) return undefined;'],
  // --- the client sends a fresh, masked token for this audience -----------------
  ['the client requests the ssd-break-glass audience', 'security/scripts/break-glass-oidc-token.mjs', "  url.searchParams.set('audience', BREAK_GLASS_AUDIENCE);", "  url.searchParams.set('audience', 'sts.amazonaws.com');"],
  ['the client masks the token', 'security/scripts/break-glass-oidc-token.mjs', '  mask(value);\n', ''],
  ['notify sends the identity token', 'security/scripts/break-glass-notify.mjs', "await invoke({ action: 'notify', payload, identityToken });", "await invoke({ action: 'notify', payload });"],
  ['every poll sends its own identity token', 'security/scripts/break-glass-poll.mjs', "await invoke({ action: 'status', requestId: request.requestId, identityToken });", "await invoke({ action: 'status', requestId: request.requestId });"],
  // --- the OIDC boundary --------------------------------------------------------
  ['_source-scan.yml stays OIDC-free', '.github/workflows/_source-scan.yml', '      pull-requests: write\n', '      pull-requests: write\n      id-token: write\n']
];

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMutationCheck({ tests: TESTS, mutations: MUTATIONS });
}
