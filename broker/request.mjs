// CI notify payload validation and pending-request construction.
//
// IDENTITY. Who is asking comes ONLY from the verified GitHub OIDC token
// (broker/identity/github-oidc.mjs). The payload's `context` is display and
// correlation data that must AGREE with the token: any supplied value that
// differs is a rejection, never a correction. The stored request keeps the
// verified `identity` separately from the display `context`, and every
// authorization and side-effect decision reads `identity`.
import { ELIGIBLE_POLICY_RULES } from './config.mjs';
import { IdentityRejected, pullRequestFromIdentity } from './identity/github-oidc.mjs';

const GATE_DIGEST = /^[a-f0-9]{64}$/i;

export const TIMEOUT_LIMITS = Object.freeze({ defaultSeconds: 900, minSeconds: 60, maxSeconds: 3600 });

export function validateNotifyPayload(payload) {
  if (!payload || payload.schemaVersion !== 1) throw new Error('unsupported schema');
  if (!Array.isArray(payload.findings) || payload.findings.length === 0) {
    throw new Error('invalid or empty finding payload');
  }
  if (!payload.findings.every((f) => f.action === 'BLOCK' && ELIGIBLE_POLICY_RULES.has(f.policyRule))) {
    throw new Error('payload contains a non-overridable finding');
  }
  if (!GATE_DIGEST.test(payload.gateDigest || '')) throw new Error('invalid gate digest');
  const context = payload.context;
  if (!context || typeof context !== 'object' || Array.isArray(context)) throw new Error('context is required');
  if (typeof context.repository !== 'string' || !context.repository.includes('/')) {
    throw new Error('repository is required');
  }
  if (!/^\d+$/.test(String(context.pullRequest ?? ''))) throw new Error('pull request number is required');
}

// The context fields a client may send. Anything else is refused, so a field
// cannot be smuggled into the stored request as if it were identity.
const CONTEXT_FIELDS = new Set([
  'repository', 'repositoryId', 'pullRequest', 'commitSha', 'runId', 'runAttempt', 'runUrl', 'ciSystem'
]);

const disagree = (field) => {
  throw new IdentityRejected(`payload_disagrees_with_token: ${field}`);
};

// verified identity + payload -> { identity, context } to store, or rejection.
//   identity  what the broker acts on: approver lookup by repositoryId, the
//             audit comment's repository and pull request, status binding
//   context   what approvers see; every value derived from the identity
export function bindRequestIdentity(payload, verified) {
  const pullRequest = pullRequestFromIdentity(verified);
  const runUrl = `https://github.com/${verified.repository}/actions/runs/${verified.runId}`;
  const supplied = payload.context;
  for (const field of Object.keys(supplied)) {
    if (!CONTEXT_FIELDS.has(field)) throw new IdentityRejected(`payload_context_field_not_allowed: ${field}`);
  }
  const expected = {
    repository: verified.repository,
    repositoryId: verified.repositoryId,
    pullRequest,
    commitSha: verified.sha,
    runId: verified.runId,
    runAttempt: verified.runAttempt,
    runUrl
  };
  for (const [field, value] of Object.entries(expected)) {
    const given = supplied[field];
    if (given !== undefined && given !== null && String(given) !== value) disagree(field);
  }
  const ciSystem = supplied.ciSystem ?? null;
  if (ciSystem !== null && (typeof ciSystem !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(ciSystem))) {
    disagree('ciSystem');
  }
  return {
    identity: {
      repositoryId: verified.repositoryId,
      repository: verified.repository,
      repositoryOwnerId: verified.repositoryOwnerId,
      pullRequest,
      sha: verified.sha,
      ref: verified.ref,
      eventName: verified.eventName,
      runId: verified.runId,
      runAttempt: verified.runAttempt,
      // As GitHub reported it (the ref part may be a tag or branch), and the
      // commit it resolved to: the one the framework policy authorizes.
      jobWorkflowRef: `${verified.jobWorkflow.repository}/${verified.jobWorkflow.path}@${verified.jobWorkflow.ref}`,
      jobWorkflowSha: verified.jobWorkflow.sha,
      jti: verified.jti
    },
    context: { ...expected, ciSystem }
  };
}

// Clamp the CI-requested timeout exactly as n8n did: default 900s, 60s..3600s.
// `bound` is bindRequestIdentity's result; nothing here reads payload.context.
// `environment` is the broker's own BREAK_GLASS_ENVIRONMENT, which the request's
// framework-derived environment has already been required to equal (Phase 3E):
// every later status call and click acts only on a request of that environment.
export function createPendingRequest(payload, { now, randomUUID, bound, environment, limits = TIMEOUT_LIMITS }) {
  const timeout = Math.min(
    Math.max(Number(payload.timeoutSeconds) || limits.defaultSeconds, limits.minSeconds),
    limits.maxSeconds
  );
  return {
    requestId: randomUUID(),
    environment,
    gateDigest: payload.gateDigest,
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + timeout * 1000).toISOString(),
    identity: bound.identity,
    context: bound.context,
    findings: payload.findings
  };
}

// The status shape the CI poll script consumes.
export function statusView(request) {
  return {
    requestId: request.requestId,
    gateDigest: request.gateDigest,
    status: request.status,
    createdAt: request.createdAt,
    expiresAt: request.expiresAt,
    decidedAt: request.decidedAt || null,
    approver: request.approver || null
  };
}
