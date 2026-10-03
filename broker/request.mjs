// CI notify payload validation and pending-request construction, shared by every
// broker transport (the Express service and the Lambda broker) so the rules the
// n8n "Validate and Store Pending Request" node enforced exist in one place.
import { ELIGIBLE_POLICY_RULES } from './config.mjs';

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
  if (!context || typeof context.repository !== 'string' || !context.repository.includes('/')) {
    throw new Error('repository is required');
  }
  if (!/^\d+$/.test(String(context.pullRequest ?? ''))) throw new Error('pull request number is required');
}

// Clamp the CI-requested timeout exactly as n8n did: default 900s, 60s..3600s.
export function createPendingRequest(payload, { now, randomUUID, limits = TIMEOUT_LIMITS }) {
  const timeout = Math.min(
    Math.max(Number(payload.timeoutSeconds) || limits.defaultSeconds, limits.minSeconds),
    limits.maxSeconds
  );
  return {
    requestId: randomUUID(),
    gateDigest: payload.gateDigest,
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + timeout * 1000).toISOString(),
    context: payload.context,
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
