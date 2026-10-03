// Platform-agnostic break-glass decision logic shared by every interaction
// handler (Slack today; Discord can be delegated onto this later). A handler
// verifies its own signature and authorizes its own user, then calls into these
// functions with a normalized decision so the race guard, the finalize step, and
// the audit trail exist in exactly one place — one fix covers every platform by
// construction rather than by keeping copies in sync.

const REQUEST_ID = /^[0-9a-f-]{36}$/;

// Claim a pending request: the race-guarded pending -> processing transition.
// `requests` is the stored request map (n8n workflow static data at runtime).
// The caller must already have verified the signature and authorized the user.
export function claimDecision({ requestId, action, userId, username, requests, now = new Date() }) {
  if (!REQUEST_ID.test(requestId || '')) return { outcome: 'rejected', reason: 'invalid request identifier' };
  if (action !== 'approve' && action !== 'deny') return { outcome: 'rejected', reason: 'invalid action' };
  if (!userId) return { outcome: 'rejected', reason: 'missing user identity' };

  const request = requests?.[requestId];
  if (!request) return { outcome: 'rejected', reason: 'unknown request', requestId };

  const nowDate = now instanceof Date ? now : new Date(now);
  if (new Date(request.expiresAt) <= nowDate) {
    if (request.status === 'pending') request.status = 'expired';
    return { outcome: 'expired', requestId };
  }
  if (request.status !== 'pending') {
    return { outcome: 'duplicate', requestId, status: request.status };
  }

  request.status = 'processing';
  request.claim = {
    decision: action === 'approve' ? 'approved' : 'denied',
    userId,
    username: username || userId,
    claimedAt: nowDate.toISOString()
  };
  return { outcome: 'claimed', requestId, request };
}

// Finalize a claimed request into stored state. Guards that the same claim we
// made is still the one in flight, so a concurrent click cannot finalize on our
// behalf. Run this BEFORE the side effects (audit comment, message update) so a
// transient side-effect failure can never strand a valid decision in processing.
export function finalizeDecision({ request, userId, now = new Date() }) {
  if (!request || request.status !== 'processing' || request.claim?.userId !== userId) {
    throw new Error('decision claim changed before finalization');
  }
  const nowDate = now instanceof Date ? now : new Date(now);
  request.status = request.claim.decision;
  request.decidedAt = nowDate.toISOString();
  request.approver = { id: request.claim.userId, username: request.claim.username };
  delete request.claim;
  return request;
}

// The GitHub PR audit comment body. Works from either an in-flight claim or a
// finalized approver record so it can be built on either side of finalize.
export function buildAuditComment(request) {
  const decider = request.claim || {
    decision: request.status,
    userId: request.approver?.id,
    username: request.approver?.username,
    claimedAt: request.decidedAt
  };
  const findingText = (request.findings || [])
    .map((finding) => `${finding.policyRule}: ${finding.id}`)
    .join('; ');
  return [
    `Break-glass decision: **${String(decider.decision || request.status).toUpperCase()}**`,
    `Verified approver: **${decider.username}** (ID: \`${decider.userId}\`)`,
    `Timestamp: ${decider.claimedAt || request.decidedAt}`,
    `Overridden finding(s): ${findingText}`,
    `Gate digest: \`${request.gateDigest}\``
  ].join('\n\n');
}
