// Transport-neutral break-glass broker used by the Lambda handlers.
//
// Verification, authorization, and the claim/finalize decisions are the shared
// modules imported verbatim — the same ones the Express service imports and the
// n8n Code nodes mirror. The only thing this file adds is persistence: each
// decision the modules make is committed with a DynamoDB conditional write, which
// is what makes a rapid double-click safe by construction instead of by
// serializing executions.
//
// IDENTITY. Both CI actions (notify, status) require a fresh GitHub OIDC token
// for the `ssd-break-glass` audience, verified by `verifyIdentity` and accepted
// once only (consumeTokenId). The repository, pull request and run a request
// belongs to come from that token; approvers are looked up by the immutable
// repository_id; the audit comment goes to the token's repository and PR; and a
// status read must come from the same repository, run and run attempt that
// filed the request. Tokens are never logged, stored or echoed.
//
// FRAMEWORK COMMIT (Phase 3D). A verified token is accepted only if its
// job_workflow_sha is in this environment's allowed set
// (identity/framework-policy.mjs). The check runs after verification and
// BEFORE the token is spent, on notify and every status call, so a refused
// commit writes nothing; and again at click time against the stored request's
// commit, before any claim, so removing a commit revokes its pending requests.
//
// ENVIRONMENT (Phase 3E). The framework derives a request's environment
// (production | synthetic) from its validated gate evidence and sends it as the
// notify payload's `environment`. The broker refuses one that is not its own
// BREAK_GLASS_ENVIRONMENT before the token is verified or spent, so a misrouted
// request writes nothing. The stored request records the environment, and a
// status call or click acts only on a request of this broker's environment.
import { createHash } from 'node:crypto';

import {
  verifySlackSignature,
  parseSlackInteraction,
  extractSlackDecision
} from '../authorize/slack-interaction-verify.mjs';
import { BREAK_GLASS_ENVIRONMENTS } from '../authorize/approvers.mjs';
import { authorizeSlackInteraction } from '../authorize/slack-authorize.mjs';
import {
  claimDecision,
  finalizeDecision,
  buildAuditComment
} from '../authorize/break-glass-decision.mjs';
import { buildApprovalMessage, buildDecisionUpdate, ephemeral } from '../messages.mjs';
import { decideFramework } from '../identity/framework-policy.mjs';
import { IdentityRejected } from '../identity/github-oidc.mjs';
import { bindRequestIdentity, createPendingRequest, statusView, validateNotifyPayload } from '../request.mjs';
import { ConditionFailed } from './dynamodb-store.mjs';

const SLACK_RESPONSE_URL = /^https:\/\/hooks\.slack\.com\//;
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// A caller-asserted value copied into a log line: bounded, never interpreted.
const claimed = (value) => (typeof value === 'string' ? value.slice(0, 200) : null);

export function createBroker({
  store,
  slack,
  github,
  signingSecret,
  // { approversFor(repositoryId) } -> an approvers.mjs lookup result.
  approverSource,
  // async (token) -> verified GitHub identity, or throws IdentityRejected.
  verifyIdentity,
  // { check(sha) } -> a framework-policy.mjs result. Absent = nothing allowed.
  frameworkPolicy,
  // This broker's BREAK_GLASS_ENVIRONMENT. Anything but production or
  // synthetic refuses every request.
  environment,
  slackChannelId,
  now = () => new Date(),
  randomUUID = () => globalThis.crypto.randomUUID(),
  log = (entry) => console.log(JSON.stringify(entry))
}) {
  // --- CI identity -------------------------------------------------------------
  // Verify the token, check its framework commit, then spend it. Returns
  // { identity } or { rejected }.
  // Rejections log enough to investigate (code, any verified ids, what the
  // payload claimed) and never the token.
  async function authenticate(action, identityToken, claimedRepository) {
    let verified;
    try {
      if (typeof verifyIdentity !== 'function') throw new IdentityRejected('verifier_not_configured');
      verified = await verifyIdentity(identityToken);
    } catch (error) {
      if (!(error instanceof IdentityRejected)) throw error;
      log({ event: 'identity_rejected', action, code: error.code, claimedRepository: claimed(claimedRepository) });
      return { rejected: { ok: false, statusCode: 401, error: error.message } };
    }
    // Before the token is spent: a refused commit writes nothing.
    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);
    if (framework.state !== 'allowed') {
      log({ event: 'framework_rejected', action, state: framework.state, reason: framework.reason, frameworkSha: verified.jobWorkflow?.sha ?? null, ...who(verified) });
      return { rejected: frameworkRejection(framework) };
    }
    const fresh = await store.consumeTokenId({
      jtiHash: createHash('sha256').update(verified.jti).digest('hex'),
      exp: verified.exp,
      repositoryId: verified.repositoryId,
      runId: verified.runId,
      runAttempt: verified.runAttempt,
      action
    });
    if (!fresh) {
      log({ event: 'identity_rejected', action, code: 'token_replayed', ...who(verified) });
      return { rejected: { ok: false, statusCode: 401, error: 'identity_rejected: token_replayed' } };
    }
    return { identity: verified };
  }

  const frameworkRejection = (framework) =>
    framework.state === 'not_allowed'
      ? { ok: false, statusCode: 403, error: 'framework_rejected: framework_sha_not_allowed' }
      : { ok: false, statusCode: 503, error: `framework_policy_unavailable: ${framework.state}` };

  // The request's framework-derived environment must be this broker's own.
  // -> null (accepted) or the refusal. Runs before anything is verified or written.
  function environmentRejection(requested) {
    if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {
      log({ event: 'environment_rejected', reason: 'broker_misconfigured', requested: claimed(requested) });
      return { ok: false, statusCode: 500, error: 'environment_misconfigured' };
    }
    if (!BREAK_GLASS_ENVIRONMENTS.includes(requested)) {
      log({ event: 'environment_rejected', reason: 'invalid', requested: claimed(requested), environment });
      return { ok: false, statusCode: 400, error: 'invalid request environment' };
    }
    if (requested !== environment) {
      log({ event: 'environment_rejected', reason: 'mismatch', requested, environment });
      return { ok: false, statusCode: 403, error: 'environment_mismatch' };
    }
    return null;
  }

  // A stored request belongs to this broker only when it records this
  // environment. A request without one (filed before Phase 3E) belongs nowhere.
  const ownEnvironment = (request) => BREAK_GLASS_ENVIRONMENTS.includes(environment) && request?.environment === environment;

  const who = (identity) => ({
    repositoryId: identity.repositoryId,
    repository: identity.repository,
    runId: identity.runId,
    runAttempt: identity.runAttempt
  });

  // --- CI notify ------------------------------------------------------------
  // Write order (asserted in test/broker-oidc-identity.test.js, "notify ordering"):
  //   1. payload shape, request environment, token verification,
  //      framework commit                               no writes
  //   2. replay claim on the token's jti                first write
  //   3. payload must agree with the token              no writes
  //   4. putPending (fresh UUID, conditional)
  //   5. Slack post + setSlackRef; on failure deletePending, then 502
  // The token is spent before anything else is written, so a resend of the
  // same event can never create a second request; any retry needs a new token
  // and, after a failure at 4 or 5, leaves at most one request with an
  // approval message.
  async function notify(payload, identityToken) {
    try {
      validateNotifyPayload(payload);
    } catch (error) {
      return { ok: false, statusCode: 400, error: error.message };
    }
    if (!slackChannelId) return { ok: false, statusCode: 500, error: 'SLACK_CHANNEL_ID is not configured' };
    // Before the token is verified or spent: a misrouted request writes nothing.
    const misrouted = environmentRejection(payload.environment);
    if (misrouted) return misrouted;

    const auth = await authenticate('notify', identityToken, payload.context.repository);
    if (auth.rejected) return auth.rejected;
    let bound;
    try {
      bound = bindRequestIdentity(payload, auth.identity);
    } catch (error) {
      if (!(error instanceof IdentityRejected)) throw error;
      log({
        event: 'identity_rejected',
        action: 'notify',
        code: error.code,
        ...who(auth.identity),
        claimedRepository: claimed(payload.context.repository),
        claimedPullRequest: claimed(String(payload.context.pullRequest ?? ''))
      });
      return { ok: false, statusCode: 403, error: error.message };
    }

    const request = createPendingRequest(payload, { now: now(), randomUUID, bound, environment });
    // Store before posting so a fast click finds the request; roll back and fail
    // closed if Slack refuses the message.
    await store.putPending(request);
    try {
      const posted = await slack.postMessage(buildApprovalMessage(request, slackChannelId));
      await store.setSlackRef(request.requestId, { channel: posted.channel, ts: posted.ts });
    } catch (error) {
      await store.deletePending(request.requestId).catch(() => {});
      return { ok: false, statusCode: 502, error: `slack_post_failed: ${error.message}` };
    }
    log({
      event: 'notify',
      requestId: request.requestId,
      ...who(request.identity),
      pullRequest: request.identity.pullRequest,
      jobWorkflowRef: request.identity.jobWorkflowRef,
      jti: request.identity.jti
    });
    return {
      ok: true,
      statusCode: 201,
      body: {
        requestId: request.requestId,
        gateDigest: request.gateDigest,
        status: request.status,
        createdAt: request.createdAt,
        expiresAt: request.expiresAt
      }
    };
  }

  // --- CI status poll ---------------------------------------------------------
  // Bound to the run that filed the request: a request id alone is not
  // authorization. A request with no stored identity (filed before this
  // hardening) matches nobody.
  async function status(requestId, identityToken) {
    const auth = await authenticate('status', identityToken, null);
    if (auth.rejected) return auth.rejected;
    const id = String(requestId || '');
    const request = REQUEST_ID.test(id) ? await store.get(id) : undefined;
    if (!request) return { ok: false, statusCode: 404, error: 'unknown_request' };
    if (!ownEnvironment(request)) {
      log({ event: 'status_environment_mismatch', requestId: id, stored: request.environment ?? null, environment, ...who(auth.identity) });
      return { ok: false, statusCode: 403, error: 'request_environment_mismatch' };
    }
    const owner = request.identity;
    if (
      !owner ||
      owner.repositoryId !== auth.identity.repositoryId ||
      owner.runId !== auth.identity.runId ||
      owner.runAttempt !== auth.identity.runAttempt
    ) {
      log({ event: 'status_identity_mismatch', requestId: id, ...who(auth.identity) });
      return { ok: false, statusCode: 403, error: 'request_identity_mismatch' };
    }
    const nowDate = now();
    if (request.status === 'pending' && new Date(request.expiresAt) <= nowDate) {
      await store.expire(request, nowDate.toISOString());
      const fresh = await store.get(request.requestId);
      return { ok: true, statusCode: 200, body: statusView(fresh) };
    }
    return { ok: true, statusCode: 200, body: statusView(request) };
  }

  // --- Slack interaction (synchronous part, before the ack) --------------------
  // Returns the HTTP response for Slack plus the follow-up work to run after the
  // ack. Every state transition happens HERE, before responding; only the
  // message update, audit comment, and ephemeral replies are deferred.
  async function handleInteraction({ headers, rawBody }) {
    const verified = verifySlackSignature({
      signingSecret,
      signature: headers['x-slack-signature'],
      timestamp: headers['x-slack-request-timestamp'],
      rawBody,
      now: now().getTime()
    });
    if (!verified) return { statusCode: 401, outcome: 'invalid_signature' };

    let interaction;
    try {
      interaction = parseSlackInteraction(rawBody);
    } catch {
      return { statusCode: 400, outcome: 'invalid_payload' };
    }
    if (interaction.type !== 'block_actions') return { statusCode: 200, outcome: 'ignored' };

    const reply = (outcome, text, extra = {}) => ({
      statusCode: 200,
      outcome,
      ...extra,
      followUp: SLACK_RESPONSE_URL.test(interaction.response_url || '')
        ? { kind: 'ephemeral', responseUrl: interaction.response_url, text }
        : null
    });

    const decision = extractSlackDecision(interaction);
    if (!decision) return reply('rejected', 'Invalid or stale approval control.');

    // The approver list is the one named by the STORED request's VERIFIED
    // repository_id — never the click payload, never the display context —
    // read at click time. No stored identity -> no lookup, nobody authorized.
    // The stored request's framework commit is re-checked at the same time (in
    // parallel, inside Slack's 3 s ack budget).
    const stored = await store.get(decision.requestId);
    // Only a request of this broker's environment can be decided here; any
    // other is answered like an unknown one, with no lookup and no state change.
    if (stored && !ownEnvironment(stored)) {
      log({ event: 'click_environment_mismatch', requestId: decision.requestId, stored: stored.environment ?? null, environment });
      return reply('rejected', 'Unknown or invalid approval request.', { requestId: decision.requestId });
    }
    const repositoryId = stored?.identity?.repositoryId;
    const [approvers, framework] = await Promise.all([
      repositoryId
        ? approverSource.approversFor(repositoryId)
        : { state: 'misconfigured', reason: 'request has no verified identity', userIds: null },
      decideFramework(frameworkPolicy, stored?.identity?.jobWorkflowSha)
    ]);
    const auth = authorizeSlackInteraction({ interaction, approvers });
    if (!auth.authorized) {
      log({
        event: 'unauthorized',
        requestId: decision.requestId,
        repositoryId: repositoryId ?? null,
        userId: auth.userId || null,
        approverList: approvers.state,
        reason: approvers.reason ?? auth.reason ?? null
      });
      return reply('unauthorized', 'You are not an authorized break-glass approver.', {
        requestId: decision.requestId
      });
    }

    // Decided only for an authorized approver, and BEFORE any claim: a request
    // whose commit is no longer allowed is not decided and changes no state.
    if (framework.state !== 'allowed') {
      log({
        event: 'framework_revoked',
        requestId: decision.requestId,
        repositoryId,
        userId: auth.userId,
        state: framework.state,
        reason: framework.reason,
        frameworkSha: stored?.identity?.jobWorkflowSha ?? null
      });
      return reply('revoked', 'This request was filed by a framework commit that is no longer allowed. It cannot be decided.', {
        requestId: decision.requestId
      });
    }

    const nowDate = now();
    const claim = claimDecision({
      requestId: decision.requestId,
      action: decision.action,
      userId: auth.userId,
      username: auth.username,
      requests: { [decision.requestId]: stored },
      now: nowDate
    });
    if (claim.outcome === 'expired') {
      await store.expire(stored, nowDate.toISOString());
      return reply('expired', 'This approval request has expired.', { requestId: decision.requestId });
    }
    if (claim.outcome === 'duplicate') {
      return reply('duplicate', `This request is already ${claim.status}.`, { requestId: decision.requestId });
    }
    if (claim.outcome !== 'claimed') {
      return reply('rejected', 'Unknown or invalid approval request.', { requestId: decision.requestId });
    }

    try {
      await store.claim(claim.request, nowDate.toISOString());
    } catch (error) {
      if (!(error instanceof ConditionFailed)) throw error;
      // Someone else committed first (or it expired between read and write).
      const fresh = await store.get(decision.requestId);
      log({ event: 'claim_lost', requestId: decision.requestId, userId: auth.userId, status: fresh?.status });
      return reply('duplicate', `This request is already ${fresh?.status ?? 'decided'}.`, {
        requestId: decision.requestId
      });
    }

    // Finalize BEFORE any side effect, so a Slack/GitHub failure can never strand
    // a valid decision in `processing`.
    const finalized = finalizeDecision({ request: claim.request, userId: auth.userId, now: now() });
    await store.finalize(finalized, auth.userId);
    log({
      event: 'decided',
      requestId: finalized.requestId,
      repositoryId: finalized.identity?.repositoryId ?? null,
      runId: finalized.identity?.runId ?? null,
      status: finalized.status,
      approverId: auth.userId
    });

    return {
      statusCode: 200,
      outcome: 'claimed',
      requestId: finalized.requestId,
      decision: finalized.status,
      followUp: { kind: 'side-effects', requestId: finalized.requestId }
    };
  }

  // --- Follow-up work (after the ack) -----------------------------------------
  async function runFollowUp(job) {
    if (job?.kind === 'ephemeral') {
      if (!SLACK_RESPONSE_URL.test(job.responseUrl || '')) throw new Error('refusing non-Slack response_url');
      await slack.respond(job.responseUrl, ephemeral(String(job.text || '')));
      return { done: true };
    }
    if (job?.kind !== 'side-effects') throw new Error('unknown follow-up job');

    // Work only from stored, finalized state — never from the job payload.
    if (!(await store.claimSideEffects(String(job.requestId || ''), now().toISOString()))) {
      return { done: false, reason: 'not finalized or already delivered' };
    }
    const request = await store.get(job.requestId);
    // The audit comment's destination is the verified identity, never context.
    if (!request?.identity) throw new Error('refusing side effects for a request without verified identity');
    const effects = [
      github.postComment(request.identity.repository, request.identity.pullRequest, buildAuditComment(request))
    ];
    if (request.slack) effects.push(slack.update(buildDecisionUpdate(request)));
    const results = await Promise.allSettled(effects);
    const failures = results.filter((r) => r.status === 'rejected').map((r) => String(r.reason));
    for (const failure of failures) console.error(`break-glass side effect failed: ${failure}`);
    return { done: true, failures };
  }

  return { notify, status, handleInteraction, runFollowUp };
}
