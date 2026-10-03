// Transport-neutral break-glass broker used by the Lambda handlers.
//
// Verification, authorization, and the claim/finalize decisions are the shared
// modules imported verbatim — the same ones the Express service imports and the
// n8n Code nodes mirror. The only thing this file adds is persistence: each
// decision the modules make is committed with a DynamoDB conditional write, which
// is what makes a rapid double-click safe by construction instead of by
// serializing executions.
import {
  verifySlackSignature,
  parseSlackInteraction,
  extractSlackDecision
} from '../authorize/slack-interaction-verify.mjs';
import { authorizeSlackInteraction } from '../authorize/slack-authorize.mjs';
import {
  claimDecision,
  finalizeDecision,
  buildAuditComment
} from '../authorize/break-glass-decision.mjs';
import { buildApprovalMessage, buildDecisionUpdate, ephemeral } from '../messages.mjs';
import { createPendingRequest, statusView, validateNotifyPayload } from '../request.mjs';
import { ConditionFailed } from './dynamodb-store.mjs';

const SLACK_RESPONSE_URL = /^https:\/\/hooks\.slack\.com\//;

export function createBroker({
  store,
  slack,
  github,
  signingSecret,
  approverMap,
  slackChannelId,
  now = () => new Date(),
  randomUUID = () => globalThis.crypto.randomUUID(),
  log = (entry) => console.log(JSON.stringify(entry))
}) {
  // --- CI notify ------------------------------------------------------------
  async function notify(payload) {
    try {
      validateNotifyPayload(payload);
    } catch (error) {
      return { ok: false, statusCode: 400, error: error.message };
    }
    if (!slackChannelId) return { ok: false, statusCode: 500, error: 'SLACK_CHANNEL_ID is not configured' };

    const request = createPendingRequest(payload, { now: now(), randomUUID });
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
    log({ event: 'notify', requestId: request.requestId, repository: request.context.repository });
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
  async function status(requestId) {
    const request = await store.get(String(requestId || ''));
    if (!request) return { ok: false, statusCode: 404, error: 'unknown_request' };
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

    // The repo comes from the STORED request, never from the click payload.
    const stored = await store.get(decision.requestId);
    const auth = authorizeSlackInteraction({
      interaction,
      repo: stored?.context?.repository,
      approverMap
    });
    if (!auth.authorized) {
      log({ event: 'unauthorized', requestId: decision.requestId, userId: auth.userId || null });
      return reply('unauthorized', 'You are not an authorized break-glass approver.', {
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
    log({ event: 'decided', requestId: finalized.requestId, status: finalized.status, approverId: auth.userId });

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
    const effects = [
      github.postComment(request.context.repository, request.context.pullRequest, buildAuditComment(request))
    ];
    if (request.slack) effects.push(slack.update(buildDecisionUpdate(request)));
    const results = await Promise.allSettled(effects);
    const failures = results.filter((r) => r.status === 'rejected').map((r) => String(r.reason));
    for (const failure of failures) console.error(`break-glass side effect failed: ${failure}`);
    return { done: true, failures };
  }

  return { notify, status, handleInteraction, runFollowUp };
}
