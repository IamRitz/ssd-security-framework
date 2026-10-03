import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  buildAuditComment,
  claimDecision,
  finalizeDecision
} from '../broker/authorize/break-glass-decision.mjs';
import {
  extractSlackDecision,
  parseSlackInteraction,
  verifySlackSignature
} from '../broker/authorize/slack-interaction-verify.mjs';
import {
  authorizeSlackInteraction,
  isAuthorizedApprover,
  parseApproverMapFromEnv
} from '../broker/authorize/slack-authorize.mjs';

const REPO_A = 'IamRitz/secure-software-delivery';
const REPO_B = 'org/other-repo';
const APPROVER_MAP_ENV = JSON.stringify({ [REPO_A]: ['U0BV6TWN60J'], [REPO_B]: ['U111', 'U222'] });

const SIGNING_SECRET = 'test-signing-secret';
const REQUEST_ID = '11111111-1111-4111-8111-111111111111';

function slackInteraction({ userId = 'U-APPROVER', action = 'approve' } = {}) {
  return {
    type: 'block_actions',
    user: { id: userId, username: 'approver' },
    actions: [{ action_id: `breakglass:${REQUEST_ID}:${action}`, type: 'button' }]
  };
}

// Build a genuine Slack-signed request: raw urlencoded form body + v0 signature.
function signedSlackRequest(interaction, { secret = SIGNING_SECRET, timestamp } = {}) {
  const ts = timestamp ?? String(Math.floor(Date.now() / 1000));
  const rawBody = `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
  const base = `v0:${ts}:${rawBody}`;
  const signature = `v0=${createHmac('sha256', secret).update(base).digest('hex')}`;
  return { rawBody, timestamp: ts, signature };
}

function pendingRequests() {
  return {
    [REQUEST_ID]: {
      requestId: REQUEST_ID,
      gateDigest: 'digest-1',
      status: 'pending',
      expiresAt: '2099-01-01T00:00:00.000Z',
      findings: [{ policyRule: 'sast.high_new', id: 'demo.rule' }]
    }
  };
}

describe('Slack signature verification', () => {
  it('accepts a genuinely valid HMAC-signed request', () => {
    const { rawBody, timestamp, signature } = signedSlackRequest(slackInteraction());
    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature, timestamp, rawBody }),
      true
    );
  });

  it('rejects a request signed with the wrong secret', () => {
    const { rawBody, timestamp, signature } = signedSlackRequest(slackInteraction(), {
      secret: 'attacker-secret'
    });
    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature, timestamp, rawBody }),
      false
    );
  });

  it('rejects a tampered body against a real signature', () => {
    const { timestamp, signature } = signedSlackRequest(slackInteraction());
    const tampered = `payload=${encodeURIComponent(JSON.stringify(slackInteraction({ action: 'deny' })))}`;
    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature, timestamp, rawBody: tampered }),
      false
    );
  });

  it('rejects a stale timestamp even with a valid signature (replay defense)', () => {
    const timestamp = '1725400000';
    const { rawBody, signature } = signedSlackRequest(slackInteraction(), { timestamp });
    // Fresh clock relative to the old timestamp -> accepted.
    assert.equal(
      verifySlackSignature({
        signingSecret: SIGNING_SECRET,
        signature,
        timestamp,
        rawBody,
        now: Number(timestamp) * 1000
      }),
      true
    );
    // Six minutes later the same signed bytes are rejected.
    assert.equal(
      verifySlackSignature({
        signingSecret: SIGNING_SECRET,
        signature,
        timestamp,
        rawBody,
        now: Number(timestamp) * 1000 + 6 * 60 * 1000
      }),
      false
    );
  });

  it('rejects a malformed signature header', () => {
    const { rawBody, timestamp } = signedSlackRequest(slackInteraction());
    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature: 'not-a-sig', timestamp, rawBody }),
      false
    );
  });

  it('verifies against the raw body, not a re-serialized payload', () => {
    const interaction = slackInteraction();
    const { rawBody, timestamp, signature } = signedSlackRequest(interaction);
    // Valid against the exact raw bytes.
    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature, timestamp, rawBody }),
      true
    );
    // Re-encoding the parsed payload changes the bytes -> signature no longer matches,
    // which is exactly why verification must run before parsing.
    const reserialized = `payload=${encodeURIComponent(JSON.stringify(parseSlackInteraction(rawBody)))} `;
    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature, timestamp, rawBody: reserialized }),
      false
    );
  });
});

describe('Slack payload parsing and authorization', () => {
  it('decodes the urlencoded payload and extracts the user id and decision', () => {
    const { rawBody } = signedSlackRequest(slackInteraction({ userId: 'U-REAL' }));
    const interaction = parseSlackInteraction(rawBody);
    assert.equal(interaction.user.id, 'U-REAL');
    assert.deepEqual(extractSlackDecision(interaction), { requestId: REQUEST_ID, action: 'approve' });
  });

  it('authorizes per repo: a repo-A approver is rejected for a repo-B request', () => {
    const map = parseApproverMapFromEnv(APPROVER_MAP_ENV);
    // U0BV6TWN60J is listed only under repo A.
    assert.equal(
      authorizeSlackInteraction({ interaction: slackInteraction({ userId: 'U0BV6TWN60J' }), repo: REPO_A, approverMap: map }).authorized,
      true
    );
    const crossRepo = authorizeSlackInteraction({
      interaction: slackInteraction({ userId: 'U0BV6TWN60J' }),
      repo: REPO_B,
      approverMap: map
    });
    assert.equal(crossRepo.authorized, false);
    assert.equal(crossRepo.repo, REPO_B);
  });

  it('rejects every user for a repo with no entry in the map (fail closed)', () => {
    const map = parseApproverMapFromEnv(APPROVER_MAP_ENV);
    assert.equal(isAuthorizedApprover('U0BV6TWN60J', 'org/unonboarded', map), false);
    assert.equal(isAuthorizedApprover('U111', 'org/unonboarded', map), false);
  });

  it('treats malformed JSON (and non-objects) as an empty map — every repo fails closed, no throw', () => {
    const broken = parseApproverMapFromEnv('{not valid json');
    assert.equal(broken.size, 0);
    assert.equal(isAuthorizedApprover('U0BV6TWN60J', REPO_A, broken), false);
    assert.equal(parseApproverMapFromEnv('["U111"]').size, 0); // JSON array, not an object
    assert.equal(parseApproverMapFromEnv('').size, 0);
    assert.equal(parseApproverMapFromEnv(undefined).size, 0);
  });

  it('preserves single-repo behavior once the demo repo has its one entry', () => {
    const map = parseApproverMapFromEnv(JSON.stringify({ [REPO_A]: ['U0BV6TWN60J'] }));
    assert.equal(isAuthorizedApprover('U0BV6TWN60J', REPO_A, map), true);
    assert.equal(isAuthorizedApprover('U-INTRUDER', REPO_A, map), false);
  });
});

describe('Shared break-glass decision logic', () => {
  it('runs the full verify -> parse -> authorize -> claim -> finalize path for a valid Slack approval', () => {
    const requests = pendingRequests();
    // The request's stored repo is REPO_A; the clicker is REPO_A's approver.
    requests[REQUEST_ID].context = { repository: REPO_A, pullRequest: '12' };
    const { rawBody, timestamp, signature } = signedSlackRequest(slackInteraction({ userId: 'U0BV6TWN60J' }));

    assert.equal(
      verifySlackSignature({ signingSecret: SIGNING_SECRET, signature, timestamp, rawBody }),
      true
    );
    const interaction = parseSlackInteraction(rawBody);
    const auth = authorizeSlackInteraction({
      interaction,
      repo: requests[REQUEST_ID].context.repository, // repo from STORED state, not the click
      approverMap: parseApproverMapFromEnv(APPROVER_MAP_ENV)
    });
    assert.equal(auth.authorized, true);
    const { requestId, action } = extractSlackDecision(interaction);

    const claim = claimDecision({ requestId, action, userId: auth.userId, username: auth.username, requests });
    assert.equal(claim.outcome, 'claimed');
    assert.equal(requests[REQUEST_ID].status, 'processing');

    finalizeDecision({ request: requests[REQUEST_ID], userId: auth.userId });
    assert.equal(requests[REQUEST_ID].status, 'approved');
    assert.equal(requests[REQUEST_ID].approver.id, 'U0BV6TWN60J');

    const comment = buildAuditComment(requests[REQUEST_ID]);
    assert.match(comment, /APPROVED/);
    assert.match(comment, /U0BV6TWN60J/);
    assert.match(comment, /sast\.high_new/);
  });

  it('leaves state untouched for an unauthorized Slack click', () => {
    const requests = pendingRequests();
    const auth = authorizeSlackInteraction({
      interaction: slackInteraction({ userId: 'U-INTRUDER' }),
      repo: REPO_A,
      approverMap: parseApproverMapFromEnv(APPROVER_MAP_ENV)
    });
    assert.equal(auth.authorized, false);
    // An authorization failure means claimDecision is never called.
    assert.equal(requests[REQUEST_ID].status, 'pending');
    assert.equal(requests[REQUEST_ID].claim, undefined);
  });

  it('only lets the first click claim a request; the second is a duplicate', () => {
    const requests = pendingRequests();
    const first = claimDecision({ requestId: REQUEST_ID, action: 'approve', userId: 'U-A', username: 'a', requests });
    const second = claimDecision({ requestId: REQUEST_ID, action: 'deny', userId: 'U-B', username: 'b', requests });
    assert.equal(first.outcome, 'claimed');
    assert.equal(second.outcome, 'duplicate');
    assert.equal(second.status, 'processing');
  });

  it('refuses to finalize when a different user holds the claim', () => {
    const requests = pendingRequests();
    claimDecision({ requestId: REQUEST_ID, action: 'approve', userId: 'U-A', username: 'a', requests });
    assert.throws(
      () => finalizeDecision({ request: requests[REQUEST_ID], userId: 'U-OTHER' }),
      /claim changed before finalization/
    );
  });
});
