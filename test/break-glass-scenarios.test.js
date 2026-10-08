// Phase 3E scenario table (docs/break-glass-validation.md § Evidence matrix):
// the whole break-glass chain, in process, with nothing stubbed between the
// steps the workflow runs:
//
//   real security gate (fixture reports)  -> evidence revalidation and route
//   -> break-glass-notify (Lambda transport) -> broker CI handler (real OIDC
//   verifier, framework policy, approvers, store) -> signed Slack clicks at
//   the interaction handler -> break-glass-poll -> break-glass-result
//   -> final gate -> conformance
//
// Each row is one live case of the synthetic session, so the live run is this
// table against AWS. Only the transport (Lambda invoke, SSM, DynamoDB, Slack,
// GitHub) is faked.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, describe, it } from 'node:test';

import { gateDigest, resolveBrokerRoute, revalidateGateForBreakGlass } from '../security/scripts/break-glass-evidence.mjs';
import { notifyBreakGlass } from '../security/scripts/break-glass-notify.mjs';
import { pollBreakGlass } from '../security/scripts/break-glass-poll.mjs';
import { deriveBreakGlassResult } from '../security/scripts/break-glass-result.mjs';
import { explainBreakGlass } from '../security/scripts/conformance.mjs';
import { decideSourceGate } from '../security/scripts/final-gate.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';
import { brokerEnv, signedClick } from './support/broker-env.mjs';
import { SLACK_A, SLACK_B, approverParameter, approversById } from './support/fake-approvers.mjs';
import { REPO_A, SHA_A } from './support/jwt-fixtures.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const WORK = mkdtempSync(join(tmpdir(), 'bg-scenarios-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

const RUN = { repository: REPO_A.repository, commitSha: SHA_A, runId: '700001' };
const PULL_REQUEST = '51';
const OTHER_SHA = 'e'.repeat(40);
const INTERVAL_MS = 10_000;
const BROKERS = {
  functionName: 'ssd-break-glass-production-ci',
  roleArn: 'arn:aws:iam::111122223333:role/ssd-break-glass-production-invoker-1001',
  region: 'us-east-1',
  syntheticFunctionName: 'ssd-break-glass-synthetic-ci',
  syntheticRoleArn: 'arn:aws:iam::111122223333:role/ssd-break-glass-synthetic-invoker-1001',
  syntheticRegion: 'us-east-1'
};

// A real eligible BLOCK, produced by the gate exactly as a synthetic run
// produces it: the SAST fixture's report, with the fixture recorded.
async function syntheticGate() {
  const dir = mkdtempSync(join(WORK, 'gate-'));
  return runSecurityGate({
    policy: resolve('security/policy.yaml'),
    gitleaks: join(CLEAN, 'gitleaks.json'),
    trufflehog: join(CLEAN, 'trufflehog.json'),
    npmAudit: join(CLEAN, 'npm-audit.json'),
    osv: join(CLEAN, 'osv-scanner.json'),
    semgrep: join(FIXTURES, 'new-high-sast/semgrep.json'),
    baseline: join(CLEAN, 'semgrep-baseline.json'),
    output: join(dir, 'security-gate.json'),
    exceptions: join(dir, 'gate-exceptions.json'),
    provenance: RUN,
    syntheticFixture: 'sast'
  });
}

const approvers = (users = [SLACK_A, SLACK_B]) => approversById({ [REPO_A.repositoryId]: users });
const setApprovers = (source, users) => {
  source.parameters[approverParameter(REPO_A.repositoryId)] = JSON.stringify(users);
};

// Runs one break-glass job against `env`. `onTick(tick, ctx)` runs at every
// poll interval (tick 1 is the first wait after the request was filed): that
// is where approvers click and operators revoke.
async function runJob(env, { timeoutSeconds = 120, onTick = async () => {} } = {}) {
  const gate = await syntheticGate();
  // Preflight: the framework's own revalidation and route, before any credential.
  const validated = revalidateGateForBreakGlass(gate, { expectedDigest: gateDigest(gate), expectedProvenance: RUN });
  const route = resolveBrokerRoute({ synthetic: validated.synthetic, config: BROKERS });
  const preflight = { accepted: true, gateDigest: validated.digest, synthetic: validated.synthetic, route: route.route };
  const token = async () => env.tokenFor({ repo: REPO_A, runId: RUN.runId, runAttempt: '1', pullRequest: PULL_REQUEST, sha: SHA_A });
  const ctx = { clicks: [], requestId: null };
  ctx.click = async (userId, action = 'approve') => {
    const response = await env.interactions(signedClick(ctx.requestId, userId, action));
    const outcome = response.headers['x-break-glass-outcome'];
    ctx.clicks.push({ userId, action, outcome });
    return outcome;
  };

  let request = null;
  let requestOutcome = 'failure';
  try {
    request = await notifyBreakGlass({
      gate,
      context: { repository: RUN.repository, commitSha: RUN.commitSha, pullRequest: PULL_REQUEST, ciSystem: 'github-actions' },
      timeoutSeconds,
      invoke: (event) => env.ci(event),
      mintIdentityToken: token
    });
    requestOutcome = 'success';
    ctx.requestId = request.requestId;
  } catch (error) {
    ctx.requestError = error;
  }

  let decision = null;
  let pollOutcome = 'skipped';
  if (request) {
    let clock = 0;
    let tick = 0;
    try {
      decision = await pollBreakGlass({
        request,
        invoke: (event) => env.ci(event),
        mintIdentityToken: token,
        timeoutSeconds,
        intervalMilliseconds: INTERVAL_MS,
        now: () => clock,
        sleep: async (ms) => {
          clock += ms;
          env.advance(ms);
          tick += 1;
          await onTick(tick, ctx);
        }
      });
      // The poll step exits 0 only for an approval.
      pollOutcome = decision.status === 'approved' ? 'success' : 'failure';
    } catch (error) {
      ctx.pollError = error;
      pollOutcome = 'failure';
    }
  }

  const result = deriveBreakGlassResult({ preflightOutcome: 'success', requestOutcome, pollOutcome, preflight, request, decision });
  const finalGate = decideSourceGate({
    sourceResult: 'failure', verdict: 'BLOCK', gateMode: 'enforce', integrityTrusted: 'true',
    breakGlassEligible: 'true', breakGlassDelegated: 'true', secretScanResult: 'success',
    dependencyScanResult: 'success', sastResult: 'success', sourceGateDigest: validated.digest,
    breakGlassResult: result.controlResult, breakGlassDecision: result.decisionStatus,
    breakGlassDelivered: String(result.requestDelivered), breakGlassGateDigest: result.gateDigest
  });
  const evidence = { status: result.controlResult, decision: result.decisionStatus, request_delivered: String(result.requestDelivered), gate_digest: result.gateDigest, delegated: 'true' };
  const sourceGate = { status: 'failure', verdict: 'BLOCK', gate_mode: 'enforce', integrity_trusted: 'true', break_glass_eligible: 'true', gate_digest: validated.digest };
  // Conformance must accept the override only when the job proved an approval.
  const conformanceOverride = explainBreakGlass(evidence, { ...sourceGate, override: 'approved' }).passed;

  // Deliver the deferred side effects (audit comment, Slack update) once.
  for (const job of env.enqueued.filter((j) => j.kind === 'side-effects')) await env.broker.runFollowUp(job);
  const stored = env.requests().map((item) => JSON.parse(item.doc.S));
  return { gate, validated, request, decision, result, finalGate, conformanceOverride, ctx, stored };
}

const blockStands = (run) => {
  assert.equal(run.result.controlResult, 'failure');
  assert.equal(run.finalGate.outcome, 'block');
  assert.equal(run.conformanceOverride, false, 'conformance never accepts an unproven override');
};

describe('Phase 3E scenario table: the whole chain, in process', () => {
  it('A + R: eligible BLOCK -> request -> approval -> overridden BLOCK, every digest identical', async () => {
    const env = brokerEnv({ approvers: approvers() });
    const run = await runJob(env, { onTick: async (tick, ctx) => tick === 1 && ctx.click(SLACK_A) });

    assert.equal(run.validated.synthetic, true, 'the fixture is recorded in the evidence');
    assert.deepEqual(run.ctx.clicks.map((c) => c.outcome), ['claimed']);
    assert.equal(run.decision.status, 'approved');
    assert.equal(run.result.decisionStatus, 'approved');
    assert.equal(run.finalGate.outcome, 'overridden-block');
    assert.equal(run.conformanceOverride, true);
    // R: one digest from the evidence to the final gate.
    const digest = gateDigest(run.gate);
    assert.deepEqual(
      [run.validated.digest, run.request.gateDigest, run.stored[0].gateDigest, run.decision.gateDigest, run.result.gateDigest],
      [digest, digest, digest, digest, digest]
    );
    assert.equal(env.github.length, 1, 'exactly one audit comment');
    assert.equal(env.github[0].repo, REPO_A.repository);
  });

  it('B: an explicit denial leaves the BLOCK', async () => {
    const env = brokerEnv({ approvers: approvers() });
    const run = await runJob(env, { onTick: async (tick, ctx) => tick === 1 && ctx.click(SLACK_A, 'deny') });
    assert.equal(run.decision.status, 'denied');
    assert.equal(run.result.decisionStatus, 'denied');
    blockStands(run);
  });

  it('C: no decision before the deadline leaves the BLOCK (timeout or expiry, never a denial)', async () => {
    const env = brokerEnv({ approvers: approvers() });
    const run = await runJob(env, { timeoutSeconds: 60 });
    assert.ok(['timeout', 'expired'].includes(run.result.decisionStatus), run.result.decisionStatus);
    blockStands(run);
    assert.equal(env.github.length, 0, 'no audit comment without a decision');
  });

  it('E + F: two approvers click at once -> exactly one decision; a later click changes nothing', async () => {
    const env = brokerEnv({ approvers: approvers() });
    const run = await runJob(env, {
      onTick: async (tick, ctx) => {
        if (tick !== 1) return;
        await Promise.all([ctx.click(SLACK_A, 'approve'), ctx.click(SLACK_B, 'deny')]);
        await ctx.click(SLACK_B, 'deny');
      }
    });
    const [first, second, repeat] = run.ctx.clicks;
    assert.deepEqual([first.outcome, second.outcome].sort(), ['claimed', 'duplicate']);
    assert.equal(repeat.outcome, 'duplicate', 'F: a click after the decision is a duplicate');
    const winner = [first, second].find((c) => c.outcome === 'claimed');
    const expected = winner.action === 'approve' ? 'approved' : 'denied';
    assert.equal(run.stored[0].status, expected, 'the stored decision is the winner\'s');
    assert.equal(run.decision.status, expected, 'CI reads the winner\'s decision');
    assert.equal(env.enqueued.filter((j) => j.kind === 'side-effects').length, 1, 'one decision, one set of side effects');
    assert.equal(env.github.length, 1, 'exactly one audit comment');
  });

  it('G + H: the framework commit is revoked while CI polls -> the poll fails closed and a click is refused', async () => {
    const env = brokerEnv({ approvers: approvers() });
    const run = await runJob(env, {
      onTick: async (tick, ctx) => {
        if (tick !== 1) return;
        env.framework.allow([OTHER_SHA]);
        assert.equal(await ctx.click(SLACK_A), 'revoked', 'G: a click on a revoked commit decides nothing');
      }
    });
    assert.match(run.ctx.pollError?.message ?? '', /framework_rejected: framework_sha_not_allowed/, 'H: the next status call is refused');
    assert.equal(run.result.decisionStatus, 'error');
    blockStands(run);
    assert.equal(run.stored[0].status, 'pending', 'revoked is never stored as a decision');
    assert.equal(env.github.length, 0);
  });

  it('I: an approver removed after filing cannot decide; the current list does', async () => {
    const source = approvers([SLACK_A, SLACK_B]);
    const env = brokerEnv({ approvers: source });
    const run = await runJob(env, {
      onTick: async (tick, ctx) => {
        if (tick !== 1) return;
        setApprovers(source, [SLACK_B]);
        assert.equal(await ctx.click(SLACK_A), 'unauthorized');
        assert.equal(await ctx.click(SLACK_B), 'claimed');
      }
    });
    assert.equal(run.decision.status, 'approved');
    assert.equal(run.stored[0].approver.id, SLACK_B, 'decided by the approver still listed');
    assert.equal(run.finalGate.outcome, 'overridden-block');
  });

  it('J: an empty approver list `[]` authorizes nobody; the BLOCK stands', async () => {
    const env = brokerEnv({ approvers: approvers([]) });
    const run = await runJob(env, {
      timeoutSeconds: 60,
      onTick: async (tick, ctx) => {
        if (tick !== 1) return;
        assert.equal(await ctx.click(SLACK_A), 'unauthorized');
        assert.equal(await ctx.click(SLACK_B, 'deny'), 'unauthorized');
      }
    });
    assert.ok(['pending', 'expired'].includes(run.stored[0].status), run.stored[0].status);
    assert.ok(!('approver' in run.stored[0]), 'nobody decided');
    blockStands(run);
    assert.equal(env.github.length, 0);
  });
});
