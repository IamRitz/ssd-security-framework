// The source leg of the caller's stable `security-gate` check, when the caller
// runs Lambda break-glass as a separate job (`_break-glass-lambda.yml`).
//
// Framework-owned so every caller evaluates the SAME conjunction instead of a
// hand-written `source failed && break-glass succeeded` shell expression, which
// would let a scanner crash or a hard block turn green.
//
// Outcomes (kept distinct from the policy verdict, which is never rewritten):
//   pass              source passed (PASS / PASS-WITH-EXCEPTIONS, or a BLOCK the
//                     source workflow itself did not enforce: log-only, or an
//                     in-job break-glass approval on the legacy/HTTP path)
//   overridden-block  source FAILED on an eligible policy BLOCK, and an exact,
//                     verified break-glass approval for that same gate exists
//   block             everything else — including any missing, empty, or
//                     unrecognized fact
//
// An override requires ALL of the following, each compared exactly:
//   source result `failure`, verdict `BLOCK`, gate_mode `enforce`,
//   integrity_trusted `true`, break_glass_eligible `true`,
//   break_glass_delegated `true`, every scanning control `success` (so the
//   failure is the policy BLOCK, not a scanner crash), break-glass job result
//   `success`, decision_status `approved`, request_delivered `true`, and a
//   SHA-256 gate digest that is identical on both sides.
//
// The image gate is deliberately NOT an input: break-glass never touches image
// policy, so a caller aggregates BLOCK_DEPLOY separately and it stays red.
import { appendFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HEX64 = /^[0-9a-f]{64}$/;
const text = (value) => (typeof value === 'string' ? value.trim() : '');

export function decideSourceGate(facts = {}) {
  const f = Object.fromEntries(Object.entries(facts).map(([key, value]) => [key, text(value)]));
  const block = (reason) => ({ outcome: 'block', override: '', reason });

  if (f.sourceResult === 'success') {
    if (['PASS', 'PASS-WITH-EXCEPTIONS'].includes(f.verdict)) {
      return { outcome: 'pass', override: '', reason: `source policy verdict ${f.verdict}` };
    }
    if (f.gateMode === 'log-only') {
      return { outcome: 'pass', override: '', reason: `source verdict ${f.verdict || 'unavailable'} reported but not enforced (gate_mode=log-only)` };
    }
    if (f.verdict === 'BLOCK' && f.gateMode === 'enforce') {
      // Only the source workflow's own in-job approval (legacy/HTTP transport)
      // lets its gate job succeed on an enforced BLOCK.
      return { outcome: 'overridden-block', override: 'in-job', reason: 'source verdict BLOCK, overridden by the source workflow\'s own verified break-glass approval' };
    }
    return block(`source succeeded but its verdict '${f.verdict}' / gate_mode '${f.gateMode}' is not a recognized combination (fail-closed)`);
  }

  if (f.sourceResult !== 'failure') {
    return block(`source security did not complete (result='${f.sourceResult}')`);
  }

  // From here the source workflow FAILED. Only an exact, verified approval of an
  // eligible policy BLOCK may change the outcome, and every fact is required.
  const required = [
    [f.verdict === 'BLOCK', `source failed with verdict '${f.verdict}', not a policy BLOCK`],
    [f.gateMode === 'enforce', `gate_mode is '${f.gateMode}', not enforce`],
    [f.integrityTrusted === 'true', `integrity_trusted is '${f.integrityTrusted}': a scan could not be trusted, which break-glass never overrides`],
    [f.breakGlassEligible === 'true', `break_glass_eligible is '${f.breakGlassEligible}': the BLOCK includes a finding break-glass may never override`],
    [f.breakGlassDelegated === 'true', `break_glass_delegated is '${f.breakGlassDelegated}': the source workflow did not hand this BLOCK to Lambda break-glass`],
    [f.secretScanResult === 'success', `secret scanning result is '${f.secretScanResult}': the failure is not only a policy BLOCK`],
    [f.dependencyScanResult === 'success', `dependency scanning result is '${f.dependencyScanResult}': the failure is not only a policy BLOCK`],
    [f.sastResult === 'success', `SAST result is '${f.sastResult}': the failure is not only a policy BLOCK`],
    [f.breakGlassResult === 'success', `break-glass job result is '${f.breakGlassResult}'`],
    [f.breakGlassDecision === 'approved', `break-glass decision is '${f.breakGlassDecision}'`],
    [f.breakGlassDelivered === 'true', `break-glass request_delivered is '${f.breakGlassDelivered}'`],
    [HEX64.test(f.sourceGateDigest), 'the source gate digest is missing or malformed'],
    [f.breakGlassGateDigest === f.sourceGateDigest, 'the approval is bound to a different gate digest than the evaluated source gate']
  ];
  for (const [ok, reason] of required) {
    if (!ok) return block(reason);
  }
  return {
    outcome: 'overridden-block',
    override: 'approved',
    reason: `source policy verdict BLOCK, overridden by a verified break-glass approval for gate sha256 ${f.sourceGateDigest}`
  };
}

export function factsFromEnv(env = process.env) {
  return {
    sourceResult: env.SOURCE_RESULT,
    verdict: env.SOURCE_VERDICT,
    gateMode: env.SOURCE_GATE_MODE,
    integrityTrusted: env.SOURCE_INTEGRITY_TRUSTED,
    breakGlassEligible: env.SOURCE_BREAK_GLASS_ELIGIBLE,
    breakGlassDelegated: env.SOURCE_BREAK_GLASS_DELEGATED,
    secretScanResult: env.SOURCE_SECRET_SCAN_RESULT,
    dependencyScanResult: env.SOURCE_DEPENDENCY_SCAN_RESULT,
    sastResult: env.SOURCE_SAST_RESULT,
    sourceGateDigest: env.SOURCE_GATE_DIGEST,
    breakGlassResult: env.BREAK_GLASS_RESULT,
    breakGlassDecision: env.BREAK_GLASS_DECISION,
    breakGlassDelivered: env.BREAK_GLASS_REQUEST_DELIVERED,
    breakGlassGateDigest: env.BREAK_GLASS_GATE_DIGEST
  };
}

async function main() {
  const facts = factsFromEnv(process.env);
  const decision = decideSourceGate(facts);
  if (text(facts.breakGlassDelegated) === 'true' && !['success', 'failure'].includes(text(facts.breakGlassResult))) {
    // The source workflow's own BLOCK alert was still sent (delegation never
    // suppresses it); what is missing is the approval request.
    console.log(`::error::The source BLOCK was delegated to Lambda break-glass, but the break-glass job result is '${text(facts.breakGlassResult)}'. No approval request was sent, so no override is possible — check the caller's break-glass job condition. (The normal BLOCK alert was sent by the source workflow.)`);
  }
  const label = { pass: 'PASS', block: 'BLOCK', 'overridden-block': 'OVERRIDDEN BLOCK' }[decision.outcome];
  if (decision.outcome === 'overridden-block') {
    console.log(`::warning::Source security: ${label} — ${decision.reason}. The policy verdict remains BLOCK.`);
  } else if (decision.outcome === 'block') {
    console.log(`::error::Source security: ${label} — ${decision.reason}`);
  } else {
    console.log(`Source security: ${label} — ${decision.reason}`);
  }
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `source_outcome=${decision.outcome}\nsource_override=${decision.override}\n`);
  }
  process.exitCode = decision.outcome === 'block' ? 1 : 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) await main();
