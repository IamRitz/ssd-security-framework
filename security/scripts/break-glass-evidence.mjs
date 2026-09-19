// Independent revalidation of a source gate result for Lambda break-glass, and
// resolution of the broker it may talk to. Framework-owned, dependency-free,
// and run by `_break-glass-lambda.yml` BEFORE it acquires any AWS credential.
//
// Why this exists separately from the source workflow's own eligibility check:
// the Lambda break-glass job is the only job that can obtain cloud credentials,
// and it runs in a DIFFERENT job from the gate. It therefore trusts nothing it
// is told by its caller — not `break_glass_eligible`, not a synthetic flag —
// and re-derives every fact it acts on from the gate evidence itself:
//
//   1. the evidence belongs to THIS run (repository, commit, run id);
//   2. the evidence is the exact gate the source workflow evaluated (digest);
//   3. the BLOCK is overridable: trusted scans, only eligible rules, no hard
//      block anywhere in the raw findings — re-checked from `findings`, not
//      from the gate's own `breakGlass.eligible` summary alone;
//   4. the broker route (production vs isolated synthetic test broker) follows
//      from the evidence's `synthetic` record, never from a caller boolean.
//
// Any doubt is a refusal. A refusal here happens before the OIDC step, so a
// hard block can never cause a role assumption or a broker invocation.
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateEligibleGate } from './break-glass-notify.mjs';

// The only policy rules break-glass may ever override. Identical to the set
// validateEligibleGate enforces; restated here so the raw-finding scan below
// does not depend on the gate's own eligibility markings.
export const ELIGIBLE_RULES = Object.freeze([
  'sast.critical_new',
  'sast.high_new',
  'dependencies.critical_with_fix',
  'dependencies.high_with_fix'
]);

// Rules that are hard blocks under every policy. Named so the refusal says WHY.
const HARD_BLOCK_RULES = {
  'secrets.verified': 'a verified secret is never overridable',
  'dependencies.malicious_package': 'a known-malicious package is never overridable'
};

export class BreakGlassRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BreakGlassRefusal';
    this.code = code;
  }
}

function refuse(code, message) {
  throw new BreakGlassRefusal(code, message);
}

// The digest the broker binds an approval to. MUST stay byte-identical to the
// one break-glass-notify.mjs sends, or approvals could not be matched.
export function gateDigest(gate) {
  return createHash('sha256').update(JSON.stringify(gate)).digest('hex');
}

const HEX64 = /^[0-9a-f]{64}$/;

function isReportIntegrity(finding) {
  return (
    finding?.id === 'report-integrity' ||
    (typeof finding?.policyRule === 'string' && finding.policyRule.endsWith('report_integrity'))
  );
}

// Returns { eligibleFindings, synthetic } or throws BreakGlassRefusal.
export function revalidateGateForBreakGlass(gate, { expectedDigest, expectedProvenance } = {}) {
  if (!gate || typeof gate !== 'object' || Array.isArray(gate)) {
    refuse('malformed-evidence', 'the security gate evidence is not a JSON object');
  }

  // 1. Run binding.
  if (!expectedProvenance) {
    refuse('configuration', 'no expected provenance was supplied to check the evidence against');
  }
  const provenance = gate.provenance;
  if (!provenance || typeof provenance !== 'object') {
    refuse('provenance', 'the gate evidence carries no provenance, so it cannot be bound to this run');
  }
  for (const [field, label] of [
    ['repository', 'repository'],
    ['commitSha', 'commit'],
    ['runId', 'workflow run']
  ]) {
    const expected = expectedProvenance[field];
    if (typeof expected !== 'string' || expected === '') {
      refuse('configuration', `expected ${label} is unknown; refusing to accept evidence without it`);
    }
    if (provenance[field] !== expected) {
      refuse(
        'provenance',
        `the gate evidence was produced for ${label} '${provenance[field]}', not this run's '${expected}'`
      );
    }
  }

  // 2. Exact-gate binding.
  const digest = gateDigest(gate);
  if (typeof expectedDigest !== 'string' || !HEX64.test(expectedDigest)) {
    refuse('configuration', 'expected_gate_digest is missing or not a SHA-256 hex digest');
  }
  if (digest !== expectedDigest) {
    refuse(
      'digest-mismatch',
      `the downloaded gate evidence (sha256 ${digest}) is not the gate the source workflow evaluated (sha256 ${expectedDigest})`
    );
  }

  // 3. Overridability, from the raw findings.
  if (gate.verdict !== 'BLOCK') {
    refuse('not-a-block', `verdict is ${gate.verdict ?? 'missing'}; break-glass exists only for a BLOCK`);
  }
  if (gate.integrity?.trusted !== true) {
    refuse('integrity', 'a scan report could not be trusted (report-integrity BLOCK); findings are UNKNOWN and never overridable');
  }
  if (gate.bootstrap?.active === true) {
    refuse('bootstrap', 'a baseline-bootstrap run is an onboarding evaluation and is never overridable');
  }
  if (!Array.isArray(gate.findings)) {
    refuse('malformed-evidence', 'the gate evidence has no findings array');
  }
  const blocked = gate.findings.filter((finding) => finding?.action === 'BLOCK');
  if (blocked.length === 0) {
    refuse('malformed-evidence', 'verdict is BLOCK but no finding carries a BLOCK action');
  }
  for (const finding of blocked) {
    if (isReportIntegrity(finding)) {
      refuse('integrity', 'the BLOCK includes a report-integrity failure, which is never overridable');
    }
    if (Object.hasOwn(HARD_BLOCK_RULES, finding.policyRule)) {
      refuse('hard-block', `the BLOCK includes ${finding.policyRule}: ${HARD_BLOCK_RULES[finding.policyRule]}`);
    }
    if (!ELIGIBLE_RULES.includes(finding.policyRule)) {
      refuse('ineligible', `the BLOCK includes ${finding.policyRule ?? 'an unclassified finding'}, which break-glass may not override`);
    }
    if (finding.breakGlassEligible !== true) {
      refuse('ineligible', `policy marked a ${finding.policyRule} finding as not break-glass eligible`);
    }
  }
  // The existing CI-side validator, unchanged, as a second opinion over the
  // gate's own summary. Its message is kept verbatim.
  let eligibleFindings;
  try {
    eligibleFindings = validateEligibleGate(gate);
  } catch (error) {
    refuse('ineligible', error.message);
  }
  // The findings sent to approvers are the summary's. They must BE the raw
  // BLOCK findings — same set, same content — otherwise a human could be shown
  // one finding while a different (or an additional) one is overridden.
  if (JSON.stringify(eligibleFindings) !== JSON.stringify(blocked)) {
    refuse('ineligible', 'the gate summary\'s eligible findings are not the raw BLOCK findings');
  }

  // 4. Synthetic-vs-real, from the evidence.
  const synthetic = gate.synthetic;
  if (!synthetic || typeof synthetic.active !== 'boolean') {
    refuse('synthetic-unknown', 'the gate evidence does not record whether a synthetic fixture was injected; refusing to guess production');
  }

  return { eligibleFindings, digest, synthetic: synthetic.active, fixture: synthetic.fixture ?? null };
}

const FUNCTION_NAME = /^[A-Za-z0-9_-]{1,64}$|^arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]{1,64}$/;
const ROLE_ARN = /^arn:aws(-[a-z]+)*:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,512}$/;
const REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;

const functionBaseName = (value) => value.replace(/^arn:aws:lambda:[a-z0-9-]+:\d{12}:function:/, '');
const text = (value) => (typeof value === 'string' ? value.trim() : '');

// Picks the broker for this request. `synthetic` comes from
// revalidateGateForBreakGlass — i.e. from the evidence.
//
// A synthetic request needs a dedicated test function AND a dedicated test
// role, and BOTH production identifiers too: "different from production" can
// only be proven by comparing against production. A missing synthetic value
// never falls back to production.
export function resolveBrokerRoute({ synthetic, config = {} }) {
  if (typeof synthetic !== 'boolean') {
    refuse('synthetic-unknown', 'the broker route cannot be chosen without evidence of synthetic vs real');
  }
  const prod = {
    functionName: text(config.functionName),
    roleArn: text(config.roleArn),
    region: text(config.region)
  };
  const test = {
    functionName: text(config.syntheticFunctionName),
    roleArn: text(config.syntheticRoleArn),
    region: text(config.syntheticRegion)
  };

  const check = (route, candidate) => {
    if (!FUNCTION_NAME.test(candidate.functionName)) {
      refuse('configuration', `${route} break-glass Lambda function is missing or malformed`);
    }
    if (!ROLE_ARN.test(candidate.roleArn)) {
      refuse('configuration', `${route} break-glass invoker role ARN is missing or malformed`);
    }
    if (!REGION.test(candidate.region)) {
      refuse('configuration', `${route} break-glass AWS region is missing or malformed`);
    }
  };

  if (!synthetic) {
    check('production', prod);
    return { route: 'production', ...prod };
  }

  if (test.functionName === '' || test.roleArn === '') {
    refuse(
      'synthetic-isolation',
      'the evidence records a SYNTHETIC fixture, but synthetic_lambda_function and synthetic_lambda_role_arn are not both set; refusing to fall back to the production broker'
    );
  }
  if (prod.functionName === '' || prod.roleArn === '') {
    refuse(
      'synthetic-isolation',
      'a synthetic request must also be given the production function and role, so isolation can be PROVEN by comparison rather than assumed'
    );
  }
  const effective = { ...test, region: test.region || prod.region };
  check('synthetic', effective);
  if (functionBaseName(effective.functionName) === functionBaseName(prod.functionName)) {
    refuse('synthetic-isolation', 'the synthetic broker function is the production function; isolation means a SEPARATE broker');
  }
  if (effective.roleArn === prod.roleArn) {
    refuse('synthetic-isolation', 'the synthetic invoker role is the production role; a fabricated finding must not be able to assume it');
  }
  return { route: 'synthetic', ...effective };
}

// ---- CLI: the preflight step of _break-glass-lambda.yml ----------------------
//
// Reads the downloaded gate, the run's own GITHUB_* identity, the expected
// digest and the broker configuration from the environment; writes the resolved
// route to $GITHUB_OUTPUT and a preflight record. Exit 1 on any refusal.

async function appendOutputs(path, values) {
  if (!path) return;
  await appendFile(path, Object.entries(values).map(([key, value]) => `${key}=${value}\n`).join(''));
}

export async function runPreflight(env = process.env, { log = console } = {}) {
  const gatePath = env.SSD_GATE_PATH;
  const recordPath = env.SSD_PREFLIGHT_PATH || 'break-glass-preflight.json';
  const record = { schemaVersion: 1, accepted: false };
  try {
    if (text(env.GATE_MODE) !== 'enforce') {
      refuse('configuration', `gate_mode is '${env.GATE_MODE ?? ''}'; break-glass only overrides an ENFORCED BLOCK`);
    }
    let gate;
    try {
      gate = JSON.parse(await readFile(gatePath, 'utf8'));
    } catch (error) {
      refuse('malformed-evidence', `the security gate evidence cannot be read or parsed (${error.message})`);
    }
    const validated = revalidateGateForBreakGlass(gate, {
      expectedDigest: text(env.EXPECTED_GATE_DIGEST),
      expectedProvenance: {
        repository: env.GITHUB_REPOSITORY,
        commitSha: env.GITHUB_SHA,
        runId: env.GITHUB_RUN_ID
      }
    });
    const route = resolveBrokerRoute({
      synthetic: validated.synthetic,
      config: {
        functionName: env.PROD_FUNCTION,
        roleArn: env.PROD_ROLE,
        region: env.PROD_REGION,
        syntheticFunctionName: env.SYNTH_FUNCTION,
        syntheticRoleArn: env.SYNTH_ROLE,
        syntheticRegion: env.SYNTH_REGION
      }
    });
    Object.assign(record, {
      accepted: true,
      gateDigest: validated.digest,
      eligibleFindings: validated.eligibleFindings.length,
      synthetic: validated.synthetic,
      fixture: validated.fixture,
      route: route.route,
      functionName: route.functionName,
      region: route.region
    });
    await appendOutputs(env.GITHUB_OUTPUT, {
      gate_digest: validated.digest,
      synthetic: String(validated.synthetic),
      route: route.route,
      function_name: route.functionName,
      role_arn: route.roleArn,
      region: route.region
    });
    if (validated.synthetic) {
      log.log?.(`::warning::SYNTHETIC break-glass request (fixture: ${validated.fixture}) — routed to the ISOLATED test broker.`);
    }
    log.log?.(
      `Break-glass preflight accepted: ${validated.eligibleFindings.length} eligible BLOCK finding(s), gate sha256 ${validated.digest}, route=${route.route}`
    );
    return record;
  } catch (error) {
    record.refusal = { code: error.code ?? 'error', reason: error.message };
    log.error?.(`BREAK-GLASS PREFLIGHT REFUSED [${record.refusal.code}]: ${error.message}`);
    throw error;
  } finally {
    await mkdir(dirname(resolve(recordPath)), { recursive: true });
    await writeFile(recordPath, `${JSON.stringify(record, null, 2)}\n`);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  try {
    await runPreflight(process.env);
  } catch {
    process.exitCode = 1;
  }
}
