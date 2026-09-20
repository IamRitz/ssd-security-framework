// The machine-readable outcome of one Lambda break-glass run.
//
// `_break-glass-lambda.yml` runs this with `if: always()` after the preflight,
// request and poll steps. It never trusts a single signal: `approved` requires
// the poll step to have succeeded AND a decision record whose requestId and
// gateDigest match the request that was delivered, which in turn must match the
// gate digest the preflight validated. Anything missing, malformed, or
// disagreeing is `error` — never approval.
//
// Output vocabulary (bounded; the caller's final gate and conformance read it):
//   decision_status   approved | denied | expired | timeout | refused | error
//                     `refused` = the preflight judged the BLOCK not overridable
//                     (PASS, integrity, hard block, mixed, ...). Nothing was sent.
//   request_delivered true | false — the broker accepted a pending request
//   gate_digest       the SHA-256 the approval is bound to ('' if none validated)
//   control_result    success (approved) | failure (everything else)
//   synthetic         true | false — from the gate evidence, not from an input
//   request_id        the broker request id, when one was delivered
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DECISION_STATUSES = ['approved', 'denied', 'expired', 'timeout', 'refused', 'error'];

// Preflight refusal codes that mean "this BLOCK is not a break-glass case",
// as opposed to configuration or evidence errors.
const NOT_OVERRIDABLE = new Set(['not-a-block', 'integrity', 'hard-block', 'ineligible', 'bootstrap']);

const HEX64 = /^[0-9a-f]{64}$/;

export function deriveBreakGlassResult({
  preflightOutcome = '',
  requestOutcome = '',
  pollOutcome = '',
  preflight = null,
  request = null,
  decision = null
} = {}) {
  const result = {
    schemaVersion: 1,
    decisionStatus: 'error',
    requestDelivered: false,
    gateDigest: '',
    synthetic: false,
    route: null,
    requestId: null,
    reason: ''
  };
  const finish = (status, reason) => {
    result.decisionStatus = status;
    result.reason = reason;
    result.controlResult = status === 'approved' ? 'success' : 'failure';
    return result;
  };

  if (preflightOutcome !== 'success' || preflight?.accepted !== true) {
    const code = preflight?.refusal?.code;
    if (NOT_OVERRIDABLE.has(code)) {
      return finish('refused', `preflight refused: ${preflight.refusal.reason}`);
    }
    return finish('error', preflight?.refusal ? `preflight failed: ${preflight.refusal.reason}` : `preflight did not complete (outcome '${preflightOutcome || 'missing'}')`);
  }
  if (!HEX64.test(preflight.gateDigest ?? '')) {
    return finish('error', 'the preflight record carries no valid gate digest');
  }
  result.gateDigest = preflight.gateDigest;
  result.synthetic = preflight.synthetic === true;
  result.route = preflight.route ?? null;

  if (requestOutcome !== 'success') {
    return finish('error', `the approval request was not delivered (request step '${requestOutcome || 'missing'}')`);
  }
  if (typeof request?.requestId !== 'string' || request.requestId === '') {
    return finish('error', 'the request step succeeded but recorded no requestId');
  }
  // Bounded, because it is echoed into $GITHUB_OUTPUT: a broker-supplied value
  // containing a newline could otherwise forge another output line.
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(request.requestId)) {
    return finish('error', 'the recorded requestId is not a bounded identifier');
  }
  if (request.gateDigest !== preflight.gateDigest) {
    return finish('error', 'the delivered request is bound to a different gate digest than the one validated');
  }
  result.requestDelivered = true;
  result.requestId = request.requestId;

  if (!decision || typeof decision !== 'object') {
    return finish('error', `no decision record was produced (poll step '${pollOutcome || 'missing'}'); the broker was unreachable or answered malformed data`);
  }
  if (decision.requestId !== request.requestId) {
    return finish('error', 'the decision record answers a different requestId');
  }
  if (decision.gateDigest !== request.gateDigest) {
    return finish('error', 'the decision record is bound to a different gate digest');
  }
  switch (decision.status) {
    case 'approved':
      if (pollOutcome !== 'success') {
        return finish('error', `the decision reads approved but the poll step reported '${pollOutcome || 'missing'}'`);
      }
      if (typeof decision.approver?.username === 'string') {
        result.approver = decision.approver.username;
      }
      return finish('approved', 'a verified approver approved this exact gate');
    case 'denied':
    case 'expired':
    case 'timeout':
      return finish(decision.status, `break-glass review ended as ${decision.status}; the BLOCK stands`);
    default:
      return finish('error', `unrecognized decision status '${decision.status}'`);
  }
}

// ---- human-readable job summary ------------------------------------------------
//
// The break-glass job's summary headlines the break-glass REVIEW, not the source
// gate: the source policy verdict, the break-glass decision, and the effective
// disposition are three different facts, shown side by side and never merged.
//   - the source verdict is read from the gate evidence and shown as-is (an
//     approved BLOCK is still "BLOCK");
//   - the decision and delivery come from the SAME result record this step
//     emits as outputs, so the summary cannot disagree with enforcement;
//   - only `approved` is shown as an OVERRIDDEN BLOCK; everything else says no
//     verified approval exists.
// Presentation only: nothing here feeds an output, the exit code, or the final gate.

const DECISION_LABELS = {
  approved: 'APPROVED',
  denied: 'DENIED',
  expired: 'EXPIRED',
  timeout: 'TIMEOUT',
  refused: 'REFUSED',
  error: 'ERROR'
};

// One line of plain text, safe inside a Markdown table cell.
const cell = (value, max = 300) => {
  const flat = String(value ?? '').replace(/[\r\n]+/g, ' ').replace(/[|`<>]/g, ' ').replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
};

export function renderBreakGlassSummary(result, { verdict = null } = {}) {
  const status = DECISION_STATUSES.includes(result?.decisionStatus) ? result.decisionStatus : 'error';
  const approved = status === 'approved';
  const sourceVerdict = typeof verdict === 'string' && /^[A-Z][A-Z_-]{0,39}$/.test(verdict) ? verdict : null;

  let decision = DECISION_LABELS[status];
  if (approved && result.approver) decision += ` by \`${cell(result.approver, 64)}\``;
  if (status === 'refused') decision += ' — this BLOCK is not eligible for break-glass';
  if (status === 'error') decision += ' — no verified decision was obtained';

  let disposition;
  if (approved) {
    disposition = '**OVERRIDDEN BLOCK** for this run only';
  } else if (sourceVerdict === 'BLOCK' || sourceVerdict === null) {
    disposition = `**BLOCK STANDS** — ${status === 'error' || status === 'refused' ? 'no verified approval exists' : 'no approval was given'}`;
  } else {
    disposition = `**NO OVERRIDE** — no verified approval exists; the source verdict ${sourceVerdict} is unchanged`;
  }

  const delivered = result?.requestDelivered === true
    ? `yes${result.requestId ? ` (request \`${cell(result.requestId, 128)}\`)` : ''}`
    : 'no — no approval request reached the broker';

  const lines = [
    `## ${approved ? '🔓' : '⛔'} Break-glass review: ${DECISION_LABELS[status]}`,
    '',
    '| | |',
    '|---|---|',
    `| Source policy verdict | ${sourceVerdict ? `**${sourceVerdict}**` : 'unavailable — the gate evidence could not be read'} |`,
    `| Request delivered | ${delivered} |`,
    `| Decision | ${decision} |`,
    `| Effective disposition | ${disposition} |`,
    `| Gate digest | ${HEX64.test(result?.gateDigest ?? '') ? `\`sha256:${result.gateDigest}\`` : 'none validated'} |`
  ];
  if (result?.synthetic === true) {
    lines.push('| Route | synthetic fixture — isolated test broker |');
  }
  lines.push('');
  // The reason is diagnostic: shown only where the table alone cannot say why.
  if ((status === 'refused' || status === 'error') && result?.reason) lines.push(`_${cell(result.reason, 500)}_`, '');
  lines.push(
    approved
      ? '> The source policy verdict remains **BLOCK**. This approval applies only to this exact gate and run.'
      : '> No override is active; the aggregate `security-gate` check stays red.'
  );
  return `${lines.join('\n')}\n\n`;
}

async function readOptionalJson(path) {
  if (!path) return null;
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

async function main() {
  const env = process.env;
  const result = deriveBreakGlassResult({
    preflightOutcome: env.PREFLIGHT_OUTCOME,
    requestOutcome: env.REQUEST_OUTCOME,
    pollOutcome: env.POLL_OUTCOME,
    preflight: await readOptionalJson(env.SSD_PREFLIGHT_PATH),
    request: await readOptionalJson(env.SSD_REQUEST_PATH),
    decision: await readOptionalJson(env.SSD_DECISION_PATH)
  });
  const output = env.SSD_RESULT_PATH || 'break-glass-result.json';
  await mkdir(dirname(resolve(output)), { recursive: true });
  await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
  if (env.GITHUB_OUTPUT) {
    await appendFile(
      env.GITHUB_OUTPUT,
      [
        `decision_status=${result.decisionStatus}`,
        `request_delivered=${result.requestDelivered}`,
        `gate_digest=${result.gateDigest}`,
        `control_result=${result.controlResult}`,
        `synthetic=${result.synthetic}`,
        `request_id=${result.requestId ?? ''}`
      ].join('\n') + '\n'
    );
  }
  console.log(`BREAK-GLASS RESULT: ${result.decisionStatus} (delivered=${result.requestDelivered}) — ${result.reason}`);
  // After the outputs, and best effort: a summary failure never changes them.
  if (env.GITHUB_STEP_SUMMARY) {
    try {
      const gate = await readOptionalJson(env.SSD_GATE_PATH);
      await appendFile(env.GITHUB_STEP_SUMMARY, renderBreakGlassSummary(result, { verdict: gate?.verdict }));
    } catch (error) {
      console.error(`BREAK-GLASS RESULT: job summary not written (${error.message})`);
    }
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) await main();
