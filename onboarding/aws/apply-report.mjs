// Presentation for `aws apply`. Human output is built from output.mjs blocks
// only (every AWS-controlled string is sanitized there; nothing here emits
// ANSI), and every status carries its word, never color alone. The JSON
// document is the report object itself (apply.mjs), never derived from this
// text.
import { dim, group, heading, result as resultLine, row, rows, section, status as statusRow, text } from '../lib/output.mjs';

const SYMBOL = { CREATE: '+', UPDATE: '~', DELETE: '-', REPLACE: '!' };
const OUTCOME_DETAIL = {
  APPLIED: 'the reviewed change set was executed and the stack reached its successful state',
  REFUSED: 'nothing was executed',
  ERROR: 'nothing was executed',
  APPLY_FAILED: 'the change set was executed (or its execution was requested) and success was NOT observed'
};

export function applyHeading() {
  return heading('SSD AWS Apply', 'Executes exactly the reviewed CloudFormation change set recorded by aws plan, after re-verifying it.');
}

export function targetBlock(report) {
  const t = report.target;
  return section(
    'Target',
    rows([
      row('Plan', report.planId, { strong: true }),
      row('Account', t.account),
      row('Region', t.region),
      t.stackName && row('Stack', `${t.stackName}${t.operation ? ` (${t.operation})` : ''}`),
      t.caller && row('Caller', t.caller.arn),
      t.plannedBy && row('Planned by', t.plannedBy)
    ])
  );
}

export function verificationBlock(report) {
  return section(
    'Verification',
    rows(report.verification.map((v) => statusRow(v.status, v.title)), { words: true }),
    report.findings.length > 0 && rows(report.findings.map((f) => statusRow('FAIL', f.message)), { words: true })
  );
}

export function changesBlocks(report) {
  if (!report.changes) {
    return [];
  }
  const c = report.changes.counts;
  const destructive = report.changes.destructive;
  return [
    section(
      'Changes',
      rows([row('ADD', String(c.CREATE)), row('UPDATE', String(c.UPDATE)), row('REPLACE', String(c.REPLACE)), row('DELETE', String(c.DELETE))]),
      group(text(report.changes.items.map((ch) => `${SYMBOL[ch.action]} ${ch.action.padEnd(7)} ${ch.type.padEnd(22)} ${ch.logicalId}${ch.conditional ? '  (conditional replacement)' : ''}`)))
    ),
    section(
      'Destructive changes',
      destructive === 0
        ? rows([statusRow('PASS', 'none')], { words: true })
        : rows([statusRow('WARN', `${destructive} destructive (${c.DELETE} DELETE, ${c.REPLACE} REPLACE)`, 'confirmed by --allow-destructive with this exact count')], { words: true })
    )
  ];
}

// Shown once the read-only pre-flight passed, before confirmation.
export function awsApplyPreflightBlocks(report) {
  return [applyHeading(), targetBlock(report), verificationBlock(report), ...changesBlocks(report)];
}

export function executingBlocks() {
  return [section('Applying', text(['Executing the reviewed change set…', 'Waiting for the stack…']))];
}

// The final result. `preflightShown`: the target/verification blocks were
// already printed (the run reached the pre-flight).
export function awsApplyBlocks(report, { preflightShown = false } = {}) {
  const e = report.execution;
  return [
    !preflightShown && applyHeading(),
    !preflightShown && targetBlock(report),
    (!preflightShown || report.outcome === 'REFUSED') && verificationBlock(report),
    !preflightShown && changesBlocks(report),
    e &&
      section(
        'Execution',
        rows([
          row('Final status', e.finalStackStatus ?? '(not observed)'),
          e.statusReason && row('Reason', e.statusReason),
          row('Observed', e.observed ? 'yes' : 'no — success was NOT confirmed'),
          e.resources && row('Resources', e.resources.map((r) => `${r.logicalId} ${r.physicalId ?? ''}`.trim()).join('\n')),
          row('Record', report.record.result ?? `NOT written${report.record.error ? ` (${report.record.error.message})` : ''}`)
        ])
      ),
    section(
      'Result',
      resultLine(report.outcome === 'APPLY_FAILED' ? 'APPLY FAILED' : report.outcome, e?.reason ?? OUTCOME_DETAIL[report.outcome] ?? ''),
      dim(OUTCOME_DETAIL[report.outcome] ?? '')
    ),
    report.nextSteps.length > 0 && section('Next steps', text(report.nextSteps.map((s) => `- ${s}`)))
  ].filter(Boolean);
}

// A run that could not produce a report (nothing was executed).
export function awsApplyErrorReport(error, target = null) {
  return { schemaVersion: 1, command: 'aws apply', target, outcome: 'ERROR', error: { kind: error?.kind ?? 'runtime', code: error?.code ?? null, message: error?.message ?? String(error) } };
}

const ERROR_TITLE = {
  configuration: 'Configuration error',
  'command-unavailable': 'AWS CLI unavailable',
  authentication: 'AWS authentication failed',
  authorization: 'AWS authorization denied',
  timeout: 'AWS CLI timed out',
  deadline: 'AWS apply ran out of time',
  'malformed-json': 'Malformed AWS output',
  malformed: 'Malformed AWS output',
  'output-too-large': 'AWS output too large',
  refused: 'Refused by the apply allowlist',
  'stack-unverified': 'Stack could not be described',
  'secret-in-plan': 'Credential-like value in apply record',
  'apply-record-exists': 'Apply record already exists',
  ERR_PATH_NOT_CONFINED: 'Unsafe plan path'
};

export function awsApplyErrorBlocks(errorReport) {
  const e = errorReport.error;
  return [
    applyHeading(),
    section('Result', rows([statusRow('FAIL', ERROR_TITLE[e.kind] ?? 'AWS apply could not run', e.code ?? '')], { words: true }), group(text(e.message))),
    dim('ERROR: nothing was executed.')
  ];
}
