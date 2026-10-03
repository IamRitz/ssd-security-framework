// Presentation for `aws plan`. Human output is built from output.mjs blocks
// only, so every AWS-controlled string passes the same terminal-control
// sanitization as the rest of ssd-onboard; nothing here emits ANSI, and every
// status carries its word, never color alone. The JSON document is the report
// object itself (plan.mjs), never derived from this text.
import { blank, dim, group, heading, result as resultLine, row, rows, section, status as statusRow, text } from '../lib/output.mjs';

const SYMBOL = { CREATE: '+', UPDATE: '~', DELETE: '-', REPLACE: '!' };
const HUMAN_OUTCOME = { PLANNED: 'READY', NO_CHANGES: 'READY', NOTHING_TO_PLAN: 'READY', BLOCKED: 'BLOCKED', ERROR: 'BLOCKED' };
const OUTCOME_DETAIL = {
  PLANNED: 'plan recorded; nothing in AWS was changed (the change set is NOT executed)',
  NO_CHANGES: 'no changes: the live stack already matches; nothing to apply',
  NOTHING_TO_PLAN: 'nothing in this scope is managed by ssd-onboard; no change set was created',
  BLOCKED: 'no change set was created',
  ERROR: 'no plan was recorded'
};

const findingRows = (findings) => rows(findings.map((f) => statusRow(f.severity, f.message)), { words: true });

function changeLines(unit) {
  return unit.changes.map((c) => {
    const tail = [c.physicalId ? `(${c.physicalId})` : '', c.conditional ? 'replacement is CONDITIONAL — counted as REPLACE' : '', c.action === 'DELETE' ? 'removed from the stack; the resource is RETAINED' : '', c.action === 'REPLACE' ? 'a NEW resource replaces it; the old one is RETAINED' : '']
      .filter(Boolean)
      .join('  ');
    return `${SYMBOL[c.action]} ${c.action.padEnd(7)} ${c.type.padEnd(22)} ${c.logicalId}${tail ? `  ${tail}` : ''}`;
  });
}

function destructiveBlock(unit) {
  if (unit.destructive === 0) {
    return rows([statusRow('PASS', 'none')], { words: true });
  }
  const c = unit.counts;
  return [
    rows([statusRow('FAIL', `DESTRUCTIVE: ${unit.destructive} (${c.DELETE} DELETE, ${c.REPLACE} REPLACE)`, 'review every line below')], { words: true }),
    group(
      text(unit.changes.filter((ch) => ch.action === 'DELETE' || ch.action === 'REPLACE').map((ch) => `${SYMBOL[ch.action]} ${ch.action} ${ch.type} ${ch.logicalId}${ch.conditional ? ' (conditional)' : ''}`)),
      dim(`aws apply requires this exact count to be confirmed: --allow-destructive ${unit.destructive}.`)
    )
  ];
}

function iamBlock(unit) {
  if (unit.iam.length === 0) {
    return null;
  }
  return section(
    'IAM (semantic diff)',
    unit.iam.flatMap((i, index) => [
      index > 0 && blank(),
      rows([row(i.logicalId, `${i.arn}${i.created ? ' (new role)' : ''}`, { strong: true })]),
      group(
        rows([
          row('Trust', i.trustChanged ? i.trust.join('\n') : 'no semantic change'),
          row('Permissions', i.permissionsChanged ? i.permissions.join('\n') : 'no semantic change'),
          i.unmanaged.length > 0 && row('Not managed', i.unmanaged.join(', '))
        ])
      )
    ])
  );
}

function baseWord(base) {
  if (!base) return '(not determined)';
  return base.state === 'absent' ? 'absent (CREATE)' : `${base.stackStatus}${base.lastUpdatedTime ? `, last updated ${base.lastUpdatedTime}` : ''}`;
}

function unitBlocks(unit) {
  const title = `${unit.label}: ${unit.stackName}`;
  if (unit.mode === 'report-only' || unit.mode === 'nothing') {
    return [
      section(
        title,
        rows([row('Planned', unit.mode === 'nothing' ? 'no (every resource is existing)' : 'no (existing: discovered, validated, reported)')]),
        unit.checks.length > 0 && rows(unit.checks.map((c) => statusRow(c.status, c.title, [...c.observed, ...c.findings.map((f) => `${f.severity}: ${f.message}`)].join('\n'))), { words: true }),
        unit.findings.length > 0 && findingRows(unit.findings),
        unit.proposal?.changed && group(text('Proposed registry scanning (current rules + this repository; NOT planned or applied):'), text(JSON.stringify(unit.proposal.proposed, null, 2))),
        unit.proposal?.impossible && group(text(`No safe proposal: ${unit.proposal.impossible}`)),
        unit.residual.length > 0 && group(dim(unit.residual))
      )
    ];
  }
  const blocks = [
    section(
      title,
      rows([
        row('Stack', unit.stackName, { strong: true }),
        row('Change set', unit.changeSetType ?? '(not created)'),
        row('Base stack', baseWord(unit.baseStack))
      ]),
      unit.findings.length > 0 && findingRows(unit.findings)
    )
  ];
  if (unit.status === 'changes' || unit.status === 'no-changes') {
    blocks.push(
      section('Changes', unit.status === 'no-changes' ? text('no changes (CloudFormation reported nothing to do)') : text(changeLines(unit))),
      section('Destructive', destructiveBlock(unit)),
      iamBlock(unit),
      section(
        'Plan',
        rows([row('ID', unit.planId), row('Change set', unit.changeSetArn), row('Directory', unit.directory), row('Outcome', unit.status === 'no-changes' ? 'no-changes (recorded, never applicable)' : 'changes')]),
        unit.changeSetType === 'CREATE' && dim('A CREATE change set leaves a REVIEW_IN_PROGRESS placeholder stack (no resources) until it is executed or deleted.')
      )
    );
  }
  return blocks;
}

export function awsPlanBlocks(report) {
  const t = report.target;
  return [
    heading('SSD AWS Plan', 'Creates an UNEXECUTED CloudFormation change set; nothing in AWS is changed until aws apply executes it.'),
    section(
      'Target',
      rows([
        row('Repository', t.repository, { strong: true }),
        row('Account', t.account),
        row('Region', `${t.region} (${t.regionSource === 'flag' ? '--region' : 'delivery.aws.region'})`),
        row('Scope', report.scope),
        row('Caller', t.caller ? t.caller.arn : '(not contacted)'),
        row('Framework', `${report.framework.repository}@${report.framework.ref}`)
      ])
    ),
    report.findings.length > 0 && section('Preconditions', findingRows(report.findings)),
    ...report.units.flatMap(unitBlocks),
    report.skipped && section('Skipped', rows([statusRow('NOT VERIFIED', report.skipped)], { words: true })),
    section(
      'Result',
      resultLine(HUMAN_OUTCOME[report.outcome] ?? 'BLOCKED', `${report.outcome.replace(/_/g, ' ')}: ${OUTCOME_DETAIL[report.outcome] ?? ''}`),
      report.outcome === 'PLANNED' && dim('Next: review this plan, then apply it with aws apply --plan-id <id> --account <account> --region <region>.')
    )
  ].filter(Boolean);
}

// A run that could not produce a report.
export function awsPlanErrorReport(error, target = null) {
  return { schemaVersion: 1, command: 'aws plan', target, outcome: 'ERROR', error: { kind: error?.kind ?? 'runtime', code: error?.code ?? null, message: error?.message ?? String(error) } };
}

const ERROR_TITLE = {
  configuration: 'Configuration error',
  'region-missing': 'Configuration error',
  'command-unavailable': 'AWS CLI unavailable',
  authentication: 'AWS authentication failed',
  authorization: 'AWS authorization denied',
  timeout: 'AWS CLI timed out',
  deadline: 'AWS plan ran out of time',
  'malformed-json': 'Malformed AWS output',
  malformed: 'Malformed AWS output',
  'malformed-response': 'Malformed AWS output',
  'output-too-large': 'AWS output too large',
  refused: 'Refused by the planning allowlist',
  'scope-violation': 'Scope boundary violated',
  'unexpected-state': 'Unexpected change-set state',
  'unexpected-action': 'Unexpected change-set action',
  'change-set-failed': 'Change set failed',
  'change-set-exists': 'Change set already exists',
  'template-invalid': 'Template rejected',
  'secret-in-plan': 'Credential-like value in plan data',
  'plan-exists': 'Plan already exists',
  ERR_PATH_NOT_CONFINED: 'Unsafe plan path',
  'unsupported-scope': 'Unsupported scope'
};

export function awsPlanErrorBlocks(errorReport) {
  const e = errorReport.error;
  return [
    heading('SSD AWS Plan'),
    section('Result', rows([statusRow('FAIL', ERROR_TITLE[e.kind] ?? 'AWS plan could not run', e.code ?? '')], { words: true }), group(text(e.message))),
    dim('No change set was executed; no plan was recorded for the failing step.')
  ];
}
