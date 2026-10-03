// Presentation for `github plan` / `github apply`. Human output is built from
// output.mjs blocks only, so every GitHub- and repository-controlled string
// (ruleset names, check contexts, CODEOWNERS errors, API messages) passes the
// same terminal-control sanitization as the rest of ssd-onboard. The JSON
// document is the report object itself (plan.mjs / apply.mjs), never derived
// from this text.
import { command, dim, group, heading, result as resultLine, row, rows, section, status as statusRow, text } from '../lib/output.mjs';
import { REQUIRED_CHECK } from './protection.mjs';

const human = (outcome) => String(outcome ?? 'ERROR').replace(/_/g, ' ');
const REQUIREMENT_STATUS = { satisfied: 'PASS', missing: 'FAIL', unverified: 'NOT VERIFIED' };
const CODEOWNERS_STATUS = { complete: 'PASS', incomplete: 'FAIL', unverified: 'NOT VERIFIED' };
const PROTECTION_STATUS = { COMPLIANT: 'PASS', INCOMPLETE: 'FAIL', 'NOT VERIFIED': 'NOT VERIFIED' };

const findingRows = (findings) => rows(findings.map((f) => statusRow(f.severity, f.message)), { words: true });

function repositoryBlock(report) {
  const g = report.repository.github;
  return section(
    'Repository',
    rows([
      row('Configured', report.repository.slug, { strong: true }),
      row('Default branch', report.repository.defaultBranch),
      row('Local origin', report.repository.origin ?? '(unknown)'),
      row('GitHub', g ? `${g.fullName} (id ${g.id}${g.visibility ? `, ${g.visibility}` : ''}${g.archived ? ', ARCHIVED' : ''}), default branch ${g.defaultBranch}` : '(not read)'),
      g && row('Token', `${report.user ?? '(user not readable)'}: ${g.permissions.admin ? 'admin' : g.permissions.maintain ? 'maintain' : g.permissions.push ? 'write' : g.permissions.pull ? 'read' : 'no access reported'}`)
    ])
  );
}

function secretState(s) {
  if (!s.enabled) return 'not needed (Slack disabled)';
  if (s.state === 'absent') return 'absent';
  if (s.state === 'present') return `present — value unknowable (GitHub returns names only)${s.metadata?.updatedAt ? `; updated ${s.metadata.updatedAt}` : ''}`;
  return `NOT VERIFIED (${s.reason})`;
}

function protectionState(p) {
  const e = p.evaluation;
  return [
    rows(
      e.requirements.map((r) =>
        statusRow(REQUIREMENT_STATUS[r.state], r.label, r.state === 'satisfied' ? r.by.join(', ') : '', {
          details: [...r.untrusted.map((u) => `not counted: ${u}`), ...r.notes]
        })
      ),
      { words: true }
    ),
    e.sources.length > 0
      ? group(
          dim('Applicable rules:'),
          rows(
            e.sources.map((s) =>
              statusRow(s.trusted ? 'PASS' : s.bypass.state === 'present' ? 'FAIL' : 'NOT VERIFIED', s.label, s.trusted ? 'no bypass (proven)' : s.bypass.state === 'present' ? 'BYPASS ALLOWED' : 'bypass unknown', { details: s.reasons })
            ),
            { words: true }
          )
        )
      : group(dim('No ruleset or classic protection applies to this branch.')),
    rows(
      [
        statusRow(CODEOWNERS_STATUS[p.codeowners.state], 'CODEOWNERS', p.codeowners.path ?? 'none on GitHub', {
          details: [...p.codeowners.reasons, ...p.codeowners.errors.map((err) => `${err.path}${err.line ? `:${err.line}` : ''}: ${err.kind} ${err.message}`.trim())]
        })
      ],
      { words: true }
    )
  ];
}

function operationLines(op) {
  if (op.type === 'actions-secret-set') {
    return rows([row(op.action === 'create' ? '+ create' : '~ rotate', `Actions secret ${op.name}`, { strong: true, details: 'the value is read at apply time (hidden prompt or stdin) and sent to gh on stdin only' })]);
  }
  return [
    rows([row('+ create', `ruleset ${op.name} (${op.groups.join(', ')})`, { strong: true, details: 'a NEW ruleset; no existing ruleset or branch protection is edited' })]),
    group(text(JSON.stringify(op.body, null, 2)))
  ];
}

function warningsAndBlocks(findings) {
  const warnings = findings.filter((f) => f.severity === 'WARN' || f.severity === 'NOT VERIFIED');
  const blocking = findings.filter((f) => f.severity === 'BLOCK' || f.severity === 'FAIL');
  return [warnings.length > 0 && section('Warnings', findingRows(warnings)), blocking.length > 0 && section('Blocking problems', findingRows(blocking))];
}

const PLAN_DETAIL = {
  PLANNED: 'plan recorded; nothing on GitHub was changed',
  COMPLIANT: 'nothing to change: merge governance is proven and CODEOWNERS appears complete',
  NO_CHANGES: 'nothing to change',
  NOTHING_TO_PLAN: 'nothing to plan',
  INCOMPLETE: 'protection cannot be claimed complete; no plan was recorded',
  NOT_VERIFIED: 'GitHub did not let this token prove the state; nothing was planned',
  BLOCKED: 'no plan was recorded',
  ERROR: 'no plan was recorded'
};

function nextAction(report) {
  switch (report.outcome) {
    case 'PLANNED':
      return [text('Review the planned change above, then:'), command(`ssd-onboard github apply --plan-id ${report.plan.id} --slug ${report.repository.slug}`)];
    case 'INCOMPLETE':
      return text(report.protection?.codeowners.state === 'incomplete' ? 'Add or fix CODEOWNERS (with real owners) on the default branch through a reviewed pull request, then re-plan.' : 'Resolve the items above, then re-plan.');
    case 'NOT_VERIFIED':
      return text('Re-run with a token that has the missing permission (repository admin for protection), or verify by hand in the repository settings.');
    case 'BLOCKED':
      return text('Resolve the blocking problems, then re-plan. Nothing was contacted for a change.');
    default:
      return report.scope === 'protection' ? text(`Nothing to do. Re-run this plan after any change to rulesets or CODEOWNERS.`) : text('Nothing to do.');
  }
}

export function githubPlanBlocks(report) {
  const state = [];
  if (report.secrets) {
    state.push(rows([row('Slack secret', report.secrets.name), row('State', secretState(report.secrets))]));
  }
  if (report.protection) {
    state.push(protectionState(report.protection));
  }
  return [
    heading(`SSD GitHub plan (${report.scope})`, 'READ-ONLY: nothing on GitHub is changed; the only write is the local plan file.'),
    report.repository.github || report.repository.origin ? repositoryBlock(report) : section('Repository', rows([row('Configured', report.repository.slug, { strong: true }), row('Default branch', report.repository.defaultBranch)])),
    state.length > 0 && section('Current GitHub state', state),
    section('Planned changes', report.operations.length > 0 ? report.operations.map(operationLines) : dim('none')),
    report.protection && section('Protection status', rows([statusRow(PROTECTION_STATUS[report.protection.status], report.protection.status, `required check \`${REQUIRED_CHECK}\` from GitHub Actions, pull-request reviews incl. code owners, no bypass, CODEOWNERS`)], { words: true })),
    warningsAndBlocks(report.findings),
    section('Next action', nextAction(report)),
    section('Result', resultLine(planOutcomeWord(report.outcome), report.plan ? `${PLAN_DETAIL[report.outcome]} — ${report.plan.path}/plan.json${report.plan.recorded === 'existing' ? ' (identical plan already recorded)' : ''}` : PLAN_DETAIL[report.outcome] ?? ''))
  ];
}

const planOutcomeWord = (outcome) => human(outcome);

export function githubApplyPreflightBlocks(report) {
  return [
    heading('SSD GitHub apply', `plan ${report.planId} (${report.scope})`),
    section('Repository', rows([row('Target', report.repository.slug, { strong: true }), row('Default branch', report.repository.defaultBranch), row('Token', report.user ?? '(user not readable)')])),
    section('Change', operationLines(report.operation)),
    section('Checks', rows([statusRow('PASS', 'plan record, configuration, framework ref, repository identity and live GitHub state match the reviewed plan')], { words: true }))
  ];
}

const APPLY_DETAIL = {
  APPLIED: 'the change was made',
  REFUSED: 'nothing on GitHub was changed',
  APPLY_FAILED: 'GitHub did not accept the change',
  ERROR: 'nothing on GitHub was changed'
};

export function githubApplyBlocks(report, { preflightShown = false } = {}) {
  return [
    !preflightShown && heading('SSD GitHub apply', `plan ${report.planId}${report.scope ? ` (${report.scope})` : ''}`),
    report.verification && section('Observed', rows([statusRow(report.verification.state === 'observed' ? 'PASS' : 'WARN', report.verification.detail)], { words: true })),
    warningsAndBlocks(report.findings),
    section('Result', resultLine(human(report.outcome), APPLY_DETAIL[report.outcome] ?? ''))
  ];
}

// Run-ending errors (authentication, timeout, malformed GitHub data, …).
export function githubErrorReport(error, { command: name, scope = null, planId = null, slug = null }) {
  return {
    schemaVersion: 1,
    command: name,
    ...(scope ? { scope } : {}),
    ...(planId ? { planId } : {}),
    outcome: 'ERROR',
    repository: slug ? { slug } : null,
    error: { kind: error.kind ?? 'error', message: error.message }
  };
}

export function githubErrorBlocks(report) {
  return [heading(`SSD GitHub ${report.command.replace(/^github /, '')}`), section('Blocking problems', findingRows([{ severity: 'FAIL', message: `${report.error.kind}: ${report.error.message}` }])), section('Result', resultLine('ERROR', 'fail closed: nothing on GitHub was changed'))];
}
