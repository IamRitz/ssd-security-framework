// Presentation for `aws doctor`. Human output is built from output.mjs blocks
// only, so every AWS-controlled string (ARNs, tags, policy Sids, stack names,
// AWS error text) passes the same terminal-control sanitization as the rest of
// ssd-onboard; nothing here emits ANSI. The JSON document is the report object
// itself, never derived from human text.
import { blank, dim, group, heading, result as resultLine, row, rows, section, status as statusRow, text } from '../lib/output.mjs';
import { FAIL, NOT_VERIFIED, PASS, WARN } from './doctor.mjs';

const SECTIONS = ['Identity', 'GitHub OIDC', 'ECR', 'IAM', 'SSM', 'Ownership'];

// JSON outcome -> the human outcome word (output.mjs OUTCOME keys).
export const HUMAN_OUTCOME = Object.freeze({ READY: 'READY', READY_WITH_WARNINGS: 'READY WITH WARNINGS', NOT_VERIFIED: 'NOT VERIFIED', BLOCKED: 'BLOCKED', ERROR: 'BLOCKED' });

function detailRows(c) {
  return rows(
    [
      ['What', [...c.observed, ...c.findings.map((f) => `${f.severity}: ${f.message}`)]],
      ['Basis', [c.basis]],
      ['Expected', c.expected],
      ['How', c.remediation]
    ]
      .filter(([, items]) => items.length > 0)
      .map(([label, items]) => row(label, items.join('\n')))
  );
}

export function awsDoctorBlocks(report) {
  const t = report.target;
  const problems = report.checks.filter((c) => c.status !== PASS);
  const bySection = SECTIONS.map((name) => [name, report.checks.filter((c) => c.section === name)]).filter(([, checks]) => checks.length > 0);
  return [
    heading('SSD AWS Doctor', 'Read-only: nothing in AWS or GitHub was changed.'),
    section(
      'Target',
      rows([
        row('Repository', t.repository, { strong: true }),
        row('Account', t.account),
        row('Region', `${t.region} (${t.regionSource === 'flag' ? '--region' : 'delivery.aws.region'})`),
        row('Caller', t.caller ? t.caller.arn : '(not contacted)')
      ])
    ),
    ...bySection.map(([name, checks]) => section(name, rows(checks.map((c) => statusRow(c.status, label(c), c.ownership ? ownershipWord(c.ownership) : '')), { words: true }))),
    report.skipped && section('Skipped', rows([statusRow(NOT_VERIFIED, report.skipped)], { words: true })),
    problems.length > 0 &&
      section('Details', problems.flatMap((c, index) => [index > 0 && blank(), rows([statusRow(c.status, `${c.section}: ${label(c)}`)], { words: true }), group(detailRows(c))])),
    section(
      'Result',
      resultLine(HUMAN_OUTCOME[report.outcome], `${report.counts[FAIL]} FAIL · ${report.counts[WARN]} WARN · ${notVerifiedSummary(report)} · ${report.counts[PASS]} PASS`),
      dim('NOT VERIFIED on a required check blocks readiness (exit 1); on an (advisory) check it is a warning (exit 0).'),
      dim('Policy analysis and simulation are not runtime proof: SCPs, resource, session and VPC endpoint policies can still deny.')
    )
  ].filter(Boolean);
}

// A non-PASS advisory check says so, so its NOT VERIFIED is never read as a
// blocked prerequisite (and a required one never reads as advisory).
const label = (c) => (c.status !== PASS && c.required === false ? `${c.title} (advisory)` : c.title);

function notVerifiedSummary(report) {
  const nv = report.checks.filter((c) => c.status === NOT_VERIFIED);
  const required = nv.filter((c) => c.required !== false).length;
  return `${nv.length} NOT VERIFIED (${required} required, ${nv.length - required} advisory)`;
}

const ownershipWord = (o) => ({ managed: 'managed', 'exists-not-owned': 'exists, not owned', unverified: 'not verified' })[o] ?? o;

// A run that could not produce a report (no CLI, no credentials, bad config…).
export function awsErrorReport(error, target = null) {
  return {
    schemaVersion: 1,
    command: 'aws doctor',
    target,
    outcome: 'ERROR',
    error: { kind: error?.kind ?? 'runtime', code: error?.code ?? null, message: error?.message ?? String(error) }
  };
}

const ERROR_TITLE = {
  configuration: 'Configuration error',
  'region-missing': 'Configuration error',
  'command-unavailable': 'AWS CLI unavailable',
  authentication: 'AWS authentication failed',
  authorization: 'AWS authorization denied',
  timeout: 'AWS CLI timed out',
  'malformed-json': 'Malformed AWS output',
  malformed: 'Malformed AWS output',
  'output-too-large': 'AWS output too large',
  refused: 'Refused by the read-only allowlist'
};

export function awsErrorBlocks(errorReport) {
  const e = errorReport.error;
  return [
    heading('SSD AWS Doctor'),
    section('Result', rows([statusRow(FAIL, ERROR_TITLE[e.kind] ?? 'AWS doctor could not run', e.code ?? '')], { words: true }), group(text(e.message))),
    dim('Nothing in AWS or GitHub was changed.')
  ];
}
