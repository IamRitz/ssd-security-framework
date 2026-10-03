// Presentation for `aws verify`. As for doctor (report.mjs): human output is
// built from output.mjs blocks only, so every AWS-controlled string is
// sanitized by the one formatter; the JSON document is the report object
// itself, never derived from human text.
import { blank, dim, group, heading, result as resultLine, row, rows, section, status as statusRow, text } from '../lib/output.mjs';
import { FAIL, NOT_VERIFIED, PASS, SECTIONS, WARN } from './verify.mjs';

export const HUMAN_OUTCOME = Object.freeze({ VERIFIED: 'VERIFIED', VERIFIED_WITH_WARNINGS: 'VERIFIED WITH WARNINGS', NOT_VERIFIED: 'NOT VERIFIED', FAILED: 'FAILED', ERROR: 'FAILED' });

const label = (c) => (c.status !== PASS && c.required === false ? `${c.title} (advisory)` : c.title);
const ownershipWord = (o) => ({ managed: 'managed', 'exists-not-owned': 'exists, not owned', unverified: 'not verified' })[o] ?? o;

// Long evidence lists (a simulation probes ~20 pairs) are cut in human output so
// the problem stays visible; --json always carries all of them.
const MAX_LINES = 6;
const capped = (items) => (items.length > MAX_LINES ? [...items.slice(0, MAX_LINES), `… ${items.length - MAX_LINES} more (aws verify --json lists all)`] : items);

function detailRows(c) {
  return rows(
    [
      ['Problem', c.findings.map((f) => `${f.severity}: ${f.message}`)],
      ['Observed', capped(c.observed)],
      ['Expected', capped(c.expected)],
      ['Why', c.why ? [c.why] : []],
      ['Basis', [c.basis]],
      ['Remediate', c.remediation]
    ]
      .filter(([, items]) => items.length > 0)
      .map(([name, items]) => row(name, items.join('\n')))
  );
}

export function awsVerifyBlocks(report) {
  const t = report.target;
  const problems = report.checks.filter((c) => c.status !== PASS);
  const bySection = SECTIONS.map((name) => [name, report.checks.filter((c) => c.section === name)]).filter(([, checks]) => checks.length > 0);
  const nv = report.checks.filter((c) => c.status === NOT_VERIFIED);
  const requiredNv = nv.filter((c) => c.required !== false).length;
  return [
    heading('SSD AWS Verify', 'Read-only: live AWS state re-read and simulated; nothing in AWS or GitHub was changed.'),
    section(
      'Target',
      rows([
        row('Repository', t.repository, { strong: true }),
        row('Account', t.account),
        row('Region', `${t.region} (${t.regionSource === 'flag' ? '--region' : 'delivery.aws.region'})`),
        row('Caller', t.caller ? t.caller.arn : '(not contacted)'),
        row('AWS profile', t.awsProfile ?? '(default credential chain)')
      ])
    ),
    ...bySection.map(([name, checks]) => section(name, rows(checks.map((c) => statusRow(c.status, label(c), c.ownership ? ownershipWord(c.ownership) : '')), { words: true }))),
    report.skipped && section('Skipped', rows([statusRow(NOT_VERIFIED, report.skipped)], { words: true })),
    problems.length > 0 &&
      section('Details', problems.flatMap((c, index) => [index > 0 && blank(), rows([statusRow(c.status, `${c.section}: ${label(c)}`)], { words: true }), group(detailRows(c))])),
    section(
      'Result',
      resultLine(
        HUMAN_OUTCOME[report.outcome] ?? 'FAILED',
        `${report.counts[FAIL]} FAIL · ${report.counts[WARN]} WARN · ${nv.length} NOT VERIFIED (${requiredNv} required, ${nv.length - requiredNv} advisory) · ${report.counts[PASS]} PASS`
      ),
      dim('Any FAIL, or NOT VERIFIED on a required check, fails verification (exit 1).'),
      dim('Effective access is IAM simulation (identity policies, permissions boundaries, SCPs); it does not evaluate resource, session or VPC endpoint policies.')
    )
  ].filter(Boolean);
}

// A run that could not produce a report (no CLI, no credentials, bad config…).
export function awsVerifyErrorReport(error, target = null) {
  return {
    schemaVersion: 1,
    command: 'aws verify',
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
  deadline: 'AWS verify ran out of time',
  'malformed-json': 'Malformed AWS output',
  malformed: 'Malformed AWS output',
  'output-too-large': 'AWS output too large',
  refused: 'Refused by the read-only allowlist'
};

export function awsVerifyErrorBlocks(errorReport) {
  const e = errorReport.error;
  return [
    heading('SSD AWS Verify'),
    section('Result', rows([statusRow(FAIL, ERROR_TITLE[e.kind] ?? 'AWS verify could not run', e.code ?? '')], { words: true }), group(text(e.message))),
    dim('Verification did not complete: nothing is verified. Nothing in AWS or GitHub was changed.')
  ];
}
