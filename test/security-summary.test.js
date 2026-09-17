// The developer-facing summary is a bounded TRIAGE surface over the one
// normalized issue model; security-gate.json stays the complete evidence.
//
//   gate status -> scan health -> counts -> compact table -> conflict callouts
//   -> integrity failures -> collapsible evidence for BLOCK / EXCEPTION / REVIEW
//
// Disposition (BLOCK / EXCEPTION / REVIEW / INFO) is presentation only and must
// never change a verdict, a count, or anything written to security-gate.json.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import {
  buildReport,
  presentationDisposition,
  renderEvidenceMarkdown,
  renderMarkdown,
  renderSlack,
  route,
  SUMMARY_LIMITS
} from '../security/scripts/format-findings.mjs';
import { dispatch } from '../security/scripts/notify.mjs';
import { acquisitionRecord, completeExecution } from '../security/scripts/scanner-execution.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const POLICY = resolve('security/policy.yaml');
const MISSING_SEMGREP = join(tmpdir(), 'ssd-security-summary-test-never-created', 'semgrep.json');

async function withTempDir(work) {
  const directory = await mkdtemp(join(tmpdir(), 'security-summary-'));
  try {
    return await work(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

// The real gate over a temporary consumer checkout; also returns the JSON it wrote.
async function gate({ requirements = null, pipAudit = null, osv = join(CLEAN, 'osv-scanner.json'), semgrep = join(CLEAN, 'semgrep.json'), record = null } = {}) {
  return withTempDir(async (directory) => {
    const repoDir = join(directory, 'repo');
    await mkdir(repoDir);
    if (requirements !== null) await writeFile(join(repoDir, 'requirements.txt'), requirements);
    let semgrepExecution = join(directory, 'no-record.json');
    if (record) {
      semgrepExecution = join(directory, 'scanner-execution-semgrep.json');
      await writeFile(semgrepExecution, JSON.stringify(record));
    }
    const output = join(directory, 'security-gate.json');
    const result = await runSecurityGate({
      policy: POLICY,
      repoDir,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      npmAudit: join(directory, 'absent-npm-audit.json'),
      pipAudit: pipAudit ?? join(directory, 'absent-pip-audit.json'),
      osv,
      semgrep,
      semgrepExecution,
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      output,
      exceptions: join(directory, 'gate-exceptions.json')
    });
    return { result, written: await readFile(output, 'utf8') };
  });
}

const LIVE_PASS = join(FIXTURES, 'live-requests-2-33-0');
const LIVE_BLOCK = join(FIXTURES, 'live-python-source-only');
const livePass = () =>
  gate({ requirements: 'requests==2.33.0\n', pipAudit: join(LIVE_PASS, 'pip-audit.json'), osv: join(LIVE_PASS, 'osv-scanner.json') });
const liveBlock = () =>
  gate({ requirements: 'requests==2.32.5\n', pipAudit: join(LIVE_BLOCK, 'pip-audit.json'), osv: join(LIVE_BLOCK, 'osv-scanner.json') });

const tableRows = (markdown) => markdown.split('\n').filter((line) => /^\| (⛔ BLOCK|⚠️ EXCEPTION|⚖️ REVIEW|ℹ️ INFO) \|/.test(line));
const rowCells = (row) => row.split(/(?<!\\)\|/).slice(1, -1).map((cell) => cell.trim());

// Minimal synthetic findings.
const trivy = (i, action, severity, extra = {}) => ({
  source: 'trivy',
  id: `CVE-2099-${String(i).padStart(5, '0')}`,
  package: `pkg-${i}`,
  installedVersion: '1.0.0',
  severity,
  fixAvailable: action !== 'EXCEPTION',
  ...(action === 'EXCEPTION' ? {} : { fixedVersion: '1.0.1' }),
  action,
  policyRule: `image.${severity}`,
  reason: 'synthetic',
  ...extra
});
const conflictedOsv = (pkg, index = 0) => ({
  source: 'osv-scanner',
  id: `PYSEC-2099-${index}`,
  package: pkg,
  ecosystem: 'PyPI',
  installedVersion: '1.0.0',
  severity: 'medium',
  severitySource: 'cvss',
  cvssScore: 5,
  fixAvailable: true,
  fixVersions: ['1.5'],
  aliases: [`CVE-2099-9${index}`],
  policyRule: 'dependencies.medium',
  action: 'LOG',
  reason: 'synthetic'
});
const conflictEvidence = (packages) => ({
  schemaVersion: 1,
  manifests: [],
  observations: packages.flatMap((pkg, index) => [
    { scanner: 'pip-audit', ecosystem: 'PyPI', package: pkg, version: '2.0.0', provenance: 'scanner-resolved', source: 'requirements.txt', advisoryIds: [] },
    { scanner: 'osv-scanner', ecosystem: 'PyPI', package: pkg, version: '1.0.0', provenance: 'scanner-inferred', source: 'requirements.txt', advisoryIds: [`PYSEC-2099-${index}`, `CVE-2099-9${index}`] }
  ])
});

describe('regression: live requests==2.33.0 (PASS with a version conflict)', () => {
  it('policy is unchanged: PASS, 2 raw LOG, 1 correlated issue, relationship unknown, resolution conflicting', async () => {
    const { result } = await livePass();
    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(result.summary, { block: 0, exception: 0, log: 2 });
    assert.equal(result.findings.every((finding) => finding.action === 'LOG'), true);
    assert.equal(result.correlation.summary.issues, 1);
    const [issue] = result.correlation.issues;
    assert.equal(issue.evidence.relationship.value, 'unknown');
    assert.equal(issue.evidence.resolution.status, 'conflicting');
  });

  it('renders the target shape: PASS, controls, counts, one REVIEW row, a conflict callout, full evidence pointer', async () => {
    const { result } = await livePass();
    const report = buildReport({ gate: result, context: { evidenceMarkdownFile: 'security-gate-evidence.md' } });
    const markdown = renderMarkdown(report);
    assert.match(markdown, /^## ✅ Security gate: PASS$/m);
    assert.match(markdown, /✅ \*\*3\/3\*\* scan controls completed/);
    assert.match(markdown, /\*\*0\*\* blocking · \*\*0\*\* exception · \*\*1\*\* logged \(\*\*1\*\* review · \*\*0\*\* info\) — \*\*1\*\* unique issue from \*\*2\*\* scanner findings/);
    const rows = tableRows(markdown);
    assert.equal(rows.length, 1, 'one row per unique issue, not per raw record');
    assert.deepEqual(rowCells(rows[0]), ['⚖️ REVIEW', 'Medium', '`idna`', '`CVE-2026-45409`', 'unknown', 'conflict: 3.19 / 3.9.0', 'disputed — 3.15 reported']);
    assert.match(markdown, /\*\*Evidence conflicts \(1\)\*\*/);
    assert.match(markdown, /pip-audit: 3\.19 · OSV-Scanner: 3\.9\.0\. The scanners disagree on the effective version\. Do not remediate until the version actually resolved is established\./);
    assert.match(markdown, /Full evidence: `security-gate\.json` and every issue's full explanation in `security-gate-evidence\.md`/);
    // The global correlation note appears once, not inside the card.
    assert.equal(markdown.split('correlated for display').length - 1, 1);
    assert.doesNotMatch(markdown, /scanner records describe the same vulnerability/);
  });

  it('no direct pin command, and 3.9.0 is never presented as the version in use', async () => {
    const { result } = await livePass();
    const report = buildReport({ gate: result });
    const all = `${renderMarkdown(report)}\n${renderEvidenceMarkdown(report)}\n${JSON.stringify(renderSlack(report))}`;
    assert.doesNotMatch(all, /pip install/);
    assert.doesNotMatch(all, /Upgrade `idna`/);
    // "fixed in 3.15" only as a scanner-attributed record line, never as the fix status.
    for (const line of all.split('\n').filter((text) => /fixed in 3\.15/.test(text))) {
      assert.match(line, /^\s+- OSV-Scanner \/ `/, `unattributed fix claim: ${line}`);
    }
    for (const line of all.split('\n').filter((text) => /3\.9\.0/.test(text))) {
      assert.match(line, /conflict: |disputed|OSV-Scanner|reported at/, `unattributed 3.9.0: ${line}`);
    }
  });
});

describe('regression: live requests==2.32.5 stays BLOCK', () => {
  it('BLOCK verdict, a policy BLOCK (not a scan problem), requests row first and its evidence open', async () => {
    const { result } = await liveBlock();
    assert.equal(result.verdict, 'BLOCK');
    const report = buildReport({ gate: result });
    assert.equal(report.gateStatus.kind, 'policy');
    const markdown = renderMarkdown(report);
    assert.match(markdown, /^## ⛔ Security gate: BLOCK$/m);
    assert.doesNotMatch(markdown, /not a vulnerability-policy BLOCK|scan unavailable|Security state: UNKNOWN/);
    const rows = tableRows(markdown).map(rowCells);
    assert.deepEqual(rows[0].slice(0, 7), ['⛔ BLOCK', 'High', '`requests`', '`CVE-2026-25645`', 'direct', '2.32.5', 'fixed in 2.33.0']);
    assert.equal(rows[1][0], '⚖️ REVIEW');
    assert.match(markdown, /<details open><summary>⛔ BLOCK · High · requests — CVE-2026-25645<\/summary>/);
  });
});

describe('dispositions', () => {
  it('a single BLOCK issue', () => {
    const report = buildReport({ gate: { verdict: 'BLOCK', findings: [trivy(1, 'BLOCK', 'critical')] } });
    const markdown = renderMarkdown(report);
    assert.deepEqual(report.dispositionCounts, { block: 1, exception: 0, review: 0, info: 0 });
    assert.equal(tableRows(markdown).length, 1);
    assert.match(markdown, /### ⛔ Blocking findings \(1\)/);
    assert.match(markdown, /<details open><summary>⛔ BLOCK · Critical · pkg-1/);
    assert.doesNotMatch(markdown, /Scan health/, 'no scan health for a gate that carries no per-control evidence');
  });

  it('PASS with INFO findings: rows only, no per-issue remediation paragraphs', () => {
    const findings = [trivy(1, 'LOG', 'medium'), trivy(2, 'LOG', 'low')];
    const report = buildReport({ gate: { verdict: 'PASS', findings } });
    const markdown = renderMarkdown(report);
    assert.match(markdown, /Security gate: PASS/);
    assert.deepEqual(tableRows(markdown).map((row) => rowCells(row)[0]), ['ℹ️ INFO', 'ℹ️ INFO']);
    assert.doesNotMatch(markdown, /<details|🔧|Trivy reports a fix/);
    assert.match(renderEvidenceMarkdown(report), /Trivy reports a fix in 1\.0\.1/, 'the full card is still available');
  });

  it('BLOCK, EXCEPTION, REVIEW and INFO sort by priority, then severity, then first appearance', () => {
    const findings = [
      trivy(1, 'LOG', 'critical'),
      conflictedOsv('aaa', 0),
      trivy(2, 'EXCEPTION', 'high'),
      trivy(3, 'BLOCK', 'high'),
      trivy(4, 'LOG', 'low'),
      trivy(5, 'BLOCK', 'critical'),
      trivy(6, 'EXCEPTION', 'critical'),
      trivy(7, 'BLOCK', 'high')
    ];
    const report = buildReport({ gate: { verdict: 'BLOCK', findings, dependencyEvidence: conflictEvidence(['aaa']) } });
    const order = tableRows(renderMarkdown(report)).map((row) => `${rowCells(row)[0].split(' ')[1]}:${rowCells(row)[2]}`);
    assert.deepEqual(order, [
      'BLOCK:`pkg-5`',
      'BLOCK:`pkg-3`',
      'BLOCK:`pkg-7`',
      'EXCEPTION:`pkg-6`',
      'EXCEPTION:`pkg-2`',
      'REVIEW:`aaa`',
      'INFO:`pkg-1`',
      'INFO:`pkg-4`'
    ]);
  });

  it('REVIEW never changes policy: verdict, counts, routing, and the gate JSON are untouched', async () => {
    const { result, written } = await livePass();
    const before = JSON.stringify(result);
    const report = buildReport({ gate: result });
    assert.equal(JSON.stringify(result), JSON.stringify(JSON.parse(before)), 'buildReport does not mutate the gate result');
    assert.equal(report.verdict, 'PASS');
    assert.deepEqual(report.counts, { block: 0, exception: 0, log: 2, integrity: 0 });
    assert.deepEqual(report.issueCounts, result.correlation.summary);
    assert.equal(report.dispositionCounts.review + report.dispositionCounts.info, report.issueCounts.log);
    assert.deepEqual(report.routing, route({ verdict: 'PASS', mode: 'enforce', breakGlass: report.breakGlass }));
    assert.equal(report.routing.slack, false);
    assert.doesNotMatch(written, /"disposition"|"presentation"|"REVIEW"/, 'no presentation label is written to security-gate.json');
    // A REVIEW issue is still a LOG issue.
    assert.equal(result.correlation.issues[0].action, 'LOG');
    assert.equal(presentationDisposition(result.correlation.issues[0]), 'REVIEW');
  });

  it('a gate result written before any of the new optional fields still renders', () => {
    const old = { verdict: 'BLOCK', findings: [trivy(1, 'BLOCK', 'high'), { source: 'semgrep', id: 'r', action: 'LOG', policyRule: 'sast.low', severity: 'low' }] };
    const report = buildReport({ gate: old });
    const markdown = renderMarkdown(report);
    assert.equal(tableRows(markdown).length, 2);
    assert.equal(report.scanHealth, null);
    assert.doesNotThrow(() => renderSlack(report));
    assert.doesNotThrow(() => renderEvidenceMarkdown(report));
    assert.doesNotThrow(() => renderMarkdown(buildReport({ gate: {} })));
  });
});

describe('large result sets produce bounded output with exact omissions', () => {
  it('150 findings: bounded, INFO capped, omitted count exact, counts unchanged', () => {
    const findings = [
      ...Array.from({ length: 5 }, (_, i) => trivy(i, 'BLOCK', 'high')),
      ...Array.from({ length: 5 }, (_, i) => trivy(100 + i, 'EXCEPTION', 'high')),
      ...Array.from({ length: 40 }, (_, i) => conflictedOsv(`review-${i}`, i)),
      ...Array.from({ length: 100 }, (_, i) => trivy(200 + i, 'LOG', 'medium'))
    ];
    const gateResult = {
      verdict: 'BLOCK',
      findings,
      dependencyEvidence: conflictEvidence(Array.from({ length: 40 }, (_, i) => `review-${i}`))
    };
    const report = buildReport({ gate: gateResult });
    assert.deepEqual(report.counts, { block: 5, exception: 5, log: 140, integrity: 0 });
    assert.deepEqual(report.dispositionCounts, { block: 5, exception: 5, review: 40, info: 100 });
    const markdown = renderMarkdown(report);
    assert.ok(markdown.length <= SUMMARY_LIMITS.maxCharacters, `summary is ${markdown.length} characters`);

    const rows = tableRows(markdown).map((row) => rowCells(row)[0]);
    const byDisposition = (label) => rows.filter((cell) => cell.endsWith(label)).length;
    assert.deepEqual([byDisposition('BLOCK'), byDisposition('EXCEPTION'), byDisposition('REVIEW'), byDisposition('INFO')], [5, 5, 30, 20]);
    const omission = /_Showing (\d+) of (\d+) issues; (\d+) table rows not shown \((.+?)\)\./.exec(markdown);
    assert.ok(omission, 'the omission is stated');
    assert.equal(Number(omission[1]), rows.length);
    assert.equal(Number(omission[2]), 150);
    assert.equal(Number(omission[1]) + Number(omission[3]), 150);
    assert.equal(omission[4], '10 REVIEW, 80 INFO');
    // Details: BLOCK/EXCEPTION/REVIEW only, capped, the rest stated exactly.
    const cards = (markdown.match(/<details( open)?><summary>/g) ?? []).length;
    assert.equal(cards, SUMMARY_LIMITS.detailCards);
    assert.doesNotMatch(markdown, /<summary>ℹ️ INFO/);
    const reviewNote = /### ⚖️ Needs review — non-blocking, evidence disagrees \(40\)[\s\S]*?_Full evidence shown for (\d+) of 40; (\d+) not shown here/.exec(markdown);
    assert.ok(reviewNote);
    assert.equal(Number(reviewNote[1]) + Number(reviewNote[2]), 40);
    assert.equal(Number(reviewNote[1]), SUMMARY_LIMITS.detailCards - 10);
    // Conflict callouts are bounded too.
    assert.match(markdown, /_30 more evidence conflict\(s\) not shown/);
    // No raw per-record card is dumped into the summary.
    assert.doesNotMatch(markdown, /Medium-severity vulnerability CVE-2099-00200/);
  });

  it('300 BLOCK issues with long names stay under the size limit, and say how many rows are missing', () => {
    const long = 'x'.repeat(400);
    const findings = Array.from({ length: 300 }, (_, i) => trivy(i, 'BLOCK', 'critical', { package: `${long}-${i}`, id: `CVE-${long}-${i}` }));
    const report = buildReport({ gate: { verdict: 'BLOCK', findings } });
    const markdown = renderMarkdown(report);
    assert.ok(markdown.length <= SUMMARY_LIMITS.maxCharacters, `summary is ${markdown.length} characters`);
    const rows = tableRows(markdown).length;
    const omission = /_Showing (\d+) of 300 issues; (\d+) table rows not shown \((\d+) BLOCK\)/.exec(markdown);
    assert.ok(omission);
    assert.deepEqual([Number(omission[1]), Number(omission[2]), Number(omission[3])], [rows, 300 - rows, 300 - rows]);
    assert.equal(report.counts.block, 300);
    assert.match(markdown, /\*\*300\*\* blocking/);
    assert.match(renderSlack(report).blocks.map((block) => block.text?.text ?? '').join('\n'), /and 295 more/);
  });

  it('full evidence remains complete in security-gate.json and the evidence document', async () => {
    const { result, written } = await livePass();
    const parsed = JSON.parse(written);
    assert.equal(parsed.findings.length, 2);
    assert.ok(parsed.correlation.issues[0].evidence.resolution.observations.length === 2);
    assert.ok(parsed.dependencyEvidence.observations.length > 0);
    const evidence = renderEvidenceMarkdown(buildReport({ gate: result }));
    assert.match(evidence, /OSV-Scanner \/ `PYSEC-2026-215`/);
    assert.match(evidence, /OSV-Scanner \/ `GHSA-65pc-fj4g-8rjx`/);
  });
});

// ---- scan availability ------------------------------------------------------------

const PINNED = 'semgrep/semgrep@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e';
const failedAttempt = (attempt) => ({ attempt, outcome: 'failed', exitCode: 1, cause: 'registry-network', retryable: true, detail: 'connection reset by peer' });
const ACQUISITION_FAILED = acquisitionRecord({
  scanner: 'semgrep',
  image: PINNED,
  acquisition: { acquired: false, source: null, maxAttempts: 3, attempts: [1, 2, 3].map(failedAttempt), cause: 'registry-network', retryable: true, detail: 'connection reset by peer' }
});
const JOBS_SAST_FAILED = { 'secret-scan': 'success', 'dependency-scan': 'success', sast: 'failure' };

describe('scan unavailable is not a vulnerability-policy BLOCK', () => {
  it('acquisition failure: BLOCK — scan unavailable, SAST unavailable, security state UNKNOWN, re-run advice', async () => {
    const { result } = await gate({ semgrep: MISSING_SEMGREP, record: ACQUISITION_FAILED });
    const report = buildReport({ gate: result, context: { jobResults: JOBS_SAST_FAILED } });
    assert.equal(report.verdict, 'BLOCK');
    assert.equal(report.gateStatus.kind, 'scan');
    assert.equal(report.counts.block, 0);
    assert.equal(report.counts.integrity, 1);
    const markdown = renderMarkdown(report);
    assert.match(markdown, /^## ⛔ Security gate: BLOCK — scan unavailable$/m);
    assert.match(markdown, /This is not a vulnerability-policy BLOCK/);
    assert.match(markdown, /\| Secret scanning \| ✅ completed \|/);
    assert.match(markdown, /\| Dependency scanning \| ✅ completed \|/);
    assert.match(markdown, /\| SAST \| ⛔ unavailable \| acquisition-failed · registry-network · retryable \|/);
    assert.match(markdown, /\*\*Security state: UNKNOWN\*\*/);
    assert.match(markdown, /Semgrep could not start because its pinned scanner image could not be obtained after 3 attempts \(cause: registry-network, retryable\)\./);
    assert.match(markdown, /\*\*Suggested action:\*\* Re-run the failed jobs\. If the failure repeats, investigate scanner registry\/network availability\./);
    assert.match(markdown, /\*\*Do not generate a baseline from this run\.\*\*/);
    // The integrity consequence is kept, alongside its cause.
    assert.match(markdown, /Semgrep: missing report file/);
    assert.match(markdown, /results are UNKNOWN, not clean/);
    assert.doesNotMatch(markdown, /Blocking security findings must be resolved|### ⛔ Blocking findings/);

    const slack = renderSlack(report);
    assert.equal(slack.text, '⛔ Security gate: BLOCK — scan unavailable');
    assert.match(JSON.stringify(slack.blocks), /Re-run the failed jobs/);
    assert.equal(report.routing.slack, true, 'routing is unchanged: a BLOCK still alerts');
  });

  it('the same state without job results (gate evidence only) reads the same', async () => {
    const { result } = await gate({ semgrep: MISSING_SEMGREP, record: ACQUISITION_FAILED });
    const markdown = renderMarkdown(buildReport({ gate: result }));
    assert.match(markdown, /Security gate: BLOCK — scan unavailable/);
    assert.match(markdown, /\| SAST \| ⛔ unavailable \|/);
    assert.match(markdown, /\| Secret scanning \| ❔ unknown \|/, 'not claimed completed without evidence');
  });

  it('a scanner runtime failure is not described as a registry problem', async () => {
    const record = await completeExecution({
      record: acquisitionRecord({ scanner: 'semgrep', image: PINNED, acquisition: { acquired: true, source: 'registry', maxAttempts: 3, attempts: [{ attempt: 1, outcome: 'acquired' }] } }),
      scanner: 'semgrep',
      exitCode: '2',
      reportPath: MISSING_SEMGREP
    });
    const { result } = await gate({ semgrep: MISSING_SEMGREP, record });
    const markdown = renderMarkdown(buildReport({ gate: result, context: { jobResults: JOBS_SAST_FAILED } }));
    assert.match(markdown, /Security gate: BLOCK — scan unavailable/);
    assert.match(markdown, /Semgrep started but failed — exit 2: fatal scanner error \(cause: scanner-runtime\)/);
    assert.match(markdown, /Inspect the scanner step in the job log/);
    assert.doesNotMatch(markdown, /registry|pinned scanner image could not be obtained/i);
  });

  it('a missing report with no execution record claims no cause', async () => {
    const { result } = await gate({ semgrep: MISSING_SEMGREP });
    const markdown = renderMarkdown(buildReport({ gate: result, context: { jobResults: JOBS_SAST_FAILED } }));
    assert.match(markdown, /Security gate: BLOCK — scan unavailable/);
    assert.match(markdown, /Diagnose the failed scanner or report step/);
    assert.doesNotMatch(markdown, /registry-network|Re-run the failed jobs/);
  });

  it('a malformed report is an untrusted scan, still not a policy BLOCK', async () => {
    const { result } = await withTempDir(async (directory) => {
      const bad = join(directory, 'semgrep.json');
      await writeFile(bad, '{ not json');
      return gate({ semgrep: bad });
    });
    const markdown = renderMarkdown(buildReport({ gate: result, context: { jobResults: { 'secret-scan': 'success', 'dependency-scan': 'success', sast: 'success' } } }));
    assert.match(markdown, /Security gate: BLOCK — scan untrusted/);
    assert.match(markdown, /\| SAST \| ⚠️ untrusted \|/);
    assert.match(markdown, /This is not a vulnerability-policy BLOCK/);
  });

  it('log-only still says NOT enforced and never "must be resolved before merge"', async () => {
    const { result } = await gate({ semgrep: MISSING_SEMGREP, record: ACQUISITION_FAILED });
    const markdown = renderMarkdown(buildReport({ gate: result, mode: 'log-only' }));
    assert.match(markdown, /NOT enforced/);
    assert.doesNotMatch(markdown, /must be resolved before merge/);
  });
});

describe('the notifier writes the full evidence document next to the gate result', () => {
  it('writes every issue, including INFO, without failing delivery', async () => {
    const written = [];
    const { result } = await livePass();
    const performed = await dispatch({
      gate: result,
      evidencePath: 'reports/security-gate-evidence.md',
      writeImpl: async (path, data) => written.push({ path, data }),
      appendImpl: async () => {},
      summaryPath: 'summary.md',
      fetchImpl: async () => ({ ok: true, json: async () => [] }),
      logger: { log: () => {}, error: () => {} }
    });
    assert.deepEqual(performed.failures, []);
    assert.equal(written.length, 1);
    assert.equal(written[0].path, 'reports/security-gate-evidence.md');
    assert.match(written[0].data, /⚖️ REVIEW · Medium · idna — CVE-2026-45409/);
  });
});
