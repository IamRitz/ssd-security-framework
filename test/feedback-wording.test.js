// Developer-facing wording that must track the evidence, not a fixed template.
//
//  - log-only + PASS: there is no blocking verdict to suppress, so the PR
//    comment / job summary must not say findings were "not enforced"; log-only
//    itself must stay visible.
//  - log-only + BLOCK: must say the BLOCK is not enforced.
//  - the exit-status decision table behind the pip-audit / OSV-Scanner steps.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { assessScannerExit, countReportFindings } from '../security/scripts/check-scanner-exit.mjs';
import { buildReport, renderMarkdown } from '../security/scripts/format-findings.mjs';

describe('log-only wording in the PR comment and job summary', () => {
  it('PASS + log-only names the mode without claiming anything was not enforced', () => {
    const markdown = renderMarkdown(buildReport({ gate: { verdict: 'PASS', findings: [] }, mode: 'log-only' }));
    assert.match(markdown, /runs in \*\*log-only\*\* mode\. The verdict is PASS, so there is no blocking verdict to suppress/);
    assert.match(markdown, /rollout mode/);
    assert.doesNotMatch(markdown, /not enforced/i);
    assert.doesNotMatch(markdown, /do not block/);
  });

  it('BLOCK + log-only says the blocking verdict is NOT enforced', () => {
    const gate = { verdict: 'BLOCK', findings: [{ source: 'semgrep', id: 'r', action: 'BLOCK', severity: 'high', policyRule: 'sast.high_new', baselineState: 'new' }] };
    const markdown = renderMarkdown(buildReport({ gate, mode: 'log-only' }));
    assert.match(markdown, /the blocking verdict above is reported but NOT enforced/);
    assert.match(markdown, /NOT enforced, because this repository runs in log-only mode/);
  });

  it('enforce mode carries no log-only note', () => {
    const markdown = renderMarkdown(buildReport({ gate: { verdict: 'PASS', findings: [] }, mode: 'enforce' }));
    assert.doesNotMatch(markdown, /log-only/);
  });
});

describe('scanner exit status decision table', () => {
  const cases = [
    // scanner, exit, findings, ok, outcome
    ['pip-audit', 0, 0, true, 'clean'],
    ['pip-audit', 1, 3, true, 'findings'],
    ['pip-audit', '1', 3, true, 'findings'],
    ['pip-audit', 0, 2, true, 'findings-clean-exit'],
    ['pip-audit', 1, 0, false, 'exit-report-mismatch'],
    ['pip-audit', 2, 3, false, 'unexpected-exit'],
    ['pip-audit', '', 3, false, 'unknown-exit'],
    ['osv-scanner', 0, 0, true, 'clean'],
    ['osv-scanner', 1, 4, true, 'findings'],
    ['osv-scanner', 1, 0, false, 'exit-report-mismatch'],
    ['osv-scanner', 127, 4, false, 'unexpected-exit'],
    ['osv-scanner', 128, 0, false, 'unexpected-exit'],
    ['npm-audit', 1, 1, false, 'unsupported']
  ];
  for (const [scanner, exitCode, findingCount, ok, outcome] of cases) {
    it(`${scanner} exit ${JSON.stringify(exitCode)} with ${findingCount} finding(s) => ${outcome}`, () => {
      const result = assessScannerExit({ scanner, exitCode, findingCount });
      assert.equal(result.ok, ok);
      assert.equal(result.outcome, outcome);
    });
  }

  it('a findings exit is described as a successful scan, never a scanner failure', () => {
    const { message } = assessScannerExit({ scanner: 'osv-scanner', exitCode: 1, findingCount: 1 });
    assert.match(message, /successful scan, not a scanner failure/);
  });

  it('counts findings the way the gate reads them', () => {
    assert.equal(
      countReportFindings('pip-audit', { dependencies: [{ name: 'a', vulns: [{ id: 'X' }, { id: 'Y' }] }, { name: 'b', skip_reason: 'x' }] }),
      2
    );
    assert.equal(countReportFindings('osv-scanner', { results: null }), 0);
    assert.equal(
      countReportFindings('osv-scanner', { results: [{ packages: [{ vulnerabilities: [{ id: 'A' }] }, { vulnerabilities: [{ id: 'B' }] }] }] }),
      2
    );
  });
});
