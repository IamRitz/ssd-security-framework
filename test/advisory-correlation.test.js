// Alias-aware correlation of dependency findings into developer-facing issues.
//
// Regression (live run IamRitz/ssd-scratch-consumer 35202539930): one requests
// vulnerability (CVE-2026-25645) was shown as 1 BLOCK (pip-audit PYSEC-2026-2275)
// plus 2 LOG (OSV PYSEC-2026-2275 and GHSA-gc5v-m9x4-r6x2), and one idna
// vulnerability (CVE-2026-45409) as 2 LOG — "1 blocking, 4 logged" for two issues.
//
// The contract under test: raw findings are untouched policy evidence; issues
// are a separate, evidence-backed grouping for people.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { correlateFindings, correlationRecord } from '../security/scripts/correlate-findings.mjs';
import { buildReport, renderEvidenceMarkdown, renderMarkdown, renderSlack } from '../security/scripts/format-findings.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const LIVE = join(FIXTURES, 'live-python-source-only');
const POLICY = resolve('security/policy.yaml');

async function liveGate() {
  const directory = await mkdtemp(join(tmpdir(), 'advisory-correlation-'));
  try {
    return await runSecurityGate({
      policy: POLICY,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      npmAudit: join(CLEAN, 'npm-audit.json'),
      osv: join(LIVE, 'osv-scanner.json'),
      pipAudit: join(LIVE, 'pip-audit.json'),
      semgrep: join(CLEAN, 'semgrep.json'),
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      output: join(directory, 'security-gate.json'),
      exceptions: join(directory, 'gate-exceptions.json')
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const osv = (id, aliases, extra = {}) => ({
  source: 'osv-scanner',
  id,
  package: 'pkg',
  ecosystem: 'PyPI',
  installedVersion: '1.0.0',
  severity: 'medium',
  severitySource: 'cvss',
  cvssScore: 5,
  policyRule: 'dependencies.medium',
  action: 'LOG',
  aliases,
  ...extra
});

describe('the live requests + idna run', () => {
  it('keeps every raw finding and the raw summary unchanged', async () => {
    const gate = await liveGate();
    assert.equal(gate.verdict, 'BLOCK');
    assert.deepEqual(gate.summary, { block: 1, exception: 0, log: 4 }, 'raw per-record counts are the policy record');
    assert.equal(gate.findings.length, 5);
    assert.deepEqual(
      gate.findings.map((finding) => `${finding.source}:${finding.id}:${finding.action}`),
      [
        'pip-audit:PYSEC-2026-2275:BLOCK',
        'osv-scanner:PYSEC-2026-2275:LOG',
        'osv-scanner:GHSA-gc5v-m9x4-r6x2:LOG',
        'osv-scanner:PYSEC-2026-215:LOG',
        'osv-scanner:GHSA-65pc-fj4g-8rjx:LOG'
      ]
    );
    assert.equal(gate.breakGlass.eligible, true, 'break-glass eligibility is computed from raw findings, unchanged');
  });

  it('records two correlated issues in the gate result, pointing at the raw findings', async () => {
    const gate = await liveGate();
    const { correlation } = gate;
    assert.equal(correlation.schemaVersion, 1);
    assert.deepEqual(correlation.summary, { issues: 2, rawFindings: 5, block: 1, exception: 0, log: 1, integrity: 0 });

    const [requests, idna] = correlation.issues;
    assert.equal(requests.package, 'requests');
    assert.equal(requests.action, 'BLOCK', 'strongest action wins for the developer-facing issue');
    assert.deepEqual(requests.actions.sort(), ['BLOCK', 'LOG'], 'underlying actions are retained');
    assert.deepEqual(requests.findings, [0, 1, 2]);
    assert.deepEqual(requests.sources.sort(), ['osv-scanner', 'pip-audit']);
    assert.equal(requests.primaryId, 'CVE-2026-25645');
    assert.deepEqual(requests.advisoryIds, ['CVE-2026-25645', 'GHSA-gc5v-m9x4-r6x2', 'PYSEC-2026-2275']);
    assert.equal(requests.breakGlassEligible, true);

    assert.equal(idna.package, 'idna');
    assert.equal(idna.action, 'LOG');
    assert.deepEqual(idna.findings, [3, 4]);
    assert.equal(idna.primaryId, 'CVE-2026-45409');
    assert.deepEqual(idna.advisoryIds, ['CVE-2026-45409', 'GHSA-65pc-fj4g-8rjx', 'PYSEC-2026-215']);
  });

  it('renders ONE blocking requests issue with every scanner record and its own severity derivation', async () => {
    const gate = await liveGate();
    const report = buildReport({ gate, mode: 'enforce' });
    const markdown = renderMarkdown(report);

    assert.match(markdown, /\*\*1\*\* blocking · \*\*0\*\* exception · \*\*1\*\* logged/);
    assert.match(markdown, /\*\*2\*\* unique issues from \*\*5\*\* scanner findings/);
    assert.match(markdown, /### ⛔ Blocking findings \(1\)/);
    // The logged idna issue has conflicting version evidence, so it is shown as
    // REVIEW (presentation only; its policy action stays LOG).
    assert.match(markdown, /### ⚖️ Needs review — non-blocking, evidence disagrees \(1\)/);
    assert.equal(report.issues.find((issue) => issue.package === 'idna').action, 'LOG');

    const blocking = markdown.slice(markdown.indexOf('### ⛔'), markdown.indexOf('### ⚖️'));
    assert.match(blocking, /\*\*`requests` 2\.32\.5 — CVE-2026-25645\*\*/);
    assert.match(blocking, /`CVE-2026-25645`, `GHSA-gc5v-m9x4-r6x2`, `PYSEC-2026-2275`/);
    assert.match(
      blocking,
      /pip-audit \/ `PYSEC-2026-2275` → \*\*BLOCK\*\* \(`dependencies\.high_with_fix`\) — severity unavailable from pip-audit; framework classifies high \(fail-closed\); fixed in 2\.33\.0/
    );
    assert.match(
      blocking,
      /OSV-Scanner \/ `PYSEC-2026-2275` → \*\*LOG\*\* \(`dependencies\.medium`\) — CVSS v3 base score 5\.5 from the OSV record; framework classifies medium/
    );
    assert.match(
      blocking,
      /OSV-Scanner \/ `GHSA-gc5v-m9x4-r6x2` → \*\*LOG\*\* \(`dependencies\.medium`\) — CVSS v3 base score 4\.4 from the OSV record; framework classifies medium/
    );
    assert.match(blocking, /records disagree \(high vs medium\)/, 'differing severities are shown, not flattened');
    assert.match(blocking, /Fixed version\(s\): 2\.33\.0 \(pip-audit, OSV-Scanner\)/, 'fix provenance per source');

    // Not duplicated as extra LOG entries.
    const logged = markdown.slice(markdown.indexOf('### ⚖️'), markdown.indexOf('\n---\n'));
    assert.doesNotMatch(logged, /requests/);
    // pip-audit listed idna 3.19 (no advisory) while OSV-Scanner matched 3.9.0:
    // neither version is headlined as the one in use.
    assert.match(logged, /\*\*`idna` — CVE-2026-45409 \(effective version disputed: 3\.19 vs 3\.9\.0\)\*\*/);
    assert.doesNotMatch(logged, /`idna` 3\.9\.0 —/);
    assert.match(logged, /Resolution conflict/);
    assert.match(logged, /OSV-Scanner \/ `PYSEC-2026-215`/);
    assert.match(logged, /OSV-Scanner \/ `GHSA-65pc-fj4g-8rjx`/);

    // Raw cards stay available on the report object for anything machine-readable.
    assert.equal(report.cards.length, 5);
    assert.deepEqual(report.counts, { block: 1, exception: 0, log: 4, integrity: 0 });
  });

  it('Slack headlines unique issues and discloses the raw count', async () => {
    const gate = await liveGate();
    const slack = JSON.stringify(renderSlack(buildReport({ gate })));
    assert.match(slack, /\*Blocking\*\\n1/);
    assert.match(slack, /\*Logged\*\\n1/);
    assert.match(slack, /\*Scanner findings\*\\n5 \(2 unique\)/);
    assert.equal((slack.match(/CVE-2026-25645/g) || []).length, 1, 'requests appears once in the Slack highlights');
  });
});

describe('correlation is supported only by identity evidence', () => {
  it('requests-equivalent: pip-audit BLOCK + two OSV LOG records collapse into one BLOCK issue', () => {
    const findings = [
      {
        source: 'pip-audit',
        id: 'PYSEC-2026-2275',
        package: 'requests',
        severity: 'high',
        severitySource: 'framework-default',
        policyRule: 'dependencies.high_with_fix',
        action: 'BLOCK',
        fixVersions: ['2.33.0'],
        aliases: ['GHSA-gc5v-m9x4-r6x2', 'CVE-2026-25645']
      },
      osv('PYSEC-2026-2275', ['CVE-2026-25645', 'GHSA-gc5v-m9x4-r6x2'], { package: 'requests', cvssScore: 5.5 }),
      osv('GHSA-gc5v-m9x4-r6x2', ['CVE-2026-25645', 'PYSEC-2026-2275'], { package: 'requests', cvssScore: 4.4 })
    ];
    const issues = correlateFindings(findings);
    assert.equal(issues.length, 1);
    assert.equal(issues[0].action, 'BLOCK');
    assert.deepEqual(issues[0].findings, [0, 1, 2]);
    // Raw evidence is not mutated by correlation.
    assert.equal(findings[1].action, 'LOG');
    assert.equal(findings[2].cvssScore, 4.4);
  });

  it('idna-equivalent: two OSV aliases collapse into one LOG issue', () => {
    const issues = correlateFindings([
      osv('PYSEC-2026-215', ['CVE-2026-45409', 'GHSA-65pc-fj4g-8rjx'], { package: 'idna' }),
      osv('GHSA-65pc-fj4g-8rjx', ['CVE-2026-45409', 'PYSEC-2026-215'], { package: 'idna' })
    ]);
    assert.equal(issues.length, 1);
    assert.equal(issues[0].action, 'LOG');
  });

  it('PYSEC + GHSA + CVE aliases on the same package collapse even when only the CVE is shared', () => {
    const issues = correlateFindings([osv('PYSEC-1', ['CVE-1']), osv('GHSA-aaaa-bbbb-cccc', ['CVE-1'])]);
    assert.equal(issues.length, 1);
    assert.deepEqual(issues[0].advisoryIds, ['CVE-1', 'GHSA-aaaa-bbbb-cccc', 'PYSEC-1']);
  });

  it('same package, unrelated CVEs stay separate issues', () => {
    const issues = correlateFindings([
      osv('PYSEC-1', ['CVE-2026-1']),
      osv('PYSEC-2', ['CVE-2026-2']),
      { source: 'pip-audit', id: 'PYSEC-3', package: 'pkg', action: 'BLOCK', aliases: ['CVE-2026-3'] }
    ]);
    assert.equal(issues.length, 3);
  });

  it('the same advisory id on a different package is not merged', () => {
    const issues = correlateFindings([
      osv('GHSA-xxxx-yyyy-zzzz', ['CVE-2026-9'], { package: 'alpha' }),
      osv('GHSA-xxxx-yyyy-zzzz', ['CVE-2026-9'], { package: 'beta' })
    ]);
    assert.equal(issues.length, 2);
  });

  it('the same advisory id and package name in a different ecosystem is not merged', () => {
    const issues = correlateFindings([
      osv('GHSA-xxxx-yyyy-zzzz', ['CVE-2026-9'], { package: 'shared', ecosystem: 'npm' }),
      osv('GHSA-xxxx-yyyy-zzzz', ['CVE-2026-9'], { package: 'shared', ecosystem: 'PyPI' })
    ]);
    assert.equal(issues.length, 2);
  });

  it('pip-audit (always PyPI) does not merge with an npm OSV record of the same name and id', () => {
    const issues = correlateFindings([
      { source: 'pip-audit', id: 'GHSA-q', package: 'left-pad', action: 'BLOCK' },
      osv('GHSA-q', [], { package: 'left-pad', ecosystem: 'npm' })
    ]);
    assert.equal(issues.length, 2);
  });

  it('an alias chain (A aliases B, B aliases C) is one identity', () => {
    const issues = correlateFindings([osv('A-1', ['B-1']), osv('B-1', ['C-1']), osv('C-1', [])]);
    assert.equal(issues.length, 1);
    assert.deepEqual(issues[0].findings, [0, 1, 2]);
    assert.deepEqual(issues[0].advisoryIds, ['A-1', 'B-1', 'C-1']);
  });

  it('a chain that arrives out of order still joins', () => {
    const issues = correlateFindings([osv('C-1', []), osv('A-1', ['B-1']), osv('X-9', []), osv('B-1', ['C-1'])]);
    assert.equal(issues.length, 2);
    assert.deepEqual(issues[0].findings, [0, 1, 3]);
  });

  it('PyPI names normalize per PEP 503; other ecosystems compare exactly', () => {
    assert.equal(
      correlateFindings([osv('PYSEC-1', [], { package: 'Charset_Normalizer' }), osv('PYSEC-1', [], { package: 'charset-normalizer' })]).length,
      1
    );
    assert.equal(
      correlateFindings([
        osv('GHSA-1', [], { package: 'Foo', ecosystem: 'npm' }),
        osv('GHSA-1', [], { package: 'foo', ecosystem: 'npm' })
      ]).length,
      2
    );
  });

  it('an OSV record with no ecosystem, npm audit, secrets, SAST and integrity findings stand alone', () => {
    const findings = [
      osv('PYSEC-1', ['CVE-1'], { ecosystem: undefined }),
      osv('PYSEC-1', ['CVE-1'], { ecosystem: undefined }),
      { source: 'npm-audit', id: 'lodash', action: 'BLOCK', url: 'https://github.com/advisories/GHSA-1' },
      { source: 'npm-audit', id: 'lodash', action: 'BLOCK' },
      { source: 'semgrep', id: 'rule', action: 'LOG' },
      { source: 'gitleaks', id: 'rule', action: 'LOG' },
      { source: 'security-gate', id: 'report-integrity', policyRule: 'gate.report_integrity', action: 'BLOCK' }
    ];
    const record = correlationRecord(findings);
    assert.equal(record.issues.length, findings.length);
    assert.equal(record.summary.integrity, 1);
    assert.equal(record.summary.block, 2, 'an integrity failure is not also counted as blocking');
  });

  it('strongest action ordering is BLOCK > EXCEPTION > LOG, regardless of record order', () => {
    const issues = correlateFindings([
      osv('A', ['CVE-7']),
      osv('B', ['CVE-7'], { action: 'EXCEPTION', policyRule: 'dependencies.high_no_fix', severity: 'high' }),
      osv('C', ['CVE-7'], { action: 'LOG' })
    ]);
    assert.equal(issues[0].action, 'EXCEPTION');
    const withBlock = correlateFindings([osv('A', ['CVE-7']), { ...osv('B', ['CVE-7']), action: 'BLOCK' }]);
    assert.equal(withBlock[0].action, 'BLOCK');
  });

  it('a correlated EXCEPTION issue renders as a tracked exception, and single records keep their original card', async () => {
    const findings = [
      osv('PYSEC-5', ['CVE-5'], { action: 'EXCEPTION', policyRule: 'dependencies.high_no_fix', severity: 'high', cvssScore: 7.5 }),
      osv('GHSA-5', ['CVE-5'], { action: 'LOG' }),
      osv('PYSEC-6', ['CVE-6'], { summary: 'standalone advisory' })
    ];
    const report = buildReport({ gate: { verdict: 'PASS-WITH-EXCEPTIONS', findings } });
    const markdown = renderMarkdown(report);
    assert.match(markdown, /### ⚠️ Tracked exceptions \(no fix available — passed deliberately\) \(1\)/);
    assert.match(markdown, /`pkg` 1\.0\.0 — CVE-5/);
    // The standalone LOG record is an INFO row in the summary; its original
    // single-record card is kept in the full evidence document.
    assert.match(markdown, /\| ℹ️ INFO \| Medium \| `pkg` \| `CVE-6` \| unknown \| 1\.0\.0 \| — \|/);
    assert.doesNotMatch(markdown, /Medium-severity advisory PYSEC-6/);
    assert.match(renderEvidenceMarkdown(report), /Medium-severity advisory PYSEC-6 in PyPI dependency `pkg` 1\.0\.0/);
    assert.equal(report.issues.length, 2);
  });
});

describe('the correlation record is additive to the gate result', () => {
  it('an integrity-failure gate result carries a correlation block too', async () => {
    const gate = await (async () => {
      const directory = await mkdtemp(join(tmpdir(), 'advisory-correlation-'));
      try {
        return await runSecurityGate({
          policy: POLICY,
          gitleaks: join(directory, 'missing.json'),
          output: join(directory, 'security-gate.json'),
          exceptions: join(directory, 'gate-exceptions.json')
        });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    })();
    assert.equal(gate.correlation.summary.integrity, 1);
    assert.equal(gate.correlation.summary.block, 0);
    assert.deepEqual(gate.summary, { block: 1, exception: 0, log: 0 });
  });

  it('the fixture is the real live report (guards against a hand-edited fixture)', async () => {
    const pip = JSON.parse(await readFile(join(LIVE, 'pip-audit.json'), 'utf8'));
    assert.equal(pip.dependencies[0].vulns.length, 2, 'pip-audit really did list PYSEC-2026-2275 twice');
  });
});
