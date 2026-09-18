// Image gate developer feedback is PRESENTATION over a complete record:
//
//   raw Trivy report -> image-gate*.json (every normalized finding)
//                    -> image-gate*-evidence.md (every group, every card)
//                    -> bounded console / job summary / PR comment / Slack
//
// These tests pin both halves: the human surfaces are bounded, ordered and
// remediation-grouped, and nothing the gate decided or wrote changes.
//
// `trivy-python-large.json` is shaped like the live Python container run that
// motivated this (15 BLOCK_DEPLOY / 45 EXCEPTION / 122 LOG, advisories repeated
// across packages). Its advisory ids are synthetic.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import {
  buildReport,
  groupImageFindings,
  IMAGE_SUMMARY_LIMITS,
  renderEvidenceMarkdown,
  renderMarkdown,
  renderSlack,
  SUMMARY_LIMITS
} from '../security/scripts/format-findings.mjs';
import { CONSOLE_PREVIEW_LIMIT, consoleSummary, runImageGate } from '../security/scripts/image-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__/image-gate');
const LARGE = join(FIXTURES, 'trivy-python-large.json');
const POLICY = resolve('security/policy.yaml');
const SCRIPT = resolve('security/scripts/image-gate.mjs');

const CONTEXT = {
  evidenceFile: 'image-gate-prepush.json',
  evidenceMarkdownFile: 'image-gate-prepush-evidence.md',
  rawReportFile: 'trivy-image.json',
  scan: { imageTarball: 'application-image.tar' }
};

async function withTempDir(work) {
  const directory = await mkdtemp(join(tmpdir(), 'image-feedback-'));
  try {
    return await work(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

// The real gate over a raw Trivy report object or path; also returns the JSON it wrote.
async function trivyGate(report) {
  return withTempDir(async (directory) => {
    let path = report;
    if (typeof report !== 'string') {
      path = join(directory, 'trivy-image.json');
      await writeFile(path, JSON.stringify(report));
    }
    const output = join(directory, 'image-gate-prepush.json');
    const result = await runImageGate({ policy: POLICY, source: 'trivy', report: path, output });
    return { result, written: await readFile(output, 'utf8') };
  });
}

const rawLarge = async () => JSON.parse(await readFile(LARGE, 'utf8'));
const summaryOf = (gate, context = CONTEXT) => renderMarkdown(buildReport({ gate, context }));
const groupLines = (markdown) => markdown.split('\n').filter((line) => /^- \*\*(Critical|High|Medium|Low|Unknown)\*\* · /.test(line));
const section = (markdown, heading) => {
  const start = markdown.indexOf(heading);
  if (start === -1) return '';
  const next = markdown.indexOf('\n### ', start + heading.length);
  return markdown.slice(start, next === -1 ? undefined : next);
};

// Minimal normalized Trivy findings, as image-gate.mjs writes them.
const vuln = (id, pkg, severity, { installed = '1.0.0', fixed = '1.0.1', target = 'app (debian 12.11)', action } = {}) => ({
  source: 'trivy',
  id,
  package: pkg,
  severity,
  scannerSeverity: severity.toUpperCase(),
  installedVersion: installed,
  target,
  fixAvailable: fixed !== null,
  action: action ?? (['critical', 'high'].includes(severity) ? (fixed !== null ? 'BLOCK_DEPLOY' : 'EXCEPTION') : 'LOG'),
  policyRule: `image.${severity}${['critical', 'high'].includes(severity) ? (fixed !== null ? '_with_fix' : '_no_fix') : ''}`,
  reason: 'synthetic',
  ...(fixed !== null ? { fixedVersion: fixed } : {})
});
const secret = (rule, target) => ({
  source: 'trivy',
  id: rule,
  severity: 'critical',
  action: 'BLOCK_DEPLOY',
  policyRule: 'image.secret',
  reason: `secret detected in image layer (${rule})`,
  scannerSeverity: 'HIGH',
  target
});
const blockDeploy = (findings) => ({
  verdict: 'BLOCK_DEPLOY',
  summary: {
    blockDeploy: findings.filter((f) => f.action === 'BLOCK_DEPLOY').length,
    exception: findings.filter((f) => f.action === 'EXCEPTION').length,
    log: findings.filter((f) => f.action === 'LOG').length
  },
  integrity: { trusted: true, failures: [] },
  findings
});

// ---- 1-3, 14: the machine record is complete and unchanged ----------------------

describe('image gate: the normalized record is complete and policy is unchanged', () => {
  it('the live-shaped report keeps its exact verdict and per-record counts', async () => {
    const { result, written } = await trivyGate(LARGE);
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.deepEqual(result.summary, { blockDeploy: 15, exception: 45, log: 122 });
    assert.equal(result.integrity.trusted, true);
    assert.equal(result.exceptions.length, 45);
    // Every raw Trivy (id, package) pair is one written finding — nothing grouped away.
    const raw = await rawLarge();
    const rawPairs = raw.Results.flatMap((r) => r.Vulnerabilities.map((v) => `${v.VulnerabilityID}|${v.PkgName}`)).sort();
    const parsed = JSON.parse(written);
    assert.deepEqual(parsed.findings.map((f) => `${f.id}|${f.package}`).sort(), rawPairs);
    assert.equal(parsed.findings.length, 182);
    assert.deepEqual(parsed, result, 'the file is the returned result');
  });

  it('policy actions follow severity and fix availability exactly as before', async () => {
    const { result } = await trivyGate(LARGE);
    const byRule = {};
    for (const finding of result.findings) byRule[`${finding.policyRule}:${finding.action}`] = (byRule[`${finding.policyRule}:${finding.action}`] ?? 0) + 1;
    assert.deepEqual(byRule, {
      'image.critical_with_fix:BLOCK_DEPLOY': 3,
      'image.high_with_fix:BLOCK_DEPLOY': 12,
      'image.critical_no_fix:EXCEPTION': 10,
      'image.high_no_fix:EXCEPTION': 35,
      'image.medium:LOG': 82,
      'image.low:LOG': 40
    });
  });

  it('the normalized gate format is pinned: top-level shape and one full record', async () => {
    const { result } = await trivyGate(join(FIXTURES, 'trivy-critical.json'));
    assert.deepEqual(Object.keys(result), ['verdict', 'summary', 'exceptions', 'image', 'findings', 'integrity']);
    assert.deepEqual(result.findings[0], {
      source: 'trivy',
      id: 'CVE-2099-0001',
      package: 'libssl3',
      severity: 'critical',
      scannerSeverity: 'CRITICAL',
      installedVersion: '3.5.7',
      target: 'alpine',
      fixAvailable: true,
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.critical_with_fix',
      reason: 'critical image finding; fix available',
      fixedVersion: '3.5.8'
    });
    assert.deepEqual(result.image, {
      imageId: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
      os: { family: 'alpine', name: '3.24.1', eosl: false },
      scannedAt: '2026-09-10T00:00:00Z'
    });
  });

  it('the raw Trivy report is read, never rewritten', async () => {
    const before = createHash('sha256').update(await readFile(LARGE)).digest('hex');
    await trivyGate(LARGE);
    assert.equal(createHash('sha256').update(await readFile(LARGE)).digest('hex'), before);
  });

  it('rendering never mutates the gate result', async () => {
    const { result } = await trivyGate(LARGE);
    const before = JSON.stringify(result);
    const report = buildReport({ gate: result, context: CONTEXT });
    renderMarkdown(report);
    renderEvidenceMarkdown(report);
    renderSlack(report);
    assert.equal(JSON.stringify(result), before);
    assert.equal(report.verdict, 'BLOCK_DEPLOY');
    assert.deepEqual(report.counts, { block: 15, exception: 45, log: 122, integrity: 0 });
    assert.equal(report.routing.slack, true);
  });
});

// ---- 1: console -----------------------------------------------------------------

describe('image gate CLI: a bounded summary, not a finding dump', () => {
  it('prints verdict, counts, a bounded Critical-first preview with the exact omission, and the JSON path', async () => {
    await withTempDir(async (directory) => {
      const output = join(directory, 'image-gate-prepush.json');
      const run = spawnSync(process.execPath, [SCRIPT, '--policy', POLICY, '--source', 'trivy', '--report', LARGE, '--output', output], { encoding: 'utf8' });
      assert.equal(run.status, 1, 'BLOCK_DEPLOY still exits non-zero');
      const lines = run.stdout.trim().split('\n');
      assert.equal(lines[0], 'IMAGE GATE: BLOCK_DEPLOY');
      assert.equal(lines[1], '15 blocking · 45 exception · 122 logged findings');
      assert.equal(lines.at(-1), `Full normalized findings: ${output}`);
      assert.ok(lines.length <= 4 + CONSOLE_PREVIEW_LIMIT + 1, `console printed ${lines.length} lines for 182 findings`);
      const preview = lines.filter((line) => /^ {2}(CRITICAL|HIGH) /.test(line));
      assert.equal(preview.length, CONSOLE_PREVIEW_LIMIT);
      assert.deepEqual(preview.slice(0, 3).map((line) => line.split(' ')[2]), ['CRITICAL', 'CRITICAL', 'CRITICAL']);
      assert.match(run.stdout, / {2}\.\.\. 10 more blocking findings not shown/);
      // No EXCEPTION or LOG record is printed individually.
      assert.doesNotMatch(run.stdout, /CVE-2099-2\d{3}|CVE-2099-3\d{3}|\(image\.(medium|low|critical_no_fix|high_no_fix)\)/);
      // The full record was still written.
      assert.equal(JSON.parse(await readFile(output, 'utf8')).findings.length, 182);
    });
  });

  it('an integrity failure is printed in full: it may be the only evidence there is', async () => {
    await withTempDir(async (directory) => {
      const output = join(directory, 'gate.json');
      const run = spawnSync(
        process.execPath,
        [SCRIPT, '--policy', POLICY, '--source', 'trivy', '--report', join(FIXTURES, 'trivy-false-clean-no-os.json'), '--output', output],
        { encoding: 'utf8' }
      );
      assert.equal(run.status, 1);
      assert.match(run.stdout, /^IMAGE GATE: BLOCK_DEPLOY$/m);
      assert.match(run.stdout, /^INTEGRITY FAILURE \(image\.report_integrity\): Trivy did not detect an OS family/m);
      assert.match(run.stdout, /results are UNKNOWN, not clean/);
    });
  });

  it('every image secret is printed even when the vulnerability preview is truncated', () => {
    // More secrets than the preview limit: none may be cut by it.
    const targets = Array.from({ length: CONSOLE_PREVIEW_LIMIT + 2 }, (_, i) => `app/secret-${i}/.npmrc`);
    const findings = [
      ...Array.from({ length: 30 }, (_, i) => vuln(`CVE-2099-${1000 + i}`, `pkg-${i}`, 'critical')),
      ...targets.map((target) => secret('npm-token', target))
    ];
    const text = consoleSummary(blockDeploy(findings), 'reports/image-gate-prepush.json');
    for (const target of targets) {
      assert.ok(text.includes(`in ${target} (image.secret)`), `secret in ${target} printed`);
    }
    assert.equal(text.split('\n').filter((line) => line.includes('(image.critical_with_fix)')).length, CONSOLE_PREVIEW_LIMIT);
    assert.match(text, /\.\.\. 25 more blocking findings not shown/);
    const lines = text.split('\n');
    assert.ok(lines.findIndex((line) => line.includes('image.secret')) < lines.findIndex((line) => line.includes('CVE-2099-1000')), 'secrets come first');
  });

  it('a DEPLOY prints no finding at all', async () => {
    const { result } = await trivyGate(join(FIXTURES, 'trivy-clean.json'));
    assert.equal(consoleSummary(result, 'x.json'), 'IMAGE GATE: DEPLOY\n0 blocking · 0 exception · 0 logged findings\nFull normalized findings: x.json');
  });
});

// ---- 4-10: the default developer summary ----------------------------------------

describe('image summary: BLOCK_DEPLOY answers can I deploy, why not, what first, where is the rest', () => {
  it('renders remediation groups, Critical first, in a stable order', async () => {
    const { result } = await trivyGate(LARGE);
    const markdown = summaryOf(result);
    assert.match(markdown, /^## ⛔ Image gate: BLOCK_DEPLOY$/m);
    assert.match(markdown, /Scan integrity: trusted — the gate interpreted the Trivy report\. Scanned image `sha256:2{64}` \(debian 12\.11\)\./);
    assert.match(markdown, /^\*\*15\*\* blocking · \*\*45\*\* exception · \*\*122\*\* logged findings$/m);
    assert.match(markdown, /### ⛔ Blocking — fix these first \(8 remediation groups · 15 findings\)/);
    const order = groupLines(markdown).map((line) => {
      const [, severity, pkg, fixed] = /^- \*\*(\w+)\*\* · image package `([^`]+)` `[^`]+` → \*\*`([^`]+)`\*\*/.exec(line);
      return `${severity}:${pkg}:${fixed}`;
    });
    assert.deepEqual(order, [
      'Critical:libssl3:3.0.17-1~deb12u2',
      'Critical:openssl:3.0.17-1~deb12u2',
      'Critical:zlib1g:1:1.2.13.dfsg-1+deb12u1',
      'High:libxml2:2.9.14+dfsg-1.3~deb12u2',
      'High:perl-base:5.36.0-7+deb12u2',
      'High:setuptools:78.1.1',
      'High:libxml2:2.9.14+dfsg-1.3~deb12u3',
      'High:pip:25.0'
    ]);
    assert.equal(summaryOf(result), markdown, 'deterministic');
    assert.match(markdown, /🔧 Upgrade each package to the fixed version shown, or move to a base image that ships it, then rebuild the image\./);
    assert.match(markdown, /🔁 Reproduce locally: `trivy image --input application-image\.tar/);
  });

  it('groups same-package / same-remediation findings and lists their advisories beneath', async () => {
    const { result } = await trivyGate(LARGE);
    const libssl = groupLines(summaryOf(result)).find((line) => line.includes('`libssl3`'));
    assert.equal(
      libssl,
      '- **Critical** · image package `libssl3` `3.0.15-1~deb12u1` → **`3.0.17-1~deb12u2`** — Trivy lists this fixed version for 3 advisories (1 critical, 2 high): ' +
        '`CVE-2099-1001`, `CVE-2099-1002`, `CVE-2099-1003` · in `app:prepush (debian 12.11)`'
    );
  });

  it('never merges findings whose remediation evidence differs', () => {
    const findings = [
      vuln('CVE-A', 'libxml2', 'high', { fixed: '2.0.1' }),
      vuln('CVE-B', 'libxml2', 'high', { fixed: '2.0.2' }), // different fixed version
      vuln('CVE-C', 'libxml2', 'high', { installed: '0.9.0', fixed: '2.0.1' }), // different installed version
      vuln('CVE-D', 'libxml2', 'high', { target: 'Python', fixed: '2.0.1' }), // different target
      vuln('CVE-E', 'libxml2-dev', 'high', { fixed: '2.0.1' }), // different package, same advisory family
      vuln('CVE-F', 'libxml2', 'medium', { fixed: '2.0.1' }), // same remediation, but LOG — not a blocker
      { ...vuln('CVE-G', 'libxml2', 'high', { fixed: '2.0.1' }), installedVersion: undefined }, // no installed version
      { ...vuln('CVE-H', 'libxml2', 'high', { fixed: '2.0.1' }), fixedVersion: undefined }, // fix-available, no fixed version
      vuln('CVE-I', 'libxml2', 'critical', { fixed: '2.0.1' }) // same as CVE-A: the only legitimate merge
    ];
    const groups = groupImageFindings(findings, findings.map((_, index) => index));
    const members = groups.map((group) => group.advisories.join('+')).sort();
    assert.deepEqual(members, ['CVE-B', 'CVE-C', 'CVE-D', 'CVE-E', 'CVE-F', 'CVE-G', 'CVE-H', 'CVE-I+CVE-A'].sort());
    // Ungroupable findings stand alone and carry no invented package/fix evidence.
    assert.equal(groups.find((group) => group.advisories[0] === 'CVE-G').evidence, null);
    assert.equal(groups.find((group) => group.advisories[0] === 'CVE-H').evidence, null);
  });

  it('the live-shaped report keeps libssl3 and openssl, and the two libxml2 fixes, apart', async () => {
    const { result } = await trivyGate(LARGE);
    const lines = groupLines(summaryOf(result));
    assert.equal(lines.filter((line) => line.includes('image package `libxml2`')).length, 2);
    assert.equal(lines.filter((line) => line.includes('`CVE-2099-1001`')).length, 2, 'the same advisory on two packages is two remediations');
  });

  it('exceptions do not compete with blockers: one count line, no exception advisory in the summary', async () => {
    const { result } = await trivyGate(LARGE);
    const markdown = summaryOf(result);
    assert.match(
      markdown,
      /⚠️ \*\*45\*\* exception findings \(9 distinct advisories in 5 packages; 10 critical, 35 high\) have no fix available according to the scanner, so policy tracks them as EXCEPTIONs; they do not block deploy\. Listed in `image-gate-prepush-evidence\.md`\./
    );
    assert.doesNotMatch(markdown, /Tracked exceptions|CVE-2099-20\d\d/);
    assert.ok(markdown.indexOf('⚠️ **45**') > markdown.indexOf('### ⛔ Blocking'), 'after the blockers');
  });

  it('logged findings are a count only, with the full list pointed to', async () => {
    const { result } = await trivyGate(LARGE);
    const markdown = summaryOf(result);
    assert.match(markdown, /ℹ️ \*\*122\*\* logged findings \(70 distinct advisories; 82 medium, 40 low\) are informational \(LOG\) and do not block deploy\./);
    assert.doesNotMatch(markdown, /CVE-2099-3\d{3}|curl|<details|\| ℹ️ INFO \|/);
    assert.match(markdown, /Full evidence: `image-gate-prepush-evidence\.md` .* and `image-gate-prepush\.json` \(complete normalized findings\); raw scanner report: `trivy-image\.json`/);
  });

  it('is small for the live-shaped run and stays bounded at scale, with exact omissions', () => {
    const long = 'x'.repeat(500);
    const findings = [
      // 300 distinct blocking remediations with oversized evidence strings.
      ...Array.from({ length: 300 }, (_, i) => vuln(`CVE-${long}-${i}`, `${long}-${i}`, i % 3 === 0 ? 'critical' : 'high', { installed: long, fixed: `${long}.1`, target: long })),
      // One package with 40 advisories behind one upgrade.
      ...Array.from({ length: 40 }, (_, i) => vuln(`CVE-2099-${5000 + i}`, 'openssl', 'critical', { installed: '3.0.1', fixed: '3.0.2' })),
      ...Array.from({ length: 400 }, (_, i) => vuln(`CVE-2099-${7000 + i}`, `log-${i}`, i % 2 ? 'medium' : 'low', { fixed: null }))
    ];
    const markdown = summaryOf(blockDeploy(findings));
    assert.ok(markdown.length <= SUMMARY_LIMITS.maxCharacters, `summary is ${markdown.length} characters`);
    assert.ok(markdown.length < 20_000, `summary is ${markdown.length} characters`);
    const lines = groupLines(markdown);
    assert.equal(lines.length, IMAGE_SUMMARY_LIMITS.blockingGroups);
    // The 40-advisory openssl group is Critical and the largest, so it leads, with its list bounded.
    assert.match(lines[0], /image package `openssl` `3\.0\.1` → \*\*`3\.0\.2`\*\* — Trivy lists this fixed version for 40 advisories: .* and 34 more/);
    // Omission: 301 groups - 10 shown = 291 groups; findings 340 - 40 - 9 = 291.
    const omitted = /_(\d+) more blocking remediation groups not shown here \((\d+) findings: (\d+) critical, (\d+) high\)/.exec(markdown);
    assert.ok(omitted, 'the omission is stated');
    assert.deepEqual(omitted.slice(1).map(Number), [291, 291, 100 - 9, 200]);
    assert.match(markdown, /\*\*340\*\* blocking · \*\*0\*\* exception · \*\*400\*\* logged findings/);
  });

  it('a single blocker renders as one line with its title', () => {
    const one = { ...vuln('CVE-2099-0001', 'libssl3', 'critical', { installed: '3.5.7', fixed: '3.5.8', target: 'alpine' }), title: 'OpenSSL buffer overflow' };
    const markdown = summaryOf(blockDeploy([one]));
    assert.match(markdown, /### ⛔ Blocking — fix these first \(1 remediation group · 1 finding\)/);
    assert.deepEqual(groupLines(markdown), [
      '- **Critical** · image package `libssl3` `3.5.7` → **`3.5.8`** — Trivy lists this fixed version for 1 advisory: `CVE-2099-0001` — OpenSSL buffer overflow · in `alpine`'
    ]);
    assert.doesNotMatch(markdown, /not shown/);
  });

  it('image secrets are shown first and never displaced by vulnerability truncation', () => {
    const findings = [
      ...Array.from({ length: 50 }, (_, i) => vuln(`CVE-2099-${1000 + i}`, `pkg-${i}`, 'critical')),
      secret('aws-access-key-id', 'app/.aws/credentials'),
      secret('npm-token', 'app/.npmrc')
    ];
    const markdown = summaryOf(blockDeploy(findings));
    const secrets = section(markdown, '### 🔑 Secrets in image layers (2)');
    assert.match(secrets, /Potential secret in an image layer \(Trivy rule `aws-access-key-id`\)\*\* · in `app\/\.aws\/credentials`/);
    assert.match(secrets, /Potential secret in an image layer \(Trivy rule `npm-token`\)\*\* · in `app\/\.npmrc`/);
    assert.match(secrets, /Trivy does not verify secrets/);
    assert.ok(markdown.indexOf('### 🔑 Secrets') < markdown.indexOf('### ⛔ Blocking'));
    // The 50 vulnerabilities are truncated; the secrets are not part of that budget.
    assert.match(markdown, /### ⛔ Blocking — fix these first \(50 remediation groups · 50 findings\)/);
    assert.match(markdown, /_40 more blocking remediation groups not shown here \(40 findings: 40 critical\)/);
    const slack = JSON.stringify(renderSlack(buildReport({ gate: blockDeploy(findings) })));
    assert.ok(slack.indexOf('aws-access-key-id') < slack.indexOf('pkg-0'), 'Slack lists secrets before vulnerabilities');
    assert.match(slack, /and 47 more/);
  });

  it('an integrity failure is visible in full, with no vulnerability section', async () => {
    const { result } = await trivyGate(join(FIXTURES, 'trivy-eosl.json'));
    const markdown = summaryOf(result);
    assert.match(markdown, /^## ⛔ Image gate: BLOCK_DEPLOY — scan untrusted$/m);
    assert.match(markdown, /### 🚨 Scan integrity failures/);
    assert.match(markdown, /end-of-life \(EOSL\)/);
    assert.match(markdown, /\*\*Security state: UNKNOWN\*\*/);
    assert.doesNotMatch(markdown, /### ⛔ Blocking|Scan integrity: trusted/);
  });

  it('findings without package evidence (ECR basic) stand alone, with their remediation stated once', async () => {
    const { result } = await withTempDir(async (directory) =>
      ({ result: await runImageGate({ policy: POLICY, report: join(FIXTURES, 'critical.json'), output: join(directory, 'g.json') }) }));
    const markdown = summaryOf(result, {});
    assert.match(markdown, /- \*\*Critical\*\* · Critical-severity finding CVE-2099-DEMO in image \(ECR basic scanning\)/);
    assert.equal((markdown.match(/ECR basic scanning does not report which package is affected/g) ?? []).length, 1);
    assert.doesNotMatch(markdown, /image package/);
  });
});

// ---- 11: DEPLOY-WITH-EXCEPTIONS and DEPLOY --------------------------------------------

describe('image summary: non-blocking verdicts', () => {
  async function exceptionsOnly() {
    const raw = await rawLarge();
    for (const result of raw.Results) {
      result.Vulnerabilities = result.Vulnerabilities.filter((v) => !(v.FixedVersion && ['CRITICAL', 'HIGH'].includes(v.Severity)));
    }
    return (await trivyGate(raw)).result;
  }

  it('DEPLOY-WITH-EXCEPTIONS makes the exceptions the main section, bounded and grouped', async () => {
    const result = await exceptionsOnly();
    assert.equal(result.verdict, 'DEPLOY-WITH-EXCEPTIONS');
    assert.deepEqual(result.summary, { blockDeploy: 0, exception: 45, log: 122 });
    const markdown = summaryOf(result);
    assert.match(markdown, /^## ⚠️ Image gate: DEPLOY-WITH-EXCEPTIONS$/m);
    const exceptions = section(markdown, '### ⚠️ Tracked exceptions — no fix available (5 groups · 45 findings)');
    assert.ok(exceptions, 'the exception section is present');
    const lines = groupLines(exceptions);
    assert.equal(lines.length, 5);
    assert.match(lines[0], /^- \*\*Critical\*\* · image package `libc-bin` `2\.36-9\+deb12u10` — no fixed version reported by Trivy · 9 advisories \(2 critical, 7 high\): `CVE-2099-2001`, .* and 3 more · in `app:prepush \(debian 12\.11\)`$/);
    assert.match(exceptions, /No fix is available according to the scanner data, so policy records these Critical\/High findings as tracked EXCEPTIONs/);
    assert.doesNotMatch(markdown, /### ⛔ Blocking|🔧 Upgrade/);
    assert.match(markdown, /ℹ️ \*\*122\*\* logged findings/);
    assert.doesNotMatch(markdown, /CVE-2099-3\d{3}/);
  });

  it('exception groups are bounded with an exact omission', () => {
    const findings = Array.from({ length: 23 }, (_, i) => vuln(`CVE-2099-${4000 + i}`, `lib-${String(i).padStart(2, '0')}`, i < 3 ? 'critical' : 'high', { fixed: null }));
    const markdown = summaryOf({ ...blockDeploy(findings), verdict: 'DEPLOY-WITH-EXCEPTIONS' });
    assert.equal(groupLines(markdown).length, IMAGE_SUMMARY_LIMITS.exceptionGroups);
    assert.match(markdown, /_13 more exception groups not shown here \(13 findings: 13 high\)/);
  });

  it('DEPLOY is a concise success with informational counts', async () => {
    const raw = await rawLarge();
    for (const result of raw.Results) {
      result.Vulnerabilities = result.Vulnerabilities.filter((v) => ['MEDIUM', 'LOW'].includes(v.Severity));
    }
    const { result } = await trivyGate(raw);
    assert.equal(result.verdict, 'DEPLOY');
    const markdown = summaryOf(result);
    assert.match(markdown, /^## ✅ Image gate: DEPLOY$/m);
    assert.match(markdown, /ℹ️ \*\*122\*\* logged findings/);
    assert.equal(groupLines(markdown).length, 0);
    assert.ok(markdown.length < 2_000, `summary is ${markdown.length} characters`);
  });
});

// ---- 12: full evidence ------------------------------------------------------------------

describe('image evidence document: complete despite the bounded summary', () => {
  it('lists every group with every advisory, and every finding card, LOG included', async () => {
    const { result } = await trivyGate(LARGE);
    const evidence = renderEvidenceMarkdown(buildReport({ gate: result, context: CONTEXT }));
    assert.match(evidence, /^# Image gate evidence: BLOCK_DEPLOY$/m);
    assert.match(evidence, /## ⛔ Blocking remediation groups \(8 groups\)/);
    assert.match(evidence, /## ⚠️ Exception groups — no fix available \(5 groups\)/);
    assert.match(evidence, /## ℹ️ Logged groups \(4 groups\)/);
    assert.doesNotMatch(evidence, / and \d+ more/, 'no advisory list is truncated in the evidence');
    for (const finding of result.findings) {
      assert.ok(evidence.includes(`${finding.package} — ${finding.id}`), `card for ${finding.package} ${finding.id}`);
    }
    // Every LOG advisory is present, in its group and its card.
    for (let i = 1; i <= 70; i += 1) {
      assert.ok(evidence.includes(`CVE-2099-3${String(i).padStart(3, '0')}`));
    }
    assert.match(evidence, /Trivy reports a fix in 7\.88\.1-10\+deb12u9/);
  });

  it('the notifier writes it next to the gate result, summary bounded and evidence complete', async () => {
    const { dispatch } = await import('../security/scripts/notify.mjs');
    const { result } = await trivyGate(LARGE);
    const written = [];
    const appended = [];
    await dispatch({
      gate: result,
      context: CONTEXT,
      evidencePath: 'reports/image-gate-prepush-evidence.md',
      summaryPath: 'summary.md',
      writeImpl: async (path, data) => written.push({ path, data }),
      appendImpl: async (_path, data) => appended.push(data),
      fetchImpl: async () => ({ ok: true, json: async () => [] }),
      logger: { log: () => {}, error: () => {} }
    });
    assert.equal(written[0].path, 'reports/image-gate-prepush-evidence.md');
    assert.ok(written[0].data.length > 5 * appended[0].length, 'the evidence is the long form');
    assert.doesNotMatch(appended[0], /CVE-2099-3\d{3}/);
    assert.match(written[0].data, /CVE-2099-3070/);
  });
});

// ---- 13: source security is untouched ---------------------------------------------------

describe('source-security presentation is not affected', () => {
  it('a source verdict keeps the triage table, the Security gate header and no image view', () => {
    const findings = [vuln('CVE-2099-0001', 'libssl3', 'critical', { action: 'BLOCK' }), vuln('CVE-2099-0002', 'zlib', 'medium')];
    const report = buildReport({ gate: { verdict: 'BLOCK', findings } });
    assert.equal(report.image, null);
    const markdown = renderMarkdown(report);
    assert.match(markdown, /^## ⛔ Security gate: BLOCK$/m);
    assert.match(markdown, /^\| ⛔ BLOCK \| Critical \| `libssl3` \|/m);
    assert.match(markdown, /^\| ℹ️ INFO \| Medium \| `zlib` \|/m);
    assert.doesNotMatch(markdown, /Image gate|remediation group/);
    assert.match(renderEvidenceMarkdown(report), /^# Security gate evidence: BLOCK$/m);
    assert.equal(renderSlack(report).text, '⛔ Security gate: BLOCK');
  });
});
