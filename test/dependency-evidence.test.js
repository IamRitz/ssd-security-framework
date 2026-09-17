// Normalized dependency evidence: relationship and version resolution, each with
// provenance, kept apart from the policy record.
//
// Regression (live run IamRitz/ssd-scratch-consumer 35214928623, requirements.txt
// `requests==2.33.0`): pip-audit listed idna 3.19 with no advisory while
// OSV-Scanner matched CVE-2026-45409 against idna 3.9.0. The feedback said
// "`idna` 3.9.0 — upgrade idna to 3.15" as though 3.9.0 were established.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { correlateFindings, correlationRecord } from '../security/scripts/correlate-findings.mjs';
import {
  collectDependencyEvidence,
  collectDependencyEvidenceSafely,
  issueDependencyEvidence,
  parseRequirements,
  versionKey
} from '../security/scripts/dependency-evidence.mjs';
import { buildReport, renderMarkdown } from '../security/scripts/format-findings.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const LIVE = join(FIXTURES, 'live-requests-2-33-0');
const LIVE_OLD = join(FIXTURES, 'live-python-source-only');
const POLICY = resolve('security/policy.yaml');

async function withTempDir(work) {
  const directory = await mkdtemp(join(tmpdir(), 'dependency-evidence-'));
  try {
    return await work(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

// Runs the real gate against a temporary consumer checkout. `requirements` is
// the checkout's requirements.txt (null: none); reports are paths or objects.
async function gate({ requirements = null, pipAudit = null, osv = join(CLEAN, 'osv-scanner.json'), repoSetup } = {}) {
  return withTempDir(async (directory) => {
    const repoDir = join(directory, 'repo');
    await mkdir(repoDir);
    if (requirements !== null) {
      await writeFile(join(repoDir, 'requirements.txt'), requirements);
    }
    if (repoSetup) {
      await repoSetup(repoDir);
    }
    const reportPath = async (name, value) => {
      if (value === null || typeof value === 'string') return value;
      const path = join(directory, name);
      await writeFile(path, JSON.stringify(value));
      return path;
    };
    return runSecurityGate({
      policy: POLICY,
      repoDir,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      npmAudit: join(directory, 'absent-npm-audit.json'),
      pipAudit: (await reportPath('pip-audit.json', pipAudit)) ?? join(directory, 'absent-pip-audit.json'),
      osv: await reportPath('osv-scanner.json', osv),
      semgrep: join(CLEAN, 'semgrep.json'),
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      output: join(directory, 'security-gate.json'),
      exceptions: join(directory, 'gate-exceptions.json')
    });
  });
}

const liveGate = (overrides = {}) =>
  gate({ requirements: 'requests==2.33.0\n', pipAudit: join(LIVE, 'pip-audit.json'), osv: join(LIVE, 'osv-scanner.json'), ...overrides });

const markdownOf = (result) => renderMarkdown(buildReport({ gate: result, mode: 'enforce' }));

// The policy record: everything a decision is made from or recorded as.
const policyView = (result) => ({
  verdict: result.verdict,
  summary: result.summary,
  integrity: result.integrity,
  findings: result.findings,
  breakGlass: result.breakGlass,
  issues: result.correlation.summary
});

// An OSV-Scanner report for one PyPI package. The advisory has a CVSS v3 vector
// that the framework maps to medium (LOG).
function osvReport(pkg, version, { path = '/repo/requirements.txt', ids = ['PYSEC-X-1', 'GHSA-xxxx-yyyy-zzzz'], cve = 'CVE-2099-1', fixed = '3.15' } = {}) {
  return {
    results: [
      {
        source: { path, type: 'unknown' },
        packages: [
          {
            package: { name: pkg, version, ecosystem: 'PyPI' },
            vulnerabilities: ids.map((id) => ({
              id,
              aliases: [cve, ...ids.filter((other) => other !== id)],
              severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }],
              affected: [{ package: { name: pkg, ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }] }]
            }))
          }
        ]
      }
    ]
  };
}

const pipAuditReport = (...dependencies) => ({
  dependencies: dependencies.map(([name, version, vulns = []]) => ({ name, version, vulns })),
  fixes: []
});

describe('live regression: requests==2.33.0, pip-audit idna 3.19 vs OSV-Scanner idna 3.9.0', () => {
  it('the fixture is the unmodified live capture', async () => {
    const pip = JSON.parse(await readFile(join(LIVE, 'pip-audit.json'), 'utf8'));
    const osv = JSON.parse(await readFile(join(LIVE, 'osv-scanner.json'), 'utf8'));
    assert.deepEqual(pip.dependencies.find((d) => d.name === 'idna'), { name: 'idna', version: '3.19', vulns: [] });
    assert.equal(osv.results.length, 1);
    assert.deepEqual(osv.results[0].packages[0].package, { name: 'idna', version: '3.9.0', ecosystem: 'PyPI' });
  });

  it('policy is unchanged: PASS, 2 raw LOG records, 1 correlated issue, same aliases', async () => {
    const result = await liveGate();
    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(result.summary, { block: 0, exception: 0, log: 2 });
    assert.deepEqual(
      result.findings.map((f) => `${f.source}:${f.id}:${f.action}:${f.installedVersion}`),
      ['osv-scanner:PYSEC-2026-215:LOG:3.9.0', 'osv-scanner:GHSA-65pc-fj4g-8rjx:LOG:3.9.0']
    );
    assert.deepEqual(result.correlation.summary, { issues: 1, rawFindings: 2, block: 0, exception: 0, log: 1, integrity: 0 });
    const [issue] = result.correlation.issues;
    assert.deepEqual(issue.findings, [0, 1]);
    assert.deepEqual(issue.advisoryIds, ['CVE-2026-45409', 'GHSA-65pc-fj4g-8rjx', 'PYSEC-2026-215']);
    assert.deepEqual(issue.installedVersions, ['3.9.0'], 'existing field keeps its meaning');
  });

  it('marks resolution conflicting, preserves both observations, and leaves the relationship unknown', async () => {
    const { evidence } = (await liveGate()).correlation.issues[0];
    assert.equal(evidence.resolution.status, 'conflicting');
    assert.equal(evidence.resolution.confidence, 'conflicting');
    assert.equal(evidence.resolution.version, null, 'no version is chosen when evidence conflicts');
    assert.deepEqual(evidence.resolution.observations, [
      { scanner: 'pip-audit', version: '3.19', provenance: 'scanner-resolved', source: 'requirements.txt', advisoryReported: false },
      { scanner: 'osv-scanner', version: '3.9.0', provenance: 'scanner-inferred', source: 'requirements.txt', advisoryReported: true }
    ]);
    assert.equal(evidence.relationship.value, 'unknown');
    assert.equal(evidence.relationship.basis, 'none');
    assert.deepEqual(evidence.relationship.dependencyPaths, []);
    assert.deepEqual(evidence.relationship.manifestsChecked, ['requirements.txt']);
  });

  it('records the run-level evidence: every package pip-audit listed, and the parsed manifest', async () => {
    const { dependencyEvidence } = await liveGate();
    assert.equal(dependencyEvidence.schemaVersion, 1);
    assert.deepEqual(
      dependencyEvidence.observations.map((o) => `${o.scanner}:${o.package}@${o.version}`),
      [
        'pip-audit:requests@2.33.0',
        'pip-audit:charset-normalizer@3.5.1',
        'pip-audit:idna@3.19',
        'pip-audit:urllib3@2.8.0',
        'pip-audit:certifi@2026.7.22',
        'osv-scanner:idna@3.9.0'
      ]
    );
    assert.deepEqual(dependencyEvidence.manifests, [
      {
        path: 'requirements.txt',
        ecosystem: 'PyPI',
        format: 'requirements.txt',
        status: 'parsed',
        declarations: [{ package: 'requests', requirement: 'requests==2.33.0', exactVersion: '2.33.0', line: 1 }]
      }
    ]);
  });

  it('developer feedback reports the conflict and never presents 3.9.0 as the version in use', async () => {
    const markdown = markdownOf(await liveGate());
    assert.match(markdown, /\*\*`idna` — CVE-2026-45409 \(effective version disputed: 3\.19 vs 3\.9\.0\)\*\*/);
    assert.match(markdown, /Resolution conflict — the evidence disagrees on the effective version of `idna`/);
    assert.match(markdown, /pip-audit resolved `idna` 3\.19 from `requirements\.txt` \(scanner-resolved; reported no advisory for this issue\)/);
    assert.match(markdown, /OSV-Scanner reported `idna` 3\.9\.0 from `requirements\.txt` \(scanner-inferred; reported this advisory\)/);
    assert.match(markdown, /The scanners disagree on the effective package version\. Treat this finding as a dependency-resolution discrepancy/);
    assert.doesNotMatch(markdown, /`idna` 3\.9\.0 —/);
    assert.doesNotMatch(markdown, /\*\*`idna` 3\.9\.0/);
  });

  it('developer feedback does not tell the user to pin idna directly', async () => {
    const markdown = markdownOf(await liveGate());
    assert.doesNotMatch(markdown, /pip install/);
    assert.doesNotMatch(markdown, /idna==3\.15/);
    assert.doesNotMatch(markdown, /Upgrade `idna`/);
    assert.match(markdown, /Do not pin `idna` from this report/);
    assert.match(markdown, /First establish the version actually resolved/);
    assert.match(markdown, /remediate through the dependency or constraint that brings it in/);
  });

  it('relationship is unknown and never inferred transitive from absence in requirements.txt', async () => {
    const markdown = markdownOf(await liveGate());
    assert.match(
      markdown,
      /Dependency relationship: unknown — the scanners identified `idna` while analyzing `requirements\.txt`, but the available reports do not prove which direct dependency introduced it/
    );
    assert.match(markdown, /`idna` is not declared in `requirements\.txt`; that alone does not prove it is transitive/);
    assert.doesNotMatch(markdown, /relationship: transitive/);
    assert.doesNotMatch(markdown, /requests -> idna/);
  });
});

describe('A. a direct dependency is proven by an explicit declaration', () => {
  it('requirements.txt declaring idna==3.9.0 makes idna direct, pointing at the declaration', async () => {
    const result = await gate({
      requirements: '# pinned\nidna==3.9.0\n',
      pipAudit: pipAuditReport(['idna', '3.9.0']),
      osv: join(LIVE, 'osv-scanner.json')
    });
    const { evidence } = result.correlation.issues[0];
    assert.equal(evidence.relationship.value, 'direct');
    assert.equal(evidence.relationship.basis, 'manifest-declaration');
    assert.deepEqual(evidence.relationship.declarations, [
      { manifest: 'requirements.txt', requirement: 'idna==3.9.0', exactVersion: '3.9.0', line: 2 }
    ]);
    assert.equal(evidence.resolution.status, 'consistent');
    assert.equal(evidence.resolution.version, '3.9.0');
    assert.equal(evidence.resolution.confidence, 'high', 'an exact direct declaration is the strongest evidence class');

    const markdown = markdownOf(result);
    assert.match(markdown, /Dependency relationship: direct — declared in `requirements\.txt` \(`idna==3\.9\.0`\)/);
    assert.match(markdown, /Version: `idna` 3\.9\.0 — consistent across the evidence \(confidence: high\)/);
    // Proven direct + agreeing version + one fixed version: upgrading the
    // declaration is the honest instruction.
    assert.match(markdown, /Upgrade the direct declaration in `requirements\.txt` \(`idna==3\.9\.0`\) to a fixed version — e\.g\. `pip install 'idna==3\.15'`/);
    assert.match(markdown, /\*\*`idna` 3\.9\.0 — CVE-2026-45409\*\*/, 'an agreed version stays in the headline');
  });

  it('a declaration through extras, markers and hashes is still a declaration; a range has no exact version', () => {
    const { declarations, unparsed } = parseRequirements(
      [
        'Requests[socks] == 2.33.0 ; python_version >= "3.9"  # comment',
        'idna>=3.7,<4',
        'urllib3==2.8.0 \\',
        '    --hash=sha256:abc',
        'flask==2.*',
        '-r other.txt',
        '-e ./local',
        'https://example.com/pkg.whl',
        ''
      ].join('\n')
    );
    assert.deepEqual(declarations, [
      { package: 'Requests', requirement: 'Requests[socks]==2.33.0', exactVersion: '2.33.0', line: 1 },
      { package: 'idna', requirement: 'idna>=3.7,<4', exactVersion: null, line: 2 },
      { package: 'urllib3', requirement: 'urllib3==2.8.0', exactVersion: '2.8.0', line: 3 },
      { package: 'flask', requirement: 'flask==2.*', exactVersion: null, line: 5 }
    ]);
    assert.deepEqual(
      unparsed.map((entry) => entry.line),
      [6, 7, 8],
      'includes, editables and URLs are listed, never followed'
    );
  });

  it('a declaration in a manifest the scanners did not analyze for this package proves nothing', async () => {
    const record = await withTempDir(async (repoDir) => {
      await mkdir(join(repoDir, 'other'));
      await writeFile(join(repoDir, 'other', 'requirements.txt'), 'idna==3.9.0\n');
      await writeFile(join(repoDir, 'requirements.txt'), 'requests==2.33.0\n');
      return collectDependencyEvidence({
        repoDir,
        osv: {
          results: [
            { source: { path: '/repo/requirements.txt' }, packages: [{ package: { name: 'idna', version: '3.9.0', ecosystem: 'PyPI' }, vulnerabilities: [] }] },
            { source: { path: '/repo/other/requirements.txt' }, packages: [{ package: { name: 'flask', version: '2.0.0', ecosystem: 'PyPI' }, vulnerabilities: [] }] }
          ]
        }
      });
    });
    const evidence = issueDependencyEvidence({ package: 'idna', ecosystem: 'PyPI', advisoryIds: [] }, [], record);
    assert.equal(evidence.relationship.value, 'unknown');
    assert.deepEqual(evidence.relationship.manifestsChecked, ['requirements.txt']);
  });
});

// A run-level record as an adapter that DOES carry dependency paths would write
// it. No scanner the framework runs today reports one (docs/evidence-model.md).
function recordWithPath(paths) {
  return {
    schemaVersion: 1,
    manifests: [{ path: 'requirements.txt', ecosystem: 'PyPI', format: 'requirements.txt', status: 'parsed', declarations: [{ package: 'requests', requirement: 'requests==2.33.0', exactVersion: '2.33.0', line: 1 }] }],
    observations: [
      { scanner: 'osv-scanner', ecosystem: 'PyPI', package: 'idna', version: '3.9.0', provenance: 'lockfile-resolved', source: 'requirements.txt', advisoryIds: ['PYSEC-1', 'CVE-1'], dependencyPaths: paths }
    ]
  };
}

const idnaFindings = [
  { source: 'osv-scanner', id: 'PYSEC-1', aliases: ['CVE-1'], package: 'idna', ecosystem: 'PyPI', installedVersion: '3.9.0', severity: 'high', severitySource: 'framework-default', policyRule: 'dependencies.high_with_fix', action: 'BLOCK', fixAvailable: true, fixVersions: ['3.15'] }
];

describe('B. a transitive dependency needs explicit path evidence', () => {
  it('an explicit requests -> idna path makes idna transitive and is rendered', () => {
    const record = recordWithPath([['requests', 'idna']]);
    const [issue] = correlateFindings(idnaFindings, record);
    assert.equal(issue.evidence.relationship.value, 'transitive');
    assert.equal(issue.evidence.relationship.basis, 'scanner-dependency-path');
    assert.deepEqual(issue.evidence.relationship.dependencyPaths, [{ path: ['requests', 'idna'], scanner: 'osv-scanner', source: 'requirements.txt' }]);

    const markdown = renderMarkdown(buildReport({ gate: { verdict: 'BLOCK', findings: idnaFindings, dependencyEvidence: record } }));
    assert.match(markdown, /Dependency relationship: transitive — dependency path: `requests -> idna` \(from OSV-Scanner\)/);
    assert.match(markdown, /Prefer updating the parent dependency `requests`, or your resolution constraints, so the resolver selects a fixed `idna`/);
    assert.doesNotMatch(markdown, /pip install/, 'no direct pin is recommended for a transitive package');
  });

  it('a path that does not end at the package is not evidence of ancestry', () => {
    const [issue] = correlateFindings(idnaFindings, recordWithPath([['requests', 'urllib3'], ['idna']]));
    assert.equal(issue.evidence.relationship.value, 'unknown');
    assert.deepEqual(issue.evidence.relationship.dependencyPaths, []);
  });

  it('a package both declared and reached by a path is direct, and keeps the path', () => {
    const record = recordWithPath([['requests', 'idna']]);
    record.manifests[0].declarations.push({ package: 'IDNA', requirement: 'IDNA==3.9.0', exactVersion: '3.9.0', line: 2 });
    const [issue] = correlateFindings(idnaFindings, record);
    assert.equal(issue.evidence.relationship.value, 'direct');
    assert.equal(issue.evidence.relationship.dependencyPaths.length, 1);
  });
});

describe('C. unknown relationship', () => {
  it('a package the scanner reports with no parent or path is unknown, even when absent from the manifest', () => {
    const [issue] = correlateFindings(idnaFindings, recordWithPath(undefined));
    assert.equal(issue.evidence.relationship.value, 'unknown');
    assert.deepEqual(issue.evidence.relationship.manifestsChecked, ['requirements.txt']);
    const markdown = renderMarkdown(buildReport({ gate: { verdict: 'BLOCK', findings: idnaFindings, dependencyEvidence: recordWithPath(undefined) } }));
    assert.match(markdown, /Dependency relationship: unknown — OSV-Scanner identified `idna` while analyzing `requirements\.txt`/);
    assert.match(markdown, /no direct pin is suggested/);
    assert.doesNotMatch(markdown, /pip install/);
    assert.doesNotMatch(markdown, /transitive dependency\./);
  });

  it('a gate result written before dependencyEvidence existed falls back to the findings and claims nothing', () => {
    const [issue] = correlateFindings(idnaFindings);
    assert.equal(issue.evidence.relationship.value, 'unknown');
    assert.deepEqual(issue.evidence.resolution.observations, [
      { scanner: 'osv-scanner', version: '3.9.0', provenance: 'unknown', source: null, advisoryReported: true }
    ]);
    assert.equal(issue.evidence.resolution.confidence, 'low');
    const markdown = renderMarkdown(buildReport({ gate: { verdict: 'BLOCK', findings: idnaFindings } }));
    assert.match(markdown, /Dependency relationship: unknown — the available reports do not record where `idna` is declared/);
  });

  it('evidence that cannot be collected is recorded as unavailable, and issues fall back to the findings', async () => {
    const broken = {
      get results() {
        throw new Error('boom');
      }
    };
    const record = await collectDependencyEvidenceSafely({ osv: broken });
    assert.match(record.unavailable, /boom/);
    const [issue] = correlateFindings(idnaFindings, record);
    assert.equal(issue.evidence.resolution.observations.length, 1);
    assert.match(issue.evidence.unavailable, /boom/);
  });
});

describe('D. consistent scanner resolution', () => {
  it('pip-audit and OSV-Scanner agreeing on idna 3.19 is consistent, confidence from the strongest class', async () => {
    const result = await gate({
      requirements: 'requests==2.33.0\n',
      pipAudit: pipAuditReport(['requests', '2.33.0'], ['idna', '3.19']),
      osv: osvReport('idna', '3.19')
    });
    const { evidence } = result.correlation.issues[0];
    assert.equal(evidence.resolution.status, 'consistent');
    assert.equal(evidence.resolution.version, '3.19');
    assert.equal(evidence.resolution.confidence, 'medium', 'scanner-resolved from an unlocked manifest is medium, not high');
    assert.equal(evidence.resolution.observations.length, 2);
    const markdown = markdownOf(result);
    assert.doesNotMatch(markdown, /Resolution conflict/);
    assert.match(markdown, /Version: `idna` 3\.19 — consistent across the evidence \(confidence: medium\)/);
  });

  it('PEP 440-equal spellings agree; different releases do not', () => {
    assert.equal(versionKey('PyPI', '3.9'), versionKey('PyPI', '3.9.0'));
    assert.equal(versionKey('PyPI', 'V3.09'), versionKey('PyPI', '3.9'));
    assert.notEqual(versionKey('PyPI', '3.19'), versionKey('PyPI', '3.9.0'));
    assert.notEqual(versionKey('npm', '1.0'), versionKey('npm', '1.0.0'), 'no normalization is guessed outside PyPI');
  });

  it('confidence is deterministic from provenance: a lone inferred version is low, a lockfile is high', async () => {
    const inferred = await withTempDir((repoDir) => collectDependencyEvidence({ repoDir, osv: osvReport('idna', '3.19') }));
    const locked = await withTempDir((repoDir) => collectDependencyEvidence({ repoDir, osv: osvReport('idna', '3.19', { path: '/repo/poetry.lock' }) }));
    const issue = { package: 'idna', ecosystem: 'PyPI', advisoryIds: ['CVE-2099-1'] };
    assert.equal(issueDependencyEvidence(issue, [], inferred).resolution.confidence, 'low');
    assert.equal(issueDependencyEvidence(issue, [], locked).resolution.observations[0].provenance, 'lockfile-resolved');
    assert.equal(issueDependencyEvidence(issue, [], locked).resolution.confidence, 'high');
  });

  it('a scanner source outside the checkout is shown but never read', async () => {
    const record = await withTempDir((repoDir) =>
      collectDependencyEvidence({ repoDir, osv: osvReport('idna', '3.19', { path: '/etc/requirements.txt' }) })
    );
    assert.equal(record.observations[0].source, '/etc/requirements.txt');
    assert.deepEqual(record.manifests, []);
  });
});

describe('E. conflicting scanner resolution', () => {
  it('different effective versions are conflicting and both are preserved', () => {
    const record = {
      schemaVersion: 1,
      manifests: [],
      observations: [
        { scanner: 'pip-audit', ecosystem: 'PyPI', package: 'idna', version: '3.19', provenance: 'scanner-resolved', source: 'requirements.txt', advisoryIds: [] },
        { scanner: 'osv-scanner', ecosystem: 'PyPI', package: 'IDNA', version: '3.9.0', provenance: 'lockfile-resolved', source: 'poetry.lock', advisoryIds: ['PYSEC-1'] }
      ]
    };
    const [issue] = correlateFindings(idnaFindings, record);
    assert.equal(issue.evidence.resolution.status, 'conflicting');
    assert.equal(issue.evidence.resolution.confidence, 'conflicting', 'a lockfile does not silently win a conflict');
    assert.deepEqual(issue.evidence.resolution.versions, ['3.19', '3.9.0']);
    assert.deepEqual(
      issue.evidence.resolution.observations.map((o) => `${o.scanner}@${o.version}`),
      ['pip-audit@3.19', 'osv-scanner@3.9.0']
    );
    const markdown = renderMarkdown(buildReport({ gate: { verdict: 'BLOCK', findings: idnaFindings, dependencyEvidence: record } }));
    // A single-record issue keeps its own card shape, minus the disputed version.
    assert.match(markdown, /High-severity advisory PYSEC-1 in PyPI dependency `idna` \(effective version disputed: 3\.19 vs 3\.9\.0\)/);
    assert.match(markdown, /OSV advisory PYSEC-1 \(aliases: CVE-1\) affects `idna` \(reported at 3\.9\.0; disputed\)/);
    assert.match(markdown, /pip-audit resolved `idna` 3\.19 from `requirements\.txt`/);
    assert.match(markdown, /OSV-Scanner read `idna` 3\.9\.0 from `poetry\.lock`/);
    assert.doesNotMatch(markdown, /pip install/);
    assert.equal(buildReport({ gate: { verdict: 'BLOCK', findings: idnaFindings, dependencyEvidence: record } }).issues[0].card.fixedVersion, null);
  });
});

describe('F. a direct declaration that disagrees with a scanner', () => {
  it('stays direct, shows declaration vs scanner, and does not let either replace the other', async () => {
    const result = await gate({
      requirements: 'idna==3.19\n',
      pipAudit: pipAuditReport(),
      osv: join(LIVE, 'osv-scanner.json')
    });
    const { evidence } = result.correlation.issues[0];
    assert.equal(evidence.relationship.value, 'direct');
    assert.equal(evidence.relationship.declarations[0].requirement, 'idna==3.19');
    assert.equal(evidence.resolution.status, 'conflicting');
    assert.deepEqual(evidence.resolution.observations, [
      { scanner: null, version: '3.19', provenance: 'manifest-declared', source: 'requirements.txt', advisoryReported: null },
      { scanner: 'osv-scanner', version: '3.9.0', provenance: 'scanner-inferred', source: 'requirements.txt', advisoryReported: true }
    ]);

    const markdown = markdownOf(result);
    assert.match(markdown, /Dependency relationship: direct — declared in `requirements\.txt` \(`idna==3\.19`\)/);
    assert.match(markdown, /`requirements\.txt` declares `idna` 3\.19 \(manifest-declared\)/);
    assert.match(markdown, /OSV-Scanner reported `idna` 3\.9\.0 from `requirements\.txt`/);
    assert.match(markdown, /The manifest declaration and the scanner results disagree on the effective package version/);
    assert.match(markdown, /remediate through its declaration in `requirements\.txt`/);
    assert.doesNotMatch(markdown, /pip install/);
  });
});

describe('G. alias correlation is unchanged by evidence', () => {
  it('PYSEC / GHSA / CVE records still collapse into one issue, every raw record preserved', async () => {
    const result = await gate({
      requirements: 'requests==2.32.5\n',
      pipAudit: join(LIVE_OLD, 'pip-audit.json'),
      osv: join(LIVE_OLD, 'osv-scanner.json')
    });
    assert.equal(result.findings.length, 5);
    const withoutEvidence = correlationRecord(result.findings);
    const strip = (issues) => issues.map(({ evidence, ...rest }) => rest);
    assert.deepEqual(strip(result.correlation.issues), strip(withoutEvidence.issues));
    assert.deepEqual(result.correlation.summary, withoutEvidence.summary);

    const [requests, idna] = result.correlation.issues;
    assert.deepEqual(requests.advisoryIds, ['CVE-2026-25645', 'GHSA-gc5v-m9x4-r6x2', 'PYSEC-2026-2275']);
    assert.deepEqual(requests.findings, [0, 1, 2]);
    assert.equal(requests.evidence.relationship.value, 'direct');
    assert.equal(requests.evidence.resolution.status, 'consistent');
    assert.equal(requests.evidence.resolution.confidence, 'high');
    assert.equal(idna.evidence.resolution.status, 'conflicting', 'the same discrepancy existed in the earlier live run');

    const markdown = markdownOf(result);
    assert.match(markdown, /\*\*`requests` 2\.32\.5 — CVE-2026-25645\*\*/);
    assert.match(markdown, /Upgrade the direct declaration in `requirements\.txt` \(`requests==2\.32\.5`\) to a fixed version — e\.g\. `pip install 'requests==2\.33\.0'`/);
  });
});

describe('H. evidence never changes policy', () => {
  it('BLOCK / EXCEPTION / LOG counts, verdict, integrity and break-glass match with and without evidence', async () => {
    const osv = osvReport('idna', '3.9.0');
    // pip-audit BLOCKs the same advisory at a version OSV-Scanner disagrees with:
    // the conflict is shown, the BLOCK stands.
    const pipAudit = pipAuditReport(['idna', '3.19', [{ id: 'PYSEC-X-1', fix_versions: ['3.15'], aliases: ['CVE-2099-1'] }]]);
    const withEvidence = await gate({ requirements: 'requests==2.33.0\n', pipAudit, osv });
    const conflicting = await gate({ requirements: 'idna==3.2\n', pipAudit, osv });
    const unreadableManifest = await gate({
      requirements: null,
      pipAudit,
      osv,
      repoSetup: async (repoDir) => mkdir(join(repoDir, 'requirements.txt'))
    });

    assert.equal(withEvidence.verdict, 'BLOCK');
    assert.deepEqual(withEvidence.summary, { block: 1, exception: 0, log: 2 });
    assert.equal(withEvidence.breakGlass.eligible, true);
    assert.equal(withEvidence.correlation.issues[0].evidence.resolution.status, 'conflicting');
    assert.equal(conflicting.correlation.issues[0].evidence.relationship.value, 'direct');
    assert.equal(unreadableManifest.dependencyEvidence.manifests[0].status, 'unreadable');
    assert.equal(unreadableManifest.integrity.trusted, true, 'an unreadable manifest is evidence-unavailable, not an integrity failure');

    assert.deepEqual(policyView(conflicting), policyView(withEvidence));
    assert.deepEqual(policyView(unreadableManifest), policyView(withEvidence));
  });

  it('the live PASS stays PASS whether or not the manifest is present', async () => {
    const withManifest = await liveGate();
    const withoutManifest = await gate({ pipAudit: join(LIVE, 'pip-audit.json'), osv: join(LIVE, 'osv-scanner.json') });
    assert.deepEqual(policyView(withoutManifest), policyView(withManifest));
  });

  it('formatter counts are computed from the raw findings, not from evidence', async () => {
    const result = await liveGate();
    const report = buildReport({ gate: result });
    assert.deepEqual(report.counts, { block: 0, exception: 0, log: 2, integrity: 0 });
    assert.deepEqual(report.issueCounts, result.correlation.summary);
  });
});
