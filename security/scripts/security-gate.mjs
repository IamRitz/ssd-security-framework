import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectEcosystems } from './detect-ecosystems.mjs';

const VALID_ACTIONS = new Set(['BLOCK', 'BLOCK_DEPLOY', 'EXCEPTION', 'LOG']);

const DEFAULT_PATHS = {
  policy: 'security/policy.yaml',
  // Checkout root used only for ecosystem detection (which language-native
  // dependency reports are required vs cleanly skipped).
  repoDir: '.',
  gitleaks: 'reports/gitleaks.json',
  trufflehog: 'reports/trufflehog.json',
  npmAudit: 'reports/npm-audit.json',
  pipAudit: 'reports/pip-audit.json',
  osv: 'reports/osv-scanner.json',
  semgrep: 'reports/semgrep.json',
  baseline: 'security/baseline/semgrep-baseline.json',
  output: 'reports/security-gate.json',
  exceptions: 'reports/gate-exceptions.json'
};

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function parseScalar(value) {
  if (/^-?\d+(?:\.\d+)?$/.test(value)) {
    return Number(value);
  }

  return value.replace(/^(['"])(.*)\1$/, '$2');
}

export function parseSimplePolicy(source) {
  const policy = {};
  const stack = [{ indent: -1, value: policy }];

  for (const [index, rawLine] of source.split('\n').entries()) {
    assert(!rawLine.includes('\t'), `policy line ${index + 1} contains a tab`);
    const withoutComment = rawLine.split('#', 1)[0].trimEnd();

    if (withoutComment.trim() === '') {
      continue;
    }

    const indent = withoutComment.length - withoutComment.trimStart().length;
    const match = withoutComment.trim().match(/^([A-Za-z0-9_]+):(?:\s*(.*))?$/);
    assert(match, `policy line ${index + 1} is not a simple key/value mapping`);

    while (stack.at(-1).indent >= indent) {
      stack.pop();
    }

    const parent = stack.at(-1)?.value;
    assert(parent, `policy line ${index + 1} has invalid indentation`);
    const [, key, rawValue = ''] = match;

    if (rawValue === '') {
      parent[key] = {};
      stack.push({ indent, value: parent[key] });
    } else {
      parent[key] = parseScalar(rawValue.trim());
    }
  }

  return policy;
}

function policyValue(policy, path) {
  const value = path.split('.').reduce((current, key) => current?.[key], policy);
  assert(value !== undefined, `policy is missing ${path}`);
  return value;
}

export function policyAction(policy, path) {
  const action = policyValue(policy, path);
  assert(VALID_ACTIONS.has(action), `policy ${path} has invalid action ${action}`);
  return action;
}

function validatePolicy(policy) {
  for (const path of [
    'secrets.verified',
    'secrets.unverified',
    'secrets.demo_dummy',
    'dependencies.critical_with_fix',
    'dependencies.high_with_fix',
    'dependencies.critical_no_fix',
    'dependencies.high_no_fix',
    'dependencies.medium',
    'dependencies.low',
    'dependencies.malicious_package',
    'sast.critical_new',
    'sast.high_new',
    'sast.critical_existing',
    'sast.high_existing',
    'sast.medium',
    'sast.low'
  ]) {
    policyAction(policy, path);
  }

  const thresholds = policyValue(policy, 'severity_mapping.osv_cvss_thresholds');
  assert(
    Number.isFinite(thresholds.critical) &&
      Number.isFinite(thresholds.high) &&
      Number.isFinite(thresholds.medium) &&
      thresholds.critical > thresholds.high &&
      thresholds.high > thresholds.medium,
    'OSV CVSS thresholds must be descending finite numbers'
  );

  for (const severity of ['ERROR', 'WARNING', 'INFO']) {
    normalizeSeverity(policyValue(policy, `severity_mapping.semgrep_severity.${severity}`));
  }

  for (const [path, expected] of [
    ['break_glass.sast_new', 'ELIGIBLE'],
    ['break_glass.dependency_with_fix', 'ELIGIBLE'],
    ['break_glass.verified_secrets', 'NEVER'],
    ['break_glass.malicious_package', 'NEVER'],
    ['break_glass.report_integrity', 'NEVER']
  ]) {
    assert(policyValue(policy, path) === expected, `policy ${path} must remain ${expected}`);
  }
}

async function readJson(path, label) {
  let source;

  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`${label}: missing report file ${path}`, { cause: error });
    }
    throw new Error(`${label}: cannot read ${path}: ${error.message}`, { cause: error });
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`${label}: malformed JSON in ${path}: ${error.message}`, { cause: error });
  }
}

// Per-ecosystem dependency reports (npm audit, pip-audit) only exist when that
// ecosystem is present in the target repo, so a missing file is a clean skip,
// not an integrity failure. Malformed content is still fail-closed. OSV-Scanner
// always runs and is the cross-ecosystem backstop, so dependency coverage is
// never fully absent even when a language-native report is skipped.
async function readOptionalJson(path, label) {
  try {
    await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw new Error(`${label}: cannot read ${path}: ${error.message}`, { cause: error });
  }
  return readJson(path, label);
}

function normalizeSeverity(value) {
  assert(typeof value === 'string', 'severity must be a string');
  const severity = value.toLowerCase();

  if (severity === 'moderate') {
    return 'medium';
  }
  if (severity === 'info') {
    return 'low';
  }

  assert(
    ['critical', 'high', 'medium', 'low'].includes(severity),
    `unsupported severity ${value}`
  );
  return severity;
}

function addFinding(findings, policy, finding) {
  findings.push({
    ...finding,
    action: policyAction(policy, finding.policyRule)
  });
}

function evaluateSecrets(policy, gitleaks, trufflehog, findings) {
  assert(Array.isArray(gitleaks), 'Gitleaks report must be an array');
  assert(Array.isArray(trufflehog), 'TruffleHog report must be an array');

  for (const finding of gitleaks) {
    assert(typeof finding.RuleID === 'string', 'Gitleaks finding is missing RuleID');
    assert(typeof finding.File === 'string', 'Gitleaks finding is missing File');
    const isDemoDummy = finding.RuleID === 'phase10-demo-dummy-secret';
    addFinding(findings, policy, {
      source: 'gitleaks',
      id: finding.RuleID,
      location: `${finding.File}:${finding.StartLine ?? '?'}`,
      policyRule: isDemoDummy ? 'secrets.demo_dummy' : 'secrets.unverified',
      reason: isDemoDummy
        ? 'Dedicated non-credential marker activated on a never-merged demo branch'
        : 'Gitleaks pattern match is not provider-verified'
    });
  }

  for (const finding of trufflehog) {
    assert(
      typeof finding.DetectorName === 'string',
      'TruffleHog finding is missing DetectorName'
    );
    assert(typeof finding.Verified === 'boolean', 'TruffleHog finding is missing Verified');
    const state = finding.Verified ? 'verified' : 'unverified';
    addFinding(findings, policy, {
      source: 'trufflehog',
      id: finding.DetectorName,
      policyRule: `secrets.${state}`,
      reason: finding.Verified
        ? 'TruffleHog verified the credential with its provider'
        : 'TruffleHog did not verify the credential'
    });
  }
}

function evaluateNpmAudit(policy, report, findings) {
  assert(report && typeof report === 'object', 'npm audit report must be an object');
  assert(report.auditReportVersion, 'npm audit report is missing auditReportVersion');
  assert(
    report.metadata?.vulnerabilities &&
      typeof report.metadata.vulnerabilities.total === 'number',
    'npm audit report is missing metadata.vulnerabilities.total'
  );
  assert(
    report.vulnerabilities && !Array.isArray(report.vulnerabilities),
    'npm audit report is missing vulnerabilities object'
  );

  const entries = Object.entries(report.vulnerabilities);
  assert(
    entries.length === report.metadata.vulnerabilities.total,
    'npm audit vulnerability total does not match its findings object'
  );

  for (const [packageName, vulnerability] of entries) {
    const severity = normalizeSeverity(vulnerability.severity);
    assert(
      Object.hasOwn(vulnerability, 'fixAvailable'),
      `npm audit finding ${packageName} is missing fixAvailable`
    );
    const fixAvailable = vulnerability.fixAvailable !== false;
    const suffix = ['critical', 'high'].includes(severity)
      ? `_${fixAvailable ? 'with_fix' : 'no_fix'}`
      : '';
    const policyRule = `dependencies.${severity}${suffix}`;

    // Optional human context: the fixed version npm suggests, and the advisory
    // title/url when `via` carries advisory objects (not just package names).
    const advisory = Array.isArray(vulnerability.via)
      ? vulnerability.via.find((entry) => entry && typeof entry === 'object')
      : undefined;
    const fixedVersion =
      vulnerability.fixAvailable && typeof vulnerability.fixAvailable === 'object'
        ? vulnerability.fixAvailable.version
        : undefined;

    addFinding(findings, policy, {
      source: 'npm-audit',
      id: packageName,
      severity,
      fixAvailable,
      policyRule,
      reason: `${severity} npm advisory; fix ${fixAvailable ? 'available' : 'not available'}`,
      ...(typeof fixedVersion === 'string' ? { fixedVersion } : {}),
      ...(advisory?.title ? { title: advisory.title } : {}),
      ...(advisory?.url ? { url: advisory.url } : {})
    });
  }
}

// pip-audit's JSON differs from npm audit's in two ways that matter here:
//   1. It reports NO severity/CVSS at all — each vuln carries only id,
//      fix_versions, aliases, and description. We therefore classify every
//      pip-audit finding fail-closed as `high`, so a known Python advisory can
//      never be silently downgraded to a non-blocking LOG. OSV-Scanner remains
//      the CVSS/severity source of record for Python packages.
//   2. Fix availability is the `fix_versions` array (non-empty => a fix exists),
//      not a boolean.
// Shape: { dependencies: [ { name, version, vulns: [ { id, fix_versions, ... } ] } ] }
// The same (package, id) pair can appear more than once, so findings are deduped.
function evaluatePipAudit(policy, report, findings) {
  assert(report && typeof report === 'object', 'pip-audit report must be an object');
  assert(Array.isArray(report.dependencies), 'pip-audit report is missing dependencies array');

  const seen = new Set();
  for (const dependency of report.dependencies) {
    assert(typeof dependency.name === 'string', 'pip-audit dependency is missing name');
    // A dependency pip-audit could not resolve carries `skip_reason` and no vulns.
    if (dependency.vulns === undefined) {
      continue;
    }
    assert(
      Array.isArray(dependency.vulns),
      `pip-audit dependency ${dependency.name} has a non-array vulns field`
    );

    for (const vulnerability of dependency.vulns) {
      assert(
        typeof vulnerability.id === 'string',
        `pip-audit finding for ${dependency.name} is missing id`
      );

      const key = `${dependency.name}\0${vulnerability.id}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);

      if (vulnerability.id.startsWith('MAL-')) {
        addFinding(findings, policy, {
          source: 'pip-audit',
          id: vulnerability.id,
          package: dependency.name,
          policyRule: 'dependencies.malicious_package',
          reason: 'pip-audit malicious-package advisory blocks regardless of severity'
        });
        continue;
      }

      assert(
        Array.isArray(vulnerability.fix_versions),
        `pip-audit finding ${vulnerability.id} is missing fix_versions`
      );
      const fixAvailable = vulnerability.fix_versions.length > 0;
      const policyRule = `dependencies.high_${fixAvailable ? 'with_fix' : 'no_fix'}`;

      addFinding(findings, policy, {
        source: 'pip-audit',
        id: vulnerability.id,
        package: dependency.name,
        severity: 'high',
        fixAvailable,
        policyRule,
        reason: `Python advisory (pip-audit reports no severity; treated as high); fix ${
          fixAvailable ? 'available' : 'not available'
        }`
      });
    }
  }
}

const CVSS_VALUES = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 }
};

function roundUpOneDecimal(value) {
  return Math.ceil((value - 1e-10) * 10) / 10;
}

function cvssV3Score(vector) {
  const metrics = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((part) => part.split(':'))
  );
  assert(['U', 'C'].includes(metrics.S), `unsupported CVSS scope in ${vector}`);

  const value = (metric) => {
    const result = CVSS_VALUES[metric]?.[metrics[metric]];
    assert(result !== undefined, `invalid CVSS ${metric} metric in ${vector}`);
    return result;
  };
  const privilegeRequired = {
    N: 0.85,
    L: metrics.S === 'C' ? 0.68 : 0.62,
    H: metrics.S === 'C' ? 0.5 : 0.27
  }[metrics.PR];
  assert(privilegeRequired !== undefined, `invalid CVSS PR metric in ${vector}`);

  const impactBase = 1 - (1 - value('C')) * (1 - value('I')) * (1 - value('A'));
  const impact =
    metrics.S === 'U'
      ? 6.42 * impactBase
      : 7.52 * (impactBase - 0.029) - 3.25 * (impactBase - 0.02) ** 15;

  if (impact <= 0) {
    return 0;
  }

  const exploitability =
    8.22 * value('AV') * value('AC') * privilegeRequired * value('UI');
  const base =
    metrics.S === 'U'
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
  return roundUpOneDecimal(base);
}

// Returns the highest CVSS v3 base score, or null when the advisory carries no
// CVSS v3 severity at all. Many PyPI (PYSEC) advisories omit severity entirely,
// which is legitimate data, not a malformed report — the caller defaults those
// to `high` fail-closed. A present-but-non-array severity is still malformed.
function osvScore(vulnerability) {
  if (vulnerability.severity === undefined) {
    return null;
  }
  assert(Array.isArray(vulnerability.severity), `OSV ${vulnerability.id} severity must be an array`);
  const scores = vulnerability.severity
    .filter((entry) => entry.type === 'CVSS_V3')
    .map((entry) => {
      const numeric = Number(entry.score);
      return Number.isFinite(numeric) ? numeric : cvssV3Score(entry.score);
    });
  return scores.length > 0 ? Math.max(...scores) : null;
}

function osvSeverity(policy, score) {
  const thresholds = policyValue(policy, 'severity_mapping.osv_cvss_thresholds');
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  return 'low';
}

function osvHasFix(vulnerability, scannedPackage) {
  assert(Array.isArray(vulnerability.affected), `OSV ${vulnerability.id} is missing affected`);
  const affected = vulnerability.affected.filter(
    (entry) =>
      entry.package?.name === scannedPackage.name &&
      (!scannedPackage.ecosystem || entry.package.ecosystem === scannedPackage.ecosystem)
  );
  assert(
    affected.length > 0,
    `OSV ${vulnerability.id} has no affected range for ${scannedPackage.name}`
  );

  // An advisory may express affected versions with `ranges` (events) or only a
  // plain `versions` list. A fix is "available" when some range carries a `fixed`
  // event; an entry that lacks ranges simply contributes no fix signal (rather
  // than failing the report), so ecosystems that omit ranges degrade to no_fix.
  return affected.some((entry) => {
    if (!Array.isArray(entry.ranges)) {
      return false;
    }
    return entry.ranges.some((range) => {
      assert(Array.isArray(range.events), `OSV ${vulnerability.id} range lacks events`);
      return range.events.some((event) => typeof event.fixed === 'string' && event.fixed !== '');
    });
  });
}

function evaluateOsv(policy, report, findings) {
  assert(report && typeof report === 'object', 'OSV-Scanner report must be an object');
  assert(Array.isArray(report.results), 'OSV-Scanner report is missing results array');

  for (const result of report.results) {
    assert(Array.isArray(result.packages), 'OSV-Scanner result is missing packages array');
    for (const dependency of result.packages) {
      assert(
        typeof dependency.package?.name === 'string',
        'OSV-Scanner package is missing package.name'
      );
      assert(
        typeof dependency.package?.version === 'string',
        `OSV-Scanner package ${dependency.package.name} is missing version`
      );
      assert(
        Array.isArray(dependency.vulnerabilities),
        `OSV-Scanner package ${dependency.package.name} is missing vulnerabilities`
      );

      for (const vulnerability of dependency.vulnerabilities) {
        assert(typeof vulnerability.id === 'string', 'OSV finding is missing id');

        if (vulnerability.id.startsWith('MAL-')) {
          addFinding(findings, policy, {
            source: 'osv-scanner',
            id: vulnerability.id,
            package: dependency.package.name,
            policyRule: 'dependencies.malicious_package',
            reason: 'OSV malicious-package advisory blocks regardless of severity'
          });
          continue;
        }

        const score = osvScore(vulnerability);
        // No CVSS v3 score (common for PyPI/PYSEC advisories) => fail-closed high.
        const severity = score === null ? 'high' : osvSeverity(policy, score);
        const fixAvailable = osvHasFix(vulnerability, dependency.package);
        const suffix = ['critical', 'high'].includes(severity)
          ? `_${fixAvailable ? 'with_fix' : 'no_fix'}`
          : '';
        const referenceUrl = Array.isArray(vulnerability.references)
          ? vulnerability.references.find((entry) => typeof entry?.url === 'string')?.url
          : undefined;
        addFinding(findings, policy, {
          source: 'osv-scanner',
          id: vulnerability.id,
          package: dependency.package.name,
          severity,
          ...(score === null ? {} : { cvssScore: score }),
          fixAvailable,
          policyRule: `dependencies.${severity}${suffix}`,
          reason: `${severity} OSV advisory (${
            score === null ? 'no CVSS score; treated as high' : `CVSS ${score}`
          }); fix ${fixAvailable ? 'available' : 'not available'}`,
          // Optional human context for the formatter.
          ...(typeof vulnerability.summary === 'string' ? { summary: vulnerability.summary } : {}),
          ...(typeof referenceUrl === 'string' ? { url: referenceUrl } : {})
        });
      }
    }
  }
}

function semgrepFingerprint(finding) {
  assert(typeof finding.check_id === 'string', 'Semgrep finding is missing check_id');
  assert(typeof finding.path === 'string', `Semgrep ${finding.check_id} is missing path`);
  assert(
    typeof finding.extra?.lines === 'string',
    `Semgrep ${finding.check_id} is missing matched source text`
  );
  return createHash('sha256')
    .update(`${finding.check_id}\0${finding.path}\0${finding.extra.lines.trim()}`)
    .digest('hex');
}

function semgrepSeverity(policy, finding) {
  const raw = finding.extra?.severity;
  assert(typeof raw === 'string', `Semgrep ${finding.check_id} is missing severity`);

  if (['critical', 'high', 'medium', 'low'].includes(raw.toLowerCase())) {
    return raw.toLowerCase();
  }

  return normalizeSeverity(policyValue(policy, `severity_mapping.semgrep_severity.${raw}`));
}

function evaluateSemgrep(policy, report, baseline, findings) {
  assert(report && typeof report === 'object', 'Semgrep report must be an object');
  assert(typeof report.version === 'string', 'Semgrep report is missing version');
  assert(Array.isArray(report.results), 'Semgrep report is missing results array');
  assert(Array.isArray(report.errors), 'Semgrep report is missing errors array');
  assert(Array.isArray(report.paths?.scanned), 'Semgrep report is missing paths.scanned array');
  assert(report.errors.length === 0, `Semgrep report contains ${report.errors.length} errors`);
  assert(baseline?.schemaVersion === 1, 'Semgrep baseline has unsupported schemaVersion');
  assert(Array.isArray(baseline.findings), 'Semgrep baseline is missing findings array');

  const knownFingerprints = new Set(
    baseline.findings.map((finding) => {
      assert(typeof finding.fingerprint === 'string', 'baseline finding is missing fingerprint');
      assert(typeof finding.checkId === 'string', 'baseline finding is missing checkId');
      assert(typeof finding.path === 'string', 'baseline finding is missing path');
      return finding.fingerprint;
    })
  );

  for (const finding of report.results) {
    const fingerprint = semgrepFingerprint(finding);
    const severity = semgrepSeverity(policy, finding);
    const existing = knownFingerprints.has(fingerprint);
    const suffix = ['critical', 'high'].includes(severity)
      ? `_${existing ? 'existing' : 'new'}`
      : '';
    addFinding(findings, policy, {
      source: 'semgrep',
      id: finding.check_id,
      location: `${finding.path}:${finding.start?.line ?? '?'}`,
      fingerprint,
      severity,
      baselineState: existing ? 'existing' : 'new',
      policyRule: `sast.${severity}${suffix}`,
      reason: `${severity} Semgrep finding is ${existing ? 'baseline-known' : 'new'}`,
      // Human context for the developer-readable formatter (Semgrep rules carry a
      // `message`); optional, so a minimal report still evaluates.
      ...(typeof finding.extra?.message === 'string' && finding.extra.message !== ''
        ? { message: finding.extra.message }
        : {}),
      ...(typeof finding.extra?.metadata?.references?.[0] === 'string'
        ? { url: finding.extra.metadata.references[0] }
        : {})
    });
  }
}

function summarize(findings) {
  return Object.fromEntries(
    ['BLOCK', 'EXCEPTION', 'LOG'].map((action) => [
      action.toLowerCase(),
      findings.filter((finding) => finding.action === action).length
    ])
  );
}

export function isBreakGlassEligibleFinding(finding) {
  return finding.action === 'BLOCK' && finding.breakGlassEligible === true;
}

// A report-integrity failure means a scanner could not interpret its input: a
// missing or malformed report, a Trivy scan that could not identify the base
// image OS, an end-of-life OS with no advisories. The findings list is then not
// "clean", it is UNKNOWN.
//
// The verdict alone cannot carry this: in `log-only` mode a BLOCK deliberately
// does not fail the job, so anything downstream reading only the verdict would
// treat an untrustworthy scan as an acceptable one. Baselining from such a run
// would bake "no findings" in as the permanently accepted state. Every gate
// result therefore carries this machine-readable flag, and
// generate-semgrep-baseline.mjs refuses to run when it is false.
export function summarizeIntegrity(findings) {
  const failures = findings.filter(
    (finding) =>
      finding.id === 'report-integrity' ||
      (typeof finding.policyRule === 'string' && finding.policyRule.endsWith('report_integrity'))
  );

  return {
    trusted: failures.length === 0,
    failures: failures.map((finding) => ({
      source: finding.source,
      reason: finding.reason
    }))
  };
}

function markBreakGlassEligibility(policy, findings) {
  for (const finding of findings) {
    let policyPath;
    if (['sast.critical_new', 'sast.high_new'].includes(finding.policyRule)) {
      policyPath = 'break_glass.sast_new';
    } else if (
      ['dependencies.critical_with_fix', 'dependencies.high_with_fix'].includes(
        finding.policyRule
      )
    ) {
      policyPath = 'break_glass.dependency_with_fix';
    } else if (finding.policyRule === 'secrets.verified') {
      policyPath = 'break_glass.verified_secrets';
    } else if (finding.policyRule === 'dependencies.malicious_package') {
      policyPath = 'break_glass.malicious_package';
    } else {
      policyPath = 'break_glass.report_integrity';
    }
    finding.breakGlassEligible =
      finding.action === 'BLOCK' && policyValue(policy, policyPath) === 'ELIGIBLE';
  }
}

function breakGlassSummary(verdict, findings) {
  const blocked = findings.filter((finding) => finding.action === 'BLOCK');
  const eligibleFindings = blocked.filter(isBreakGlassEligibleFinding);
  const ineligibleFindings = blocked.filter(
    (finding) => !isBreakGlassEligibleFinding(finding)
  );

  return {
    eligible:
      verdict === 'BLOCK' &&
      eligibleFindings.length > 0 &&
      ineligibleFindings.length === 0,
    eligibleFindings,
    ineligibleFindings
  };
}

async function writeResults(paths, result) {
  const exceptions = result.findings.filter((finding) => finding.action === 'EXCEPTION');
  await mkdir(dirname(paths.output), { recursive: true });
  await mkdir(dirname(paths.exceptions), { recursive: true });
  await writeFile(paths.output, `${JSON.stringify(result, null, 2)}\n`);
  await writeFile(
    paths.exceptions,
    `${JSON.stringify({ verdict: result.verdict, exceptions }, null, 2)}\n`
  );
}

export async function runSecurityGate(customPaths = {}) {
  const paths = { ...DEFAULT_PATHS, ...customPaths };
  let result;

  try {
    const policy = parseSimplePolicy(await readFile(paths.policy, 'utf8'));
    validatePolicy(policy);
    // A language-native dependency report is REQUIRED (fail-closed on a missing
    // file) only when the scanner that produces it would actually run — i.e. its
    // audit-target file exists (package-lock.json for npm audit, requirements.txt
    // for pip-audit). Otherwise its absence is a clean skip. OSV-Scanner is always
    // required and covers every ecosystem's lockfiles, so dependency coverage is
    // never fully absent even when a language-native report is skipped.
    const ecosystems = await detectEcosystems(paths.repoDir);
    const [gitleaks, trufflehog, osv, semgrep, baseline, npmAudit, pipAudit] = await Promise.all([
      readJson(paths.gitleaks, 'Gitleaks'),
      readJson(paths.trufflehog, 'TruffleHog'),
      readJson(paths.osv, 'OSV-Scanner'),
      readJson(paths.semgrep, 'Semgrep'),
      readJson(paths.baseline, 'Semgrep baseline'),
      ecosystems.packageLock
        ? readJson(paths.npmAudit, 'npm audit')
        : readOptionalJson(paths.npmAudit, 'npm audit'),
      ecosystems.requirementsTxt
        ? readJson(paths.pipAudit, 'pip-audit')
        : readOptionalJson(paths.pipAudit, 'pip-audit')
    ]);
    const findings = [];

    evaluateSecrets(policy, gitleaks, trufflehog, findings);
    if (npmAudit !== null) {
      evaluateNpmAudit(policy, npmAudit, findings);
    }
    if (pipAudit !== null) {
      evaluatePipAudit(policy, pipAudit, findings);
    }
    evaluateOsv(policy, osv, findings);
    evaluateSemgrep(policy, semgrep, baseline, findings);
    markBreakGlassEligibility(policy, findings);

    const summary = summarize(findings);
    const verdict =
      summary.block > 0
        ? 'BLOCK'
        : summary.exception > 0
          ? 'PASS-WITH-EXCEPTIONS'
          : 'PASS';
    result = {
      verdict,
      summary,
      integrity: summarizeIntegrity(findings),
      findings,
      breakGlass: breakGlassSummary(verdict, findings)
    };
  } catch (error) {
    const finding = {
      source: 'security-gate',
      id: 'report-integrity',
      action: 'BLOCK',
      policyRule: 'gate.report_integrity',
      reason: error.message,
      breakGlassEligible: false
    };
    result = {
      verdict: 'BLOCK',
      summary: { block: 1, exception: 0, log: 0 },
      integrity: summarizeIntegrity([finding]),
      findings: [finding],
      breakGlass: breakGlassSummary('BLOCK', [finding])
    };
  }

  await writeResults(paths, result);
  return result;
}

function parseArguments(arguments_) {
  const aliases = {
    '--policy': 'policy',
    '--repo-dir': 'repoDir',
    '--gitleaks': 'gitleaks',
    '--trufflehog': 'trufflehog',
    '--npm-audit': 'npmAudit',
    '--pip-audit': 'pipAudit',
    '--osv': 'osv',
    '--semgrep': 'semgrep',
    '--baseline': 'baseline',
    '--output': 'output',
    '--exceptions': 'exceptions'
  };
  const paths = {};

  for (let index = 0; index < arguments_.length; index += 2) {
    const key = aliases[arguments_[index]];
    const value = arguments_[index + 1];
    assert(key && value, `unknown or incomplete argument ${arguments_[index]}`);
    paths[key] = value;
  }

  return paths;
}

async function main() {
  let paths;

  try {
    paths = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`SECURITY GATE: BLOCK\nBLOCK security-gate report-integrity: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const result = await runSecurityGate(paths);

  for (const finding of result.findings) {
    console.log(
      `${finding.action} ${finding.source} ${finding.id} (${finding.policyRule}): ${finding.reason}`
    );
  }
  console.log(`SECURITY GATE: ${result.verdict}`);
  process.exitCode = result.verdict === 'BLOCK' ? 1 : 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
