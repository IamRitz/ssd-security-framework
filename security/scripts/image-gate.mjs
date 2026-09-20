import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseSimplePolicy, policyAction, summarizeIntegrity } from './security-gate.mjs';

const DEFAULT_PATHS = {
  policy: 'security/policy.yaml',
  report: 'reports/ecr-image-scan.json',
  output: 'reports/image-gate.json'
};

const DEFAULT_SOURCE = 'ecr';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function readJson(path) {
  let source;

  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`missing image scan report ${path}`, { cause: error });
    }
    throw new Error(`cannot read image scan report ${path}: ${error.message}`, { cause: error });
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`malformed JSON in image scan report ${path}: ${error.message}`, {
      cause: error
    });
  }
}

function validatePolicy(policy) {
  // Severity-only keys: ECR basic scanning (no fix data), and medium/low for
  // every source.
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const action = policyAction(policy, `image.${severity}`);
    const expected = ['critical', 'high'].includes(severity) ? 'BLOCK_DEPLOY' : 'LOG';
    assert(action === expected, `image.${severity} must be ${expected} for this POC`);
  }
  // with_fix/no_fix keys (Trivy pre-push and ECR enhanced/Inspector — fix
  // availability known), mirroring the
  // dependency model: fixable Critical/High blocks, unfixable is an EXCEPTION.
  for (const [path, expected] of [
    ['image.critical_with_fix', 'BLOCK_DEPLOY'],
    ['image.high_with_fix', 'BLOCK_DEPLOY'],
    ['image.critical_no_fix', 'EXCEPTION'],
    ['image.high_no_fix', 'EXCEPTION']
  ]) {
    assert(policyAction(policy, path) === expected, `${path} must be ${expected} for this POC`);
  }
}

// Normalized registry report sources this gate recognizes. Adding a value is how a
// new collector or scanning mode is admitted; an unrecognized source is a
// report-integrity BLOCK_DEPLOY, never a best-effort parse. The two ECR modes
// differ in exactly one capability:
//   aws-ecr-basic    — severity only. Basic scanning reports no fix
//                      availability, so Critical/High conservatively BLOCK.
//   aws-ecr-enhanced — Amazon Inspector. Findings carry fix availability, so
//                      Critical/High use the same with_fix/no_fix split as Trivy.
// The asymmetry is a scanner limitation, not a policy choice.
const REGISTRY_SOURCES = {
  'aws-ecr-basic': { fixAware: false, findingSource: 'ecr-image-scan' },
  'aws-ecr-enhanced': { fixAware: true, findingSource: 'ecr-enhanced-scan' }
};

function registryFinding(policy, finding, mode) {
  assert(typeof finding.id === 'string', 'image finding lacks id');
  assert(typeof finding.severity === 'string', `image finding ${finding.id} lacks severity`);
  const severity = finding.severity.toLowerCase();
  assert(
    ['critical', 'high', 'medium', 'low'].includes(severity),
    `image finding ${finding.id} has unsupported severity ${finding.severity}`
  );

  if (!mode.fixAware) {
    const policyRule = `image.${severity}`;
    return {
      source: mode.findingSource,
      id: finding.id,
      severity,
      action: policyAction(policy, policyRule),
      policyRule,
      reason: `${severity} image finding`
    };
  }

  // Fix availability is REQUIRED from a fix-aware source. Defaulting a missing
  // value to "no fix" would silently turn a BLOCK_DEPLOY into an EXCEPTION —
  // fail-open — so an absent or non-boolean value is a report-integrity failure.
  assert(
    typeof finding.fixAvailable === 'boolean',
    `image finding ${finding.id} lacks a boolean fixAvailable from a fix-aware source`
  );
  const suffix = ['critical', 'high'].includes(severity)
    ? `_${finding.fixAvailable ? 'with_fix' : 'no_fix'}`
    : '';
  const policyRule = `image.${severity}${suffix}`;
  return {
    source: mode.findingSource,
    id: finding.id,
    severity,
    fixAvailable: finding.fixAvailable,
    action: policyAction(policy, policyRule),
    policyRule,
    reason: `${severity} image finding; fix ${finding.fixAvailable ? 'available' : 'not available'}`,
    ...(typeof finding.package === 'string' ? { package: finding.package } : {}),
    ...(typeof finding.fixedVersion === 'string' && finding.fixedVersion !== ''
      ? { fixedVersion: finding.fixedVersion }
      : {}),
    ...(typeof finding.title === 'string' && finding.title !== '' ? { title: finding.title } : {}),
    ...(typeof finding.url === 'string' ? { url: finding.url } : {}),
    // Optional scanner evidence, passed through for developer guidance only.
    ...(typeof finding.scannerSeverity === 'string' ? { scannerSeverity: finding.scannerSeverity } : {}),
    ...(typeof finding.fixAvailability === 'string' ? { fixAvailability: finding.fixAvailability } : {}),
    ...(Array.isArray(finding.packages)
      ? {
          packages: finding.packages
            .filter((pkg) => pkg && typeof pkg.name === 'string')
            .map((pkg) => ({
              name: pkg.name,
              ...(typeof pkg.version === 'string' ? { version: pkg.version } : {}),
              ...(typeof pkg.fixedInVersion === 'string' ? { fixedInVersion: pkg.fixedInVersion } : {})
            }))
        }
      : {})
  };
}

function evaluate(policy, report) {
  assert(report?.schemaVersion === 1, 'image scan report has unsupported schemaVersion');
  const mode = Object.hasOwn(REGISTRY_SOURCES, report.source ?? '')
    ? REGISTRY_SOURCES[report.source]
    : null;
  assert(mode, `image scan report has unsupported source ${JSON.stringify(report.source)}`);
  assert(report.scanStatus === 'COMPLETE', 'image scan report status is not COMPLETE');
  assert(typeof report.image?.repository === 'string', 'image scan report lacks repository');
  assert(typeof report.image?.imageTag === 'string', 'image scan report lacks imageTag');
  assert(typeof report.image?.imageDigest === 'string', 'image scan report lacks imageDigest');
  assert(Array.isArray(report.findings), 'image scan report lacks findings array');
  assert(
    report.severityCounts && typeof report.severityCounts === 'object',
    'image scan report lacks severityCounts'
  );

  const findings = report.findings.map((finding) => registryFinding(policy, finding, mode));

  const severities = ['critical', 'high', 'medium', 'low'];
  for (const severity of Object.keys(report.severityCounts)) {
    assert(severities.includes(severity), `unsupported image severity count ${severity}`);
  }
  for (const severity of severities) {
    const reported = report.severityCounts[severity] ?? 0;
    const observed = findings.filter((finding) => finding.severity === severity).length;
    assert(
      Number.isInteger(reported) && reported >= 0,
      `image ${severity} severity count must be a non-negative integer`
    );
    assert(reported === observed, `image ${severity} count does not match findings array`);
  }

  const blockDeploy = findings.filter((finding) => finding.action === 'BLOCK_DEPLOY').length;
  const log = findings.filter((finding) => finding.action === 'LOG').length;

  if (!mode.fixAware) {
    // Severity-only source: no EXCEPTION is possible, output unchanged.
    return {
      verdict: blockDeploy > 0 ? 'BLOCK_DEPLOY' : 'DEPLOY',
      summary: { blockDeploy, log },
      image: report.image,
      findings
    };
  }

  // Fix-aware source: the same three-state verdict as the Trivy pre-push gate.
  const exceptions = findings.filter((finding) => finding.action === 'EXCEPTION');
  return {
    verdict:
      blockDeploy > 0
        ? 'BLOCK_DEPLOY'
        : exceptions.length > 0
          ? 'DEPLOY-WITH-EXCEPTIONS'
          : 'DEPLOY',
    summary: { blockDeploy, exception: exceptions.length, log },
    exceptions,
    image: report.image,
    findings
  };
}

// Trivy severities -> our four levels. UNKNOWN maps to `high`, the same
// fail-closed choice already made for OSV advisories that carry no CVSS.
function trivySeverity(raw) {
  const severity = String(raw ?? '').toLowerCase();
  if (severity === 'unknown' || severity === '') {
    return 'high';
  }
  assert(
    ['critical', 'high', 'medium', 'low'].includes(severity),
    `unsupported Trivy severity ${raw}`
  );
  return severity;
}

// Normalise a raw Trivy `image` JSON report (SchemaVersion 2) and evaluate it
// against the same image policy. Report-integrity is fail-closed: a scan that
// could not actually inspect the image (no OS detected, end-of-life OS) reports
// zero findings, which must BLOCK rather than pass as clean.
function evaluateTrivy(policy, report) {
  assert(report?.SchemaVersion === 2, 'Trivy report has unsupported SchemaVersion (expected 2)');
  assert(
    report.ArtifactType === 'container_image',
    'Trivy report is not a container_image artifact'
  );
  assert(
    typeof report.Metadata?.ImageID === 'string' && report.Metadata.ImageID.startsWith('sha256:'),
    'Trivy report lacks a Metadata.ImageID (sha256 config digest)'
  );
  assert(Array.isArray(report.Results), 'Trivy report lacks a Results array');

  // False-clean guard: if Trivy could not identify the OS it scans no OS
  // packages and returns zero vulnerabilities — "clean" would actually mean
  // "did not understand the image". Require a detected OS family AND an os-pkgs
  // result class; either missing is a report-integrity BLOCK.
  const osFamily = report.Metadata?.OS?.Family;
  assert(
    typeof osFamily === 'string' && osFamily !== '',
    'Trivy did not detect an OS family — a zero-finding result would be a false clean'
  );
  assert(
    report.Results.some((result) => result.Class === 'os-pkgs'),
    'Trivy produced no os-pkgs result — the OS layer was not scanned (false clean)'
  );

  // End-of-life OS: advisories stop, so "no known vulnerabilities" is unknowable.
  assert(report.Metadata.OS?.EOSL !== true, `OS ${osFamily} is end-of-life (EOSL) — no advisories`);

  const findings = [];
  const seen = new Set();
  for (const result of report.Results) {
    for (const vulnerability of result.Vulnerabilities ?? []) {
      assert(typeof vulnerability.VulnerabilityID === 'string', 'Trivy vulnerability lacks an ID');
      // Trivy can list the same CVE under more than one target; dedupe by
      // (id, package) so the gate output has one row per real finding.
      const key = `${vulnerability.VulnerabilityID}\0${vulnerability.PkgName ?? ''}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      const severity = trivySeverity(vulnerability.Severity);
      const fixAvailable =
        typeof vulnerability.FixedVersion === 'string' && vulnerability.FixedVersion !== '';
      // Critical/High split on fix availability (with_fix -> BLOCK_DEPLOY,
      // no_fix -> EXCEPTION); medium/low stay severity-only LOG.
      const suffix = ['critical', 'high'].includes(severity)
        ? `_${fixAvailable ? 'with_fix' : 'no_fix'}`
        : '';
      const policyRule = `image.${severity}${suffix}`;
      findings.push({
        source: 'trivy',
        id: vulnerability.VulnerabilityID,
        package: vulnerability.PkgName,
        severity,
        // Trivy's own rating; UNKNOWN is classified high by trivySeverity.
        ...(typeof vulnerability.Severity === 'string' ? { scannerSeverity: vulnerability.Severity } : {}),
        ...(typeof vulnerability.InstalledVersion === 'string'
          ? { installedVersion: vulnerability.InstalledVersion }
          : {}),
        ...(typeof result.Target === 'string' ? { target: result.Target } : {}),
        fixAvailable,
        action: policyAction(policy, policyRule),
        policyRule,
        reason: `${severity} image finding; fix ${fixAvailable ? 'available' : 'not available'}`,
        // Optional human context (CVE title/description, fixed version, link) for
        // the developer-readable formatter; omitted when Trivy did not provide it.
        ...(fixAvailable ? { fixedVersion: vulnerability.FixedVersion } : {}),
        ...(typeof vulnerability.Title === 'string' && vulnerability.Title !== ''
          ? { title: vulnerability.Title }
          : {}),
        ...(typeof vulnerability.Description === 'string' && vulnerability.Description !== ''
          ? { description: vulnerability.Description }
          : {}),
        ...(typeof vulnerability.PrimaryURL === 'string' ? { url: vulnerability.PrimaryURL } : {})
      });
    }
    // Secrets baked into layers (e.g. an .npmrc token) are a hard BLOCK and are
    // never break-glass eligible — a leaked credential has no "accept" path.
    for (const secret of result.Secrets ?? []) {
      assert(typeof secret.RuleID === 'string', 'Trivy secret finding lacks a RuleID');
      findings.push({
        source: 'trivy',
        id: secret.RuleID,
        severity: 'critical',
        action: 'BLOCK_DEPLOY',
        policyRule: 'image.secret',
        reason: `secret detected in image layer (${secret.Title ?? secret.RuleID})`,
        // Trivy's own rating (the gate classifies every image secret critical),
        // and where inside the IMAGE it was found — not a repository path.
        ...(typeof secret.Severity === 'string' ? { scannerSeverity: secret.Severity } : {}),
        ...(typeof secret.Title === 'string' && secret.Title !== '' ? { title: secret.Title } : {}),
        ...(typeof result.Target === 'string' ? { target: result.Target } : {})
      });
    }
  }

  const blockDeploy = findings.filter((finding) => finding.action === 'BLOCK_DEPLOY').length;
  const exception = findings.filter((finding) => finding.action === 'EXCEPTION').length;
  const log = findings.filter((finding) => finding.action === 'LOG').length;
  return {
    // Three-state, mirroring the dependency gate: an unfixable Critical/High is a
    // tracked EXCEPTION (deploy proceeds) rather than a permanent block.
    verdict:
      blockDeploy > 0 ? 'BLOCK_DEPLOY' : exception > 0 ? 'DEPLOY-WITH-EXCEPTIONS' : 'DEPLOY',
    summary: { blockDeploy, exception, log },
    exceptions: findings.filter((finding) => finding.action === 'EXCEPTION'),
    image: {
      // The config digest Trivy scanned — the anchor of the build->push->deploy
      // digest chain (see docs/aws-setup.md §digest chaining).
      imageId: report.Metadata.ImageID,
      os: { family: osFamily, name: report.Metadata.OS?.Name, eosl: report.Metadata.OS?.EOSL === true },
      // Scan time; Trivy's vuln-DB timestamp is printed to stderr, not the JSON,
      // so it is not available to record here.
      scannedAt: report.CreatedAt ?? null
    },
    findings
  };
}

async function writeResult(path, result) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(result, null, 2)}\n`);
}

export async function runImageGate(customPaths = {}) {
  const paths = { source: DEFAULT_SOURCE, ...DEFAULT_PATHS, ...customPaths };
  let result;

  try {
    const policy = parseSimplePolicy(await readFile(paths.policy, 'utf8'));
    validatePolicy(policy);
    const report = await readJson(paths.report);
    result =
      paths.source === 'trivy'
        ? evaluateTrivy(policy, report)
        : evaluate(policy, report);
    result.integrity = summarizeIntegrity(result.findings);
  } catch (error) {
    const integrityFinding = {
      source: 'image-gate',
      id: 'report-integrity',
      severity: 'unknown',
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.report_integrity',
      reason: error.message
    };
    result = {
      verdict: 'BLOCK_DEPLOY',
      summary: { blockDeploy: 1, log: 0 },
      integrity: summarizeIntegrity([integrityFinding]),
      findings: [integrityFinding]
    };
  }

  await writeResult(paths.output, result);
  return result;
}

function parseArguments(arguments_) {
  const aliases = {
    '--policy': 'policy',
    '--report': 'report',
    '--output': 'output',
    '--source': 'source'
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

// ---- console output -----------------------------------------------------------
//
// PRESENTATION ONLY. The written JSON is the complete record; the console is a
// bounded pointer to it. A real image routinely carries hundreds of findings,
// so the log gets the verdict, the recorded counts, a short deterministic
// blocker preview with its exact omission, and the path to the full result.
// Integrity failures and image secrets are always printed in full: an
// integrity failure may be the only evidence there is, and a secret must never
// be hidden behind a vulnerability preview.

export const CONSOLE_PREVIEW_LIMIT = 5;

const CONSOLE_SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

const isIntegrity = (finding) =>
  finding.id === 'report-integrity' ||
  (typeof finding.policyRule === 'string' && finding.policyRule.endsWith('report_integrity'));

function consoleLine(finding) {
  const pkg = typeof finding.package === 'string' && finding.package !== '' ? ` ${finding.package}` : '';
  const installed = pkg && typeof finding.installedVersion === 'string' ? ` ${finding.installedVersion}` : '';
  const fixed = pkg && typeof finding.fixedVersion === 'string' ? ` -> ${finding.fixedVersion}` : '';
  const where = finding.policyRule === 'image.secret' && typeof finding.target === 'string' ? ` in ${finding.target}` : '';
  return `  ${String(finding.severity).toUpperCase()} ${finding.id}${pkg}${installed}${fixed}${where} (${finding.policyRule})`;
}

export function consoleSummary(result, outputPath) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const summary = result.summary ?? {};
  const lines = [`IMAGE GATE: ${result.verdict}`];

  const integrity = findings.filter(isIntegrity);
  for (const finding of integrity) {
    lines.push(`INTEGRITY FAILURE (${finding.policyRule}): ${finding.reason}`);
  }
  if (integrity.length > 0) {
    lines.push('The image scan could not be trusted: results are UNKNOWN, not clean.');
  }

  // The counts exactly as recorded in the result's `summary`.
  const counts = [`${summary.blockDeploy ?? 0} blocking`];
  if (Object.hasOwn(summary, 'exception')) counts.push(`${summary.exception} exception`);
  counts.push(`${summary.log ?? 0} logged findings`);
  lines.push(counts.join(' · '));

  // Secrets first and never truncated, then Critical before High; ties break on
  // package, id and position so the preview is identical run to run.
  const blockers = findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => finding.action === 'BLOCK_DEPLOY' && !isIntegrity(finding));
  const secrets = blockers.filter(({ finding }) => finding.policyRule === 'image.secret');
  const vulnerabilities = blockers
    .filter(({ finding }) => finding.policyRule !== 'image.secret')
    .sort(
      (a, b) =>
        (CONSOLE_SEVERITY_RANK[a.finding.severity] ?? 9) - (CONSOLE_SEVERITY_RANK[b.finding.severity] ?? 9) ||
        String(a.finding.package ?? '').localeCompare(String(b.finding.package ?? '')) ||
        String(a.finding.id).localeCompare(String(b.finding.id)) ||
        a.index - b.index
    );
  const preview = vulnerabilities.slice(0, CONSOLE_PREVIEW_LIMIT);
  if (secrets.length + preview.length > 0) {
    lines.push(
      vulnerabilities.length > preview.length
        ? `Blocking (${secrets.length > 0 ? 'every secret, then ' : ''}the first ${preview.length} of ${vulnerabilities.length} vulnerabilities, Critical first):`
        : 'Blocking:'
    );
    for (const { finding } of [...secrets, ...preview]) {
      lines.push(consoleLine(finding));
    }
    const omitted = vulnerabilities.length - preview.length;
    if (omitted > 0) {
      lines.push(`  ... ${omitted} more blocking finding${omitted === 1 ? '' : 's'} not shown`);
    }
  }
  lines.push(`Full normalized findings: ${outputPath}`);
  return lines.join('\n');
}

async function main() {
  let paths;

  try {
    paths = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`IMAGE GATE: BLOCK_DEPLOY\n${error.message}`);
    process.exitCode = 1;
    return;
  }

  const result = await runImageGate(paths);
  console.log(consoleSummary(result, paths.output ?? DEFAULT_PATHS.output));
  process.exitCode = result.verdict === 'BLOCK_DEPLOY' ? 1 : 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
