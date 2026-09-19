// Shared developer-readable formatter for every pipeline failure point.
//
// One structured finding shape, three thin renderers (Slack Block Kit, PR
// comment markdown, and $GITHUB_STEP_SUMMARY markdown). Consistency is by
// construction: a change to the finding shape or the plain-language derivation
// updates every surface at once, because every surface reads the same
// normalized objects produced by `buildReport`.
//
// Input is the JSON a gate already wrote (reports/security-gate.json or
// reports/image-gate*.json) — the reviewed verdict is the source of truth. The
// formatter only makes that verdict legible to a developer who is not a
// security specialist; it never re-decides policy.
//
// EVIDENCE RULE: every sentence rendered here must be backed by a fact the gate
// recorded or the workflow observed. Where a value is the framework's own
// interpretation (a fail-closed default severity, a CVSS threshold), it is said
// to be the framework's, never attributed to the scanner. Where a fact was not
// observed (whether a break-glass request was sent, which Semgrep config held a
// rule), nothing is claimed.

import { correlateFindings, summarizeIssues } from './correlate-findings.mjs';
import { versionKey } from './dependency-evidence.mjs';
import { RECORDED_SCANNERS } from './scanner-execution.mjs';
import { deriveScanControlResults, SCAN_CONTROLS } from './source-control-results.mjs';

export const PR_COMMENT_MARKER = '<!-- security-gate-findings -->';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 };

// Verdict -> how the header reads on every surface. Each verdict is visibly
// distinct (label + emoji + one-line meaning) so BLOCK, EXCEPTION and a clean
// pass are never confused with one another.
const VERDICTS = {
  PASS: { emoji: '✅', label: 'PASS', blurb: 'No blocking security findings.' },
  'PASS-WITH-EXCEPTIONS': {
    emoji: '⚠️',
    label: 'EXCEPTION',
    blurb: 'Passed with tracked exceptions — Critical/High findings with no fix available.'
  },
  BLOCK: { emoji: '⛔', label: 'BLOCK', blurb: 'Blocking security findings must be resolved before merge.' },
  DEPLOY: { emoji: '✅', label: 'DEPLOY', blurb: 'Image cleared for deploy.' },
  'DEPLOY-WITH-EXCEPTIONS': {
    emoji: '⚠️',
    label: 'DEPLOY-WITH-EXCEPTIONS',
    blurb: 'Deploying with tracked image exceptions — Critical/High with no fix available.'
  },
  BLOCK_DEPLOY: { emoji: '⛔', label: 'BLOCK_DEPLOY', blurb: 'Blocking image findings must be resolved before deploy.' }
};

const isBlockingVerdict = (verdict) => verdict === 'BLOCK' || verdict === 'BLOCK_DEPLOY';

// How a developer reproduces a finding locally. Telling someone in another repo
// to run `make sast` when they have no Makefile is worse than telling them
// nothing, so the defaults are direct scanner invocations that hold anywhere. A
// repo with its own wrapper overrides them through the `reproduce_commands`
// workflow input -> SECURITY_REPRODUCE_COMMANDS.
//
// Semgrep, the registry scanners and the config-aware secret scanners are NOT
// static here: their honest command depends on what this run actually scanned
// with (see reproduceCommand). A generic `--config p/owasp-top-ten` does not
// reproduce a finding from a local rule file, so none is offered.
export const DEFAULT_REPRODUCE_COMMANDS = {
  gitleaks: 'gitleaks git . --redact=100',
  trufflehog: 'trufflehog git file://. --results=verified,unverified,unknown',
  'npm-audit': 'npm audit --package-lock-only',
  'pip-audit': 'pip-audit --requirement requirements.txt --no-deps',
  'osv-scanner': 'osv-scanner scan source --recursive .',
  trivy: 'trivy image --input <image.tar> --scanners vuln,secret --pkg-types os,library'
};

// Parses the SECURITY_REPRODUCE_COMMANDS override. Malformed JSON falls back to
// the portable defaults rather than crashing the notifier — this is developer
// guidance, never a gate input, so it must never be able to fail a run.
export function resolveReproduceCommands(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return DEFAULT_REPRODUCE_COMMANDS;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return DEFAULT_REPRODUCE_COMMANDS;
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return DEFAULT_REPRODUCE_COMMANDS;
  }

  const overrides = Object.fromEntries(
    Object.entries(parsed).filter(([, value]) => typeof value === 'string' && value !== '')
  );
  return { ...DEFAULT_REPRODUCE_COMMANDS, ...overrides };
}

// Shell-quote a value only when it needs it, so ordinary commands stay readable.
function shellArg(value) {
  return /^[A-Za-z0-9_./:=@+-]+$/.test(value) ? value : `'${String(value).replaceAll("'", "'\\''")}'`;
}

// The command that reproduces THIS finding, from what the run actually used.
// An explicit per-repo override always wins. Returns null rather than a command
// that would not reproduce the finding.
function reproduceCommand(finding, context, gate) {
  const commands = context?.reproduceCommands || DEFAULT_REPRODUCE_COMMANDS;
  const configured = commands[finding.source];
  const overridden =
    typeof configured === 'string' && configured !== DEFAULT_REPRODUCE_COMMANDS[finding.source];
  if (overridden) {
    return configured;
  }
  const scan = context?.scan || {};

  switch (finding.source) {
    case 'gitleaks':
      return scan.gitleaksConfig
        ? `gitleaks git . --config ${shellArg(scan.gitleaksConfig)} --redact=100`
        : DEFAULT_REPRODUCE_COMMANDS.gitleaks;
    case 'trufflehog':
      return scan.trufflehogExcludePaths
        ? `${DEFAULT_REPRODUCE_COMMANDS.trufflehog} --exclude-paths=${shellArg(scan.trufflehogExcludePaths)}`
        : DEFAULT_REPRODUCE_COMMANDS.trufflehog;
    case 'semgrep': {
      // Exactly the configs and paths this run scanned with, when the workflow
      // passed them. This reproduces registry and local rules alike.
      if (Array.isArray(scan.semgrepConfigs) && scan.semgrepConfigs.length > 0) {
        const configs = scan.semgrepConfigs.map((config) => `--config ${shellArg(config)}`).join(' ');
        const paths =
          Array.isArray(scan.semgrepPaths) && scan.semgrepPaths.length > 0
            ? scan.semgrepPaths.map(shellArg).join(' ')
            : '.';
        return `semgrep scan ${configs} ${paths}`;
      }
      // Without the run's configs, only a rule with Registry evidence can be
      // named precisely; a local rule's config file is unknown here.
      const registryId = finding.registryUrl?.match(/^https:\/\/semgrep\.dev\/r\/(.+)$/)?.[1];
      return registryId ? `semgrep scan --config r/${registryId} .` : null;
    }
    case 'trivy':
      return scan.imageTarball
        ? `trivy image --input ${shellArg(scan.imageTarball)} --scanners vuln,secret --pkg-types os,library`
        : DEFAULT_REPRODUCE_COMMANDS.trivy;
    case 'ecr-image-scan':
    case 'ecr-enhanced-scan': {
      // The registry result for the exact digest the gate judged. A local Trivy
      // scan is a different scanner and would not reproduce this finding.
      const repository = gate?.image?.repository;
      const digest = gate?.image?.imageDigest;
      return repository && digest
        ? `aws ecr describe-image-scan-findings --repository-name ${shellArg(repository)} --image-id imageDigest=${shellArg(digest)}`
        : null;
    }
    default:
      return typeof configured === 'string' ? configured : null;
  }
}

function titleCase(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function locationParts(location) {
  if (typeof location !== 'string' || location === '') {
    return null;
  }
  // Findings encode location as "path:line"; the line may be "?" when unknown.
  const lastColon = location.lastIndexOf(':');
  if (lastColon === -1) {
    return { path: location, line: null };
  }
  const path = location.slice(0, lastColon);
  const rawLine = location.slice(lastColon + 1);
  const line = /^\d+$/.test(rawLine) ? Number(rawLine) : null;
  return { path, line };
}

// Only these sources record a REPOSITORY path. An image-layer path or a package
// name must never be turned into a link into the repository.
const REPOSITORY_LOCATED_SOURCES = new Set(['semgrep', 'gitleaks', 'trufflehog']);

function deepLink(context, place, source) {
  if (!place || !context?.repository || !context?.sha || !REPOSITORY_LOCATED_SOURCES.has(source)) {
    return null;
  }
  const anchor = place.line ? `#L${place.line}` : '';
  return `https://github.com/${context.repository}/blob/${context.sha}/${place.path}${anchor}`;
}

function sentence(text) {
  const value = String(text ?? '').trim();
  return value === '' || /[.!?]$/.test(value) ? value : `${value}.`;
}

function list(values) {
  return values.map((value) => `\`${value}\``).join(', ');
}

// Critical/High with no fix -> EXCEPTION. The gate knows fix availability; it
// does NOT know whether this change introduced the finding, so that is not said.
const EXCEPTION_FIX =
  'No fix is available according to the scanner data, so policy records this Critical/High finding as a tracked ' +
  'EXCEPTION instead of a block. It is reported on every run, and will block once a fix becomes available.';

// Ecosystem-appropriate upgrade example. Only npm and PyPI have a command the
// framework can state with confidence; anything else gets no invented command.
function upgradeExample(ecosystem, pkg, version) {
  if (ecosystem === 'npm') {
    return `\`npm install ${pkg}${version ? `@${version}` : ''}\` (then commit the lockfile)`;
  }
  if (ecosystem === 'PyPI') {
    return `\`pip install '${pkg}${version ? `==${version}` : ''}'\` (then update your pinned requirements)`;
  }
  return null;
}

function maliciousCard(base, finding, scannerLabel) {
  return {
    ...base,
    kind: 'malicious-package',
    severity: 'critical',
    title: `Known-malicious package \`${finding.package || finding.id}\` (${finding.id})`,
    whatItMeans:
      `${scannerLabel} matched a malicious-package advisory (${finding.id}): the package itself is malicious, ` +
      'not merely vulnerable. Policy blocks it regardless of severity.',
    severityNote: 'Severity does not apply — malicious-package advisories block unconditionally.',
    howToFix:
      'Remove the package, and treat any machine or CI environment that installed it as potentially compromised. ' +
      'Policy never allows break-glass for a malicious package.'
  };
}

// Turn one decided gate finding into a surface-agnostic, plain-language card.
function classify(finding, context, gate) {
  const severity = (finding.severity || 'none').toLowerCase();
  const place = locationParts(finding.location);
  const isException = finding.action === 'EXCEPTION';

  const base = {
    id: finding.id,
    source: finding.source,
    severity,
    action: finding.action,
    policyRule: finding.policyRule,
    package: finding.package || null,
    isException,
    isIntegrity: false,
    location: place,
    deepLink: deepLink(context, place, finding.source),
    target: null,
    reproduce: reproduceCommand(finding, context, gate),
    fixAvailable: finding.fixAvailable,
    fixedVersion: finding.fixedVersion || null,
    referenceUrl: finding.url || null,
    severityNote: null,
    evidenceNote: null
  };

  // Report-integrity: a fail-closed BLOCK that is NOT a vulnerability. Say so
  // plainly so a developer does not hunt for code they never wrote, and never
  // offer a reproduce command for a finding that does not exist.
  if (finding.policyRule?.endsWith('report_integrity') || finding.id === 'report-integrity') {
    return {
      ...base,
      kind: 'integrity',
      isIntegrity: true,
      severity: 'unknown',
      reproduce: null,
      fixAvailable: undefined,
      fixedVersion: null,
      title: 'Scan integrity failure — results are UNKNOWN, not clean',
      whatItMeans:
        `${sentence(finding.reason)} A scanner or its report could not be interpreted, so this run's results cannot be ` +
        'trusted. The gate fails closed (blocks) rather than treating an uninterpretable scan as clean. ' +
        'This is not a vulnerability finding.',
      howToFix:
        'Diagnose the scanner/report step named above in the run log — a missing, empty or malformed report, ' +
        'scanner errors, or an undetected or end-of-life base-image OS — then re-run. Do not generate or update a ' +
        'baseline from this run. An integrity failure can never be overridden with break-glass.'
    };
  }

  switch (finding.source) {
    case 'gitleaks': {
      if (finding.policyRule === 'secrets.demo_dummy') {
        return {
          ...base,
          kind: 'secret',
          title: `Demo marker detected (\`${finding.id}\`) — not a real credential`,
          whatItMeans:
            'The dedicated, inert demo marker is active. Policy blocks it so a demo exercises the BLOCK path; it is ' +
            'not a credential and nothing was verified with any provider.',
          evidenceNote: 'Verification: none — this is a fixed demo marker, not a detected credential.',
          howToFix:
            'This belongs only on a never-merged demo branch. Remove the marker (or do not merge the branch); ' +
            'there is nothing to rotate.'
        };
      }
      return {
        ...base,
        kind: 'secret',
        title: `Potential secret — unverified pattern match (Gitleaks rule \`${finding.id}\`)`,
        whatItMeans:
          `Gitleaks rule \`${finding.id}\` matched${finding.ruleDescription ? ` (${finding.ruleDescription})` : ''}. ` +
          'Gitleaks matches patterns and does not check credentials with their provider, so this may or may not ' +
          'be a real, live secret.',
        evidenceNote: 'Verification: not verified — Gitleaks does not verify credentials.',
        howToFix:
          'Check whether it is a real credential. If it is, revoke/rotate it at the provider first, then remove it ' +
          '(it stays in git history until history is rewritten). If it is a false positive, add its fingerprint to ' +
          '`.gitleaksignore`, add an allowlist to your Gitleaks config, or mark the line with a `gitleaks:allow` comment.'
      };
    }
    case 'trufflehog': {
      const verified = finding.policyRule === 'secrets.verified';
      if (verified) {
        return {
          ...base,
          kind: 'secret',
          title: `Verified live credential (TruffleHog detector \`${finding.id}\`)`,
          whatItMeans:
            'TruffleHog verified this credential with its provider: it was live when scanned. Treat it as compromised.',
          evidenceNote: 'Verification: verified by TruffleHog with the provider.',
          howToFix:
            'Revoke/rotate the credential at the provider now, then remove it from the code and from git history. ' +
            'Policy never allows break-glass for a verified secret.'
        };
      }
      return {
        ...base,
        kind: 'secret',
        title: `Potential credential — not verified (TruffleHog detector \`${finding.id}\`)`,
        whatItMeans:
          `TruffleHog's \`${finding.id}\` detector matched, but the credential was not confirmed with its provider` +
          `${finding.verificationErrored ? ' (verification was attempted and errored)' : ''}. ` +
          'It may be inactive, a test value, or a false positive.',
        evidenceNote: finding.verificationErrored
          ? 'Verification: not verified — the verification attempt errored.'
          : 'Verification: not verified.',
        howToFix:
          'Check whether it is a real credential; if so, rotate it and remove it from the code and history. If the ' +
          'match is expected, add a `trufflehog:ignore` comment on the line, or add a path regex to your TruffleHog ' +
          `exclude-paths file (\`${context?.scan?.trufflehogExcludePaths || '.trufflehog-exclude-paths.txt'}\`).`
      };
    }
    case 'npm-audit': {
      const pkg = finding.package || finding.id;
      const advisory = finding.title
        ? `npm advisory: ${finding.title}.`
        : Array.isArray(finding.viaPackages) && finding.viaPackages.length > 0
          ? `npm audit flags \`${pkg}\` because it depends on vulnerable ${list(finding.viaPackages)}.`
          : `npm audit reports a ${severity}-severity advisory affecting \`${pkg}\`.`;
      let howToFix;
      if (isException) {
        howToFix = EXCEPTION_FIX;
      } else if (finding.fixAvailable === false) {
        howToFix = 'npm audit reports no fix available yet.';
      } else if (finding.fixPackage && finding.fixedVersion) {
        const major = finding.fixIsSemVerMajor ? ' This is a semver-major change — review it for breaking changes.' : '';
        howToFix =
          finding.fixPackage === pkg
            ? `npm resolves this by updating \`${pkg}\` to ${finding.fixedVersion}, e.g. ${upgradeExample('npm', pkg, finding.fixedVersion)}.${major}`
            : `npm resolves this by updating \`${finding.fixPackage}\` to ${finding.fixedVersion}, which pulls in a fixed \`${pkg}\` — e.g. ${upgradeExample('npm', finding.fixPackage, finding.fixedVersion)}.${major}`;
      } else {
        howToFix =
          'npm audit reports a fix is available but did not name a target version. Run `npm audit fix` and review the lockfile change.';
      }
      return {
        ...base,
        kind: 'dependency',
        title: `${titleCase(severity)}-severity npm advisory for dependency \`${pkg}\``,
        whatItMeans: advisory,
        howToFix
      };
    }
    case 'pip-audit': {
      if (finding.policyRule === 'dependencies.malicious_package') {
        return maliciousCard(base, finding, 'pip-audit');
      }
      const pkg = finding.package || finding.id;
      const installed = finding.installedVersion ? ` ${finding.installedVersion}` : '';
      const fixVersions = Array.isArray(finding.fixVersions) ? finding.fixVersions : [];
      const aliases = Array.isArray(finding.aliases) && finding.aliases.length > 0 ? ` (aliases: ${finding.aliases.join(', ')})` : '';
      return {
        ...base,
        kind: 'dependency',
        fixedVersion: fixVersions[0] || null,
        title: `Python advisory ${finding.id} for dependency \`${pkg}\`${installed}`,
        whatItMeans: `pip-audit reports advisory ${finding.id}${aliases} affecting \`${pkg}\`${installed}.`,
        severityNote:
          'Severity: pip-audit reports no severity. The framework classifies every pip-audit advisory as high ' +
          '(fail-closed); this is not a severity pip-audit assigned.',
        howToFix: isException
          ? EXCEPTION_FIX
          : fixVersions.length > 0
            ? `pip-audit lists fixed version(s): ${fixVersions.join(', ')}. Upgrade, e.g. ${upgradeExample('PyPI', pkg, fixVersions[0])}.`
            : 'pip-audit lists no fixed version.'
      };
    }
    case 'osv-scanner': {
      if (finding.policyRule === 'dependencies.malicious_package') {
        return maliciousCard(base, finding, 'OSV-Scanner');
      }
      const pkg = finding.package || finding.id;
      const installed = finding.installedVersion ? ` ${finding.installedVersion}` : '';
      const ecosystem = finding.ecosystem ? `${finding.ecosystem} ` : '';
      const fixVersions = Array.isArray(finding.fixVersions) ? finding.fixVersions : [];
      const aliases = Array.isArray(finding.aliases) && finding.aliases.length > 0 ? ` (aliases: ${finding.aliases.join(', ')})` : '';
      // `cvssScore` present means the severity came from the record's CVSS v3
      // score via policy thresholds; absent means the fail-closed default.
      const severityNote =
        typeof finding.cvssScore === 'number'
          ? `Severity: classified ${severity} by the framework's CVSS thresholds from the record's CVSS v3 base score ${finding.cvssScore}.`
          : 'Severity: the OSV record carries no CVSS v3 score. The framework classifies it as high (fail-closed); ' +
            'this is not a severity OSV assigned.';
      let howToFix;
      if (isException) {
        howToFix = EXCEPTION_FIX;
      } else if (fixVersions.length > 0) {
        const example = upgradeExample(finding.ecosystem, pkg, null);
        howToFix =
          `OSV records a fix in version(s): ${fixVersions.join(', ')}. Upgrade \`${pkg}\` to a fixed version on a ` +
          `release line that includes the fix${example ? ` — e.g. ${example} with the chosen version` : ''}.`;
      } else if (finding.fixAvailable === false) {
        howToFix = `OSV records no fixed version for \`${pkg}\`.`;
      } else {
        howToFix = `Upgrade \`${pkg}\` to a version outside the affected range.`;
      }
      return {
        ...base,
        kind: 'dependency',
        fixedVersion: null,
        referenceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(finding.id)}`,
        title: `${titleCase(severity)}-severity advisory ${finding.id} in ${ecosystem}dependency \`${pkg}\`${installed}`,
        whatItMeans: finding.summary
          ? `${finding.summary}${aliases}`
          : `OSV advisory ${finding.id}${aliases} affects \`${pkg}\`${installed}.`,
        severityNote,
        howToFix
      };
    }
    case 'semgrep': {
      const path = place?.path || 'the scanned code';
      const state =
        {
          new: 'New',
          existing: 'Baseline-known',
          unbaselined: 'Unbaselined'
        }[finding.baselineState] || '';
      const raw = typeof finding.scannerSeverity === 'string' ? finding.scannerSeverity : null;
      const severityNote =
        raw && raw.toLowerCase() !== severity
          ? `Severity: Semgrep reported ${raw}; policy maps it to ${severity}.`
          : null;
      const ruleFact = finding.registryUrl
        ? `Semgrep Registry rule \`${finding.id}\`: ${finding.registryUrl}`
        : `Rule \`${finding.id}\` carries no Semgrep Registry metadata, so it is not linked to the Registry — it comes from a non-registry config such as a local rules file.`;
      return {
        ...base,
        kind: 'sast',
        title: `${state ? `${state} ` : ''}${severity}-severity code security issue in \`${path}\``,
        whatItMeans: finding.message || `Semgrep rule \`${finding.id}\` flagged this code as a likely security issue.`,
        severityNote,
        evidenceNote: ruleFact,
        howToFix: isException ? EXCEPTION_FIX : 'Review the flagged code and remediate the pattern the rule describes.'
      };
    }
    case 'trivy': {
      if (finding.policyRule === 'image.secret') {
        const where = finding.target ? ` in \`${finding.target}\`` : '';
        return {
          ...base,
          kind: 'image-secret',
          target: finding.target || null,
          title: `Potential secret in an image layer (Trivy rule \`${finding.id}\`)`,
          whatItMeans:
            `Trivy's secret scanner matched rule \`${finding.id}\`${finding.title ? ` (${finding.title})` : ''}${where} ` +
            'inside the built image. Trivy matches patterns and does not verify secrets with their provider.',
          severityNote: finding.scannerSeverity
            ? `Severity: Trivy rated it ${finding.scannerSeverity}; policy blocks every secret found in an image.`
            : 'Severity: policy blocks every secret found in an image.',
          evidenceNote: 'Verification: not verified — Trivy does not verify secrets.',
          howToFix:
            'Remove the file or value from the build (do not COPY credentials into layers; use build secrets or runtime ' +
            'injection) and rebuild. If it is a real credential, rotate it. An image finding has no break-glass path.'
        };
      }
      const pkg = finding.package || finding.id;
      const installed = finding.installedVersion ? ` ${finding.installedVersion}` : '';
      const unknownSeverity = typeof finding.scannerSeverity === 'string' && finding.scannerSeverity.toUpperCase() === 'UNKNOWN';
      return {
        ...base,
        kind: 'image-trivy',
        target: finding.target || null,
        title: `${titleCase(severity)}-severity vulnerability ${finding.id} in image package \`${pkg}\`${installed}`,
        whatItMeans: finding.title || finding.description || `Trivy reports ${finding.id} in image package \`${pkg}\`${installed}.`,
        severityNote: unknownSeverity
          ? 'Severity: Trivy reported UNKNOWN. The framework classifies it as high (fail-closed); this is not a severity Trivy assigned.'
          : null,
        howToFix: isException
          ? EXCEPTION_FIX
          : finding.fixedVersion
            ? `Trivy reports a fix in ${finding.fixedVersion}. Upgrade \`${pkg}\`, or move to a base image that ships the fixed package, then rebuild.`
            : `Trivy reports no fixed version for \`${pkg}\` yet.`
      };
    }
    case 'ecr-enhanced-scan': {
      const packages = Array.isArray(finding.packages) ? finding.packages : [];
      const pkgLabel = packages.length > 0
        ? [...new Set(packages.map((pkg) => pkg.name))].join(', ')
        : finding.package || null;
      const raw = typeof finding.scannerSeverity === 'string' ? finding.scannerSeverity : null;
      const severityNote =
        raw && raw.toLowerCase() !== severity
          ? `Severity: Amazon Inspector reported ${raw}; the framework classifies it as ${severity}.`
          : null;
      const fixes = packages.filter((pkg) => pkg.fixedInVersion);
      let howToFix;
      if (isException) {
        howToFix = EXCEPTION_FIX;
      } else if (fixes.length > 0) {
        const detail = fixes
          .map((pkg) => `\`${pkg.name}\`${pkg.version ? ` ${pkg.version}` : ''} → ${pkg.fixedInVersion}`)
          .join('; ');
        howToFix = `Amazon Inspector reports fixed version(s): ${detail}. Upgrade, or move to a base image that ships the fix, then rebuild.`;
      } else if (finding.fixAvailable === true) {
        howToFix = 'Amazon Inspector reports a fix is available but named no fixed version. Upgrade the affected package or base image.';
      } else {
        howToFix = 'Amazon Inspector reports no fix available.';
      }
      if (!isException && finding.fixAvailability === 'PARTIAL') {
        howToFix += ' Inspector reports the fix as PARTIAL (not every affected package has one); policy treats that as fix-available.';
      }
      return {
        ...base,
        kind: 'image-ecr-enhanced',
        package: pkgLabel,
        title: `${titleCase(severity)}-severity vulnerability ${finding.id} in image${pkgLabel ? ` package \`${pkgLabel}\`` : ''} (Amazon Inspector)`,
        whatItMeans: finding.title || `Amazon Inspector reports ${finding.id} in the pushed image.`,
        severityNote,
        howToFix
      };
    }
    case 'ecr-image-scan': {
      // ECR basic scanning supplies an id and a severity — nothing else.
      return {
        ...base,
        kind: 'image-ecr',
        fixAvailable: undefined,
        fixedVersion: null,
        title: `${titleCase(severity)}-severity finding ${finding.id} in image (ECR basic scanning)`,
        whatItMeans:
          `ECR basic scanning reports ${finding.id}. Basic scanning supplies only a vulnerability ID and severity — ` +
          'no package, installed version, or fix information — so policy blocks Critical/High regardless of fix availability.',
        howToFix:
          'ECR basic scanning does not report which package is affected or whether a fix exists. Identify the package ' +
          '(a Trivy scan of the same image, or ECR enhanced scanning, reports package and fixed version), then upgrade ' +
          'that package or the base image.'
      };
    }
    default:
      return {
        ...base,
        kind: 'other',
        title: `${titleCase(severity)} finding ${finding.id}`,
        whatItMeans: finding.message || finding.summary || finding.title || finding.reason || '',
        howToFix: isException ? EXCEPTION_FIX : finding.reason || ''
      };
  }
}

// ---- correlated issues --------------------------------------------------------
//
// Cards above are one per RAW finding. A developer, though, fixes vulnerabilities,
// not scanner records: pip-audit's PYSEC-2026-2275 and OSV-Scanner's
// PYSEC-2026-2275 and GHSA-gc5v-m9x4-r6x2 for the same `requests` are one thing to
// upgrade. correlate-findings.mjs groups records whose identity is proven by
// package scope + advisory ids/aliases; here a group of more than one record is
// rendered as ONE card that keeps every record's own evidence visible: which
// scanner, which id, which action, and how its severity was derived. Nothing is
// averaged, and the least severe interpretation is never chosen — the issue takes
// the strongest action any record received.

const SCANNER_LABELS = { 'pip-audit': 'pip-audit', 'osv-scanner': 'OSV-Scanner' };

function scannerLabel(source) {
  return SCANNER_LABELS[source] || source;
}

// How THIS record's severity came to be, attributed to whoever decided it.
function severityDerivation(finding) {
  if (finding.policyRule === 'dependencies.malicious_package') {
    return 'malicious-package advisory; severity does not apply (always blocks)';
  }
  const severity = (finding.severity || 'unknown').toLowerCase();
  if (finding.source === 'pip-audit') {
    return `severity unavailable from pip-audit; framework classifies ${severity} (fail-closed)`;
  }
  if (typeof finding.cvssScore === 'number') {
    return `CVSS v3 base score ${finding.cvssScore} from the OSV record; framework classifies ${severity} by policy thresholds`;
  }
  if (finding.severitySource === 'framework-default') {
    return `no CVSS v3 score in the record; framework classifies ${severity} (fail-closed)`;
  }
  return `classified ${severity}`;
}

function recordFixVersions(finding) {
  if (Array.isArray(finding.fixVersions)) {
    return finding.fixVersions.filter((version) => typeof version === 'string' && version !== '');
  }
  return typeof finding.fixedVersion === 'string' && finding.fixedVersion !== '' ? [finding.fixedVersion] : [];
}

function correlatedCard(issue, members, memberCards, context, gate) {
  const pkg = issue.package;
  const versions = issue.installedVersions ?? [];
  const versionText = versions.length === 0 ? '' : ` ${versions.join(' / ')}`;
  const malicious = members.some((finding) => finding.policyRule === 'dependencies.malicious_package');
  const isException = issue.action === 'EXCEPTION';

  // One line per distinct record. Identical records (OSV-Scanner lists the same
  // package once per lockfile it was found in) are shown once, counted.
  const lines = new Map();
  for (const finding of members) {
    const fixes = recordFixVersions(finding);
    const key = [finding.source, finding.id, finding.installedVersion, finding.action, finding.policyRule, finding.cvssScore].join('\0');
    const existing = lines.get(key);
    if (existing) {
      existing.times += 1;
      continue;
    }
    lines.set(key, {
      times: 1,
      text:
        `${scannerLabel(finding.source)} / \`${finding.id}\`` +
        `${finding.installedVersion && versions.length > 1 ? ` (reported at ${finding.installedVersion})` : ''}` +
        ` → **${finding.action}** (\`${finding.policyRule}\`) — ${severityDerivation(finding)}` +
        `; ${fixes.length > 0 ? `fixed in ${fixes.join(', ')}` : 'no fixed version listed'}`
    });
  }
  const observedBy = [...lines.values()].map(({ text, times }) => (times > 1 ? `${text} (reported ${times}×)` : text));

  // Fixed versions with the scanners that list each, so provenance survives.
  const fixProvenance = new Map();
  for (const finding of members) {
    for (const version of recordFixVersions(finding)) {
      if (!fixProvenance.has(version)) fixProvenance.set(version, new Set());
      fixProvenance.get(version).add(scannerLabel(finding.source));
    }
  }
  const fixSummary = [...fixProvenance.entries()]
    .map(([version, sources]) => `${version} (${[...sources].join(', ')})`)
    .join('; ');

  const derivations = [...new Set(members.map((finding) => (finding.severity || 'unknown').toLowerCase()))];
  const strongest = members.filter((finding) => finding.action === issue.action);
  const strongestText = [...new Set(strongest.map((finding) => `${scannerLabel(finding.source)} / \`${finding.id}\``))].join(', ');
  // Only a DISAGREEMENT is worth a severity note. Records that agree need no
  // repeated policy explanation: each record's own derivation is listed under
  // "Observed by", and why records are grouped is stated once per report.
  const severityNote =
    derivations.length > 1
      ? `Severity: the records disagree (${derivations.join(' vs ')}), and each derivation is listed below as recorded. ` +
        `This issue takes the strongest policy action any record received — **${issue.action}**, from ${strongestText} — ` +
        'and discards no record\'s interpretation.'
      : null;

  const summary = members.map((finding) => finding.summary).find((value) => typeof value === 'string' && value !== '');
  const whatItMeans = summary
    ? sentence(summary)
    : `Advisory ${issue.primaryId} affects \`${pkg}\`, reported by ${members.length} scanner records.`;

  let howToFix;
  if (malicious) {
    howToFix =
      'Remove the package, and treat any machine or CI environment that installed it as potentially compromised. ' +
      'Policy never allows break-glass for a malicious package.';
  } else if (isException) {
    howToFix = EXCEPTION_FIX;
  } else if (fixProvenance.size === 1) {
    const [version] = fixProvenance.keys();
    const example = upgradeExample(issue.ecosystem, pkg, version);
    howToFix = `The records list fixed version ${version}. Upgrade \`${pkg}\` to it${example ? ` — e.g. ${example}` : ''}.`;
  } else if (fixProvenance.size > 1) {
    howToFix =
      `The records list fixed versions ${[...fixProvenance.keys()].join(', ')}. Upgrade \`${pkg}\` to a fixed version on a ` +
      'release line that includes the fix.';
  } else {
    howToFix = `No scanner record lists a fixed version for \`${pkg}\`.`;
  }

  const reproduceAll = [...new Set(memberCards.map((card) => card.reproduce).filter(Boolean))];
  const highest = issue.highestSeverity || 'unknown';

  return {
    id: issue.primaryId,
    source: issue.sources.join('+'),
    severity: malicious ? 'critical' : highest,
    action: issue.action,
    policyRule: strongest[0]?.policyRule,
    package: pkg,
    isException,
    isIntegrity: false,
    location: null,
    deepLink: null,
    target: null,
    reproduce: reproduceAll[0] || null,
    reproduceAll,
    fixAvailable: fixProvenance.size > 0 ? true : members.some((finding) => finding.fixAvailable === true),
    fixedVersion: fixProvenance.size === 1 ? [...fixProvenance.keys()][0] : null,
    referenceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(issue.primaryId)}`,
    kind: malicious ? 'malicious-package' : 'dependency',
    correlated: true,
    advisoryIds: issue.advisoryIds,
    observedBy,
    fixSummary: fixSummary || null,
    title: `${malicious ? 'Known-malicious package ' : ''}\`${pkg}\`${versionText} — ${issue.primaryId}`,
    whatItMeans,
    severityNote,
    evidenceNote: null,
    howToFix
  };
}

// ---- dependency evidence -----------------------------------------------------
//
// Every package-scoped issue carries `evidence` (dependency-evidence.mjs,
// docs/evidence-model.md). Its facts are rendered with their provenance and the
// remediation follows from them:
//
//   proven fact           stated plainly (a declaration in requirements.txt)
//   supported inference   stated with who said it and how they derived it
//   conflicting           every side shown; no version is presented as THE one
//   unknown               said to be unknown
//
// A pin command is offered only for a proven DIRECT dependency whose version
// evidence agrees and whose records name exactly one fixed version.

const PROVENANCE_VERBS = {
  'lockfile-resolved': 'read',
  'environment-observed': 'observed installed',
  'scanner-resolved': 'resolved',
  'scanner-inferred': 'reported',
  unknown: 'reported'
};

function observationLine(pkg, observation) {
  if (observation.provenance === 'manifest-declared') {
    return `\`${observation.source}\` declares \`${pkg}\` ${observation.version} (manifest-declared)`;
  }
  const from = observation.source ? ` from \`${observation.source}\`` : '';
  const verb = PROVENANCE_VERBS[observation.provenance] ?? 'reported';
  const version = observation.version ?? '(no version)';
  const advisory =
    observation.advisoryReported === true
      ? 'reported this advisory'
      : observation.advisoryReported === false
        ? 'reported no advisory for this issue'
        : null;
  return `${scannerLabel(observation.scanner)} ${verb} \`${pkg}\` ${version}${from} (${observation.provenance}${advisory ? `; ${advisory}` : ''})`;
}

function relationshipNote(pkg, evidence) {
  const { relationship, resolution } = evidence;
  if (relationship.value === 'direct') {
    const where = relationship.declarations
      .map((declaration) => `\`${declaration.manifest}\` (\`${declaration.requirement}\`)`)
      .join('; ');
    return `Dependency relationship: direct — declared in ${where}.`;
  }
  if (relationship.value === 'transitive') {
    const paths = relationship.dependencyPaths
      .map((entry) => `\`${entry.path.join(' -> ')}\` (from ${scannerLabel(entry.scanner)})`)
      .join('; ');
    return `Dependency relationship: transitive — dependency path: ${paths}.`;
  }
  const scanners = [...new Set(resolution.observations.filter((o) => o.scanner).map((o) => scannerLabel(o.scanner)))];
  const sources = [...new Set(resolution.observations.filter((o) => o.scanner && o.source).map((o) => `\`${o.source}\``))];
  const who = scanners.length === 1 ? scanners[0] : 'the scanners';
  const checked =
    relationship.manifestsChecked.length > 0
      ? ` \`${pkg}\` is not declared in ${relationship.manifestsChecked.map((path) => `\`${path}\``).join(', ')}; that alone does not prove it is transitive.`
      : '';
  return sources.length > 0
    ? `Dependency relationship: unknown — ${who} identified \`${pkg}\` while analyzing ${sources.join(', ')}, but the available reports do not prove which direct dependency introduced it.${checked}`
    : `Dependency relationship: unknown — the available reports do not record where \`${pkg}\` is declared or which dependency introduced it.`;
}

function resolutionNote(pkg, evidence) {
  const { resolution } = evidence;
  const lines = resolution.observations.map((observation) => observationLine(pkg, observation));
  if (resolution.status === 'conflicting') {
    const declared = resolution.observations.some((o) => o.provenance === 'manifest-declared');
    return {
      conflict: true,
      text:
        `Resolution conflict — the evidence disagrees on the effective version of \`${pkg}\`:` +
        lines.map((line) => `\n  - ${line}`).join('') +
        `\n  ${declared ? 'The manifest declaration and the scanner results disagree' : 'The scanners disagree'} on the effective package version. ` +
        'Treat this finding as a dependency-resolution discrepancy until a lockfile, build artifact, or environment ' +
        'observation establishes the version actually used.'
    };
  }
  if (resolution.status === 'unknown') {
    return { conflict: false, text: `Version: unknown — no record states which version of \`${pkg}\` is in use.` };
  }
  const head = `Version: \`${pkg}\` ${resolution.version} — consistent across the evidence (confidence: ${resolution.confidence})`;
  return {
    conflict: false,
    text: lines.length === 1 ? `${head}: ${lines[0]}.` : `${head}:${lines.map((line) => `\n  - ${line}`).join('')}`
  };
}

function fixProvenanceOf(members) {
  const provenance = new Map();
  for (const finding of members) {
    for (const version of recordFixVersions(finding)) {
      if (!provenance.has(version)) provenance.set(version, new Set());
      provenance.get(version).add(scannerLabel(finding.source));
    }
  }
  return provenance;
}

// What the records say about a fix, in the words each card used before.
function fixStatement(pkg, members, fixes) {
  if (members.length === 1) {
    const [finding] = members;
    const versions = [...fixes.keys()].join(', ');
    if (finding.source === 'pip-audit') {
      return fixes.size > 0 ? `pip-audit lists fixed version(s): ${versions}.` : 'pip-audit lists no fixed version.';
    }
    if (fixes.size > 0) {
      return `OSV records a fix in version(s): ${versions}.`;
    }
    return finding.fixAvailable === false ? `OSV records no fixed version for \`${pkg}\`.` : `No scanner record lists a fixed version for \`${pkg}\`.`;
  }
  return fixes.size > 0
    ? `The records list fixed version(s): ${[...fixes.entries()].map(([version, sources]) => `${version} (${[...sources].join(', ')})`).join('; ')}.`
    : `No scanner record lists a fixed version for \`${pkg}\`.`;
}

export function evidenceHowToFix(issue, members) {
  const { evidence } = issue;
  const pkg = issue.package;
  const fixes = fixProvenanceOf(members);
  const parts = [fixStatement(pkg, members, fixes)];
  const { relationship, resolution } = evidence;

  if (resolution.status === 'conflicting') {
    const owner =
      relationship.value === 'direct'
        ? `its declaration in ${[...new Set(relationship.declarations.map((d) => `\`${d.manifest}\``))].join(', ')}`
        : 'the dependency or constraint that brings it in';
    parts.push(
      `Do not pin \`${pkg}\` from this report: the evidence disagrees on which version is in use. First establish the ` +
        "version actually resolved — from a lockfile, the built artifact, or the installed environment, using the project's " +
        `normal dependency management — then, if that version is affected, remediate through ${owner}.`
    );
  } else if (fixes.size === 0) {
    // Nothing to upgrade to; the fix statement is the whole answer.
  } else if (relationship.value === 'direct') {
    const where = relationship.declarations.map((d) => `\`${d.manifest}\` (\`${d.requirement}\`)`).join('; ');
    const example = fixes.size === 1 ? upgradeExample(issue.ecosystem, pkg, [...fixes.keys()][0]) : null;
    parts.push(
      `Upgrade the direct declaration in ${where} to a fixed version${example ? ` — e.g. ${example}` : ' on a release line that includes the fix'}.`
    );
  } else if (relationship.value === 'transitive') {
    const parents = [...new Set(relationship.dependencyPaths.map((entry) => entry.path[0]))].map((name) => `\`${name}\``);
    parts.push(
      `\`${pkg}\` is a transitive dependency. Prefer updating the parent dependency ${parents.join(' or ')}, or your ` +
        `resolution constraints, so the resolver selects a fixed \`${pkg}\`. A direct pin on a transitive package is not the default remedy.`
    );
  } else {
    parts.push(
      `The reports do not prove how \`${pkg}\` enters the dependency tree, so no direct pin is suggested. Establish the ` +
        "version actually resolved and the dependency or constraint that introduces it — through the project's normal " +
        'dependency management (a lockfile or the resolver\'s output) — and remediate there so the resolver selects a fixed version.'
    );
  }
  return parts.join(' ');
}

function withDependencyEvidence(card, issue, members) {
  const { evidence } = issue;
  const pkg = issue.package;
  const resolution = resolutionNote(pkg, evidence);
  const malicious = members.some((finding) => finding.policyRule === 'dependencies.malicious_package');
  const next = {
    ...card,
    dependencyEvidence: evidence,
    relationshipNote: relationshipNote(pkg, evidence),
    resolutionNote: resolution.text,
    resolutionConflict: resolution.conflict
  };
  if (!malicious && issue.action !== 'EXCEPTION') {
    next.howToFix = evidenceHowToFix(issue, members);
  }
  if (resolution.conflict) {
    // No scanner-reported version is shown as THE version: each one moves out
    // of the headline and is attributed in the conflict note.
    const disputed = ` (effective version disputed: ${evidence.resolution.versions.join(' vs ')})`;
    let { title, whatItMeans } = next;
    if (card.correlated) {
      title = `${malicious ? 'Known-malicious package ' : ''}\`${pkg}\` — ${issue.primaryId}`;
    } else {
      for (const version of issue.installedVersions ?? []) {
        title = title.replaceAll(`\`${pkg}\` ${version}`, `\`${pkg}\``);
        whatItMeans = String(whatItMeans ?? '').replaceAll(`\`${pkg}\` ${version}`, `\`${pkg}\` (reported at ${version}; disputed)`);
      }
    }
    next.title = `${title}${disputed}`;
    next.whatItMeans = whatItMeans;
    next.fixedVersion = null;
  }
  return next;
}

// Issues over the raw cards. `cards[i]` is the card for `findings[i]`.
export function buildIssues(findings, cards, context = {}, gate = null) {
  return correlateFindings(findings, gate?.dependencyEvidence ?? null).map((issue) => {
    const members = issue.findings.map((index) => findings[index]);
    const memberCards = issue.findings.map((index) => cards[index]);
    let card = memberCards.length === 1 ? memberCards[0] : correlatedCard(issue, members, memberCards, context, gate);
    if (issue.evidence) {
      card = withDependencyEvidence(card, issue, members);
    }
    return { ...issue, card, cards: memberCards };
  });
}

// ---- break-glass state -------------------------------------------------------
//
// Facts kept distinct. Each later one requires evidence of its own and is NEVER
// inferred from an earlier one:
//   eligible            policy: the BLOCK consists only of eligible findings
//   enabled             the consumer set break_glass_enabled (null = not told)
//   requestPathEntered  the eligibility check passed. This proves only that the
//                       approval path began — a later transport/credential step
//                       can still stop it before any request is attempted.
//   requested           the "Request break-glass decision" step itself RAN
//                       (outcome success, failure, or cancelled mid-run)
//   delivered           that step succeeded: the broker accepted a pending request
//   delegated           the source workflow handed this eligible BLOCK to the
//                       separate Lambda break-glass workflow. Only ever set from
//                       the workflow's explicit delegation output. It is NOT
//                       delivery: this job cannot observe whether that other
//                       workflow runs or delivers, so delegation never
//                       suppresses the plain BLOCK alert (fail-safe: a duplicate
//                       alert is preferred over a silently lost one).
//   decision            approved | denied | expired | timeout |
//                       decision-unavailable | request-failed |
//                       request-not-attempted | not-requested | not-eligible |
//                       delegated | unknown | not-applicable
//
// Inputs are GitHub step outcomes ('success' | 'failure' | 'cancelled' |
// 'skipped' | '' when the step does not exist) and the decision artifact.
// `approved` is derived exactly as the job's enforcement step derives it — the
// poll step's outcome — so the feedback can never disagree with the verdict.
export function deriveBreakGlassState({
  verdict,
  eligible = false,
  mode = 'enforce',
  enabled = null,
  checkOutcome = '',
  requestOutcome = '',
  pollOutcome = '',
  request = null,
  decision = null,
  delegated = false
} = {}) {
  const state = {
    eligible: eligible === true,
    enabled: typeof enabled === 'boolean' ? enabled : null,
    requestPathEntered: false,
    requested: false,
    delivered: false,
    decision: 'not-applicable'
  };

  if (verdict !== 'BLOCK') {
    return state;
  }
  if (mode === 'log-only') {
    state.decision = 'not-requested';
    return state;
  }
  if (state.enabled === null) {
    // The notifier was not given the run's break-glass state. Claim nothing.
    state.decision = 'unknown';
    return state;
  }
  if (!state.enabled) {
    state.decision = 'not-requested';
    return state;
  }
  if (!state.eligible) {
    state.decision = 'not-eligible';
    return state;
  }
  if (delegated === true) {
    // Not a request outcome: this job made no request, and cannot see
    // whether the break-glass workflow will. Informational only — routing
    // still sends the plain BLOCK alert.
    state.delegated = true;
    state.decision = 'delegated';
    return state;
  }

  state.requestPathEntered = checkOutcome === 'success';
  // A step whose `if` was false (including an earlier step in the job failing)
  // reports 'skipped': it never ran, so no request was attempted.
  state.requested = state.requestPathEntered && ['success', 'failure', 'cancelled'].includes(requestOutcome);
  state.delivered = state.requested && requestOutcome === 'success';
  if (typeof request?.requestId === 'string' && state.delivered) {
    state.requestId = request.requestId;
  }

  if (!state.requested) {
    state.decision = 'request-not-attempted';
    return state;
  }
  if (!state.delivered) {
    // The poll step cannot have run, and any decision file present is not
    // evidence about THIS request — no denied/timeout is manufactured.
    state.decision = 'request-failed';
    return state;
  }
  if (pollOutcome === 'success') {
    state.decision = 'approved';
    if (typeof decision?.approver?.username === 'string') {
      state.approver = decision.approver.username;
    }
    return state;
  }
  const status = decision?.status;
  state.decision = ['denied', 'expired', 'timeout'].includes(status) ? status : 'decision-unavailable';
  return state;
}

// The one sentence every surface shows about break-glass, or null. Channel
// agnostic: the framework observes that the broker accepted the request, not
// which chat tool rendered it.
export function breakGlassNotice(state) {
  if (!state) return null;
  const request = state.requestId ? ` (request \`${state.requestId}\`)` : '';
  const entered = `This BLOCK entered break-glass review: an interactive approval request was sent successfully${request}.`;
  switch (state.decision) {
    case 'not-requested':
      if (!state.eligible) return null;
      return state.enabled === false
        ? '🔑 This BLOCK is eligible for break-glass by policy, but break-glass is not enabled for this repository. No approval request was made; the findings must be fixed.'
        : '🔑 This BLOCK is eligible for break-glass by policy, but `gate_mode` is log-only, so nothing is enforced and no approval request was made.';
    case 'unknown':
      return state.eligible
        ? '🔑 This BLOCK is eligible for break-glass by policy. This notifier was not given the run\'s break-glass state, so it makes no claim about whether an approval request was made.'
        : null;
    case 'delegated':
      return '🔑 This BLOCK is eligible for break-glass and was handed to the Lambda break-glass workflow in this run, which sends any approval request and reports the decision. This alert is sent regardless, because a hand-off is not a delivered request. Until a verified approval exists, the BLOCK stands.';
    case 'not-eligible':
      return '🔒 Break-glass is enabled, but this BLOCK is not eligible: it includes at least one finding policy never allows to be overridden. No approval request was made.';
    case 'request-not-attempted':
      return '⚠️ This BLOCK is eligible for break-glass and break-glass is enabled, but the approval path stopped before any request was attempted. No approval request was made and no override is active — check the break-glass steps in the run log.';
    case 'request-failed':
      return '⚠️ This BLOCK is eligible for break-glass. An approval request was attempted, but it failed and could not be confirmed as delivered. No override is active — check the break-glass steps in the run log.';
    case 'approved':
      return `✅ ${entered} A verified break-glass approval${state.approver ? ` by \`${state.approver}\`` : ''} overrode this BLOCK for this run.`;
    case 'denied':
      return `🚫 ${entered} Break-glass review was denied. The BLOCK remains enforced.`;
    case 'expired':
    case 'timeout':
      return `⏱️ ${entered} Break-glass review timed out without an authorized decision. The BLOCK remains enforced.`;
    case 'decision-unavailable':
      return `⚠️ ${entered} No verified decision could be retrieved, so no override is active. The BLOCK remains enforced.`;
    default:
      return null;
  }
}

// Notification routing. Returns which surfaces receive this report, and why
// Slack was or was not chosen.
//   BLOCK / BLOCK_DEPLOY / integrity  -> Slack + PR comment + summary
//   EXCEPTION-only verdict            -> PR comment + summary (visible, no ping)
//   clean PASS / DEPLOY               -> PR comment + summary (keeps a stale red
//                                        comment honest), no ping
//   gate_mode: log-only               -> never Slack (a LOG repo pages no one)
//   break-glass request DELIVERED     -> no plain Slack ping: the interactive
//                                        request already reached approvers.
// Eligibility alone never suppresses Slack. An eligible BLOCK whose repo has no
// break-glass, or whose request failed, still needs its normal alert.
// Routing never changes the verdict; it only chooses surfaces.
export function route({ verdict, mode = 'enforce', breakGlass = null }) {
  const blocking = isBlockingVerdict(verdict);
  let slack = blocking;
  let slackReason = blocking ? 'blocking-verdict' : 'non-blocking-verdict';
  if (blocking && mode === 'log-only') {
    slack = false;
    slackReason = 'log-only';
  } else if (blocking && breakGlass?.delivered === true) {
    slack = false;
    slackReason = 'break-glass-request-delivered';
  }
  // Deliberately NO suppression for a delegated BLOCK (breakGlass.decision ===
  // 'delegated'). Delegation is a hand-off to another workflow this job cannot
  // observe; if the caller skips or misconfigures it, suppressing here would
  // lose the only alert. A duplicate (this alert + the interactive request) is
  // the accepted, fail-safe cost until an orchestrator can observe delivery.
  return { slack, slackReason, prComment: true, summary: true };
}

// ---- presentation model -------------------------------------------------------
//
// The job summary, PR comment and Slack are TRIAGE surfaces, not the evidence
// database. `security-gate.json` (raw findings, correlation.issues[].evidence,
// dependencyEvidence, scannerExecution) stays complete; these surfaces show the
// few fields a developer acts on, in priority order, with bounded size.
//
// DISPOSITION IS PRESENTATION ONLY. Policy actions stay BLOCK / EXCEPTION / LOG
// on the raw findings and the verdict is computed from those alone. A
// disposition only chooses where an issue is shown:
//
//   BLOCK      the issue's strongest action is BLOCK / BLOCK_DEPLOY
//   EXCEPTION  the issue's strongest action is EXCEPTION
//   REVIEW     a LOG issue whose evidence explicitly disagrees with itself
//              (reviewReasons below). Non-blocking; shown with full detail.
//   INFO       any other LOG issue. Non-blocking; a table row only.
//
// No disposition is written to security-gate.json, so nothing downstream can
// mistake it for a policy action.

export const DISPOSITIONS = ['BLOCK', 'EXCEPTION', 'REVIEW', 'INFO'];
const DISPOSITION_RANK = { BLOCK: 0, EXCEPTION: 1, REVIEW: 2, INFO: 3 };
const DISPOSITION_LABELS = { BLOCK: '⛔ BLOCK', EXCEPTION: '⚠️ EXCEPTION', REVIEW: '⚖️ REVIEW', INFO: 'ℹ️ INFO' };

// Explicitly modeled evidence discrepancies. An `unknown` relationship is NOT a
// reason on its own: no current scanner report proves ancestry, so it is the
// normal state of every undeclared package (docs/evidence-model.md), and
// flagging it would turn REVIEW into noise.
export function reviewReasons(issue) {
  const reasons = [];
  if (issue?.evidence?.resolution?.status === 'conflicting') {
    reasons.push('version-conflict');
  }
  return reasons;
}

export function presentationDisposition(issue) {
  if (issue.action === 'EXCEPTION') return 'EXCEPTION';
  if (issue.action === 'LOG') return reviewReasons(issue).length > 0 ? 'REVIEW' : 'INFO';
  // BLOCK, BLOCK_DEPLOY, and anything unrecognized: fail toward visibility.
  return 'BLOCK';
}

const isMalicious = (finding) => finding.policyRule === 'dependencies.malicious_package';

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === 'string' && value !== ''))];
}

// version: the effective version and whether it is established. A disputed
// version is never returned as `version`.
export function versionStatus(issue, members) {
  const resolution = issue.evidence?.resolution;
  if (resolution) {
    if (resolution.status === 'conflicting') {
      return { status: 'conflicting', versions: resolution.versions, text: `conflict: ${resolution.versions.join(' / ')}` };
    }
    if (resolution.status === 'consistent') {
      return { status: 'consistent', version: resolution.version, text: resolution.version };
    }
    return { status: 'unknown', text: 'unknown' };
  }
  const reported = uniqueStrings(members.map((finding) => finding.installedVersion));
  if (reported.length === 1) {
    return { status: 'reported', version: reported[0], text: reported[0] };
  }
  if (reported.length > 1) {
    return { status: 'conflicting', versions: reported, text: `conflict: ${reported.join(' / ')}` };
  }
  return { status: 'not-applicable', text: '—' };
}

// fix: what the records say, never promised when the version itself is disputed.
export function fixStatus(members, version) {
  if (members.some(isMalicious)) {
    return { status: 'remove', text: 'remove the package' };
  }
  const versions = uniqueStrings([
    ...members.flatMap(recordFixVersions),
    ...members.flatMap((finding) => (Array.isArray(finding.packages) ? finding.packages.map((pkg) => pkg?.fixedInVersion) : []))
  ]);
  if (version.status === 'conflicting') {
    return {
      status: 'disputed',
      versions,
      text: versions.length > 0 ? `disputed — ${versions.join(', ')} reported` : 'disputed applicability'
    };
  }
  // npm names the package it would change, which may be a parent.
  const viaParent = members.find(
    (finding) => finding.source === 'npm-audit' && finding.fixPackage && finding.fixPackage !== (finding.package || finding.id) && finding.fixedVersion
  );
  if (viaParent) {
    return { status: 'fix-available', text: `fix via ${viaParent.fixPackage} ${viaParent.fixedVersion}` };
  }
  if (versions.length > 0) {
    return { status: 'fixed-in', versions, text: `fixed in ${versions.join(', ')}` };
  }
  if (members.some((finding) => finding.fixAvailable === true)) {
    return { status: 'fix-available', text: 'fix available' };
  }
  if (members.some((finding) => finding.fixAvailable === false)) {
    return { status: 'no-fix', text: 'no fix reported' };
  }
  return { status: 'not-applicable', text: '—' };
}

function componentOf(issue, members, card) {
  if (issue.package) return issue.package;
  const [first] = members;
  if (first?.source === 'npm-audit') return first.package || first.id;
  if (card.package) return card.package;
  if (card.location?.path) return `${card.location.path}${card.location.line ? `:${card.location.line}` : ''}`;
  if (card.target) return card.target;
  return '—';
}

function advisoryOf(issue, members) {
  if (issue.primaryId && issue.package) return issue.primaryId;
  const [first] = members;
  if (first?.source === 'npm-audit') {
    return first.url?.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i)?.[0] ?? '—';
  }
  return first?.id ?? '—';
}

function severityOf(members, card) {
  if (members.some(isMalicious)) return 'malicious';
  return ['critical', 'high', 'medium', 'low'].includes(card.severity) ? card.severity : 'unknown';
}

const PRESENTED_SEVERITY_RANK = { malicious: -1, ...SEVERITY_RANK };

export function presentIssue(issue, findings) {
  const members = issue.findings.map((index) => findings[index]);
  const card = issue.card;
  const version = versionStatus(issue, members);
  return {
    disposition: presentationDisposition(issue),
    reviewReasons: reviewReasons(issue),
    severity: severityOf(members, card),
    component: componentOf(issue, members, card),
    advisory: advisoryOf(issue, members),
    relationship: issue.evidence?.relationship?.value ?? null,
    version,
    fix: fixStatus(members, version)
  };
}

// Priority order: disposition, then severity, then first appearance (stable).
function orderIssues(issues) {
  return issues
    .map((issue, index) => ({ issue, index }))
    .sort(
      (a, b) =>
        DISPOSITION_RANK[a.issue.presentation.disposition] - DISPOSITION_RANK[b.issue.presentation.disposition] ||
        (PRESENTED_SEVERITY_RANK[a.issue.presentation.severity] ?? 9) - (PRESENTED_SEVERITY_RANK[b.issue.presentation.severity] ?? 9) ||
        a.index - b.index
    )
    .map(({ issue }) => issue);
}

// ---- scan health ------------------------------------------------------------------
//
// Scan health answers "did each scanner run and produce a trustworthy report",
// never "did the code pass policy". It is derived exactly as the per-control
// workflow outputs are (deriveScanControlResults), then refined by the scanner
// execution record, which says WHY a control has no trustworthy report.

const CONTROL_HEALTH = {
  success: 'completed',
  failure: 'unavailable',
  untrusted: 'untrusted',
  cancelled: 'cancelled',
  skipped: 'skipped'
};
const HEALTH_LABELS = {
  completed: '✅ completed',
  unavailable: '⛔ unavailable',
  untrusted: '⚠️ untrusted',
  cancelled: '✖️ cancelled',
  skipped: '⏭️ skipped',
  unknown: '❔ unknown'
};
const NO_REPORT_STATES = new Set(['acquisition-failed', 'execution-failed', 'report-missing', 'incomplete']);

function scannerLabelOf(scanner) {
  return RECORDED_SCANNERS[scanner]?.label ?? scannerLabel(scanner);
}

// Null for a gate result that carries no per-control evidence at all (an image
// gate, or a source gate result written before scan health existed).
export function deriveScanHealth(gate, jobResults = null) {
  const failures = Array.isArray(gate?.integrity?.failures) ? gate.integrity.failures : [];
  const records = Array.isArray(gate?.scannerExecution?.records) ? gate.scannerExecution.records : [];
  const haveJobs =
    jobResults && SCAN_CONTROLS.some((control) => typeof jobResults[control.id] === 'string' && jobResults[control.id] !== '');
  const attributed = failures.some((failure) => SCAN_CONTROLS.some((control) => control.id === failure?.control));
  if (!haveJobs && !gate?.scannerExecution && !attributed) {
    return null;
  }
  const derived = haveJobs ? deriveScanControlResults({ jobResults, gate }) : null;

  return SCAN_CONTROLS.map((control) => {
    const execution = records.find((record) => record?.control === control.id) ?? null;
    const failure = failures.find((entry) => entry?.control === control.id) ?? null;
    let status;
    let reason;
    if (derived) {
      status = CONTROL_HEALTH[derived[control.id].result] ?? 'unavailable';
      reason = derived[control.id].reason;
    } else if (failure) {
      status = 'untrusted';
      reason = failure.reason;
    } else if (gate?.integrity?.trusted === true) {
      status = 'completed';
      reason = "the gate evaluated this control's reports";
    } else {
      status = 'unknown';
      reason = 'not evaluated: the gate stopped at another uninterpretable input';
    }
    // A control with no trustworthy report is UNAVAILABLE when the evidence
    // shows no report was ever produced, UNTRUSTED when one was but failed.
    if (status !== 'completed') {
      if (execution && NO_REPORT_STATES.has(execution.state)) {
        status = 'unavailable';
      } else if (status === 'untrusted' && !execution && /missing report file/.test(failure?.reason ?? '')) {
        status = 'unavailable';
      }
    }
    return { id: control.id, label: control.job, status, reason, execution, integrityFailure: failure };
  });
}

// One sentence on why a scanner produced nothing usable, from its record only.
export function executionSentence(record) {
  if (!record) return null;
  const label = scannerLabelOf(record.scanner);
  const attempts = record.acquisition?.attempts?.length ?? 0;
  const retry = record.retryable ? ', retryable' : '';
  switch (record.state) {
    case 'acquisition-failed':
      return (
        `${label} could not start because its pinned scanner image could not be obtained` +
        `${attempts > 0 ? ` after ${attempts} attempt${attempts === 1 ? '' : 's'}` : ''} (cause: ${record.cause}${retry}).`
      );
    case 'execution-failed':
      return record.execution?.exitCode == null && record.cause === 'scanner-configuration'
        ? `${label} was not run: ${record.detail} (cause: ${record.cause}).`
        : `${label} started but failed — ${record.detail} (cause: ${record.cause}) — so it produced no usable report.`;
    case 'report-missing':
      return `${label} exited successfully but wrote no report (cause: ${record.cause}).`;
    case 'report-invalid':
      return `${label} ran, but its report failed validation: ${record.detail} (cause: ${record.cause}).`;
    case 'incomplete':
      return `${label}'s image was acquired, but the scan never recorded finishing: the step stopped before completion.`;
    case 'unknown':
      return `${label}'s execution record could not be interpreted (${record.unavailable ?? 'unexpected shape'}).`;
    default:
      return null;
  }
}

const SUGGESTED_ACTIONS = {
  'registry-network': 'Re-run the failed jobs. If the failure repeats, investigate scanner registry/network availability.',
  'registry-rate-limit':
    'Re-run the failed jobs after a short wait. If the failure repeats, the runner is being rate-limited by the scanner image registry.',
  'registry-auth':
    'Re-running is unlikely to help: the registry refused access to the pinned scanner image. Check that the pinned image is still published and pullable from this runner.',
  'image-not-found':
    'Re-running will not help: the registry reports that the pinned scanner image does not exist. The framework\'s pinned image reference needs attention.',
  'scanner-configuration':
    'Fix the scanner configuration named above (for Semgrep: `semgrep_configs`, `semgrep_paths`, and any local rule files), then re-run.',
  'scanner-runtime':
    'Inspect the scanner step in the job log. Re-run only if the log shows a transient cause, such as the runner running out of memory.',
  'report-validation': 'Inspect the scanner step in the job log: the report it wrote could not be interpreted.'
};
const DEFAULT_SUGGESTED_ACTION =
  'Diagnose the failed scanner or report step named in the integrity failure below, using the run log, then re-run.';

// Gate status in terms a developer can act on. `kind` separates a vulnerability
// POLICY block from a SCAN (availability / integrity) block.
function assessGate({ verdict, verdictLabel, counts, scanHealth }) {
  const blocking = isBlockingVerdict(verdict);
  const kind = !blocking
    ? 'pass'
    : counts.integrity > 0 && counts.block === 0
      ? 'scan'
      : counts.integrity > 0
        ? 'policy-and-scan'
        : 'policy';
  const unavailable = (scanHealth ?? []).filter((control) => control.status === 'unavailable');
  const qualifier = unavailable.length > 0 ? 'scan unavailable' : 'scan untrusted';
  const headline =
    kind === 'scan' ? `${verdictLabel} — ${qualifier}` : kind === 'policy-and-scan' ? `${verdictLabel} — policy findings and ${qualifier}` : verdictLabel;

  const problems = (scanHealth ?? []).filter((control) => !['completed', 'skipped'].includes(control.status) && control.status !== 'unknown');
  const explanations = uniqueStrings(problems.map((control) => executionSentence(control.execution)));
  const causes = uniqueStrings(problems.map((control) => control.execution?.cause));
  const actions = uniqueStrings(causes.map((cause) => SUGGESTED_ACTIONS[cause]));
  return {
    kind,
    headline,
    securityState: counts.integrity > 0 ? 'UNKNOWN' : 'KNOWN',
    scanProblems: problems.map((control) => control.id),
    explanations,
    suggestedActions: counts.integrity > 0 ? (actions.length > 0 ? actions : [DEFAULT_SUGGESTED_ACTION]) : []
  };
}

// Normalize a gate JSON result into the report every renderer consumes.
// `breakGlass` is the run's OBSERVED break-glass state (deriveBreakGlassState);
// when omitted it is derived with no runtime evidence, which claims nothing.
export function buildReport({ gate, context = {}, mode = 'enforce', breakGlass }) {
  const verdict = gate?.verdict || 'BLOCK';
  const meta = VERDICTS[verdict] || VERDICTS.BLOCK;
  const findings = Array.isArray(gate?.findings) ? gate.findings : [];
  const cards = findings.map((finding) => classify(finding, context, gate));
  const issues = buildIssues(findings, cards, context, gate);
  const isBreakGlassEligible = gate?.breakGlass?.eligible === true;
  const breakGlassState =
    breakGlass ?? deriveBreakGlassState({ verdict, eligible: isBreakGlassEligible, mode });

  const counts = {
    // Integrity failures are counted once, on their own — not also as findings.
    block: cards.filter((c) => (c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY') && !c.isIntegrity).length,
    exception: cards.filter((c) => c.action === 'EXCEPTION').length,
    log: cards.filter((c) => c.action === 'LOG').length,
    integrity: cards.filter((c) => c.isIntegrity).length
  };

  // What every surface headlines: UNIQUE issues. `counts` stays the raw
  // per-record count (and is what "is this run clean?" is decided from).
  const issueCounts = summarizeIssues(issues, cards.length);

  // Presentation, attached per issue and ordered once for every surface.
  for (const issue of issues) {
    issue.presentation = issue.card.isIntegrity ? null : presentIssue(issue, findings);
  }
  const ordered = orderIssues(issues.filter((issue) => issue.presentation));
  const dispositionCounts = Object.fromEntries(
    DISPOSITIONS.map((disposition) => [disposition.toLowerCase(), ordered.filter((issue) => issue.presentation.disposition === disposition).length])
  );

  const scanHealth = deriveScanHealth(gate, context.jobResults ?? null);
  const gateStatus = assessGate({ verdict, verdictLabel: meta.label, counts, scanHealth });

  // Image gates (the only producers of DEPLOY / DEPLOY-WITH-EXCEPTIONS /
  // BLOCK_DEPLOY) get a remediation-grouped view; source gates are unchanged.
  const image = IMAGE_VERDICTS.has(verdict) ? buildImagePresentation(gate, findings, cards) : null;

  let blurb = meta.blurb;
  if (gateStatus.kind === 'scan') {
    blurb =
      mode === 'log-only'
        ? 'This is not a vulnerability-policy BLOCK: the scan could not be completed or trusted. Reported, NOT enforced, because this repository runs in log-only mode.'
        : 'This is not a vulnerability-policy BLOCK: the scan could not be completed or trusted, so the gate fails closed.';
  } else if (isBlockingVerdict(verdict) && mode === 'log-only') {
    blurb = 'Blocking findings reported — NOT enforced, because this repository runs in log-only mode.';
  } else if (breakGlassState.decision === 'approved') {
    blurb = 'Blocking findings were found; a verified break-glass approval overrode the BLOCK for this run only.';
  }

  return {
    verdict,
    verdictLabel: meta.label,
    headline: gateStatus.headline,
    gateStatus,
    emoji: meta.emoji,
    blurb,
    context,
    mode,
    cards,
    counts,
    issues,
    issueCounts,
    orderedIssues: ordered,
    dispositionCounts,
    scanHealth,
    image,
    isBreakGlassEligible,
    breakGlass: breakGlassState,
    breakGlassNotice: breakGlassNotice(breakGlassState),
    routing: route({ verdict, mode, breakGlass: breakGlassState })
  };
}

function sortCards(cards) {
  return [...cards].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
}

function contextLine(context) {
  const bits = [];
  if (context.repository) {
    bits.push(`repo [\`${context.repository}\`](https://github.com/${context.repository})`);
  }
  if (context.prNumber) {
    bits.push(`PR [#${context.prNumber}](https://github.com/${context.repository}/pull/${context.prNumber})`);
  }
  if (context.sha) {
    const short = String(context.sha).slice(0, 12);
    bits.push(`commit [\`${short}\`](https://github.com/${context.repository}/commit/${context.sha})`);
  }
  if (context.runUrl) {
    bits.push(`[run log](${context.runUrl})`);
  }
  return bits.join(' · ');
}

// ---- Markdown renderer (PR comment AND $GITHUB_STEP_SUMMARY share it) --------
//
// Shape: gate status → scan health → issue counts → one compact triage table →
// evidence-conflict callouts → integrity failures → collapsible per-issue
// evidence for BLOCK / EXCEPTION / REVIEW only → one set of global notes.
//
// BOUNDED. A PR comment body over 65,536 characters is rejected by GitHub, and a
// repository can have hundreds of findings, so every variable-length part has a
// limit. Nothing is dropped silently: each omission states its exact count and
// points to security-gate.json, which is always complete.

export const SUMMARY_LIMITS = {
  maxCharacters: 60_000,
  tableRows: 100,
  // Per-disposition caps for the non-blocking classes. BLOCK and EXCEPTION rows
  // are limited only by `tableRows`, and fill it first.
  tableRowsPerDisposition: { REVIEW: 30, INFO: 20 },
  detailCards: 25,
  callouts: 10,
  integrityCards: 10,
  cellCharacters: 72
};

// GitHub renders <details> in job summaries and PR comments; markdown inside
// needs the blank lines around it. <summary> is HTML, so it is escaped and
// carries no markdown.
function escapeHtml(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function cell(text, { code = false, limit = SUMMARY_LIMITS.cellCharacters } = {}) {
  let value = String(text ?? '—').replace(/\s+/g, ' ').trim() || '—';
  if (value.length > limit) {
    value = `${value.slice(0, limit - 1)}…`;
  }
  value = value.replace(/\|/g, '\\|');
  return code && value !== '—' ? `\`${value.replace(/`/g, "'")}\`` : value;
}

const titleOrDash = (value) => (value && value !== 'unknown' ? titleCase(value) : '—');

function renderCardMarkdown(card) {
  const lines = [`**${card.title}**`];
  if (card.whatItMeans) {
    lines.push('', card.whatItMeans);
  }
  const facts = [];
  if (card.deepLink) {
    facts.push(`📍 [\`${card.location.path}${card.location.line ? `:${card.location.line}` : ''}\`](${card.deepLink})`);
  } else if (card.location?.path) {
    facts.push(`📍 \`${card.location.path}${card.location.line ? `:${card.location.line}` : ''}\``);
  }
  if (card.target) {
    facts.push(`📦 In image: \`${card.target}\``);
  }
  if (card.executionNote) {
    facts.push(`🧰 ${card.executionNote}`);
  }
  if (card.severityNote) {
    facts.push(`📊 ${card.severityNote}`);
  }
  if (card.evidenceNote) {
    facts.push(`🔎 ${card.evidenceNote}`);
  }
  if (Array.isArray(card.advisoryIds) && card.advisoryIds.length > 0) {
    facts.push(`🏷️ Advisory IDs: ${list(card.advisoryIds)}`);
  }
  if (card.relationshipNote) {
    facts.push(`🧬 ${card.relationshipNote}`);
  }
  if (card.resolutionNote) {
    facts.push(`${card.resolutionConflict ? '⚖️' : '📌'} ${card.resolutionNote}`);
  }
  if (Array.isArray(card.observedBy) && card.observedBy.length > 0) {
    facts.push(`🔎 Observed by:${card.observedBy.map((line) => `\n  - ${line}`).join('')}`);
  }
  if (card.fixSummary) {
    facts.push(`🧩 Fixed version(s): ${card.fixSummary}`);
  }
  if (Array.isArray(card.reproduceAll) && card.reproduceAll.length > 1) {
    facts.push(`🔁 Reproduce locally: ${card.reproduceAll.map((command) => `\`${command}\``).join(' · ')}`);
  } else if (card.reproduce) {
    facts.push(`🔁 Reproduce locally: \`${card.reproduce}\``);
  }
  if (card.howToFix) {
    facts.push(`🔧 ${card.howToFix}`);
  }
  if (card.referenceUrl) {
    facts.push(`🔗 ${card.referenceUrl}`);
  }
  for (const fact of facts) {
    lines.push(`- ${fact}`);
  }
  return lines.join('\n');
}

function renderScanHealth(report) {
  const health = report.scanHealth;
  if (!health) {
    return [];
  }
  const completed = health.filter((control) => control.status === 'completed').length;
  if (completed === health.length) {
    return [`✅ **${completed}/${health.length}** scan controls completed — scanners ran and produced reports the gate accepted (scan health, not a policy result).`];
  }
  const rows = health.map((control) => {
    const execution = control.execution;
    const detail =
      execution && execution.state !== 'success'
        ? [execution.state, execution.cause, execution.retryable ? 'retryable' : null].filter(Boolean).join(' · ')
        : control.status === 'completed'
          ? ''
          : control.integrityFailure?.reason ?? '';
    return `| ${control.label} | ${HEALTH_LABELS[control.status] ?? control.status} | ${cell(detail || ' ', { limit: 120 })} |`;
  });
  return [
    [
      `**Scan health** — ${completed}/${health.length} scan controls completed. This is whether each scanner ran and produced a trustworthy report, not a policy result.`,
      '',
      '| Control | Scan | Detail |',
      '| --- | --- | --- |',
      ...rows
    ].join('\n')
  ];
}

function renderScanProblem(report) {
  const status = report.gateStatus;
  if (report.counts.integrity === 0) {
    return [];
  }
  const lines = [`**Security state: ${status.securityState}** — the findings list is unknown, not clean.`];
  for (const explanation of status.explanations) {
    lines.push('', explanation);
  }
  lines.push('', `**Suggested action:** ${status.suggestedActions.join(' ')}`);
  lines.push('', '**Do not generate a baseline from this run.**');
  return [lines.join('\n')];
}

function countsLine(report) {
  const shown = report.issueCounts ?? report.counts;
  const summaryBits = [`**${shown.block}** blocking`, `**${shown.exception}** exception`];
  const dispositions = report.dispositionCounts;
  summaryBits.push(
    dispositions
      ? `**${shown.log}** logged (**${dispositions.review}** review · **${dispositions.info}** info)`
      : `**${shown.log}** logged`
  );
  if (shown.integrity > 0) {
    summaryBits.push(`**${shown.integrity}** integrity failure${shown.integrity === 1 ? '' : 's'}`);
  }
  let line = summaryBits.join(' · ');
  if (report.issueCounts && report.issueCounts.issues !== report.issueCounts.rawFindings) {
    line +=
      ` — **${report.issueCounts.issues}** unique issue${report.issueCounts.issues === 1 ? '' : 's'} from ` +
      `**${report.issueCounts.rawFindings}** scanner findings (records that share advisory IDs are shown once)`;
  }
  return line;
}

// Which ordered issues get a table row, with exact per-disposition omissions.
export function selectTableRows(ordered, limits = SUMMARY_LIMITS) {
  const shown = [];
  const omitted = { BLOCK: 0, EXCEPTION: 0, REVIEW: 0, INFO: 0 };
  const perDisposition = { BLOCK: 0, EXCEPTION: 0, REVIEW: 0, INFO: 0 };
  for (const issue of ordered) {
    const { disposition } = issue.presentation;
    const cap = limits.tableRowsPerDisposition[disposition] ?? Infinity;
    if (shown.length < limits.tableRows && perDisposition[disposition] < cap) {
      shown.push(issue);
      perDisposition[disposition] += 1;
    } else {
      omitted[disposition] += 1;
    }
  }
  return { shown, omitted };
}

function omissionText(omitted, noun) {
  const parts = DISPOSITIONS.filter((disposition) => omitted[disposition] > 0).map(
    (disposition) => `${omitted[disposition]} ${disposition}`
  );
  const total = DISPOSITIONS.reduce((sum, disposition) => sum + omitted[disposition], 0);
  return total === 0
    ? null
    : `${total} ${noun}${total === 1 ? '' : 's'} not shown (${parts.join(', ')})`;
}

function renderTable(report, limits = SUMMARY_LIMITS) {
  const ordered = report.orderedIssues ?? [];
  if (ordered.length === 0) {
    return { blocks: [], omitted: null };
  }
  const { shown, omitted } = selectTableRows(ordered, limits);
  const rows = shown.map((issue) => {
    const p = issue.presentation;
    return `| ${DISPOSITION_LABELS[p.disposition]} | ${titleOrDash(p.severity)} | ${cell(p.component, { code: true })} | ${cell(p.advisory, { code: true })} | ${cell(p.relationship ?? '—')} | ${cell(p.version.text)} | ${cell(p.fix.text)} |`;
  });
  const lines = [
    `### Issues (${ordered.length})`,
    '',
    '| Action | Severity | Component | Advisory / rule | Relationship | Version | Fix |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...rows
  ];
  const note = omissionText(omitted, 'table row');
  if (note) {
    lines.push('', `_Showing ${shown.length} of ${ordered.length} issues; ${note}. Every issue, with full evidence, is in \`${evidenceFile(report)}\`._`);
  }
  return { blocks: [lines.join('\n')], omitted };
}

function conflictCallout(issue) {
  const resolution = issue.evidence.resolution;
  const sides = new Map();
  for (const observation of resolution.observations) {
    if (observation.version === null || observation.version === undefined) continue;
    const key = versionKey(issue.ecosystem, observation.version);
    if (!sides.has(key)) sides.set(key, { version: observation.version, who: new Set() });
    sides.get(key).who.add(observation.scanner ? scannerLabel(observation.scanner) : `\`${observation.source}\` declaration`);
  }
  const text = [...sides.values()].map((side) => `${[...side.who].join(', ')}: ${side.version}`).join(' · ');
  const declared = resolution.observations.some((observation) => observation.provenance === 'manifest-declared');
  return (
    `> ⚖️ **\`${issue.package}\` — ${issue.primaryId}** (${issue.presentation.disposition}): ${text}. ` +
    `${declared ? 'The manifest declaration and the scanner results disagree' : 'The scanners disagree'} on the effective version. ` +
    'Do not remediate until the version actually resolved is established.'
  );
}

function renderCallouts(report) {
  const conflicted = (report.orderedIssues ?? []).filter((issue) => issue.presentation.reviewReasons.includes('version-conflict'));
  if (conflicted.length === 0) {
    return [];
  }
  const shown = conflicted.slice(0, SUMMARY_LIMITS.callouts);
  const lines = [`**Evidence conflicts (${conflicted.length})**`, '', shown.map(conflictCallout).join('\n>\n')];
  if (conflicted.length > shown.length) {
    lines.push('', `_${conflicted.length - shown.length} more evidence conflict(s) not shown; see \`${evidenceFile(report)}\`._`);
  }
  return [lines.join('\n')];
}

function renderIntegrity(report) {
  const cards = (report.issues ?? []).map((issue) => issue.card).filter((card) => card.isIntegrity);
  if (cards.length === 0) {
    return [];
  }
  const shown = cards.slice(0, SUMMARY_LIMITS.integrityCards);
  const lines = [
    `### 🚨 Scan integrity failures — results UNKNOWN, fail-closed, not a code defect (${cards.length})`,
    '',
    shown.map((card) => renderCardMarkdown(withExecutionNote(card, report))).join('\n\n')
  ];
  if (cards.length > shown.length) {
    lines.push('', `_${cards.length - shown.length} more integrity failure(s) not shown; see \`${evidenceFile(report)}\`._`);
  }
  return [lines.join('\n')];
}

// The integrity card names the report that could not be trusted; the execution
// record, when there is one, names why. Both are kept.
function withExecutionNote(card, report) {
  const problems = (report.scanHealth ?? []).filter((control) => control.execution && control.execution.state !== 'success');
  const notes = uniqueStrings(problems.map((control) => executionSentence(control.execution)));
  return notes.length > 0 ? { ...card, executionNote: `Scanner execution: ${notes.join(' ')}` } : card;
}

const DETAIL_SECTIONS = [
  ['BLOCK', '⛔ Blocking findings'],
  ['EXCEPTION', '⚠️ Tracked exceptions (no fix available — passed deliberately)'],
  ['REVIEW', '⚖️ Needs review — non-blocking, evidence disagrees']
];

function detailBlock(issue, open) {
  const p = issue.presentation;
  const summary = escapeHtml(`${DISPOSITION_LABELS[p.disposition]} · ${titleOrDash(p.severity)} · ${p.component} — ${p.advisory}`);
  return `<details${open ? ' open' : ''}><summary>${summary}</summary>\n\n${renderCardMarkdown(issue.card)}\n\n</details>`;
}

// Per-issue evidence for BLOCK / EXCEPTION / REVIEW only, in priority order,
// within `budget` characters and SUMMARY_LIMITS.detailCards cards. Once one card
// does not fit, every later card is omitted too, so a smaller low-priority card
// never displaces a higher-priority one.
const SECTION_OVERHEAD = 240; // heading plus a possible omission note

function renderDetails(report, budget) {
  const blocks = [];
  let used = 0;
  let cards = 0;
  let full = false;
  for (const [disposition, heading] of DETAIL_SECTIONS) {
    const issues = (report.orderedIssues ?? []).filter((issue) => issue.presentation.disposition === disposition);
    if (issues.length === 0) continue;
    used += SECTION_OVERHEAD;
    const open = disposition === 'BLOCK' && issues.length <= 5;
    const rendered = [];
    for (const issue of issues) {
      const block = detailBlock(issue, open);
      full = full || cards >= SUMMARY_LIMITS.detailCards || used + block.length + 2 > budget;
      if (full) break;
      rendered.push(block);
      used += block.length + 2;
      cards += 1;
    }
    const omitted = issues.length - rendered.length;
    const lines = [`### ${heading} (${issues.length})`];
    if (rendered.length > 0) lines.push('', rendered.join('\n\n'));
    if (omitted > 0) {
      lines.push('', `_Full evidence shown for ${rendered.length} of ${issues.length}; ${omitted} not shown here — see \`${evidenceFile(report)}\`._`);
    }
    blocks.push(lines.join('\n'));
  }
  return blocks;
}

function evidenceFile(report) {
  return report.context?.evidenceFile || 'security-gate.json';
}

function renderFooter(report) {
  const notes = [];
  if (report.issueCounts && report.issueCounts.issues !== report.issueCounts.rawFindings) {
    notes.push(`Scanner records that share advisory aliases are correlated for display; every raw scanner record remains in \`${evidenceFile(report)}\`.`);
  }
  if ((report.dispositionCounts?.review ?? 0) > 0 || (report.dispositionCounts?.info ?? 0) > 0) {
    notes.push('REVIEW and INFO label non-blocking (LOG) issues for triage — REVIEW means the evidence disagrees. Labels never change the policy verdict.');
  }
  if ((report.orderedIssues?.length ?? 0) > 0 || report.counts.integrity > 0) {
    const readable = report.context?.evidenceMarkdownFile ? ` and every issue's full explanation in \`${report.context.evidenceMarkdownFile}\`` : '';
    notes.push(
      `Full evidence: \`${evidenceFile(report)}\`${readable}, in this run's artifacts${report.context?.runUrl ? ` ([run](${report.context.runUrl}))` : ''}.`
    );
  }
  return notes.length > 0 ? [`---\n${notes.map((note) => `<sub>${note}</sub>`).join('<br>\n')}`] : [];
}

export function renderMarkdown(report, { includeMarker = false } = {}) {
  if (report.image) {
    return renderImageMarkdown(report, { includeMarker });
  }
  const head = [];
  if (includeMarker) {
    head.push(PR_COMMENT_MARKER);
  }
  head.push(`## ${report.emoji} Security gate: ${report.headline ?? report.verdictLabel}`);
  head.push(`_${report.blurb}_`);

  const ctx = contextLine(report.context);
  if (ctx) {
    head.push(ctx);
  }
  head.push(...renderScanHealth(report));
  head.push(...renderScanProblem(report));
  head.push(countsLine(report));

  if (report.mode === 'log-only') {
    head.push(
      isBlockingVerdict(report.verdict)
        ? '> ℹ️ This repository runs in **log-only** mode: the blocking verdict above is reported but NOT enforced, and no Slack alert is sent.'
        : `> ℹ️ This repository runs in **log-only** mode. The verdict is ${report.verdictLabel}, so there is no blocking verdict to suppress. ` +
            'log-only is a rollout mode: a future BLOCK would be reported without blocking the merge, and no Slack alert is sent.'
    );
  }
  if (report.breakGlassNotice) {
    head.push(`> ${report.breakGlassNotice}`);
  }

  const rest = [...renderCallouts(report), ...renderIntegrity(report)];
  if (report.cards.length === 0) {
    rest.push('No findings. 🎉');
  }
  const footer = renderFooter(report);

  // Rows are capped by count; if unusually long cells still push the fixed part
  // over the size limit, fewer rows are shown — and the omission says so.
  let tableRows = SUMMARY_LIMITS.tableRows;
  let table = renderTable(report, { ...SUMMARY_LIMITS, tableRows });
  const fixedLength = () => [...head, ...table.blocks, ...rest, ...footer].join('\n\n').length;
  while (tableRows > 0 && fixedLength() > SUMMARY_LIMITS.maxCharacters - 2_000) {
    tableRows = Math.floor(tableRows / 2);
    table = renderTable(report, { ...SUMMARY_LIMITS, tableRows });
  }
  head.push(...table.blocks, ...rest);
  const fixed = [...head, ...footer].join('\n\n').length;
  const details = renderDetails(report, Math.max(0, SUMMARY_LIMITS.maxCharacters - fixed - 2_000));

  return [...head, ...details, ...footer].filter(Boolean).join('\n\n') + '\n';
}

// ---- full evidence document -----------------------------------------------------
//
// Every issue's full card — INFO included — in priority order, unbounded. It is
// written as a run artifact next to security-gate.json, not posted anywhere, so
// the triage summary can stay small without any per-issue explanation becoming
// unavailable. It renders the SAME cards the summary's details use.
export function renderEvidenceMarkdown(report) {
  const gateName = report.image ? 'Image gate' : 'Security gate';
  const blocks = [`# ${gateName} evidence: ${report.headline ?? report.verdictLabel}`, `_${report.blurb}_`];
  const ctx = contextLine(report.context);
  if (ctx) blocks.push(ctx);
  blocks.push(...renderScanHealth(report), ...renderScanProblem(report), report.image ? imageCountsLine(report) : countsLine(report));
  if (report.image) {
    blocks.push(...imageScanLine(report), ...renderImageGroupIndex(report));
  }
  const integrity = (report.issues ?? []).map((issue) => issue.card).filter((card) => card.isIntegrity);
  for (const card of integrity) {
    blocks.push(`## 🚨 Scan integrity failure\n\n${renderCardMarkdown(withExecutionNote(card, report))}`);
  }
  for (const issue of report.orderedIssues ?? []) {
    const p = issue.presentation;
    blocks.push(
      `## ${DISPOSITION_LABELS[p.disposition]} · ${titleOrDash(p.severity)} · ${p.component} — ${p.advisory}\n\n` +
        `Relationship: ${p.relationship ?? '—'} · Version: ${p.version.text} · Fix: ${p.fix.text}\n\n${renderCardMarkdown(issue.card)}`
    );
  }
  if (report.cards.length === 0) {
    blocks.push('No findings.');
  }
  blocks.push(`Machine-readable evidence, including every raw scanner record: \`${evidenceFile(report)}\`.`);
  return `${blocks.join('\n\n')}\n`;
}

// ---- image gate presentation ---------------------------------------------------
//
// An image scan reports hundreds of records for one base image, most repeating
// the same few package upgrades. The developer surface for an image gate is
// therefore organized by REMEDIATION, not by record:
//
//   raw scanner report  ->  image-gate*.json (complete normalized findings)
//                       ->  image-gate*-evidence.md (every card, every group)
//                       ->  bounded summary / PR comment / Slack (this section)
//
// PRESENTATION ONLY. Grouping reads the normalized findings and writes nothing
// back: the verdict, `summary`, `findings` and every policy action are the
// gate's. A group holds findings whose recorded remediation evidence is
// IDENTICAL — scanner, policy action, package, installed version, fixed version
// and target. A finding that records less than package + installed version (or
// a fix-available finding with no fixed version) is never merged: it stands
// alone and is shown with its own card title. No upgrade command is invented;
// the fixed version shown is the one the scanner lists.
//
// Disclosure by verdict:
//   BLOCK_DEPLOY            integrity failures and image secrets in full, then
//                           blocking remediation groups (bounded, Critical
//                           first); exceptions and logged findings as counts
//   DEPLOY-WITH-EXCEPTIONS  exception groups (bounded); logged as counts
//   DEPLOY                  logged as counts
// Every omission states its exact group and finding count.

const IMAGE_VERDICTS = new Set(['DEPLOY', 'DEPLOY-WITH-EXCEPTIONS', 'BLOCK_DEPLOY']);

// EXCEPTION_FIX, stated once for a list of groups.
const IMAGE_EXCEPTIONS_FIX =
  'No fix is available according to the scanner data, so policy records these Critical/High findings as tracked ' +
  'EXCEPTIONs instead of blocks. They are reported on every run, and each will block once a fix becomes available.';

export const IMAGE_SUMMARY_LIMITS = {
  secrets: 20,
  blockingGroups: 10,
  exceptionGroups: 10,
  advisoriesPerGroup: 6,
  textCharacters: 120
};

const IMAGE_SCANNER_LABELS = { trivy: 'Trivy', 'ecr-enhanced-scan': 'Amazon Inspector', 'ecr-image-scan': 'ECR basic scanning' };

const nonEmpty = (value) => typeof value === 'string' && value !== '';
const severityRank = (severity) => SEVERITY_RANK[String(severity ?? 'unknown').toLowerCase()] ?? 9;
const compareText = (a, b) => String(a ?? '').localeCompare(String(b ?? ''));

// The remediation facts one image finding records, or null when it records too
// few for it to be grouped safely with anything else.
export function imageRemediationEvidence(finding) {
  let evidence = null;
  if (finding?.source === 'trivy' && finding.policyRule !== 'image.secret') {
    if (nonEmpty(finding.package) && nonEmpty(finding.installedVersion)) {
      evidence = {
        package: finding.package,
        installedVersion: finding.installedVersion,
        fixedVersion: nonEmpty(finding.fixedVersion) ? finding.fixedVersion : null,
        target: nonEmpty(finding.target) ? finding.target : null
      };
    }
  } else if (finding?.source === 'ecr-enhanced-scan') {
    // Only a single-package finding: with several packages there is no one
    // upgrade to share.
    const packages = Array.isArray(finding.packages) ? finding.packages : [];
    if (packages.length === 1 && nonEmpty(packages[0]?.name) && nonEmpty(packages[0]?.version)) {
      evidence = {
        package: packages[0].name,
        installedVersion: packages[0].version,
        fixedVersion: nonEmpty(packages[0].fixedInVersion) ? packages[0].fixedInVersion : null,
        target: null
      };
    }
  }
  if (evidence && finding.fixAvailable === true && evidence.fixedVersion === null) {
    return null;
  }
  return evidence;
}

function severityBreakdown(findings) {
  const counts = new Map();
  for (const finding of findings) {
    const severity = String(finding.severity ?? 'unknown').toLowerCase();
    counts.set(severity, (counts.get(severity) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => severityRank(a[0]) - severityRank(b[0]))
    .map(([severity, count]) => `${count} ${severity}`)
    .join(', ');
}

// Groups `indexes` (into `findings`) by identical remediation evidence.
// Deterministic: groups by highest severity, then size, then package /
// installed / fixed / target, then first appearance; advisories inside a group
// by severity, then id.
export function groupImageFindings(findings, indexes) {
  const groups = new Map();
  for (const index of indexes) {
    const finding = findings[index];
    const evidence = imageRemediationEvidence(finding);
    const key = evidence
      ? JSON.stringify([finding.source, finding.action, evidence.package, evidence.installedVersion, evidence.fixedVersion, evidence.target])
      : `finding:${index}`;
    if (!groups.has(key)) {
      groups.set(key, { key, source: finding.source, action: finding.action, evidence, findings: [] });
    }
    groups.get(key).findings.push(index);
  }
  return [...groups.values()]
    .map((group) => {
      const ordered = [...group.findings].sort(
        (a, b) => severityRank(findings[a].severity) - severityRank(findings[b].severity) || compareText(findings[a].id, findings[b].id) || a - b
      );
      const members = ordered.map((index) => findings[index]);
      return {
        ...group,
        findings: ordered,
        firstIndex: Math.min(...group.findings),
        severity: String(members[0].severity ?? 'unknown').toLowerCase(),
        severityBreakdown: severityBreakdown(members),
        mixedSeverity: new Set(members.map((finding) => finding.severity)).size > 1,
        advisories: uniqueStrings(members.map((finding) => finding.id)),
        scanner: IMAGE_SCANNER_LABELS[group.source] ?? group.source
      };
    })
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        b.findings.length - a.findings.length ||
        compareText(a.evidence?.package, b.evidence?.package) ||
        compareText(a.evidence?.installedVersion, b.evidence?.installedVersion) ||
        compareText(a.evidence?.fixedVersion, b.evidence?.fixedVersion) ||
        compareText(a.evidence?.target, b.evidence?.target) ||
        a.firstIndex - b.firstIndex
    );
}

function imageStats(findings, groups) {
  const indexes = groups.flatMap((group) => group.findings);
  const members = indexes.map((index) => findings[index]);
  return {
    findings: indexes.length,
    groups: groups.length,
    advisories: uniqueStrings(members.map((finding) => finding.id)).length,
    packages: uniqueStrings(members.map((finding) => imageRemediationEvidence(finding)?.package ?? finding.package)).length,
    severities: severityBreakdown(members)
  };
}

function buildImagePresentation(gate, findings, cards) {
  const where = (predicate) => findings.map((_, index) => index).filter((index) => predicate(findings[index], cards[index]));
  const isBlocking = (finding) => finding.action === 'BLOCK_DEPLOY' || finding.action === 'BLOCK';
  const secrets = where((finding, card) => finding.policyRule === 'image.secret' && !card.isIntegrity);
  const blocking = groupImageFindings(
    findings,
    where((finding, card) => isBlocking(finding) && !card.isIntegrity && finding.policyRule !== 'image.secret')
  );
  const exceptions = groupImageFindings(findings, where((finding) => finding.action === 'EXCEPTION'));
  const logged = groupImageFindings(findings, where((finding) => finding.action === 'LOG'));
  const sources = uniqueStrings(findings.map((finding) => finding.source)).filter((source) => IMAGE_SCANNER_LABELS[source]);
  return {
    findings,
    scanner: sources.length > 0 ? sources.map((source) => IMAGE_SCANNER_LABELS[source]).join(' + ') : gate?.image?.imageId ? 'Trivy' : null,
    trusted: typeof gate?.integrity?.trusted === 'boolean' ? gate.integrity.trusted : null,
    identity: gate?.image ?? null,
    secrets,
    blocking,
    exceptions,
    logged,
    stats: {
      blocking: imageStats(findings, blocking),
      exception: imageStats(findings, exceptions),
      logged: imageStats(findings, logged)
    }
  };
}

function clip(text, limit = IMAGE_SUMMARY_LIMITS.textCharacters) {
  const value = String(text ?? '').replace(/\s+/g, ' ').trim();
  return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

const codeSpan = (text, limit) => `\`${clip(text, limit).replace(/`/g, "'")}\``;
const plural = (count, noun, nouns = `${noun}s`) => `${count} ${count === 1 ? noun : nouns}`;

function advisoryList(group, limit) {
  const shown = group.advisories.slice(0, limit);
  const more = group.advisories.length - shown.length;
  return `${shown.map((id) => codeSpan(id)).join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
}

// One line per group. `limit` bounds the advisory ids listed (Infinity in the
// evidence document).
function imageGroupLine(group, report, { limit = IMAGE_SUMMARY_LIMITS.advisoriesPerGroup } = {}) {
  const { findings } = report.image;
  const severity = `**${titleCase(group.severity)}**`;
  const ev = group.evidence;
  if (!ev) {
    return `- ${severity} · ${clip(report.cards[group.findings[0]].title, 300)}`;
  }
  const count = group.advisories.length;
  const breakdown = group.mixedSeverity ? ` (${group.severityBreakdown})` : '';
  const only = group.findings.length === 1 ? findings[group.findings[0]] : null;
  const title = only && nonEmpty(only.title) ? ` — ${clip(only.title, 100)}` : '';
  const target = ev.target ? ` · in ${codeSpan(ev.target)}` : '';
  const pkg = `image package ${codeSpan(ev.package)} ${codeSpan(ev.installedVersion)}`;
  const ids = `${advisoryList(group, limit)}${title}`;
  return ev.fixedVersion
    ? `- ${severity} · ${pkg} → **${codeSpan(ev.fixedVersion)}** — ${group.scanner} lists this fixed version for ${plural(count, 'advisory', 'advisories')}${breakdown}: ${ids}${target}`
    : `- ${severity} · ${pkg} — no fixed version reported by ${group.scanner} · ${plural(count, 'advisory', 'advisories')}${breakdown}: ${ids}${target}`;
}

function evidencePointer(report) {
  const markdown = report.context?.evidenceMarkdownFile;
  return markdown ? `\`${markdown}\`` : `\`${evidenceFile(report)}\``;
}

function omittedGroupsNote(report, groups, shownCount, noun) {
  const omitted = groups.slice(shownCount);
  if (omitted.length === 0) return null;
  const members = omitted.flatMap((group) => group.findings).map((index) => report.image.findings[index]);
  return (
    `_${plural(omitted.length, `more ${noun} group`)} not shown here (${plural(members.length, 'finding')}: ` +
    `${severityBreakdown(members)}). Every group and finding is in ${evidencePointer(report)}._`
  );
}

function renderImageSecrets(report) {
  const { secrets } = report.image;
  if (secrets.length === 0) return [];
  const cards = secrets.map((index) => report.cards[index]);
  const shown = cards.slice(0, IMAGE_SUMMARY_LIMITS.secrets);
  const lines = [
    `### 🔑 Secrets in image layers (${cards.length}) — blocking, no break-glass`,
    '',
    ...shown.map((card) => `- **${clip(card.title, 300)}**${card.target ? ` · in ${codeSpan(card.target)}` : ''}`)
  ];
  if (cards.length > shown.length) {
    lines.push('', `_${plural(cards.length - shown.length, 'more secret finding')} not shown here; every one is in ${evidencePointer(report)}._`);
  }
  lines.push('', `🔎 ${cards[0].evidenceNote}`, `🔧 ${cards[0].howToFix}`);
  return [lines.join('\n')];
}

function reproduceLine(report, groups) {
  const commands = uniqueStrings(groups.flatMap((group) => group.findings.map((index) => report.cards[index].reproduce)));
  return commands.length > 0 ? `🔁 Reproduce locally: ${commands.slice(0, 2).map((command) => `\`${command}\``).join(' · ')}` : null;
}

function renderImageBlocking(report) {
  const { blocking, stats } = report.image;
  if (blocking.length === 0) return [];
  const shown = blocking.slice(0, IMAGE_SUMMARY_LIMITS.blockingGroups);
  const lines = [
    `### ⛔ Blocking — fix these first (${plural(stats.blocking.groups, 'remediation group')} · ${plural(stats.blocking.findings, 'finding')})`,
    '',
    '_Findings are grouped only when the scanner records the same package, installed version, fixed version and target; a finding without that evidence is its own group._',
    '',
    ...shown.map((group) => imageGroupLine(group, report))
  ];
  const omitted = omittedGroupsNote(report, blocking, shown.length, 'blocking remediation');
  if (omitted) lines.push('', omitted);
  const hints = [];
  if (shown.some((group) => group.evidence?.fixedVersion)) {
    hints.push('Upgrade each package to the fixed version shown, or move to a base image that ships it, then rebuild the image.');
  }
  // A standalone finding's own remediation, each distinct text once.
  hints.push(...uniqueStrings(shown.filter((group) => !group.evidence).map((group) => report.cards[group.findings[0]].howToFix)).map((text) => clip(text, 400)));
  lines.push('', ...hints.map((hint) => `🔧 ${hint}`));
  const reproduce = reproduceLine(report, shown);
  if (reproduce) lines.push(reproduce);
  return [lines.join('\n')];
}

function renderImageExceptions(report) {
  const { exceptions, stats } = report.image;
  if (exceptions.length === 0) return [];
  const shown = exceptions.slice(0, IMAGE_SUMMARY_LIMITS.exceptionGroups);
  const lines = [
    `### ⚠️ Tracked exceptions — no fix available (${plural(stats.exception.groups, 'group')} · ${plural(stats.exception.findings, 'finding')})`,
    '',
    ...shown.map((group) => imageGroupLine(group, report))
  ];
  const omitted = omittedGroupsNote(report, exceptions, shown.length, 'exception');
  if (omitted) lines.push('', omitted);
  lines.push('', `ℹ️ ${IMAGE_EXCEPTIONS_FIX}`);
  return [lines.join('\n')];
}

function exceptionCountLine(report) {
  const { exception } = report.image.stats;
  if (exception.findings === 0) return null;
  return (
    `⚠️ **${exception.findings}** exception ${exception.findings === 1 ? 'finding' : 'findings'} ` +
    `(${plural(exception.advisories, 'distinct advisory', 'distinct advisories')} in ${plural(exception.packages, 'package')}; ${exception.severities}) ` +
    'have no fix available according to the scanner, so policy tracks them as EXCEPTIONs; they do not block deploy. ' +
    `Listed in ${evidencePointer(report)}.`
  );
}

function loggedCountLine(report) {
  const { logged } = report.image.stats;
  if (logged.findings === 0) return null;
  return (
    `ℹ️ **${logged.findings}** logged ${logged.findings === 1 ? 'finding' : 'findings'} ` +
    `(${plural(logged.advisories, 'distinct advisory', 'distinct advisories')}; ${logged.severities}) ` +
    `are informational (LOG) and do not block deploy. Listed in ${evidencePointer(report)}.`
  );
}

// The gate's raw per-record counts (image findings are never correlated), with
// integrity failures counted on their own.
function imageCountsLine(report) {
  const { block, exception, log, integrity } = report.counts;
  const bits = [`**${block}** blocking`, `**${exception}** exception`, `**${log}** logged ${block + exception + log === 1 ? 'finding' : 'findings'}`];
  if (integrity > 0) bits.push(`**${integrity}** integrity failure${integrity === 1 ? '' : 's'}`);
  return bits.join(' · ');
}

function imageScanLine(report) {
  const { scanner, trusted, identity } = report.image;
  const bits = [];
  if (trusted === true) {
    bits.push(`Scan integrity: trusted — the gate interpreted the ${scanner ?? 'image scan'} report.`);
  }
  if (identity?.imageId) {
    const os = [identity.os?.family, identity.os?.name].filter(nonEmpty).join(' ');
    bits.push(`Scanned image \`${identity.imageId}\`${os ? ` (${os})` : ''}.`);
  } else if (identity?.imageDigest) {
    bits.push(`Scanned image \`${identity.repository ?? '?'}@${identity.imageDigest}\`.`);
  }
  return bits.length > 0 ? [bits.join(' ')] : [];
}

function renderImageFooter(report) {
  const raw = report.context?.rawReportFile;
  const markdown = report.context?.evidenceMarkdownFile;
  const notes = [
    'This summary is bounded on purpose: what blocks, and what to change first. Grouping is presentation only and never changes the verdict, the counts, or any finding.',
    `Full evidence: ${markdown ? `\`${markdown}\` (every finding's explanation and every remediation group) and ` : ''}` +
      `\`${evidenceFile(report)}\` (complete normalized findings)${raw ? `; raw scanner report: \`${raw}\`` : ''} — in this run's artifacts` +
      `${report.context?.runUrl ? ` ([run](${report.context.runUrl}))` : ''}.`
  ];
  return [`---\n${notes.map((note) => `<sub>${note}</sub>`).join('<br>\n')}`];
}

function renderImageMarkdown(report, { includeMarker = false } = {}) {
  const blocks = [];
  if (includeMarker) {
    blocks.push(PR_COMMENT_MARKER);
  }
  blocks.push(`## ${report.emoji} Image gate: ${report.headline ?? report.verdictLabel}`, `_${report.blurb}_`);
  const ctx = contextLine(report.context);
  if (ctx) blocks.push(ctx);
  blocks.push(...imageScanLine(report), ...renderScanProblem(report), imageCountsLine(report));
  if (report.mode === 'log-only') {
    blocks.push(
      isBlockingVerdict(report.verdict)
        ? '> ℹ️ This repository runs in **log-only** mode: the blocking verdict above is reported but NOT enforced, and no Slack alert is sent.'
        : `> ℹ️ This repository runs in **log-only** mode. The verdict is ${report.verdictLabel}, so there is no blocking verdict to suppress.`
    );
  }
  blocks.push(...renderIntegrity(report), ...renderImageSecrets(report), ...renderImageBlocking(report));
  if (report.verdict === 'BLOCK_DEPLOY') {
    // Exceptions do not compete with blockers: a count and a pointer.
    blocks.push(exceptionCountLine(report));
  } else {
    blocks.push(...renderImageExceptions(report));
  }
  blocks.push(loggedCountLine(report));
  if (report.cards.length === 0) {
    blocks.push('No findings. 🎉');
  }
  blocks.push(...renderImageFooter(report));
  return `${blocks.filter(Boolean).join('\n\n')}\n`;
}

// The evidence document's unbounded index: every group with every advisory.
function renderImageGroupIndex(report) {
  const blocks = [];
  const { secrets, blocking, exceptions, logged } = report.image;
  const section = (heading, groups) => {
    if (groups.length === 0) return;
    blocks.push(`## ${heading} (${plural(groups.length, 'group')})\n\n${groups.map((group) => imageGroupLine(group, report, { limit: Infinity })).join('\n')}`);
  };
  if (secrets.length > 0) {
    blocks.push(
      `## 🔑 Secrets in image layers (${secrets.length})\n\n${secrets.map((index) => `- ${report.cards[index].title}${report.cards[index].target ? ` · in \`${report.cards[index].target}\`` : ''}`).join('\n')}`
    );
  }
  section('⛔ Blocking remediation groups', blocking);
  section('⚠️ Exception groups — no fix available', exceptions);
  section('ℹ️ Logged groups', logged);
  if (blocks.length > 0) {
    blocks.push('Every finding\'s full explanation follows, in priority order.');
  }
  return blocks;
}

// ---- Slack Block Kit renderer (concise: what/where/how many + link) ---------

// Slack mrkdwn has no **bold** and renders `code` the same way markdown does.
function toSlackMrkdwn(text) {
  return text.replace(/\*\*(.+?)\*\*/g, '*$1*');
}

function slackCardLine(card) {
  const loc = card.deepLink ? `<${card.deepLink}|${card.location.path}${card.location.line ? `:${card.location.line}` : ''}>` : '';
  return `• *${card.title}*${loc ? `\n   ${loc}` : ''}`;
}

function slackGroupLine(group, report) {
  if (!group.evidence) {
    return slackCardLine(report.cards[group.findings[0]]);
  }
  const { package: pkg, installedVersion, fixedVersion } = group.evidence;
  const fix = fixedVersion ? ` → ${clip(fixedVersion)}` : '';
  return `• *${titleCase(group.severity)}* · \`${clip(pkg)}\` ${clip(installedVersion)}${fix} · ${plural(group.advisories.length, 'advisory', 'advisories')}`;
}

export function renderSlack(report, { detailUrl } = {}) {
  const counts = report.issueCounts ?? report.counts;
  const headline = `${report.emoji} ${report.image ? 'Image' : 'Security'} gate: ${report.headline ?? report.verdictLabel}`;
  const fields = [
    { type: 'mrkdwn', text: `*Blocking*\n${counts.block}` },
    { type: 'mrkdwn', text: `*Exceptions*\n${counts.exception}` },
    { type: 'mrkdwn', text: `*Logged*\n${counts.log}` },
    { type: 'mrkdwn', text: `*Repository*\n${report.context.repository || 'n/a'}` }
  ];
  if ((report.dispositionCounts?.review ?? 0) > 0) {
    fields.splice(3, 0, { type: 'mrkdwn', text: `*Needs review*\n${report.dispositionCounts.review}` });
  }
  if (counts.integrity > 0) {
    fields.splice(3, 0, { type: 'mrkdwn', text: `*Integrity failures*\n${counts.integrity}` });
  }
  if (report.issueCounts && report.issueCounts.issues !== report.issueCounts.rawFindings) {
    fields.push({
      type: 'mrkdwn',
      text: `*Scanner findings*\n${report.issueCounts.rawFindings} (${report.issueCounts.issues} unique)`
    });
  }
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: headline } },
    { type: 'section', text: { type: 'mrkdwn', text: `_${report.blurb}_` } },
    { type: 'section', fields }
  ];

  if (report.counts.integrity > 0 && report.gateStatus) {
    const status = report.gateStatus;
    const text = [
      ...status.explanations,
      `*Security state:* ${status.securityState}`,
      `*Suggested action:* ${status.suggestedActions.join(' ')}`,
      'Do not generate a baseline from this run.'
    ].join('\n');
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: toSlackMrkdwn(text) } });
  }

  if (report.breakGlassNotice) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: toSlackMrkdwn(report.breakGlassNotice) } });
  }

  // Concise: integrity failures and BLOCK issues only, in the same priority
  // order as every other surface; full detail lives in the PR comment / job
  // summary, which is linked below.
  // An image gate highlights secrets, then remediation groups, never per-CVE records.
  const actionable = report.image
    ? [
        ...report.issues.map((issue) => issue.card).filter((card) => card.isIntegrity).map(slackCardLine),
        ...report.image.secrets.map((index) => slackCardLine(report.cards[index])),
        ...report.image.blocking.map((group) => slackGroupLine(group, report))
      ]
    : Array.isArray(report.orderedIssues)
    ? [
        ...report.issues.map((issue) => issue.card).filter((card) => card.isIntegrity),
        ...report.orderedIssues.filter((issue) => issue.presentation.disposition === 'BLOCK').map((issue) => issue.card)
      ].map(slackCardLine)
    : sortCards(report.cards.filter((c) => c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY' || c.isIntegrity)).map(slackCardLine);
  const highlights = actionable.slice(0, 5);
  if (highlights.length > 0) {
    const shown = highlights.join('\n');
    const remaining = actionable.length - highlights.length;
    const more = remaining > 0 ? `\n_…and ${remaining} more — see full detail._` : '';
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `${shown}${more}` } });
  }

  const links = [];
  if (report.context.prNumber && report.context.repository) {
    links.push(`<https://github.com/${report.context.repository}/pull/${report.context.prNumber}|Open PR #${report.context.prNumber}>`);
  } else if (detailUrl) {
    links.push(`<${detailUrl}|Full detail>`);
  }
  if (report.context.runUrl) {
    links.push(`<${report.context.runUrl}|Run log and job summary>`);
  }
  if (links.length > 0) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: links.join('  ·  ') }] });
  }

  return { text: headline, blocks };
}
