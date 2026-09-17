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
//   decision            approved | denied | expired | timeout |
//                       decision-unavailable | request-failed |
//                       request-not-attempted | not-requested | not-eligible |
//                       unknown | not-applicable
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
  decision = null
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
  return { slack, slackReason, prComment: true, summary: true };
}

// Normalize a gate JSON result into the report every renderer consumes.
// `breakGlass` is the run's OBSERVED break-glass state (deriveBreakGlassState);
// when omitted it is derived with no runtime evidence, which claims nothing.
export function buildReport({ gate, context = {}, mode = 'enforce', breakGlass }) {
  const verdict = gate?.verdict || 'BLOCK';
  const meta = VERDICTS[verdict] || VERDICTS.BLOCK;
  const findings = Array.isArray(gate?.findings) ? gate.findings : [];
  const cards = findings.map((finding) => classify(finding, context, gate));
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

  let blurb = meta.blurb;
  if (isBlockingVerdict(verdict) && mode === 'log-only') {
    blurb = 'Blocking findings reported — NOT enforced, because this repository runs in log-only mode.';
  } else if (breakGlassState.decision === 'approved') {
    blurb = 'Blocking findings were found; a verified break-glass approval overrode the BLOCK for this run only.';
  }

  return {
    verdict,
    verdictLabel: meta.label,
    emoji: meta.emoji,
    blurb,
    context,
    mode,
    cards,
    counts,
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
  if (card.severityNote) {
    facts.push(`📊 ${card.severityNote}`);
  }
  if (card.evidenceNote) {
    facts.push(`🔎 ${card.evidenceNote}`);
  }
  if (card.reproduce) {
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

function renderGroupMarkdown(heading, cards, { collapseOver = 10 } = {}) {
  if (cards.length === 0) {
    return '';
  }
  const sorted = sortCards(cards);
  const body = sorted.map(renderCardMarkdown).join('\n\n');
  const title = `### ${heading} (${cards.length})`;
  if (cards.length > collapseOver) {
    return `${title}\n\n<details><summary>Show ${cards.length} findings</summary>\n\n${body}\n\n</details>`;
  }
  return `${title}\n\n${body}`;
}

export function renderMarkdown(report, { includeMarker = false } = {}) {
  const { counts } = report;
  const blocks = [];
  if (includeMarker) {
    blocks.push(PR_COMMENT_MARKER);
  }
  blocks.push(`## ${report.emoji} Security gate: ${report.verdictLabel}`);
  blocks.push(`_${report.blurb}_`);

  const ctx = contextLine(report.context);
  if (ctx) {
    blocks.push(ctx);
  }

  const summaryBits = [`**${counts.block}** blocking`, `**${counts.exception}** exception`, `**${counts.log}** logged`];
  if (counts.integrity > 0) {
    summaryBits.push(`**${counts.integrity}** integrity failure${counts.integrity === 1 ? '' : 's'}`);
  }
  blocks.push(summaryBits.join(' · '));

  if (report.mode === 'log-only') {
    blocks.push('> ℹ️ This repository runs in **log-only** mode: findings are reported but do not block, and no Slack alert is sent.');
  }
  if (report.breakGlassNotice) {
    blocks.push(`> ${report.breakGlassNotice}`);
  }

  const blocking = report.cards.filter((c) => (c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY') && !c.isIntegrity);
  const integrity = report.cards.filter((c) => c.isIntegrity);
  const exceptions = report.cards.filter((c) => c.action === 'EXCEPTION');
  const logged = report.cards.filter((c) => c.action === 'LOG');

  // Actionable groups (integrity, blocking, exceptions) stay visible even at
  // repo scale; only very large lists collapse. LOG noise collapses early.
  const integritySection = renderGroupMarkdown(
    '🚨 Scan integrity failures — results UNKNOWN, fail-closed, not a code defect',
    integrity,
    { collapseOver: 25 }
  );
  if (integritySection) blocks.push(integritySection);
  const blockingSection = renderGroupMarkdown('⛔ Blocking findings', blocking, { collapseOver: 25 });
  if (blockingSection) blocks.push(blockingSection);
  const exceptionSection = renderGroupMarkdown(
    '⚠️ Tracked exceptions (no fix available — passed deliberately)',
    exceptions,
    { collapseOver: 25 }
  );
  if (exceptionSection) blocks.push(exceptionSection);
  const loggedSection = renderGroupMarkdown('📝 Logged (non-blocking)', logged, { collapseOver: 5 });
  if (loggedSection) blocks.push(loggedSection);

  if (report.cards.length === 0) {
    blocks.push('No findings. 🎉');
  }

  return blocks.filter(Boolean).join('\n\n') + '\n';
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

export function renderSlack(report, { detailUrl } = {}) {
  const { counts } = report;
  const headline = `${report.emoji} Security gate: ${report.verdictLabel}`;
  const fields = [
    { type: 'mrkdwn', text: `*Blocking*\n${counts.block}` },
    { type: 'mrkdwn', text: `*Exceptions*\n${counts.exception}` },
    { type: 'mrkdwn', text: `*Logged*\n${counts.log}` },
    { type: 'mrkdwn', text: `*Repository*\n${report.context.repository || 'n/a'}` }
  ];
  if (counts.integrity > 0) {
    fields.splice(3, 0, { type: 'mrkdwn', text: `*Integrity failures*\n${counts.integrity}` });
  }
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: headline } },
    { type: 'section', text: { type: 'mrkdwn', text: `_${report.blurb}_` } },
    { type: 'section', fields }
  ];

  if (report.breakGlassNotice) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: toSlackMrkdwn(report.breakGlassNotice) } });
  }

  // Concise: show the most severe blocking/integrity findings only; full detail
  // lives in the PR comment / job summary, which is linked below.
  const actionable = report.cards.filter((c) => c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY' || c.isIntegrity);
  const highlights = sortCards(actionable).slice(0, 5);
  if (highlights.length > 0) {
    const shown = highlights.map(slackCardLine).join('\n');
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
