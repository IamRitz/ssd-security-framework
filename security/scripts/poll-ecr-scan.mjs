import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function parseArguments(arguments_) {
  const values = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index]?.replace(/^--/, '').replaceAll('-', '_');
    const value = arguments_[index + 1];
    assert(key && value, `incomplete argument ${arguments_[index]}`);
    values[key] = value;
  }

  for (const required of ['repository', 'region', 'output']) {
    assert(values[required], `missing --${required.replaceAll('_', '-')}`);
  }
  // Prefer polling by immutable digest (the pushed manifest) so the scan result
  // is provably for the exact artifact that was pushed, not whatever a mutable
  // tag currently points at. Fall back to tag when no digest is supplied.
  assert(
    values.image_digest || values.image_tag,
    'missing --image-digest (preferred) or --image-tag'
  );
  return {
    ...values,
    maxAttempts: Number(values.max_attempts ?? 40),
    delaySeconds: Number(values.delay_seconds ?? 15)
  };
}

function run(command, arguments_, environment) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, { env: environment });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (error) => rejectPromise(new Error(`cannot start ${command}: ${error.message}`, {
      cause: error
    })));
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

function ecrScanArguments(options) {
  return [
    'ecr',
    'describe-image-scan-findings',
    '--repository-name',
    options.repository,
    '--image-id',
    options.image_digest ? `imageDigest=${options.image_digest}` : `imageTag=${options.image_tag}`,
    '--region',
    options.region,
    '--output',
    'json'
  ];
}

function awsInvocation(options, arguments_) {
  if (!options.aws_cli_container) {
    return { command: 'aws', arguments_, environment: process.env };
  }

  return {
    command: 'docker',
    arguments_: [
      'run',
      '--rm',
      '-e',
      'AWS_ACCESS_KEY_ID',
      '-e',
      'AWS_SECRET_ACCESS_KEY',
      '-e',
      'AWS_SESSION_TOKEN',
      '-e',
      'AWS_REGION',
      '-e',
      'AWS_DEFAULT_REGION',
      options.aws_cli_container,
      ...arguments_
    ],
    environment: process.env
  };
}

// ECR has two scanning modes with different DescribeImageScanFindings bodies.
// Confirmed against the live API (run 34744609758), not the documented schema:
//
//   BASIC      imageScanFindings.findings[]            { name, severity }
//   ENHANCED   imageScanFindings.enhancedFindings[]    Amazon Inspector findings:
//              packageVulnerabilityDetails.vulnerabilityId, severity,
//              fixAvailable "YES"|"NO"|"PARTIAL", status, type,
//              vulnerablePackages[].fixedInVersion, resources[].imageHash
//
// A COMPLETE enhanced body ALSO carries `findings: []`. A normalizer that only
// read `findings` accepted it as a clean basic scan — 1 Critical and 4 High
// findings normalized to zero, and the image deployed. Two guards now make that
// structurally impossible:
//   1. Mode is decided by which array is present, and both populated is ambiguous.
//   2. The parsed findings must reproduce ECR's own findingSeverityCounts exactly,
//      in BOTH modes. Any finding the parser did not see is a count mismatch.
const SEVERITY_MAP = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFORMATIONAL: 'low',
  UNDEFINED: 'low',
  // Inspector's not-yet-triaged severity. Mapped up, never down — the same
  // fail-closed choice as Trivy UNKNOWN and OSV advisories with no CVSS.
  UNTRIAGED: 'high'
};

function mappedSeverity(raw, label) {
  const severity = SEVERITY_MAP[raw];
  assert(severity, `unsupported ${label} severity ${raw}`);
  return severity;
}

// "PARTIAL" means at least one vulnerable package has a fix: the developer can
// act, so it is treated as fix-available (BLOCK_DEPLOY for Critical/High), never
// as no-fix (EXCEPTION). Any other value is not guessed at.
const FIX_AVAILABLE = { YES: true, PARTIAL: true, NO: false };

function normalizeBasicFinding(finding) {
  assert(typeof finding.name === 'string', 'ECR finding lacks name');
  return { id: finding.name, severity: mappedSeverity(finding.severity, 'ECR') };
}

function normalizeEnhancedFinding(finding, imageDigest) {
  const details = finding.packageVulnerabilityDetails;
  const id = details?.vulnerabilityId;
  assert(typeof id === 'string' && id !== '', 'enhanced finding lacks packageVulnerabilityDetails.vulnerabilityId');
  // Only package vulnerabilities apply to a container image. An unknown type is
  // a shape this normalizer has not been verified against.
  assert(
    finding.type === 'PACKAGE_VULNERABILITY',
    `enhanced finding ${id} has unsupported type ${finding.type}`
  );
  // Observed live: ACTIVE. SUPPRESSED/CLOSED have not been observed through this
  // API, so rather than silently drop or silently keep them, fail closed.
  assert(finding.status === 'ACTIVE', `enhanced finding ${id} has unsupported status ${finding.status}`);
  assert(
    Object.hasOwn(FIX_AVAILABLE, finding.fixAvailable ?? ''),
    `enhanced finding ${id} has unsupported fixAvailable ${JSON.stringify(finding.fixAvailable)}`
  );
  // Digest binding, one level deeper than imageId: every finding must name the
  // exact manifest that was polled.
  const images = (finding.resources ?? []).filter((resource) => resource.type === 'AWS_ECR_CONTAINER_IMAGE');
  assert(images.length > 0, `enhanced finding ${id} names no AWS_ECR_CONTAINER_IMAGE resource`);
  for (const resource of images) {
    const hash = resource.details?.awsEcrContainerImage?.imageHash;
    assert(hash === imageDigest, `enhanced finding ${id} is for image ${hash}, not ${imageDigest}`);
  }

  const packages = details.vulnerablePackages ?? [];
  const names = [...new Set(packages.map((pkg) => pkg.name).filter((name) => typeof name === 'string'))];
  const fixedVersion = packages
    .map((pkg) => pkg.fixedInVersion)
    .find((version) => typeof version === 'string' && version !== '' && version !== 'NotAvailable');

  return {
    id,
    severity: mappedSeverity(finding.severity, 'enhanced'),
    fixAvailable: FIX_AVAILABLE[finding.fixAvailable],
    ...(names.length > 0 ? { package: names.join(', ') } : {}),
    ...(fixedVersion ? { fixedVersion } : {}),
    ...(typeof finding.title === 'string' ? { title: finding.title } : {}),
    ...(typeof details.sourceUrl === 'string' ? { url: details.sourceUrl } : {})
  };
}

export function normalizeEcrResponse(response, options) {
  assert(response.imageScanStatus?.status === 'COMPLETE', 'ECR scan is not complete');
  const scan = response.imageScanFindings;
  // A PENDING body (observed live) carries `findings: []` but no severity
  // counts, so requiring the counts is also what keeps a not-yet-started scan
  // from ever reading as a complete scan with no findings.
  assert(
    scan?.findingSeverityCounts && typeof scan.findingSeverityCounts === 'object',
    'ECR response lacks findingSeverityCounts'
  );
  assert(typeof response.imageId?.imageDigest === 'string', 'ECR response lacks image digest');
  // If we polled by digest, bind the result: ECR must have scanned that exact
  // manifest, not a different one behind the same tag.
  assert(
    !options.image_digest || response.imageId.imageDigest === options.image_digest,
    `ECR scan digest ${response.imageId.imageDigest} does not match requested ${options.image_digest}`
  );

  const hasEnhanced = Array.isArray(scan.enhancedFindings);
  const hasBasic = Array.isArray(scan.findings);
  assert(hasEnhanced || hasBasic, 'ECR response has neither findings nor enhancedFindings');
  assert(
    !(hasEnhanced && hasBasic && scan.enhancedFindings.length > 0 && scan.findings.length > 0),
    'ECR response has both basic and enhanced findings populated — mode is ambiguous'
  );

  const enhanced = hasEnhanced;
  const findings = enhanced
    ? scan.enhancedFindings.map((finding) => normalizeEnhancedFinding(finding, response.imageId.imageDigest))
    : scan.findings.map(normalizeBasicFinding);

  const severityCounts = findings.reduce((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    return counts;
  }, {});

  // Guard 2: reconcile with ECR's own counts. This is what would have caught the
  // fail-open — ECR said {CRITICAL:1, HIGH:4, MEDIUM:1}, the parser saw nothing.
  const reported = {};
  for (const [rawSeverity, count] of Object.entries(scan.findingSeverityCounts)) {
    assert(Number.isInteger(count) && count >= 0, `ECR severity count for ${rawSeverity} is not a non-negative integer`);
    const severity = mappedSeverity(rawSeverity, 'ECR count');
    reported[severity] = (reported[severity] ?? 0) + count;
  }
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    assert(
      (reported[severity] ?? 0) === (severityCounts[severity] ?? 0),
      `ECR reported ${reported[severity] ?? 0} ${severity} finding(s) but ${severityCounts[severity] ?? 0} were parsed ` +
        `from ${enhanced ? 'enhancedFindings' : 'findings'} — refusing to under-report`
    );
  }

  return {
    schemaVersion: 1,
    source: enhanced ? 'aws-ecr-enhanced' : 'aws-ecr-basic',
    scanStatus: 'COMPLETE',
    image: {
      repository: options.repository,
      imageTag: options.image_tag,
      imageDigest: response.imageId.imageDigest
    },
    severityCounts,
    findings
  };
}

// Errors that retrying cannot fix. Deliberately narrow: only authorization
// failures. Throttling, transient network errors, and "scan not found yet" keep
// the normal retry path.
export function isPermanentAwsError(stderr) {
  return /\b(AccessDeniedException|AccessDenied|UnauthorizedOperation|UnrecognizedClientException|InvalidClientTokenId|ExpiredTokenException)\b|is not authorized to perform/.test(
    String(stderr ?? '')
  );
}

// Every raw DescribeImageScanFindings attempt, persisted as it happens so the
// record survives a throw. This is evidence, never a gate input: it is how the
// real response shape (basic vs enhanced) and any permission error are observed
// empirically, and it is the raw registry side of the Trivy comparison.
async function recordRawAttempts(path, attempts) {
  if (!path) {
    return;
  }
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify({ attempts }, null, 2)}\n`);
}

export async function pollEcrScan(options) {
  assert(Number.isInteger(options.maxAttempts) && options.maxAttempts > 0, 'invalid max attempts');
  assert(Number.isFinite(options.delaySeconds) && options.delaySeconds >= 0, 'invalid delay');
  const invocation = awsInvocation(options, ecrScanArguments(options));
  const attempts = [];
  let lastWaitReason = 'no successful response';

  for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
    const result = await run(invocation.command, invocation.arguments_, invocation.environment);
    const record = {
      attempt,
      at: new Date().toISOString(),
      exitCode: result.code,
      stderr: result.stderr.trim().slice(0, 4000) || null,
      response: null
    };
    attempts.push(record);

    if (result.code === 0) {
      let response;
      try {
        response = JSON.parse(result.stdout);
      } catch (error) {
        record.rawStdout = result.stdout.slice(0, 4000);
        await recordRawAttempts(options.raw_output, attempts);
        throw new Error(`AWS CLI returned malformed JSON: ${error.message}`, { cause: error });
      }
      record.response = response;
      await recordRawAttempts(options.raw_output, attempts);
      const status = response.imageScanStatus?.status;
      if (status === 'COMPLETE' && findingsAttached(response)) {
        console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: COMPLETE`);
        return normalizeEcrResponse(response, options);
      }
      if (status === 'COMPLETE') {
        // Observed live (run 34745111774): with enhanced scanning, ECR reported
        // COMPLETE ~10s after imageScanCompletedAt with `findings: []` and NO
        // severity counts or enhancedFindings — Inspector had not attached its
        // results yet. The previous run's findings arrived ~22s after completion.
        // This is "not ready", not "clean": wait within the attempt budget, and
        // if the counts never appear, fail closed at the limit below.
        //
        // Observed live (run 34809100547): a CLEAN enhanced scan returns this same
        // counts-less body permanently. For 40 attempts over 10 minutes it never
        // changed, and Inspector showed the digest scanned with zero findings. The
        // body alone cannot tell "not attached yet" from "clean", so ask Inspector
        // directly. Only a positive confirmation reads as clean; anything else
        // keeps waiting.
        const confirmation = await confirmCleanEnhancedScan(response, options);
        record.cleanConfirmation = confirmation;
        await recordRawAttempts(options.raw_output, attempts);
        if (confirmation.clean) {
          console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: COMPLETE, clean (confirmed with Inspector)`);
          return cleanEnhancedReport(response, options);
        }
        lastWaitReason = `COMPLETE but findings not yet attached (no findingSeverityCounts; ${confirmation.reason})`;
        console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: ${lastWaitReason}`);
      } else if (['IN_PROGRESS', 'PENDING', 'ACTIVE'].includes(status)) {
        lastWaitReason = status;
        console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: ${status}`);
      } else {
        throw new Error(`ECR image scan ended with status ${status ?? 'UNKNOWN'}`);
      }
    } else {
      await recordRawAttempts(options.raw_output, attempts);
      // Surface the CLI error on every attempt, not only the last: a permanent
      // error (e.g. a missing permission) must be visible immediately rather than
      // hidden behind forty identical "not ready" lines.
      const firstLine = result.stderr.trim().split('\n')[0] || `exit ${result.code}`;
      console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: not ready (${firstLine})`);
      // An authorization failure cannot become ready by waiting. Observed live:
      // with ECR enhanced scanning, DescribeImageScanFindings needs Inspector
      // permissions, and a role without them spent all 40 attempts (10m17s)
      // retrying an AccessDenied before failing closed. Fail closed on the first
      // attempt instead; the outcome is identical, just ten minutes sooner.
      if (isPermanentAwsError(result.stderr)) {
        throw new Error(`AWS CLI authorization failure while polling ECR (not retried): ${result.stderr.trim()}`);
      }
      if (attempt === options.maxAttempts) {
        throw new Error(`AWS CLI failed while polling ECR: ${result.stderr.trim()}`);
      }
    }

    if (attempt < options.maxAttempts) {
      await delay(options.delaySeconds * 1000);
    }
  }

  throw new Error(
    `ECR image scan did not complete before the polling limit (last state: ${lastWaitReason})`
  );
}

// How long the counts-less body must persist after imageScanCompletedAt before
// Inspector is asked whether it is clean. Findings for a vulnerable image have
// attached within ~22s of completion; this leaves margin for that race.
export const CLEAN_SETTLE_SECONDS = 60;

// Inspector coverage states that mean "this image was scanned successfully".
const CONFIRMED_COVERAGE_STATUSES = [
  // Observed live after a successful scan-on-push scan (run 34809100547), and on
  // the vulnerable image from run 34744609758 whose findings did attach.
  ['INACTIVE', 'SCAN_FREQUENCY_SCAN_ON_PUSH'],
  // Documented state for a successfully scanned, continuously monitored image.
  ['ACTIVE', 'SUCCESSFUL']
];

async function awsJson(options, arguments_) {
  const invocation = awsInvocation(options, arguments_);
  const result = await run(invocation.command, invocation.arguments_, invocation.environment);
  if (result.code !== 0) {
    if (isPermanentAwsError(result.stderr)) {
      throw new Error(
        `AWS CLI authorization failure while confirming a clean scan with Inspector (not retried): ${result.stderr.trim()}`
      );
    }
    return { error: result.stderr.trim().split('\n')[0] || `exit ${result.code}` };
  }
  try {
    return { body: JSON.parse(result.stdout) };
  } catch {
    return { error: 'malformed JSON from Inspector' };
  }
}

function notConfirmed(reason) {
  return { clean: false, reason };
}

// Positive evidence that a counts-less COMPLETE body is a clean enhanced scan,
// not an unattached one. Every condition must hold. Any failure, including an
// Inspector API error, returns not-confirmed, and the poller keeps waiting and
// fails closed at its limit.
//   1. The body has exactly the counts-less shape: `findings: []`, no counts,
//      no enhancedFindings, and it was polled by digest.
//   2. At least CLEAN_SETTLE_SECONDS have passed since imageScanCompletedAt.
//   3. Inspector coverage has exactly one package-scan entry for this manifest,
//      in a confirmed-scanned status, last scanned no earlier than ECR's completion.
//   4. Inspector holds zero findings, in any status, for this image hash.
export async function confirmCleanEnhancedScan(response, options, now = Date.now()) {
  const scan = response.imageScanFindings ?? {};
  const digest = response.imageId?.imageDigest;
  if (!options.image_digest || digest !== options.image_digest) {
    return notConfirmed('clean confirmation requires polling by digest');
  }
  if (
    Object.hasOwn(scan, 'findingSeverityCounts') ||
    Object.hasOwn(scan, 'enhancedFindings') ||
    !Array.isArray(scan.findings) ||
    scan.findings.length > 0
  ) {
    return notConfirmed('body is not the counts-less COMPLETE shape');
  }
  const completedAt = Date.parse(scan.imageScanCompletedAt);
  if (!Number.isFinite(completedAt)) {
    return notConfirmed('body lacks imageScanCompletedAt');
  }
  const settleSeconds = options.cleanSettleSeconds ?? CLEAN_SETTLE_SECONDS;
  if (now - completedAt < settleSeconds * 1000) {
    return notConfirmed(`settling: less than ${settleSeconds}s since the scan completed`);
  }
  if (typeof response.registryId !== 'string' || response.registryId === '') {
    return notConfirmed('body lacks registryId');
  }

  const resourceId = `arn:aws:ecr:${options.region}:${response.registryId}:repository/${options.repository}/${digest}`;
  const coverage = await awsJson(options, [
    'inspector2',
    'list-coverage',
    '--region',
    options.region,
    '--filter-criteria',
    JSON.stringify({ resourceId: [{ comparison: 'EQUALS', value: resourceId }] }),
    '--output',
    'json'
  ]);
  if (coverage.error) {
    return notConfirmed(`Inspector coverage unavailable: ${coverage.error}`);
  }
  const resources = coverage.body?.coveredResources;
  if (!Array.isArray(resources) || resources.length !== 1) {
    return notConfirmed(
      `Inspector coverage lists ${Array.isArray(resources) ? resources.length : 'no'} resource(s) for ${digest}`
    );
  }
  const [resource] = resources;
  if (
    resource.resourceId !== resourceId ||
    resource.resourceType !== 'AWS_ECR_CONTAINER_IMAGE' ||
    resource.scanType !== 'PACKAGE'
  ) {
    return notConfirmed('Inspector coverage entry is not a package scan of this image');
  }
  const { statusCode, reason } = resource.scanStatus ?? {};
  if (!CONFIRMED_COVERAGE_STATUSES.some(([code, why]) => code === statusCode && why === reason)) {
    return notConfirmed(`Inspector coverage status ${statusCode}/${reason} is not a confirmed scan`);
  }
  const lastScannedAt = Date.parse(resource.lastScannedAt);
  if (!Number.isFinite(lastScannedAt) || lastScannedAt < completedAt) {
    return notConfirmed('Inspector has not scanned this image since ECR reported completion');
  }

  // No status filter: a SUPPRESSED or CLOSED finding is not "clean" either. The
  // CLI auto-paginates, so this is the complete list.
  const inspectorFindings = await awsJson(options, [
    'inspector2',
    'list-findings',
    '--region',
    options.region,
    '--filter-criteria',
    JSON.stringify({ ecrImageHash: [{ comparison: 'EQUALS', value: digest }] }),
    '--output',
    'json'
  ]);
  if (inspectorFindings.error) {
    return notConfirmed(`Inspector findings unavailable: ${inspectorFindings.error}`);
  }
  if (!Array.isArray(inspectorFindings.body?.findings)) {
    return notConfirmed('Inspector list-findings returned no findings array');
  }
  if (inspectorFindings.body.findings.length > 0) {
    return notConfirmed(
      `Inspector holds ${inspectorFindings.body.findings.length} finding(s) for ${digest} that ECR has not attached`
    );
  }

  return {
    clean: true,
    resourceId,
    coverageStatus: `${statusCode}/${reason}`,
    lastScannedAt: resource.lastScannedAt,
    inspectorFindings: 0
  };
}

// The same report normalizeEcrResponse produces for an enhanced scan with zero
// findings. It is only reachable through confirmCleanEnhancedScan.
function cleanEnhancedReport(response, options) {
  return {
    schemaVersion: 1,
    source: 'aws-ecr-enhanced',
    scanStatus: 'COMPLETE',
    image: {
      repository: options.repository,
      imageTag: options.image_tag,
      imageDigest: response.imageId.imageDigest
    },
    severityCounts: {},
    findings: []
  };
}

// A COMPLETE status alone does not mean results are readable: the severity
// counts are what a finished scan — basic or enhanced, clean or not — carries.
// normalizeEcrResponse re-asserts this independently.
export function findingsAttached(response) {
  const counts = response.imageScanFindings?.findingSeverityCounts;
  return Boolean(counts) && typeof counts === 'object' && !Array.isArray(counts);
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const report = await pollEcrScan(options);
  await mkdir(dirname(options.output), { recursive: true });
  await writeFile(options.output, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`ECR image scan report written to ${options.output}`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
