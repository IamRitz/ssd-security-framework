// `ssd-onboard aws doctor`: is the AWS side of this repository's delivery
// ready, and is it scoped the way the framework assumes?
//
// READ-ONLY. Every AWS call goes through readOnlyAws(), whose allowlist admits
// only listed read operations; there is no mutating wrapper in Phase 2A.
//
// Order is part of the contract:
//   1. resolve the region (--region > delivery.aws.region); a flag that
//      disagrees with the configuration blocks BEFORE AWS is contacted;
//   2. sts get-caller-identity; a wrong account or the root user blocks BEFORE
//      any other call;
//   3. discovery, each result present | absent | unverified — an access denial
//      is never reported as absence;
//   4. checks, pure functions of what was discovered.
//
// Statuses: PASS, WARN, FAIL, NOT VERIFIED. `required` marks a prerequisite
// whose NOT VERIFIED blocks readiness (exit 1): doctor could not safely prove
// it. Each check names its basis: runtime (observed state), configuration,
// policy-document (offline analysis) or simulation.
import { readOnlyAws } from './aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from './identity.mjs';
import { discoverRegistryScanning, discoverRepository, scanningCoverage } from './discover/ecr.mjs';
import { discoverInspectorAccount, discoverInspectorCoverage } from './discover/inspector.mjs';
import { discoverRole, discoverRolePolicies, simulateRole } from './discover/iam-role.mjs';
import { discoverOidcProvider } from './discover/oidc-provider.mjs';
import { describeError } from './discover/result.mjs';
import { discoverInstance, discoverInstanceProfile, discoverManagedInstance } from './discover/ssm.mjs';
import { discoverStack, evaluateOwnership } from './discover/stacks.mjs';
import { SHARED_STACKS, repoStackName } from './stack-names.mjs';
import { principals, statements } from './policy/evaluate.mjs';
import { analyzePermissions, proposedInstancePolicy, simulationGroups } from './policy/permissions.mjs';
import { GITHUB_OIDC_HOST, STS_AUDIENCE, evaluateTrust, intendedContexts, providerArn } from './policy/trust.mjs';

export const SCHEMA_VERSION = 1;
export const PASS = 'PASS';
export const WARN = 'WARN';
export const FAIL = 'FAIL';
export const NOT_VERIFIED = 'NOT VERIFIED';
const RANK = { [PASS]: 0, [WARN]: 1, [NOT_VERIFIED]: 2, [FAIL]: 3 };

// Outcomes: JSON value -> exit code.
export const OUTCOMES = Object.freeze({ READY: 0, READY_WITH_WARNINGS: 0, NOT_VERIFIED: 1, BLOCKED: 1, ERROR: 1 });

function check(id, section, title, fields = {}) {
  return { id, section, title, status: PASS, required: true, basis: 'runtime', observed: [], expected: [], findings: [], remediation: [], ...fields };
}

// The worst severity among findings (and a floor).
function worst(findings, floor = PASS) {
  return findings.reduce((acc, f) => (RANK[f.severity] > RANK[acc] ? f.severity : acc), floor);
}

const unverifiedCheck = (c, result) => ({ ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: result.error.kind, message: describeError(result) }] });

// --- checks ------------------------------------------------------------------------

export function oidcProviderCheck(result, { account, partition }) {
  const expected = providerArn(account, partition);
  const c = check('oidc.provider', 'GitHub OIDC', 'Provider', {
    expected: [`${expected}`, `client ID (audience) ${STS_AUDIENCE}`],
    remediation: []
  });
  if (result.state === 'unverified') {
    return unverifiedCheck(c, result);
  }
  if (result.state === 'absent') {
    return {
      ...c,
      status: FAIL,
      observed: [`no IAM OIDC provider for ${GITHUB_OIDC_HOST} in the account`],
      findings: [{ severity: FAIL, kind: 'resource-absent', message: 'the GitHub OIDC provider does not exist, so no workflow can assume a role' }],
      remediation: ['Create it in the shared scope (a future `ssd-onboard aws plan --scope shared`), or by hand with audience sts.amazonaws.com.']
    };
  }
  const p = result.value;
  const findings = [];
  if (p.account !== account) {
    findings.push({ severity: FAIL, kind: 'account-mismatch', message: `the listed provider ${p.arn} belongs to account ${p.account}, not ${account}` });
  }
  if (p.url !== GITHUB_OIDC_HOST) {
    findings.push({ severity: FAIL, kind: 'wrong-provider', message: `provider URL is '${p.url}', not ${GITHUB_OIDC_HOST}` });
  }
  if (!p.clientIds.includes(STS_AUDIENCE)) {
    findings.push({ severity: FAIL, kind: 'wrong-audience', message: `client IDs [${p.clientIds.join(', ')}] do not include ${STS_AUDIENCE}` });
  }
  const extra = p.clientIds.filter((id) => id !== STS_AUDIENCE);
  if (extra.length > 0) {
    findings.push({ severity: WARN, kind: 'additional-audiences', message: `the provider also accepts audiences [${extra.join(', ')}]; each role must still require aud = ${STS_AUDIENCE}` });
  }
  return {
    ...c,
    status: worst(findings),
    observed: [p.arn, `client IDs: ${p.clientIds.join(', ') || '(none)'}`, `thumbprints: ${p.thumbprints.length} (reported only; not changed)`, ...p.others.map((o) => `also listed: ${o}`)],
    findings
  };
}

export function subjectFormatCheck(trustResults) {
  const formats = [...new Set(trustResults.map((t) => t?.format).filter(Boolean))];
  return check('oidc.subject-format', 'GitHub OIDC', 'Subject format', {
    status: NOT_VERIFIED,
    required: false,
    basis: 'policy-document',
    observed: [formats.length ? `role trust policies use the ${formats.join(' and ')} subject format` : 'no accepted role trust subject was found', 'which format GitHub issues for this repository is set by its OIDC customization, which doctor does not read'],
    expected: ['legacy repo:<owner>/<repo>:<context>, or the immutable repo:<owner>@<owner_id>/<repo>@<repo_id>:<context> customization — whichever GitHub actually sends'],
    findings: [{ severity: NOT_VERIFIED, kind: 'subject-format-unverified', message: 'the subject format GitHub issues is not independently verified (no GitHub API calls from aws commands)' }],
    remediation: ['Confirm with a claims-printing workflow run, or `gh api repos/<owner>/<repo>/actions/oidc/customization/sub` (a later, explicit integration will do this).']
  });
}

export function repositoryCheck(result, { account, repository }) {
  const c = check('ecr.repository', 'ECR', 'Repository', { expected: [`repository ${repository} in account ${account}`] });
  if (result.state === 'unverified') {
    return unverifiedCheck(c, result);
  }
  if (result.state === 'absent') {
    return { ...c, status: FAIL, observed: [`no repository ${repository}`], findings: [{ severity: FAIL, kind: 'resource-absent', message: `ECR repository ${repository} does not exist` }], remediation: ['Create it (or set delivery.ecr.repository to the existing one).'] };
  }
  const r = result.value;
  const findings = [];
  if (r.registryId && r.registryId !== account) {
    findings.push({ severity: FAIL, kind: 'account-mismatch', message: `registry ${r.registryId} is not account ${account}` });
  }
  const facts = [
    `ARN ${r.arn}`,
    `URI ${r.uri}`,
    `encryption: ${r.encryption.type ?? 'unknown'}${r.encryption.kmsKey ? ` (${r.encryption.kmsKey})` : ''}`,
    `repository-level scanOnPush: ${r.scanOnPush}`,
    `lifecycle policy: ${presence(r.lifecyclePolicy)}`,
    `repository policy: ${presence(r.repositoryPolicy)}`
  ];
  if (r.repositoryPolicy.state === 'present') {
    findings.push(...repositoryPolicyFindings(r.repositoryPolicy.value.text, account));
  }
  return { ...c, status: worst(findings), observed: facts, findings };
}

const presence = (result) => (result.state === 'present' ? 'present' : result.state === 'absent' ? 'none' : `not readable (${describeError(result)})`);

// A repository policy that opens the repository beyond the account.
function repositoryPolicyFindings(text, account) {
  let stmts;
  try {
    stmts = statements(text);
  } catch (error) {
    return [{ severity: NOT_VERIFIED, kind: 'malformed-policy', message: `repository policy: ${error.message}` }];
  }
  const out = [];
  for (const s of stmts.filter((x) => x.effect === 'Allow')) {
    const p = principals(s.principal);
    if (p.any) {
      out.push({
        severity: Object.keys(s.condition).length === 0 ? FAIL : WARN,
        kind: 'public-repository-policy',
        message: `repository policy statement ${s.sid} allows Principal "*"${Object.keys(s.condition).length ? ' (with conditions, not evaluated)' : ''}`
      });
    }
    for (const principal of p.aws) {
      const other = /^arn:[^:]+:iam::(\d{12}):/.exec(principal)?.[1] ?? (/^\d{12}$/.test(principal) ? principal : null);
      if (other && other !== account) {
        out.push({ severity: WARN, kind: 'cross-account-access', message: `repository policy statement ${s.sid} grants ${principal}` });
      }
    }
  }
  return out;
}

export function immutabilityCheck(result) {
  const c = check('ecr.tag-immutability', 'ECR', 'Tag immutability', {
    required: false,
    expected: ['IMMUTABLE (deploys pin the digest, so a mutable tag cannot swap the deployed image — but a tag can still be repointed)']
  });
  if (result.state !== 'present') {
    return { ...c, status: NOT_VERIFIED, observed: ['repository not available'] };
  }
  const m = result.value.tagMutability;
  if (m === 'IMMUTABLE') {
    return { ...c, observed: ['IMMUTABLE'] };
  }
  if (m === null) {
    return { ...c, status: NOT_VERIFIED, observed: ['tag mutability not reported'], findings: [{ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'imageTagMutability missing' }] };
  }
  const exclusions = result.value.tagMutabilityExclusions;
  return {
    ...c,
    status: WARN,
    observed: [`${m}${exclusions.length ? ` (exclusions: ${exclusions.join(', ')})` : ''}`],
    findings: [{ severity: WARN, kind: 'mutable-tags', message: `image tags are ${m}: a tag can be repointed to another image` }],
    remediation: ['Set the repository to IMMUTABLE (an owner decision for an existing repository; doctor changes nothing).']
  };
}

const SCAN_TYPES = ['BASIC', 'ENHANCED'];

// true (ENHANCED) | false (BASIC) | null (unknown: unreadable or unrecognised).
export const enhancedOf = (scanning) => (scanning.state === 'present' && SCAN_TYPES.includes(scanning.value.scanType) ? scanning.value.scanType === 'ENHANCED' : null);

export function scanningCheck(result, { repository, repositoryScanOnPush }) {
  const c = check('ecr.scanning', 'ECR', 'Registry scanning coverage', { expected: [`a registry scanning rule that scans ${repository} on push (BASIC) or on push/continuously (ENHANCED)`] });
  if (result.state !== 'present') {
    return result.state === 'unverified' ? unverifiedCheck(c, result) : { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'no scanning configuration returned' }] };
  }
  const s = result.value;
  if (!SCAN_TYPES.includes(s.scanType)) {
    // Coverage rules mean different things under BASIC and ENHANCED; with no
    // recognised scan type nothing can be concluded from them.
    return {
      ...c,
      status: NOT_VERIFIED,
      observed: [`registry scan type ${s.scanType === null || s.scanType === undefined ? 'missing' : `'${s.scanType}'`} (not BASIC or ENHANCED)`],
      findings: [{ severity: NOT_VERIFIED, kind: 'scan-type-unknown', message: 'the registry scan type is missing or unrecognised, so coverage cannot be evaluated' }]
    };
  }
  const coverage = scanningCoverage(s, repository, { repositoryScanOnPush });
  const observed = [`registry scan type ${s.scanType ?? 'unknown'}`, ...s.rules.map((r, i) => `rule ${i + 1}: ${r.frequency} for ${r.filters.map((f) => `${f.type} '${f.filter}'`).join(', ') || '(no filters)'}`)];
  const findings = coverage.unsupported.map((message) => ({ severity: coverage.covered ? WARN : NOT_VERIFIED, kind: 'unsupported-construct', message }));
  if (coverage.covered) {
    observed.push(coverage.basis === 'registry-rule' ? `covered: rule ${coverage.rule} ('${coverage.filter}') ${coverage.frequency}` : 'covered: repository-level scanOnPush (BASIC)');
    if (coverage.basis === 'repository-setting') {
      findings.push({ severity: WARN, kind: 'deprecated-repository-scan', message: 'coverage relies on the deprecated repository-level scanOnPush; a registry rule is the supported setting' });
    }
  } else {
    findings.push({
      severity: findings.length ? NOT_VERIFIED : FAIL,
      kind: 'not-covered',
      message: `no registry rule scans ${repository} automatically${coverage.frequency === 'MANUAL' ? ' (only a MANUAL rule matches)' : ''}: the pipeline would wait for a scan that never happens and fail closed`
    });
  }
  return { ...c, status: worst(findings), observed, findings, coverage, remediation: coverage.covered ? [] : ['Add a filter for this repository to the registry scanning configuration (shared scope; a future `aws plan --scope shared` proposes current rules + one filter, never a replacement).'] };
}

export function inspectorCheck(account, coverage) {
  const c = check('ecr.inspector', 'ECR', 'Inspector (enhanced scanning)', { expected: ['Inspector ECR scanning ENABLED for the account', 'an ACTIVE Inspector coverage record for the repository'] });
  if (account.state === 'unverified') {
    return unverifiedCheck(c, account);
  }
  const findings = [];
  const observed = [];
  if (account.state === 'absent') {
    findings.push({ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'Inspector returned no status for this account' });
  } else {
    observed.push(`account ${account.value.accountState ?? 'unknown'}, ECR ${account.value.ecrState ?? 'unknown'}`);
    if (account.value.ecrState !== 'ENABLED') {
      findings.push({ severity: FAIL, kind: 'inspector-disabled', message: `registry scanning is ENHANCED but Inspector ECR scanning is ${account.value.ecrState ?? 'unknown'}` });
    }
  }
  if (coverage.state === 'unverified') {
    findings.push({ severity: WARN, kind: coverage.error.kind, message: `repository coverage not read: ${describeError(coverage)}` });
  } else if (coverage.state === 'present') {
    const records = coverage.value.records;
    if (records.length === 0) {
      findings.push({ severity: WARN, kind: 'no-coverage-record', message: 'Inspector lists no coverage record for the repository yet (Inspector being enabled does not prove this repository is covered)' });
    }
    for (const r of records) {
      observed.push(`coverage ${r.resourceId}: ${r.scanStatus}${r.reason ? ` (${r.reason})` : ''}`);
      if (r.scanStatus !== 'ACTIVE') {
        findings.push({ severity: FAIL, kind: 'not-covered', message: `Inspector coverage for ${r.resourceId} is ${r.scanStatus}${r.reason ? ` (${r.reason})` : ''}` });
      }
    }
  }
  return { ...c, status: worst(findings), observed, findings };
}

export function roleCheck(result, { label, arn, id }) {
  const c = check(id, 'IAM', `${label} role`, { expected: [arn] });
  if (result.state === 'unverified') {
    return unverifiedCheck(c, result);
  }
  if (result.state === 'absent') {
    return { ...c, status: FAIL, observed: [`no role named ${arn.split('/').pop()}`], findings: [{ severity: FAIL, kind: 'resource-absent', message: `${arn} does not exist` }] };
  }
  const r = result.value;
  if (r.arn !== arn) {
    return { ...c, status: FAIL, observed: [r.arn ?? '(no ARN)'], findings: [{ severity: FAIL, kind: 'role-arn-mismatch', message: `a role with this name exists as ${r.arn}, not ${arn}` }] };
  }
  return { ...c, observed: [r.arn, ...(r.permissionsBoundary ? [`permissions boundary ${r.permissionsBoundary}`] : [])] };
}

export function trustCheck(role, { label, id, account, partition, slug, contexts, noEnvironment }) {
  const c = check(id, 'IAM', `${label} trust`, {
    basis: 'policy-document',
    expected: [`only ${providerArn(account, partition)} with aud = ${STS_AUDIENCE} and sub exactly repo:${slug}:${contexts.join(' | ')} (StringEquals)`]
  });
  if (role.state !== 'present') {
    return { ...c, status: NOT_VERIFIED, observed: ['role not available'], findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the role could not be read' }], evaluation: null };
  }
  const evaluation = evaluateTrust(role.value.trust, { account, partition, slug, contexts });
  const findings = evaluation.findings.map((f) => ({ ...f }));
  if (noEnvironment) {
    findings.push({ severity: WARN, kind: 'no-environment', message: 'delivery.environment is empty: the deploy role trusts the default-branch context, so GitHub environment reviewers cannot gate it' });
  }
  return {
    ...c,
    status: worst(findings),
    observed: evaluation.subjects.length ? evaluation.subjects.map((s) => `sub ${s.value}${s.expected ? '' : ' (NOT the intended context)'}`) : ['no subject condition found'],
    findings,
    evaluation: { verdict: evaluation.verdict, format: evaluation.format, reachable: evaluation.reachable }
  };
}

export function permissionsCheck(analysis, { label, id, simulation, boundary }) {
  const c = check(id, 'IAM', `${label} permissions`, {
    basis: simulation?.state === 'present' ? 'policy-document+simulation' : 'policy-document',
    expected: analysis ? analysis.required.map((r) => `${r.action} on ${r.resource}`) : []
  });
  if (!analysis) {
    return { ...c, status: NOT_VERIFIED, observed: ['role not available'], findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the role could not be read' }] };
  }
  const findings = [...analysis.findings];
  if (boundary && simulation?.state !== 'present') {
    findings.push({ severity: WARN, kind: 'permissions-boundary', message: `permissions boundary ${boundary} is not evaluated offline and simulation was not available` });
  }
  const observed = analysis.required.map((r) => `${r.action} on ${r.resource}: ${r.decision}${r.simulation ? ` (simulation: ${r.simulation})` : ''}`);
  observed.push(
    simulation?.state === 'present'
      ? 'simulate-principal-policy consulted (includes boundaries; not resource/session/VPC endpoint policies)'
      : `simulation not available${simulation?.state === 'unverified' ? ` (${describeError(simulation)})` : ''}; policy-document analysis only`
  );
  observed.push('not runtime proof: SCPs, resource policies, session policies and VPC endpoint policies can still deny');
  return { ...c, status: worst(findings), observed, findings };
}

export function instanceCheck(result, { account, region, instanceId }) {
  const c = check('ssm.instance', 'SSM', 'Instance', { expected: [`EC2 instance ${instanceId} in account ${account}, ${region}, running`] });
  if (result.state === 'unverified') {
    return unverifiedCheck(c, result);
  }
  if (result.state === 'absent') {
    return { ...c, status: FAIL, observed: [`no instance ${instanceId} in ${region}`], findings: [{ severity: FAIL, kind: 'resource-absent', message: `instance ${instanceId} does not exist in ${region} (Phase 2 never creates it)` }] };
  }
  const i = result.value;
  const findings = [];
  if (i.ownerId !== account) {
    findings.push({ severity: FAIL, kind: 'account-mismatch', message: `instance is owned by ${i.ownerId}, not ${account}` });
  }
  if (i.state !== 'running') {
    findings.push({ severity: FAIL, kind: 'instance-not-running', message: `instance state is ${i.state}` });
  }
  return { ...c, status: worst(findings), observed: [`owner ${i.ownerId}, state ${i.state}`, `instance profile ${i.instanceProfileArn ?? '(none)'}`], findings };
}

export function managedInstanceCheck(result, { instanceId }) {
  const c = check('ssm.managed', 'SSM', 'Managed instance Online', { expected: [`SSM lists ${instanceId} with PingStatus Online`] });
  if (result.state === 'unverified') {
    return unverifiedCheck(c, result);
  }
  if (result.state === 'absent') {
    return { ...c, status: FAIL, observed: ['SSM does not list the instance'], findings: [{ severity: FAIL, kind: 'not-managed', message: `SSM does not manage ${instanceId}: send-command cannot reach it` }], remediation: ['Install/start the SSM agent and give the instance profile AmazonSSMManagedInstanceCore (an owner change; doctor attaches nothing).'] };
  }
  const online = result.value.pingStatus === 'Online';
  return {
    ...c,
    status: online ? PASS : FAIL,
    observed: [`PingStatus ${result.value.pingStatus}, ${result.value.resourceType ?? 'unknown type'}, agent ${result.value.agentVersion ?? 'unknown'}`],
    findings: online ? [] : [{ severity: FAIL, kind: 'instance-offline', message: `PingStatus is ${result.value.pingStatus}, not Online` }]
  };
}

export function instanceRoleCheck({ instance, profile, analysis, online, target }) {
  const c = check('ssm.instance-role', 'SSM', 'Instance role (ECR pull)', {
    basis: 'policy-document',
    expected: [`an instance profile with one role that can ecr:GetAuthorizationToken and pull ${target.repository}`]
  });
  if (instance.state !== 'present') {
    return { ...c, status: NOT_VERIFIED, observed: ['instance not available'], findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the instance could not be read' }] };
  }
  const profileArn = instance.value.instanceProfileArn;
  if (!profileArn) {
    return { ...c, status: FAIL, observed: ['no instance profile'], findings: [{ severity: FAIL, kind: 'no-instance-profile', message: 'the instance has no IAM instance profile, so it cannot pull from ECR' }] };
  }
  const profileAccount = /^arn:[^:]+:iam::(\d{12}):/.exec(profileArn)?.[1];
  if (profileAccount !== target.account) {
    return { ...c, status: FAIL, observed: [profileArn], findings: [{ severity: FAIL, kind: 'account-mismatch', message: `instance profile ${profileArn} is not in account ${target.account}` }] };
  }
  if (profile.state === 'unverified') {
    return unverifiedCheck({ ...c, observed: [profileArn] }, profile);
  }
  if (profile.state === 'absent') {
    return { ...c, status: FAIL, observed: [profileArn], findings: [{ severity: FAIL, kind: 'profile-relationship', message: `instance profile ${profileArn} does not exist` }] };
  }
  if (profile.value.roles.length !== 1) {
    return { ...c, status: FAIL, observed: [profileArn], findings: [{ severity: FAIL, kind: 'profile-relationship', message: `instance profile holds ${profile.value.roles.length} roles (expected exactly 1)` }] };
  }
  const roleArn = profile.value.roles[0];
  if (!analysis) {
    return { ...c, status: NOT_VERIFIED, observed: [profileArn, `role ${roleArn}`], findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the instance role could not be read' }] };
  }
  // An Online instance is runtime proof that SSM core works (possibly through
  // Default Host Management), so the soft SSM-core requirement is dropped.
  const findings = analysis.findings.filter((f) => !(online && f.kind === 'permission-missing' && /^(ssm|ssmmessages|ec2messages):/.test(f.message)));
  const missing = findings.some((f) => f.kind === 'permission-missing' && f.severity === FAIL);
  return {
    ...c,
    basis: online ? 'policy-document+runtime' : 'policy-document',
    status: worst(findings),
    observed: [profileArn, `role ${roleArn}`, ...analysis.required.map((r) => `${r.action} on ${r.resource}: ${r.decision}`), ...(online ? ['SSM core: proven at runtime (instance is Online)'] : [])],
    findings,
    remediation: missing
      ? [
          'RECOMMENDATION for the owner of this instance role (doctor attaches nothing — the role may serve other workloads):',
          JSON.stringify(proposedInstancePolicy(target), null, 2)
        ]
      : []
  };
}

export function ownershipCheck({ label, id, mode, evaluation, resourceState, stackName }) {
  const c = check(id, 'Ownership', label, {
    required: mode === 'managed',
    basis: 'runtime',
    expected: [
      mode === 'managed'
        ? `managed: a physical resource of stack ${stackName} (exact name, this region), tagged ssd:managed-by=ssd-onboard and ssd:environment=production`
        : `existing: validated in place; never modified or adopted by name (an ssd-onboard owner would be stack ${stackName})`
    ]
  });
  if (resourceState !== 'present') {
    return { ...c, status: NOT_VERIFIED, ownership: 'unverified', observed: ['resource not available'], findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'ownership is only evaluated for a resource that exists' }] };
  }
  const { ownership, reasons } = evaluation;
  const observed = [ownership === 'managed' ? 'managed' : ownership === 'exists-not-owned' ? 'exists, not owned' : 'ownership not verified', ...reasons];
  if (ownership === 'unverified') {
    return { ...c, status: NOT_VERIFIED, ownership, observed, findings: [{ severity: NOT_VERIFIED, kind: evaluation.error?.kind ?? 'unverified', message: evaluation.error ? describeError({ error: evaluation.error }) : reasons.join('; ') }] };
  }
  const findings = [];
  if (mode === 'managed' && ownership !== 'managed') {
    // Proven NOT owned is stronger evidence than unverified, so it blocks too.
    findings.push({ severity: FAIL, kind: 'present-unowned', message: 'configured as managed, but it exists and is NOT owned by ssd-onboard; it will never be adopted by name (use existing, or an explicit CloudFormation import)' });
  }
  if (mode === 'existing' && ownership === 'managed') {
    findings.push({ severity: WARN, kind: 'ownership-mode-mismatch', message: 'owned by an ssd-onboard stack, but configured as existing' });
  }
  return { ...c, status: worst(findings), ownership, observed, findings };
}

// --- orchestration ------------------------------------------------------------------

// The outcome contract. `required` is the only thing that separates the two
// kinds of NOT VERIFIED:
//   any FAIL                         -> BLOCKED              (exit 1)
//   a REQUIRED check NOT VERIFIED    -> NOT_VERIFIED         (exit 1): a prerequisite
//                                       doctor could not safely prove
//   an ADVISORY check NOT VERIFIED,  -> READY_WITH_WARNINGS  (exit 0)
//   or any WARN
//   everything PASS                  -> READY                (exit 0)
// Advisory (required: false) checks are only those that cannot be proven from
// AWS at all or are informational: the GitHub subject format, tag mutability,
// and ownership of a resource configured as `existing`.
export function outcomeOf(checks) {
  if (checks.some((c) => c.status === FAIL)) {
    return 'BLOCKED';
  }
  if (checks.some((c) => c.status === NOT_VERIFIED && c.required)) {
    return 'NOT_VERIFIED';
  }
  if (checks.some((c) => c.status !== PASS)) {
    return 'READY_WITH_WARNINGS';
  }
  return 'READY';
}

function report({ target, checks, calls, skipped = null }) {
  const counts = { [PASS]: 0, [WARN]: 0, [FAIL]: 0, [NOT_VERIFIED]: 0 };
  checks.forEach((c) => (counts[c.status] += 1));
  return { schemaVersion: SCHEMA_VERSION, command: 'aws doctor', target, outcome: outcomeOf(checks), counts, checks, skipped, awsCalls: calls };
}

export const exitCodeOf = (r) => OUTCOMES[r.outcome] ?? 1;

// awsDoctor({ config, region, exec, env }) -> report. Throws AwsCliError for a
// run-ending failure (no CLI, no credentials, timeout on identity, …).
export async function awsDoctor({ config, region: explicitRegion = null, exec, env = process.env }) {
  const d = config.delivery;
  const slug = config.repository.slug;
  const account = d.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: d.aws.region });
  const target = { repository: slug, account, region: resolved.region, regionSource: resolved.source, caller: null };
  const calls = [];
  const regionC = regionCheck(resolved);
  if (regionC.status === FAIL) {
    // Nothing is contacted in a region the configuration does not name.
    return report({ target, checks: [regionC], calls, skipped: 'region mismatch: AWS was not contacted' });
  }
  const aws = readOnlyAws({ region: resolved.region, exec, env, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).join(' ')) });

  const caller = await callerIdentity(aws);
  target.caller = caller;
  const identity = [accountCheck(caller, account), principalCheck(caller), regionC];
  if (identity.some((c) => c.status === FAIL)) {
    return report({ target, checks: identity, calls, skipped: 'identity check failed: no resource was read' });
  }
  const partition = caller.partition;

  // Discovery (reads only).
  const oidc = await discoverOidcProvider(aws, { account });
  const repo = await discoverRepository(aws, { account, repository: d.ecr.repository });
  const scanning = await discoverRegistryScanning(aws);
  const enhanced = enhancedOf(scanning);
  const inspector = enhanced === true
    ? { account: await discoverInspectorAccount(aws, { account }), coverage: await discoverInspectorCoverage(aws, { repository: d.ecr.repository }) }
    : null;
  const target2 = { partition, account, region: resolved.region, repository: d.ecr.repository, instanceId: d.ssm.instanceId };

  const roles = [];
  for (const [key, label, arn] of [['push', 'Push/scan', d.roles.pushScanRoleArn], ['deploy', 'Deploy', d.roles.deployRoleArn]]) {
    const role = await discoverRole(aws, arn);
    let analysis = null;
    let simulation = null;
    if (role.state === 'present' && role.value.arn === arn) {
      const policies = await discoverRolePolicies(aws, role.value.name ?? arn.split('/').pop());
      simulation = await simulateRole(aws, arn, simulationGroups(key, target2, { enhanced }));
      analysis = analyzePermissions(key, target2, { policies: policies.policies, complete: policies.complete, enhanced, simulation: simulation.state === 'present' ? simulation.value : null });
      if (policies.errors.length > 0) {
        analysis.findings.push(...policies.errors.map((e) => ({ severity: NOT_VERIFIED, kind: e.kind, message: `policy not read: ${e.message}` })));
        analysis.status = worst(analysis.findings);
      }
    }
    roles.push({ key, label, arn, role, analysis, simulation });
  }

  const instance = await discoverInstance(aws, { instanceId: d.ssm.instanceId });
  const managed = await discoverManagedInstance(aws, { instanceId: d.ssm.instanceId });
  let profile = { state: 'absent', code: 'NoProfile' };
  let instanceAnalysis = null;
  const profileArn = instance.state === 'present' ? instance.value.instanceProfileArn : null;
  if (profileArn && /^arn:[^:]+:iam::(\d{12}):/.exec(profileArn)?.[1] === account) {
    profile = await discoverInstanceProfile(aws, profileArn);
    if (profile.state === 'present' && profile.value.roles.length === 1) {
      const instanceRoleArn = profile.value.roles[0];
      const instanceRole = await discoverRole(aws, instanceRoleArn);
      if (instanceRole.state === 'present') {
        const policies = await discoverRolePolicies(aws, instanceRole.value.name ?? instanceRoleArn.split('/').pop());
        instanceAnalysis = analyzePermissions('instance', target2, { policies: policies.policies, complete: policies.complete });
      }
    }
  }

  // Ownership (discovery of the stack relationship, for resources that exist).
  const owned = [];
  const ownershipTargets = [
    { id: 'ownership.oidc-provider', label: 'OIDC provider (shared)', mode: d.oidcProvider, state: oidc.state, physicalId: oidc.state === 'present' ? oidc.value.arn : null, type: 'AWS::IAM::OIDCProvider', scope: 'shared', stackName: SHARED_STACKS.githubOidc, tags: oidc.state === 'present' ? oidc.value.tags : null },
    { id: 'ownership.ecr-repository', label: 'ECR repository', mode: d.ecr.ownership, state: repo.state, physicalId: d.ecr.repository, type: 'AWS::ECR::Repository', scope: 'repo', stackName: repoStackName(slug), tags: repo.state === 'present' && repo.value.tags.state === 'present' ? repo.value.tags.value : null },
    ...roles.map((r) => ({ id: `ownership.${r.key}-role`, label: `${r.label} role`, mode: r.key === 'push' ? d.roles.pushScanOwnership : d.roles.deployOwnership, state: r.role.state === 'present' && r.role.value.arn === r.arn ? 'present' : 'unavailable', physicalId: r.role.state === 'present' ? r.role.value.name : null, type: 'AWS::IAM::Role', scope: 'repo', stackName: repoStackName(slug), tags: r.role.state === 'present' ? r.role.value.tags : null }))
  ];
  for (const o of ownershipTargets) {
    const evaluation = o.state === 'present' ? evaluateOwnership({ discovered: await discoverStack(aws, o.physicalId), resourceTags: o.tags, expectedType: o.type, slug, scope: o.scope, expectedStackName: o.stackName }) : null;
    owned.push(ownershipCheck({ label: o.label, id: o.id, mode: o.mode, evaluation, resourceState: o.state, stackName: o.stackName }));
  }

  // Checks.
  const trustChecks = roles.map((r) =>
    trustCheck(r.role.state === 'present' && r.role.value.arn === r.arn ? r.role : { state: 'unavailable' }, {
      label: r.label,
      id: `iam.${r.key}-trust`,
      account,
      partition,
      slug,
      contexts: intendedContexts(r.key, { defaultBranch: config.repository.defaultBranch, environment: d.environment }),
      noEnvironment: r.key === 'deploy' && !d.environment
    })
  );
  const checks = [
    ...identity,
    oidcProviderCheck(oidc, { account, partition }),
    subjectFormatCheck(trustChecks.map((t) => t.evaluation)),
    repositoryCheck(repo, { account, repository: d.ecr.repository }),
    immutabilityCheck(repo),
    scanningCheck(scanning, { repository: d.ecr.repository, repositoryScanOnPush: repo.state === 'present' && repo.value.scanOnPush }),
    ...(inspector ? [inspectorCheck(inspector.account, inspector.coverage)] : []),
    ...roles.flatMap((r, index) => [
      roleCheck(r.role, { label: r.label, arn: r.arn, id: `iam.${r.key}-role` }),
      trustChecks[index],
      permissionsCheck(r.analysis, { label: r.label, id: `iam.${r.key}-permissions`, simulation: r.simulation, boundary: r.role.state === 'present' ? r.role.value.permissionsBoundary : null })
    ]),
    instanceCheck(instance, { account, region: resolved.region, instanceId: d.ssm.instanceId }),
    managedInstanceCheck(managed, { instanceId: d.ssm.instanceId }),
    instanceRoleCheck({ instance, profile, analysis: instanceAnalysis, online: managed.state === 'present' && managed.value.pingStatus === 'Online', target: target2 }),
    ...owned
  ];
  return report({ target, checks, calls });
}
