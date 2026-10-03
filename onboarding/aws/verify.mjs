// `ssd-onboard aws verify` (Phase 2D): does the DEPLOYED AWS state actually hold
// the security boundary this repository's delivery assumes?
//
// Not a planner and not a mutator. It re-reads live state and does not trust a
// CloudFormation status, an `aws apply` record, a resource name or a
// configuration value as evidence of anything.
//
// READ-ONLY BY CONSTRUCTION. Every AWS call goes through verifyAws, which IS
// readOnlyAws(): the same explicit (service, operation, flags) allowlist as
// `aws doctor`, refusing any other argv before a process is spawned. There is
// no controlled live probe in Phase 2D: a real AssumeRoleWithWebIdentity needs a
// GitHub-issued token, and a real ssm send-command runs on the production
// instance. Effective authorization is established with
// iam simulate-principal-policy instead, which has no side effect.
//
// Order is part of the contract (as doctor):
//   1. region (--region > delivery.aws.region); a disagreeing flag fails BEFORE
//      AWS is contacted;
//   2. sts get-caller-identity; a wrong account or the root user fails BEFORE
//      any other call;
//   3. discovery (present | absent | unverified — access denied is never absence);
//   4. effective-permission simulation, for every role, of what it MUST be able
//      to do (expected ALLOW) and of what it must NOT (expected DENY);
//   5. checks, pure functions of what was read.
//
// Separate facts stay separate checks: a role existing, its trust, its required
// access and its denied access are four results, never one IAM PASS.
//
// Statuses and outcomes follow the Phase 2A contract (doctor.mjs):
//   any FAIL                       -> FAILED                  (exit 1)
//   a REQUIRED check NOT VERIFIED  -> NOT_VERIFIED            (exit 1)
//   WARN, or advisory NOT VERIFIED -> VERIFIED_WITH_WARNINGS  (exit 0)
//   everything PASS                -> VERIFIED                (exit 0)
//   could not run                  -> ERROR                   (exit 1)
// Uncertainty is never PASS: an unreadable, malformed, truncated or incomplete
// AWS answer is NOT VERIFIED, and a required NOT VERIFIED fails the command.
import { readOnlyAws } from './aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from './identity.mjs';
import { discoverRegistryScanning, discoverRepository } from './discover/ecr.mjs';
import { discoverInspectorAccount, discoverInspectorCoverage } from './discover/inspector.mjs';
import { discoverRole, discoverRolePolicies, roleName, simulateProbes } from './discover/iam-role.mjs';
import { discoverOidcProvider } from './discover/oidc-provider.mjs';
import { describeError } from './discover/result.mjs';
import { discoverInstance, discoverInstanceProfile, discoverManagedInstance } from './discover/ssm.mjs';
import { discoverStack, evaluateOwnership } from './discover/stacks.mjs';
import {
  FAIL,
  NOT_VERIFIED,
  PASS,
  WARN,
  enhancedOf,
  immutabilityCheck,
  instanceCheck,
  instanceRoleCheck,
  managedInstanceCheck,
  oidcProviderCheck,
  ownershipCheck,
  ownershipTargets,
  repositoryCheck,
  roleCheck,
  scanningCheck,
  subjectFormatCheck,
  trustCheck
} from './doctor.mjs';
import { analyzePermissions, arns, proposedInstancePolicy, verificationProbes } from './policy/permissions.mjs';
import { intendedContexts } from './policy/trust.mjs';
import { REPO_LOGICAL_IDS } from './templates/repo-ecr-delivery.mjs';
import { OIDC_LOGICAL_ID } from './templates/shared-github-oidc.mjs';

export { FAIL, NOT_VERIFIED, PASS, WARN };
export const SCHEMA_VERSION = 1;
const RANK = { [PASS]: 0, [WARN]: 1, [NOT_VERIFIED]: 2, [FAIL]: 3 };

// The only AWS wrapper `aws verify` ever receives: the read-only one.
export const verifyAws = readOnlyAws;

export const OUTCOMES = Object.freeze({ VERIFIED: 0, VERIFIED_WITH_WARNINGS: 0, NOT_VERIFIED: 1, FAILED: 1, ERROR: 1 });
export const exitCodeOf = (r) => OUTCOMES[r.outcome] ?? 1;

export const SECTIONS = Object.freeze(['Identity', 'GitHub OIDC', 'Push/scan role', 'Deploy role', 'Separation of duties', 'ECR', 'SSM', 'Ownership']);
const ROLE_SECTION = { push: 'Push/scan role', deploy: 'Deploy role' };

function check(id, section, title, fields = {}) {
  return { id, section, title, status: PASS, required: true, basis: 'runtime', why: '', observed: [], expected: [], findings: [], remediation: [], ...fields };
}

const worst = (findings, floor = PASS) => findings.reduce((acc, f) => (RANK[f.severity] > RANK[acc] ? f.severity : acc), floor);

// A doctor check, placed in verify's report.
const adopt = (c, fields) => ({ why: '', ...c, ...fields });

const SIMULATOR_REMEDIATION =
  'Give the operator iam:SimulatePrincipalPolicy on the push/scan, deploy and instance roles (docs/onboarding-cli.md § AWS verification, Prerequisites); without it effective access cannot be proven.';

// --- effective permissions (pure) ---------------------------------------------------

const decisionOf = (simulation, probe) => simulation.find((s) => s.action.toLowerCase() === probe.action.toLowerCase() && s.resource === probe.resource) ?? null;

// Expected ALLOW. Every probe must evaluate to `allowed`. A denial with missing
// context values may be allowed in a real request context, so it is NOT
// VERIFIED, not FAIL — and never PASS.
export function requiredAccessCheck({ id, section, title, why, simulation, probes, remediation = [] }) {
  const c = check(id, section, title, {
    basis: 'simulation',
    why,
    expected: probes.map((p) => `ALLOW ${p.action} on ${p.resource}`)
  });
  if (!simulation || simulation.state !== 'present') {
    return unavailable(c, simulation);
  }
  const findings = [];
  const observed = [];
  for (const p of probes) {
    const r = decisionOf(simulation.value, p);
    if (!r) {
      findings.push({ severity: NOT_VERIFIED, kind: 'simulation-incomplete', message: `no simulation result for ${p.action} on ${p.resource}` });
      continue;
    }
    observed.push(`${p.action} on ${p.resource}: ${r.decision}${r.missingContext.length ? ` (missing context: ${r.missingContext.join(', ')})` : ''}`);
    if (r.decision === 'allowed') {
      continue;
    }
    const uncertain = r.missingContext.length > 0 || p.possible;
    findings.push({
      severity: uncertain ? NOT_VERIFIED : FAIL,
      kind: uncertain ? 'access-unproven' : 'required-access-denied',
      message: `${p.action} on ${p.resource} evaluates to ${r.decision}${r.missingContext.length ? ` without context values ${r.missingContext.join(', ')}` : ''}: ${p.why}`
    });
  }
  const status = worst(findings);
  return { ...c, status, observed, findings, remediation: status === PASS ? [] : remediation };
}

// Expected DENY. Any probe that evaluates to `allowed` fails (with the
// contract's severity). An implicit deny that depends on missing context
// values could be an allow in a real request: NOT VERIFIED. The offline
// breadth findings of the role's own policy documents (administrator,
// NotAction, a forbidden grant, an unreadable policy) are kept beside the
// simulation: a finite probe set cannot see every grant.
export function deniedAccessCheck({ id, section, title, why, simulation, probes, analysis = null, remediation = [] }) {
  const c = check(id, section, title, {
    basis: analysis ? 'simulation+policy-document' : 'simulation',
    why,
    expected: probes.map((p) => `DENY ${p.action} on ${p.resource}`)
  });
  if (!simulation || simulation.state !== 'present') {
    return unavailable(c, simulation);
  }
  const findings = [];
  const observed = [];
  for (const p of probes) {
    const r = decisionOf(simulation.value, p);
    if (!r) {
      findings.push({ severity: NOT_VERIFIED, kind: 'simulation-incomplete', message: `no simulation result for ${p.action} on ${p.resource}` });
      continue;
    }
    observed.push(`${p.action} on ${p.resource}: ${r.decision}`);
    if (r.decision === 'allowed') {
      findings.push({ severity: p.severity, kind: 'forbidden-access-allowed', message: `${p.action} on ${p.resource} is ALLOWED: ${p.why}` });
    } else if (r.decision === 'implicitDeny' && r.missingContext.length > 0) {
      findings.push({
        severity: p.severity === WARN ? WARN : NOT_VERIFIED,
        kind: 'denial-unproven',
        message: `${p.action} on ${p.resource} is denied only for want of context values ${r.missingContext.join(', ')}: a request carrying them may be allowed`
      });
    }
  }
  if (analysis) {
    const breadth = new Set(['permission-too-broad', 'administrator', 'possible-administrator', 'malformed-policy', 'policies-incomplete', 'policy-unreadable']);
    findings.push(...analysis.findings.filter((f) => breadth.has(f.kind)).map((f) => ({ ...f, message: `policy document: ${f.message}` })));
  }
  const status = worst(findings);
  return { ...c, status, observed, findings, remediation: status === PASS ? [] : remediation };
}

function unavailable(c, simulation) {
  if (simulation?.state === 'unverified') {
    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: simulation.error.kind, message: `simulate-principal-policy: ${describeError(simulation)}` }], remediation: [SIMULATOR_REMEDIATION] };
  }
  return { ...c, status: NOT_VERIFIED, observed: ['role not available'], findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the role could not be read, so its effective access was not simulated' }] };
}

// --- separation of duties (pure) -----------------------------------------------------

// The push/scan and deploy roles are two identities, and neither can do the
// other's job: distinct configured ARNs, distinct live ARNs and RoleIds, the
// push role cannot SendCommand to the instance, the deploy role cannot push.
export function separationCheck({ config, roles, target }) {
  const d = config.delivery;
  const c = check('separation.roles', 'Separation of duties', 'Distinct push and deploy roles', {
    basis: 'runtime+simulation',
    why: 'a single identity that can both publish an image and deploy it removes the gate between the two',
    expected: ['delivery.roles.pushScanRoleArn ≠ delivery.roles.deployRoleArn', 'two live roles with different ARNs and RoleIds', 'push role: DENY ssm:SendCommand on the instance', 'deploy role: DENY ecr:PutImage on the repository']
  });
  const findings = [];
  const observed = [];
  const configuredSame = d.roles.pushScanRoleArn.toLowerCase() === d.roles.deployRoleArn.toLowerCase();
  observed.push(`configured: ${d.roles.pushScanRoleArn} / ${d.roles.deployRoleArn}`);
  if (configuredSame) {
    findings.push({ severity: FAIL, kind: 'same-role', message: 'push/scan and deploy are configured as the same role' });
  }
  const push = roles.find((r) => r.key === 'push');
  const deploy = roles.find((r) => r.key === 'deploy');
  const live = (r) => (r.role.state === 'present' && r.role.value.arn === r.arn ? r.role.value : null);
  const p = live(push);
  const q = live(deploy);
  if (!p || !q) {
    findings.push({ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'both roles must be readable to prove they are distinct identities' });
  } else {
    observed.push(`live RoleIds: ${p.roleId ?? '(missing)'} / ${q.roleId ?? '(missing)'}`);
    if (p.arn === q.arn) {
      findings.push({ severity: FAIL, kind: 'same-role', message: `both resolve to the live role ${p.arn}` });
    }
    if (!p.roleId || !q.roleId) {
      findings.push({ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'get-role returned no RoleId, so the live identities cannot be compared' });
    } else if (p.roleId === q.roleId) {
      findings.push({ severity: FAIL, kind: 'same-role', message: `both roles have RoleId ${p.roleId}` });
    }
  }
  const a = arns(target);
  for (const [r, action, resource, what] of [
    [push, 'ssm:SendCommand', a.instance, 'the push/scan role can deploy'],
    [deploy, 'ecr:PutImage', a.repository, 'the deploy role can push images']
  ]) {
    const sim = r.simulation;
    if (!sim || sim.state !== 'present') {
      findings.push({ severity: NOT_VERIFIED, kind: 'simulation-unavailable', message: `${action} on ${resource} for the ${r.label} role was not simulated` });
      continue;
    }
    const result = decisionOf(sim.value, { action, resource });
    if (!result) {
      findings.push({ severity: NOT_VERIFIED, kind: 'simulation-incomplete', message: `no simulation result for ${action} on ${resource} (${r.label} role)` });
      continue;
    }
    observed.push(`${r.label} role ${action} on ${resource}: ${result.decision}`);
    if (result.decision === 'allowed') {
      findings.push({ severity: FAIL, kind: 'duties-not-separated', message: `${what} (${action} on ${resource} is ALLOWED)` });
    }
  }
  const status = worst(findings);
  return {
    ...c,
    status,
    observed,
    findings,
    remediation: status === PASS ? [] : ['Use two roles: the push/scan role holds only ECR push and scan reads; the deploy role holds only ssm:SendCommand on the instance and AWS-RunShellScript.']
  };
}

// --- ECR (pure) ------------------------------------------------------------------------

// doctor's repository check, plus: the live ARN is exactly the configured
// repository in the configured account AND region, and the registry is named.
export function verifyRepositoryCheck(result, { account, region, repository, partition }) {
  const base = adopt(repositoryCheck(result, { account, repository }), {
    why: 'the pipeline pushes to and the instance pulls from this repository; it must be the one in this account and region'
  });
  if (result.state !== 'present') {
    return base;
  }
  const expectedArn = arns({ partition, account, region, repository }).repository;
  const findings = [...base.findings];
  if (result.value.registryId === null) {
    findings.push({ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'describe-repositories returned no registryId' });
  }
  if (result.value.arn !== expectedArn) {
    findings.push({ severity: FAIL, kind: 'repository-location', message: `the repository ARN is ${result.value.arn ?? '(missing)'}, not ${expectedArn} (wrong account, region or name)` });
  }
  return { ...base, status: worst(findings), expected: [...base.expected, expectedArn], findings };
}

// Tag immutability. For a MANAGED repository it is required: the stack
// declares IMMUTABLE, so anything else is drift and FAILS. For an EXISTING
// repository it stays doctor's advisory WARN (an owner decision).
export function verifyImmutabilityCheck(result, { mode }) {
  const base = immutabilityCheck(result);
  const why = 'an immutable tag cannot be repointed to a different image after it was scanned';
  if (mode !== 'managed') {
    return adopt(base, { why });
  }
  const c = { ...base, required: true, why, expected: ['IMMUTABLE (declared by the ssd-onboard stack: anything else is drift)'] };
  if (result.state !== 'present') {
    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the repository could not be read' }] };
  }
  if (result.value.tagMutability === 'IMMUTABLE') {
    return { ...c, status: PASS, findings: [], remediation: [] };
  }
  if (result.value.tagMutability === null) {
    return { ...c, status: NOT_VERIFIED };
  }
  return {
    ...c,
    status: FAIL,
    findings: [{ severity: FAIL, kind: 'managed-drift', message: `the managed repository is ${result.value.tagMutability}, but its stack declares IMMUTABLE` }],
    remediation: ['Restore IMMUTABLE through the stack (`aws plan` then `aws apply`); verify changes nothing.']
  };
}

// The settings the ssd-onboard stack declares for a MANAGED repository, other
// than tag mutability: scanOnPush and AES256 encryption. Drift FAILS.
export function managedRepositorySettingsCheck(result) {
  const c = check('ecr.managed-settings', 'ECR', 'Managed settings', {
    why: 'a managed resource that no longer matches its stack was changed outside ssd-onboard',
    expected: ['scanOnPush true', 'encryption AES256']
  });
  if (result.state !== 'present') {
    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: 'prerequisite-missing', message: 'the repository could not be read' }] };
  }
  const r = result.value;
  const findings = [];
  if (r.scanOnPush !== true) {
    findings.push({ severity: FAIL, kind: 'managed-drift', message: 'repository-level scanOnPush is off, but the stack declares it on' });
  }
  if (r.encryption.type === null) {
    findings.push({ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'encryption type not reported' });
  } else if (r.encryption.type !== 'AES256') {
    findings.push({ severity: FAIL, kind: 'managed-drift', message: `encryption is ${r.encryption.type}, but the stack declares AES256` });
  }
  const status = worst(findings);
  return { ...c, status, observed: [`scanOnPush ${r.scanOnPush}`, `encryption ${r.encryption.type ?? 'unknown'}`, `lifecycle policy: ${r.lifecyclePolicy.state === 'present' ? 'present (not managed by the stack)' : r.lifecyclePolicy.state === 'absent' ? 'none (not managed by the stack)' : 'not readable'}`], findings, remediation: status === PASS ? [] : ['Bring the repository back to its stack (`aws plan` then `aws apply`).'] };
}

// doctor's coverage check, plus: the scanning configuration is this account's.
export function verifyScanningCheck(result, { account, repository, repositoryScanOnPush }) {
  const base = adopt(scanningCheck(result, { repository, repositoryScanOnPush }), {
    why: 'the gate waits for this repository\'s scan; a repository no rule covers is never scanned'
  });
  if (result.state !== 'present') {
    return base;
  }
  const findings = [...base.findings];
  if (result.value.registryId === null) {
    findings.push({ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'get-registry-scanning-configuration returned no registryId' });
  } else if (result.value.registryId !== account) {
    findings.push({ severity: FAIL, kind: 'account-mismatch', message: `the scanning configuration is registry ${result.value.registryId}'s, not ${account}'s` });
  }
  return { ...base, status: worst(findings), findings };
}

// ENHANCED scanning: "Inspector is enabled" and "this repository is covered"
// are separate facts; so is "the push role may read the evidence" (below).
export function inspectorAccountCheck(result) {
  const c = check('ecr.inspector-account', 'ECR', 'Inspector enabled', {
    why: 'with ENHANCED scanning, ECR scans are performed by Inspector; disabled Inspector means no scan',
    expected: ['Inspector ECR scanning ENABLED for the account']
  });
  if (result.state === 'unverified') {
    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: result.error.kind, message: describeError(result) }] };
  }
  if (result.state === 'absent') {
    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: 'malformed-response', message: 'Inspector returned no status for this account' }] };
  }
  const { accountState, ecrState } = result.value;
  const enabled = ecrState === 'ENABLED';
  return {
    ...c,
    status: enabled ? PASS : FAIL,
    observed: [`account ${accountState ?? 'unknown'}, ECR ${ecrState ?? 'unknown'}`],
    findings: enabled ? [] : [{ severity: FAIL, kind: 'inspector-disabled', message: `registry scanning is ENHANCED but Inspector ECR scanning is ${ecrState ?? 'unknown'}` }],
    remediation: enabled ? [] : ['Enable Inspector ECR scanning for the account (a shared, account-level change; verify enables nothing).']
  };
}

// At least one ACTIVE coverage record and none that is not. No record at all is
// NOT VERIFIED: Inspector being enabled does not prove this repository is covered.
export function inspectorCoverageCheck(result, { repository }) {
  const c = check('ecr.inspector-coverage', 'ECR', 'Inspector coverage', {
    why: 'Inspector being enabled does not prove it scans this repository',
    expected: [`an ACTIVE Inspector coverage record for ${repository}`]
  });
  if (result.state !== 'present') {
    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: result.error?.kind ?? 'malformed-response', message: result.state === 'unverified' ? describeError(result) : 'no coverage answer' }] };
  }
  const records = result.value.records;
  const findings = [];
  if (records.length === 0) {
    findings.push({ severity: NOT_VERIFIED, kind: 'no-coverage-record', message: `Inspector lists no coverage record for ${repository} (a repository is listed once Inspector has evaluated it)` });
  }
  for (const r of records) {
    if (r.scanStatus !== 'ACTIVE') {
      findings.push({ severity: FAIL, kind: 'not-covered', message: `Inspector coverage for ${r.resourceId ?? '(unnamed)'} is ${r.scanStatus ?? 'unknown'}${r.reason ? ` (${r.reason})` : ''}` });
    }
  }
  const status = worst(findings);
  return {
    ...c,
    status,
    observed: records.map((r) => `coverage ${r.resourceId ?? '(unnamed)'}: ${r.scanStatus ?? 'unknown'}${r.reason ? ` (${r.reason})` : ''}`),
    findings,
    remediation: status === PASS ? [] : ['Make sure an ENHANCED registry rule covers the repository and Inspector ECR scanning is enabled; push an image and re-run verify.']
  };
}

// --- SSM (pure) ------------------------------------------------------------------------

// The instance role can log in to ECR and pull the repository — proven by
// simulation, not by the policy text. The profile → single role relationship
// is doctor's instanceRoleCheck; its offline permission findings are replaced
// by the simulation.
export function instancePullCheck({ instance, profile, analysis, online, target, simulation, probes }) {
  const base = instanceRoleCheck({ instance, profile, analysis, online, target });
  const c = adopt(base, {
    id: 'ssm.instance-pull',
    title: 'ECR pull access',
    basis: 'simulation',
    why: 'the instance pulls the approved digest with its own role; without pull access the deploy cannot happen',
    expected: [...probes.required.map((p) => `ALLOW ${p.action} on ${p.resource}`), ...probes.denied.map((p) => `DENY ${p.action} on ${p.resource}`)]
  });
  const permissionKinds = new Set(['permission-missing', 'permission-unproven', 'permission-too-broad', 'simulation-denies']);
  const structural = base.findings.filter((f) => !permissionKinds.has(f.kind) && f.severity !== PASS && f.severity !== WARN);
  if (structural.length > 0 || !analysis) {
    // No profile, wrong account, not exactly one role, role unreadable.
    return { ...c, basis: base.basis, remediation: base.remediation };
  }
  const required = requiredAccessCheck({ id: c.id, section: c.section, title: c.title, why: c.why, simulation, probes: probes.required });
  const denied = deniedAccessCheck({ id: c.id, section: c.section, title: c.title, why: c.why, simulation, probes: probes.denied });
  const findings = [...required.findings, ...denied.findings];
  const status = worst(findings);
  const missing = required.findings.some((f) => f.kind === 'required-access-denied');
  return {
    ...c,
    status,
    observed: [...base.observed.filter((line) => !/: (allowed|denied|not-granted|conditional|unsupported)$/.test(line)), ...required.observed, ...denied.observed],
    findings,
    remediation: missing
      ? ['RECOMMENDATION for the owner of this instance role (verify attaches nothing — the role may serve other workloads):', JSON.stringify(proposedInstancePolicy(target), null, 2)]
      : status === PASS
        ? []
        : [...required.remediation, ...denied.remediation]
  };
}

// --- ownership (pure) ---------------------------------------------------------------

const LOGICAL_IDS = {
  'ownership.oidc-provider': OIDC_LOGICAL_ID,
  'ownership.ecr-repository': REPO_LOGICAL_IDS.repository,
  'ownership.push-role': REPO_LOGICAL_IDS.push,
  'ownership.deploy-role': REPO_LOGICAL_IDS.deploy
};

// doctor's ownership check, plus: a managed resource is the stack's resource
// under the logical id ssd-onboard gave it, not merely some resource of it.
export function verifyOwnershipCheck(target, evaluation, region) {
  const base = adopt(ownershipCheck({ label: target.label, id: target.id, mode: target.mode, evaluation, resourceState: target.state, stackName: target.stackName, region }), {
    why: 'a resource is managed by ssd-onboard only when its stack and tags prove it; a matching name proves nothing'
  });
  if (target.mode !== 'managed' || evaluation?.ownership !== 'managed') {
    return base;
  }
  const expected = LOGICAL_IDS[target.id];
  if (evaluation.stack?.logicalId === expected) {
    return base;
  }
  const findings = [...base.findings, { severity: FAIL, kind: 'logical-id-mismatch', message: `it is resource ${evaluation.stack?.logicalId ?? '(unknown)'} of ${target.stackName}, not ${expected}` }];
  return { ...base, status: worst(findings), findings };
}

// --- orchestration ------------------------------------------------------------------

export function outcomeOf(checks) {
  if (checks.some((c) => c.status === FAIL)) {
    return 'FAILED';
  }
  if (checks.some((c) => c.status === NOT_VERIFIED && c.required)) {
    return 'NOT_VERIFIED';
  }
  if (checks.some((c) => c.status !== PASS)) {
    return 'VERIFIED_WITH_WARNINGS';
  }
  return 'VERIFIED';
}

function report({ target, checks, calls, skipped = null }) {
  const counts = { [PASS]: 0, [WARN]: 0, [FAIL]: 0, [NOT_VERIFIED]: 0 };
  checks.forEach((c) => (counts[c.status] += 1));
  return { schemaVersion: SCHEMA_VERSION, command: 'aws verify', target, outcome: outcomeOf(checks), counts, checks, skipped, awsCalls: calls };
}

const IDENTITY_WHY = {
  'identity.account': 'every conclusion below is about delivery.aws.accountId; another account proves nothing about it',
  'identity.principal': 'the account root user is never an acceptable operator identity',
  'identity.region': 'stacks, the repository, scanning and the instance are regional; only the configured region is examined'
};
const identityCheck = (c) => adopt(c, { why: IDENTITY_WHY[c.id] });

const ROLE_WHY = {
  push: {
    trust: 'only this repository\'s default-branch workflow may obtain the push/scan role',
    required: 'the pipeline must be able to log in, push to the configured repository and read its scan results',
    denied: 'the push/scan role must not deploy, write other repositories, escalate in IAM or weaken scanning'
  },
  deploy: {
    trust: 'only this repository\'s deploy context may obtain the deploy role',
    required: 'the deploy must be able to run AWS-RunShellScript on the configured instance and read the result',
    denied: 'the deploy role must not push images, reach another instance, escalate in IAM or read secrets'
  }
};

// awsVerify({ config, region, exec, env, deadlineMs, now }) -> report.
// Throws AwsCliError / IdentityError for a run-ending failure.
export async function awsVerify({ config, region: explicitRegion = null, exec, env = process.env, deadlineMs, now }) {
  const d = config.delivery;
  const slug = config.repository.slug;
  const account = d.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: d.aws.region });
  const target = { repository: slug, account, region: resolved.region, regionSource: resolved.source, caller: null, awsProfile: env.AWS_PROFILE || null };
  const calls = [];
  const regionC = identityCheck(regionCheck(resolved));
  if (regionC.status === FAIL) {
    return report({ target, checks: [regionC], calls, skipped: 'region mismatch: AWS was not contacted' });
  }
  const aws = verifyAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).join(' ')) });

  const caller = await callerIdentity(aws);
  target.caller = caller;
  const identity = [identityCheck(accountCheck(caller, account)), identityCheck(principalCheck(caller)), regionC];
  if (identity.some((c) => c.status === FAIL)) {
    return report({ target, checks: identity, calls, skipped: 'identity check failed: no resource was read' });
  }
  const partition = caller.partition;
  const t = { partition, account, region: resolved.region, repository: d.ecr.repository, instanceId: d.ssm.instanceId };

  // Discovery (reads only).
  const oidc = await discoverOidcProvider(aws, { account });
  const repo = await discoverRepository(aws, { account, repository: d.ecr.repository });
  const scanning = await discoverRegistryScanning(aws);
  const enhanced = enhancedOf(scanning);
  const inspector = enhanced === true
    ? { account: await discoverInspectorAccount(aws, { account }), coverage: await discoverInspectorCoverage(aws, { repository: d.ecr.repository }) }
    : null;

  // Roles: read, analyse offline, simulate expected ALLOW and expected DENY.
  const roles = [];
  for (const [key, label, arn] of [['push', 'Push/scan', d.roles.pushScanRoleArn], ['deploy', 'Deploy', d.roles.deployRoleArn]]) {
    const role = await discoverRole(aws, arn);
    const probes = verificationProbes(key, t, { enhanced, self: arn });
    let analysis = null;
    let simulation = null;
    if (role.state === 'present' && role.value.arn === arn) {
      const policies = await discoverRolePolicies(aws, role.value.name ?? roleName(arn));
      analysis = analyzePermissions(key, t, { policies: policies.policies, complete: policies.complete, enhanced });
      if (policies.errors.length > 0) {
        analysis.findings.push(...policies.errors.map((e) => ({ severity: NOT_VERIFIED, kind: 'policy-unreadable', message: `policy not read: ${e.message}` })));
      }
      simulation = await simulateProbes(aws, arn, [...probes.required, ...probes.denied]);
    }
    roles.push({ key, label, arn, role, probes, analysis, simulation });
  }

  // SSM target and the instance's own role.
  const instance = await discoverInstance(aws, { instanceId: d.ssm.instanceId });
  const managed = await discoverManagedInstance(aws, { instanceId: d.ssm.instanceId });
  let profile = { state: 'absent', code: 'NoProfile' };
  let instanceAnalysis = null;
  let instanceSimulation = null;
  const instanceProbes = verificationProbes('instance', t, { enhanced: false, self: null });
  const profileArn = instance.state === 'present' ? instance.value.instanceProfileArn : null;
  if (profileArn && /^arn:[^:]+:iam::(\d{12}):/.exec(profileArn)?.[1] === account) {
    profile = await discoverInstanceProfile(aws, profileArn);
    if (profile.state === 'present' && profile.value.roles.length === 1) {
      const instanceRoleArn = profile.value.roles[0];
      const instanceRole = await discoverRole(aws, instanceRoleArn);
      if (instanceRole.state === 'present') {
        const policies = await discoverRolePolicies(aws, instanceRole.value.name ?? roleName(instanceRoleArn));
        instanceAnalysis = analyzePermissions('instance', t, { policies: policies.policies, complete: policies.complete });
        instanceSimulation = await simulateProbes(aws, instanceRoleArn, [...instanceProbes.required, ...instanceProbes.denied]);
      }
    }
  }

  // Ownership.
  const owned = [];
  for (const o of ownershipTargets({ config, oidc, repo, roles })) {
    const evaluation = o.state === 'present' ? evaluateOwnership({ discovered: await discoverStack(aws, o.physicalId), resourceTags: o.tags, expectedType: o.type, slug, scope: o.scope, expectedStackName: o.stackName, region: resolved.region }) : null;
    owned.push(verifyOwnershipCheck(o, evaluation, resolved.region));
  }

  // Checks.
  const roleChecks = roles.map((r) => {
    const section = ROLE_SECTION[r.key];
    const present = r.role.state === 'present' && r.role.value.arn === r.arn;
    const trust = trustCheck(present ? r.role : { state: 'unavailable' }, {
      label: r.label,
      id: `iam.${r.key}-trust`,
      account,
      partition,
      slug,
      contexts: intendedContexts(r.key, { defaultBranch: config.repository.defaultBranch, environment: d.environment }),
      noEnvironment: r.key === 'deploy' && !d.environment
    });
    const simulation = present ? r.simulation : null;
    return {
      trust,
      checks: [
        adopt(roleCheck(r.role, { label: r.label, arn: r.arn, id: `iam.${r.key}-role` }), { section, title: 'Role', why: 'the configured role must exist as exactly this ARN' }),
        adopt(trust, { section, title: 'Trust', why: ROLE_WHY[r.key].trust }),
        requiredAccessCheck({
          id: `iam.${r.key}-required-access`,
          section,
          title: 'Required access',
          why: ROLE_WHY[r.key].required,
          simulation,
          probes: r.probes.required,
          remediation: ['Grant exactly the missing actions on exactly these resources (a managed role: `aws plan` then `aws apply`).']
        }),
        deniedAccessCheck({
          id: `iam.${r.key}-negative-access`,
          section,
          title: 'Negative access',
          why: ROLE_WHY[r.key].denied,
          simulation,
          probes: r.probes.denied,
          analysis: present ? r.analysis : null,
          remediation: ['Remove the grant that allows it (or bound the role with a permissions boundary); re-run verify.']
        })
      ]
    };
  });

  const push = roles.find((r) => r.key === 'push');
  const inspectorChecks = inspector
    ? [
        inspectorAccountCheck(inspector.account),
        inspectorCoverageCheck(inspector.coverage, { repository: d.ecr.repository }),
        requiredAccessCheck({
          id: 'ecr.inspector-evidence',
          section: 'ECR',
          title: 'Inspector evidence access',
          why: 'with ENHANCED scanning the gate reads coverage and findings from Inspector as the push/scan role',
          simulation: push.role.state === 'present' && push.role.value.arn === push.arn ? push.simulation : null,
          probes: push.probes.required.filter((p) => p.action.startsWith('inspector2:')),
          remediation: ['Grant the push/scan role inspector2:ListCoverage and inspector2:ListFindings.']
        })
      ]
    : [];

  const online = managed.state === 'present' && managed.value.pingStatus === 'Online';
  const checks = [
    ...identity,
    adopt(oidcProviderCheck(oidc, { account, partition }), { why: 'every role trust names this provider; without it no workflow can assume a role' }),
    adopt(subjectFormatCheck(roleChecks.map((r) => r.trust.evaluation)), { why: 'trust matches the subject GitHub sends; aws commands make no GitHub call to confirm its format' }),
    ...roleChecks.flatMap((r) => r.checks),
    separationCheck({ config, roles, target: t }),
    verifyRepositoryCheck(repo, { account, region: resolved.region, repository: d.ecr.repository, partition }),
    verifyImmutabilityCheck(repo, { mode: d.ecr.ownership }),
    ...(d.ecr.ownership === 'managed' ? [managedRepositorySettingsCheck(repo)] : []),
    verifyScanningCheck(scanning, { account, repository: d.ecr.repository, repositoryScanOnPush: repo.state === 'present' && repo.value.scanOnPush }),
    ...inspectorChecks,
    adopt(instanceCheck(instance, { account, region: resolved.region, instanceId: d.ssm.instanceId }), { why: 'the deploy target must be this exact instance, in this account and region, running' }),
    adopt(managedInstanceCheck(managed, { instanceId: d.ssm.instanceId }), { title: 'Online', why: 'send-command reaches only an SSM-managed instance whose agent is Online' }),
    instancePullCheck({ instance, profile, analysis: instanceAnalysis, online, target: t, simulation: instanceSimulation, probes: instanceProbes }),
    ...owned
  ];
  return report({ target, checks, calls });
}
