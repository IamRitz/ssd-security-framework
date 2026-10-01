// `ssd-onboard aws plan`: discover, render, validate, and create an UNEXECUTED
// CloudFormation change set per stack, then record it locally for review.
//
// It creates PLANS, not infrastructure. Every AWS call goes through
// planningAws(), whose allowlist adds to the read-only operations only
// validate-template, create-change-set (CREATE/UPDATE, never IMPORT),
// describe-change-set and stack lookups by name. There is no way to execute a
// change set from here. Its only writes are:
//   - .ssd/aws-plans/<plan-id>/ (plan/record.mjs), and
//   - the unexecuted change set in CloudFormation — which, for a CREATE, also
//     leaves a REVIEW_IN_PROGRESS placeholder stack holding no resources until
//     the change set is executed (Phase 2C) or someone deletes it.
//
// Order is part of the contract; each step blocks before the next:
//   1. the framework checkout is bound to framework.repository @ framework.ref
//      (lib/framework.mjs, the same rule `render` uses) — AWS is not contacted
//      otherwise;
//   2. region (--region > delivery.aws.region; a disagreeing flag blocks);
//   3. sts get-caller-identity: expected account, never the root user;
//   4. discovery and ownership per unit (one unit = one stack = one change set):
//        --scope repo     the per-repository delivery stack
//        --scope shared   the shared GitHub OIDC stack (when managed), plus the
//                         registry scanning configuration, which Phase 2B only
//                         REPORTS (see prepareScanningUnit)
//      Any FAIL blocks the whole run before any change set is created;
//   5. render; the scope boundary is asserted on the template; plan ids are
//      derived and every plan directory slot is proven free;
//   6. validate-template, create-change-set, poll describe-change-set; the
//      described changes are classified and scope-asserted again;
//   7. the plan directory is written (secret-checked, exclusive, plan.json last).
import { planningAws } from './aws-cli.mjs';
import { enhancedOf, oidcProviderCheck, scanningCheck } from './doctor.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from './identity.mjs';
import { discoverRegistryScanning, discoverRepository, mergeScanningRules } from './discover/ecr.mjs';
import { discoverInspectorAccount } from './discover/inspector.mjs';
import { discoverRole, discoverRolePolicies, roleName } from './discover/iam-role.mjs';
import { discoverOidcProvider } from './discover/oidc-provider.mjs';
import { describeError } from './discover/result.mjs';
import { discoverStack, discoverStackByName, discoverStackResources, evaluateOwnership, planStack } from './discover/stacks.mjs';
import { SHARED_STACKS, canonicalSlug, repoStackName } from './stack-names.mjs';
import { diffLines, semanticPolicyDiff } from './policy/diff.mjs';
import { parseDocument } from './policy/evaluate.mjs';
import { planChangeSet } from './plan/change-set.mjs';
import { PLAN_SCHEMA_VERSION, assertPersistable, assertPlanSlotFree, changeSetNameOf, planDirOf, planIdInput, planIdOf, writePlanDirectory } from './plan/record.mjs';
import { STACK_KINDS, assertTemplateScope } from './plan/scope.mjs';
import { canonicalJson, sha256, ssdTags } from './templates/common.mjs';
import { REPO_LOGICAL_IDS, ROLE_POLICY_NAMES, renderRepoTemplate } from './templates/repo-ecr-delivery.mjs';
import { OIDC_LOGICAL_ID, renderOidcTemplate } from './templates/shared-github-oidc.mjs';
import { frameworkProblems } from '../lib/framework.mjs';

export const SCHEMA_VERSION = 1;
export const SCOPES = Object.freeze(['repo', 'shared']);
export const OUTCOMES = Object.freeze({ PLANNED: 0, NO_CHANGES: 0, NOTHING_TO_PLAN: 0, BLOCKED: 1, ERROR: 1 });
export const exitCodeOf = (report) => OUTCOMES[report.outcome] ?? 1;

export class PlanError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'PlanError';
    this.kind = kind;
  }
}

const FAIL = 'FAIL';
const WARN = 'WARN';
const NOT_VERIFIED = 'NOT VERIFIED';
const finding = (severity, kind, message) => ({ severity, kind, message });

// Phase 2B cannot plan the registry scanning configuration safely; this is why
// (verified against the CloudFormation resource schema and the ECR API).
export const REGISTRY_SCANNING_UNSUPPORTED =
  'delivery.registryScanning is managed, but Phase 2B does not plan AWS::ECR::RegistryScanningConfiguration: the resource is a registry-wide singleton ' +
  'whose create/update is a full PutRegistryScanningConfiguration replacement; its CloudFormation schema cannot express MANUAL rules; its handlers hold ' +
  'inspector2:Enable/Disable, so a change can enable or disable Inspector as a side effect; it cannot be tagged; and its create behaviour on an already ' +
  'configured registry is undocumented. Set delivery.registryScanning to existing: the plan then reports coverage and the proposed rules (current rules + this repository).';

// --- repo unit ---------------------------------------------------------------------------

async function evaluateResource(ctx, { label, logicalId, mode, discovered, physicalId, type, tags, stackName, scope, inStack }) {
  const out = { label, logicalId, type, mode, physicalId, state: discovered.state, ownership: null, findings: [], owned: false };
  if (discovered.state === 'unverified') {
    out.findings.push(finding(mode === 'managed' ? FAIL : NOT_VERIFIED, 'discovery-unverified', `${label}: ${describeError(discovered)}`));
    return out;
  }
  if (discovered.state === 'absent') {
    if (inStack) {
      out.findings.push(finding(FAIL, 'stack-drift', `${label}: stack ${stackName} lists ${logicalId}, but the resource does not exist (drift); planning against it is refused`));
    } else if (mode === 'existing') {
      out.findings.push(finding(WARN, 'existing-absent', `${label} is configured existing but does not exist; the plan never creates an existing resource (aws doctor fails readiness)`));
    }
    return out;
  }
  const evaluation = evaluateOwnership({ discovered: await discoverStack(ctx.aws, physicalId), resourceTags: tags, expectedType: type, slug: ctx.slug, scope, expectedStackName: stackName, region: ctx.region });
  out.ownership = evaluation.ownership;
  if (evaluation.ownership === 'unverified') {
    out.findings.push(finding(mode === 'managed' ? FAIL : NOT_VERIFIED, 'ownership-unverified', `${label}: ownership could not be determined (${evaluation.reasons.join('; ')})`));
    return out;
  }
  if (evaluation.ownership === 'managed') {
    if (evaluation.stack?.logicalId !== logicalId) {
      out.findings.push(finding(FAIL, 'logical-id-mismatch', `${label} is a resource of ${stackName}, but as ${evaluation.stack?.logicalId}, not ${logicalId}`));
      return out;
    }
    out.owned = true;
    if (mode === 'existing') {
      out.findings.push(finding(WARN, 'leaves-stack', `${label} is configured existing but is owned by ${stackName}: the plan removes it from the stack (a DELETE; the resource itself is retained)`));
    }
    return out;
  }
  // exists-not-owned
  if (mode === 'managed') {
    out.findings.push(
      finding(
        FAIL,
        'exists-not-owned',
        `${label} ${physicalId} exists and is NOT owned by ${stackName} (${evaluation.reasons.join('; ')}). A name match is never ownership: the plan will not create a stack that tries to take it over. Configure it as existing, or use a future CloudFormation import flow (not implemented in Phase 2B)`
      )
    );
  }
  return out;
}

const unexpectedStackResources = (stackKind, stackResources) =>
  stackResources.filter((r) => !Object.hasOwn(STACK_KINDS[stackKind].resources, r.logicalId) || STACK_KINDS[stackKind].resources[r.logicalId] !== r.type);

async function stackState(ctx, unit, { stackName, scope }) {
  const stack = await discoverStackByName(ctx.aws, stackName);
  const sp = planStack({ stack, expectedStackName: stackName, scope, slug: ctx.slug });
  unit.changeSetType = sp.type;
  unit.baseStack = sp.baseStack;
  sp.problems.forEach((p) => unit.findings.push(finding(FAIL, 'stack-not-plannable', p)));
  let resources = [];
  if (stack.state === 'present' && sp.type !== null) {
    const listed = await discoverStackResources(ctx.aws, stackName);
    if (listed.state !== 'present') {
      unit.findings.push(finding(FAIL, 'stack-resources-unverified', `the resources of ${stackName} could not be listed (${listed.state === 'unverified' ? describeError(listed) : listed.code})`));
    } else {
      resources = listed.value;
      for (const r of unexpectedStackResources(unit.stackKind, resources)) {
        unit.findings.push(finding(FAIL, 'unexpected-stack-resource', `${stackName} holds ${r.logicalId} (${r.type}), which is not a resource this stack may hold; the plan refuses rather than propose deleting it`));
      }
    }
  }
  return resources;
}

// Before/after for one generated role's trust and permissions.
//
// A framework-managed role that the stack already owns must have EXACTLY the
// permissions the stack models: its one inline policy (ROLE_POLICY_NAMES).
// Any other inline policy, or any managed policy attached directly to the role,
// makes its effective permissions differ from the reviewed template and change
// set — so planning for that role is REFUSED (never warned about), and nothing
// is detached or modified. A policy list that cannot be read completely proves
// nothing and is refused the same way.
async function iamRecord(ctx, { key, arn, logicalId, generated, resource, stackName }) {
  const record = { logicalId, role: key, arn, trust: null, permissions: null, unmanaged: [], findings: [] };
  let beforeTrust = null;
  let beforePermissions = null;
  if (resource.owned) {
    beforeTrust = parseDocument(resource.discovered.value.trust ?? '{}');
    const policies = await discoverRolePolicies(ctx.aws, resource.physicalId);
    const ours = policies.policies.find((p) => p.kind === 'inline' && p.name === `inline:${ROLE_POLICY_NAMES[key]}`);
    beforePermissions = ours ? parseDocument(ours.document) : null;
    const unmanaged = policies.policies.filter((p) => p !== ours);
    record.unmanaged = unmanaged.map((p) => (p.kind === 'attached' ? `managed policy ${p.arn}` : `inline policy ${p.name.slice('inline:'.length)}`));
    for (const policy of unmanaged) {
      const what = policy.kind === 'attached' ? `managed policy ${policy.arn} (${policy.name.slice('attached:'.length)}) is attached directly to it` : `inline policy '${policy.name.slice('inline:'.length)}' is not the stack's ${ROLE_POLICY_NAMES[key]}`;
      record.findings.push(
        finding(
          FAIL,
          'unmanaged-policy',
          `${arn} exists and is owned by ${stackName}, but ${what}: an unmanaged attachment the stack does not represent. Planning is refused for this role — its effective permissions would differ from the reviewed template, so it could not honestly be called managed or least-privilege. ssd-onboard never detaches or edits it: remove it manually, or adopt/model it explicitly in a future workflow`
        )
      );
    }
    if (!policies.complete) {
      record.findings.push(
        finding(FAIL, 'policies-unverified', `${arn} is owned by ${stackName}, but not every policy attached to it could be read (${policies.errors.map((e) => e.message).join('; ')}): an unmanaged attachment cannot be ruled out, so planning is refused for this role`)
      );
    }
  }
  const trustDiff = semanticPolicyDiff(beforeTrust, generated.trust);
  const permissionsDiff = semanticPolicyDiff(beforePermissions, generated.permissions);
  record.trust = { before: beforeTrust, after: generated.trust, diff: trustDiff, lines: diffLines(trustDiff, { dimensions: ['principals', 'subjects', 'audiences', 'actions', 'conditions'] }) };
  record.permissions = { before: beforePermissions, after: generated.permissions, diff: permissionsDiff, lines: diffLines(permissionsDiff, { dimensions: ['actions', 'resources', 'grants', 'conditions'] }) };
  return record;
}

async function prepareRepoUnit(ctx) {
  const d = ctx.config.delivery;
  const stackName = repoStackName(ctx.slug);
  const unit = { stackKind: 'repo', scope: 'repo', stackName, label: 'Per-repository delivery stack', mode: 'planned', findings: [], checks: [], resources: [], iam: [], template: null, policies: {} };

  const pushName = roleName(d.roles.pushScanRoleArn);
  const deployName = roleName(d.roles.deployRoleArn);
  if (pushName.toLowerCase() === deployName.toLowerCase()) {
    unit.findings.push(finding(FAIL, 'role-separation', `the push+scan and deploy roles resolve to the same IAM role name ('${pushName}' / '${deployName}'; IAM role names are case-insensitive): no single role may both push and deploy`));
  }
  const stackResources = await stackState(ctx, unit, { stackName, scope: 'repo' });
  const inStack = (logicalId) => stackResources.some((r) => r.logicalId === logicalId);

  const repo = await discoverRepository(ctx.aws, { account: ctx.account, repository: d.ecr.repository });
  unit.resources.push({
    ...(await evaluateResource(ctx, {
      label: 'ECR repository',
      logicalId: REPO_LOGICAL_IDS.repository,
      mode: d.ecr.ownership,
      discovered: repo,
      physicalId: d.ecr.repository,
      type: 'AWS::ECR::Repository',
      tags: repo.state === 'present' && repo.value.tags.state === 'present' ? repo.value.tags.value : null,
      stackName,
      scope: 'repo',
      inStack: inStack(REPO_LOGICAL_IDS.repository)
    })),
    discovered: repo
  });
  for (const [key, label, arn, mode] of [
    ['push', 'Push/scan role', d.roles.pushScanRoleArn, d.roles.pushScanOwnership],
    ['deploy', 'Deploy role', d.roles.deployRoleArn, d.roles.deployOwnership]
  ]) {
    const role = await discoverRole(ctx.aws, arn);
    if (role.state === 'present' && role.value.arn !== arn) {
      unit.findings.push(finding(mode === 'managed' ? FAIL : WARN, 'role-name-collision', `${label}: a role named like ${roleName(arn)} exists as ${role.value.arn ?? '(no ARN)'}, not ${arn} (IAM role names are case-insensitive)`));
      unit.resources.push({ label, logicalId: REPO_LOGICAL_IDS[key], type: 'AWS::IAM::Role', mode, physicalId: role.value.name, state: 'collision', ownership: null, findings: [], owned: false, discovered: role, key, arn });
      continue;
    }
    const evaluated = await evaluateResource(ctx, {
      label,
      logicalId: REPO_LOGICAL_IDS[key],
      mode,
      discovered: role,
      physicalId: role.state === 'present' ? role.value.name : roleName(arn),
      type: 'AWS::IAM::Role',
      tags: role.state === 'present' ? role.value.tags : null,
      stackName,
      scope: 'repo',
      inStack: inStack(REPO_LOGICAL_IDS[key])
    });
    unit.resources.push({ ...evaluated, discovered: role, key, arn });
  }
  unit.resources.forEach((r) => unit.findings.push(...r.findings));

  let enhanced = false;
  if (d.roles.pushScanOwnership === 'managed') {
    const scanning = await discoverRegistryScanning(ctx.aws);
    enhanced = enhancedOf(scanning);
    if (enhanced === null) {
      unit.findings.push(finding(FAIL, 'scan-type-unknown', `the registry scan type could not be determined (${scanning.state === 'unverified' ? describeError(scanning) : 'missing or unrecognised'}), so the push+scan role's inspector2 statement cannot be decided`));
      enhanced = false;
    }
  }
  if (!d.environment && d.roles.deployOwnership === 'managed') {
    unit.findings.push(finding(WARN, 'no-environment', 'delivery.environment is empty: the generated deploy role trusts the default-branch context, so GitHub environment reviewers cannot gate it'));
  }
  if ([d.roles.pushScanOwnership, d.roles.deployOwnership].includes('managed')) {
    unit.findings.push(finding(NOT_VERIFIED, 'subject-format-unverified', 'trust uses exact legacy subjects repo:<owner>/<repo>:<context>; which format GitHub issues for this repository (OIDC customization) is not verified — aws plan makes no GitHub call'));
  }

  const blocked = unit.findings.some((f) => f.severity === FAIL);
  const anyManaged = [d.ecr.ownership, d.roles.pushScanOwnership, d.roles.deployOwnership].includes('managed');
  if (!anyManaged) {
    if (stackResources.length > 0) {
      unit.findings.push(finding(FAIL, 'stack-would-empty', `every per-repository resource is configured existing, but ${stackName} still holds resources; removing them all requires deleting the stack, which a plan cannot express`));
    } else {
      unit.mode = 'nothing';
    }
    return unit;
  }
  if (blocked) {
    return unit;
  }
  const rendered = renderRepoTemplate({ config: ctx.config, partition: ctx.partition, enhanced });
  unit.template = rendered.template;
  for (const [logicalId, generated] of Object.entries(rendered.policies)) {
    const resource = unit.resources.find((r) => r.logicalId === logicalId);
    const record = await iamRecord(ctx, { key: generated.role, arn: generated.arn, logicalId, generated, resource, stackName });
    unit.iam.push(record);
    unit.findings.push(...record.findings);
  }
  return unit;
}

// --- shared units ------------------------------------------------------------------------

async function prepareOidcUnit(ctx) {
  const d = ctx.config.delivery;
  const stackName = SHARED_STACKS.githubOidc;
  const unit = { stackKind: 'shared-github-oidc', scope: 'shared', stackName, label: 'Shared GitHub OIDC provider stack', mode: d.oidcProvider === 'managed' ? 'planned' : 'report-only', findings: [], checks: [], resources: [], iam: [], template: null, policies: {} };
  const oidc = await discoverOidcProvider(ctx.aws, { account: ctx.account });
  if (d.oidcProvider !== 'managed') {
    unit.checks.push(oidcProviderCheck(oidc, { account: ctx.account, partition: ctx.partition }));
    return unit;
  }
  const stackResources = await stackState(ctx, unit, { stackName, scope: 'shared' });
  if (oidc.state === 'present' && oidc.value.account !== ctx.account) {
    unit.findings.push(finding(FAIL, 'account-mismatch', `the listed GitHub OIDC provider ${oidc.value.arn} is in account ${oidc.value.account}, not ${ctx.account}`));
  } else {
    const evaluated = await evaluateResource(ctx, {
      label: 'GitHub OIDC provider',
      logicalId: OIDC_LOGICAL_ID,
      mode: 'managed',
      discovered: oidc,
      physicalId: oidc.state === 'present' ? oidc.value.arn : null,
      type: 'AWS::IAM::OIDCProvider',
      tags: oidc.state === 'present' ? oidc.value.tags : null,
      stackName,
      scope: 'shared',
      inStack: stackResources.some((r) => r.logicalId === OIDC_LOGICAL_ID)
    });
    unit.resources.push(evaluated);
    unit.findings.push(...evaluated.findings);
  }
  if (!unit.findings.some((f) => f.severity === FAIL)) {
    unit.template = renderOidcTemplate().template;
  }
  return unit;
}

// The registry scanning configuration is REPORTED, never planned, in Phase 2B:
//   existing  discover, validate coverage, and show the proposal (current rules
//             + one filter for this repository) — no change set;
//   managed   blocks, with the reason (REGISTRY_SCANNING_UNSUPPORTED).
// Inspector enablement has no CloudFormation resource type: it is reported as a
// prerequisite when the registry uses ENHANCED scanning.
async function prepareScanningUnit(ctx) {
  const d = ctx.config.delivery;
  const unit = { stackKind: 'shared-ecr-scanning', scope: 'shared', stackName: SHARED_STACKS.ecrScanning, label: 'Shared ECR registry scanning', mode: 'report-only', findings: [], checks: [], resources: [], iam: [], template: null, policies: {}, proposal: null, residual: [] };
  const scanning = await discoverRegistryScanning(ctx.aws);
  if (d.registryScanning === 'managed') {
    unit.findings.push(finding(FAIL, 'registry-scanning-unsupported', REGISTRY_SCANNING_UNSUPPORTED));
  }
  unit.checks.push(scanningCheck(scanning, { repository: d.ecr.repository, repositoryScanOnPush: false }));
  if (scanning.state === 'present') {
    unit.proposal = { current: scanning.value, ...mergeScanningRules(scanning.value, d.ecr.repository) };
  }
  const enhanced = enhancedOf(scanning);
  if (enhanced === true) {
    const inspector = await discoverInspectorAccount(ctx.aws, { account: ctx.account });
    const state = inspector.state === 'present' ? `Inspector ECR scanning is ${inspector.value.ecrState ?? 'unknown'}` : inspector.state === 'unverified' ? `Inspector status not readable (${describeError(inspector)})` : 'Inspector returned no status';
    unit.residual.push(`Inspector enablement is a prerequisite of ENHANCED scanning and is never planned (no CloudFormation resource type enables it): ${state}`);
  } else {
    unit.residual.push('Inspector enablement is not planned (no CloudFormation resource type enables it); BASIC scanning does not need it');
  }
  return unit;
}

// --- orchestration -----------------------------------------------------------------------

function report(base, { outcome, units = [], findings = [], skipped = null }) {
  return {
    schemaVersion: SCHEMA_VERSION,
    command: 'aws plan',
    scope: base.scope,
    target: base.target,
    framework: base.framework,
    outcome,
    findings,
    skipped,
    units: units.map(publicUnit),
    awsCalls: base.calls
  };
}

// What a unit reports (JSON and human): no live AWS objects, no templates.
function publicUnit(unit) {
  return {
    stackKind: unit.stackKind,
    scope: unit.scope,
    stackName: unit.stackName,
    label: unit.label,
    mode: unit.mode,
    status: unit.status ?? (unit.findings.some((f) => f.severity === FAIL) ? 'blocked' : unit.mode === 'planned' ? 'not-run' : unit.mode),
    changeSetType: unit.changeSetType ?? null,
    baseStack: unit.baseStack ?? null,
    planId: unit.planId ?? null,
    changeSetName: unit.changeSetName ?? null,
    changeSetArn: unit.changeSetArn ?? null,
    directory: unit.directory ?? null,
    counts: unit.counts ?? null,
    destructive: unit.destructive ?? null,
    changes: unit.changes ?? [],
    resources: unit.resources.map((r) => ({ label: r.label, logicalId: r.logicalId, type: r.type, mode: r.mode, physicalId: r.physicalId ?? null, state: r.state, ownership: r.ownership })),
    iam: unit.iam.map((i) => ({ logicalId: i.logicalId, role: i.role, arn: i.arn, created: i.trust.diff.created, trust: i.trust.lines, permissions: i.permissions.lines, trustChanged: i.trust.diff.changed, permissionsChanged: i.permissions.diff.changed, unmanaged: i.unmanaged })),
    findings: unit.findings,
    checks: unit.checks,
    proposal: unit.proposal ?? null,
    residual: unit.residual ?? []
  };
}

const capabilitiesFor = (template) => (Object.values(template.Resources).some((r) => r.Type.startsWith('AWS::IAM::Role')) ? ['CAPABILITY_NAMED_IAM'] : []);

// awsPlan(options) -> report. Throws for a run-ending failure (AwsCliError,
// IdentityError, PlanError, ChangeSetError, ScopeError, PlanRecordError,
// PathConfinementError, TrustBuildError).
//   config     the validated configuration       framework  detectFramework() result
//   root       consumer repository root          scope      'repo' (default) | 'shared'
//   region     --region or null                  exec/env/deadlineMs/now  planningAws()
//   sleep      injectable wait between describe-change-set polls
export async function awsPlan({ config, scope = 'repo', region: explicitRegion = null, exec, env = process.env, framework, root, deadlineMs, now, sleep }) {
  if (!SCOPES.includes(scope)) {
    throw new PlanError('unsupported-scope', `--scope must be repo or shared (got '${scope}')`);
  }
  const d = config.delivery;
  const slug = config.repository.slug;
  const account = d.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: d.aws.region });
  const calls = [];
  const base = {
    scope,
    target: { repository: slug, account, region: resolved.region, regionSource: resolved.source, caller: null },
    framework: { repository: config.framework.repository, ref: config.framework.ref },
    calls
  };

  const bindingProblems = frameworkProblems(framework, config);
  if (bindingProblems.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: bindingProblems.map((m) => finding(FAIL, 'framework-binding', m)), skipped: 'the framework checkout is not bound to framework.ref: AWS was not contacted' });
  }
  const regionC = regionCheck(resolved);
  if (regionC.status === FAIL) {
    return report(base, { outcome: 'BLOCKED', findings: regionC.findings.map((f) => finding(FAIL, f.kind, f.message)), skipped: 'region mismatch: AWS was not contacted' });
  }

  const aws = planningAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).filter((_, i, all) => all[i - 1] !== '--template-body').join(' ')) });
  const caller = await callerIdentity(aws);
  base.target.caller = { arn: caller.arn, account: caller.account, kind: caller.kind };
  const identity = [accountCheck(caller, account), principalCheck(caller)].filter((c) => c.status === FAIL);
  if (identity.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: identity.flatMap((c) => c.findings.map((f) => finding(FAIL, f.kind, f.message))), skipped: 'identity check failed: nothing was read and no change set was created' });
  }
  const ctx = { aws, config, slug, account, region: resolved.region, partition: caller.partition };

  const units = scope === 'repo' ? [await prepareRepoUnit(ctx)] : [await prepareOidcUnit(ctx), await prepareScanningUnit(ctx)];
  if (units.some((u) => u.findings.some((f) => f.severity === FAIL))) {
    return report(base, { outcome: 'BLOCKED', units, skipped: 'a precondition failed: no change set was created' });
  }

  // Render, assert scope, derive plan ids, prove every slot free — before ANY
  // AWS object is created.
  const tags = ssdTags({ scope, slug });
  const planned = units.filter((u) => u.template);
  for (const unit of planned) {
    assertTemplateScope(unit.stackKind, unit.template);
    unit.body = canonicalJson(unit.template);
    unit.parametersText = canonicalJson([]);
    unit.capabilities = capabilitiesFor(unit.template);
    unit.policiesText = canonicalJson(Object.fromEntries(unit.iam.map((i) => [i.logicalId, { role: i.role, arn: i.arn, trust: { before: i.trust.before, after: i.trust.after, diff: i.trust.diff.dimensions }, permissions: { before: i.permissions.before, after: i.permissions.after, diff: i.permissions.diff.dimensions }, unmanagedPolicies: i.unmanaged }])));
    assertPersistable({ 'template.json': unit.body, 'parameters.json': unit.parametersText, 'policies.json': unit.policiesText }, env);
    unit.planIdInput = planIdInput({
      account,
      region: resolved.region,
      scope,
      stackKind: unit.stackKind,
      stackName: unit.stackName,
      changeSetType: unit.changeSetType,
      baseStack: unit.baseStack,
      templateSha256: sha256(unit.body),
      parametersSha256: sha256(unit.parametersText),
      tagsSha256: sha256(canonicalJson(tags)),
      capabilities: unit.capabilities,
      framework: base.framework,
      repository: canonicalSlug(slug)
    });
    unit.planId = planIdOf(unit.planIdInput);
    unit.changeSetName = changeSetNameOf(unit.planId);
    await assertPlanSlotFree(root, unit.planId);
  }
  const configDigest = sha256(canonicalJson(config));

  for (const unit of planned) {
    const result = await planChangeSet(aws, { stackKind: unit.stackKind, stackName: unit.stackName, changeSetName: unit.changeSetName, type: unit.changeSetType, body: unit.body, tags, account, region: resolved.region, sleep });
    if (JSON.stringify(result.capabilities) !== JSON.stringify(unit.capabilities)) {
      throw new PlanError('capabilities-mismatch', `validate-template requires [${result.capabilities.join(', ')}], but the plan id binds [${unit.capabilities.join(', ')}]`);
    }
    Object.assign(unit, { status: result.outcome, changeSetArn: result.changeSetArn, changes: result.changes, counts: result.counts, destructive: result.destructive });
    const changeSetText = canonicalJson(result.described);
    const files = { 'template.json': unit.body, 'parameters.json': unit.parametersText, 'change-set.json': changeSetText, 'policies.json': unit.policiesText };
    const plan = {
      schemaVersion: PLAN_SCHEMA_VERSION,
      planId: unit.planId,
      outcome: result.outcome,
      scope,
      stackKind: unit.stackKind,
      repository: canonicalSlug(slug),
      account,
      region: resolved.region,
      callerArn: caller.arn,
      stackName: unit.stackName,
      changeSetType: unit.changeSetType,
      changeSetName: unit.changeSetName,
      changeSetArn: result.changeSetArn,
      changeSet: { status: result.described.Status, executionStatus: result.described.ExecutionStatus ?? null, statusReason: result.described.StatusReason ?? null },
      baseStack: unit.planIdInput.baseStack,
      templateSha256: unit.planIdInput.templateSha256,
      parametersSha256: unit.planIdInput.parametersSha256,
      tags,
      capabilities: unit.capabilities,
      framework: base.framework,
      createdFromConfigDigest: configDigest,
      changes: result.changes,
      counts: result.counts,
      destructive: result.destructive,
      planIdInput: unit.planIdInput,
      files: Object.fromEntries(Object.entries(files).map(([name, text]) => [name, sha256(text)]))
    };
    unit.directory = await writePlanDirectory(root, unit.planId, { ...files, 'plan.json': canonicalJson(plan) }, env);
  }
  const outcome = planned.length === 0 ? 'NOTHING_TO_PLAN' : planned.every((u) => u.status === 'no-changes') ? 'NO_CHANGES' : 'PLANNED';
  return report(base, { outcome, units });
}

export { planDirOf };
