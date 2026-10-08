// `ssd-onboard aws verify --scope break-glass-repo --environment <env>`
// (Phase 3D): does one repository's deployed stack hold exactly the reviewed
// invoker role and approver parameter? Read-only by construction
// (repositoryReadAws: this stack's resources, the OIDC provider, and simulation
// of invoker and execution roles only), plus the read-only GitHub identity.
//
// Each fact is its own check:
//   - GitHub still reports this repository_id under this slug, with the
//     DEFAULT OIDC subject (the trust is only right if that holds);
//   - the stack is ssd-onboard's, for this environment, holding exactly the
//     role and the parameter under their derived names;
//   - the role: that ARN, MaxSessionDuration 3600, exactly its one inline
//     policy, nothing attached;
//   - trust and permissions BYTE-EXACT (canonical JSON) to the reviewed
//     documents, and the live trust evaluated offline: the configured subject
//     assumes; other repositories, other events, other audiences do not;
//   - simulation: InvokeFunction on this environment's CI broker ALLOWED, the
//     doc's whole negative table DENIED;
//   - the approver parameter: String/Standard/text, byte-equal to the
//     configuration, accepted by the broker's parser (`[]` is a WARN); this
//     environment's interaction role may read it, its CI role and the other
//     environment's interaction role may not.
import { parseApproverList } from '../../../broker/authorize/approvers.mjs';
import { repositoryReadAws } from '../aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from '../identity.mjs';
import { discoverRole, discoverRolePolicies, simulateProbes } from '../discover/iam-role.mjs';
import { describeError } from '../discover/result.mjs';
import { LIVE, discoverStackByName, discoverStackResources, stackTagProblems } from '../discover/stacks.mjs';
import { PolicyError, parseDocument } from '../policy/evaluate.mjs';
import { INVOKER_POLICY_NAME, MAX_SESSION_SECONDS, defaultSubject, invokerPermissionPolicy, invokerProbes, invokerTrustPolicy, invokerTrustProblems } from '../policy/break-glass-invoker.mjs';
import { BREAK_GLASS_ENVIRONMENTS } from '../stack-names.mjs';
import { canonicalJson } from '../templates/common.mjs';
import { REPOSITORY_LOGICAL_IDS as L, REPOSITORY_RESOURCE_TYPES, approverParameter } from '../templates/break-glass-repository.mjs';
import { FAIL, NOT_VERIFIED, PASS, WARN, check, deniedAccessCheck, identityCheck, report, requiredAccessCheck, worst } from '../verify.mjs';
import { discoverParameter, discoverParameterMetadata } from './discover.mjs';
import { breakGlassArns, invokerArns, invokerNames, otherEnvironment } from './names.mjs';
import { githubIdentityFindings } from './repository-plan.mjs';

export const REPOSITORY_SECTIONS = Object.freeze(['Identity', 'Repository', 'Ownership', 'Invoker role', 'Approvers']);

const fail = (kind, message) => ({ severity: FAIL, kind, message });
const nv = (kind, message) => ({ severity: NOT_VERIFIED, kind, message });
const done = (c, findings, observed = [], remediation = []) => {
  const status = worst(findings);
  return { ...c, status, findings, observed, remediation: status === PASS ? [] : remediation };
};
const unreadable = (what, result) => nv(result.state === 'unverified' ? result.error.kind : 'absent', `${what} could not be read (${result.state === 'unverified' ? describeError(result) : result.code})`);
const REPLAN = ['Bring the stack back to its configuration: `aws plan --scope break-glass-repo` then `aws apply`.'];
const absentRole = (simulation) => simulation?.state === 'unverified' && simulation.error.kind === 'not-found' && simulation.error.code === 'NoSuchEntity';
const doc = (value) => {
  try {
    return parseDocument(value ?? '');
  } catch (error) {
    if (error instanceof PolicyError) return null;
    throw error;
  }
};

// --- pure checks ----------------------------------------------------------------------

export function repositoryIdentityCheck({ config, identity }) {
  const c = check('bg.repo.github', 'Repository', 'GitHub identity', {
    basis: 'github',
    why: 'approvers and the invoker role are keyed on repository_id, and the trust is right only while GitHub issues the default subject',
    expected: [`repos/${config.repository.slug}: id ${config.repository.id}, full_name ${config.repository.slug} (ignoring case)`, 'OIDC subject customization: use_default true']
  });
  const gh = githubIdentityFindings(config, identity);
  // An unreadable GitHub proves nothing either way: NOT VERIFIED, not FAIL.
  const findings = gh.findings.map((f) => (/-unverified$/.test(f.kind) ? { ...f, severity: NOT_VERIFIED } : f));
  return { check: done(c, findings, gh.fullName ? [`${config.repository.id} = ${gh.fullName}, default subject`] : []), fullName: gh.fullName };
}

export function repositoryStackCheck({ environment, repositoryId, stack, resources }) {
  const n = invokerNames(environment, repositoryId);
  const c = check('bg.repo.stack', 'Ownership', 'Stack and resources', {
    why: 'the role and the parameter are ssd-onboard\'s only when their stack, its environment tag and their logical ids prove it',
    expected: [`stack ${n.stack}, settled, tagged ssd:environment=${environment}`, `exactly ${L.role} = ${n.role} and ${L.approvers} = ${n.approverParameter}`]
  });
  if (stack.state === 'absent') return done(c, [fail('not-deployed', `stack ${n.stack} does not exist`)], [], ['Plan and apply it: `aws plan --scope break-glass-repo` then `aws apply`.']);
  if (stack.state !== 'present') return done(c, [unreadable(`stack ${n.stack}`, stack)]);
  const st = stack.value;
  const findings = [];
  if (st.name !== n.stack) findings.push(fail('stack-not-owned', `describe-stacks returned '${st.name}', not '${n.stack}'`));
  if (!LIVE.has(st.status)) findings.push(fail('stack-unsettled', `stack ${n.stack} is ${st.status}`));
  findings.push(...stackTagProblems(st.tags, { scope: 'break-glass', slug: null, environment }).map((m) => fail('stack-not-owned', m)));
  if (resources.state !== 'present') {
    findings.push(unreadable(`the resources of ${n.stack}`, resources));
  } else {
    for (const r of resources.value) {
      if (!Object.hasOwn(REPOSITORY_RESOURCE_TYPES, r.logicalId) || REPOSITORY_RESOURCE_TYPES[r.logicalId] !== r.type) findings.push(fail('unexpected-resource', `${n.stack} holds ${r.logicalId} (${r.type}), which a repository stack never holds`));
    }
    for (const [id, physical] of [[L.role, n.role], [L.approvers, n.approverParameter]]) {
      const own = resources.value.filter((r) => r.logicalId === id);
      if (own.length !== 1) findings.push(fail('resource-missing', `${n.stack} has ${own.length === 0 ? 'no' : 'more than one'} ${id}`));
      else if (own[0].physicalId !== physical) findings.push(fail('physical-id', `${id} is ${own[0].physicalId}, not ${physical}`));
    }
  }
  return done(c, findings, [`${n.stack}: ${st.status}`], REPLAN);
}

export function invokerRoleCheck({ environment, repositoryId, target, live, policies }) {
  const n = invokerNames(environment, repositoryId);
  const arn = invokerArns(environment, repositoryId, target).role;
  const c = check('bg.repo.role', 'Invoker role', 'Role and attachments', {
    why: 'the role\'s effective permissions must be exactly its one reviewed inline policy',
    expected: [arn, `MaxSessionDuration ${MAX_SESSION_SECONDS}`, `inline policy ${INVOKER_POLICY_NAME} only; no managed policy attached`]
  });
  if (live.state !== 'present') return done(c, [live.state === 'absent' ? fail('role-missing', `${arn} does not exist`) : unreadable(arn, live)], [], REPLAN);
  const findings = [];
  if (live.value.arn !== arn) findings.push(fail('role-location', `the role is ${live.value.arn}, not ${arn}`));
  if (live.value.maxSessionDuration !== MAX_SESSION_SECONDS) findings.push(fail('managed-drift', `MaxSessionDuration is ${live.value.maxSessionDuration ?? 'unreported'}, not ${MAX_SESSION_SECONDS}`));
  if (!policies) findings.push(nv('prerequisite-missing', 'the role\'s policies could not be read'));
  else {
    for (const p of policies.policies) {
      if (!(p.kind === 'inline' && p.name === `inline:${INVOKER_POLICY_NAME}`)) findings.push(fail('unmanaged-policy', `${p.kind === 'attached' ? `managed policy ${p.arn}` : `inline policy ${p.name.slice('inline:'.length)}`} is attached: the role's effective permissions are not the reviewed policy`));
    }
    if (!policies.policies.some((p) => p.name === `inline:${INVOKER_POLICY_NAME}`)) findings.push(fail('policy-missing', `the inline policy ${INVOKER_POLICY_NAME} is missing`));
    if (!policies.complete) findings.push(nv('policies-incomplete', `not every policy could be read: ${policies.errors.map((e) => e.message).join('; ')}`));
  }
  return done(c, findings, [`${n.role}: ${live.value.arn}`, ...(policies ? [`policies: ${policies.policies.map((p) => p.name).join(', ') || '(none)'}`] : [])], REPLAN);
}

// Trust: byte-exact to the reviewed document, AND evaluated offline.
export function invokerTrustCheck({ repositoryId, target, live, fullName }) {
  const c = check('bg.repo.trust', 'Invoker role', 'Trust: pull_request runs of this repository only', {
    basis: 'policy-document',
    why: 'any job of an admitted subject can assume the role; the subject must be exactly GitHub\'s default for this repository\'s pull_request runs',
    expected: [fullName ? `exactly ${canonicalJson(invokerTrustPolicy({ ...target, subject: defaultSubject(fullName) })).replace(/\s+/g, ' ')}` : 'the default subject (GitHub identity required)']
  });
  if (live.state !== 'present') return done(c, [nv('prerequisite-missing', 'the role could not be read')]);
  if (!fullName) return done(c, [nv('prerequisite-missing', 'GitHub did not confirm the repository and its default subject, so the expected trust is unknown')]);
  const trust = doc(live.value.trust);
  if (!trust) return done(c, [fail('malformed-policy', 'the trust policy is not a JSON document')]);
  const findings = [];
  if (canonicalJson(trust) !== canonicalJson(invokerTrustPolicy({ ...target, subject: defaultSubject(fullName) }))) findings.push(fail('trust-drift', `the trust is not the reviewed document: ${JSON.stringify(trust)}`));
  findings.push(...invokerTrustProblems(trust, { ...target, fullName, repositoryId }).map((m) => fail('trust', m)));
  return done(c, findings, [`subject ${defaultSubject(fullName)}`], REPLAN);
}

export function invokerPermissionsCheck({ environment, target, policies }) {
  const want = invokerPermissionPolicy(environment, target);
  const c = check('bg.repo.permissions', 'Invoker role', 'Permissions: invoke the CI broker only', {
    basis: 'policy-document',
    why: 'the role must do nothing but invoke this environment\'s unqualified CI broker',
    expected: [`exactly ${canonicalJson(want).replace(/\s+/g, ' ')}`]
  });
  const ours = policies?.policies.find((p) => p.kind === 'inline' && p.name === `inline:${INVOKER_POLICY_NAME}`);
  if (!ours) return done(c, [nv('prerequisite-missing', `the inline policy ${INVOKER_POLICY_NAME} could not be read`)]);
  const live = doc(ours.document);
  if (!live) return done(c, [fail('malformed-policy', 'the inline policy is not a JSON document')]);
  return done(c, canonicalJson(live) === canonicalJson(want) ? [] : [fail('permissions-drift', `the inline policy is not the reviewed document: ${JSON.stringify(live)}`)], [], REPLAN);
}

export function approverParameterCheck({ environment, target, config, parameter, metadata }) {
  const want = approverParameter(config, environment);
  const arn = invokerArns(environment, config.repository.id, target).approverParameter;
  const c = check('bg.repo.approvers', 'Approvers', 'Approver parameter', {
    why: 'the interaction function authorizes a click only for these Slack user ids; anything else must be exactly the reviewed list',
    expected: [arn, `Type ${want.type}, Tier ${want.tier}, DataType ${want.dataType}`, `Value ${want.value}`]
  });
  if (parameter.state !== 'present') return done(c, [parameter.state === 'absent' ? fail('parameter-missing', `${want.name} does not exist: nobody is authorized`) : unreadable(want.name, parameter)], [], REPLAN);
  const p = parameter.value;
  const findings = [];
  if (p.name !== want.name || p.arn !== arn) findings.push(fail('parameter-location', `the parameter is ${p.arn ?? p.name}, not ${arn}`));
  if (p.type !== want.type) findings.push(fail('parameter-type', `Type is ${p.type}, not ${want.type} (the broker refuses anything else)`));
  if (p.dataType !== want.dataType) findings.push(fail('managed-drift', `DataType is ${p.dataType ?? '(none)'}, not ${want.dataType}`));
  if (metadata.state !== 'present') findings.push(unreadable(`the tier of ${want.name}`, metadata));
  else if (metadata.value.tier !== want.tier) findings.push(fail('managed-drift', `Tier is ${metadata.value.tier ?? '(none)'}, not ${want.tier}`));
  const parsed = parseApproverList(p.value);
  if (parsed.state === 'malformed') findings.push(fail('value-malformed', `the broker reads it as malformed (nobody is authorized): ${parsed.reason}`));
  if (p.value !== want.value) findings.push(fail('value-drift', `the live value is not the reviewed list (live ${JSON.stringify(p.value)})`));
  if (parsed.state === 'empty') findings.push({ severity: WARN, kind: 'no-approvers', message: 'the approver list is []: enabled but not operationally ready — nobody can approve (never a reason to authorize)' });
  return done(c, findings, [`${p.name}: ${p.type}${metadata.state === 'present' ? `/${metadata.value.tier}` : ''}/${p.dataType}`, `value ${JSON.stringify(p.value)}`], REPLAN);
}

// --- orchestration --------------------------------------------------------------------

//   operator / repository   the validated files      github  async (slug) -> discoverRepositoryIdentity() result
export async function awsVerifyBreakGlassRepository({ operator, repository: config, environment, github, region: explicitRegion = null, exec, env = process.env, deadlineMs, now }) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment) || !Object.hasOwn(config?.environments ?? {}, environment)) {
    throw Object.assign(new Error(`--environment must be production or synthetic and configured in --repository-config (got '${environment}')`), { kind: 'configuration' });
  }
  const account = operator.aws.accountId;
  const id = config.repository.id;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: operator.aws.region });
  const target = { scope: 'break-glass-repo', environment, repository: config.repository.slug, repositoryId: id, account, region: resolved.region, regionSource: resolved.source, caller: null, awsProfile: env.AWS_PROFILE || null };
  const calls = [];
  const sections = REPOSITORY_SECTIONS;
  const regionC = identityCheck(regionCheck(resolved));
  if (regionC.status === FAIL) {
    return report({ target, checks: [regionC], calls, sections, skipped: 'region mismatch: AWS was not contacted' });
  }
  const aws = repositoryReadAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).join(' ')) });
  const caller = await callerIdentity(aws);
  target.caller = caller;
  const identity = [identityCheck(accountCheck(caller, account)), identityCheck(principalCheck(caller)), regionC];
  if (identity.some((c) => c.status === FAIL)) {
    return report({ target, checks: identity, calls, sections, skipped: 'identity check failed: no resource was read' });
  }
  const t = { partition: caller.partition, account, region: resolved.region };
  const n = invokerNames(environment, id);
  const a = invokerArns(environment, id, t);

  const gh = repositoryIdentityCheck({ config, identity: typeof github === 'function' ? await github(config.repository.slug) : null });
  const stack = await discoverStackByName(aws, n.stack);
  const resources = stack.state === 'present' ? await discoverStackResources(aws, n.stack) : stack;
  const live = await discoverRole(aws, a.role);
  const policies = live.state === 'present' && live.value.arn === a.role ? await discoverRolePolicies(aws, live.value.name ?? n.role) : null;
  const probes = invokerProbes(environment, t, { repositoryId: id });
  const simulation = live.state === 'present' && live.value.arn === a.role ? await simulateProbes(aws, a.role, [...probes.required, ...probes.denied]) : null;
  const parameter = await discoverParameter(aws, n.approverParameter);
  const metadata = await discoverParameterMetadata(aws, n.approverParameter);

  // Who may read the approvers: this environment's interaction role only.
  const own = breakGlassArns(environment, t).roles;
  const other = breakGlassArns(otherEnvironment(environment), t).roles;
  const read = [{ action: 'ssm:GetParameter', resource: a.approverParameter, why: 'the interaction function reads the approvers at click time (Phase 3B)' }];
  const denyRead = (why) => [{ action: 'ssm:GetParameter', resource: a.approverParameter, severity: FAIL, why }];
  const interactionsSim = await simulateProbes(aws, own.interactions, read);
  const ciSim = await simulateProbes(aws, own.ci, denyRead('the CI broker never reads approvers'));
  const otherSim = await simulateProbes(aws, other.interactions, denyRead(`the ${otherEnvironment(environment)} interaction function never reads ${environment}'s approvers`));
  const otherCheck = deniedAccessCheck({ id: 'bg.repo.approvers-other-environment', section: 'Approvers', title: `${otherEnvironment(environment)} interaction role cannot read them`, why: denyRead('')[0].why, simulation: otherSim, probes: denyRead(`the ${otherEnvironment(environment)} interaction function never reads ${environment}'s approvers`) });

  const checks = [
    ...identity,
    gh.check,
    repositoryStackCheck({ environment, repositoryId: id, stack, resources }),
    invokerRoleCheck({ environment, repositoryId: id, target: t, live, policies }),
    invokerTrustCheck({ repositoryId: id, target: t, live, fullName: gh.fullName }),
    invokerPermissionsCheck({ environment, target: t, policies }),
    requiredAccessCheck({ id: 'bg.repo.invoke', section: 'Invoker role', title: 'Invokes the CI broker', why: probes.required[0].why, simulation, probes: probes.required, remediation: REPLAN }),
    deniedAccessCheck({ id: 'bg.repo.negative-access', section: 'Invoker role', title: 'Nothing else', why: 'no state, secret, parameter, log, other function, other environment or role is reachable', simulation, probes: probes.denied, remediation: ['Remove the grant that allows it; re-run verify.'] }),
    approverParameterCheck({ environment, target: t, config, parameter, metadata }),
    requiredAccessCheck({ id: 'bg.repo.approvers-reader', section: 'Approvers', title: `${environment} interaction role reads them`, why: read[0].why, simulation: interactionsSim, probes: read }),
    deniedAccessCheck({ id: 'bg.repo.approvers-ci', section: 'Approvers', title: `${environment} CI role cannot read them`, why: 'the CI broker never reads approvers', simulation: ciSim, probes: denyRead('the CI broker never reads approvers') }),
    absentRole(otherSim) ? { ...otherCheck, status: PASS, findings: [], observed: [`${other.interactions} does not exist: it holds no access`], remediation: [] } : otherCheck
  ];
  return report({ target, checks, calls, sections });
}

