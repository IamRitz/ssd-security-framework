// `ssd-onboard aws verify --scope break-glass-governance --environment <env>`
// (Phase 3D): does the deployed governance stack hold exactly the reviewed
// allowed-commit set, and can only the right principals read it?
// Read-only by construction (governanceReadAws: governance reads, the tier,
// and simulation of the four break-glass execution roles only).
//
// Each fact is its own check:
//   - the stack is ssd-onboard's, tagged for THIS environment, holding exactly
//     AllowedFrameworkShas (AWS::SSM::Parameter) under the exact name;
//   - the parameter: that name and ARN, String, Standard, text, and a value
//     BYTE-EQUAL to the one rendered from --policy-config. Anything else is
//     drift — including a bootstrap admin's emergency `"shas": []`, which
//     fails closed but is still not the reviewed configuration;
//   - the broker's own parser accepts the LIVE value for this environment;
//   - every live commit is admissible (break-glass/admission.mjs), from the
//     framework checkout verify runs in;
//   - this environment's CI and interaction roles may GetParameter it; the
//     other environment's roles may not read or write it; no execution role
//     may write it.
// Advisory NOT VERIFIED (never a PASS): which OTHER principals of the account
// could write it cannot be enumerated from IAM.
import { parseFrameworkPolicy } from '../../../broker/identity/framework-policy.mjs';
import { governanceReadAws } from '../aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from '../identity.mjs';
import { simulateProbes } from '../discover/iam-role.mjs';
import { describeError } from '../discover/result.mjs';
import { LIVE, discoverStackByName, discoverStackResources, stackTagProblems } from '../discover/stacks.mjs';
import { BREAK_GLASS_ENVIRONMENTS, BREAK_GLASS_GOVERNANCE_STACKS } from '../stack-names.mjs';
import { GOVERNANCE_LOGICAL_ID, GOVERNANCE_RESOURCE_TYPES, governanceParameter } from '../templates/break-glass-governance.mjs';
import { FAIL, NOT_VERIFIED, PASS, check, deniedAccessCheck, identityCheck, report, requiredAccessCheck, worst } from '../verify.mjs';
import { admissionFindings, frameworkGit } from './admission.mjs';
import { discoverParameter, discoverParameterMetadata } from './discover.mjs';
import { breakGlassArns, otherEnvironment } from './names.mjs';

export const GOVERNANCE_SECTIONS = Object.freeze(['Identity', 'Ownership', 'Parameter', 'Admission', 'Access']);
export const GOVERNANCE_WRITE_ACTIONS = Object.freeze(['ssm:PutParameter', 'ssm:DeleteParameter', 'ssm:LabelParameterVersion', 'ssm:AddTagsToResource']);
const ROLES = ['ci', 'interactions'];

const fail = (kind, message) => ({ severity: FAIL, kind, message });
const nv = (kind, message) => ({ severity: NOT_VERIFIED, kind, message });
const done = (c, findings, observed = [], remediation = []) => {
  const status = worst(findings);
  return { ...c, status, findings, observed, remediation: status === PASS ? [] : remediation };
};
const unreadable = (what, result) => nv(result.state === 'unverified' ? result.error.kind : 'absent', `${what} could not be read (${result.state === 'unverified' ? describeError(result) : result.code})`);
const REPLAN = ['Bring the parameter back to its stack: `aws plan --scope break-glass-governance` then `aws apply`. Never put-parameter it by hand (except an emergency revoke to "shas": []).'];

// --- pure checks ----------------------------------------------------------------------

export function governanceStackCheck({ environment, stack, resources }) {
  const name = BREAK_GLASS_GOVERNANCE_STACKS[environment];
  const parameter = `/ssd/break-glass/${environment}/governance/allowed-framework-shas`;
  const c = check('bg.gov.stack', 'Ownership', 'Stack and resource', {
    why: 'the parameter is ssd-onboard\'s only when its stack, the stack\'s environment tag and its logical id prove it; a name proves nothing',
    expected: [`stack ${name}, settled, tagged ssd:environment=${environment}`, `exactly ${GOVERNANCE_LOGICAL_ID} (AWS::SSM::Parameter) = ${parameter}`]
  });
  if (stack.state === 'absent') return done(c, [fail('not-deployed', `stack ${name} does not exist`)], [], ['Plan and apply it: `aws plan --scope break-glass-governance` then `aws apply`.']);
  if (stack.state !== 'present') return done(c, [unreadable(`stack ${name}`, stack)]);
  const st = stack.value;
  const findings = [];
  if (st.name !== name) findings.push(fail('stack-not-owned', `describe-stacks returned '${st.name}', not '${name}'`));
  if (!LIVE.has(st.status)) findings.push(fail('stack-unsettled', `stack ${name} is ${st.status}`));
  findings.push(...stackTagProblems(st.tags, { scope: 'break-glass', slug: null, environment }).map((m) => fail('stack-not-owned', m)));
  if (resources.state !== 'present') {
    findings.push(unreadable(`the resources of ${name}`, resources));
  } else {
    for (const r of resources.value) {
      if (!Object.hasOwn(GOVERNANCE_RESOURCE_TYPES, r.logicalId) || GOVERNANCE_RESOURCE_TYPES[r.logicalId] !== r.type) {
        findings.push(fail('unexpected-resource', `${name} holds ${r.logicalId} (${r.type}), which a governance stack never holds`));
      }
    }
    const own = resources.value.filter((r) => r.logicalId === GOVERNANCE_LOGICAL_ID);
    if (own.length !== 1) findings.push(fail('resource-missing', `${name} has ${own.length === 0 ? 'no' : 'more than one'} ${GOVERNANCE_LOGICAL_ID}`));
    else if (own[0].physicalId !== parameter) findings.push(fail('physical-id', `${GOVERNANCE_LOGICAL_ID} is ${own[0].physicalId}, not ${parameter}`));
  }
  return done(c, findings, [`${name}: ${st.status}`], REPLAN);
}

export function governanceParameterCheck({ environment, target, policy, parameter, metadata }) {
  const want = governanceParameter(policy);
  const arn = breakGlassArns(environment, target).frameworkPolicyParameter;
  const c = check('bg.gov.parameter', 'Parameter', 'Exact shape and value', {
    why: 'the broker admits exactly the commits in this value; it must be byte-for-byte the reviewed configuration',
    expected: [arn, `Type ${want.type}, Tier ${want.tier}, DataType ${want.dataType}`, `Value ${want.value}`]
  });
  if (parameter.state !== 'present') return done(c, [parameter.state === 'absent' ? fail('parameter-missing', `${want.name} does not exist: the broker admits nothing`) : unreadable(want.name, parameter)], [], REPLAN);
  const p = parameter.value;
  const findings = [];
  if (p.name !== want.name) findings.push(fail('parameter-location', `get-parameter returned ${p.name}, not ${want.name}`));
  if (p.arn !== arn) findings.push(fail('parameter-location', `the parameter ARN is ${p.arn ?? '(none)'}, not ${arn}`));
  if (p.type !== want.type) findings.push(fail('parameter-type', `Type is ${p.type}, not ${want.type} (the broker refuses anything else)`));
  if (p.dataType !== want.dataType) findings.push(fail('managed-drift', `DataType is ${p.dataType ?? '(none)'}, not ${want.dataType}`));
  if (metadata.state !== 'present') findings.push(unreadable(`the tier of ${want.name}`, metadata));
  else if (metadata.value.tier !== want.tier) findings.push(fail('managed-drift', `Tier is ${metadata.value.tier ?? '(none)'}, not ${want.tier}`));
  if (p.value !== want.value) {
    const live = parseFrameworkPolicy(p.value, environment);
    const revoked = live.state === 'valid' && live.shas.size === 0 && policy.allowedFrameworkShas.length > 0;
    findings.push(fail('value-drift', revoked ? 'the live value is the emergency revoke ("shas": []): it admits nothing, but it is not the reviewed configuration — re-plan once the revoke is resolved' : `the live value is not the reviewed configuration (live ${JSON.stringify(p.value)})`));
  }
  return done(c, findings, [`${p.name}: ${p.type}${metadata.state === 'present' ? `/${metadata.value.tier}` : ''}/${p.dataType}, version ${p.version ?? '?'}`, `value ${JSON.stringify(p.value)}`], REPLAN);
}

// The broker's own parser, on the LIVE value: what the broker will actually do.
export function governanceParserCheck({ environment, parameter }) {
  const c = check('bg.gov.parser', 'Parameter', 'Accepted by the broker', {
    why: 'a value the broker parses as malformed (or as another environment\'s) admits nothing; verify must see the same answer the broker will',
    expected: [`broker/identity/framework-policy.mjs parseFrameworkPolicy(value, '${environment}') = valid`]
  });
  if (parameter.state !== 'present') return done(c, [nv('prerequisite-missing', 'the parameter could not be read')]);
  if (parameter.value.type !== 'String') return done(c, [fail('parameter-type', `Type ${parameter.value.type}: the broker refuses anything but String`)]);
  const parsed = parseFrameworkPolicy(parameter.value.value, environment);
  if (parsed.state !== 'valid') return done(c, [fail('value-malformed', `the broker reads it as malformed: ${parsed.reason}`)], [], REPLAN);
  return done(c, [], [`${parsed.shas.size} commit(s) admitted in ${environment}`]);
}

export function governanceAdmissionCheck({ admission, live }) {
  const c = check('bg.gov.admission', 'Admission', 'Every admitted commit is admissible', {
    basis: 'framework-checkout',
    why: 'a commit without the workflow binding would let a caller-chosen toolkit file requests under it; production admits only merged commits',
    expected: ['each commit exists in the framework checkout', '_break-glass-lambda.yml binds itself (first step bind-framework-commit; every checkout at its output)', 'production: an ancestor of refs/remotes/origin/main']
  });
  if (!admission) return done(c, [nv('prerequisite-missing', live === null ? 'the live value could not be parsed, so its commits were not checked' : 'no framework checkout: run verify from a git checkout of the framework')]);
  return done(c, admission.findings, admission.observed.length > 0 ? admission.observed : ['no commit admitted'], ['Remove the commit from the policy, plan and apply.']);
}

export function otherWritersCheck({ environment }) {
  return done(
    check('bg.gov.other-writers', 'Access', 'No other principal can write it', {
      required: false,
      basis: 'not-enumerable',
      why: 'IAM cannot list every principal of an account that ssm:PutParameter would allow; only the execution roles are simulated',
      expected: [`only CloudFormation (the scoped deployer) and the bootstrap admin change /ssd/break-glass/${environment}/governance/allowed-framework-shas`]
    }),
    [nv('not-enumerable', 'which other principals could write this parameter cannot be enumerated from IAM; review the account\'s administrators and the deployer policy')]
  );
}

// -> { own: { ci, interactions }, other: { ci, interactions } } probe sets.
export function governanceProbes(environment, target) {
  const arn = breakGlassArns(environment, target).frameworkPolicyParameter;
  const other = otherEnvironment(environment);
  return {
    readers: [{ action: 'ssm:GetParameter', resource: arn, why: `this environment's broker checks the framework commit against it (Phase 3D)` }],
    writes: GOVERNANCE_WRITE_ACTIONS.map((action) => ({ action, resource: arn, severity: FAIL, why: 'only the governance stack changes the allowed commits' })),
    crossEnvironment: ['ssm:GetParameter', ...GOVERNANCE_WRITE_ACTIONS].map((action) => ({ action, resource: arn, severity: FAIL, why: `a ${other} role must never read or change ${environment}'s allowed commits` }))
  };
}

const absentRole = (simulation) => simulation?.state === 'unverified' && simulation.error.kind === 'not-found' && simulation.error.code === 'NoSuchEntity';

// --- orchestration --------------------------------------------------------------------

// awsVerifyBreakGlassGovernance(options) -> report. Throws AwsCliError /
// IdentityError for a run-ending failure.
//   operator / policy   the validated files        framework  detectFramework() (admission)
//   git                 injectable admission git (tests); defaults to frameworkGit(framework.root)
export async function awsVerifyBreakGlassGovernance({ operator, policy, environment, region: explicitRegion = null, exec, env = process.env, framework = null, git = null, deadlineMs, now }) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment) || policy?.environment !== environment) {
    throw Object.assign(new Error(`--environment must be production or synthetic and equal the policy's environment (got '${environment}', policy '${policy?.environment}')`), { kind: 'configuration' });
  }
  const account = operator.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: operator.aws.region });
  const target = { scope: 'break-glass-governance', environment, repository: null, account, region: resolved.region, regionSource: resolved.source, caller: null, awsProfile: env.AWS_PROFILE || null };
  const calls = [];
  const sections = GOVERNANCE_SECTIONS;
  const regionC = identityCheck(regionCheck(resolved));
  if (regionC.status === FAIL) {
    return report({ target, checks: [regionC], calls, sections, skipped: 'region mismatch: AWS was not contacted' });
  }
  const aws = governanceReadAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).join(' ')) });
  const caller = await callerIdentity(aws);
  target.caller = caller;
  const identity = [identityCheck(accountCheck(caller, account)), identityCheck(principalCheck(caller)), regionC];
  if (identity.some((c) => c.status === FAIL)) {
    return report({ target, checks: identity, calls, sections, skipped: 'identity check failed: no resource was read' });
  }
  const t = { partition: caller.partition, account, region: resolved.region };
  const stackName = BREAK_GLASS_GOVERNANCE_STACKS[environment];
  const name = governanceParameter(policy).name;

  const stack = await discoverStackByName(aws, stackName);
  const resources = stack.state === 'present' ? await discoverStackResources(aws, stackName) : stack;
  const parameter = await discoverParameter(aws, name);
  const metadata = await discoverParameterMetadata(aws, name);

  // Admission of the LIVE set: that is what the broker admits.
  const parsed = parameter.state === 'present' && parameter.value.type === 'String' ? parseFrameworkPolicy(parameter.value.value, environment) : null;
  const liveShas = parsed?.state === 'valid' ? [...parsed.shas] : null;
  const gitReader = git ?? (framework?.root ? frameworkGit(framework.root) : null);
  const admission = liveShas && gitReader ? await admissionFindings({ environment, shas: liveShas, git: gitReader }) : null;

  const probes = governanceProbes(environment, t);
  const access = [];
  for (const [env2, sets, label] of [
    [environment, ['readers', 'writes'], environment],
    [otherEnvironment(environment), ['crossEnvironment'], otherEnvironment(environment)]
  ]) {
    const arns = breakGlassArns(env2, t).roles;
    for (const role of ROLES) {
      const all = sets.flatMap((s) => probes[s]);
      const simulation = await simulateProbes(aws, arns[role], all);
      const section = 'Access';
      if (sets.includes('readers')) {
        access.push(requiredAccessCheck({ id: `bg.gov.${role}-reads`, section, title: `${label} ${role} role reads it`, why: probes.readers[0].why, simulation, probes: probes.readers, remediation: ['Apply the Phase 3D shared-stack update (`aws plan --scope break-glass`).'] }));
        access.push(deniedAccessCheck({ id: `bg.gov.${role}-never-writes`, section, title: `${label} ${role} role never writes it`, why: probes.writes[0].why, simulation, probes: probes.writes, remediation: ['Remove the grant that allows it.'] }));
      } else {
        const separated = deniedAccessCheck({ id: `bg.gov.${label}-${role}-separated`, section, title: `${label} ${role} role cannot reach it`, why: probes.crossEnvironment[0].why, simulation, probes: probes.crossEnvironment, remediation: ['Remove the cross-environment grant.'] });
        // A role that does not exist (the other environment is not deployed)
        // holds no access at all: IAM answers NoSuchEntity, and that answer —
        // only that one — proves the denial. Required reads never get this.
        access.push(absentRole(simulation) ? { ...separated, status: PASS, findings: [], observed: [`${arns[role]} does not exist: it holds no access`], remediation: [] } : separated);
      }
    }
  }

  const checks = [
    ...identity,
    governanceStackCheck({ environment, stack, resources }),
    governanceParameterCheck({ environment, target: t, policy, parameter, metadata }),
    governanceParserCheck({ environment, parameter }),
    governanceAdmissionCheck({ admission, live: liveShas }),
    ...access,
    otherWritersCheck({ environment })
  ];
  return report({ target, checks, calls, sections });
}
