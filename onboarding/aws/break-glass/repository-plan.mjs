// `ssd-onboard aws plan --scope break-glass-repo --environment <env>` (Phase 3D):
// one UNEXECUTED change set for ssd-break-glass-<env>-repo-<repository_id>,
// holding that repository's invoker role and approver parameter.
//
// Order is part of the contract; each step blocks before the next:
//   1. the repository is configured for --environment;
//   2. the framework checkout is bound to the operator config's framework.ref;
//   3. GITHUB, before AWS (read-only, injected): `repos/<slug>` must return this
//      repository_id and a full_name equal to the slug ignoring case, and
//      `…/actions/oidc/customization/sub` must report the DEFAULT subject. The
//      id is what approvers are keyed on: anything short of proof blocks
//      (gh unavailable included). A customized subject blocks: this version
//      never builds one;
//   4. region; 5. sts get-caller-identity: the configured account, never root;
//   6. the account's GitHub OIDC provider exists with client id
//      sts.amazonaws.com (read only; never created here);
//   7. the environment's shared stack is settled and tagged for it;
//   8. the stack: absent, a placeholder, or a settled stack tagged for this
//      environment;
//   9. the role and the parameter: absent, or exactly this stack's own. A
//      resource that merely has the name is never adopted;
//  10. render (subject from GitHub's full_name); trust/permission diffs;
//      recordPlans().
import { repositoryPlanningAws } from '../aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from '../identity.mjs';
import { discoverOidcProvider } from '../discover/oidc-provider.mjs';
import { discoverRole } from '../discover/iam-role.mjs';
import { describeError } from '../discover/result.mjs';
import { LIVE, discoverStackByName, stackTagProblems } from '../discover/stacks.mjs';
import { PlanError, evaluateResource, iamRecord, recordPlans, report, stackState } from '../plan.mjs';
import { INVOKER_POLICY_NAME, defaultSubject } from '../policy/break-glass-invoker.mjs';
import { STS_AUDIENCE } from '../policy/trust.mjs';
import { BREAK_GLASS_ENVIRONMENTS, breakGlassRepoStackKind } from '../stack-names.mjs';
import { canonicalJson, sha256, ssdTags } from '../templates/common.mjs';
import { REPOSITORY_LOGICAL_IDS as L, renderRepositoryTemplate } from '../templates/break-glass-repository.mjs';
import { frameworkProblems } from '../../lib/framework.mjs';
import { discoverParameter } from './discover.mjs';
import { breakGlassNames, invokerArns, invokerNames } from './names.mjs';
import { operatorDigestOf } from './operator-config.mjs';
import { repositoryDigestOf } from './repository-config.mjs';

const FAIL = 'FAIL';
const WARN = 'WARN';
const finding = (severity, kind, message) => ({ severity, kind, message });

// What a repository plan binds: the operator config AND the repository file.
export const repositoryPlanDigestOf = (operator, config) => sha256(canonicalJson({ operator: operatorDigestOf(operator), repository: repositoryDigestOf(config) }));

const ghError = (r) => `${r.state === 'absent' ? 'not found, or this gh login cannot see it' : `${r.error?.kind ?? 'error'}${r.error?.status ? ` HTTP ${r.error.status}` : ''}: ${r.error?.message ?? ''}`}`;

// GitHub's answers -> { findings[], fullName | null }. Shared with verify.
export function githubIdentityFindings(config, identity) {
  const findings = [];
  const { slug, id } = config.repository;
  const repo = identity?.repository;
  if (repo?.state !== 'present') {
    findings.push(finding(FAIL, 'repository-unverified', `GitHub repository ${slug} could not be read (${repo ? ghError(repo) : 'no GitHub lookup available'}): its repository_id is never taken on trust`));
    return { findings, fullName: null };
  }
  if (repo.value.id !== id) findings.push(finding(FAIL, 'repository-id-mismatch', `GitHub reports ${slug} as repository_id ${repo.value.id}, not the configured ${id}`));
  if (repo.value.fullName.toLowerCase() !== slug.toLowerCase()) findings.push(finding(FAIL, 'repository-slug-mismatch', `repository_id ${repo.value.id} is ${repo.value.fullName} on GitHub, not ${slug}`));
  else if (repo.value.fullName !== slug) findings.push(finding(WARN, 'slug-case', `GitHub spells the repository ${repo.value.fullName}; the OIDC subject uses that spelling (IAM compares it case-sensitively)`));
  const oidc = identity.oidc;
  if (oidc?.state !== 'present') findings.push(finding(FAIL, 'oidc-subject-unverified', `the OIDC subject customization of ${slug} could not be read (${oidc ? ghError(oidc) : 'no lookup'}): the subject GitHub emits is unknown`));
  else if (oidc.value.useDefault !== true) {
    findings.push(finding(FAIL, 'oidc-subject-customized', `${slug} customizes its OIDC subject (claims ${oidc.value.includeClaimKeys.join(', ') || 'none'}): this version plans only GitHub's default subject repo:<owner>/<repo>:pull_request and never constructs a custom one`));
  }
  return { findings, fullName: findings.some((f) => f.severity === FAIL) ? null : repo.value.fullName };
}

//   operator / repository   the validated files      github  async (slug) -> discoverRepositoryIdentity() result
export async function awsPlanBreakGlassRepository({ operator, repository: config, environment, github, region: explicitRegion = null, exec, env = process.env, framework, root, deadlineMs, now, sleep }) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {
    throw new PlanError('unsupported-environment', `--environment must be production or synthetic (got '${environment}')`);
  }
  if (!Object.hasOwn(config.environments, environment)) {
    throw new PlanError('environment-not-configured', `${config.repository.slug} is not configured for '${environment}' (environments.${environment} is absent)`);
  }
  const scope = 'break-glass';
  const account = operator.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: operator.aws.region });
  const calls = [];
  const base = {
    scope,
    target: { repository: config.repository.slug, repositoryId: config.repository.id, environment, account, region: resolved.region, regionSource: resolved.source, caller: null },
    framework: { repository: operator.framework.repository, ref: operator.framework.ref },
    calls
  };

  const bindingProblems = frameworkProblems(framework, operator);
  if (bindingProblems.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: bindingProblems.map((m) => finding(FAIL, 'framework-binding', m)), skipped: 'the framework checkout is not bound to framework.ref: GitHub and AWS were not contacted' });
  }
  const identity = typeof github === 'function' ? await github(config.repository.slug) : null;
  const gh = githubIdentityFindings(config, identity);
  if (gh.fullName === null) {
    return report(base, { outcome: 'BLOCKED', findings: gh.findings, skipped: 'the repository identity was not proven by GitHub: AWS was not contacted' });
  }
  const regionC = regionCheck(resolved);
  if (regionC.status === FAIL) {
    return report(base, { outcome: 'BLOCKED', findings: regionC.findings.map((f) => finding(FAIL, f.kind, f.message)), skipped: 'region mismatch: AWS was not contacted' });
  }

  const aws = repositoryPlanningAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).filter((_, i, all) => all[i - 1] !== '--template-body').join(' ')) });
  const caller = await callerIdentity(aws);
  base.target.caller = { arn: caller.arn, account: caller.account, kind: caller.kind };
  const callerChecks = [accountCheck(caller, account), principalCheck(caller)].filter((c) => c.status === FAIL);
  if (callerChecks.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: callerChecks.flatMap((c) => c.findings.map((f) => finding(FAIL, f.kind, f.message))), skipped: 'identity check failed: nothing was read and no change set was created' });
  }
  const ctx = { aws, operator, environment, slug: null, account, region: resolved.region, partition: caller.partition };
  const target = { partition: caller.partition, account, region: resolved.region };
  const id = config.repository.id;
  const n = invokerNames(environment, id);
  const a = invokerArns(environment, id, target);
  const unit = { stackKind: breakGlassRepoStackKind(environment), scope, stackName: n.stack, label: `Break-glass repository stack (${config.repository.slug}, ${environment})`, mode: 'planned', findings: [...gh.findings], checks: [], resources: [], iam: [], template: null, policies: {}, residual: [] };
  const subject = defaultSubject(gh.fullName);
  unit.checks.push({ id: 'repository-identity', title: 'Repository identity proven by GitHub', observed: [`repository_id ${id} = ${gh.fullName}`, `OIDC subject: GitHub default -> ${subject}`], findings: [] });
  unit.record = { repositoryIdentity: { repositoryId: id, fullName: gh.fullName, subject, oidcSubject: 'default' } };

  // The account's GitHub OIDC provider: read only, never created here.
  const provider = await discoverOidcProvider(aws, { account });
  if (provider.state !== 'present') {
    unit.findings.push(finding(FAIL, 'oidc-provider-missing', provider.state === 'absent' ? 'the account has no GitHub OIDC provider (token.actions.githubusercontent.com); this plan never creates it' : `the GitHub OIDC provider could not be read (${describeError(provider)})`));
  } else if (provider.value.account !== account || !provider.value.clientIds.includes(STS_AUDIENCE)) {
    unit.findings.push(finding(FAIL, 'oidc-provider-mismatch', `the GitHub OIDC provider ${provider.value.arn} is not in ${account} with client id ${STS_AUDIENCE} (client ids: ${provider.value.clientIds.join(', ') || 'none'})`));
  }

  // The environment's shared stack must be settled and ours.
  const sharedName = breakGlassNames(environment).stack;
  const shared = await discoverStackByName(aws, sharedName);
  if (shared.state !== 'present') {
    unit.findings.push(finding(FAIL, 'shared-stack-not-ready', shared.state === 'absent' ? `the shared stack ${sharedName} does not exist: plan and apply it first` : `the shared stack ${sharedName} could not be read (${describeError(shared)})`));
  } else {
    const problems = [...(LIVE.has(shared.value.status) ? [] : [`it is ${shared.value.status}`]), ...stackTagProblems(shared.value.tags, { scope, slug: null, environment })];
    if (shared.value.name !== sharedName) problems.push(`describe-stacks returned '${shared.value.name}'`);
    if (problems.length > 0) unit.findings.push(finding(FAIL, 'shared-stack-not-ready', `the shared stack ${sharedName} is not a settled ssd-onboard stack for ${environment}: ${problems.join('; ')}`));
  }

  const stackResources = await stackState(ctx, unit, { stackName: n.stack, scope });
  const inStack = (logicalId) => stackResources.some((r) => r.logicalId === logicalId);

  const role = await discoverRole(aws, a.role);
  if (role.state === 'present' && role.value.arn !== a.role) {
    unit.findings.push(finding(FAIL, 'role-name-collision', `a role named like ${n.role} exists as ${role.value.arn ?? '(no ARN)'}, not ${a.role} (IAM role names are case-insensitive)`));
  } else {
    const evaluated = await evaluateResource(ctx, { label: 'Invoker role', logicalId: L.role, mode: 'managed', discovered: role, physicalId: role.state === 'present' ? role.value.name : n.role, type: 'AWS::IAM::Role', tags: role.state === 'present' ? role.value.tags : null, stackName: n.stack, scope, inStack: inStack(L.role) });
    unit.resources.push({ ...evaluated, discovered: role, key: 'invoker', arn: a.role });
    unit.findings.push(...evaluated.findings);
  }
  const parameter = await discoverParameter(aws, n.approverParameter);
  const evaluatedParameter = await evaluateResource(ctx, { label: 'Approver parameter', logicalId: L.approvers, mode: 'managed', discovered: parameter, physicalId: n.approverParameter, type: 'AWS::SSM::Parameter', tags: null, stackName: n.stack, scope, inStack: inStack(L.approvers) });
  unit.resources.push({ ...evaluatedParameter, discovered: parameter });
  unit.findings.push(...evaluatedParameter.findings);

  if (config.environments[environment].approvers.length === 0) {
    unit.findings.push(finding(WARN, 'no-approvers', `approvers is [] for ${environment}: enabled but not operationally ready — nobody can approve a request of this repository`));
  }
  unit.residual.push(
    'Retain: deleting this stack revokes nothing. To offboard, plan `approvers: []` and apply first.',
    `Any pull_request job of ${gh.fullName} can assume ${n.role}; its one permission is invoking ${breakGlassNames(environment).functions.ci}, and the broker refuses every token not from _break-glass-lambda.yml at an admitted commit.`
  );
  if (unit.findings.some((f) => f.severity === FAIL)) {
    return report(base, { outcome: 'BLOCKED', units: [unit], skipped: 'a precondition failed: no change set was created' });
  }
  const rendered = renderRepositoryTemplate({ config, environment, fullName: gh.fullName, ...target });
  unit.template = rendered.template;
  const generated = rendered.policies[L.role];
  const resource = unit.resources.find((r) => r.logicalId === L.role) ?? { owned: false };
  const record = await iamRecord(ctx, { key: 'invoker', arn: generated.arn, logicalId: L.role, generated, resource, stackName: n.stack, policyName: INVOKER_POLICY_NAME });
  unit.iam.push(record);
  unit.findings.push(...record.findings);
  if (unit.findings.some((f) => f.severity === FAIL)) {
    return report(base, { outcome: 'BLOCKED', units: [unit], skipped: 'a precondition failed: no change set was created' });
  }
  return recordPlans({ units: [unit], base, scope, tags: ssdTags({ scope, environment }), aws, account, region: resolved.region, caller, root, env, sleep, repository: null, configDigest: repositoryPlanDigestOf(operator, config) });
}
