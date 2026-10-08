// The LOCAL half of `aws apply`: is this recorded plan internally consistent,
// and is it the plan the operator, the configuration and this framework
// checkout say should be applied? Pure — no AWS, no file access (the texts
// come from plan/record.mjs readPlan(), already hash-verified).
//
// plan.json carries copies of what its planIdInput binds, plus fields the plan
// id does not bind (changeSetArn, changes, counts, destructive). Nothing here
// trusts a copy: every bound copy must equal planIdInput, and every unbound
// field must be re-derivable from a hash-verified file — change-set.json is the
// described change set exactly as `aws plan` saw it.
import { assertDescribedMatches, classifyChanges, countChanges } from '../plan/change-set.mjs';
import { assertChangeScope, assertTemplateScope } from '../plan/scope.mjs';
import { changeSetNameOf, configDigestOf } from '../plan/record.mjs';
import { LIVE } from '../discover/stacks.mjs';
import { BREAK_GLASS_GOVERNANCE_STACKS, BREAK_GLASS_STACKS, SHARED_STACKS, breakGlassEnvironmentOf, breakGlassKindOf, breakGlassRepoStackName, canonicalSlug, repoStackName, repositoryIdOfStack } from '../stack-names.mjs';
import { operatorDigestOf } from '../break-glass/operator-config.mjs';
import { governanceDigestOf } from '../break-glass/governance-plan.mjs';
import { repositoryPlanDigestOf } from '../break-glass/repository-plan.mjs';
import { canonicalJson, ssdTags } from '../templates/common.mjs';
import { frameworkProblems } from '../../lib/framework.mjs';

const CHANGE_SET_ARN = /^arn:(aws|aws-cn|aws-us-gov):cloudformation:([a-z0-9-]+):(\d{12}):changeSet\/(ssd-plan-[0-9a-f]{64})\/[0-9a-f-]+$/;
const STACK_ID = /^arn:(aws|aws-cn|aws-us-gov):cloudformation:([a-z0-9-]+):(\d{12}):stack\/([A-Za-z][A-Za-z0-9-]*)\/[0-9a-f-]+$/;
const BOUND = ['account', 'region', 'scope', 'stackKind', 'stackName', 'changeSetType', 'baseStack', 'templateSha256', 'parametersSha256', 'capabilities', 'framework', 'repository'];

const same = (a, b) => canonicalJson(a ?? null) === canonicalJson(b ?? null);
const finding = (kind, message) => ({ kind, message });

// The stack a plan of this kind must name, derived from the CURRENT config.
export function expectedStackName(stackKind, slug) {
  if (stackKind === 'repo') return repoStackName(slug);
  if (stackKind === 'shared-github-oidc') return SHARED_STACKS.githubOidc;
  const kind = breakGlassKindOf(stackKind);
  if (kind?.family === 'shared') return BREAK_GLASS_STACKS[kind.environment];
  if (kind?.family === 'governance') return BREAK_GLASS_GOVERNANCE_STACKS[kind.environment];
  return null;
}

// A break-glass plan's scope, stack kind, stack name and repository must agree
// with each other: the environment comes from the stack kind, and the stack
// name and tags must be that environment's. -> environment | null
export const planEnvironment = (input) => (input.scope === 'break-glass' ? breakGlassEnvironmentOf(input.stackKind) : null);

function parse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// -> { findings[], record | null }. record (only when findings is empty):
//   { plan, operation, templateText, changeSet, changes, counts, destructive,
//     binding: { stackName, stackId, changeSetArn } }
export function checkPlanRecord({ plan, texts }) {
  const findings = [];
  const input = plan.planIdInput;
  for (const key of BOUND) {
    if (!same(plan[key], input[key])) {
      findings.push(finding('plan-inconsistent', `plan.json ${key} differs from the ${key} its plan id binds`));
    }
  }
  if (plan.changeSetName !== changeSetNameOf(plan.planId)) {
    findings.push(finding('plan-inconsistent', `plan.json changeSetName is not ${changeSetNameOf(plan.planId)}`));
  }
  const arn = CHANGE_SET_ARN.exec(String(plan.changeSetArn ?? ''));
  if (!arn || arn[2] !== input.region || arn[3] !== input.account || arn[4] !== plan.changeSetName) {
    findings.push(finding('plan-inconsistent', 'plan.json changeSetArn is not a change set of this plan, account and region'));
  }
  if (!['CREATE', 'UPDATE'].includes(input.changeSetType)) {
    findings.push(finding('plan-inconsistent', `change-set type ${input.changeSetType} is not one apply executes`));
  }
  const base = input.baseStack;
  if (input.changeSetType === 'UPDATE' && !(base?.state === 'present' && LIVE.has(base.stackStatus))) {
    findings.push(finding('plan-inconsistent', 'an UPDATE plan must be bound to a settled, successful base stack'));
  }
  if (input.changeSetType === 'CREATE' && !(base?.state === 'absent' || (base?.state === 'present' && base.stackStatus === 'REVIEW_IN_PROGRESS'))) {
    findings.push(finding('plan-inconsistent', 'a CREATE plan must be bound to an absent stack or a REVIEW_IN_PROGRESS placeholder'));
  }
  const environment = planEnvironment(input);
  if (input.scope === 'break-glass') {
    // A repository stack's name is derived from its repository_id, which the
    // record alone cannot supply: it must at least be exactly such a name.
    const kind = breakGlassKindOf(input.stackKind);
    const named = kind?.family === 'repo' ? repositoryIdOfStack(environment, input.stackName) !== null : input.stackName === expectedStackName(input.stackKind, null);
    if (!environment || !named || input.repository !== null) {
      findings.push(finding('plan-inconsistent', 'a break-glass plan must name a break-glass stack kind, that environment\'s stack, and no consumer repository'));
    }
  } else if (breakGlassEnvironmentOf(input.stackKind)) {
    findings.push(finding('plan-inconsistent', `stack kind ${input.stackKind} belongs to the break-glass scope, not ${input.scope}`));
  }
  let expectedTags = null;
  try {
    expectedTags = ssdTags({ scope: input.scope, slug: input.repository, environment });
  } catch {
    expectedTags = null;
  }
  if (!expectedTags || !same(plan.tags, expectedTags)) {
    findings.push(finding('plan-inconsistent', `plan.json tags are not the SSD ownership tags of this scope and ${input.scope === 'break-glass' ? 'environment' : 'repository'}`));
  }

  const template = parse(texts['template.json']);
  const parameters = parse(texts['parameters.json']);
  const changeSet = parse(texts['change-set.json']);
  if (!template || typeof template !== 'object') {
    findings.push(finding('plan-inconsistent', 'template.json is not a JSON template'));
  } else if (texts['template.json'] !== canonicalJson(template)) {
    findings.push(finding('plan-inconsistent', 'template.json is not in the canonical form aws plan writes'));
  } else {
    try {
      assertTemplateScope(input.stackKind, template);
    } catch (error) {
      findings.push(finding('scope-violation', error.message));
    }
  }
  if (!Array.isArray(parameters) || parameters.length !== 0) {
    findings.push(finding('plan-inconsistent', 'parameters.json must be an empty list (generated templates take no parameters)'));
  }
  if (!changeSet || typeof changeSet !== 'object') {
    findings.push(finding('plan-inconsistent', 'change-set.json is not a describe-change-set document'));
    return { findings, record: null };
  }

  // The recorded description must be the reviewed, executable change set.
  if (changeSet.Status !== 'CREATE_COMPLETE' || changeSet.ExecutionStatus !== 'AVAILABLE') {
    findings.push(finding('plan-inconsistent', `change-set.json records ${changeSet.Status}/${changeSet.ExecutionStatus}, not CREATE_COMPLETE/AVAILABLE`));
  }
  try {
    assertDescribedMatches(changeSet, { stackName: input.stackName, changeSetName: plan.changeSetName, changeSetArn: plan.changeSetArn, tags: plan.tags, capabilities: input.capabilities });
  } catch (error) {
    findings.push(finding('plan-inconsistent', `change-set.json: ${error.message}`));
  }
  const stackId = STACK_ID.exec(String(changeSet.StackId ?? ''));
  if (!stackId || stackId[2] !== input.region || stackId[3] !== input.account || stackId[4] !== input.stackName) {
    findings.push(finding('plan-inconsistent', 'change-set.json StackId is not a stack of this plan, account and region'));
  } else if (base?.state === 'present' && base.stackId !== changeSet.StackId) {
    findings.push(finding('plan-inconsistent', 'change-set.json StackId is not the base stack the plan id binds'));
  }

  let classified = null;
  try {
    classified = classifyChanges(Array.isArray(changeSet.Changes) ? changeSet.Changes : []);
    assertChangeScope(input.stackKind, classified);
  } catch (error) {
    findings.push(finding('plan-inconsistent', `change-set.json: ${error.message}`));
    classified = null;
  }
  if (classified) {
    const { counts, destructive } = countChanges(classified);
    if (classified.length === 0) {
      findings.push(finding('plan-inconsistent', 'change-set.json lists no changes'));
    }
    if (!same(plan.changes, classified) || !same(plan.counts, counts) || plan.destructive !== destructive) {
      findings.push(finding('plan-inconsistent', "plan.json changes / counts / destructive count differ from the recorded change set's"));
    }
    if (findings.length === 0) {
      return {
        findings,
        record: {
          plan,
          operation: input.changeSetType,
          templateText: texts['template.json'],
          changeSet,
          changes: classified,
          counts,
          destructive,
          binding: { stackName: input.stackName, stackId: changeSet.StackId, changeSetArn: plan.changeSetArn }
        }
      };
    }
  }
  return { findings, record: null };
}

// Is this the plan the operator, the configuration and this framework checkout
// say should be applied? -> findings[]
//   account / region: --account == plan == delivery.aws.accountId (and region);
//   repository and stack: the plan's consumer repository and stack name are the
//     ones the current configuration derives;
//   configuration: unchanged since the plan (createdFromConfigDigest);
//   framework: the `aws plan` binding rule, and the plan was made at this ref.
//
// A break-glass plan is checked against the OPERATOR configuration instead
// (operator: break-glass/operator-config.mjs): aws.accountId / aws.region,
// the environment's stack, the operator config digest and its framework.ref.
// Each kind of plan needs its own kind of configuration: a break-glass plan
// is never applied against .ssd/onboarding.yml, nor a delivery plan against
// an operator config.
export function checkIntent({ plan, config = null, operator = null, policy = null, repository = null, framework, account, region }) {
  if (plan.scope === 'break-glass' || operator || policy || repository) {
    return checkOperatorIntent({ plan, operator, policy, repository, framework, account, region });
  }
  if (!config) {
    return [finding('config-kind-mismatch', `a ${plan.scope} plan is applied against .ssd/onboarding.yml, which was not loaded`)];
  }
  const findings = [];
  const d = config.delivery;
  if (account !== plan.account || account !== d.aws.accountId) {
    findings.push(finding('account-mismatch', `--account ${account}, plan account ${plan.account} and delivery.aws.accountId ${d.aws.accountId} must all be equal`));
  }
  if (region !== plan.region || region !== d.aws.region) {
    findings.push(finding('region-mismatch', `--region ${region}, plan region ${plan.region} and delivery.aws.region ${d.aws.region} must all be equal`));
  }
  if (plan.repository !== canonicalSlug(config.repository.slug)) {
    findings.push(finding('repository-mismatch', `the plan is for ${plan.repository}, not ${canonicalSlug(config.repository.slug)}`));
  }
  if (plan.stackName !== expectedStackName(plan.stackKind, config.repository.slug)) {
    findings.push(finding('stack-mismatch', `the plan names stack ${plan.stackName}, not the ${plan.stackKind} stack this configuration derives`));
  }
  if (plan.createdFromConfigDigest !== configDigestOf(config)) {
    findings.push(finding('config-changed', '.ssd/onboarding.yml changed since this plan was created: re-plan against the current configuration'));
  }
  for (const problem of frameworkProblems(framework, config)) {
    findings.push(finding('framework-binding', problem));
  }
  if (!same(plan.framework, { repository: config.framework.repository, ref: config.framework.ref })) {
    findings.push(finding('framework-binding', `the plan was created by ${plan.framework?.repository}@${plan.framework?.ref}, not framework.ref ${config.framework.repository}@${config.framework.ref}`));
  }
  return findings;
}

// The configuration a break-glass plan of each family is bound to, and which
// extra file it needs: shared = the operator config alone; governance = the
// operator config + --policy-config; repo = the operator config +
// --repository-config. A file of the wrong kind refuses.
function checkOperatorIntent({ plan, operator, policy, repository, framework, account, region }) {
  if (plan.scope !== 'break-glass') {
    return [finding('config-kind-mismatch', `this is a ${plan.scope} plan; --operator-config applies only to break-glass plans (apply it from the consumer repository, without --operator-config)`)];
  }
  if (!operator) {
    return [finding('config-kind-mismatch', 'this is a break-glass plan: apply it with --operator-config <the file it was planned from>')];
  }
  const kind = breakGlassKindOf(plan.stackKind);
  if (kind?.family === 'governance' && !policy) {
    return [finding('config-kind-mismatch', 'this is a break-glass governance plan: apply it with --operator-config and --policy-config <the files it was planned from>')];
  }
  if (kind?.family !== 'governance' && policy) {
    return [finding('config-kind-mismatch', `--policy-config applies only to break-glass governance plans, not ${plan.stackKind}`)];
  }
  if (kind?.family === 'repo' && !repository) {
    return [finding('config-kind-mismatch', 'this is a break-glass repository plan: apply it with --operator-config and --repository-config <the files it was planned from>')];
  }
  if (kind?.family !== 'repo' && repository) {
    return [finding('config-kind-mismatch', `--repository-config applies only to break-glass repository plans, not ${plan.stackKind}`)];
  }
  const findings = [];
  if (account !== plan.account || account !== operator.aws.accountId) {
    findings.push(finding('account-mismatch', `--account ${account}, plan account ${plan.account} and aws.accountId ${operator.aws.accountId} must all be equal`));
  }
  if (region !== plan.region || region !== operator.aws.region) {
    findings.push(finding('region-mismatch', `--region ${region}, plan region ${plan.region} and aws.region ${operator.aws.region} must all be equal`));
  }
  const environment = breakGlassEnvironmentOf(plan.stackKind);
  const expected = kind?.family === 'repo' ? (environment ? breakGlassRepoStackName(environment, repository.repository.id) : null) : expectedStackName(plan.stackKind, null);
  if (!environment || plan.stackName !== expected) {
    findings.push(finding('stack-mismatch', `the plan names stack ${plan.stackName}, not the ${plan.stackKind} stack${kind?.family === 'repo' ? ` of repository_id ${repository.repository.id}` : ''}`));
  }
  if (kind?.family === 'repo') {
    if (environment && !Object.hasOwn(repository.environments, environment)) {
      findings.push(finding('environment-mismatch', `--repository-config does not configure '${environment}'`));
    }
    if (plan.createdFromConfigDigest !== repositoryPlanDigestOf(operator, repository)) {
      findings.push(finding('config-changed', 'the operator configuration or the repository configuration changed since this plan was created: re-plan against the current files'));
    }
  } else if (kind?.family === 'governance') {
    if (policy.environment !== environment) {
      findings.push(finding('environment-mismatch', `--policy-config is for '${policy.environment}', but the plan is for '${environment}'`));
    }
    if (plan.createdFromConfigDigest !== governanceDigestOf(operator, policy)) {
      findings.push(finding('config-changed', 'the operator configuration or the framework policy changed since this plan was created: re-plan against the current files'));
    }
  } else if (plan.createdFromConfigDigest !== operatorDigestOf(operator)) {
    findings.push(finding('config-changed', 'the operator configuration changed since this plan was created: re-plan against the current file'));
  }
  for (const problem of frameworkProblems(framework, operator)) {
    findings.push(finding('framework-binding', problem));
  }
  if (!same(plan.framework, { repository: operator.framework.repository, ref: operator.framework.ref })) {
    findings.push(finding('framework-binding', `the plan was created by ${plan.framework?.repository}@${plan.framework?.ref}, not framework.ref ${operator.framework.repository}@${operator.framework.ref}`));
  }
  return findings;
}

// --allow-destructive <n> must state the exact destructive count; with no
// destructive change the flag may be omitted (or be 0). -> findings[]
export function checkDestructive(destructive, allowDestructive) {
  if (destructive === 0 && (allowDestructive === null || allowDestructive === 0)) {
    return [];
  }
  if (allowDestructive === null) {
    return [finding('destructive-unconfirmed', `the change set holds ${destructive} destructive change(s) (DELETE/REPLACE): pass --allow-destructive ${destructive} to apply it`)];
  }
  if (allowDestructive !== destructive) {
    return [finding('destructive-count-mismatch', `--allow-destructive ${allowDestructive} does not equal the change set's ${destructive} destructive change(s)`)];
  }
  return [];
}
