// Recorded AWS and git behaviour for the Phase 3D governance tests. No test
// talks to AWS or reads another commit with real git.
//
//   greenfieldGovernance(env)        nothing exists yet (aws plan)
//   deployedGovernance(env, policy)  the stack as `aws apply` leaves it, and the
//                                    four execution roles as the Phase 3D shared
//                                    stacks grant them (aws verify)
//   fakeGit({ … })                   the admission git interface
//
// The IAM simulator is independent of onboarding/aws/policy/: it evaluates the
// documents the fake account HOLDS with its own glob matcher, so a test that
// changes a role's policy changes what simulate-principal-policy answers.
import { readFileSync } from 'node:fs';

import { ok, awsError } from './aws-fake.mjs';
import { changeSets, stackIdOf } from './aws-plan-fake.mjs';
import { ACCOUNT, REGION, TARGET, tagsFor } from './break-glass-fake.mjs';
import { validateFrameworkPolicyConfig } from '../../onboarding/aws/break-glass/framework-policy-config.mjs';
import { breakGlassArns, breakGlassNames } from '../../onboarding/aws/break-glass/names.mjs';
import { executionRolePolicy } from '../../onboarding/aws/policy/break-glass.mjs';
import { BREAK_GLASS_GOVERNANCE_STACKS } from '../../onboarding/aws/stack-names.mjs';
import { renderGovernanceTemplate } from '../../onboarding/aws/templates/break-glass-governance.mjs';

export { ACCOUNT, REGION, TARGET };

// Commits of the fake framework checkout.
export const MAIN = '1111111111111111111111111111111111111111';
export const MERGED_BOUND = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
export const CANDIDATE_BOUND = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
export const MERGED_UNBOUND = 'cccccccccccccccccccccccccccccccccccccccc';
export const MISSING = 'dddddddddddddddddddddddddddddddddddddddd';

// The binding workflow as committed (C2) and the pre-3D one it replaced.
export const BOUND_WORKFLOW = readFileSync(new URL('../../.github/workflows/_break-glass-lambda.yml', import.meta.url), 'utf8');
export const UNBOUND_WORKFLOW = BOUND_WORKFLOW.replace('ref: ${{ steps.bind-framework-commit.outputs.sha }}', 'ref: ${{ inputs.toolkit_ref }}').replace(/\n\s*id: bind-framework-commit\n/, '\n');

export function fakeGit({ commits = { [MERGED_BOUND]: BOUND_WORKFLOW, [CANDIDATE_BOUND]: BOUND_WORKFLOW, [MERGED_UNBOUND]: UNBOUND_WORKFLOW }, merged = [MERGED_BOUND, MERGED_UNBOUND], originMain = MAIN, unanswerable = [] } = {}) {
  const asked = [];
  return {
    asked,
    async isCommit(sha) {
      asked.push(['isCommit', sha]);
      return unanswerable.includes(sha) ? null : Object.hasOwn(commits, sha);
    },
    async resolve(ref) {
      asked.push(['resolve', ref]);
      return ref === 'refs/remotes/origin/main' ? originMain : null;
    },
    async isAncestor(sha, ref) {
      asked.push(['isAncestor', sha, ref]);
      return ref === 'refs/remotes/origin/main' && merged.includes(sha);
    },
    async show(sha, path) {
      asked.push(['show', sha, path]);
      return path === '.github/workflows/_break-glass-lambda.yml' ? (commits[sha] ?? null) : null;
    }
  };
}

export const rawPolicy = (environment = 'synthetic', shas = [CANDIDATE_BOUND, MERGED_BOUND], overrides = {}) => ({ schemaVersion: '1', kind: 'break-glass-framework-policy', environment, allowedFrameworkShas: shas, ...overrides });
export const policy = (environment, shas, overrides) => validateFrameworkPolicyConfig(rawPolicy(environment, shas, overrides), { environment });
export const policyYaml = (environment = 'synthetic', shas = [CANDIDATE_BOUND]) =>
  `schemaVersion: "1"\nkind: break-glass-framework-policy\nenvironment: ${environment}\nallowedFrameworkShas:${shas.length === 0 ? ' []' : shas.map((s) => `\n  - ${s}`).join('')}\n`;

const noStack = (name) => awsError('ValidationError', 'DescribeStacks', `Stack with id ${name} does not exist`);
const notInStack = (id) => awsError('ValidationError', 'DescribeStackResources', `Stack for ${id} does not exist`);
export const parameterNotFound = () => awsError('ParameterNotFound', 'GetParameter', '');
export const parameterArn = (environment) => breakGlassArns(environment, TARGET).frameworkPolicyParameter;
export const describeParametersKey = (environment) => `ssm describe-parameters --parameter-filters ${JSON.stringify([{ Key: 'Name', Option: 'Equals', Values: [breakGlassNames(environment).frameworkPolicyParameter] }])}`;

export function greenfieldGovernance(environment = 'synthetic') {
  const n = breakGlassNames(environment);
  const world = { 'sts get-caller-identity': ok({ Account: ACCOUNT, Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`, UserId: 'AROAEXAMPLEEXAMPLE01:alice' }) };
  world[`cloudformation describe-stacks --stack-name ${BREAK_GLASS_GOVERNANCE_STACKS[environment]}`] = noStack(BREAK_GLASS_GOVERNANCE_STACKS[environment]);
  world[`ssm get-parameter --name ${n.frameworkPolicyParameter}`] = parameterNotFound();
  return changeSets(world);
}

// A parameter of that name exists, owned by `stackName` (or by no stack).
export function existingParameter(world, environment, { stackName = null, logicalId = 'AllowedFrameworkShas', value = '{}' } = {}) {
  const name = breakGlassNames(environment).frameworkPolicyParameter;
  world[`ssm get-parameter --name ${name}`] = ok({ Parameter: { Name: name, Type: 'String', Value: value, Version: 3, ARN: parameterArn(environment), DataType: 'text' } });
  world[`cloudformation describe-stack-resources --physical-resource-id ${name}`] = stackName
    ? ok({ StackResources: [{ StackName: stackName, StackId: stackIdOf(stackName), LogicalResourceId: logicalId, PhysicalResourceId: name, ResourceType: 'AWS::SSM::Parameter', ResourceStatus: 'CREATE_COMPLETE' }] })
    : notInStack(name);
  if (stackName) {
    world[`cloudformation describe-stacks --stack-name ${stackIdOf(stackName)}`] = ok({ Stacks: [{ StackName: stackName, StackId: stackIdOf(stackName), StackStatus: 'CREATE_COMPLETE', Tags: tagsFor(stackName.includes('production') ? 'production' : 'synthetic') }] });
  }
  return world;
}

// --- an independent IAM simulator -------------------------------------------------

const glob = (pattern, flags) => new RegExp(`^${String(pattern).split('').map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[\\^$.|+()[\]{}]/g, '\\$&'))).join('')}$`, flags);
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
function decide(doc, action, resource) {
  let allowed = false;
  for (const s of list(doc?.Statement)) {
    if (list(s.Action).some((p) => glob(p, 'i').test(action)) && list(s.Resource).some((p) => glob(p, '').test(resource))) {
      if (s.Effect === 'Deny') return 'explicitDeny';
      if (s.Effect === 'Allow') allowed = true;
    }
  }
  return allowed ? 'allowed' : 'implicitDeny';
}
const flag = (argv, name) => argv[argv.indexOf(name) + 1];

// The deployed governance stack of `environment`, holding the value rendered
// from `deployedPolicy`; the four execution roles hold the Phase 3D documents.
export function deployedGovernance(environment = 'synthetic', deployedPolicy = policy(environment)) {
  const name = breakGlassNames(environment).frameworkPolicyParameter;
  const stackName = BREAK_GLASS_GOVERNANCE_STACKS[environment];
  const stackId = stackIdOf(stackName);
  const world = { 'sts get-caller-identity': ok({ Account: ACCOUNT, Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`, UserId: 'AROAEXAMPLEEXAMPLE01:alice' }) };
  world.__stack = { StackName: stackName, StackId: stackId, StackStatus: 'CREATE_COMPLETE', Tags: tagsFor(environment), LastUpdatedTime: '2026-10-07T10:00:00.000Z' };
  world[`cloudformation describe-stacks --stack-name ${stackName}`] = () => ok({ Stacks: [world.__stack] });
  world.__resources = [{ StackName: stackName, StackId: stackId, LogicalResourceId: 'AllowedFrameworkShas', PhysicalResourceId: name, ResourceType: 'AWS::SSM::Parameter', ResourceStatus: 'CREATE_COMPLETE' }];
  world[`cloudformation describe-stack-resources --stack-name ${stackName}`] = () => ok({ StackResources: world.__resources });
  const { parameter } = renderGovernanceTemplate({ policy: deployedPolicy, environment });
  world.__parameter = { Name: name, Type: 'String', Value: parameter.value, Version: 1, ARN: parameterArn(environment), DataType: 'text', LastModifiedDate: '2026-10-07T10:00:00.000Z' };
  world[`ssm get-parameter --name ${name}`] = () => (world.__parameter ? ok({ Parameter: world.__parameter }) : parameterNotFound());
  world.__tier = 'Standard';
  world[describeParametersKey(environment)] = () => ok({ Parameters: world.__parameter ? [{ Name: name, Type: world.__parameter.Type, Tier: world.__tier, DataType: world.__parameter.DataType, Version: 1 }] : [] });
  world.__roles = {};
  for (const env2 of ['production', 'synthetic']) {
    const a = breakGlassArns(env2, TARGET);
    for (const role of ['ci', 'interactions']) world.__roles[a.roles[role]] = executionRolePolicy(role, env2, TARGET);
  }
  world['iam simulate-principal-policy *'] = (argv) => {
    const arn = flag(argv, '--policy-source-arn');
    if (world.__absentRoles?.includes(arn)) return awsError('NoSuchEntity', 'SimulatePrincipalPolicy', `The role with name ${arn.split('/').pop()} cannot be found.`);
    const doc = world.__roles[arn];
    const actions = JSON.parse(flag(argv, '--action-names'));
    const [resource] = JSON.parse(flag(argv, '--resource-arns'));
    return ok({ IsTruncated: false, EvaluationResults: actions.map((action) => ({ EvalActionName: action, EvalResourceName: resource, EvalDecision: doc ? decide(doc, action, resource) : 'implicitDeny', MissingContextValues: [] })) });
  };
  return world;
}
