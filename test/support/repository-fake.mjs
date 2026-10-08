// Recorded AWS and GitHub behaviour for the Phase 3D repository-stack tests. No
// test talks to AWS or GitHub.
//
//   greenfieldRepository(env)          the shared stack and the OIDC provider exist;
//                                      nothing of the repository does (aws plan)
//   deployedRepository(env, config)    the stack as `aws apply` leaves it; the
//                                      four execution roles hold the Phase 3D
//                                      documents (aws verify)
//   github({ … })                      the injected repository identity lookup
//
// The IAM simulator is independent of onboarding/aws/policy/: it evaluates the
// documents the fake account HOLDS with its own matcher.
import { ok, awsError } from './aws-fake.mjs';
import { changeSets, stackIdOf } from './aws-plan-fake.mjs';
import { ACCOUNT, REGION, TARGET, tagsFor } from './break-glass-fake.mjs';
import { breakGlassArns, breakGlassNames, invokerArns, invokerNames } from '../../onboarding/aws/break-glass/names.mjs';
import { validateRepositoryConfig } from '../../onboarding/aws/break-glass/repository-config.mjs';
import { executionRolePolicy } from '../../onboarding/aws/policy/break-glass.mjs';
import { invokerPermissionPolicy, invokerTrustPolicy } from '../../onboarding/aws/policy/break-glass-invoker.mjs';

export { ACCOUNT, REGION, TARGET };
export const SLUG = 'Acme/Payments-API';
export const REPO_ID = '424242';
export const APPROVERS = Object.freeze(['U0APPROVER1', 'W0APPROVER2']);
export const PROVIDER = `arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com`;
export const SUBJECT = `repo:${SLUG}:pull_request`;

export const rawRepository = (overrides = {}) => ({
  schemaVersion: '1',
  kind: 'break-glass-repository',
  repository: { slug: SLUG, id: REPO_ID },
  environments: { synthetic: { approvers: [...APPROVERS] }, production: { approvers: [] } },
  ...overrides
});
export const repository = (overrides) => validateRepositoryConfig(rawRepository(overrides));
export const REPOSITORY_YAML = `schemaVersion: "1"
kind: break-glass-repository
repository:
  slug: ${SLUG}
  id: "${REPO_ID}"
environments:
  synthetic:
    approvers:
      - ${APPROVERS[0]}
      - ${APPROVERS[1]}
  production:
    approvers: []
`;

// The injected GitHub lookup (onboarding/github/repository-identity.mjs shape).
export function github({ id = REPO_ID, fullName = SLUG, useDefault = true, repository = null, oidc = null } = {}) {
  const calls = [];
  const fn = async (slug) => {
    calls.push(slug);
    return {
      repository: repository ?? { state: 'present', value: { id, fullName } },
      oidc: oidc ?? { state: 'present', value: { useDefault, includeClaimKeys: useDefault ? [] : ['repository_owner_id', 'repository_id'] } }
    };
  };
  fn.calls = calls;
  return fn;
}

const noStack = (name) => awsError('ValidationError', 'DescribeStacks', `Stack with id ${name} does not exist`);
const notInStack = (id) => awsError('ValidationError', 'DescribeStackResources', `Stack for ${id} does not exist`);
const caller = () => ok({ Account: ACCOUNT, Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`, UserId: 'AROAEXAMPLEEXAMPLE01:alice' });

export function oidcProvider(world, { clientIds = ['sts.amazonaws.com'], present = true } = {}) {
  world['iam list-open-id-connect-providers'] = ok({ OpenIDConnectProviderList: present ? [{ Arn: PROVIDER }] : [] });
  world[`iam get-open-id-connect-provider --open-id-connect-provider-arn ${PROVIDER}`] = ok({ Url: 'token.actions.githubusercontent.com', ClientIDList: clientIds, ThumbprintList: [], Tags: [] });
  return world;
}

export function sharedStack(world, environment, { status = 'CREATE_COMPLETE', tags = tagsFor(environment), present = true } = {}) {
  const name = breakGlassNames(environment).stack;
  world[`cloudformation describe-stacks --stack-name ${name}`] = present ? ok({ Stacks: [{ StackName: name, StackId: stackIdOf(name), StackStatus: status, Tags: tags }] }) : noStack(name);
  return world;
}

export function greenfieldRepository(environment = 'synthetic', repositoryId = REPO_ID) {
  const n = invokerNames(environment, repositoryId);
  const world = { 'sts get-caller-identity': caller() };
  oidcProvider(world);
  sharedStack(world, environment);
  world[`cloudformation describe-stacks --stack-name ${n.stack}`] = noStack(n.stack);
  world[`iam get-role --role-name ${n.role}`] = awsError('NoSuchEntity', 'GetRole', `The role with name ${n.role} cannot be found.`);
  world[`ssm get-parameter --name ${n.approverParameter}`] = awsError('ParameterNotFound', 'GetParameter', '');
  return changeSets(world);
}

// A role / parameter of the repository's names exists, owned by `stackName` (or none).
export function existingResource(world, environment, kind, { stackName = null, arn = null } = {}) {
  const n = invokerNames(environment, REPO_ID);
  const a = invokerArns(environment, REPO_ID, TARGET);
  const physical = kind === 'role' ? n.role : n.approverParameter;
  if (kind === 'role') {
    world[`iam get-role --role-name ${n.role}`] = ok({ Role: { RoleName: n.role, Arn: arn ?? a.role, RoleId: 'AROAINVOKER000000001', AssumeRolePolicyDocument: '{}', Tags: [] } });
  } else {
    world[`ssm get-parameter --name ${n.approverParameter}`] = ok({ Parameter: { Name: n.approverParameter, Type: 'String', Value: '[]', ARN: a.approverParameter, DataType: 'text' } });
  }
  world[`cloudformation describe-stack-resources --physical-resource-id ${physical}`] = stackName
    ? ok({ StackResources: [{ StackName: stackName, StackId: stackIdOf(stackName), LogicalResourceId: kind === 'role' ? 'InvokerRole' : 'ApproverParameter', PhysicalResourceId: physical, ResourceType: kind === 'role' ? 'AWS::IAM::Role' : 'AWS::SSM::Parameter', ResourceStatus: 'CREATE_COMPLETE' }] })
    : notInStack(physical);
  if (stackName) {
    world[`cloudformation describe-stacks --stack-name ${stackIdOf(stackName)}`] = ok({ Stacks: [{ StackName: stackName, StackId: stackIdOf(stackName), StackStatus: 'CREATE_COMPLETE', Tags: tagsFor(stackName.includes('production') ? 'production' : 'synthetic') }] });
  }
  return world;
}

// --- an independent IAM simulator -------------------------------------------------

const glob = (pattern, flags) => new RegExp(`^${String(pattern).split('').map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[\\^$.|+()[\]{}]/g, '\\$&'))).join('')}$`, flags);
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
function decide(docs, action, resource) {
  let allowed = false;
  for (const doc of docs) {
    for (const s of list(doc?.Statement)) {
      if (list(s.Action).some((p) => glob(p, 'i').test(action)) && list(s.Resource).some((p) => glob(p, '').test(resource))) {
        if (s.Effect === 'Deny') return 'explicitDeny';
        if (s.Effect === 'Allow') allowed = true;
      }
    }
  }
  return allowed ? 'allowed' : 'implicitDeny';
}
const flag = (argv, name) => argv[argv.indexOf(name) + 1];

export function deployedRepository(environment = 'synthetic', config = repository(), { fullName = SLUG } = {}) {
  const id = config.repository.id;
  const n = invokerNames(environment, id);
  const a = invokerArns(environment, id, TARGET);
  const stackId = stackIdOf(n.stack);
  const world = { 'sts get-caller-identity': caller() };
  world.__stack = { StackName: n.stack, StackId: stackId, StackStatus: 'CREATE_COMPLETE', Tags: tagsFor(environment) };
  world[`cloudformation describe-stacks --stack-name ${n.stack}`] = () => ok({ Stacks: [world.__stack] });
  world.__resources = [
    { StackName: n.stack, StackId: stackId, LogicalResourceId: 'InvokerRole', PhysicalResourceId: n.role, ResourceType: 'AWS::IAM::Role', ResourceStatus: 'CREATE_COMPLETE' },
    { StackName: n.stack, StackId: stackId, LogicalResourceId: 'ApproverParameter', PhysicalResourceId: n.approverParameter, ResourceType: 'AWS::SSM::Parameter', ResourceStatus: 'CREATE_COMPLETE' }
  ];
  world[`cloudformation describe-stack-resources --stack-name ${n.stack}`] = () => ok({ StackResources: world.__resources });
  world.__role = { RoleName: n.role, Arn: a.role, RoleId: 'AROAINVOKER000000001', Path: '/', MaxSessionDuration: 3600, Tags: tagsFor(environment) };
  world.__trust = invokerTrustPolicy({ partition: 'aws', account: ACCOUNT, subject: `repo:${fullName}:pull_request` });
  world.__inline = { 'ssd-break-glass-invoke-ci': invokerPermissionPolicy(environment, TARGET) };
  world.__attached = [];
  world[`iam get-role --role-name ${n.role}`] = () => ok({ Role: { ...world.__role, AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify(world.__trust)) } });
  world[`iam list-role-policies --role-name ${n.role}`] = () => ok({ PolicyNames: Object.keys(world.__inline) });
  world[`iam get-role-policy --role-name ${n.role} *`] = (argv) => {
    const name = flag(argv, '--policy-name');
    return world.__inline[name] ? ok({ RoleName: n.role, PolicyName: name, PolicyDocument: encodeURIComponent(JSON.stringify(world.__inline[name])) }) : awsError('NoSuchEntity', 'GetRolePolicy', 'no such policy');
  };
  world[`iam list-attached-role-policies --role-name ${n.role}`] = () => ok({ AttachedPolicies: world.__attached.map((x) => ({ PolicyName: x.name, PolicyArn: x.arn })) });
  world['iam get-policy *'] = (argv) => ok({ Policy: { Arn: flag(argv, '--policy-arn'), DefaultVersionId: 'v1' } });
  world['iam get-policy-version *'] = (argv) => ok({ PolicyVersion: { VersionId: 'v1', Document: world.__attached.find((x) => x.arn === flag(argv, '--policy-arn'))?.document ?? {} } });
  world.__parameter = { Name: n.approverParameter, Type: 'String', Value: JSON.stringify(config.environments[environment].approvers), ARN: a.approverParameter, DataType: 'text', Version: 1 };
  world[`ssm get-parameter --name ${n.approverParameter}`] = () => (world.__parameter ? ok({ Parameter: world.__parameter }) : awsError('ParameterNotFound', 'GetParameter', ''));
  world.__tier = 'Standard';
  world[`ssm describe-parameters --parameter-filters ${JSON.stringify([{ Key: 'Name', Option: 'Equals', Values: [n.approverParameter] }])}`] = () => ok({ Parameters: world.__parameter ? [{ Name: n.approverParameter, Type: world.__parameter.Type, Tier: world.__tier, DataType: world.__parameter.DataType }] : [] });
  // What each principal holds, for the simulator.
  world.__principals = { [a.role]: () => [...Object.values(world.__inline), ...world.__attached.map((x) => x.document)] };
  for (const env2 of ['production', 'synthetic']) {
    const roles = breakGlassArns(env2, TARGET).roles;
    for (const role of ['ci', 'interactions']) {
      const docRef = { doc: executionRolePolicy(role, env2, TARGET) };
      world.__principals[roles[role]] = () => [docRef.doc];
    }
  }
  world.__absent = [];
  world['iam simulate-principal-policy *'] = (argv) => {
    const arn = flag(argv, '--policy-source-arn');
    if (world.__absent.includes(arn) || !world.__principals[arn]) return awsError('NoSuchEntity', 'SimulatePrincipalPolicy', `The role with name ${arn.split('/').pop()} cannot be found.`);
    const docs = world.__principals[arn]();
    const actions = JSON.parse(flag(argv, '--action-names'));
    const [resource] = JSON.parse(flag(argv, '--resource-arns'));
    return ok({ IsTruncated: false, EvaluationResults: actions.map((action) => ({ EvalActionName: action, EvalResourceName: resource, EvalDecision: decide(docs, action, resource), MissingContextValues: [] })) });
  };
  return world;
}
