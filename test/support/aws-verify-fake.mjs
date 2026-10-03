// Recorded AWS behaviour for the `aws verify` tests (Phase 2D). No test talks to AWS.
//
// verifiedWorld() is the doctor's ready world (aws-fake.mjs) plus what verify
// reads beyond it: RoleIds, and simulate-principal-policy answers for the
// push/scan, deploy and instance roles. The simulator is deliberately
// INDEPENDENT of onboarding/aws/policy/permissions.mjs: the grants each role
// holds are written out below, so a change to the code's probe list cannot
// silently change what the fixture answers.
import { ACCOUNT, DEPLOY_ROLE, INSTANCE, INSTANCE_ARN, INSTANCE_ROLE, PUSH_ROLE, REGION, REPOSITORY, REPO_ARN, SLUG, accessDenied, ok, readyWorld } from './aws-fake.mjs';

export const RUN_SHELL = `arn:aws:ssm:${REGION}::document/AWS-RunShellScript`;
const PUSH = ['ecr:BatchCheckLayerAvailability', 'ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload', 'ecr:PutImage'];

// role ARN -> Set of "action resource" the role is effectively ALLOWED.
export function grants({ enhanced = false } = {}) {
  return {
    [PUSH_ROLE]: new Set([
      'ecr:GetAuthorizationToken *',
      ...[...PUSH, 'ecr:DescribeImageScanFindings'].map((a) => `${a} ${REPO_ARN}`),
      ...(enhanced ? ['inspector2:ListCoverage *', 'inspector2:ListFindings *'] : [])
    ]),
    [DEPLOY_ROLE]: new Set([`ssm:SendCommand ${INSTANCE_ARN}`, `ssm:SendCommand ${RUN_SHELL}`, 'ssm:GetCommandInvocation *']),
    [INSTANCE_ROLE]: new Set(['ecr:GetAuthorizationToken *', `ecr:BatchGetImage ${REPO_ARN}`, `ecr:GetDownloadUrlForLayer ${REPO_ARN}`])
  };
}

const flag = (argv, name) => argv[argv.indexOf(name) + 1];

// A simulate-principal-policy responder over a grant table. `missing` maps
// "action resource" to MissingContextValues reported with an implicit deny.
export function simulator(table, { missing = {} } = {}) {
  return (argv) => {
    const arn = flag(argv, '--policy-source-arn');
    const actions = JSON.parse(flag(argv, '--action-names'));
    const [resource] = JSON.parse(flag(argv, '--resource-arns'));
    const allowed = table[arn] ?? new Set();
    return ok({
      IsTruncated: false,
      EvaluationResults: actions.map((action) => {
        const key = `${action} ${resource}`;
        return {
          EvalActionName: action,
          EvalResourceName: resource,
          EvalDecision: allowed.has(key) ? 'allowed' : 'implicitDeny',
          MissingContextValues: allowed.has(key) ? [] : (missing[key] ?? [])
        };
      })
    });
  };
}

const ROLE_IDS = { [PUSH_ROLE]: 'AROAPUSHPUSHPUSHPUSH1', [DEPLOY_ROLE]: 'AROADEPLOYDEPLOYDEPL2', [INSTANCE_ROLE]: 'AROAINSTANCEINSTANC3' };

// The verified world: doctor's ready world (existing ownership, BASIC scanning)
// with every role simulated as it should be.
export function verifiedWorld({ enhanced = false, table = grants({ enhanced }) } = {}) {
  const world = readyWorld();
  for (const arn of [PUSH_ROLE, DEPLOY_ROLE, INSTANCE_ROLE]) {
    const key = `iam get-role --role-name ${arn.split('/').pop()}`;
    const doc = JSON.parse(world[key].stdout);
    doc.Role.RoleId = ROLE_IDS[arn];
    world[key] = ok(doc);
    delete world[`iam simulate-principal-policy --policy-source-arn ${arn} *`];
    world[`iam simulate-principal-policy --policy-source-arn ${arn} *`] = simulator(table);
  }
  if (enhanced) {
    world['ecr get-registry-scanning-configuration'] = ok({
      registryId: ACCOUNT,
      scanningConfiguration: { scanType: 'ENHANCED', rules: [{ scanFrequency: 'CONTINUOUS_SCAN', repositoryFilters: [{ filter: REPOSITORY, filterType: 'WILDCARD' }] }] }
    });
    world[`inspector2 batch-get-account-status --account-ids ${ACCOUNT}`] = ok({ accounts: [{ accountId: ACCOUNT, state: { status: 'ENABLED' }, resourceState: { ecr: { status: 'ENABLED' } } }] });
    world[`inspector2 list-coverage --filter-criteria ${inspectorFilter()}`] = ok({
      coveredResources: [{ resourceId: REPO_ARN, resourceType: 'AWS_ECR_REPOSITORY', scanStatus: { statusCode: 'ACTIVE', reason: 'SUCCESSFUL' } }]
    });
  }
  return world;
}

export const inspectorFilter = () =>
  JSON.stringify({ resourceType: [{ comparison: 'EQUALS', value: 'AWS_ECR_REPOSITORY' }], ecrRepositoryName: [{ comparison: 'EQUALS', value: REPOSITORY }] });

export const simulationDenied = (world, arn) => {
  world[`iam simulate-principal-policy --policy-source-arn ${arn} *`] = accessDenied('SimulatePrincipalPolicy', 'iam:SimulatePrincipalPolicy');
  return world;
};

export { ACCOUNT, DEPLOY_ROLE, INSTANCE, INSTANCE_ARN, INSTANCE_ROLE, PUSH_ROLE, REGION, REPOSITORY, REPO_ARN, SLUG };
