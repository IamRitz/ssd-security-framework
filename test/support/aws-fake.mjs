// Recorded AWS CLI behaviour for the Phase 2 tests. No test talks to AWS.
//
// A world maps the argv a caller passes to readOnlyAws() — WITHOUT the
// wrapper's `--region <r> --output json --no-cli-pager` suffix, joined by
// spaces — to a recorded { stdout, stderr, exitCode }. fakeAws(world) is an
// injectable executor that records every argv it receives (exactly as
// execFile would get it). It is STRICT, independently of the code under test:
//   - every argv must end in exactly the wrapper suffix and its call part must
//     pass the read-only allowlist, so a path that bypasses readOnlyAws() fails;
//   - an UNRECORDED call throws a plain Error (FakeAwsError), which no doctor
//     code treats as an AWS answer, so the test fails instead of degrading the
//     call to NOT VERIFIED.
// A key ending in ' *' matches every call that starts with the text before it
// (exact keys win).
import { assertReadOnly } from '../../onboarding/aws/aws-cli.mjs';
import { ACCOUNT, DEPLOY_ROLE, PUSH_ROLE } from './onboarding-fixtures.mjs';

export { ACCOUNT, DEPLOY_ROLE, PUSH_ROLE };
export const REGION = 'us-east-1';
export const SLUG = 'acme/app';
export const REPOSITORY = 'app';
export const INSTANCE = 'i-0123456789abcdef0';
export const PROVIDER = `arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com`;
export const REPO_ARN = `arn:aws:ecr:${REGION}:${ACCOUNT}:repository/${REPOSITORY}`;
export const INSTANCE_ARN = `arn:aws:ec2:${REGION}:${ACCOUNT}:instance/${INSTANCE}`;
export const PROFILE_ARN = `arn:aws:iam::${ACCOUNT}:instance-profile/app-instance`;
export const INSTANCE_ROLE = `arn:aws:iam::${ACCOUNT}:role/app-instance`;
export const CALLER = `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`;
const SSM_CORE_ARN = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore';
const PULL_ARN = `arn:aws:iam::${ACCOUNT}:policy/app-pull`;

export const ok = (value) => ({ stdout: JSON.stringify(value), stderr: '', exitCode: 0 });
export const awsError = (code, operation, message = `${code} message`) => ({
  stdout: '',
  stderr: `\nAn error occurred (${code}) when calling the ${operation} operation: ${message}\n`,
  exitCode: 254
});
export const accessDenied = (operation, action = 'x:Y') =>
  awsError('AccessDenied', operation, `User: ${CALLER} is not authorized to perform: ${action} because no identity-based policy allows the ${action} action`);

export function trustPolicy({ subjects, audience = ['sts.amazonaws.com'], operator = 'StringEquals', provider = PROVIDER, extra = {} } = {}) {
  const condition = { StringEquals: { 'token.actions.githubusercontent.com:aud': audience } };
  condition[operator] = { ...(condition[operator] ?? {}), 'token.actions.githubusercontent.com:sub': subjects };
  return {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { Federated: provider }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { ...condition, ...extra } }]
  };
}

export const PUSH_POLICY = {
  Version: '2012-10-17',
  Statement: [
    { Sid: 'Login', Effect: 'Allow', Action: 'ecr:GetAuthorizationToken', Resource: '*' },
    {
      Sid: 'PushAndScan',
      Effect: 'Allow',
      Action: ['ecr:BatchCheckLayerAvailability', 'ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload', 'ecr:PutImage', 'ecr:DescribeImageScanFindings'],
      Resource: REPO_ARN
    }
  ]
};
export const DEPLOY_POLICY = {
  Version: '2012-10-17',
  Statement: [
    { Sid: 'Send', Effect: 'Allow', Action: 'ssm:SendCommand', Resource: [INSTANCE_ARN, `arn:aws:ssm:${REGION}::document/AWS-RunShellScript`] },
    { Sid: 'Read', Effect: 'Allow', Action: 'ssm:GetCommandInvocation', Resource: '*' }
  ]
};
export const PULL_POLICY = {
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'ecr:GetAuthorizationToken', Resource: '*' },
    { Effect: 'Allow', Action: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'], Resource: REPO_ARN }
  ]
};
const SSM_CORE_POLICY = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: ['ssm:UpdateInstanceInformation', 'ssmmessages:*', 'ec2messages:*'], Resource: '*' }]
};

const roleResponses = (arn, { trust, inline = {}, attached = [] }) => {
  const name = arn.split('/').pop();
  const out = {
    [`iam get-role --role-name ${name}`]: ok({ Role: { Arn: arn, RoleName: name, AssumeRolePolicyDocument: trust, Tags: [] } }),
    [`iam list-role-policies --role-name ${name}`]: ok({ PolicyNames: Object.keys(inline) }),
    [`iam list-attached-role-policies --role-name ${name}`]: ok({ AttachedPolicies: attached.map((a) => ({ PolicyName: a.name, PolicyArn: a.arn })) })
  };
  for (const [policyName, document] of Object.entries(inline)) {
    out[`iam get-role-policy --role-name ${name} --policy-name ${policyName}`] = ok({ RoleName: name, PolicyName: policyName, PolicyDocument: document });
  }
  for (const a of attached) {
    out[`iam get-policy --policy-arn ${a.arn}`] = ok({ Policy: { Arn: a.arn, DefaultVersionId: 'v1' } });
    out[`iam get-policy-version --policy-arn ${a.arn} --version-id v1`] = ok({ PolicyVersion: { Document: a.document, VersionId: 'v1' } });
  }
  return out;
};

export const simulateKey = (arn, actions, resource) =>
  `iam simulate-principal-policy --policy-source-arn ${arn} --action-names ${JSON.stringify(actions)} --resource-arns ${JSON.stringify([resource])}`;

const notInStack = (id) => awsError('ValidationError', 'DescribeStackResources', `Stack for ${id} does not exist`);

// The ready world: every prerequisite in place, `existing` ownership, BASIC
// scanning, simulation denied to the operator (policy-document basis only).
export function readyWorld() {
  const world = {
    'sts get-caller-identity': ok({ Account: ACCOUNT, Arn: CALLER, UserId: 'AROAEXAMPLEEXAMPLE01:alice' }),
    'iam list-open-id-connect-providers': ok({ OpenIDConnectProviderList: [{ Arn: PROVIDER }] }),
    [`iam get-open-id-connect-provider --open-id-connect-provider-arn ${PROVIDER}`]: ok({
      Url: 'token.actions.githubusercontent.com',
      ClientIDList: ['sts.amazonaws.com'],
      ThumbprintList: ['6938fd4d98bab03faadb97b34396831e3780aea1'],
      Tags: []
    }),
    [`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`]: ok({
      repositories: [
        {
          repositoryArn: REPO_ARN,
          registryId: ACCOUNT,
          repositoryName: REPOSITORY,
          repositoryUri: `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}`,
          imageTagMutability: 'IMMUTABLE',
          imageScanningConfiguration: { scanOnPush: false },
          encryptionConfiguration: { encryptionType: 'AES256' }
        }
      ]
    }),
    [`ecr get-lifecycle-policy --registry-id ${ACCOUNT} --repository-name ${REPOSITORY}`]: awsError('LifecyclePolicyNotFoundException', 'GetLifecyclePolicy'),
    [`ecr get-repository-policy --registry-id ${ACCOUNT} --repository-name ${REPOSITORY}`]: awsError('RepositoryPolicyNotFoundException', 'GetRepositoryPolicy'),
    [`ecr list-tags-for-resource --resource-arn ${REPO_ARN}`]: ok({ tags: [] }),
    'ecr get-registry-scanning-configuration': ok({
      registryId: ACCOUNT,
      scanningConfiguration: { scanType: 'BASIC', rules: [{ scanFrequency: 'SCAN_ON_PUSH', repositoryFilters: [{ filter: REPOSITORY, filterType: 'WILDCARD' }] }] }
    }),
    ...roleResponses(PUSH_ROLE, { trust: trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] }), inline: { push: PUSH_POLICY } }),
    ...roleResponses(DEPLOY_ROLE, { trust: trustPolicy({ subjects: [`repo:${SLUG}:environment:production`] }), inline: { deploy: DEPLOY_POLICY } }),
    [`ec2 describe-instances --instance-ids ${INSTANCE}`]: ok({
      Reservations: [{ OwnerId: ACCOUNT, Instances: [{ InstanceId: INSTANCE, State: { Name: 'running' }, IamInstanceProfile: { Arn: PROFILE_ARN } }] }]
    }),
    [`ssm describe-instance-information --filters ${JSON.stringify([{ Key: 'InstanceIds', Values: [INSTANCE] }])}`]: ok({
      InstanceInformationList: [{ InstanceId: INSTANCE, PingStatus: 'Online', ResourceType: 'EC2Instance', AgentVersion: '3.3.0' }]
    }),
    'iam get-instance-profile --instance-profile-name app-instance': ok({ InstanceProfile: { Arn: PROFILE_ARN, Roles: [{ Arn: INSTANCE_ROLE }] } }),
    ...roleResponses(INSTANCE_ROLE, {
      trust: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }] },
      attached: [
        { name: 'AmazonSSMManagedInstanceCore', arn: SSM_CORE_ARN, document: SSM_CORE_POLICY },
        { name: 'app-pull', arn: PULL_ARN, document: PULL_POLICY }
      ]
    })
  };
  for (const id of [PROVIDER, REPOSITORY, 'app-ecr-push-scan', 'app-deploy']) {
    world[`cloudformation describe-stack-resources --physical-resource-id ${id}`] = notInStack(id);
  }
  // Simulation: denied to this operator unless a test records exact results.
  for (const arn of [PUSH_ROLE, DEPLOY_ROLE]) {
    world[`iam simulate-principal-policy --policy-source-arn ${arn} *`] = accessDenied('SimulatePrincipalPolicy', 'iam:SimulatePrincipalPolicy');
  }
  return world;
}

// A managed stack relationship for one physical id.
export function managedStack(world, physicalId, { type, tags, stackName = 'ssd-app-delivery' }) {
  const stackId = `arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/${stackName}/1`;
  world[`cloudformation describe-stack-resources --physical-resource-id ${physicalId}`] = ok({
    StackResources: [{ StackName: stackName, StackId: stackId, LogicalResourceId: 'Resource', PhysicalResourceId: physicalId, ResourceType: type, ResourceStatus: 'CREATE_COMPLETE' }]
  });
  world[`cloudformation describe-stacks --stack-name ${stackId}`] = ok({ Stacks: [{ StackName: stackName, StackId: stackId, StackStatus: 'CREATE_COMPLETE', Tags: tags }] });
  return world;
}

export const SSD_STACK_TAGS = [
  { Key: 'ssd:framework', Value: 'ssd-security-framework' },
  { Key: 'ssd:managed-by', Value: 'ssd-onboard' },
  { Key: 'ssd:consumer-repository', Value: SLUG },
  { Key: 'ssd:environment', Value: 'production' }
];

const WRAPPER = ['--region', '--output', 'json', '--no-cli-pager'];

export class FakeAwsError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FakeAwsError';
  }
}

function lookup(world, key) {
  if (Object.hasOwn(world, key)) {
    return world[key];
  }
  const prefix = Object.keys(world)
    .filter((k) => k.endsWith(' *') && key.startsWith(k.slice(0, -1)))
    .sort((a, b) => b.length - a.length)[0];
  return prefix ? world[prefix] : undefined;
}

export function fakeAws(world) {
  const calls = [];
  const unexpected = [];
  const exec = async (argv, options) => {
    calls.push({ argv: [...argv], options });
    const at = argv.indexOf('--region');
    const suffix = at === -1 ? [] : argv.slice(at);
    if (at === -1 || suffix.length !== 5 || suffix[0] !== '--region' || suffix[2] !== '--output' || suffix[3] !== 'json' || suffix[4] !== '--no-cli-pager') {
      throw new FakeAwsError(`argv without the read-only wrapper suffix reached the executor: ${argv.join(' ')}`);
    }
    const call = argv.slice(0, at);
    try {
      assertReadOnly(call);
    } catch (error) {
      throw new FakeAwsError(`a non-allowlisted argv reached the executor: ${call.join(' ')} (${error.message})`);
    }
    const key = call.join(' ');
    const response = lookup(world, key);
    if (!response) {
      unexpected.push(key);
      throw new FakeAwsError(`UNRECORDED AWS CALL: ${key}`);
    }
    return typeof response === 'function' ? response(argv) : response;
  };
  return {
    exec,
    calls,
    unexpected,
    keys: () => calls.map((c) => c.argv.slice(0, c.argv.indexOf('--region')).join(' ')),
    operations: () => calls.map((c) => `${c.argv[0]} ${c.argv[1]}`),
    wrapperSuffix: WRAPPER
  };
}
