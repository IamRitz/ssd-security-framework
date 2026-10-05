// Recorded AWS behaviour for the Phase 3C break-glass tests. No test talks to AWS.
//
// Two worlds, both strict fakeAws worlds (an unrecorded call fails the test):
//   greenfieldBreakGlass(env)  nothing of the environment exists yet, the
//                              artifact is published (aws plan)
//   deployedBreakGlass(env)    the stack as `aws apply` leaves it, secrets
//                              populated (aws verify)
//
// The IAM simulator is deliberately INDEPENDENT of onboarding/aws/policy/:
// it evaluates the inline policy document the fake account HOLDS (world
// .__roles[name].policy) with its own small glob matcher. So a test that
// mutates the deployed document (drop PutItem, broaden to "*", grant the other
// environment's table) changes what simulate-principal-policy answers, exactly
// as IAM would — the code's probe list cannot quietly agree with itself.
import { ok, awsError } from './aws-fake.mjs';
import { changeSets, stackIdOf } from './aws-plan-fake.mjs';
import { ACCOUNT, REF } from './onboarding-fixtures.mjs';
import { validateOperatorConfig } from '../../onboarding/aws/break-glass/operator-config.mjs';
import { breakGlassArns, breakGlassNames, codeSha256Of } from '../../onboarding/aws/break-glass/names.mjs';
import { executionRolePolicy, executionTrustPolicy } from '../../onboarding/aws/policy/break-glass.mjs';
import { BREAK_GLASS_RESOURCE_TYPES } from '../../onboarding/aws/templates/shared-break-glass.mjs';

export { ACCOUNT, REF };
export const REGION = 'us-east-1';
export const CALLER = `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`;
export const TARGET = Object.freeze({ partition: 'aws', account: ACCOUNT, region: REGION });
export const ZIP_SHA256 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
export const ARTIFACT = Object.freeze({ bucket: 'ssd-break-glass-artifacts', key: 'broker/ssd-broker-068303774554.zip', versionId: '3sL4kqtJlcpXroDTDmJ-rmSpXd3dIbrHY', sha256: ZIP_SHA256 });
export const CHANNELS = Object.freeze({ production: 'C0PRODCHAN01', synthetic: 'C0SYNTHCHAN1' });

export function rawOperator(overrides = {}) {
  return {
    schemaVersion: '1',
    framework: { repository: 'IamRitz/ssd-security-framework', ref: REF },
    aws: { accountId: ACCOUNT, region: REGION },
    environments: {
      production: { slackChannelId: CHANNELS.production, artifact: { ...ARTIFACT } },
      synthetic: { slackChannelId: CHANNELS.synthetic, artifact: { ...ARTIFACT } }
    },
    ...overrides
  };
}
export const operator = (overrides) => validateOperatorConfig(rawOperator(overrides));

export const OPERATOR_YAML = `schemaVersion: "1"
framework:
  repository: IamRitz/ssd-security-framework
  ref: ${REF}
aws:
  accountId: "${ACCOUNT}"
  region: ${REGION}
environments:
  production:
    slackChannelId: ${CHANNELS.production}
    artifact:
      bucket: ${ARTIFACT.bucket}
      key: ${ARTIFACT.key}
      versionId: ${ARTIFACT.versionId}
      sha256: ${ARTIFACT.sha256}
  synthetic:
    slackChannelId: ${CHANNELS.synthetic}
    artifact:
      bucket: ${ARTIFACT.bucket}
      key: ${ARTIFACT.key}
      versionId: ${ARTIFACT.versionId}
      sha256: ${ARTIFACT.sha256}
`;

const noStack = (name) => awsError('ValidationError', 'DescribeStacks', `Stack with id ${name} does not exist`);
const notInStack = (id) => awsError('ValidationError', 'DescribeStackResources', `Stack for ${id} does not exist`);
const notFound = (op) => awsError('ResourceNotFoundException', op, 'Resource not found');
export const secretArnOf = (name) => `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:${name}-Ab12Cd`;
export const tagsFor = (environment) => [
  { Key: 'ssd:environment', Value: environment },
  { Key: 'ssd:framework', Value: 'ssd-security-framework' },
  { Key: 'ssd:managed-by', Value: 'ssd-onboard' }
];

// The published artifact, readable, in a private, versioned bucket.
export function artifactReads(world, { artifact = ARTIFACT, checksum = codeSha256Of(artifact.sha256), checksumType = 'FULL_OBJECT', versioning = 'Enabled', publicAccess = true, policyPublic = null } = {}) {
  world[`s3api head-object --bucket ${artifact.bucket} --key ${artifact.key} --version-id ${artifact.versionId} --checksum-mode ENABLED`] = ok({
    VersionId: artifact.versionId,
    ContentLength: 48211,
    ...(checksum ? { ChecksumSHA256: checksum, ...(checksumType ? { ChecksumType: checksumType } : {}) } : {})
  });
  world[`s3api get-bucket-versioning --bucket ${artifact.bucket}`] = ok(versioning ? { Status: versioning } : {});
  world[`s3api get-public-access-block --bucket ${artifact.bucket}`] = publicAccess
    ? ok({ PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true } })
    : awsError('NoSuchPublicAccessBlockConfiguration', 'GetPublicAccessBlock', 'The public access block configuration was not found');
  world[`s3api get-bucket-policy-status --bucket ${artifact.bucket}`] = policyPublic === null ? awsError('NoSuchBucketPolicy', 'GetBucketPolicyStatus', 'The bucket policy does not exist') : ok({ PolicyStatus: { IsPublic: policyPublic } });
  return world;
}

// Nothing of `environment` exists; change sets are modelled (aws-plan-fake).
export function greenfieldBreakGlass(environment = 'production') {
  const n = breakGlassNames(environment);
  const world = { 'sts get-caller-identity': ok({ Account: ACCOUNT, Arn: CALLER, UserId: 'AROAEXAMPLEEXAMPLE01:alice' }) };
  world[`cloudformation describe-stacks --stack-name ${n.stack}`] = noStack(n.stack);
  world[`dynamodb describe-table --table-name ${n.table}`] = notFound('DescribeTable');
  for (const s of Object.values(n.secrets)) world[`secretsmanager describe-secret --secret-id ${s}`] = notFound('DescribeSecret');
  for (const g of Object.values(n.logGroups)) world[`logs describe-log-groups --log-group-name-prefix ${g}`] = ok({ logGroups: [] });
  for (const r of Object.values(n.roles)) world[`iam get-role --role-name ${r}`] = awsError('NoSuchEntity', 'GetRole', `The role with name ${r} cannot be found.`);
  for (const f of Object.values(n.functions)) {
    world[`lambda get-function-configuration --function-name ${f}`] = notFound('GetFunctionConfiguration');
    world[`lambda get-function-concurrency --function-name ${f}`] = notFound('GetFunctionConcurrency');
  }
  artifactReads(world);
  accountConcurrency(world);
  return changeSets(world);
}

// The account's Lambda concurrency (lambda get-account-settings): by default a
// standard 1000 with nothing reserved.
export function accountConcurrency(world, { limit = 1000, unreserved = 1000 } = {}) {
  world['lambda get-account-settings'] = ok({ AccountLimit: { ConcurrentExecutions: limit, UnreservedConcurrentExecutions: unreserved, TotalCodeSize: 80530636800, CodeSizeUnzipped: 262144000, CodeSizeZipped: 52428800 }, AccountUsage: { TotalCodeSize: 0, FunctionCount: 0 } });
  return world;
}

// A named resource of `environment` that exists and belongs to `stackName`
// (or to no stack at all when stackName is null).
export function existingResource(world, { kind, environment, stackName = null, physicalId = null }) {
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, TARGET);
  const answers = {
    table: [`dynamodb describe-table --table-name ${n.table}`, ok({ Table: { TableName: n.table, TableArn: a.table, TableStatus: 'ACTIVE', KeySchema: [{ AttributeName: 'requestId', KeyType: 'HASH' }], AttributeDefinitions: [{ AttributeName: 'requestId', AttributeType: 'S' }] } }), n.table, 'RequestTable', 'AWS::DynamoDB::Table'],
    ciFunction: [`lambda get-function-configuration --function-name ${n.functions.ci}`, ok({ FunctionName: n.functions.ci, FunctionArn: a.functions.ci }), n.functions.ci, 'CiFunction', 'AWS::Lambda::Function']
  };
  const [key, answer, id, logicalId, type] = answers[kind];
  world[key] = answer;
  const pid = physicalId ?? id;
  world[`cloudformation describe-stack-resources --physical-resource-id ${pid}`] = stackName
    ? ok({ StackResources: [{ StackName: stackName, StackId: stackIdOf(stackName), LogicalResourceId: logicalId, PhysicalResourceId: pid, ResourceType: type, ResourceStatus: 'CREATE_COMPLETE' }] })
    : notInStack(pid);
  if (stackName) {
    world[`cloudformation describe-stacks --stack-name ${stackIdOf(stackName)}`] = ok({ Stacks: [{ StackName: stackName, StackId: stackIdOf(stackName), StackStatus: 'CREATE_COMPLETE', Tags: tagsFor(stackName.endsWith('production') ? 'production' : 'synthetic') }] });
  }
  return world;
}

// --- an independent IAM simulator --------------------------------------------------

const glob = (pattern, flags) => new RegExp(`^${String(pattern).split('').map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[\\^$.|+()[\]{}]/g, '\\$&'))).join('')}$`, flags);
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
function decide(doc, action, resource) {
  let allowed = false;
  for (const s of list(doc?.Statement)) {
    const act = list(s.Action).some((p) => glob(p, 'i').test(action));
    const res = list(s.Resource).some((p) => glob(p, '').test(resource));
    if (act && res) {
      if (s.Effect === 'Deny') return 'explicitDeny';
      if (s.Effect === 'Allow') allowed = true;
    }
  }
  return allowed ? 'allowed' : 'implicitDeny';
}
const flag = (argv, name) => argv[argv.indexOf(name) + 1];

// The deployed stack of `environment`, as apply leaves it.
export function deployedBreakGlass(environment = 'production', { op = operator() } = {}) {
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, TARGET);
  const env = op.environments[environment];
  const world = { 'sts get-caller-identity': ok({ Account: ACCOUNT, Arn: CALLER, UserId: 'AROAEXAMPLEEXAMPLE01:alice' }) };
  const stackId = stackIdOf(n.stack);
  const stack = { StackName: n.stack, StackId: stackId, StackStatus: 'CREATE_COMPLETE', Tags: tagsFor(environment), LastUpdatedTime: '2026-10-04T10:00:00.000Z' };
  world[`cloudformation describe-stacks --stack-name ${n.stack}`] = ok({ Stacks: [stack] });
  const secretArns = Object.fromEntries(Object.entries(n.secrets).map(([k, name]) => [k, secretArnOf(name)]));
  const physical = {
    RequestTable: n.table,
    SlackBotTokenSecret: secretArns.slackBotToken,
    SlackSigningSecret: secretArns.slackSigningSecret,
    GithubTokenSecret: secretArns.githubToken,
    CiLogGroup: n.logGroups.ci,
    InteractionsLogGroup: n.logGroups.interactions,
    CiExecutionRole: n.roles.ci,
    InteractionsExecutionRole: n.roles.interactions,
    CiFunction: n.functions.ci,
    InteractionsFunction: n.functions.interactions,
    InteractionsFunctionUrl: a.functions.interactions,
    InteractionsUrlPermission: `${n.stack}-InteractionsUrlPermission-AAAA`,
    InteractionsUrlInvokePermission: `${n.stack}-InteractionsUrlInvokePermission-BBBB`,
    InteractionsEventInvokeConfig: `${n.stack}-InteractionsEventInvokeConfig-CCCC`
  };
  world.__stackResources = Object.entries(BREAK_GLASS_RESOURCE_TYPES).map(([logicalId, type]) => ({ StackName: n.stack, StackId: stackId, LogicalResourceId: logicalId, PhysicalResourceId: physical[logicalId], ResourceType: type, ResourceStatus: 'CREATE_COMPLETE' }));
  world[`cloudformation describe-stack-resources --stack-name ${n.stack}`] = () => ok({ StackResources: world.__stackResources });

  world.__table = { TableName: n.table, TableArn: a.table, TableStatus: 'ACTIVE', KeySchema: [{ AttributeName: 'requestId', KeyType: 'HASH' }], AttributeDefinitions: [{ AttributeName: 'requestId', AttributeType: 'S' }], BillingModeSummary: { BillingMode: 'PAY_PER_REQUEST' }, DeletionProtectionEnabled: true };
  world[`dynamodb describe-table --table-name ${n.table}`] = () => ok({ Table: world.__table });
  world.__ttl = { TimeToLiveStatus: 'ENABLED', AttributeName: 'ttl' };
  world[`dynamodb describe-time-to-live --table-name ${n.table}`] = () => ok({ TimeToLiveDescription: world.__ttl });
  world[`dynamodb describe-continuous-backups --table-name ${n.table}`] = ok({ ContinuousBackupsDescription: { ContinuousBackupsStatus: 'ENABLED', PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: 'ENABLED' } } });

  world.__secrets = Object.fromEntries(Object.entries(n.secrets).map(([k, name]) => [k, { Name: name, ARN: secretArns[k], Tags: tagsFor(environment), VersionIdsToStages: { 'v-1': ['AWSCURRENT'] } }]));
  for (const [k, name] of Object.entries(n.secrets)) {
    world[`secretsmanager describe-secret --secret-id ${name}`] = () => ok(world.__secrets[k]);
  }

  const code = codeSha256Of(env.artifact.sha256);
  const fn = (role, Variables) => ({ FunctionName: n.functions[role], FunctionArn: a.functions[role], Role: a.roles[role], Runtime: 'nodejs24.x', Handler: `broker/lambda/index.${role === 'ci' ? 'ciHandler' : 'interactionsHandler'}`, Architectures: ['arm64'], MemorySize: 256, Timeout: 20, CodeSha256: code, PackageType: 'Zip', Environment: { Variables }, State: 'Active' });
  world.__functions = {
    ci: fn('ci', { TABLE_NAME: n.table, SLACK_CHANNEL_ID: env.slackChannelId, SLACK_BOT_TOKEN_SECRET_ARN: secretArns.slackBotToken }),
    interactions: fn('interactions', { TABLE_NAME: n.table, BREAK_GLASS_ENVIRONMENT: environment, SLACK_BOT_TOKEN_SECRET_ARN: secretArns.slackBotToken, SLACK_SIGNING_SECRET_ARN: secretArns.slackSigningSecret, GITHUB_TOKEN_SECRET_ARN: secretArns.githubToken })
  };
  for (const role of ['ci', 'interactions']) {
    world[`lambda get-function-configuration --function-name ${n.functions[role]}`] = () => ok(world.__functions[role]);
    // Live AWS (2026-10-05): with no reservation, get-function-concurrency exits 0
    // and prints NOTHING (not "{}"). The CI broker deliberately has none.
    world[`lambda get-function-concurrency --function-name ${n.functions[role]}`] = role === 'interactions' ? ok({ ReservedConcurrentExecutions: 5 }) : { stdout: '', stderr: '', exitCode: 0 };
  }
  world.__urls = { ci: null, interactions: { FunctionUrl: 'https://abc123.lambda-url.us-east-1.on.aws/', AuthType: 'NONE', FunctionArn: a.functions.interactions } };
  world.__policies = {
    ci: null,
    interactions: [
      { Sid: 'url', Effect: 'Allow', Principal: '*', Action: 'lambda:InvokeFunctionUrl', Resource: a.functions.interactions, Condition: { StringEquals: { 'lambda:FunctionUrlAuthType': 'NONE' } } },
      { Sid: 'via-url', Effect: 'Allow', Principal: '*', Action: 'lambda:InvokeFunction', Resource: a.functions.interactions, Condition: { Bool: { 'lambda:InvokedViaFunctionUrl': 'true' } } }
    ]
  };
  for (const role of ['ci', 'interactions']) {
    world[`lambda get-function-url-config --function-name ${n.functions[role]}`] = () => (world.__urls[role] ? ok(world.__urls[role]) : notFound('GetFunctionUrlConfig'));
    world[`lambda get-policy --function-name ${n.functions[role]}`] = () => (world.__policies[role] ? ok({ Policy: JSON.stringify({ Version: '2012-10-17', Statement: world.__policies[role] }) }) : notFound('GetPolicy'));
  }
  world.__async = { MaximumRetryAttempts: 0, MaximumEventAgeInSeconds: 900 };
  world[`lambda get-function-event-invoke-config --function-name ${n.functions.interactions}`] = () => (world.__async ? ok(world.__async) : notFound('GetFunctionEventInvokeConfig'));
  for (const role of ['ci', 'interactions']) {
    world[`logs describe-log-groups --log-group-name-prefix ${n.logGroups[role]}`] = ok({ logGroups: [{ logGroupName: n.logGroups[role], arn: `arn:aws:logs:${REGION}:${ACCOUNT}:log-group:${n.logGroups[role]}:*`, retentionInDays: 90 }] });
  }
  artifactReads(world, { artifact: env.artifact });
  accountConcurrency(world, { unreserved: 990 });

  // Execution roles: the deployed documents, and a simulator over them.
  world.__roles = {};
  for (const role of ['ci', 'interactions']) {
    world.__roles[n.roles[role]] = { arn: a.roles[role], roleId: role === 'ci' ? 'AROACIEXECUTIONROLE01' : 'AROAINTEXECUTIONROL02', trust: executionTrustPolicy(), policyName: n.rolePolicies[role], policy: executionRolePolicy(role, environment, TARGET), attached: [] };
  }
  for (const name of Object.keys(world.__roles)) {
    const r = () => world.__roles[name];
    world[`iam get-role --role-name ${name}`] = () => ok({ Role: { RoleName: name, Arn: r().arn, RoleId: r().roleId, AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify(r().trust)), Tags: tagsFor(environment) } });
    world[`iam list-role-policies --role-name ${name}`] = () => ok({ PolicyNames: [r().policyName, ...(r().extraInline ? Object.keys(r().extraInline) : [])] });
    world[`iam get-role-policy --role-name ${name} --policy-name ${world.__roles[name].policyName}`] = () => ok({ RoleName: name, PolicyName: r().policyName, PolicyDocument: encodeURIComponent(JSON.stringify(r().policy)) });
    world[`iam list-attached-role-policies --role-name ${name}`] = () => ok({ AttachedPolicies: r().attached });
  }
  world['iam simulate-principal-policy *'] = (argv) => {
    const arn = flag(argv, '--policy-source-arn');
    const role = Object.values(world.__roles).find((x) => x.arn === arn);
    const actions = JSON.parse(flag(argv, '--action-names'));
    const [resource] = JSON.parse(flag(argv, '--resource-arns'));
    return ok({ IsTruncated: false, EvaluationResults: actions.map((action) => ({ EvalActionName: action, EvalResourceName: resource, EvalDecision: role ? decide(role.policy, action, resource) : 'implicitDeny', MissingContextValues: [] })) });
  };
  return world;
}
