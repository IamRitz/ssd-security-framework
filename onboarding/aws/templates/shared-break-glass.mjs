// One shared break-glass stack (Phase 3C): ssd-break-glass-production or
// ssd-break-glass-synthetic. The two are rendered by this one function from
// different environments, so they differ in every runtime and security-state
// resource by construction (break-glass/names.mjs); renderBreakGlassTemplate
// additionally refuses a render whose derived identifiers would coincide with
// the other environment's.
//
//   RequestTable                  DynamoDB, key requestId (S), on-demand,
//                                 TTL ENABLED on `ttl`, PITR, deletion protection
//   SlackBotTokenSecret           Secrets Manager CONTAINERS: no SecretString and
//   SlackSigningSecret            no GenerateSecretString, which CloudFormation
//   GithubTokenSecret             documents as creating an EMPTY secret. The value
//                                 is put afterwards, out of band (stdin); until
//                                 then the broker cannot start (fail closed)
//   CiLogGroup / InteractionsLogGroup   90-day retention; created here so neither
//                                 role needs logs:CreateLogGroup
//   CiExecutionRole / InteractionsExecutionRole   policy/break-glass.mjs
//   CiFunction                    CI broker: NO Function URL, NO resource policy
//                                 (IAM lambda:InvokeFunction only)
//   InteractionsFunction          Slack interaction handler
//   InteractionsFunctionUrl       the ONE public surface: AuthType NONE, the
//                                 Slack HMAC signature is the authentication
//   InteractionsUrlPermission     lambda:InvokeFunctionUrl, Principal *, only
//                                 with FunctionUrlAuthType NONE
//   InteractionsUrlInvokePermission  lambda:InvokeFunction, Principal *, only
//                                 when invoked via the Function URL
//   InteractionsEventInvokeConfig the async follow-up runs at most once
//                                 (0 retries): a retry could post a second
//                                 audit comment
//
// CODE is an already-published, immutable S3 object version (operator config
// `artifact`): the template pins bucket, key AND S3ObjectVersion. No local
// file is packaged and nothing is uploaded by plan or apply. The artifact's
// sha256 is not a template input (CloudFormation has no property that checks
// it); `aws verify` compares the live CodeSha256 to it.
//
// No VPC: both functions reach Slack, GitHub and GitHub's JWKS over the public
// internet. The interaction function has a deliberate reserved concurrency
// (INTERACTIONS_RESERVED_CONCURRENCY, break-glass/names.mjs explains the
// sizing); the IAM-only CI broker has none (aws verify WARNs). The
// approver map is never set in the environment: the interaction function reads
// /ssd/break-glass/<environment>/approvers/<repository_id> (Phase 3B, PR #17);
// against pre-3B broker code nobody is authorized (fail closed). Both functions
// get BREAK_GLASS_ENVIRONMENT and read exactly
// /ssd/break-glass/<environment>/governance/allowed-framework-shas (Phase 3D),
// which the governance stack owns; this stack never creates it.
import { assertSeparated, breakGlassArns, breakGlassNames, HANDLERS, INTERACTIONS_RESERVED_CONCURRENCY, LAMBDA_ARCHITECTURE, LAMBDA_MEMORY_MB, LAMBDA_RUNTIME, LAMBDA_TIMEOUT_SECONDS, LOG_RETENTION_DAYS, TABLE_KEY, TTL_ATTRIBUTE } from '../break-glass/names.mjs';
import { executionRolePolicy, executionTrustPolicy } from '../policy/break-glass.mjs';
import { retained, ssdTags, template } from './common.mjs';

export const BREAK_GLASS_LOGICAL_IDS = Object.freeze({
  table: 'RequestTable',
  slackBotToken: 'SlackBotTokenSecret',
  slackSigningSecret: 'SlackSigningSecret',
  githubToken: 'GithubTokenSecret',
  ciLogGroup: 'CiLogGroup',
  interactionsLogGroup: 'InteractionsLogGroup',
  ciRole: 'CiExecutionRole',
  interactionsRole: 'InteractionsExecutionRole',
  ciFunction: 'CiFunction',
  interactionsFunction: 'InteractionsFunction',
  url: 'InteractionsFunctionUrl',
  urlPermission: 'InteractionsUrlPermission',
  urlInvokePermission: 'InteractionsUrlInvokePermission',
  eventInvokeConfig: 'InteractionsEventInvokeConfig'
});

const L = BREAK_GLASS_LOGICAL_IDS;
export const BREAK_GLASS_RESOURCE_TYPES = Object.freeze({
  [L.table]: 'AWS::DynamoDB::Table',
  [L.slackBotToken]: 'AWS::SecretsManager::Secret',
  [L.slackSigningSecret]: 'AWS::SecretsManager::Secret',
  [L.githubToken]: 'AWS::SecretsManager::Secret',
  [L.ciLogGroup]: 'AWS::Logs::LogGroup',
  [L.interactionsLogGroup]: 'AWS::Logs::LogGroup',
  [L.ciRole]: 'AWS::IAM::Role',
  [L.interactionsRole]: 'AWS::IAM::Role',
  [L.ciFunction]: 'AWS::Lambda::Function',
  [L.interactionsFunction]: 'AWS::Lambda::Function',
  [L.url]: 'AWS::Lambda::Url',
  [L.urlPermission]: 'AWS::Lambda::Permission',
  [L.urlInvokePermission]: 'AWS::Lambda::Permission',
  [L.eventInvokeConfig]: 'AWS::Lambda::EventInvokeConfig'
});

const SECRET_DESCRIPTIONS = {
  slackBotToken: 'Slack bot token (chat:write) of this environment\'s break-glass Slack app',
  slackSigningSecret: 'Slack signing secret of this environment\'s break-glass Slack app',
  githubToken: 'GitHub credential that posts the break-glass audit comment'
};

const ref = (logicalId) => ({ Ref: logicalId });
const arnOf = (logicalId) => ({ 'Fn::GetAtt': [logicalId, 'Arn'] });

// operator: the validated operator config (break-glass/operator-config.mjs).
// -> { template, policies: { CiExecutionRole: { role, arn, trust, permissions }, InteractionsExecutionRole: … } }
export function renderBreakGlassTemplate({ operator, environment, partition }) {
  const target = { partition, account: operator.aws.accountId, region: operator.aws.region };
  const env = operator.environments[environment];
  if (!env) {
    throw new Error(`the operator configuration has no '${environment}' environment`);
  }
  assertSeparated(target, { production: operator.environments.production?.slackChannelId, synthetic: operator.environments.synthetic?.slackChannelId });
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, target);
  const tags = ssdTags({ scope: 'break-glass', environment });
  const resources = {};
  const policies = {};

  resources[L.table] = retained('AWS::DynamoDB::Table', {
    TableName: n.table,
    BillingMode: 'PAY_PER_REQUEST',
    AttributeDefinitions: [{ AttributeName: TABLE_KEY, AttributeType: 'S' }],
    KeySchema: [{ AttributeName: TABLE_KEY, KeyType: 'HASH' }],
    TimeToLiveSpecification: { AttributeName: TTL_ATTRIBUTE, Enabled: true },
    PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
    DeletionProtectionEnabled: true,
    Tags: tags
  });

  for (const key of ['slackBotToken', 'slackSigningSecret', 'githubToken']) {
    // Deliberately NO SecretString and NO GenerateSecretString (see above).
    resources[L[key]] = retained('AWS::SecretsManager::Secret', {
      Name: n.secrets[key],
      Description: `${SECRET_DESCRIPTIONS[key]} (${environment}). Created empty by ssd-onboard; the value is put out of band and never appears in a template, plan or log.`,
      Tags: tags
    });
  }

  for (const role of ['ci', 'interactions']) {
    resources[L[`${role}LogGroup`]] = retained('AWS::Logs::LogGroup', {
      LogGroupName: n.logGroups[role],
      RetentionInDays: LOG_RETENTION_DAYS,
      Tags: tags
    });
    const trust = executionTrustPolicy();
    const permissions = executionRolePolicy(role, environment, target);
    resources[L[`${role}Role`]] = retained('AWS::IAM::Role', {
      RoleName: n.roles[role],
      Path: '/',
      Description: `ssd-onboard ${environment} break-glass ${role === 'ci' ? 'CI broker' : 'interaction'} function execution role`,
      AssumeRolePolicyDocument: trust,
      Policies: [{ PolicyName: n.rolePolicies[role], PolicyDocument: permissions }],
      Tags: tags
    });
    policies[L[`${role}Role`]] = { role, arn: a.roles[role], trust, permissions };
  }

  const fn = (role, variables, extra = {}) => ({
    ...retained('AWS::Lambda::Function', {
      FunctionName: n.functions[role],
      Description: `ssd-onboard ${environment} break-glass ${role === 'ci' ? 'CI broker (IAM invoke only, no URL)' : 'Slack interaction handler'}`,
      Role: arnOf(L[`${role}Role`]),
      Runtime: LAMBDA_RUNTIME,
      Architectures: [LAMBDA_ARCHITECTURE],
      Handler: HANDLERS[role],
      MemorySize: LAMBDA_MEMORY_MB,
      Timeout: LAMBDA_TIMEOUT_SECONDS,
      Code: { S3Bucket: env.artifact.bucket, S3Key: env.artifact.key, S3ObjectVersion: env.artifact.versionId },
      Environment: { Variables: variables },
      ...extra,
      Tags: tags
    }),
    DependsOn: [L[`${role}LogGroup`]]
  });
  resources[L.ciFunction] = fn('ci', {
    TABLE_NAME: n.table,
    SLACK_CHANNEL_ID: env.slackChannelId,
    // Phase 3D: selects this environment's framework policy parameter.
    BREAK_GLASS_ENVIRONMENT: environment,
    SLACK_BOT_TOKEN_SECRET_ARN: ref(L.slackBotToken)
  });
  resources[L.interactionsFunction] = fn('interactions', {
    TABLE_NAME: n.table,
    BREAK_GLASS_ENVIRONMENT: environment,
    SLACK_BOT_TOKEN_SECRET_ARN: ref(L.slackBotToken),
    SLACK_SIGNING_SECRET_ARN: ref(L.slackSigningSecret),
    GITHUB_TOKEN_SECRET_ARN: ref(L.githubToken)
  }, { ReservedConcurrentExecutions: INTERACTIONS_RESERVED_CONCURRENCY });

  resources[L.url] = retained('AWS::Lambda::Url', { TargetFunctionArn: arnOf(L.interactionsFunction), AuthType: 'NONE' });
  resources[L.urlPermission] = retained('AWS::Lambda::Permission', {
    FunctionName: ref(L.interactionsFunction),
    Action: 'lambda:InvokeFunctionUrl',
    Principal: '*',
    FunctionUrlAuthType: 'NONE'
  });
  resources[L.urlInvokePermission] = retained('AWS::Lambda::Permission', {
    FunctionName: ref(L.interactionsFunction),
    Action: 'lambda:InvokeFunction',
    Principal: '*',
    InvokedViaFunctionUrl: true
  });
  resources[L.eventInvokeConfig] = retained('AWS::Lambda::EventInvokeConfig', {
    FunctionName: ref(L.interactionsFunction),
    Qualifier: '$LATEST',
    MaximumRetryAttempts: 0,
    MaximumEventAgeInSeconds: 900
  });

  return { template: template(`ssd-onboard shared break-glass broker (${environment})`, resources), policies };
}
