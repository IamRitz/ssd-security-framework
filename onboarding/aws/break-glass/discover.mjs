// Break-glass discovery (Phase 3C): read-only answers about one environment's
// resources and its published artifact. Every function returns the shared
// result shape (discover/result.mjs) — present | absent | unverified — so an
// AccessDenied is never absence. Each read names the not-found codes that mean
// absence for THAT call and nothing else.
//
// Nothing here reads a secret value (describe-secret is metadata only) or a
// function's code (get-function-configuration, never get-function).
import { tagList } from '../discover/oidc-provider.mjs';
import { absent, present, read, unverified } from '../discover/result.mjs';

const malformed = (operation, message) => unverified({ kind: 'malformed-response', operation, message });

// -> { name, arn, status, keySchema, attributes, billingMode, deletionProtection, tags }
export async function discoverTable(aws, name) {
  const got = await read(aws, ['dynamodb', 'describe-table', '--table-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  const t = got.value.Table;
  if (!t || typeof t.TableArn !== 'string') return malformed('dynamodb describe-table', 'no Table/TableArn in the answer');
  return present({
    name: t.TableName ?? null,
    arn: t.TableArn,
    status: t.TableStatus ?? null,
    keySchema: Array.isArray(t.KeySchema) ? t.KeySchema.map((k) => ({ name: k?.AttributeName ?? null, type: k?.KeyType ?? null })) : null,
    attributes: Array.isArray(t.AttributeDefinitions) ? t.AttributeDefinitions.map((d) => ({ name: d?.AttributeName ?? null, type: d?.AttributeType ?? null })) : null,
    billingMode: t.BillingModeSummary?.BillingMode ?? null,
    deletionProtection: typeof t.DeletionProtectionEnabled === 'boolean' ? t.DeletionProtectionEnabled : null,
    indexes: [...(t.GlobalSecondaryIndexes ?? []), ...(t.LocalSecondaryIndexes ?? [])].map((i) => i?.IndexName ?? '?')
  });
}

// -> { status, attribute }   (status: ENABLED | ENABLING | DISABLED | DISABLING)
export async function discoverTimeToLive(aws, name) {
  const got = await read(aws, ['dynamodb', 'describe-time-to-live', '--table-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  const d = got.value.TimeToLiveDescription;
  if (!d || typeof d.TimeToLiveStatus !== 'string') return malformed('dynamodb describe-time-to-live', 'no TimeToLiveDescription.TimeToLiveStatus');
  return present({ status: d.TimeToLiveStatus, attribute: typeof d.AttributeName === 'string' ? d.AttributeName : null });
}

export async function discoverBackups(aws, name) {
  const got = await read(aws, ['dynamodb', 'describe-continuous-backups', '--table-name', name], { notFound: ['ResourceNotFoundException', 'TableNotFoundException'] });
  if (got.state !== 'present') return got;
  const pitr = got.value.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus;
  return typeof pitr === 'string' ? present({ pointInTimeRecovery: pitr }) : malformed('dynamodb describe-continuous-backups', 'no PointInTimeRecoveryStatus');
}

// -> configuration of a function; never its code.
export async function discoverFunction(aws, name) {
  const got = await read(aws, ['lambda', 'get-function-configuration', '--function-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  const f = got.value;
  if (typeof f.FunctionArn !== 'string') return malformed('lambda get-function-configuration', 'no FunctionArn');
  return present({
    name: f.FunctionName ?? null,
    arn: f.FunctionArn,
    role: f.Role ?? null,
    runtime: f.Runtime ?? null,
    handler: f.Handler ?? null,
    architectures: Array.isArray(f.Architectures) ? f.Architectures : null,
    memorySize: f.MemorySize ?? null,
    timeout: f.Timeout ?? null,
    codeSha256: typeof f.CodeSha256 === 'string' ? f.CodeSha256 : null,
    packageType: f.PackageType ?? null,
    layers: Array.isArray(f.Layers) ? f.Layers.map((l) => l?.Arn ?? '?') : [],
    // Values are identifiers only (table, channel, secret ARNs, environment):
    // the template never puts a secret value in a function's environment.
    variables: f.Environment?.Variables && typeof f.Environment.Variables === 'object' ? { ...f.Environment.Variables } : {},
    vpc: f.VpcConfig && ((f.VpcConfig.SubnetIds ?? []).length > 0 || (f.VpcConfig.SecurityGroupIds ?? []).length > 0) ? f.VpcConfig : null,
    state: f.State ?? null
  });
}

export async function discoverFunctionUrl(aws, name) {
  const got = await read(aws, ['lambda', 'get-function-url-config', '--function-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  return present({ url: got.value.FunctionUrl ?? null, authType: got.value.AuthType ?? null, functionArn: got.value.FunctionArn ?? null });
}

// The function's resource-based policy, parsed. absent = no policy at all.
export async function discoverFunctionPolicy(aws, name) {
  const got = await read(aws, ['lambda', 'get-policy', '--function-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  try {
    const doc = JSON.parse(got.value.Policy);
    return present({ statements: Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement] });
  } catch {
    return malformed('lambda get-policy', 'the policy is not JSON');
  }
}

export async function discoverConcurrency(aws, name) {
  const got = await read(aws, ['lambda', 'get-function-concurrency', '--function-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  return present({ reserved: Number.isInteger(got.value.ReservedConcurrentExecutions) ? got.value.ReservedConcurrentExecutions : null });
}

export async function discoverEventInvokeConfig(aws, name) {
  const got = await read(aws, ['lambda', 'get-function-event-invoke-config', '--function-name', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  return present({ maximumRetryAttempts: got.value.MaximumRetryAttempts ?? null, maximumEventAgeInSeconds: got.value.MaximumEventAgeInSeconds ?? null });
}

// Secret METADATA. `populated` is whether any version carries AWSCURRENT —
// learned from the version-stage map, never by reading the value.
export async function discoverSecret(aws, name) {
  const got = await read(aws, ['secretsmanager', 'describe-secret', '--secret-id', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  const s = got.value;
  if (typeof s.ARN !== 'string') return malformed('secretsmanager describe-secret', 'no ARN');
  const stages = s.VersionIdsToStages && typeof s.VersionIdsToStages === 'object' ? Object.values(s.VersionIdsToStages).flat() : [];
  return present({
    name: s.Name ?? null,
    arn: s.ARN,
    tags: tagList(s.Tags),
    populated: stages.includes('AWSCURRENT'),
    deletedDate: s.DeletedDate ?? null,
    rotationEnabled: s.RotationEnabled === true
  });
}

export async function discoverLogGroup(aws, name) {
  const got = await read(aws, ['logs', 'describe-log-groups', '--log-group-name-prefix', name], { notFound: ['ResourceNotFoundException'] });
  if (got.state !== 'present') return got;
  const groups = Array.isArray(got.value.logGroups) ? got.value.logGroups : null;
  if (!groups) return malformed('logs describe-log-groups', 'logGroups is not a list');
  const g = groups.find((x) => x?.logGroupName === name);
  return g ? present({ name, arn: g.arn ?? null, retentionInDays: g.retentionInDays ?? null }) : absent('NotListed');
}

// The published artifact: object VERSION metadata, never the object.
export async function discoverArtifact(aws, artifact) {
  const head = await read(aws, ['s3api', 'head-object', '--bucket', artifact.bucket, '--key', artifact.key, '--version-id', artifact.versionId, '--checksum-mode', 'ENABLED']);
  const versioning = await read(aws, ['s3api', 'get-bucket-versioning', '--bucket', artifact.bucket]);
  let publicAccess = await read(aws, ['s3api', 'get-public-access-block', '--bucket', artifact.bucket]);
  if (publicAccess.state === 'unverified' && publicAccess.error.code === 'NoSuchPublicAccessBlockConfiguration') {
    publicAccess = absent('NoSuchPublicAccessBlockConfiguration');
  }
  let policyStatus = await read(aws, ['s3api', 'get-bucket-policy-status', '--bucket', artifact.bucket]);
  if (policyStatus.state === 'unverified' && policyStatus.error.code === 'NoSuchBucketPolicy') {
    policyStatus = absent('NoSuchBucketPolicy');
  }
  return {
    head: head.state === 'present' ? present({ versionId: head.value.VersionId ?? null, checksumSha256: head.value.ChecksumSHA256 ?? null, checksumType: head.value.ChecksumType ?? null, contentLength: head.value.ContentLength ?? null }) : head,
    versioning: versioning.state === 'present' ? present({ status: versioning.value.Status ?? null }) : versioning,
    publicAccess: publicAccess.state === 'present' ? present({ ...(publicAccess.value.PublicAccessBlockConfiguration ?? {}) }) : publicAccess,
    policyStatus: policyStatus.state === 'present' ? present({ isPublic: policyStatus.value.PolicyStatus?.IsPublic ?? null }) : policyStatus
  };
}
