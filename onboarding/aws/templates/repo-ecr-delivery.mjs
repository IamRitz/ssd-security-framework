// The per-repository delivery stack (ssd-delivery-<display>-<h8>): the ECR
// repository and the push+scan and deploy roles — each ONLY when its
// configured ownership is `managed`. An `existing` resource never appears here.
//
// It never contains the account's GitHub OIDC provider, the registry scanning
// configuration, Inspector enablement or break-glass resources (asserted by
// plan/scope.mjs before create-change-set and again on the described changes).
//
// Policies come from the canonical builders — trust from policy/trust.mjs,
// permissions from policy/permissions.mjs — which refuse to return a document
// the doctor's own evaluators would not accept.
import { roleName } from '../discover/iam-role.mjs';
import { rolePolicyDocument } from '../policy/permissions.mjs';
import { buildTrustPolicy } from '../policy/trust.mjs';
import { retained, ssdTags, template } from './common.mjs';

export const REPO_LOGICAL_IDS = Object.freeze({ repository: 'EcrRepository', push: 'PushScanRole', deploy: 'DeployRole' });
export const ROLE_POLICY_NAMES = Object.freeze({ push: 'ssd-push-scan', deploy: 'ssd-deploy' });

// arn:aws:iam::<acct>:role/<path/>name -> '/<path/>'
export function rolePath(arn) {
  const resource = arn.split(':role')[1] ?? '/';
  const path = resource.slice(0, resource.lastIndexOf('/') + 1);
  return path || '/';
}

// -> { template, policies: { PushScanRole?: { trust, permissions }, DeployRole?: … } }
export function renderRepoTemplate({ config, partition, enhanced }) {
  const d = config.delivery;
  const slug = config.repository.slug;
  const account = d.aws.accountId;
  const tags = ssdTags({ scope: 'repo', slug });
  const target = { partition, account, region: d.aws.region, repository: d.ecr.repository, instanceId: d.ssm.instanceId };
  const resources = {};
  const policies = {};
  if (d.ecr.ownership === 'managed') {
    resources[REPO_LOGICAL_IDS.repository] = retained('AWS::ECR::Repository', {
      RepositoryName: d.ecr.repository,
      ImageTagMutability: 'IMMUTABLE',
      // Repository-level scan-on-push (BASIC). Registry-wide scanning is a
      // separate, shared control this stack never touches.
      ImageScanningConfiguration: { ScanOnPush: true },
      EncryptionConfiguration: { EncryptionType: 'AES256' },
      Tags: tags
    });
  }
  for (const [key, arn, mode, description] of [
    ['push', d.roles.pushScanRoleArn, d.roles.pushScanOwnership, `ssd-onboard push+scan role for ${slug}: ECR push to ${d.ecr.repository} and its scan results`],
    ['deploy', d.roles.deployRoleArn, d.roles.deployOwnership, `ssd-onboard deploy role for ${slug}: SSM RunShellScript on ${d.ssm.instanceId}`]
  ]) {
    if (mode !== 'managed') {
      continue;
    }
    const trust = buildTrustPolicy(key, { account, partition, slug, defaultBranch: config.repository.defaultBranch, environment: d.environment });
    const permissions = rolePolicyDocument(key, target, { enhanced });
    resources[REPO_LOGICAL_IDS[key]] = retained('AWS::IAM::Role', {
      RoleName: roleName(arn),
      Path: rolePath(arn),
      Description: description,
      AssumeRolePolicyDocument: trust,
      Policies: [{ PolicyName: ROLE_POLICY_NAMES[key], PolicyDocument: permissions }],
      Tags: tags
    });
    policies[REPO_LOGICAL_IDS[key]] = { role: key, arn, trust, permissions };
  }
  return { template: template(`ssd-onboard per-repository delivery resources for ${slug}`, resources), policies };
}
