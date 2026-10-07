// What each planned stack may contain — the repo/shared boundary.
//
// A plan unit is exactly one stack. Each stack kind names the ONLY logical
// resources (id -> type) it may hold. The boundary is enforced twice:
//   assertTemplateScope   on the rendered template, BEFORE validate-template /
//                         create-change-set;
//   assertChangeScope     on what describe-change-set says CloudFormation will
//                         do, so an unexpected change AWS reports (a resource
//                         added to the stack out of band, a different type)
//                         fails the plan instead of being recorded.
//
// Repo scope NEVER holds the GitHub OIDC provider, the registry scanning
// configuration, Inspector enablement or break-glass resources. Shared scope
// NEVER holds a per-repository ECR repository or IAM role. Registry scanning
// has no stack kind in Phase 2B (see plan.mjs): it is reported, never planned.
//
// Break-glass scope (Phase 3C) is the ONE narrow exception to "shared stacks
// hold no IAM role": the two named kinds break-glass-production and
// break-glass-synthetic may hold exactly their two Lambda execution roles
// (and their functions, table, secrets and log groups) — nothing else, and no
// other shared kind gains IAM roles. A break-glass kind never holds a
// per-repository resource (ECR repository, invoker role) or an account-level
// one (the OIDC provider, registry scanning, Inspector).
//
// Break-glass governance (Phase 3D): the two kinds break-glass-governance-
// production and break-glass-governance-synthetic hold exactly ONE
// AWS::SSM::Parameter (the environment's allowed framework commits) and
// nothing else — no role, no function, no other parameter.
import { GOVERNANCE_RESOURCE_TYPES } from '../templates/break-glass-governance.mjs';
import { BREAK_GLASS_RESOURCE_TYPES } from '../templates/shared-break-glass.mjs';
import { REPO_LOGICAL_IDS } from '../templates/repo-ecr-delivery.mjs';
import { OIDC_LOGICAL_ID } from '../templates/shared-github-oidc.mjs';

export class ScopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScopeError';
    this.kind = 'scope-violation';
  }
}

export const STACK_KINDS = Object.freeze({
  repo: Object.freeze({
    scope: 'repo',
    resources: Object.freeze({
      [REPO_LOGICAL_IDS.repository]: 'AWS::ECR::Repository',
      [REPO_LOGICAL_IDS.push]: 'AWS::IAM::Role',
      [REPO_LOGICAL_IDS.deploy]: 'AWS::IAM::Role'
    })
  }),
  'shared-github-oidc': Object.freeze({
    scope: 'shared',
    resources: Object.freeze({ [OIDC_LOGICAL_ID]: 'AWS::IAM::OIDCProvider' })
  }),
  'break-glass-production': Object.freeze({ scope: 'break-glass', environment: 'production', resources: BREAK_GLASS_RESOURCE_TYPES }),
  'break-glass-synthetic': Object.freeze({ scope: 'break-glass', environment: 'synthetic', resources: BREAK_GLASS_RESOURCE_TYPES }),
  'break-glass-governance-production': Object.freeze({ scope: 'break-glass', family: 'governance', environment: 'production', resources: GOVERNANCE_RESOURCE_TYPES }),
  'break-glass-governance-synthetic': Object.freeze({ scope: 'break-glass', family: 'governance', environment: 'synthetic', resources: GOVERNANCE_RESOURCE_TYPES })
});

// Resource types that are shared by nature: never in a repo-scope stack, even
// if a future edit added them to the table above.
const SHARED_ONLY = /^AWS::(?:IAM::OIDCProvider|ECR::RegistryScanningConfiguration|ECR::RegistryPolicy|ECR::ReplicationConfiguration|ECR::PullThroughCacheRule|InspectorV2::.+|Inspector::.+|Lambda::.+|DynamoDB::.+|SecretsManager::.+)$/;
// Resource types that are per repository by nature: never in a shared stack.
const REPO_ONLY = /^AWS::(?:ECR::Repository|IAM::Role)$/;
// The only resource types a break-glass stack may hold. IAM::Role is here and
// ONLY here among the shared kinds. Like REPO_ONLY / SHARED_ONLY this is
// defense in depth: today every kind's exact logicalId -> type table already
// refuses a foreign type; these guards hold if a future edit widens a table.
const BREAK_GLASS_ONLY = /^AWS::(?:DynamoDB::Table|SecretsManager::Secret|Logs::LogGroup|IAM::Role|Lambda::(?:Function|Url|Permission|EventInvokeConfig))$/;
// The only resource type a governance stack may hold.
const GOVERNANCE_ONLY = /^AWS::SSM::Parameter$/;

const TEMPLATE_KEYS = new Set(['AWSTemplateFormatVersion', 'Description', 'Resources']);

function kindOf(stackKind) {
  const kind = Object.hasOwn(STACK_KINDS, stackKind) ? STACK_KINDS[stackKind] : null;
  if (!kind) {
    throw new ScopeError(`unknown stack kind '${stackKind}'`);
  }
  return kind;
}

function assertType(kind, stackKind, logicalId, type, where) {
  if (kind.scope === 'repo' && SHARED_ONLY.test(type)) {
    throw new ScopeError(`${where}: ${logicalId} is ${type}, a shared resource; a repo-scope plan never contains it`);
  }
  if (kind.family === 'governance' && !GOVERNANCE_ONLY.test(type)) {
    throw new ScopeError(`${where}: ${logicalId} is ${type}; a break-glass governance stack holds only its allowed-commit parameter`);
  }
  if (kind.scope === 'break-glass' && !kind.family && !BREAK_GLASS_ONLY.test(type)) {
    throw new ScopeError(`${where}: ${logicalId} is ${type}; a break-glass stack holds only its functions, table, secrets, log groups and execution roles`);
  }
  if (kind.scope === 'shared' && REPO_ONLY.test(type)) {
    throw new ScopeError(`${where}: ${logicalId} is ${type}, a per-repository resource; a shared-scope plan never contains it`);
  }
  if (!Object.hasOwn(kind.resources, logicalId) || kind.resources[logicalId] !== type) {
    throw new ScopeError(`${where}: ${logicalId} (${type}) is not a resource the ${stackKind} stack may hold`);
  }
}

// The rendered template: only the allowed logical resources, each retained,
// and nothing that could run code or pull in other content (no Transform,
// Parameters, Conditions, Outputs, Mappings, Metadata or nested stacks).
export function assertTemplateScope(stackKind, template) {
  const kind = kindOf(stackKind);
  for (const key of Object.keys(template)) {
    if (!TEMPLATE_KEYS.has(key)) {
      throw new ScopeError(`template: top-level '${key}' is not allowed in a generated template`);
    }
  }
  const resources = Object.entries(template.Resources ?? {});
  if (resources.length === 0) {
    throw new ScopeError('template: no resources');
  }
  for (const [logicalId, resource] of resources) {
    assertType(kind, stackKind, logicalId, resource?.Type, 'template');
    if (resource.DeletionPolicy !== 'Retain' || resource.UpdateReplacePolicy !== 'Retain') {
      throw new ScopeError(`template: ${logicalId} must carry DeletionPolicy: Retain and UpdateReplacePolicy: Retain`);
    }
  }
}

// The classified changes (plan/change-set.mjs) of a described change set.
export function assertChangeScope(stackKind, changes) {
  const kind = kindOf(stackKind);
  for (const change of changes) {
    assertType(kind, stackKind, change.logicalId, change.type, 'change set');
  }
}
