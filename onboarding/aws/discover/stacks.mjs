// Ownership: EXISTENCE IS NOT OWNERSHIP.
//
// A resource is `managed` only when ALL of these hold:
//   - CloudFormation reports it as a physical resource, of the expected
//     resource type, of THE expected stack — the exact derived name from
//     stack-names.mjs, in delivery.aws.region. Another ssd-onboard stack, even
//     a correctly tagged one, is not this repository's or scope's owner;
//   - that stack is in a settled, successful state (CREATE_COMPLETE,
//     UPDATE_COMPLETE, UPDATE_ROLLBACK_COMPLETE, IMPORT_COMPLETE,
//     IMPORT_ROLLBACK_COMPLETE) and its
//     stack tags carry ssd:framework=ssd-security-framework,
//     ssd:managed-by=ssd-onboard, ssd:environment=production and, for
//     per-repository resources, ssd:consumer-repository=<canonical owner/repo>;
//   - the resource's own tags, when readable, do not name another consumer.
// The stack name LOCATES the owner; it never proves ownership on its own. A
// resource with the right name — or even the right tags — but not in the
// expected stack is `exists-not-owned`. Nothing is adopted, or inferred, by
// name or ARN.
import { DELIVERY_ENVIRONMENT, STACK_NAME, canonicalSlug } from '../stack-names.mjs';
import { tagList } from './oidc-provider.mjs';
import { read } from './result.mjs';

export const SSD_TAGS = Object.freeze({
  framework: ['ssd:framework', 'ssd-security-framework'],
  managedBy: ['ssd:managed-by', 'ssd-onboard'],
  consumer: 'ssd:consumer-repository',
  environment: 'ssd:environment'
});
// Only settled, successful stack states. Anything else — in progress, failed,
// rolled back after create, being deleted — proves no ownership.
const LIVE = new Set(['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_COMPLETE']);

// -> { stackResource: result, stack: result|null }
export async function discoverStack(aws, physicalId) {
  const resources = await read(aws, ['cloudformation', 'describe-stack-resources', '--physical-resource-id', physicalId], { notFound: ['ValidationError'] });
  if (resources.state !== 'present') {
    return { stackResource: resources, stack: null };
  }
  const entry = (Array.isArray(resources.value.StackResources) ? resources.value.StackResources : []).find((r) => r?.PhysicalResourceId === physicalId) ?? null;
  if (!entry) {
    return { stackResource: { state: 'absent', code: 'NotReturned' }, stack: null };
  }
  const stack = await read(aws, ['cloudformation', 'describe-stacks', '--stack-name', String(entry.StackId ?? entry.StackName)], { notFound: ['ValidationError'] });
  const s = stack.state === 'present' ? (Array.isArray(stack.value.Stacks) ? stack.value.Stacks[0] : null) : null;
  return {
    stackResource: { state: 'present', value: { stackName: entry.StackName ?? null, stackId: entry.StackId ?? null, logicalId: entry.LogicalResourceId ?? null, type: entry.ResourceType ?? null } },
    stack: stack.state === 'present' ? (s ? { state: 'present', value: { name: s.StackName ?? null, status: s.StackStatus ?? null, tags: tagList(s.Tags) } } : { state: 'absent', code: 'NotReturned' }) : stack
  };
}

const tagValue = (tags, key) => tags.find((t) => t.key === key)?.value;

// Pure. -> { ownership: 'managed'|'exists-not-owned'|'unverified', reasons[], stack }
// scope 'repo' requires the consumer tag; 'shared' must not be tied to one.
// expectedStackName is mandatory: without it no ownership can be concluded.
// region: where the lookup ran (delivery.aws.region). CloudFormation stacks are
// regional while IAM roles and OIDC providers are global, so a conclusion names
// the region it is about (L2).
export function evaluateOwnership({ discovered, resourceTags = null, expectedType, slug, scope, expectedStackName, region = null }) {
  if (typeof expectedStackName !== 'string' || !STACK_NAME.test(expectedStackName)) {
    throw new Error('evaluateOwnership: an expected stack name is required');
  }
  const { stackResource, stack } = discovered;
  const reasons = [];
  const where = region ? ` in ${region}` : '';
  const globalNote = region && expectedType.startsWith('AWS::IAM::')
    ? `IAM resources are global but stacks are regional: only ${region} (delivery.aws.region, where ssd-onboard's stacks live) was searched`
    : null;
  const ssdTagged = resourceTags && resourceTags.some((t) => t.key.startsWith('ssd:'));
  if (stackResource.state === 'unverified') {
    return { ownership: 'unverified', reasons: [`the owning CloudFormation stack could not be looked up${where}`], stack: null, error: stackResource.error };
  }
  if (stackResource.state === 'absent') {
    reasons.push(`not a physical resource of any CloudFormation stack${where}`);
    if (globalNote) {
      reasons.push(globalNote);
    }
    if (ssdTagged) {
      reasons.push('it carries ssd:* tags, but tags without a stack relationship do not prove ownership');
    }
    return { ownership: 'exists-not-owned', reasons, stack: null };
  }
  const sr = stackResource.value;
  if (sr.type !== expectedType) {
    reasons.push(`the stack resource is ${sr.type}, not ${expectedType}`);
  }
  if (!stack || stack.state === 'unverified') {
    return { ownership: 'unverified', reasons: [`stack ${sr.stackName} could not be described`], stack: sr, error: stack?.error ?? null };
  }
  if (stack.state === 'absent') {
    return { ownership: 'exists-not-owned', reasons: [...reasons, `stack ${sr.stackName} was not returned`], stack: sr };
  }
  const st = stack.value;
  if (sr.stackName !== expectedStackName || st.name !== expectedStackName) {
    reasons.push(`it belongs to stack '${sr.stackName}'${where}, not the expected stack '${expectedStackName}'`);
  }
  if (!LIVE.has(st.status)) {
    reasons.push(`stack ${st.name} is ${st.status ?? 'in an unknown state'} (not a settled, successful state)`);
  }
  for (const [key, value] of [SSD_TAGS.framework, SSD_TAGS.managedBy]) {
    if (tagValue(st.tags, key) !== value) {
      reasons.push(`stack tag ${key} is ${tagValue(st.tags, key) === undefined ? 'missing' : `'${tagValue(st.tags, key)}'`} (expected '${value}')`);
    }
  }
  const environment = tagValue(st.tags, SSD_TAGS.environment);
  if (environment !== DELIVERY_ENVIRONMENT) {
    reasons.push(`stack tag ${SSD_TAGS.environment} is ${environment === undefined ? 'missing' : `'${environment}'`} (expected '${DELIVERY_ENVIRONMENT}')`);
  }
  const canonical = canonicalSlug(slug);
  const consumer = tagValue(st.tags, SSD_TAGS.consumer);
  if (scope === 'repo' && consumer !== canonical) {
    reasons.push(`stack tag ${SSD_TAGS.consumer} is ${consumer === undefined ? 'missing' : `'${consumer}'`} (expected '${canonical}')`);
  }
  const resourceConsumer = resourceTags ? tagValue(resourceTags, SSD_TAGS.consumer) : undefined;
  if (scope === 'repo' && resourceConsumer !== undefined && resourceConsumer.toLowerCase() !== canonical) {
    reasons.push(`the resource's own ${SSD_TAGS.consumer} tag is '${resourceConsumer}' (expected '${canonical}')`);
  }
  if (reasons.length > 0) {
    return { ownership: 'exists-not-owned', reasons, stack: { ...sr, status: st.status } };
  }
  return { ownership: 'managed', reasons: [`physical resource ${sr.logicalId} of stack ${st.name}${where} (${st.status}), tagged for ${scope === 'repo' ? slug : 'the shared scope'} (${environment})`], stack: { ...sr, status: st.status } };
}
