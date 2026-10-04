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
import { BREAK_GLASS_ENVIRONMENTS, DELIVERY_ENVIRONMENT, STACK_NAME, canonicalSlug } from '../stack-names.mjs';
import { tagList } from './oidc-provider.mjs';
import { absent, present, read, unverified } from './result.mjs';

export const SSD_TAGS = Object.freeze({
  framework: ['ssd:framework', 'ssd-security-framework'],
  managedBy: ['ssd:managed-by', 'ssd-onboard'],
  consumer: 'ssd:consumer-repository',
  environment: 'ssd:environment'
});
// Only settled, successful stack states. Anything else — in progress, failed,
// rolled back after create, being deleted — proves no ownership.
export const LIVE = new Set(['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_COMPLETE']);

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
export function evaluateOwnership({ discovered, resourceTags = null, expectedType, slug, scope, expectedStackName, region = null, environment = null }) {
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
  reasons.push(...stackTagProblems(st.tags, { scope, slug, environment }));
  const stackEnvironment = tagValue(st.tags, SSD_TAGS.environment);
  const expectedConsumer = scope === 'repo' ? canonicalSlug(slug) : null;
  const resourceConsumer = resourceTags ? tagValue(resourceTags, SSD_TAGS.consumer) : undefined;
  if (scope === 'repo' && resourceConsumer !== undefined && resourceConsumer.toLowerCase() !== expectedConsumer) {
    reasons.push(`the resource's own ${SSD_TAGS.consumer} tag is '${resourceConsumer}' (expected '${expectedConsumer}')`);
  }
  if (reasons.length > 0) {
    return { ownership: 'exists-not-owned', reasons, stack: { ...sr, status: st.status } };
  }
  return { ownership: 'managed', reasons: [`physical resource ${sr.logicalId} of stack ${st.name}${where} (${st.status}), tagged for ${scope === 'repo' ? slug : scope === 'break-glass' ? 'the break-glass scope' : 'the shared scope'} (${stackEnvironment})`], stack: { ...sr, status: st.status } };
}

// The stack-tag half of ownership, shared by doctor (evaluateOwnership) and
// plan (planStack). -> reasons[] (empty when the tags prove SSD ownership).
//
// The expected ssd:environment is `production` for every Phase 2 scope; a
// break-glass stack must carry exactly its own environment (production or
// synthetic) — a synthetic-tagged stack is never the production owner, and
// the reverse. A break-glass scope without a valid environment proves nothing.
export function stackTagProblems(tags, { scope, slug, environment = null }) {
  const reasons = [];
  for (const [key, value] of [SSD_TAGS.framework, SSD_TAGS.managedBy]) {
    if (tagValue(tags, key) !== value) {
      reasons.push(`stack tag ${key} is ${tagValue(tags, key) === undefined ? 'missing' : `'${tagValue(tags, key)}'`} (expected '${value}')`);
    }
  }
  const expected = scope === 'break-glass' ? (BREAK_GLASS_ENVIRONMENTS.includes(environment) ? environment : null) : DELIVERY_ENVIRONMENT;
  const tagged = tagValue(tags, SSD_TAGS.environment);
  if (expected === null) {
    reasons.push(`no break-glass environment was given, so stack tag ${SSD_TAGS.environment} cannot prove ownership`);
  } else if (tagged !== expected) {
    reasons.push(`stack tag ${SSD_TAGS.environment} is ${tagged === undefined ? 'missing' : `'${tagged}'`} (expected '${expected}')`);
  }
  const consumer = tagValue(tags, SSD_TAGS.consumer);
  if (scope === 'repo') {
    const canonical = canonicalSlug(slug);
    if (consumer !== canonical) {
      reasons.push(`stack tag ${SSD_TAGS.consumer} is ${consumer === undefined ? 'missing' : `'${consumer}'`} (expected '${canonical}')`);
    }
  } else if (scope === 'break-glass' && consumer !== undefined) {
    // A break-glass stack is shared: it is never one repository's.
    reasons.push(`stack tag ${SSD_TAGS.consumer} is '${consumer}', but a break-glass stack is shared and names no consumer repository`);
  }
  return reasons;
}

// --- planning (Phase 2B) -------------------------------------------------------------

// `describe-stacks --stack-name <exact name>` -> present | absent | unverified.
// CloudFormation answers a missing stack with ValidationError "Stack with id
// <name> does not exist"; that exact answer, and only it, is absence.
const NO_SUCH_STACK = /^Stack with id \S+ does not exist$/;
export async function discoverStackByName(aws, name) {
  const got = await read(aws, ['cloudformation', 'describe-stacks', '--stack-name', name]);
  if (got.state === 'unverified' && got.error.code === 'ValidationError' && NO_SUCH_STACK.test(got.error.message ?? '')) {
    return absent('NoSuchStack');
  }
  if (got.state !== 'present') {
    return got;
  }
  const stacks = Array.isArray(got.value.Stacks) ? got.value.Stacks : null;
  if (!stacks || stacks.length !== 1 || typeof stacks[0]?.StackId !== 'string' || typeof stacks[0]?.StackStatus !== 'string') {
    return unverified({ kind: 'malformed-response', operation: 'cloudformation describe-stacks', message: 'describe-stacks did not return exactly one stack with an id and a status' });
  }
  const s = stacks[0];
  return present({
    stackId: s.StackId,
    name: s.StackName ?? null,
    status: s.StackStatus,
    tags: tagList(s.Tags),
    lastUpdatedTime: typeof s.LastUpdatedTime === 'string' ? s.LastUpdatedTime : null
  });
}

// `describe-stack-resources --stack-name <name>` -> result whose value is
// [{ logicalId, physicalId, type, status }].
export async function discoverStackResources(aws, name) {
  const got = await read(aws, ['cloudformation', 'describe-stack-resources', '--stack-name', name]);
  if (got.state !== 'present') {
    return got;
  }
  if (!Array.isArray(got.value.StackResources)) {
    return unverified({ kind: 'malformed-response', operation: 'cloudformation describe-stack-resources', message: 'StackResources is not a list' });
  }
  return present(
    got.value.StackResources.map((r) => ({
      logicalId: String(r?.LogicalResourceId ?? ''),
      physicalId: r?.PhysicalResourceId ?? null,
      type: String(r?.ResourceType ?? ''),
      status: r?.ResourceStatus ?? null
    }))
  );
}

// Pure. What kind of change set may be created against the expected stack?
//   absent                                    -> CREATE, baseStack { state: 'absent' }
//   REVIEW_IN_PROGRESS, SSD-tagged            -> CREATE (the placeholder an
//                                                earlier unexecuted CREATE change
//                                                set left; it holds no resources)
//   settled successful state, SSD-tagged      -> UPDATE
//   anything else                             -> blocked (never UPDATE an
//                                                unowned or unsettled stack)
// Returns { type, baseStack, problems[] }; type is null when blocked.
export function planStack({ stack, expectedStackName, scope, slug, environment = null }) {
  if (typeof expectedStackName !== 'string' || !STACK_NAME.test(expectedStackName)) {
    throw new Error('planStack: an expected stack name is required');
  }
  if (stack.state === 'unverified') {
    return { type: null, baseStack: null, problems: [`stack ${expectedStackName} could not be looked up (${stack.error.code ?? stack.error.kind}: ${stack.error.message})`] };
  }
  if (stack.state === 'absent') {
    return { type: 'CREATE', baseStack: { state: 'absent' }, problems: [] };
  }
  const st = stack.value;
  const baseStack = { state: 'present', stackId: st.stackId, stackStatus: st.status, lastUpdatedTime: st.lastUpdatedTime };
  const problems = [];
  if (st.name !== expectedStackName) {
    problems.push(`describe-stacks returned stack '${st.name}', not '${expectedStackName}'`);
  }
  const tagReasons = stackTagProblems(st.tags, { scope, slug, environment });
  if (tagReasons.length > 0) {
    problems.push(`stack ${expectedStackName} exists but is NOT an ssd-onboard stack for this ${scope === 'repo' ? 'repository' : scope === 'break-glass' ? `break-glass environment (${environment})` : 'scope'}: ${tagReasons.join('; ')}. It is never updated or adopted`);
  }
  if (st.status !== 'REVIEW_IN_PROGRESS' && !LIVE.has(st.status)) {
    problems.push(`stack ${expectedStackName} is ${st.status}: only an absent stack, an ssd-onboard REVIEW_IN_PROGRESS placeholder or a settled, successful stack can be planned`);
  }
  if (problems.length > 0) {
    return { type: null, baseStack, problems };
  }
  return { type: st.status === 'REVIEW_IN_PROGRESS' ? 'CREATE' : 'UPDATE', baseStack, problems };
}
