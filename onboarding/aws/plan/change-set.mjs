// The change-set lifecycle of one plan unit: validate the template, create an
// UNEXECUTED change set, wait for CloudFormation to compute it, and classify
// exactly what it would do. Nothing here can execute it (the planning
// allowlist has no execute-change-set).
//
// Status handling (fail closed on anything not listed):
//   CREATE_PENDING / CREATE_IN_PROGRESS            poll again (bounded backoff,
//                                                  inside the run's deadline)
//   CREATE_COMPLETE + ExecutionStatus AVAILABLE    a reviewable plan
//   FAILED + CloudFormation's no-change reason     outcome no-changes
//   FAILED (any other reason)                      error
//   anything else, or a malformed document         error
//
// Classification uses CloudFormation's own fields: Action (Add / Modify /
// Remove) and, for Modify, Replacement (True / False / Conditional). Import,
// Dynamic and any unknown action fail closed. Conditional replacement is
// counted as REPLACE (it may replace). DELETE and REPLACE are destructive.
import { AwsCliError, redact } from '../aws-cli.mjs';
import { assertChangeScope } from './scope.mjs';

export class ChangeSetError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'ChangeSetError';
    this.kind = kind;
  }
}

// CloudFormation's documented StatusReason for a change set with nothing to
// do. This text is the only signal AWS gives; only these exact forms count.
const NO_CHANGE_REASONS = [
  /^The submitted information didn't contain changes\. Submit different information to create a change set\.$/,
  /^No updates are to be performed\.?$/
];
export const isNoChangeReason = (reason) => typeof reason === 'string' && NO_CHANGE_REASONS.some((re) => re.test(reason.trim()));

const PENDING = new Set(['CREATE_PENDING', 'CREATE_IN_PROGRESS']);
export const POLL_DELAYS_MS = Object.freeze([1_000, 2_000, 3_000, 5_000, 8_000, 10_000]);
export const MAX_POLLS = 60;
const ALLOWED_CAPABILITIES = new Set(['CAPABILITY_NAMED_IAM', 'CAPABILITY_IAM']);
const CHANGE_SET_ARN = /^arn:(aws|aws-cn|aws-us-gov):cloudformation:([a-z0-9-]+):(\d{12}):changeSet\/([A-Za-z][A-Za-z0-9-]*)\/[0-9a-f-]+$/;

export const defaultSleep = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));

// validate-template on the exact body; the template must declare no transform
// and no parameters, and need no capability beyond named IAM.
// -> { capabilities: [] | ['CAPABILITY_NAMED_IAM'] }
export async function validateTemplate(aws, body) {
  let response;
  try {
    response = await aws(['cloudformation', 'validate-template', '--template-body', body]);
  } catch (error) {
    if (error instanceof AwsCliError && error.kind === 'aws-error' && error.code === 'ValidationError') {
      throw new ChangeSetError('template-invalid', `CloudFormation rejected the generated template: ${error.message}`);
    }
    throw error;
  }
  const capabilities = response.Capabilities ?? [];
  const transforms = response.DeclaredTransforms ?? [];
  const parameters = response.Parameters ?? [];
  if (!Array.isArray(capabilities) || !Array.isArray(transforms) || !Array.isArray(parameters)) {
    throw new ChangeSetError('malformed-response', 'validate-template returned an unexpected document');
  }
  if (transforms.length > 0 || parameters.length > 0) {
    throw new ChangeSetError('template-invalid', 'the generated template declares a transform or parameters, which plans never use');
  }
  const unknown = capabilities.filter((c) => !ALLOWED_CAPABILITIES.has(c));
  if (unknown.length > 0) {
    throw new ChangeSetError('template-invalid', `the template requires capabilities [${unknown.join(', ')}], which plans never grant`);
  }
  // Named IAM covers IAM; the planner only ever passes CAPABILITY_NAMED_IAM.
  return { capabilities: capabilities.length > 0 ? ['CAPABILITY_NAMED_IAM'] : [] };
}

// create-change-set. -> { changeSetArn, stackId }
export async function createChangeSet(aws, { stackName, changeSetName, type, body, tags, capabilities, account, region }) {
  const argv = [
    'cloudformation', 'create-change-set',
    '--stack-name', stackName,
    '--change-set-name', changeSetName,
    '--change-set-type', type,
    '--template-body', body,
    '--tags', JSON.stringify(tags),
    ...(capabilities.length > 0 ? ['--capabilities', capabilities[0]] : [])
  ];
  let response;
  try {
    response = await aws(argv);
  } catch (error) {
    if (error instanceof AwsCliError && error.code === 'AlreadyExistsException') {
      throw new ChangeSetError(
        'change-set-exists',
        `a change set named ${changeSetName} already exists on ${stackName}: this exact plan was created before (its local directory is missing). Plan ids are deterministic and change sets are never deleted by ssd-onboard; restore the plan directory, or change an input`
      );
    }
    throw error;
  }
  const match = CHANGE_SET_ARN.exec(String(response.Id ?? ''));
  if (!match || match[2] !== region || match[3] !== account || match[4] !== changeSetName || typeof response.StackId !== 'string') {
    throw new ChangeSetError('malformed-response', 'create-change-set did not return the change set this plan asked for');
  }
  return { changeSetArn: response.Id, stackId: response.StackId };
}

// Poll describe-change-set until it settles. The wrapper's deadline bounds the
// whole wait (a spent budget ends the run as `deadline`); MAX_POLLS bounds it
// independently of the clock.
// -> { described, status: 'complete' | 'no-changes' }
export async function waitForChangeSet(aws, { stackName, changeSetName, sleep = defaultSleep }) {
  for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
    const described = await aws(['cloudformation', 'describe-change-set', '--stack-name', stackName, '--change-set-name', changeSetName]);
    const status = described.Status;
    if (PENDING.has(status)) {
      const delay = POLL_DELAYS_MS[Math.min(attempt, POLL_DELAYS_MS.length - 1)];
      const remaining = typeof aws.remainingMs === 'function' ? aws.remainingMs() : Infinity;
      await sleep(Math.max(0, Math.min(delay, remaining)));
      continue;
    }
    if (status === 'CREATE_COMPLETE') {
      if (described.ExecutionStatus !== 'AVAILABLE') {
        throw new ChangeSetError('unexpected-state', `change set is CREATE_COMPLETE but its execution status is ${described.ExecutionStatus ?? 'missing'} (expected AVAILABLE)`);
      }
      return { described, status: 'complete' };
    }
    if (status === 'FAILED') {
      if (isNoChangeReason(described.StatusReason)) {
        return { described, status: 'no-changes' };
      }
      throw new ChangeSetError('change-set-failed', `CloudFormation could not compute the change set: ${redact(described.StatusReason ?? '(no reason given)')}`);
    }
    throw new ChangeSetError('unexpected-state', `change set status is ${status === undefined ? 'missing' : `'${redact(String(status))}'`}`);
  }
  throw new ChangeSetError('unexpected-state', `the change set did not settle after ${MAX_POLLS} polls`);
}

const sameTags = (a, b) => JSON.stringify([...a].sort((x, y) => (x.Key < y.Key ? -1 : 1))) === JSON.stringify([...b].sort((x, y) => (x.Key < y.Key ? -1 : 1)));

// The described change set must be EXACTLY the one created: same name, id and
// stack, the tags and capabilities sent, no parameters, no nested stacks, no
// import of existing resources, no pagination.
export function assertDescribedMatches(described, { stackName, changeSetName, changeSetArn, tags, capabilities }) {
  const problems = [];
  if (described.ChangeSetName !== changeSetName) problems.push('ChangeSetName');
  if (described.ChangeSetId !== changeSetArn) problems.push('ChangeSetId');
  if (described.StackName !== stackName) problems.push('StackName');
  if (described.NextToken !== undefined && described.NextToken !== null) problems.push('NextToken (paginated change sets are not supported)');
  if (Array.isArray(described.Parameters) && described.Parameters.length > 0) problems.push('Parameters');
  if (described.IncludeNestedStacks === true) problems.push('IncludeNestedStacks');
  if (described.ImportExistingResources === true) problems.push('ImportExistingResources');
  if (!Array.isArray(described.Tags) || !sameTags(described.Tags, tags)) problems.push('Tags');
  const caps = Array.isArray(described.Capabilities) ? described.Capabilities : [];
  if (caps.length !== capabilities.length || !capabilities.every((c) => caps.includes(c))) problems.push('Capabilities');
  if (!Array.isArray(described.Changes)) problems.push('Changes');
  if (problems.length > 0) {
    throw new ChangeSetError('malformed-response', `describe-change-set does not match the change set this plan created: ${problems.join(', ')}`);
  }
}

// Changes[] -> [{ action, logicalId, type, physicalId, replacement, conditional, policyAction, scope }]
// where action is CREATE | UPDATE | DELETE | REPLACE.
export function classifyChanges(changes) {
  return changes.map((change, index) => {
    const rc = change?.ResourceChange;
    if (change?.Type !== 'Resource' || !rc || typeof rc.LogicalResourceId !== 'string' || typeof rc.ResourceType !== 'string') {
      throw new ChangeSetError('malformed-response', `change ${index + 1} is not a resource change CloudFormation documents`);
    }
    const base = {
      logicalId: rc.LogicalResourceId,
      type: rc.ResourceType,
      physicalId: typeof rc.PhysicalResourceId === 'string' ? rc.PhysicalResourceId : null,
      replacement: rc.Replacement ?? null,
      conditional: false,
      policyAction: typeof rc.PolicyAction === 'string' ? rc.PolicyAction : null,
      scope: Array.isArray(rc.Scope) ? rc.Scope.map(String) : []
    };
    switch (rc.Action) {
      case 'Add':
        return { ...base, action: 'CREATE' };
      case 'Remove':
        return { ...base, action: 'DELETE' };
      case 'Modify':
        if (rc.Replacement === 'True') {
          return { ...base, action: 'REPLACE' };
        }
        if (rc.Replacement === 'Conditional') {
          return { ...base, action: 'REPLACE', conditional: true };
        }
        if (rc.Replacement === 'False') {
          return { ...base, action: 'UPDATE' };
        }
        throw new ChangeSetError('malformed-response', `change ${rc.LogicalResourceId}: Modify with Replacement '${rc.Replacement}' is not understood`);
      default:
        // Import, Dynamic and anything newer: never recorded as a plan.
        throw new ChangeSetError('unexpected-action', `change ${rc.LogicalResourceId}: action '${rc.Action}' is not one a plan may contain`);
    }
  });
}

export function countChanges(classified) {
  const counts = { CREATE: 0, UPDATE: 0, DELETE: 0, REPLACE: 0 };
  for (const change of classified) {
    counts[change.action] += 1;
  }
  return { counts, destructive: counts.DELETE + counts.REPLACE };
}

// The whole lifecycle for one unit.
// -> { outcome: 'changes' | 'no-changes', changeSetArn, described, changes[], counts, destructive, capabilities }
export async function planChangeSet(aws, { stackKind, stackName, changeSetName, type, body, tags, account, region, sleep }) {
  const { capabilities } = await validateTemplate(aws, body);
  const { changeSetArn } = await createChangeSet(aws, { stackName, changeSetName, type, body, tags, capabilities, account, region });
  const { described, status } = await waitForChangeSet(aws, { stackName, changeSetName, sleep });
  assertDescribedMatches(described, { stackName, changeSetName, changeSetArn, tags, capabilities });
  if (status === 'no-changes') {
    if (described.Changes.length > 0) {
      throw new ChangeSetError('malformed-response', 'a change set reported as having no changes lists changes');
    }
    return { outcome: 'no-changes', changeSetArn, described, changes: [], counts: { CREATE: 0, UPDATE: 0, DELETE: 0, REPLACE: 0 }, destructive: 0, capabilities };
  }
  const changes = classifyChanges(described.Changes);
  assertChangeScope(stackKind, changes);
  if (changes.length === 0) {
    throw new ChangeSetError('malformed-response', 'a CREATE_COMPLETE change set lists no changes');
  }
  const { counts, destructive } = countChanges(changes);
  return { outcome: 'changes', changeSetArn, described, changes, counts, destructive, capabilities };
}
