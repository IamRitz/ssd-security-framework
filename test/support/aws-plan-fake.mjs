// Recorded AWS behaviour for `aws plan` tests, on top of aws-fake.mjs. The
// executor is fakeAws(world, { allowlist: assertPlanning }): every argv must
// pass the PLANNING allowlist, independently of the code under test.
//
// CloudFormation change-set calls are answered by a small stateful model:
// create-change-set records what was sent (name, type, tags, capabilities,
// template) and describe-change-set echoes it back with the Changes a test
// chooses — by default, one Add per template resource.
import { assertPlanning } from '../../onboarding/aws/aws-cli.mjs';
import { SHARED_STACKS } from '../../onboarding/aws/stack-names.mjs';
import { ACCOUNT, DEPLOY_ROLE, EXPECTED_STACK, PROVIDER, PUSH_ROLE, REGION, REPOSITORY, SSD_STACK_TAGS, awsError, fakeAws, ok, readyWorld } from './aws-fake.mjs';

export { ACCOUNT, DEPLOY_ROLE, EXPECTED_STACK, PROVIDER, PUSH_ROLE, REGION, REPOSITORY, SSD_STACK_TAGS };

export const SHARED_TAGS = SSD_STACK_TAGS.filter((t) => t.Key !== 'ssd:consumer-repository');
export const stackIdOf = (name) => `arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/${name}/11111111-2222-3333-4444-555555555555`;
const noStack = (name) => awsError('ValidationError', 'DescribeStacks', `Stack with id ${name} does not exist`);
const notInStack = (id) => awsError('ValidationError', 'DescribeStackResources', `Stack for ${id} does not exist`);

export const planFake = (world) => fakeAws(world, { allowlist: assertPlanning });

// A flag's value in a full argv.
export const flag = (argv, name) => {
  const at = argv.indexOf(name);
  return at === -1 ? undefined : argv[at + 1];
};

// Greenfield: nothing per-repository exists, no ssd-onboard stack exists.
export function greenfieldWorld() {
  const world = readyWorld();
  world[`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`] = awsError('RepositoryNotFoundException', 'DescribeRepositories');
  for (const arn of [PUSH_ROLE, DEPLOY_ROLE]) {
    world[`iam get-role --role-name ${arn.split('/').pop()}`] = awsError('NoSuchEntity', 'GetRole', `The role with name ${arn.split('/').pop()} cannot be found.`);
  }
  for (const name of [EXPECTED_STACK, SHARED_STACKS.githubOidc, SHARED_STACKS.ecrScanning]) {
    world[`cloudformation describe-stacks --stack-name ${name}`] = noStack(name);
  }
  return changeSets(world);
}

// The expected stack exists (status/tags chosen) and lists `resources`
// ([{ logicalId, physicalId, type }]); each physical id resolves to it.
export function withStack(world, { name = EXPECTED_STACK, status = 'CREATE_COMPLETE', tags = SSD_STACK_TAGS, resources = [], lastUpdatedTime = '2026-09-01T10:00:00.000Z' } = {}) {
  const stackId = stackIdOf(name);
  const stack = { StackName: name, StackId: stackId, StackStatus: status, Tags: tags, CreationTime: '2026-08-01T10:00:00.000Z', ...(lastUpdatedTime ? { LastUpdatedTime: lastUpdatedTime } : {}) };
  world[`cloudformation describe-stacks --stack-name ${name}`] = ok({ Stacks: [stack] });
  world[`cloudformation describe-stacks --stack-name ${stackId}`] = ok({ Stacks: [stack] });
  world[`cloudformation describe-stack-resources --stack-name ${name}`] = ok({
    StackResources: resources.map((r) => ({ StackName: name, StackId: stackId, LogicalResourceId: r.logicalId, PhysicalResourceId: r.physicalId, ResourceType: r.type, ResourceStatus: 'CREATE_COMPLETE' }))
  });
  for (const r of resources) {
    world[`cloudformation describe-stack-resources --physical-resource-id ${r.physicalId}`] = ok({
      StackResources: [{ StackName: name, StackId: stackId, LogicalResourceId: r.logicalId, PhysicalResourceId: r.physicalId, ResourceType: r.type, ResourceStatus: 'CREATE_COMPLETE' }]
    });
  }
  return world;
}

export { notInStack };

// The stateful change-set model. options:
//   changes(template, type)  -> Changes[] (default: one Add per resource)
//   status / reason          final Status / StatusReason (default CREATE_COMPLETE)
//   pending                  how many CREATE_IN_PROGRESS answers come first
//   describe(doc)            last-chance rewrite of the described document
export function changeSets(world, { changes = null, status = 'CREATE_COMPLETE', reason = undefined, pending = 0, describe = (doc) => doc, validate = null } = {}) {
  const state = { created: [], validated: [], polls: 0 };
  world.__changeSets = state;
  world['cloudformation validate-template *'] = (argv) => {
    const body = flag(argv, '--template-body');
    state.validated.push(body);
    if (validate) {
      return validate(body);
    }
    const template = JSON.parse(body);
    const iam = Object.values(template.Resources).some((r) => r.Type === 'AWS::IAM::Role');
    return ok({ Parameters: [], Description: template.Description, ...(iam ? { Capabilities: ['CAPABILITY_NAMED_IAM'], CapabilitiesReason: 'The following resource(s) require capabilities: [AWS::IAM::Role]' } : {}) });
  };
  world['cloudformation create-change-set *'] = (argv) => {
    const name = flag(argv, '--change-set-name');
    const stackName = flag(argv, '--stack-name');
    const entry = {
      name,
      stackName,
      type: flag(argv, '--change-set-type'),
      tags: JSON.parse(flag(argv, '--tags')),
      capabilities: flag(argv, '--capabilities') ? [flag(argv, '--capabilities')] : [],
      template: JSON.parse(flag(argv, '--template-body')),
      id: `arn:aws:cloudformation:${REGION}:${ACCOUNT}:changeSet/${name}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,
      argv
    };
    state.created.push(entry);
    return ok({ Id: entry.id, StackId: stackIdOf(stackName) });
  };
  world['cloudformation describe-change-set *'] = (argv) => {
    const entry = state.created.find((c) => c.name === flag(argv, '--change-set-name'));
    if (!entry) {
      return awsError('ChangeSetNotFound', 'DescribeChangeSet', 'ChangeSet not found');
    }
    state.polls += 1;
    const settled = state.polls > pending;
    const finalChanges = changes
      ? changes(entry.template, entry.type)
      : Object.entries(entry.template.Resources).map(([logicalId, r]) => ({ Type: 'Resource', ResourceChange: { Action: 'Add', LogicalResourceId: logicalId, ResourceType: r.Type, Scope: [], Details: [] } }));
    const doc = {
      ChangeSetName: entry.name,
      ChangeSetId: entry.id,
      StackId: stackIdOf(entry.stackName),
      StackName: entry.stackName,
      CreationTime: '2026-10-01T00:00:00.000Z',
      ExecutionStatus: settled ? (status === 'CREATE_COMPLETE' ? 'AVAILABLE' : 'UNAVAILABLE') : 'UNAVAILABLE',
      Status: settled ? status : 'CREATE_IN_PROGRESS',
      ...(settled && reason !== undefined ? { StatusReason: reason } : {}),
      Capabilities: entry.capabilities,
      Tags: entry.tags,
      Parameters: [],
      IncludeNestedStacks: false,
      Changes: settled && status === 'CREATE_COMPLETE' ? finalChanges : []
    };
    return ok(describe(doc));
  };
  return world;
}

// A managed config: every per-repository resource managed.
export const MANAGED = { delivery: { environment: 'production', ecr: { ownership: 'managed' }, roles: { pushScanOwnership: 'managed', deployOwnership: 'managed' } } };
