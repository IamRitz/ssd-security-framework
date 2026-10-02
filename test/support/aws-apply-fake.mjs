// Recorded AWS behaviour for `aws apply` tests, on top of aws-fake.mjs and
// aws-plan-fake.mjs. A test first records a REAL plan (awsPlan against the
// planning fake); applyWorld() then models what AWS holds afterwards, taken
// from that plan directory:
//
//   - the change set, described by its ARN exactly as change-set.json recorded
//     it (a test may rewrite the live description);
//   - its template (get-template --template-stage Original);
//   - the stack: the base revision (UPDATE) or the REVIEW_IN_PROGRESS
//     placeholder (CREATE), looked up by name or id;
//   - execute-change-set: counted, prints nothing (as the CLI does), marks the
//     change set EXECUTE_IN_PROGRESS and starts the stack along `sequence` —
//     one status per describe-stacks poll by stack id, the last one sticking.
//
// The executor is fakeAws(world, { allowlist: assertApply(binding) }): every
// argv must pass the APPLY allowlist of this exact plan, independently of the
// code under test; an unrecorded call fails the test.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { assertApply } from '../../onboarding/aws/aws-cli.mjs';
import { planDirOf } from '../../onboarding/aws/plan/record.mjs';
import { CALLER, awsError, fakeAws, ok } from './aws-fake.mjs';
import { ACCOUNT, OWNED, SSD_STACK_TAGS } from './aws-plan-fake.mjs';

export const UPDATED_AT = '2026-10-01T12:00:00.000Z';
export const EXECUTE = 'cloudformation execute-change-set';

export const readPlanFile = (root, planId, name) => readFileSync(join(root, planDirOf(planId), name), 'utf8');
export const readPlanJson = (root, planId, name = 'plan.json') => JSON.parse(readPlanFile(root, planId, name));

// options:
//   sequence        stack statuses after execute (default: <OP>_IN_PROGRESS, <OP>_COMPLETE)
//   stack(doc)      rewrite of the live stack document before execution (null: absent)
//   changeSet(doc)  rewrite of the live change-set description
//   template(body)  rewrite of the live change-set template
//   caller          sts get-caller-identity document
//   execute         the execute-change-set response (default: success, empty stdout)
//   poll(n)         optional override of the n-th describe-stacks-by-id response after execute
export function applyWorld(options = {}) {
  try {
    return modelOf(options);
  } catch {
    // A plan a test deliberately damaged cannot be modelled; apply must refuse
    // it before AWS, so ANY call through this executor fails the test.
    const fake = fakeAws({}, { allowlist: () => { throw new Error('no AWS call is expected for an unreadable plan'); } });
    return { world: {}, state: { executions: 0, polls: 0 }, fake, plan: null, binding: null, recorded: null, operation: null };
  }
}

function modelOf({ root, planId, sequence = null, stack = (doc) => doc, changeSet = (doc) => doc, template = (body) => body, caller = null, execute = null, poll = null, outputs = [] } = {}) {
  const plan = readPlanJson(root, planId);
  const recorded = readPlanJson(root, planId, 'change-set.json');
  const operation = plan.changeSetType;
  const stackId = recorded.StackId;
  const base = plan.baseStack;
  const binding = { stackName: plan.stackName, stackId, changeSetArn: plan.changeSetArn };
  const state = {
    executions: 0,
    polls: 0,
    changeSet: changeSet(structuredClone(recorded)),
    stack: stack({
      StackName: plan.stackName,
      StackId: stackId,
      StackStatus: operation === 'CREATE' ? 'REVIEW_IN_PROGRESS' : base.stackStatus,
      Tags: plan.tags,
      CreationTime: '2026-08-01T10:00:00.000Z',
      ...(operation === 'UPDATE' && base.lastUpdatedTime ? { LastUpdatedTime: base.lastUpdatedTime } : {}),
      ...(operation === 'CREATE' && base.state === 'present' && base.lastUpdatedTime ? { LastUpdatedTime: base.lastUpdatedTime } : {})
    }),
    sequence: sequence ?? [`${operation}_IN_PROGRESS`, `${operation}_COMPLETE`]
  };
  const noStack = (name) => awsError('ValidationError', 'DescribeStacks', `Stack with id ${name} does not exist`);
  const describeStack = (key) => {
    if (!state.stack) {
      return noStack(key);
    }
    return ok({ Stacks: [state.stack] });
  };
  const world = {
    'sts get-caller-identity': ok(caller ?? { Account: ACCOUNT, Arn: CALLER, UserId: 'AROAEXAMPLEEXAMPLE01:alice' }),
    [`cloudformation describe-change-set --stack-name ${binding.stackName} --change-set-name ${binding.changeSetArn}`]: () => (state.changeSet ? ok(state.changeSet) : awsError('ChangeSetNotFound', 'DescribeChangeSet', `ChangeSet [${binding.changeSetArn}] does not exist`)),
    [`cloudformation get-template --stack-name ${binding.stackName} --change-set-name ${binding.changeSetArn} --template-stage Original`]: () =>
      ok({ TemplateBody: template(JSON.parse(readPlanFile(root, planId, 'template.json'))), StagesAvailable: ['Original', 'Processed'] }),
    [`cloudformation describe-stacks --stack-name ${binding.stackName}`]: () => describeStack(binding.stackName),
    [`cloudformation describe-stacks --stack-name ${stackId}`]: () => {
      if (state.executions === 0) {
        return describeStack(stackId);
      }
      state.polls += 1;
      if (poll) {
        const answer = poll(state.polls, state);
        if (answer) {
          return answer;
        }
      }
      const status = state.sequence[Math.min(state.polls - 1, state.sequence.length - 1)];
      state.stack = { ...state.stack, StackStatus: status, LastUpdatedTime: UPDATED_AT, ...(status.endsWith('_COMPLETE') ? { Outputs: outputs } : {}) };
      return ok({ Stacks: [state.stack] });
    },
    [`cloudformation describe-stack-resources --stack-name ${stackId}`]: () =>
      ok({ StackResources: OWNED.filter((r) => Object.hasOwn(JSON.parse(readPlanFile(root, planId, 'template.json')).Resources, r.logicalId)).map((r) => ({ StackName: binding.stackName, StackId: stackId, LogicalResourceId: r.logicalId, PhysicalResourceId: r.physicalId, ResourceType: r.type, ResourceStatus: 'CREATE_COMPLETE' })) }),
    [`${EXECUTE} --stack-name ${binding.stackName} --change-set-name ${binding.changeSetArn}`]: () => {
      state.executions += 1;
      if (execute) {
        return execute(state);
      }
      state.changeSet = { ...state.changeSet, ExecutionStatus: 'EXECUTE_IN_PROGRESS' };
      return { stdout: '', stderr: '', exitCode: 0 };
    }
  };
  const fake = fakeAws(world, { allowlist: assertApply(binding) });
  return { world, state, fake, plan, binding, recorded, operation };
}

// The index of the first mutating call in the recorded argv list (-1: none).
export const firstMutation = (fake) => fake.keys().findIndex((k) => k.startsWith(EXECUTE));
export const mutations = (fake) => fake.keys().filter((k) => k.startsWith(EXECUTE)).length;

export { SSD_STACK_TAGS };
