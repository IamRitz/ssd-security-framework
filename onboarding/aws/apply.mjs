// `ssd-onboard aws apply`: execute EXACTLY ONE previously reviewed
// CloudFormation change set — the one recorded in .ssd/aws-plans/<plan-id>/ —
// and only after re-proving that the plan, the operator's stated intent, the
// configuration, the framework checkout, the caller, the change set and the
// stack are all still what was reviewed.
//
// It never renders a template, creates a change set, or creates, updates or
// deletes a stack directly: applyAws() (aws-cli.mjs) can read only this plan's
// stack and change set, and its single mutation is execute-change-set with the
// recorded stack name and change-set ARN, at most once.
//
// Order is part of the contract; each step blocks before the next, and
// nothing in AWS is changed before step 7:
//   1. the plan directory: complete, every hash recomputed, the tags bound, not
//      a no-change plan, and no apply record (apply-started.json / apply.json);
//   2. the record is internally consistent (apply/plan-check.mjs): every copy in
//      plan.json equals what the plan id binds; the change-set ARN, stack id,
//      changes and destructive count re-derive from change-set.json;
//   3. intent: --account == plan == delivery.aws.accountId; --region == plan ==
//      delivery.aws.region; the plan's repository and stack are the ones the
//      configuration derives; the configuration is unchanged since the plan;
//      the framework checkout is bound to framework.ref (the `aws plan` rule)
//      and is the ref the plan was made at;
//   4. --allow-destructive <n> equals the recorded destructive count (when
//      there is any); --yes or an interactive confirmer is available;
//   5. AWS (read-only): caller identity (account, never root), the change set
//      re-described by its recorded ARN and compared in full, its template,
//      the stack's base revision / placeholder, the fresh destructive count;
//   6. confirmation: the operator types the account id and the region (or
//      --yes); then step 5 is repeated immediately before execution, so the
//      time spent typing is not a window;
//   7. apply-started.json is written exclusively, then execute-change-set;
//   8. the stack is polled until it settles; only the operation's own
//      *_COMPLETE is APPLIED; apply.json records the result.
//
// Outcomes: APPLIED; REFUSED (a verification or intent mismatch: nothing was
// executed); ERROR (an operational failure before execution: nothing was
// executed); APPLY_FAILED (execute-change-set was issued and success was not
// observed — including a rollback, a timeout and lost credentials).
//
// The caller ARN is RECORDED (plan.json callerArn, apply.json callerArn) but
// not required to be the planner's: architecture D.11 deliberately keeps it
// out of the plan id, so any non-root principal of the plan's account may
// apply a reviewed plan.
//
// It never writes .ssd/onboarding.yml, workflows, or any repository file other
// than the two apply records in the plan directory.
import { AwsCliError, DEFAULT_DEADLINE_MS, applyAws, redact } from './aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck } from './identity.mjs';
import { discoverStackByName } from './discover/stacks.mjs';
import { describeError } from './discover/result.mjs';
import { classifyChanges, countChanges, defaultSleep } from './plan/change-set.mjs';
import { applyRecordsOf, planDirOf, readPlan, writeApplyRecord } from './plan/record.mjs';
import { checkDestructive, checkIntent, checkPlanRecord } from './apply/plan-check.mjs';
import { SUCCESS, checkStack, compareChangeSet, compareTemplate, stackProgress } from './apply/live.mjs';
import { REPO_LOGICAL_IDS } from './templates/repo-ecr-delivery.mjs';
import { canonicalJson } from './templates/common.mjs';
import { roleName } from './discover/iam-role.mjs';
import { breakGlassNames } from './break-glass/names.mjs';
import { breakGlassEnvironmentOf } from './stack-names.mjs';

export const SCHEMA_VERSION = 1;
export const APPLY_RECORD_SCHEMA_VERSION = 1;
export const OUTCOMES = Object.freeze({ APPLIED: 0, REFUSED: 1, ERROR: 1, APPLY_FAILED: 1 });
export const exitCodeOf = (report) => OUTCOMES[report.outcome] ?? 1;

// How long to wait for the stack once execute-change-set was accepted, and how
// often to look. A stack that has not settled by then is APPLY_FAILED
// (unconfirmed), never APPLIED.
export const DEFAULT_WAIT_MS = 30 * 60_000;
export const WAIT_DELAYS_MS = Object.freeze([2_000, 3_000, 5_000, 5_000, 10_000, 15_000]);
export const MAX_WAIT_POLLS = 600;
// Consecutive failed describe-stacks calls tolerated while waiting.
const MAX_READ_FAILURES = 3;

export class ApplyError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'ApplyError';
    this.kind = kind;
  }
}

const FAIL = 'FAIL';
const PASS = 'PASS';

function newReport({ planId, account, region, config, operator, framework }) {
  const bound = operator ?? config;
  return {
    schemaVersion: SCHEMA_VERSION,
    command: 'aws apply',
    planId,
    target: { repository: config?.repository.slug ?? null, account, region, stackName: null, stackKind: null, scope: null, operation: null, caller: null, plannedBy: null },
    framework: { repository: bound?.framework.repository ?? null, ref: bound?.framework.ref ?? null, checkout: framework?.sha ?? null },
    outcome: null,
    verification: [],
    findings: [],
    changes: null,
    execution: null,
    record: { started: null, result: null, error: null },
    nextSteps: [],
    awsCalls: []
  };
}

// One verification row; returns whether it passed.
function step(report, id, title, findings) {
  report.verification.push({ id, title, status: findings.length === 0 ? PASS : FAIL });
  report.findings.push(...findings);
  return findings.length === 0;
}

const refuse = (report) => Object.assign(report, { outcome: 'REFUSED' });

// Step 5: everything live, read-only. Throws AwsCliError / IdentityError /
// ApplyError for an operational failure (ERROR); returns false after recording
// a refusal.
async function verifyLive(report, aws, { record, account, allowDestructive, slug }) {
  const caller = await callerIdentity(aws);
  report.target.caller = { arn: caller.arn, account: caller.account, kind: caller.kind };
  const identity = [accountCheck(caller, account), principalCheck(caller)].filter((c) => c.status === FAIL).flatMap((c) => c.findings);
  if (!step(report, 'identity', 'Caller identity accepted (account, not root)', identity)) {
    return false;
  }

  let live;
  try {
    live = await aws(['cloudformation', 'describe-change-set', '--stack-name', record.binding.stackName, '--change-set-name', record.binding.changeSetArn]);
  } catch (error) {
    if (error instanceof AwsCliError && error.code === 'ChangeSetNotFound') {
      step(report, 'change-set', 'Change set unchanged', [{ kind: 'change-set-missing', message: `change set ${record.binding.changeSetArn} no longer exists (deleted, or removed by another execution): re-plan` }]);
      return false;
    }
    throw error;
  }
  if (!step(report, 'change-set', 'Change set unchanged', compareChangeSet(record.changeSet, live))) {
    return false;
  }

  let fresh;
  try {
    fresh = countChanges(classifyChanges(live.Changes));
  } catch (error) {
    step(report, 'destructive', 'Destructive changes confirmed', [{ kind: 'change-set-changed', message: error.message }]);
    return false;
  }
  const destructive = [
    ...(fresh.destructive !== record.destructive ? [{ kind: 'destructive-count-changed', message: `the change set now holds ${fresh.destructive} destructive change(s); the plan recorded ${record.destructive}` }] : []),
    ...checkDestructive(fresh.destructive, allowDestructive)
  ];
  if (!step(report, 'destructive', 'Destructive changes confirmed', destructive)) {
    return false;
  }

  const template = await aws(['cloudformation', 'get-template', '--stack-name', record.binding.stackName, '--change-set-name', record.binding.changeSetArn, '--template-stage', 'Original']);
  if (!step(report, 'template', 'Change-set template is template.json', compareTemplate(record.templateText, template))) {
    return false;
  }

  const stack = await discoverStackByName(aws, record.binding.stackName);
  if (stack.state === 'unverified') {
    throw new ApplyError('stack-unverified', `stack ${record.binding.stackName} could not be described (${describeError(stack)})`);
  }
  const title = record.operation === 'CREATE' ? 'CREATE placeholder is the recorded one' : 'Base stack unchanged since the plan';
  return step(report, 'stack', title, checkStack({ record, stack, slug }));
}

// Step 8. Never throws: anything that prevents observing a successful terminal
// state is APPLY_FAILED (unconfirmed).
async function waitForStack(aws, { record, now, sleep, waitMs, env }) {
  const startedAt = now();
  let failures = 0;
  let last = null;
  for (let attempt = 0; attempt < MAX_WAIT_POLLS; attempt += 1) {
    if (now() - startedAt > waitMs) {
      return { observed: false, state: 'timeout', reason: `the stack did not settle within ${Math.round(waitMs / 60_000)} min (last seen ${last?.status ?? 'nothing'})`, last };
    }
    let described;
    try {
      described = await aws(['cloudformation', 'describe-stacks', '--stack-name', record.binding.stackId]);
      failures = 0;
    } catch (error) {
      const kind = error instanceof AwsCliError ? error.kind : 'runtime';
      failures += 1;
      if (['authentication', 'deadline', 'command-unavailable', 'refused', 'runtime'].includes(kind) || failures >= MAX_READ_FAILURES) {
        return { observed: false, state: 'unconfirmed', reason: `the stack could no longer be read (${kind}: ${redact(error?.message ?? String(error), env)})`, last };
      }
      await sleep(WAIT_DELAYS_MS[Math.min(attempt, WAIT_DELAYS_MS.length - 1)]);
      continue;
    }
    const s = Array.isArray(described.Stacks) && described.Stacks.length === 1 ? described.Stacks[0] : null;
    if (!s || typeof s.StackStatus !== 'string') {
      return { observed: false, state: 'unconfirmed', reason: 'describe-stacks did not return exactly one stack with a status', last };
    }
    last = {
      stackId: s.StackId ?? null,
      status: s.StackStatus,
      statusReason: typeof s.StackStatusReason === 'string' ? redact(s.StackStatusReason, env) : null,
      lastUpdatedTime: typeof s.LastUpdatedTime === 'string' ? s.LastUpdatedTime : null,
      outputs: Array.isArray(s.Outputs) ? s.Outputs.map((o) => ({ key: String(o?.OutputKey ?? ''), value: String(o?.OutputValue ?? ''), exportName: o?.ExportName ?? null })) : []
    };
    const progress = stackProgress({ record, live: last });
    if (progress.state === 'succeeded') {
      return { observed: true, state: 'succeeded', reason: progress.reason, last };
    }
    if (progress.state === 'failed') {
      return { observed: true, state: 'failed', reason: progress.reason, last };
    }
    await sleep(WAIT_DELAYS_MS[Math.min(attempt, WAIT_DELAYS_MS.length - 1)]);
  }
  return { observed: false, state: 'timeout', reason: `the stack did not settle after ${MAX_WAIT_POLLS} polls`, last };
}

// The stack's resources after a successful apply (evidence only; a failure to
// read them does not change the outcome).
async function stackResources(aws, record) {
  try {
    const got = await aws(['cloudformation', 'describe-stack-resources', '--stack-name', record.binding.stackId]);
    return (Array.isArray(got.StackResources) ? got.StackResources : []).map((r) => ({
      logicalId: String(r?.LogicalResourceId ?? ''),
      type: String(r?.ResourceType ?? ''),
      physicalId: r?.PhysicalResourceId ?? null,
      status: r?.ResourceStatus ?? null
    }));
  } catch {
    return null;
  }
}

// What the operator may need to change in .ssd/onboarding.yml. apply never
// edits it: the generated stacks have no outputs and create resources under
// the names the configuration already holds, so normally nothing changes.
function nextSteps(config, record, resources) {
  if (record.plan.scope === 'break-glass') {
    return breakGlassNextSteps(record);
  }
  const steps = [];
  if (record.plan.stackKind === 'repo' && resources) {
    const d = config.delivery;
    const expected = {
      [REPO_LOGICAL_IDS.repository]: ['delivery.ecr.repository', d.ecr.repository],
      [REPO_LOGICAL_IDS.push]: ['delivery.roles.pushScanRoleArn', roleName(d.roles.pushScanRoleArn)],
      [REPO_LOGICAL_IDS.deploy]: ['delivery.roles.deployRoleArn', roleName(d.roles.deployRoleArn)]
    };
    for (const r of resources) {
      const want = expected[r.logicalId];
      if (want && r.physicalId !== want[1]) {
        steps.push(`${want[0]}: the stack created ${r.logicalId} as ${r.physicalId}, but the configuration names ${want[1]}. Update .ssd/onboarding.yml by hand (aws apply never edits it).`);
      }
    }
  }
  if (steps.length === 0) {
    steps.push('No .ssd/onboarding.yml change is needed: the stack holds the resources the configuration already names (aws apply never edits it).');
  }
  steps.push('Run `ssd-onboard aws doctor` to confirm delivery readiness.');
  return steps;
}

// After a break-glass stack is applied: the out-of-band steps the plan
// deliberately does not perform (no secret value ever passes through ssd-onboard).
function breakGlassNextSteps(record) {
  const environment = breakGlassEnvironmentOf(record.plan.stackKind);
  const n = breakGlassNames(environment);
  return [
    `Put each secret value out of band, from a file descriptor, never argv — e.g. \`aws secretsmanager put-secret-value --secret-id ${n.secrets.slackBotToken} --secret-string file:///dev/stdin\`, and the same for ${n.secrets.slackSigningSecret} and ${n.secrets.githubToken}. Until then the broker cannot start (fail closed).`,
    `Set the Slack Request URL of the ${environment} Slack app to the Function URL of ${n.functions.interactions} (aws lambda get-function-url-config). Only after the secrets are in place: Slack verifies the URL when it is saved.`,
    `Run \`ssd-onboard aws verify --scope break-glass --environment ${environment} --operator-config <file>\` to prove the deployed boundary (TTL, PutItem, separation, CodeSha256).`
  ];
}

function applyRecord(report, record, { appliedAt, waited }) {
  return {
    schemaVersion: APPLY_RECORD_SCHEMA_VERSION,
    planId: report.planId,
    outcome: report.outcome,
    appliedAt,
    account: report.target.account,
    region: report.target.region,
    callerArn: report.target.caller?.arn ?? null,
    plannedByArn: record.plan.callerArn ?? null,
    stackName: record.binding.stackName,
    stackId: record.binding.stackId,
    changeSetId: record.binding.changeSetArn,
    changeSetName: record.plan.changeSetName,
    operation: record.operation,
    observed: waited.observed,
    finalStackStatus: waited.last?.status ?? null,
    stackStatusReason: waited.last?.statusReason ?? null,
    reason: waited.reason,
    counts: record.counts,
    destructiveCount: record.destructive,
    outputs: waited.last?.outputs ?? [],
    resources: report.execution?.resources ?? null,
    framework: { repository: record.plan.framework.repository, ref: record.plan.framework.ref }
  };
}

// awsApply(options) -> report. Throws for an operational failure BEFORE
// execution (AwsCliError, IdentityError, ApplyError, PlanRecordError,
// PathConfinementError) — nothing was executed then.
//   config        the validated configuration     framework  detectFramework()
//   root          consumer repository root        planId     64 hex
//   account       --account (12 digits)           region     --region
//   yes           --yes (skip the typed confirmation; account/region still required)
//   allowDestructive   --allow-destructive <n> as a number, or null
//   confirm       async ({ account, region }) -> { account, region } as typed;
//                 required unless yes
//   onPreflight   observer of the report once step 5 passed (human output)
//   onExecute     observer called just before execute-change-set
//   exec/env/now/deadlineMs  applyAws()        sleep/waitMs  the wait (step 8)
export async function awsApply({
  config = null,
  operator = null,
  planId,
  account,
  region,
  yes = false,
  allowDestructive = null,
  confirm = null,
  onPreflight = () => {},
  onExecute = () => {},
  exec,
  env = process.env,
  framework,
  root,
  deadlineMs = DEFAULT_DEADLINE_MS,
  waitMs = DEFAULT_WAIT_MS,
  now = Date.now,
  sleep = defaultSleep
}) {
  const report = newReport({ planId, account, region, config, operator, framework });
  const slug = config?.repository.slug ?? null;

  // 1. The plan directory.
  const read = await readPlan(root, planId);
  if (!step(report, 'plan', 'Plan complete; every recorded hash recomputed', read.applicable ? [] : [{ kind: 'plan-not-applicable', message: `${planDirOf(planId)}: ${read.reason}` }])) {
    return refuse(report);
  }
  const applied = await applyRecordsOf(root, planId);
  if (!step(report, 'not-applied', 'Plan not applied before', applied.length === 0 ? [] : [{ kind: 'already-applied', message: `${planDirOf(planId)} already holds ${applied.join(' and ')}: a plan is executed at most once. Re-plan to change the stack again` }])) {
    return refuse(report);
  }

  // 2. The record.
  const { findings: recordFindings, record } = checkPlanRecord(read);
  if (!step(report, 'record', 'Plan record consistent (change set, stack, changes, destructive count)', recordFindings)) {
    return refuse(report);
  }
  const plan = record.plan;
  Object.assign(report.target, { stackName: plan.stackName, stackKind: plan.stackKind, scope: plan.scope, operation: record.operation, plannedBy: plan.callerArn ?? null });
  report.changes = { counts: record.counts, destructive: record.destructive, items: record.changes };

  // 3. Intent, configuration and framework binding.
  if (!step(report, 'intent', 'Account, region, repository, stack, configuration and framework match', checkIntent({ plan, config, operator, framework, account, region }))) {
    return refuse(report);
  }

  // 4. Destructive count and confirmation mode, still before AWS.
  if (!step(report, 'destructive-flag', '--allow-destructive matches the recorded count', checkDestructive(record.destructive, allowDestructive))) {
    return refuse(report);
  }
  if (!step(report, 'confirmation-mode', 'Confirmation available', yes || typeof confirm === 'function' ? [] : [{ kind: 'confirmation-required', message: 'no interactive terminal: pass --yes together with --account and --region to apply without typed confirmation' }])) {
    return refuse(report);
  }

  // 5. Live, read-only.
  const onCall = (argv) => report.awsCalls.push(argv.slice(0, argv.indexOf('--region')).join(' '));
  const preflight = applyAws({ binding: record.binding, region, exec, env, deadlineMs, now, onCall });
  if (!(await verifyLive(report, preflight, { record, account, allowDestructive, slug }))) {
    return refuse(report);
  }
  await onPreflight(report);

  // 6. Typed confirmation, then the same live checks again.
  if (!yes) {
    const typed = await confirm({ account, region });
    if (!step(report, 'confirmation', 'Typed confirmation of account and region', typed?.account === account && typed?.region === region ? [] : [{ kind: 'confirmation-mismatch', message: 'the typed account and region did not both match exactly: nothing was executed' }])) {
      return refuse(report);
    }
  }
  const aws = applyAws({ binding: record.binding, region, exec, env, deadlineMs: deadlineMs + waitMs, now, onCall });
  report.verification = report.verification.filter((v) => !['identity', 'change-set', 'destructive', 'template', 'stack'].includes(v.id));
  if (!(await verifyLive(report, aws, { record, account, allowDestructive, slug }))) {
    return refuse(report);
  }

  // 7. Record the attempt, then execute — exactly once.
  const startedAt = new Date(now()).toISOString();
  const started = {
    schemaVersion: APPLY_RECORD_SCHEMA_VERSION,
    planId,
    startedAt,
    account,
    region,
    callerArn: report.target.caller.arn,
    stackName: record.binding.stackName,
    stackId: record.binding.stackId,
    changeSetId: record.binding.changeSetArn,
    operation: record.operation
  };
  report.record.started = await writeApplyRecord(root, planId, 'apply-started.json', canonicalJson(started), env);
  await onExecute(report);

  report.execution = { requested: true, accepted: null, observed: false, finalStackStatus: null, statusReason: null, reason: null, outputs: [], resources: null };
  let waited;
  try {
    await aws.executeChangeSet();
    report.execution.accepted = true;
  } catch (error) {
    const answered = error instanceof AwsCliError && ['aws-error', 'authorization'].includes(error.kind) && error.code;
    report.execution.accepted = answered ? false : 'unknown';
    waited = answered ? { observed: false, state: 'rejected', reason: `execute-change-set was rejected (${error.code}: ${redact(error.message, env)})`, last: null } : null;
    report.execution.reason = `execute-change-set failed (${error?.kind ?? 'runtime'}: ${redact(error?.message ?? String(error), env)})`;
  }

  // 8. Wait; only the operation's own success is APPLIED.
  if (!waited) {
    waited = await waitForStack(aws, { record, now, sleep, waitMs, env });
  }
  report.outcome = waited.state === 'succeeded' ? 'APPLIED' : 'APPLY_FAILED';
  Object.assign(report.execution, {
    observed: waited.observed,
    finalStackStatus: waited.last?.status ?? null,
    statusReason: waited.last?.statusReason ?? null,
    reason: waited.state === 'succeeded' ? `stack reached ${SUCCESS[record.operation]}` : waited.reason,
    outputs: waited.last?.outputs ?? []
  });
  if (report.outcome === 'APPLIED') {
    report.execution.resources = await stackResources(aws, record);
    report.nextSteps = nextSteps(config, record, report.execution.resources);
  } else {
    report.nextSteps = [
      'Inspect the stack and its events in the CloudFormation console; nothing was rolled back or deleted by ssd-onboard.',
      'This plan is spent (apply-started.json): run `ssd-onboard aws plan` again once the stack is settled.'
    ];
  }
  try {
    report.record.result = await writeApplyRecord(root, planId, 'apply.json', canonicalJson(applyRecord(report, record, { appliedAt: new Date(now()).toISOString(), waited })), env);
  } catch (error) {
    // The outcome stands; the missing record is reported, never hidden.
    report.record.error = { kind: error?.kind ?? 'runtime', message: error?.message ?? String(error) };
  }
  return report;
}
