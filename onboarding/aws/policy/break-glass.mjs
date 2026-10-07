// The break-glass execution roles (Phase 3C): what each Lambda may — and must
// not — be able to do. ONE contract, used three ways:
//   - the permission documents the template renders (executionRolePolicy);
//   - offline analysis of a role's live policy documents (analyzeExecutionRole);
//   - the live probes `aws verify --scope break-glass` simulates
//     (executionProbes): every required action must be ALLOWED, every
//     forbidden one DENIED.
//
// The requirements mirror what the broker actually calls (broker/lambda/):
//   ci            notify: consumeTokenId (PutItem — the replay record),
//                 putPending (PutItem), setSlackRef (UpdateItem),
//                 deletePending (DeleteItem); status: consumeTokenId
//                 (PutItem), get (GetItem), expire (UpdateItem).
//                 Secrets: SLACK_BOT_TOKEN only. ssm:GetParameter on its own
//                 environment's ONE framework policy parameter (notify and
//                 status check the commit, Phase 3D).
//   interactions  get (GetItem); claim / finalize / expire / claimSideEffects
//                 (UpdateItem). It never creates or deletes an item: no PutItem,
//                 no DeleteItem. Secrets: bot token, signing secret, GitHub
//                 token. lambda:InvokeFunction on ITSELF (the async follow-up,
//                 runtime.mjs enqueueSelf). ssm:GetParameter on its own
//                 environment's approver path (Phase 3B contract, PR #17) and
//                 on its ONE framework policy parameter (the click-time
//                 re-check, Phase 3D).
//   both          CloudWatch Logs: CreateLogStream / PutLogEvents on its own
//                 log group, which the stack creates (so no CreateLogGroup).
//
// No grant uses Action "*" or Resource "*": nothing here needs it. Every
// wildcard that does appear is one of three documented, exact patterns
// (ALLOWED_WILDCARDS) — anything else is a finding.
//
// Encryption: the table uses DynamoDB's AWS-owned key and the secrets the
// account's aws/secretsmanager key, so neither role needs a kms: action.
import { statements } from './evaluate.mjs';
import { analyzeRequirements } from './permissions.mjs';
import { breakGlassArns, otherEnvironment } from '../break-glass/names.mjs';

export const EXECUTION_ROLES = Object.freeze(['ci', 'interactions']);
export const LAMBDA_SERVICE = 'lambda.amazonaws.com';

// Every action below has a runtime consumer, pinned by
// test/aws-break-glass-policy.test.js § "every granted action has a runtime
// call site". The two least obvious:
//   ci dynamodb:DeleteItem      ciHandler -> broker.notify -> store.deletePending
//                               (broker/lambda/broker.mjs) -> conditional
//                               'DeleteItem' (dynamodb-store.mjs): the rollback
//                               when Slack refuses the approval message
//   interactions lambda:InvokeFunction (own ARN only)
//                               interactionsHandler -> enqueue -> enqueueSelf
//                               (broker/lambda/runtime.mjs): InvokeCommand with
//                               FunctionName AWS_LAMBDA_FUNCTION_NAME — itself
const TABLE_ACTIONS = Object.freeze({
  ci: ['dynamodb:DeleteItem', 'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
  interactions: ['dynamodb:GetItem', 'dynamodb:UpdateItem']
});
const SECRETS = Object.freeze({ ci: ['slackBotToken'], interactions: ['slackBotToken', 'slackSigningSecret', 'githubToken'] });
const LOG_ACTIONS = ['logs:CreateLogStream', 'logs:PutLogEvents'];
// Table operations neither role ever performs: a grant of any is drift.
const NEVER_TABLE = ['dynamodb:Scan', 'dynamodb:Query', 'dynamodb:BatchWriteItem', 'dynamodb:DeleteTable', 'dynamodb:UpdateTable', 'dynamodb:UpdateTimeToLive'];

function assertRole(role) {
  if (!EXECUTION_ROLES.includes(role)) {
    throw new Error(`unknown break-glass execution role '${role}'`);
  }
}

// Only the Lambda service may assume an execution role. No condition is added:
// Lambda does not document a source context for execution-role assumption, and
// a condition it never supplies would make the role unassumable.
export function executionTrustPolicy() {
  return {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { Service: LAMBDA_SERVICE }, Action: 'sts:AssumeRole' }]
  };
}

// target: { partition, account, region }
export function executionRolePolicy(role, environment, target) {
  assertRole(role);
  const a = breakGlassArns(environment, target);
  const statements = [
    {
      Sid: role === 'ci' ? 'RequestAndReplayState' : 'ClaimAndFinalize',
      Effect: 'Allow',
      Action: [...TABLE_ACTIONS[role]],
      Resource: a.table
    },
    {
      Sid: role === 'ci' ? 'PostApprovalMessage' : 'VerifyUpdateAndAudit',
      Effect: 'Allow',
      Action: 'secretsmanager:GetSecretValue',
      Resource: SECRETS[role].length === 1 ? a.secretPatterns[SECRETS[role][0]] : SECRETS[role].map((k) => a.secretPatterns[k])
    }
  ];
  if (role === 'interactions') {
    statements.push(
      { Sid: 'DeferSideEffectsAfterSlackAck', Effect: 'Allow', Action: 'lambda:InvokeFunction', Resource: a.functions.interactions },
      { Sid: 'ReadApprovers', Effect: 'Allow', Action: 'ssm:GetParameter', Resource: a.approverParameters }
    );
  }
  // Both functions check the framework commit (Phase 3D): one exact ARN,
  // read-only, this environment's only.
  statements.push({ Sid: 'ReadFrameworkPolicy', Effect: 'Allow', Action: 'ssm:GetParameter', Resource: a.frameworkPolicyParameter });
  statements.push({ Sid: 'WriteOwnLogs', Effect: 'Allow', Action: [...LOG_ACTIONS], Resource: a.logStreams[role] });
  return { Version: '2012-10-17', Statement: statements };
}

// The only wildcards a break-glass execution policy may contain, and why:
//   <secret name>-??????        Secrets Manager's random 6-character ARN suffix
//   log-group:<own group>:*     the log streams Lambda creates in its own group
//   parameter/ssd/break-glass/<env>/approvers/*
//                               one parameter per repository_id (Phase 3B);
//                               onboarding a repository adds a parameter, never
//                               a policy change
export function allowedWildcards(role, environment, target) {
  assertRole(role);
  const a = breakGlassArns(environment, target);
  return [...SECRETS[role].map((k) => a.secretPatterns[k]), a.logStreams[role], ...(role === 'interactions' ? [a.approverParameters] : [])];
}

const probe = (action, resource, why, severity) => ({ action, resource, why, ...(severity ? { severity } : {}) });

// role -> { required: [{action, resource, why}], forbidden: [{action, resource, severity, why}] }
export function executionRequirements(role, environment, target) {
  assertRole(role);
  const a = breakGlassArns(environment, target);
  const other = otherEnvironment(environment);
  const o = breakGlassArns(other, target);
  const required = [
    ...TABLE_ACTIONS[role].map((action) =>
      probe(action, a.table, action === 'dynamodb:PutItem' ? 'the one-shot OIDC replay record (consumeTokenId) and the pending request are conditional puts' : `the ${role} function's request-state transitions`)
    ),
    ...SECRETS[role].map((k) => probe('secretsmanager:GetSecretValue', a.secretSamples[k], `the ${role} function reads ${k} at cold start`)),
    ...(role === 'interactions'
      ? [
          probe('lambda:InvokeFunction', a.functions.interactions, 'the post-decision side effects run in an async self-invocation'),
          probe('ssm:GetParameter', a.approverParameterSample, `approvers are read from ${environment}'s per-repository parameter (Phase 3B)`)
        ]
      : []),
    probe('ssm:GetParameter', a.frameworkPolicyParameter, role === 'ci' ? `notify and every status call check the framework commit against ${environment}'s allowed set (Phase 3D)` : `an approver's click re-checks the request's framework commit against ${environment}'s allowed set (Phase 3D)`),
    // Probed on the group's own ARN, not a stream ARN: see breakGlassArns().logGroupProbes.
    ...LOG_ACTIONS.map((action) => probe(action, a.logGroupProbes[role], 'the function writes its own logs'))
  ];
  const otherRole = role === 'ci' ? 'interactions' : 'ci';
  const FAIL = 'FAIL';
  const forbidden = [
    // Cross-environment: never the other environment's state, secrets,
    // approvers or functions.
    ...[...TABLE_ACTIONS.ci, ...NEVER_TABLE].map((action) => probe(action, o.table, `the ${environment} ${role} role must never touch the ${other} table`, FAIL)),
    ...Object.keys(o.secretSamples).map((k) => probe('secretsmanager:GetSecretValue', o.secretSamples[k], `the ${environment} ${role} role must never read ${other}'s ${k}`, FAIL)),
    probe('ssm:GetParameter', o.approverParameterSample, `the ${environment} ${role} role must never read ${other}'s approvers`, FAIL),
    probe('ssm:GetParameter', o.frameworkPolicyParameter, `the ${environment} ${role} role must never read ${other}'s allowed framework commits`, FAIL),
    ...['ssm:PutParameter', 'ssm:DeleteParameter'].map((action) => probe(action, o.frameworkPolicyParameter, `the ${environment} ${role} role must never change ${other}'s allowed framework commits`, FAIL)),
    ...Object.values(o.functions).map((fn) => probe('lambda:InvokeFunction', fn, `the ${environment} ${role} role must never invoke a ${other} function`, FAIL)),
    ...EXECUTION_ROLES.flatMap((r) => LOG_ACTIONS.map((action) => probe(action, o.logGroupProbes[r], `the ${environment} ${role} role must never write ${other}'s ${r} logs`, FAIL))),
    // Same environment: only its OWN log group.
    ...LOG_ACTIONS.map((action) => probe(action, a.logGroupProbes[otherRole], `the ${role} function never writes the ${otherRole} function's logs`, FAIL)),
    // Same environment, beyond what this function does.
    ...NEVER_TABLE.map((action) => probe(action, a.table, `the ${role} function never ${action.split(':')[1]}s the table`, FAIL)),
    ...(role === 'interactions'
      ? [
          probe('dynamodb:PutItem', a.table, 'the interaction function never creates a request or a replay record', FAIL),
          probe('dynamodb:DeleteItem', a.table, 'the interaction function never deletes a request', FAIL),
          probe('lambda:InvokeFunction', a.functions.ci, 'the interaction function never invokes the CI broker', FAIL),
          probe('ssm:GetParameter', a.nonApproverParameterSample, 'the interaction function reads only the approver path', FAIL)
        ]
      : [
          probe('secretsmanager:GetSecretValue', a.secretSamples.slackSigningSecret, 'only the interaction function verifies Slack signatures', FAIL),
          probe('secretsmanager:GetSecretValue', a.secretSamples.githubToken, 'only the interaction function posts the audit comment', FAIL),
          probe('ssm:GetParameter', a.approverParameterSample, 'the CI broker never decides who may approve', FAIL),
          probe('lambda:InvokeFunction', a.functions.interactions, 'the CI broker never invokes the interaction function', FAIL),
          probe('lambda:InvokeFunction', a.functions.ci, 'the CI broker never invokes itself', FAIL)
        ]),
    // The framework policy is read, exactly, and never written: only the
    // governance stack (the scoped deployer) changes it.
    ...['ssm:PutParameter', 'ssm:DeleteParameter', 'ssm:LabelParameterVersion', 'ssm:AddTagsToResource'].map((action) => probe(action, a.frameworkPolicyParameter, `a broker function never changes ${environment}'s allowed framework commits`, FAIL)),
    probe('ssm:GetParameter', a.governanceSiblingSample, 'the framework policy grant is one parameter, never governance/*', FAIL),
    probe('ssm:GetParameters', a.frameworkPolicyParameter, 'the broker reads the framework policy with GetParameter only', FAIL),
    probe('ssm:GetParametersByPath', a.frameworkPolicyParameter, 'the broker never lists the governance path', FAIL),
    probe('ssm:PutParameter', a.approverParameterSample, 'a broker function never changes approvers', FAIL),
    ...Object.values(a.secretSamples).map((s) => probe('secretsmanager:PutSecretValue', s, 'a broker function never writes a secret', FAIL)),
    probe('lambda:UpdateFunctionCode', a.functions[role], 'a broker function never replaces its own code', FAIL),
    probe('iam:PassRole', '*', 'an execution role never passes roles', FAIL)
  ];
  return { required, forbidden };
}

// What `aws verify` simulates: required (expected ALLOW) and denied (expected DENY).
export function executionProbes(role, environment, target) {
  const req = executionRequirements(role, environment, target);
  return { required: req.required, denied: req.forbidden };
}

// Action or resource wildcards beyond ALLOWED_WILDCARDS. -> findings[]
export function wildcardProblems(documents, role, environment, target) {
  const allowed = new Set(allowedWildcards(role, environment, target));
  const findings = [];
  for (const { name, document } of documents) {
    let stmts;
    try {
      stmts = statements(document);
    } catch {
      continue; // reported as malformed-policy by the requirement analysis
    }
    for (const s of stmts.filter((x) => x.effect === 'Allow')) {
      for (const action of [...s.actions, ...s.notActions]) {
        if (/[*?]/.test(action)) {
          findings.push({ severity: 'FAIL', kind: 'wildcard-action', message: `${name}:${s.sid} grants wildcard action '${action}'` });
        }
      }
      if (s.notActions.length > 0 || s.notResources.length > 0) {
        findings.push({ severity: 'FAIL', kind: 'wildcard-action', message: `${name}:${s.sid} uses NotAction/NotResource, which grants by exclusion` });
      }
      for (const resource of s.resources) {
        if (/[*?]/.test(resource) && !allowed.has(resource)) {
          findings.push({ severity: 'FAIL', kind: 'wildcard-resource', message: `${name}:${s.sid} grants on wildcard resource '${resource}', which is not one of the documented break-glass patterns` });
        }
      }
    }
  }
  return findings;
}

// Offline analysis of one execution role's policies. -> { status, required, findings }
export function analyzeExecutionRole(role, environment, target, { policies, complete, simulation = null }) {
  const analysis = analyzeRequirements(executionRequirements(role, environment, target), { policies, complete, simulation });
  const extra = wildcardProblems(policies, role, environment, target);
  const findings = [...analysis.findings, ...extra];
  const status = findings.some((f) => f.severity === 'FAIL') ? 'FAIL' : findings.some((f) => f.severity === 'NOT VERIFIED') ? 'NOT VERIFIED' : findings.some((f) => f.severity === 'WARN') ? 'WARN' : 'PASS';
  return { status, required: analysis.required, findings };
}

// Is this document exactly the Lambda-only trust policy? -> problems[]
export function trustProblems(document) {
  let stmts;
  try {
    stmts = statements(document);
  } catch (error) {
    return [`the trust policy is malformed: ${error.message}`];
  }
  const problems = [];
  if (stmts.length !== 1) {
    problems.push(`the trust policy has ${stmts.length} statements; exactly one (lambda.amazonaws.com) is expected`);
  }
  for (const s of stmts) {
    const services = [].concat(s.principal?.Service ?? []);
    const others = Object.keys(s.principal ?? {}).filter((k) => k !== 'Service');
    if (s.effect !== 'Allow' || s.actions.length !== 1 || s.actions[0] !== 'sts:AssumeRole' || services.length !== 1 || services[0] !== LAMBDA_SERVICE || others.length > 0 || s.principal === '*') {
      problems.push(`statement ${s.sid} is not "Allow lambda.amazonaws.com sts:AssumeRole" (principal ${JSON.stringify(s.principal)}, actions ${JSON.stringify(s.actions)})`);
    }
  }
  return problems;
}
