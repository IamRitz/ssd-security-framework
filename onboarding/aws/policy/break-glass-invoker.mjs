// The Phase 3D per-repository INVOKER role
// (docs/break-glass-repositories.md § Invoker role):
//
//   ssd-break-glass-<env>-invoker-<repository_id>
//   trust        the account's GitHub OIDC provider, sts:AssumeRoleWithWebIdentity,
//                StringEquals aud = sts.amazonaws.com AND sub = <subject>, where
//                <subject> is GitHub's DEFAULT repo:<full_name>:pull_request.
//                No StringLike, no wildcard, no ref:/environment: subject, no
//                job_workflow_ref condition (the broker authorizes the workflow).
//   permissions  ONE inline policy, ssd-break-glass-invoke-ci:
//                lambda:InvokeFunction on exactly this environment's CI broker,
//                unqualified. Nothing else: no DynamoDB, Secrets Manager, SSM,
//                logs, interaction function, other environment or PassRole.
//
// IAM does not separate repositories here: every repository's invoker role in
// an environment invokes the same function. Repositories are separated by the
// broker's verified token identity and by approvers keyed on repository_id.
import { GITHUB_OIDC_HOST, STS_AUDIENCE, providerArn } from './trust.mjs';
import { INVOKER_POLICY_NAME, breakGlassArns, invokerArns, otherEnvironment } from '../break-glass/names.mjs';

export { INVOKER_POLICY_NAME };
export const MAX_SESSION_SECONDS = 3600;
const FAIL = 'FAIL';
const AUD = `${GITHUB_OIDC_HOST}:aud`;
const SUB = `${GITHUB_OIDC_HOST}:sub`;

// GitHub's default subject for pull_request runs, from the full_name GitHub
// reports (its exact spelling: IAM StringEquals is case-sensitive).
export function defaultSubject(fullName) {
  if (typeof fullName !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(fullName)) {
    throw new Error(`cannot build an OIDC subject from '${fullName}'`);
  }
  return `repo:${fullName}:pull_request`;
}

export function invokerTrustPolicy({ partition = 'aws', account, subject }) {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'PullRequestRunsOfOneRepository',
        Effect: 'Allow',
        Principal: { Federated: providerArn(account, partition) },
        Action: 'sts:AssumeRoleWithWebIdentity',
        Condition: { StringEquals: { [AUD]: STS_AUDIENCE, [SUB]: subject } }
      }
    ]
  };
}

export function invokerPermissionPolicy(environment, target) {
  return {
    Version: '2012-10-17',
    Statement: [{ Sid: 'InvokeCiBrokerOnly', Effect: 'Allow', Action: 'lambda:InvokeFunction', Resource: breakGlassArns(environment, target).functions.ci }]
  };
}

const probe = (action, resource, why, severity) => ({ action, resource, why, ...(severity ? { severity } : {}) });
// A different, valid repository_id (for "another repository's" resources).
const anotherId = (id) => (BigInt(id) + 1n).toString();

// -> { required: [probe], denied: [probe] } — the doc's table, exactly.
export function invokerProbes(environment, target, { repositoryId }) {
  const a = breakGlassArns(environment, target);
  const o = breakGlassArns(otherEnvironment(environment), target);
  const own = invokerArns(environment, repositoryId, target);
  const another = invokerArns(environment, anotherId(repositoryId), target);
  const unrelated = `arn:${target.partition ?? 'aws'}:lambda:${target.region}:${target.account}:function:unrelated-function`;
  const deny = (actions, resources, why) => actions.flatMap((action) => resources.map((resource) => probe(action, resource, why, FAIL)));
  return {
    required: [probe('lambda:InvokeFunction', a.functions.ci, `a pull_request run of this repository files its request through ${environment}'s CI broker`)],
    denied: [
      ...deny(['lambda:InvokeFunction'], [`${a.functions.ci}:$LATEST`, a.functions.interactions, o.functions.ci, o.functions.interactions, unrelated], 'the invoker reaches only the unqualified CI broker of its own environment'),
      ...deny(['lambda:InvokeFunctionUrl', 'lambda:InvokeAsync'], [a.functions.interactions, a.functions.ci], 'no URL or asynchronous invocation'),
      ...deny(['lambda:GetFunction', 'lambda:GetFunctionConfiguration', 'lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration', 'lambda:AddPermission', 'lambda:CreateFunctionUrlConfig', 'lambda:PutFunctionConcurrency'], [a.functions.ci], 'the invoker never reads or changes the broker'),
      ...deny(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:Query', 'dynamodb:Scan'], [a.table, o.table], 'requests are written by the broker only'),
      ...deny(['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret', 'secretsmanager:PutSecretValue'], [...Object.values(a.secretSamples), ...Object.values(o.secretSamples)], 'the invoker never touches a broker secret'),
      ...deny(['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter'], [own.approverParameter, another.approverParameter, a.frameworkPolicyParameter, o.frameworkPolicyParameter], 'approvers and the allowed commits are never the repository\'s to read or change'),
      ...deny(['iam:PassRole', 'sts:AssumeRole'], [a.roles.ci, a.roles.interactions, o.roles.ci, o.roles.interactions, another.role], 'the invoker never becomes another role'),
      ...deny(['logs:CreateLogStream', 'logs:PutLogEvents'], [a.logGroupProbes.ci, a.logGroupProbes.interactions, o.logGroupProbes.ci, o.logGroupProbes.interactions], 'the invoker never writes broker logs')
    ]
  };
}

// --- offline trust evaluation (independent of the rendered expectation) ------------

const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const glob = (pattern) => new RegExp(`^${String(pattern).split('').map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[\\^$.|+()[\]{}]/g, '\\$&'))).join('')}$`);

// Would `document` let a web-identity token with these claims assume the role?
// Conservative: an unknown condition operator, NotPrincipal/NotAction, or a
// Deny is treated as "cannot judge" -> null.
export function assumes(document, { provider, claims }) {
  let allowed = false;
  for (const s of list(document?.Statement)) {
    if (s.NotPrincipal !== undefined || s.NotAction !== undefined) return null;
    if (!list(s.Action).some((a) => glob(a).test('sts:AssumeRoleWithWebIdentity'))) continue;
    if (!list(s.Principal?.Federated).includes(provider) && s.Principal !== '*') continue;
    let match = true;
    for (const [operator, block] of Object.entries(s.Condition ?? {})) {
      for (const [key, values] of Object.entries(block ?? {})) {
        const claim = claims[key.toLowerCase()];
        if (operator === 'StringEquals') match &&= claim !== undefined && list(values).includes(claim);
        else if (operator === 'StringLike') match &&= claim !== undefined && list(values).some((v) => glob(v).test(claim));
        else return null;
      }
    }
    if (!match) continue;
    if (s.Effect === 'Deny') return null;
    if (s.Effect === 'Allow') allowed = true;
  }
  return allowed;
}

// -> problems[]: the configured subject must assume; nothing else may.
export function invokerTrustProblems(document, { partition = 'aws', account, fullName, repositoryId }) {
  const provider = providerArn(account, partition);
  const subject = defaultSubject(fullName);
  const [owner, repo] = fullName.split('/');
  const claims = (sub, aud = STS_AUDIENCE) => ({ [AUD.toLowerCase()]: aud, [SUB.toLowerCase()]: sub });
  const problems = [];
  const text = JSON.stringify(document ?? {});
  if (/StringLike|ForAnyValue|ForAllValues/.test(text)) problems.push('the trust uses StringLike or a set operator: only exact StringEquals is allowed');
  if (list(document?.Statement).length !== 1) problems.push(`the trust has ${list(document?.Statement).length} statements, not exactly one`);
  const positive = assumes(document, { provider, claims: claims(subject) });
  if (positive !== true) problems.push(`the configured subject ${subject} ${positive === null ? 'cannot be evaluated' : 'cannot assume the role'}`);
  const negatives = [
    [`repo:${owner}/${repo}-other:pull_request`, 'another repository'],
    [`repo:${owner}@1/${repo}-other@${anotherId(repositoryId)}:pull_request`, 'another repository (immutable subject form)'],
    [`repo:${owner}@1/${repo}@${repositoryId}:pull_request`, 'this repository in the customized immutable form (not what GitHub emits for it)'],
    [`repo:${fullName}:ref:refs/heads/main`, 'a push to main of this repository'],
    [`repo:${fullName}:environment:production`, 'an environment-scoped job of this repository'],
    [`repo:${fullName}:workflow_dispatch`, 'a non-pull_request event of this repository']
  ];
  for (const [sub, what] of negatives) {
    if (assumes(document, { provider, claims: claims(sub) }) !== false) problems.push(`${what} (${sub}) could assume the role`);
  }
  if (assumes(document, { provider, claims: claims(subject, 'ssd-break-glass') }) !== false) problems.push('a token for another audience (ssd-break-glass) could assume the role');
  if (assumes(document, { provider: `arn:${partition}:iam::${account}:oidc-provider/other.example.com`, claims: claims(subject) }) !== false) problems.push('another identity provider could be trusted');
  return problems;
}
