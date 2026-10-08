// Phase 3C: `aws verify --scope break-glass` against a recorded deployed
// stack. The deployed world verifies (with the advisory concurrency WARN);
// every drift, broadening or cross-environment reference FAILS its own check.
// The IAM simulator answers from the documents the fake account holds
// (support/break-glass-fake.mjs), independently of the code under test.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { assertBreakGlassRead } from '../onboarding/aws/aws-cli.mjs';
import { awsVerifyBreakGlass } from '../onboarding/aws/break-glass/verify.mjs';
import { breakGlassArns, breakGlassNames } from '../onboarding/aws/break-glass/names.mjs';
import { fakeAws } from './support/aws-fake.mjs';
import { ACCOUNT, TARGET, artifactReads, deployedBreakGlass, operator, secretArnOf } from './support/break-glass-fake.mjs';

async function verify(world, { environment = 'production', op = operator(), region = null } = {}) {
  const f = fakeAws(world, { allowlist: assertBreakGlassRead });
  const report = await awsVerifyBreakGlass({ operator: op, environment, region, exec: f.exec, env: {} });
  assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
  return { report, f, byId: (id) => report.checks.find((c) => c.id === id) };
}
const failing = (report) => report.checks.filter((c) => c.status === 'FAIL').map((c) => c.id);
const P = breakGlassArns('production', TARGET);
const S = breakGlassArns('synthetic', TARGET);
const ci = (world) => world.__roles['ssd-break-glass-production-ci-execution'];
const interactions = (world) => world.__roles['ssd-break-glass-production-interactions-execution'];

describe('aws verify --scope break-glass: the deployed stack', () => {
  for (const environment of ['production', 'synthetic']) {
    it(`${environment} verifies; the only non-PASS is the CI broker's advisory concurrency cap`, async () => {
      const { report, byId } = await verify(deployedBreakGlass(environment), { environment });
      const problems = report.checks.filter((c) => c.status !== 'PASS');
      assert.deepEqual(problems.map((c) => [c.id, c.status]), [['bg.ci-concurrency', 'WARN']], JSON.stringify(problems.map((c) => c.findings)));
      assert.equal(byId('bg.interactions-concurrency').status, 'PASS');
      assert.equal(byId('bg.interactions-concurrency').required, true);
      assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS');
      assert.equal(report.target.environment, environment);
    });
  }

  it('proves dynamodb:PutItem on its own table by simulation, and its denial on the other environment\'s', async () => {
    const { byId } = await verify(deployedBreakGlass());
    assert.ok(byId('bg.ci-required-access').observed.includes(`dynamodb:PutItem on ${P.table}: allowed`));
    assert.ok(byId('bg.ci-negative-access').observed.includes(`dynamodb:PutItem on ${S.table}: implicitDeny`));
    assert.ok(byId('bg.interactions-negative-access').observed.includes(`dynamodb:PutItem on ${P.table}: implicitDeny`));
  });

  it('only reads: every call passes the break-glass read allowlist and none reads a secret value or code', async () => {
    const { f } = await verify(deployedBreakGlass());
    for (const key of f.keys()) {
      assert.doesNotMatch(key, /get-secret-value|lambda get-function |put-|update-|delete-|create-/, key);
    }
  });

  it('a wrong account fails before any resource is read', async () => {
    const world = deployedBreakGlass();
    world['sts get-caller-identity'] = { stdout: JSON.stringify({ Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'x' }), stderr: '', exitCode: 0 };
    const { report, f } = await verify(world);
    assert.equal(report.outcome, 'FAILED');
    assert.deepEqual(f.operations(), ['sts get-caller-identity']);
  });
});

describe('aws verify --scope break-glass: drift fails', () => {
  const cases = [
    ['TTL disabled', (w) => (w.__ttl = { TimeToLiveStatus: 'DISABLED' }), 'bg.table-ttl'],
    ['TTL on another attribute', (w) => (w.__ttl = { TimeToLiveStatus: 'ENABLED', AttributeName: 'expiresAt' }), 'bg.table-ttl'],
    ['deletion protection off', (w) => (w.__table.DeletionProtectionEnabled = false), 'bg.table'],
    ['a second key attribute', (w) => w.__table.KeySchema.push({ AttributeName: 'kind', KeyType: 'RANGE' }), 'bg.table'],
    ['dynamodb:PutItem deleted from the CI role', (w) => (ci(w).policy.Statement[0].Action = ['dynamodb:DeleteItem', 'dynamodb:GetItem', 'dynamodb:UpdateItem']), 'bg.ci-required-access'],
    ['the CI role\'s table grant broadened to *', (w) => (ci(w).policy.Statement[0].Resource = '*'), 'bg.ci-negative-access'],
    ['the production CI role granted the synthetic table', (w) => (ci(w).policy.Statement[0].Resource = [P.table, S.table]), 'bg.ci-negative-access'],
    ['the production interaction role granted synthetic approvers', (w) => interactions(w).policy.Statement.push({ Effect: 'Allow', Action: 'ssm:GetParameter', Resource: S.approverParameters }), 'bg.interactions-negative-access'],
    ['the interaction role granted PutItem', (w) => interactions(w).policy.Statement[0].Action.push('dynamodb:PutItem'), 'bg.interactions-negative-access'],
    [
      'a managed policy attached to the CI role',
      (w) => {
        ci(w).attached = [{ PolicyName: 'ReadOnlyAccess', PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' }];
        w['iam get-policy --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess'] = { stdout: '{"Policy":{"DefaultVersionId":"v1"}}', stderr: '', exitCode: 0 };
        w['iam get-policy-version --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --version-id v1'] = { stdout: '{"PolicyVersion":{"Document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"*"}]}}}', stderr: '', exitCode: 0 };
      },
      'bg.ci-role'
    ],
    ['the CI role trusts another principal', (w) => (ci(w).trust = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${ACCOUNT}:root` }, Action: 'sts:AssumeRole' }] }), 'bg.ci-role'],
    ['the CI broker has a Function URL', (w) => (w.__urls.ci = { FunctionUrl: 'https://x.lambda-url.us-east-1.on.aws/', AuthType: 'NONE', FunctionArn: P.functions.ci }), 'bg.ci-exposure'],
    ['the CI broker has a resource policy', (w) => (w.__policies.ci = [{ Sid: 'x', Effect: 'Allow', Principal: { AWS: '111111111111' }, Action: 'lambda:InvokeFunction', Resource: P.functions.ci }]), 'bg.ci-exposure'],
    ['a public InvokeFunction WITHOUT the via-URL condition (forgeable follow-up)', (w) => (w.__policies.interactions[1] = { ...w.__policies.interactions[1], Condition: undefined }), 'bg.interactions-exposure'],
    ['an extra public statement on the interaction function', (w) => w.__policies.interactions.push({ Sid: 'extra', Effect: 'Allow', Principal: '*', Action: 'lambda:GetFunction', Resource: P.functions.interactions }), 'bg.interactions-exposure'],
    ['the Function URL switched to AWS_IAM', (w) => (w.__urls.interactions.AuthType = 'AWS_IAM'), 'bg.interactions-exposure'],
    ['async retries left at the default', (w) => (w.__async = null), 'bg.interactions-async'],
    ['async retries set to 2', (w) => (w.__async = { MaximumRetryAttempts: 2, MaximumEventAgeInSeconds: 900 }), 'bg.interactions-async'],
    ['an unknown variable in the CI environment', (w) => (w.__functions.ci.Environment.Variables.DEBUG = '1'), 'bg.ci-function'],
    ['the CI broker runs other code', (w) => (w.__functions.ci.CodeSha256 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='), 'bg.ci-code'],
    ['the interaction function runs as the CI role', (w) => (w.__functions.interactions.Role = P.roles.ci), 'bg.interactions-function'],
    ['an approver map in the interaction environment', (w) => (w.__functions.interactions.Environment.Variables.SLACK_APPROVER_IDS_BY_REPOSITORY_ID = '{"1":["U1"]}'), 'bg.interactions-function'],
    ['a layer on the CI broker', (w) => (w.__functions.ci.Layers = [{ Arn: 'arn:aws:lambda:us-east-1:111111111111:layer:x:1' }]), 'bg.ci-function'],
    ['a secret tagged for the other environment', (w) => (w.__secrets.slackBotToken.Tags = [{ Key: 'ssd:environment', Value: 'synthetic' }]), 'bg.secrets'],
    ['the public interaction function has no reserved concurrency', (w) => (w['lambda get-function-concurrency --function-name ssd-break-glass-production-interactions'] = { stdout: '{}', stderr: '', exitCode: 0 }), 'bg.interactions-concurrency'],
    ['the public interaction function has no reserved concurrency (the live empty response)', (w) => (w['lambda get-function-concurrency --function-name ssd-break-glass-production-interactions'] = { stdout: '', stderr: '', exitCode: 0 }), 'bg.interactions-concurrency'],
    ['the interaction function\'s reservation drifted', (w) => (w['lambda get-function-concurrency --function-name ssd-break-glass-production-interactions'] = { stdout: '{"ReservedConcurrentExecutions":50}', stderr: '', exitCode: 0 }), 'bg.interactions-concurrency'],
    ['S3 stores no SHA-256 for the artifact version', (w) => artifactReads(w, { checksum: null }), 'bg.artifact'],
    ['S3\'s SHA-256 for the artifact is COMPOSITE', (w) => artifactReads(w, { checksumType: 'COMPOSITE' }), 'bg.artifact'],
    ['an unexpected resource in the stack', (w) => w.__stackResources.push({ LogicalResourceId: 'InvokerRole', PhysicalResourceId: 'x', ResourceType: 'AWS::IAM::Role' }), 'bg.stack']
  ];
  for (const [what, mutate, id] of cases) {
    it(what, async () => {
      const world = deployedBreakGlass();
      mutate(world);
      const { report } = await verify(world);
      assert.equal(report.outcome, 'FAILED');
      assert.ok(failing(report).includes(id), `${id} not in ${JSON.stringify(failing(report))}`);
    });
  }
});

describe('aws verify --scope break-glass: cross-environment reuse fails', () => {
  it('the production CI broker pointed at the synthetic table', async () => {
    const world = deployedBreakGlass();
    world.__functions.ci.Environment.Variables.TABLE_NAME = breakGlassNames('synthetic').table;
    const { report } = await verify(world);
    assert.ok(failing(report).includes('bg.separation'));
    assert.ok(failing(report).includes('bg.ci-function'));
  });

  it('the production interaction function reading a synthetic secret', async () => {
    const world = deployedBreakGlass();
    world.__functions.interactions.Environment.Variables.SLACK_SIGNING_SECRET_ARN = secretArnOf(breakGlassNames('synthetic').secrets.slackSigningSecret);
    const { report } = await verify(world);
    assert.ok(failing(report).includes('bg.separation'));
  });

  it('the production CI broker posting to the synthetic channel', async () => {
    const world = deployedBreakGlass();
    world.__functions.ci.Environment.Variables.SLACK_CHANNEL_ID = operator().environments.synthetic.slackChannelId;
    const { report } = await verify(world);
    assert.ok(failing(report).includes('bg.separation'));
  });

  it('the production function running as a synthetic execution role', async () => {
    const world = deployedBreakGlass();
    world.__functions.ci.Role = S.roles.ci;
    const { report } = await verify(world);
    assert.ok(failing(report).includes('bg.separation'));
  });

  it('a production stack tagged synthetic is not owned', async () => {
    const world = deployedBreakGlass();
    const key = `cloudformation describe-stacks --stack-name ${breakGlassNames('production').stack}`;
    const doc = JSON.parse(world[key].stdout);
    doc.Stacks[0].Tags = doc.Stacks[0].Tags.map((t) => (t.Key === 'ssd:environment' ? { ...t, Value: 'synthetic' } : t));
    world[key] = { stdout: JSON.stringify(doc), stderr: '', exitCode: 0 };
    const { report } = await verify(world);
    assert.ok(failing(report).includes('bg.stack'));
  });
});

// Logging access. IAM's simulator never allows CreateLogStream / PutLogEvents
// on a log-stream ARN under a '/aws/lambda/…' group (observed live 2026-10-05;
// the fake reproduces it), so verify probes each group's own ARN
// (`…:log-group:<name>:*`) — and requires ONLY the function's own group.
describe('aws verify --scope break-glass: logging access (own log group only)', () => {
  const logs = (role, environment = 'production') => breakGlassArns(environment, TARGET).logGroupProbes[role];
  const writeOwnLogs = (role) => role.policy.Statement.find((st) => st.Sid === 'WriteOwnLogs');
  const readFrameworkPolicy = (role) => role.policy.Statement.find((st) => st.Sid === 'ReadFrameworkPolicy');
  const governanceArn = (environment = 'production') => `arn:aws:ssm:${TARGET.region}:${ACCOUNT}:parameter/ssd/break-glass/${environment}/governance/allowed-framework-shas`;
  const roleOf = (world, environment, role) => world.__roles[`ssd-break-glass-${environment}-${role}-execution`];
  const simulate = (world, roleArn, action, resource) =>
    JSON.parse(world['iam simulate-principal-policy *'](['iam', 'simulate-principal-policy', '--policy-source-arn', roleArn, '--action-names', JSON.stringify([action]), '--resource-arns', JSON.stringify([resource])]).stdout).EvaluationResults[0].EvalDecision;

  it('the fake reproduces the live simulator: no grant, not even Resource "*", allows a stream under /aws/lambda', () => {
    const world = deployedBreakGlass();
    const role = ci(world);
    role.policy.Statement.push({ Sid: 'Broad', Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: '*' });
    const stream = `${logs('ci').slice(0, -2)}:log-stream:2026/10/04/[$LATEST]0123456789abcdef`;
    for (const action of ['logs:CreateLogStream', 'logs:PutLogEvents']) {
      assert.equal(simulate(world, role.arn, action, stream), 'implicitDeny');
      assert.equal(simulate(world, role.arn, action, logs('ci')), 'allowed');
    }
  });

  for (const environment of ['production', 'synthetic']) {
    it(`${environment}: the generated policies pass, own group allowed, every other group denied`, async () => {
      const { report, byId } = await verify(deployedBreakGlass(environment), { environment });
      const other = environment === 'production' ? 'synthetic' : 'production';
      for (const role of ['ci', 'interactions']) {
        const otherRole = role === 'ci' ? 'interactions' : 'ci';
        assert.equal(byId(`bg.${role}-required-access`).status, 'PASS');
        assert.equal(byId(`bg.${role}-negative-access`).status, 'PASS');
        for (const action of ['logs:CreateLogStream', 'logs:PutLogEvents']) {
          assert.ok(byId(`bg.${role}-required-access`).observed.includes(`${action} on ${logs(role, environment)}: allowed`));
          assert.ok(byId(`bg.${role}-negative-access`).observed.includes(`${action} on ${logs(otherRole, environment)}: implicitDeny`), 'cross-function probed and denied');
          for (const r of ['ci', 'interactions']) {
            assert.ok(byId(`bg.${role}-negative-access`).observed.includes(`${action} on ${logs(r, other)}: implicitDeny`), `${other} ${r} probed and denied`);
          }
        }
      }
      assert.notEqual(report.outcome, 'FAILED');
    });
  }

  const drift = [
    ['CI without logs:CreateLogStream', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'ci')).Action = ['logs:PutLogEvents']), ['bg.ci-required-access']],
    ['interactions without logs:PutLogEvents', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'interactions')).Action = ['logs:CreateLogStream']), ['bg.interactions-required-access']],
    ['CI writing to a log group that is not its own', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'ci')).Resource = `arn:aws:logs:${TARGET.region}:${ACCOUNT}:log-group:/aws/lambda/some-other-function:*`), ['bg.ci-required-access']],
    ['CI granted the interaction function\'s group INSTEAD of its own', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'ci')).Resource = logs('interactions')), ['bg.ci-required-access', 'bg.ci-negative-access']],
    ['CI granted the interaction function\'s group AS WELL', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'ci')).Resource = [logs('ci'), logs('interactions')]), ['bg.ci-negative-access']],
    ['interactions granted the CI group as well', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'interactions')).Resource = [logs('interactions'), logs('ci')]), ['bg.interactions-negative-access']],
    ['synthetic interactions granted production\'s interactions group', 'synthetic', (w) => (writeOwnLogs(roleOf(w, 'synthetic', 'interactions')).Resource = [logs('interactions', 'synthetic'), logs('interactions', 'production')]), ['bg.interactions-negative-access']],
    ['synthetic CI granted production\'s CI group', 'synthetic', (w) => (writeOwnLogs(roleOf(w, 'synthetic', 'ci')).Resource = [logs('ci', 'synthetic'), logs('ci', 'production')]), ['bg.ci-negative-access']],
    ['a broad Resource "*" Logs grant', 'production', (w) => roleOf(w, 'production', 'ci').policy.Statement.push({ Sid: 'Broad', Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: '*' }), ['bg.ci-policy-document', 'bg.ci-negative-access']],
    ['an account-wide log-group:* grant', 'production', (w) => roleOf(w, 'production', 'ci').policy.Statement.push({ Sid: 'AllGroups', Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: `arn:aws:logs:${TARGET.region}:${ACCOUNT}:log-group:*` }), ['bg.ci-policy-document', 'bg.ci-negative-access']],
    ['a logs:* action on its own group', 'production', (w) => (writeOwnLogs(roleOf(w, 'production', 'ci')).Action = ['logs:*']), ['bg.ci-policy-document']],
    // --- Phase 3D: the framework policy read and the CI environment -------------
    ['the CI function deployed without BREAK_GLASS_ENVIRONMENT (the 3C shape)', 'production', (w) => delete w.__functions.ci.Environment.Variables.BREAK_GLASS_ENVIRONMENT, ['bg.ci-function']],
    ['the production CI function naming synthetic', 'production', (w) => (w.__functions.ci.Environment.Variables.BREAK_GLASS_ENVIRONMENT = 'synthetic'), ['bg.ci-function', 'bg.separation']],
    ['the CI role without its governance read', 'production', (w) => (roleOf(w, 'production', 'ci').policy.Statement = roleOf(w, 'production', 'ci').policy.Statement.filter((st) => st.Sid !== 'ReadFrameworkPolicy')), ['bg.ci-required-access']],
    ['the interaction role without its governance read', 'synthetic', (w) => (roleOf(w, 'synthetic', 'interactions').policy.Statement = roleOf(w, 'synthetic', 'interactions').policy.Statement.filter((st) => st.Sid !== 'ReadFrameworkPolicy')), ['bg.interactions-required-access']],
    ['the CI governance read broadened to governance/*', 'production', (w) => (readFrameworkPolicy(roleOf(w, 'production', 'ci')).Resource = `arn:aws:ssm:${TARGET.region}:${ACCOUNT}:parameter/ssd/break-glass/production/governance/*`), ['bg.ci-policy-document', 'bg.ci-negative-access']],
    ['the interaction role also reading the other environment\'s commits', 'synthetic', (w) => (readFrameworkPolicy(roleOf(w, 'synthetic', 'interactions')).Resource = [governanceArn('synthetic'), governanceArn('production')]), ['bg.interactions-negative-access']],
    ['the CI role able to write the governance parameter', 'production', (w) => (readFrameworkPolicy(roleOf(w, 'production', 'ci')).Action = ['ssm:GetParameter', 'ssm:PutParameter']), ['bg.ci-negative-access']],
    ['the CI role given approver read', 'production', (w) => roleOf(w, 'production', 'ci').policy.Statement.push({ Sid: 'ReadApprovers', Effect: 'Allow', Action: 'ssm:GetParameter', Resource: `arn:aws:ssm:${TARGET.region}:${ACCOUNT}:parameter/ssd/break-glass/production/approvers/*` }), ['bg.ci-negative-access']],
    ['the interaction role without its approver read', 'production', (w) => (roleOf(w, 'production', 'interactions').policy.Statement = roleOf(w, 'production', 'interactions').policy.Statement.filter((st) => st.Sid !== 'ReadApprovers')), ['bg.interactions-required-access']]
  ];
  for (const [what, environment, mutate, ids] of drift) {
    it(`FAILS: ${what}`, async () => {
      const world = deployedBreakGlass(environment);
      mutate(world);
      const { report } = await verify(world, { environment });
      assert.equal(report.outcome, 'FAILED');
      for (const id of ids) assert.ok(failing(report).includes(id), `${id} not in ${JSON.stringify(failing(report))}`);
    });
  }
});

describe('aws verify --scope break-glass: warnings and uncertainty', () => {
  it('an unpopulated secret is a WARN (fail closed), never a PASS or a FAIL', async () => {
    const world = deployedBreakGlass();
    world.__secrets.githubToken.VersionIdsToStages = {};
    const { byId } = await verify(world);
    assert.equal(byId('bg.secrets').status, 'WARN');
  });

  // Live AWS (2026-10-05): no reservation = exit 0 with EMPTY stdout. That is a
  // successful read meaning "no cap" — the advisory WARN — never NOT VERIFIED.
  it('the CI broker with no reservation (empty successful response) is the advisory WARN, not NOT VERIFIED', async () => {
    const world = deployedBreakGlass();
    assert.deepEqual(world['lambda get-function-concurrency --function-name ssd-break-glass-production-ci'], { stdout: '', stderr: '', exitCode: 0 }, 'the fake models the live response');
    const { byId } = await verify(world);
    const c = byId('bg.ci-concurrency');
    assert.equal(c.status, 'WARN');
    assert.ok(c.findings.some((f) => f.kind === 'no-concurrency-cap'));
  });

  it('a malformed concurrency response is NOT VERIFIED (CI), never a WARN or PASS', async () => {
    for (const stdout of ['not json', '[]', 'null']) {
      const world = deployedBreakGlass();
      world['lambda get-function-concurrency --function-name ssd-break-glass-production-ci'] = { stdout, stderr: '', exitCode: 0 };
      const { byId } = await verify(world);
      assert.equal(byId('bg.ci-concurrency').status, 'NOT VERIFIED', stdout);
    }
  });

  it('a malformed concurrency response on the interaction function never passes', async () => {
    const world = deployedBreakGlass();
    world['lambda get-function-concurrency --function-name ssd-break-glass-production-interactions'] = { stdout: 'not json', stderr: '', exitCode: 0 };
    const { byId } = await verify(world);
    assert.notEqual(byId('bg.interactions-concurrency').status, 'PASS');
  });

  it('the interaction function with exactly 5 reserved passes', async () => {
    const { byId } = await verify(deployedBreakGlass());
    assert.equal(byId('bg.interactions-concurrency').status, 'PASS');
  });

  it('a configured concurrency cap clears the WARN', async () => {
    const world = deployedBreakGlass();
    world['lambda get-function-concurrency --function-name ssd-break-glass-production-ci'] = { stdout: '{"ReservedConcurrentExecutions":5}', stderr: '', exitCode: 0 };
    const { byId } = await verify(world);
    assert.equal(byId('bg.ci-concurrency').status, 'PASS');
  });

  it('a simulation the operator may not run is NOT VERIFIED, never PASS', async () => {
    const world = deployedBreakGlass();
    world['iam simulate-principal-policy *'] = { stdout: '', stderr: '\nAn error occurred (AccessDenied) when calling the SimulatePrincipalPolicy operation: denied\n', exitCode: 254 };
    const { report, byId } = await verify(world);
    assert.equal(byId('bg.ci-required-access').status, 'NOT VERIFIED');
    assert.equal(report.outcome, 'NOT_VERIFIED');
  });

  it('a stack that does not exist fails, and nothing pretends otherwise', async () => {
    const world = deployedBreakGlass();
    world[`cloudformation describe-stacks --stack-name ${breakGlassNames('production').stack}`] = { stdout: '', stderr: '\nAn error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id ssd-break-glass-production does not exist\n', exitCode: 254 };
    const { report } = await verify(world);
    assert.ok(failing(report).includes('bg.stack'));
  });
});
