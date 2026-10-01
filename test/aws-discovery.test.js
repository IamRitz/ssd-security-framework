// Read-only discovery and the checks built from it (onboarding/aws/discover/*,
// doctor.mjs), from recorded AWS responses. Each case asserts the status and,
// where it matters, the calls that happened and the calls that must not.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { awsDoctor, exitCodeOf } from '../onboarding/aws/doctor.mjs';
import { scanningCoverage, wildcardFilterMatches } from '../onboarding/aws/discover/ecr.mjs';
import { evaluateOwnership } from '../onboarding/aws/discover/stacks.mjs';
import { grants, statements } from '../onboarding/aws/policy/evaluate.mjs';
import { analyzePermissions } from '../onboarding/aws/policy/permissions.mjs';
import { config } from './support/onboarding-fixtures.mjs';
import {
  ACCOUNT,
  DEPLOY_POLICY,
  DEPLOY_ROLE,
  INSTANCE,
  INSTANCE_ARN,
  INSTANCE_ROLE,
  PROFILE_ARN,
  PROVIDER,
  PUSH_POLICY,
  PUSH_ROLE,
  REGION,
  REPOSITORY,
  REPO_ARN,
  SLUG,
  SSD_STACK_TAGS,
  accessDenied,
  awsError,
  FakeAwsError,
  fakeAws,
  managedStack,
  ok,
  readyWorld,
  simulateKey,
  trustPolicy
} from './support/aws-fake.mjs';

const ECR = 'container-ecr-framework-gated';
const run = async (world, overrides = {}) => {
  const f = fakeAws(world);
  const report = await awsDoctor({ config: config(ECR, { delivery: { environment: 'production' }, ...overrides }), exec: f.exec, env: {} });
  return { report, f, check: (id) => report.checks.find((c) => c.id === id) };
};
const kinds = (check) => check.findings.map((f) => f.kind);
const DESCRIBE_REPO = `ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`;
const SCANNING = 'ecr get-registry-scanning-configuration';
const scanning = (scanType, rules) => ok({ registryId: ACCOUNT, scanningConfiguration: { scanType, rules } });
const rule = (frequency, ...filters) => ({ scanFrequency: frequency, repositoryFilters: filters.map((filter) => ({ filter, filterType: 'WILDCARD' })) });
const TARGET = { partition: 'aws', account: ACCOUNT, region: REGION, repository: REPOSITORY, instanceId: INSTANCE };

describe('ready world', () => {
  it('everything present: READY WITH WARNINGS (subject format only), no unrecorded call', async () => {
    const { report, f } = await run(readyWorld());
    assert.deepEqual(f.unexpected, []);
    assert.equal(report.outcome, 'READY_WITH_WARNINGS');
    assert.deepEqual(
      report.checks.filter((c) => c.status !== 'PASS').map((c) => [c.id, c.status]),
      [['oidc.subject-format', 'NOT VERIFIED']]
    );
  });

  it('the exact read sequence, and no Inspector call under BASIC scanning', async () => {
    const { f } = await run(readyWorld());
    assert.deepEqual(f.operations(), [
      'sts get-caller-identity',
      'iam list-open-id-connect-providers',
      'iam get-open-id-connect-provider',
      'ecr describe-repositories',
      'ecr get-lifecycle-policy',
      'ecr get-repository-policy',
      'ecr list-tags-for-resource',
      'ecr get-registry-scanning-configuration',
      'iam get-role',
      'iam list-role-policies',
      'iam get-role-policy',
      'iam list-attached-role-policies',
      'iam simulate-principal-policy',
      'iam get-role',
      'iam list-role-policies',
      'iam get-role-policy',
      'iam list-attached-role-policies',
      'iam simulate-principal-policy',
      'ec2 describe-instances',
      'ssm describe-instance-information',
      'iam get-instance-profile',
      'iam get-role',
      'iam list-role-policies',
      'iam list-attached-role-policies',
      'iam get-policy',
      'iam get-policy-version',
      'iam get-policy',
      'iam get-policy-version',
      'cloudformation describe-stack-resources',
      'cloudformation describe-stack-resources',
      'cloudformation describe-stack-resources',
      'cloudformation describe-stack-resources'
    ]);
    assert.ok(!f.operations().some((op) => op.startsWith('inspector2 ')));
  });
});

describe('GitHub OIDC provider', () => {
  it('exists with the sts audience: PASS', async () => {
    const { check } = await run(readyWorld());
    assert.equal(check('oidc.provider').status, 'PASS');
  });

  it('absent: FAIL (resource-absent)', async () => {
    const world = readyWorld();
    world['iam list-open-id-connect-providers'] = ok({ OpenIDConnectProviderList: [{ Arn: `arn:aws:iam::${ACCOUNT}:oidc-provider/gitlab.example.com` }] });
    const { check, report } = await run(world);
    assert.equal(check('oidc.provider').status, 'FAIL');
    assert.deepEqual(kinds(check('oidc.provider')), ['resource-absent']);
    assert.equal(report.outcome, 'BLOCKED');
  });

  it('wrong audience: FAIL with the exact client IDs', async () => {
    const world = readyWorld();
    world[`iam get-open-id-connect-provider --open-id-connect-provider-arn ${PROVIDER}`] = ok({ Url: 'token.actions.githubusercontent.com', ClientIDList: ['https://github.com/acme'], ThumbprintList: [] });
    const { check } = await run(world);
    assert.equal(check('oidc.provider').status, 'FAIL');
    assert.ok(kinds(check('oidc.provider')).includes('wrong-audience'));
    assert.ok(check('oidc.provider').findings.some((f) => f.message.includes('https://github.com/acme')));
  });

  it('an extra audience beside sts: WARN', async () => {
    const world = readyWorld();
    world[`iam get-open-id-connect-provider --open-id-connect-provider-arn ${PROVIDER}`] = ok({ Url: 'token.actions.githubusercontent.com', ClientIDList: ['sts.amazonaws.com', 'other'], ThumbprintList: [] });
    const { check } = await run(world);
    assert.equal(check('oidc.provider').status, 'WARN');
  });

  it('a provider listed in another account: FAIL (account-mismatch)', async () => {
    const other = PROVIDER.replace(ACCOUNT, '999999999999');
    const world = readyWorld();
    world['iam list-open-id-connect-providers'] = ok({ OpenIDConnectProviderList: [{ Arn: other }] });
    world[`iam get-open-id-connect-provider --open-id-connect-provider-arn ${other}`] = ok({ Url: 'token.actions.githubusercontent.com', ClientIDList: ['sts.amazonaws.com'], ThumbprintList: [] });
    world[`cloudformation describe-stack-resources --physical-resource-id ${other}`] = awsError('ValidationError', 'DescribeStackResources', `Stack for ${other} does not exist`);
    const { check } = await run(world);
    assert.equal(check('oidc.provider').status, 'FAIL');
    assert.ok(kinds(check('oidc.provider')).includes('account-mismatch'));
  });

  it('access denied: NOT VERIFIED, never absent', async () => {
    const world = readyWorld();
    world['iam list-open-id-connect-providers'] = accessDenied('ListOpenIDConnectProviders', 'iam:ListOpenIDConnectProviders');
    const { check, report } = await run(world);
    assert.equal(check('oidc.provider').status, 'NOT VERIFIED');
    assert.deepEqual(kinds(check('oidc.provider')), ['authorization']);
    assert.equal(report.outcome, 'NOT_VERIFIED');
  });
});

describe('ECR repository', () => {
  it('exists: facts reported (ARN, URI, encryption, lifecycle, repository policy)', async () => {
    const { check } = await run(readyWorld());
    const c = check('ecr.repository');
    assert.equal(c.status, 'PASS');
    assert.ok(c.observed.includes(`ARN ${REPO_ARN}`));
    assert.ok(c.observed.includes('encryption: AES256'));
    assert.ok(c.observed.includes('lifecycle policy: none'));
    assert.ok(c.observed.includes('repository policy: none'));
  });

  it('absent: FAIL, and nothing further is read about it', async () => {
    const world = readyWorld();
    world[DESCRIBE_REPO] = awsError('RepositoryNotFoundException', 'DescribeRepositories');
    const { check, f } = await run(world);
    assert.equal(check('ecr.repository').status, 'FAIL');
    assert.ok(!f.operations().includes('ecr get-lifecycle-policy'));
    assert.equal(check('ownership.ecr-repository').status, 'NOT VERIFIED');
  });

  it('access denied: NOT VERIFIED, not absent', async () => {
    const world = readyWorld();
    world[DESCRIBE_REPO] = accessDenied('DescribeRepositories', 'ecr:DescribeRepositories');
    const { check } = await run(world);
    assert.equal(check('ecr.repository').status, 'NOT VERIFIED');
    assert.ok(!kinds(check('ecr.repository')).includes('resource-absent'));
  });

  it('mutable tags: reported as WARN; immutable: PASS', async () => {
    const world = readyWorld();
    const doc = JSON.parse(world[DESCRIBE_REPO].stdout);
    doc.repositories[0].imageTagMutability = 'MUTABLE';
    world[DESCRIBE_REPO] = ok(doc);
    const { check } = await run(world);
    assert.equal(check('ecr.tag-immutability').status, 'WARN');
    assert.deepEqual(check('ecr.tag-immutability').observed, ['MUTABLE']);
    assert.equal((await run(readyWorld())).check('ecr.tag-immutability').status, 'PASS');
  });

  it('a public repository policy FAILs', async () => {
    const world = readyWorld();
    world[`ecr get-repository-policy --registry-id ${ACCOUNT} --repository-name ${REPOSITORY}`] = ok({
      policyText: JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'Public', Effect: 'Allow', Principal: '*', Action: 'ecr:BatchGetImage' }] })
    });
    const { check } = await run(world);
    assert.equal(check('ecr.repository').status, 'FAIL');
    assert.ok(kinds(check('ecr.repository')).includes('public-repository-policy'));
  });
});

describe('registry scanning coverage', () => {
  const coverage = (scanType, rules, options) => scanningCoverage({ scanType, rules: rules.map((r) => ({ frequency: r.scanFrequency, filters: r.repositoryFilters.map((x) => ({ filter: x.filter, type: x.filterType })) })) }, REPOSITORY, options);

  it('a rule for the exact repository covers it', () => {
    assert.equal(coverage('BASIC', [rule('SCAN_ON_PUSH', 'app')]).covered, true);
  });

  it('a wildcard rule covers it', () => {
    assert.equal(coverage('BASIC', [rule('SCAN_ON_PUSH', '*')]).covered, true);
    assert.equal(coverage('ENHANCED', [rule('CONTINUOUS_SCAN', 'a*')]).covered, true);
    assert.equal(wildcardFilterMatches('prod/*', 'prod/app'), true);
    assert.equal(wildcardFilterMatches('app', 'app2'), false, 'no implicit prefix match');
    assert.equal(wildcardFilterMatches('a.p', 'app'), false, 'only * is special');
  });

  it('a rule for another repository does not cover it', () => {
    assert.equal(coverage('BASIC', [rule('SCAN_ON_PUSH', 'other', 'app-*')]).covered, false);
    assert.equal(coverage('ENHANCED', []).covered, false);
  });

  it('MANUAL is not automatic coverage; CONTINUOUS_SCAN is not a BASIC frequency', () => {
    assert.equal(coverage('BASIC', [rule('MANUAL', '*')]).covered, false);
    const continuousBasic = coverage('BASIC', [rule('CONTINUOUS_SCAN', '*')]);
    assert.equal(continuousBasic.covered, false);
    assert.equal(continuousBasic.unsupported.length, 1);
  });

  it('ENHANCED ignores the repository-level scanOnPush; BASIC honours it (deprecated)', () => {
    assert.equal(coverage('ENHANCED', [], { repositoryScanOnPush: true }).covered, false);
    assert.equal(coverage('BASIC', [], { repositoryScanOnPush: true }).basis, 'repository-setting');
  });

  it('the higher ENHANCED frequency wins', () => {
    assert.equal(coverage('ENHANCED', [rule('SCAN_ON_PUSH', '*'), rule('CONTINUOUS_SCAN', 'app')]).frequency, 'CONTINUOUS_SCAN');
  });

  it('doctor: uncovered FAILs; covered PASSes', async () => {
    const world = readyWorld();
    world[SCANNING] = scanning('BASIC', [rule('SCAN_ON_PUSH', 'other')]);
    const { check } = await run(world);
    assert.equal(check('ecr.scanning').status, 'FAIL');
    assert.ok(kinds(check('ecr.scanning')).includes('not-covered'));
  });

  it('doctor: access denied on the scanning configuration is NOT VERIFIED', async () => {
    const world = readyWorld();
    world[SCANNING] = accessDenied('GetRegistryScanningConfiguration', 'ecr:GetRegistryScanningConfiguration');
    const { check } = await run(world);
    assert.equal(check('ecr.scanning').status, 'NOT VERIFIED');
  });
});

describe('Inspector (enhanced scanning)', () => {
  const COVERAGE = `inspector2 list-coverage --filter-criteria ${JSON.stringify({ resourceType: [{ comparison: 'EQUALS', value: 'AWS_ECR_REPOSITORY' }], ecrRepositoryName: [{ comparison: 'EQUALS', value: REPOSITORY }] })}`;
  const enhancedWorld = (ecrState, records) => {
    const world = readyWorld();
    world[SCANNING] = scanning('ENHANCED', [rule('SCAN_ON_PUSH', '*')]);
    world[`inspector2 batch-get-account-status --account-ids ${ACCOUNT}`] = ok({ accounts: [{ accountId: ACCOUNT, state: { status: 'ENABLED' }, resourceState: { ecr: { status: ecrState } } }] });
    world[COVERAGE] = ok({ coveredResources: records });
    // ENHANCED adds the inspector2 actions to the push role's first simulation group.
    return world;
  };

  it('enhanced + Inspector ECR ENABLED + ACTIVE coverage: PASS', async () => {
    const world = enhancedWorld('ENABLED', [{ resourceId: REPO_ARN, resourceType: 'AWS_ECR_REPOSITORY', scanStatus: { statusCode: 'ACTIVE' } }]);
    world[`iam get-role-policy --role-name app-ecr-push-scan --policy-name push`] = ok({ PolicyDocument: { ...PUSH_POLICY, Statement: [...PUSH_POLICY.Statement, { Effect: 'Allow', Action: ['inspector2:ListCoverage', 'inspector2:ListFindings'], Resource: '*' }] } });
    const { check, f } = await run(world);
    assert.equal(check('ecr.inspector').status, 'PASS');
    assert.equal(check('iam.push-permissions').status, 'PASS');
    assert.ok(f.operations().includes('inspector2 batch-get-account-status'));
  });

  it('enhanced but Inspector ECR scanning DISABLED: FAIL', async () => {
    const { check } = await run(enhancedWorld('DISABLED', []));
    assert.equal(check('ecr.inspector').status, 'FAIL');
    assert.ok(kinds(check('ecr.inspector')).includes('inspector-disabled'));
  });

  it('Inspector enabled is not the same as this repository covered', async () => {
    const inactive = await run(enhancedWorld('ENABLED', [{ resourceId: REPO_ARN, resourceType: 'AWS_ECR_REPOSITORY', scanStatus: { statusCode: 'INACTIVE', reason: 'EXCLUDED' } }]));
    assert.equal(inactive.check('ecr.inspector').status, 'FAIL');
    const none = await run(enhancedWorld('ENABLED', []));
    assert.ok(kinds(none.check('ecr.inspector')).includes('no-coverage-record'));
  });

  it('enhanced requires the Inspector statement on the push role', async () => {
    const { check } = await run(enhancedWorld('ENABLED', []));
    assert.equal(check('iam.push-permissions').status, 'FAIL');
    assert.ok(check('iam.push-permissions').findings.some((f) => f.message.startsWith('inspector2:ListCoverage')));
  });
});

describe('IAM roles', () => {
  it('role missing: FAIL, and its trust/permissions are NOT VERIFIED (never PASS)', async () => {
    const world = readyWorld();
    world['iam get-role --role-name app-deploy'] = awsError('NoSuchEntity', 'GetRole', 'The role with name app-deploy cannot be found.');
    const { check, f } = await run(world);
    assert.equal(check('iam.deploy-role').status, 'FAIL');
    assert.deepEqual(kinds(check('iam.deploy-role')), ['resource-absent']);
    assert.equal(check('iam.deploy-trust').status, 'NOT VERIFIED');
    assert.equal(check('iam.deploy-permissions').status, 'NOT VERIFIED');
    assert.ok(!f.keys().includes('iam list-role-policies --role-name app-deploy'));
  });

  it('role exists: PASS', async () => {
    const { check } = await run(readyWorld());
    assert.equal(check('iam.push-role').status, 'PASS');
    assert.equal(check('iam.deploy-role').status, 'PASS');
  });

  it('access denied on get-role is NOT VERIFIED, never absent', async () => {
    const world = readyWorld();
    world['iam get-role --role-name app-deploy'] = accessDenied('GetRole', 'iam:GetRole');
    const { check, report } = await run(world);
    assert.equal(check('iam.deploy-role').status, 'NOT VERIFIED');
    assert.ok(!kinds(check('iam.deploy-role')).includes('resource-absent'));
    assert.equal(report.outcome, 'NOT_VERIFIED');
  });

  it('a same-named role on another path is not the configured role', async () => {
    const world = readyWorld();
    world['iam get-role --role-name app-deploy'] = ok({ Role: { Arn: `arn:aws:iam::${ACCOUNT}:role/other/app-deploy`, RoleName: 'app-deploy', AssumeRolePolicyDocument: {} } });
    const { check } = await run(world);
    assert.deepEqual(kinds(check('iam.deploy-role')), ['role-arn-mismatch']);
  });

  it('inline policies are retrieved and analysed', async () => {
    const world = readyWorld();
    world['iam get-role-policy --role-name app-deploy --policy-name deploy'] = ok({ PolicyDocument: { Version: '2012-10-17', Statement: [DEPLOY_POLICY.Statement[1]] } });
    const { check } = await run(world);
    assert.equal(check('iam.deploy-permissions').status, 'FAIL');
    assert.ok(check('iam.deploy-permissions').findings.some((f) => f.kind === 'permission-missing' && f.message.startsWith('ssm:SendCommand')));
  });

  it('attached managed policies are retrieved (default version) and analysed', async () => {
    const world = readyWorld();
    const managed = `arn:aws:iam::${ACCOUNT}:policy/deploy-managed`;
    world['iam list-role-policies --role-name app-deploy'] = ok({ PolicyNames: [] });
    world['iam list-attached-role-policies --role-name app-deploy'] = ok({ AttachedPolicies: [{ PolicyName: 'deploy-managed', PolicyArn: managed }] });
    world[`iam get-policy --policy-arn ${managed}`] = ok({ Policy: { DefaultVersionId: 'v3' } });
    world[`iam get-policy-version --policy-arn ${managed} --version-id v3`] = ok({ PolicyVersion: { Document: encodeURIComponent(JSON.stringify(DEPLOY_POLICY)) } });
    const { check, f } = await run(world);
    assert.equal(check('iam.deploy-permissions').status, 'PASS');
    assert.ok(f.keys().includes(`iam get-policy-version --policy-arn ${managed} --version-id v3`));
  });

  it('a policy that cannot be read makes the analysis NOT VERIFIED, never PASS', async () => {
    const world = readyWorld();
    world['iam list-attached-role-policies --role-name app-deploy'] = accessDenied('ListAttachedRolePolicies', 'iam:ListAttachedRolePolicies');
    const { check } = await run(world);
    assert.equal(check('iam.deploy-permissions').status, 'NOT VERIFIED');
  });

  it('role separation: a push role that can reach the instance, a deploy role that can push, admin', () => {
    const push = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: { Statement: [...PUSH_POLICY.Statement, { Effect: 'Allow', Action: 'ssm:SendCommand', Resource: '*' }] } }], complete: true });
    assert.equal(push.status, 'FAIL');
    assert.ok(push.findings.some((f) => f.kind === 'permission-too-broad' && f.message.startsWith('ssm:SendCommand')));
    const deploy = analyzePermissions('deploy', TARGET, { policies: [{ name: 'd', document: { Statement: [...DEPLOY_POLICY.Statement, { Effect: 'Allow', Action: 'ecr:*', Resource: '*' }] } }], complete: true });
    assert.equal(deploy.status, 'FAIL');
    const admin = analyzePermissions('push', TARGET, { policies: [{ name: 'a', document: { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } }], complete: true });
    assert.ok(admin.findings.some((f) => f.kind === 'administrator'));
    const otherRepo = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: { Statement: [{ Effect: 'Allow', Action: 'ecr:*', Resource: `arn:aws:ecr:${REGION}:${ACCOUNT}:repository/*` }, PUSH_POLICY.Statement[0]] } }], complete: true });
    assert.ok(otherRepo.findings.some((f) => f.kind === 'permission-too-broad' && f.severity === 'FAIL'));
  });

  it('simulation that denies what the documents allow is a FAIL; the basis names both', async () => {
    const world = readyWorld();
    world[simulateKey(DEPLOY_ROLE, ['ssm:SendCommand'], INSTANCE_ARN)] = ok({ EvaluationResults: [{ EvalActionName: 'ssm:SendCommand', EvalResourceName: INSTANCE_ARN, EvalDecision: 'implicitDeny' }] });
    world[simulateKey(DEPLOY_ROLE, ['ssm:SendCommand'], `arn:aws:ssm:${REGION}::document/AWS-RunShellScript`)] = ok({ EvaluationResults: [{ EvalActionName: 'ssm:SendCommand', EvalResourceName: `arn:aws:ssm:${REGION}::document/AWS-RunShellScript`, EvalDecision: 'allowed' }] });
    world[simulateKey(DEPLOY_ROLE, ['ssm:GetCommandInvocation'], '*')] = ok({ EvaluationResults: [{ EvalActionName: 'ssm:GetCommandInvocation', EvalResourceName: '*', EvalDecision: 'allowed' }] });
    const { check } = await run(world);
    const c = check('iam.deploy-permissions');
    assert.equal(c.basis, 'policy-document+simulation');
    assert.equal(c.status, 'FAIL');
    assert.ok(kinds(c).includes('simulation-denies'));
  });

  it('trust scoping is enforced per role intent', async () => {
    const world = readyWorld();
    world['iam get-role --role-name app-ecr-push-scan'] = ok({ Role: { Arn: PUSH_ROLE, RoleName: 'app-ecr-push-scan', AssumeRolePolicyDocument: trustPolicy({ operator: 'StringLike', subjects: [`repo:${SLUG}:*`] }) } });
    const { check } = await run(world);
    assert.equal(check('iam.push-trust').status, 'FAIL');
    assert.ok(kinds(check('iam.push-trust')).includes('wildcard-subject'));
  });

  it('deploy without a GitHub environment trusts the branch context, with a WARN', async () => {
    const world = readyWorld();
    world['iam get-role --role-name app-deploy'] = ok({ Role: { Arn: DEPLOY_ROLE, RoleName: 'app-deploy', AssumeRolePolicyDocument: trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] }) } });
    const { check } = await run(world, { delivery: { environment: '' } });
    assert.equal(check('iam.deploy-trust').status, 'WARN');
    assert.ok(kinds(check('iam.deploy-trust')).includes('no-environment'));
  });
});

describe('SSM', () => {
  const INFO = `ssm describe-instance-information --filters ${JSON.stringify([{ Key: 'InstanceIds', Values: [INSTANCE] }])}`;
  const DESCRIBE = `ec2 describe-instances --instance-ids ${INSTANCE}`;

  it('Online: PASS', async () => {
    const { check } = await run(readyWorld());
    assert.equal(check('ssm.managed').status, 'PASS');
    assert.equal(check('ssm.instance').status, 'PASS');
    assert.equal(check('ssm.instance-role').status, 'PASS');
  });

  it('ConnectionLost (offline): FAIL', async () => {
    const world = readyWorld();
    world[INFO] = ok({ InstanceInformationList: [{ InstanceId: INSTANCE, PingStatus: 'ConnectionLost', ResourceType: 'EC2Instance' }] });
    const { check, report } = await run(world);
    assert.equal(check('ssm.managed').status, 'FAIL');
    assert.deepEqual(kinds(check('ssm.managed')), ['instance-offline']);
    assert.equal(report.outcome, 'BLOCKED');
  });

  it('absent from EC2 and SSM: FAIL', async () => {
    const world = readyWorld();
    world[DESCRIBE] = awsError('InvalidInstanceID.NotFound', 'DescribeInstances', `The instance ID '${INSTANCE}' does not exist`);
    world[INFO] = ok({ InstanceInformationList: [] });
    const { check } = await run(world);
    assert.equal(check('ssm.instance').status, 'FAIL');
    assert.equal(check('ssm.managed').status, 'FAIL');
    assert.deepEqual(kinds(check('ssm.managed')), ['not-managed']);
    assert.equal(check('ssm.instance-role').status, 'NOT VERIFIED');
  });

  it('access denied: NOT VERIFIED, not absent', async () => {
    const world = readyWorld();
    world[DESCRIBE] = awsError('UnauthorizedOperation', 'DescribeInstances', 'You are not authorized to perform this operation.');
    world[INFO] = accessDenied('DescribeInstanceInformation', 'ssm:DescribeInstanceInformation');
    const { check } = await run(world);
    assert.equal(check('ssm.instance').status, 'NOT VERIFIED');
    assert.equal(check('ssm.managed').status, 'NOT VERIFIED');
  });

  it('wrong instance/profile relationship: no role, another account, missing pull permission', async () => {
    const noRole = readyWorld();
    noRole['iam get-instance-profile --instance-profile-name app-instance'] = ok({ InstanceProfile: { Arn: PROFILE_ARN, Roles: [] } });
    assert.deepEqual(kinds((await run(noRole)).check('ssm.instance-role')), ['profile-relationship']);

    const otherAccount = readyWorld();
    otherAccount[DESCRIBE] = ok({ Reservations: [{ OwnerId: ACCOUNT, Instances: [{ InstanceId: INSTANCE, State: { Name: 'running' }, IamInstanceProfile: { Arn: 'arn:aws:iam::999999999999:instance-profile/x' } }] }] });
    const other = await run(otherAccount);
    assert.deepEqual(kinds(other.check('ssm.instance-role')), ['account-mismatch']);
    assert.ok(!other.f.operations().includes('iam get-instance-profile'), 'nothing is read in another account');

    const noPull = readyWorld();
    noPull['iam list-attached-role-policies --role-name app-instance'] = ok({ AttachedPolicies: [{ PolicyName: 'AmazonSSMManagedInstanceCore', PolicyArn: 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore' }] });
    const pull = await run(noPull);
    assert.equal(pull.check('ssm.instance-role').status, 'FAIL');
    assert.ok(pull.check('ssm.instance-role').remediation[0].startsWith('RECOMMENDATION'), 'a proposed policy, never attached');
    assert.ok(!pull.f.operations().some((op) => / (attach|put|detach)-/.test(op)));
  });

  it('an instance owned by another account: FAIL', async () => {
    const world = readyWorld();
    world[DESCRIBE] = ok({ Reservations: [{ OwnerId: '999999999999', Instances: [{ InstanceId: INSTANCE, State: { Name: 'running' }, IamInstanceProfile: { Arn: PROFILE_ARN } }] }] });
    assert.ok(kinds((await run(world)).check('ssm.instance')).includes('account-mismatch'));
  });

  it('SSM core is proven by Online at runtime; without it, only a WARN', async () => {
    const world = readyWorld();
    world['iam list-attached-role-policies --role-name app-instance'] = ok({ AttachedPolicies: [{ PolicyName: 'app-pull', PolicyArn: `arn:aws:iam::${ACCOUNT}:policy/app-pull` }] });
    const online = await run(world);
    assert.equal(online.check('ssm.instance-role').status, 'PASS');
    assert.equal(online.check('ssm.instance-role').basis, 'policy-document+runtime');
  });

  it('the instance role ARN comes from the profile, not from naming', async () => {
    const { f } = await run(readyWorld());
    assert.ok(f.keys().includes(`iam get-role --role-name ${INSTANCE_ROLE.split('/').pop()}`));
  });
});

describe('ownership: existence is not ownership', () => {
  const roleTags = (tags) => tags.map((t) => ({ key: t.Key, value: t.Value }));

  it('a matching name with no managed stack is NOT owned', async () => {
    const { check } = await run(readyWorld());
    for (const id of ['ownership.oidc-provider', 'ownership.ecr-repository', 'ownership.push-role', 'ownership.deploy-role']) {
      assert.equal(check(id).ownership, 'exists-not-owned', id);
    }
  });

  it('ssd:* tags without a stack relationship are NOT ownership', () => {
    const result = evaluateOwnership({ discovered: { stackResource: { state: 'absent', code: 'ValidationError' }, stack: null }, resourceTags: roleTags(SSD_STACK_TAGS), expectedType: 'AWS::IAM::Role', slug: SLUG, scope: 'repo' });
    assert.equal(result.ownership, 'exists-not-owned');
  });

  it('the correct stack + tags is managed', async () => {
    const world = managedStack(readyWorld(), 'app-deploy', { type: 'AWS::IAM::Role', tags: SSD_STACK_TAGS });
    const { check } = await run(world, { delivery: { environment: 'production', roles: { deployOwnership: 'managed' } } });
    assert.equal(check('ownership.deploy-role').ownership, 'managed');
    assert.equal(check('ownership.deploy-role').status, 'PASS');
  });

  it('a wrong consumer tag is not managed', async () => {
    const tags = SSD_STACK_TAGS.map((t) => (t.Key === 'ssd:consumer-repository' ? { ...t, Value: 'acme/other' } : t));
    const world = managedStack(readyWorld(), 'app-deploy', { type: 'AWS::IAM::Role', tags });
    const { check } = await run(world, { delivery: { environment: 'production', roles: { deployOwnership: 'managed' } } });
    assert.equal(check('ownership.deploy-role').ownership, 'exists-not-owned');
    assert.equal(check('ownership.deploy-role').status, 'FAIL');
    assert.ok(kinds(check('ownership.deploy-role')).includes('present-unowned'));
  });

  it('a stack without ssd:managed-by, of the wrong type, or deleted is not managed', () => {
    const base = (stackTags, type = 'AWS::IAM::Role', status = 'CREATE_COMPLETE') => ({
      stackResource: { state: 'present', value: { stackName: 's', stackId: 's', logicalId: 'R', type } },
      stack: { state: 'present', value: { name: 's', status, tags: roleTags(stackTags) } }
    });
    const evaluate = (discovered) => evaluateOwnership({ discovered, resourceTags: null, expectedType: 'AWS::IAM::Role', slug: SLUG, scope: 'repo' }).ownership;
    assert.equal(evaluate(base(SSD_STACK_TAGS)), 'managed');
    assert.equal(evaluate(base(SSD_STACK_TAGS.filter((t) => t.Key !== 'ssd:managed-by'))), 'exists-not-owned');
    assert.equal(evaluate(base(SSD_STACK_TAGS, 'AWS::IAM::Policy')), 'exists-not-owned');
    assert.equal(evaluate(base(SSD_STACK_TAGS, 'AWS::IAM::Role', 'DELETE_COMPLETE')), 'exists-not-owned');
    assert.equal(evaluate(base(SSD_STACK_TAGS.filter((t) => t.Key !== 'ssd:environment'))), 'exists-not-owned');
  });

  it('a resource tag naming another consumer overrides matching stack tags', () => {
    const result = evaluateOwnership({
      discovered: { stackResource: { state: 'present', value: { stackName: 's', stackId: 's', logicalId: 'R', type: 'AWS::IAM::Role' } }, stack: { state: 'present', value: { name: 's', status: 'CREATE_COMPLETE', tags: roleTags(SSD_STACK_TAGS) } } },
      resourceTags: [{ key: 'ssd:consumer-repository', value: 'acme/other' }],
      expectedType: 'AWS::IAM::Role',
      slug: SLUG,
      scope: 'repo'
    });
    assert.equal(result.ownership, 'exists-not-owned');
  });

  it('access denied on the stack lookup is NOT VERIFIED, not "not owned"', async () => {
    const world = readyWorld();
    world['cloudformation describe-stack-resources --physical-resource-id app-deploy'] = accessDenied('DescribeStackResources', 'cloudformation:DescribeStackResources');
    const { check } = await run(world);
    assert.equal(check('ownership.deploy-role').ownership, 'unverified');
    assert.equal(check('ownership.deploy-role').status, 'NOT VERIFIED');
    assert.equal(check('ownership.deploy-role').required, false, 'existing mode: informational');
  });
});

// --- hardened readiness conclusions (follow-up review fixes) ----------------------

const pushRoleWith = (world, extra, base = PUSH_POLICY) => {
  world['iam get-role-policy --role-name app-ecr-push-scan --policy-name push'] = ok({ PolicyDocument: { ...base, Statement: [...base.Statement, ...extra] } });
  return world;
};
const deployRoleWith = (world, statements) => {
  world['iam get-role-policy --role-name app-deploy --policy-name deploy'] = ok({ PolicyDocument: { Version: '2012-10-17', Statement: statements } });
  return world;
};
const COND = { Bool: { 'aws:SecureTransport': 'true' } };

describe('M3: unknown registry scan type fails closed', () => {
  for (const [label, scanType] of [['missing', undefined], ['unrecognised', 'PREMIUM']]) {
    it(`a ${label} scanType: scanning is required NOT VERIFIED, exit 1, Inspector not consulted`, async () => {
      const world = readyWorld();
      world[SCANNING] = ok({ registryId: ACCOUNT, scanningConfiguration: { ...(scanType ? { scanType } : {}), rules: [rule('SCAN_ON_PUSH', '*')] } });
      const { check, report, f } = await run(world);
      assert.equal(check('ecr.scanning').status, 'NOT VERIFIED');
      assert.equal(check('ecr.scanning').required, true);
      assert.deepEqual(kinds(check('ecr.scanning')), ['scan-type-unknown']);
      assert.equal(report.outcome, 'NOT_VERIFIED');
      assert.equal(exitCodeOf(report), 1);
      assert.ok(!f.operations().some((op) => op.startsWith('inspector2 ')));
    });
  }

  it('unknown scan type: a push role WITHOUT the Inspector statement is NOT VERIFIED (possibly needed), never PASS or FAIL', async () => {
    const world = readyWorld();
    world[SCANNING] = ok({ registryId: ACCOUNT, scanningConfiguration: { rules: [] } });
    const { check } = await run(world);
    const c = check('iam.push-permissions');
    assert.equal(c.status, 'NOT VERIFIED');
    assert.ok(c.findings.some((x) => x.severity === 'NOT VERIFIED' && x.message.startsWith('inspector2:ListCoverage')));
    assert.ok(!c.findings.some((x) => x.severity === 'FAIL'));
  });

  it('unknown scan type: a push role WITH the Inspector statement has no possibly-needed finding', async () => {
    const world = pushRoleWith(readyWorld(), [{ Effect: 'Allow', Action: ['inspector2:ListCoverage', 'inspector2:ListFindings'], Resource: '*' }]);
    world[SCANNING] = accessDenied('GetRegistryScanningConfiguration', 'ecr:GetRegistryScanningConfiguration');
    const { check } = await run(world);
    assert.equal(check('iam.push-permissions').status, 'PASS');
    assert.equal(check('ecr.scanning').status, 'NOT VERIFIED');
  });

  it('BASIC never asks for Inspector; ENHANCED makes it a hard requirement', () => {
    const basic = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: PUSH_POLICY }], complete: true, enhanced: false });
    assert.equal(basic.status, 'PASS');
    const enhanced = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: PUSH_POLICY }], complete: true, enhanced: true });
    assert.ok(enhanced.findings.some((x) => x.severity === 'FAIL' && x.message.startsWith('inspector2:ListCoverage')));
  });
});

describe('H2: managed vs existing ownership conclusions', () => {
  it('managed + exists-not-owned (name-only): FAIL, BLOCKED, exit 1', async () => {
    const { check, report } = await run(readyWorld(), { delivery: { environment: 'production', roles: { deployOwnership: 'managed' } } });
    const c = check('ownership.deploy-role');
    assert.deepEqual([c.ownership, c.status, c.required], ['exists-not-owned', 'FAIL', true]);
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(exitCodeOf(report), 1);
  });

  it('managed + exists-not-owned blocks for every managed resource kind', async () => {
    for (const overrides of [{ ecr: { ownership: 'managed' } }, { oidcProvider: 'managed' }, { roles: { pushScanOwnership: 'managed' } }]) {
      const { report } = await run(readyWorld(), { delivery: { environment: 'production', ...overrides } });
      assert.equal(report.outcome, 'BLOCKED', JSON.stringify(overrides));
    }
  });

  it('existing + managed-owned: WARN (mode mismatch), exit 0', async () => {
    const world = managedStack(readyWorld(), 'app-deploy', { type: 'AWS::IAM::Role', tags: SSD_STACK_TAGS });
    const { check, report } = await run(world);
    const c = check('ownership.deploy-role');
    assert.deepEqual([c.ownership, c.status, c.required], ['managed', 'WARN', false]);
    assert.ok(kinds(c).includes('ownership-mode-mismatch'));
    assert.equal(exitCodeOf(report), 0);
  });

  it('managed + managed-owned: PASS', async () => {
    const world = managedStack(readyWorld(), 'app-deploy', { type: 'AWS::IAM::Role', tags: SSD_STACK_TAGS });
    const { check } = await run(world, { delivery: { environment: 'production', roles: { deployOwnership: 'managed' } } });
    assert.equal(check('ownership.deploy-role').status, 'PASS');
  });
});

describe('H1 + M2: permission conclusions fail closed', () => {
  it('a push role with Allow NotAction on "*" (everything but IAM): FAIL, BLOCKED, exit 1', async () => {
    const world = pushRoleWith(readyWorld(), [{ Sid: 'AllButIam', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }]);
    const { check, report } = await run(world);
    const c = check('iam.push-permissions');
    assert.equal(c.status, 'FAIL');
    assert.ok(kinds(c).includes('possible-administrator'));
    assert.ok(c.findings.some((x) => x.kind === 'permission-too-broad' && x.severity === 'FAIL' && x.message.startsWith('ssm:SendCommand')));
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(exitCodeOf(report), 1);
  });

  it('Allow NotAction with NotResource is possible administrator too; a scoped NotAction is not', () => {
    const notResource = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: { Statement: [...PUSH_POLICY.Statement, { Effect: 'Allow', NotAction: 'iam:*', NotResource: 'arn:aws:s3:::x' }] } }], complete: true });
    assert.ok(notResource.findings.some((x) => x.kind === 'possible-administrator'));
    const scoped = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: { Statement: [...PUSH_POLICY.Statement, { Effect: 'Allow', NotAction: 'ecr:DeleteRepository', Resource: REPO_ARN }] } }], complete: true });
    assert.ok(!scoped.findings.some((x) => x.kind === 'possible-administrator'));
  });

  it('a forbidden action granted only under a Condition is FAIL, never WARN', async () => {
    const world = pushRoleWith(readyWorld(), [{ Sid: 'MaybeSsm', Effect: 'Allow', Action: 'ssm:SendCommand', Resource: '*', Condition: COND }]);
    const { check, report } = await run(world);
    assert.equal(check('iam.push-permissions').status, 'FAIL');
    assert.ok(check('iam.push-permissions').findings.some((x) => x.kind === 'permission-too-broad' && x.severity === 'FAIL'));
    assert.equal(exitCodeOf(report), 1);
  });

  it('a conditional Deny does not hide a forbidden grant; an unconditional Deny does', () => {
    const allowSsm = { Effect: 'Allow', Action: 'ssm:SendCommand', Resource: '*' };
    const conditionalDeny = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: { Statement: [...PUSH_POLICY.Statement, allowSsm, { Effect: 'Deny', Action: 'ssm:*', Resource: '*', Condition: COND }] } }], complete: true });
    assert.ok(conditionalDeny.findings.some((x) => x.kind === 'permission-too-broad' && x.severity === 'FAIL'));
    const hardDeny = analyzePermissions('push', TARGET, { policies: [{ name: 'p', document: { Statement: [...PUSH_POLICY.Statement, allowSsm, { Effect: 'Deny', Action: 'ssm:*', Resource: '*' }] } }], complete: true });
    assert.ok(!hardDeny.findings.some((x) => x.kind === 'permission-too-broad'));
  });

  it('a required action granted only under a Condition is required NOT VERIFIED, exit 1', async () => {
    const world = deployRoleWith(readyWorld(), DEPLOY_POLICY.Statement.map((s) => ({ ...s, Condition: COND })));
    const { check, report } = await run(world);
    const c = check('iam.deploy-permissions');
    assert.deepEqual([c.status, c.required], ['NOT VERIFIED', true]);
    assert.ok(c.findings.every((x) => x.severity !== 'WARN'));
    assert.ok(kinds(c).includes('permission-unproven'));
    assert.equal(report.outcome, 'NOT_VERIFIED');
    assert.equal(exitCodeOf(report), 1);
  });

  it('a required action granted only through NotAction / NotResource is NOT VERIFIED', () => {
    const viaNotAction = analyzePermissions('deploy', TARGET, {
      policies: [{ name: 'd', document: { Statement: [{ Effect: 'Allow', NotAction: 'ecr:*', Resource: [INSTANCE_ARN, `arn:aws:ssm:${REGION}::document/AWS-RunShellScript`] }, DEPLOY_POLICY.Statement[1]] } }],
      complete: true
    });
    assert.equal(viaNotAction.status, 'NOT VERIFIED');
    assert.ok(viaNotAction.findings.some((x) => x.kind === 'permission-unproven' && x.message.startsWith('ssm:SendCommand')));
    const viaNotResource = analyzePermissions('deploy', TARGET, {
      policies: [{ name: 'd', document: { Statement: [{ Effect: 'Allow', Action: 'ssm:SendCommand', NotResource: 'arn:aws:s3:::x' }, DEPLOY_POLICY.Statement[1]] } }],
      complete: true
    });
    assert.ok(viaNotResource.findings.some((x) => x.kind === 'permission-unproven'));
  });

  it('a required action shadowed by a conditional Deny is NOT VERIFIED; by an unconditional Deny, FAIL', () => {
    const shadowed = analyzePermissions('deploy', TARGET, { policies: [{ name: 'd', document: { Statement: [...DEPLOY_POLICY.Statement, { Effect: 'Deny', Action: 'ssm:GetCommandInvocation', Resource: '*', Condition: COND }] } }], complete: true });
    assert.equal(shadowed.status, 'NOT VERIFIED');
    const denied = analyzePermissions('deploy', TARGET, { policies: [{ name: 'd', document: { Statement: [...DEPLOY_POLICY.Statement, { Effect: 'Deny', Action: 'ssm:GetCommandInvocation', Resource: '*' }] } }], complete: true });
    assert.equal(denied.status, 'FAIL');
  });

  it('grants(): NotAction / NotResource are matched by their IAM meaning', () => {
    const stmts = statements({ Statement: [{ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }] });
    assert.equal(grants(stmts, 'ssm:SendCommand', INSTANCE_ARN).decision, 'conditional');
    assert.equal(grants(stmts, 'iam:PassRole', '*').decision, 'not-granted');
    const deny = statements({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }, { Effect: 'Deny', NotAction: 'ecr:*', Resource: '*' }] });
    assert.equal(grants(deny, 'ssm:SendCommand', INSTANCE_ARN).decision, 'denied');
    assert.equal(grants(deny, 'ecr:PutImage', REPO_ARN).decision, 'allowed');
  });

  it('a malformed statement makes a required grant unproven and a forbidden one possible', () => {
    const doc = { Statement: [...DEPLOY_POLICY.Statement, { Effect: 'Maybe', Action: '*', Resource: '*' }] };
    const result = analyzePermissions('deploy', TARGET, { policies: [{ name: 'd', document: doc }], complete: true });
    assert.equal(result.status, 'FAIL', 'forbidden actions are possibly granted');
    assert.ok(result.findings.some((x) => x.kind === 'permission-unproven'));
  });

  it('the trust evaluator still refuses to bound NotAction / NotPrincipal (unchanged)', async () => {
    const { evaluateTrust } = await import('../onboarding/aws/policy/trust.mjs');
    const result = evaluateTrust({ Statement: [{ Effect: 'Allow', Principal: { Federated: PROVIDER }, NotAction: 'sts:AssumeRole' }] }, { account: ACCOUNT, slug: SLUG, contexts: ['ref:refs/heads/main'] });
    assert.equal(result.verdict, 'rejected');
  });
});

describe('L1: only settled, successful stack states prove ownership', () => {
  const discovered = (status) => ({
    stackResource: { state: 'present', value: { stackName: 's', stackId: 's', logicalId: 'R', type: 'AWS::IAM::Role' } },
    stack: { state: 'present', value: { name: 's', status, tags: SSD_STACK_TAGS.map((t) => ({ key: t.Key, value: t.Value })) } }
  });
  const ownershipFor = (status) => evaluateOwnership({ discovered: discovered(status), resourceTags: null, expectedType: 'AWS::IAM::Role', slug: SLUG, scope: 'repo' }).ownership;

  it('the five live states are managed', () => {
    for (const status of ['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_COMPLETE']) {
      assert.equal(ownershipFor(status), 'managed', status);
    }
  });

  it('every transitional, failed or deleted state is not managed', () => {
    for (const status of ['CREATE_IN_PROGRESS', 'DELETE_IN_PROGRESS', 'DELETE_COMPLETE', 'DELETE_FAILED', 'UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_IN_PROGRESS', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'CREATE_FAILED', 'IMPORT_IN_PROGRESS', 'IMPORT_ROLLBACK_FAILED', 'REVIEW_IN_PROGRESS', null, 'SOMETHING_NEW']) {
      assert.equal(ownershipFor(status), 'exists-not-owned', String(status));
    }
  });

  it('doctor: a managed resource whose stack is DELETE_IN_PROGRESS blocks', async () => {
    const world = managedStack(readyWorld(), 'app-deploy', { type: 'AWS::IAM::Role', tags: SSD_STACK_TAGS });
    const key = Object.keys(world).find((k) => k.startsWith('cloudformation describe-stacks'));
    const doc = JSON.parse(world[key].stdout);
    doc.Stacks[0].StackStatus = 'DELETE_IN_PROGRESS';
    world[key] = ok(doc);
    const { check, report } = await run(world, { delivery: { environment: 'production', roles: { deployOwnership: 'managed' } } });
    assert.deepEqual([check('ownership.deploy-role').ownership, check('ownership.deploy-role').status], ['exists-not-owned', 'FAIL']);
    assert.equal(report.outcome, 'BLOCKED');
  });
});

describe('M4: the fake AWS harness is strict', () => {
  it('an unrecorded call fails the run loudly instead of degrading to NOT VERIFIED', async () => {
    const world = readyWorld();
    delete world[`ec2 describe-instances --instance-ids ${INSTANCE}`];
    const f = fakeAws(world);
    await assert.rejects(awsDoctor({ config: config(ECR, { delivery: { environment: 'production' } }), exec: f.exec, env: {} }), (error) => error instanceof FakeAwsError && /UNRECORDED/.test(error.message));
    assert.deepEqual(f.unexpected, [`ec2 describe-instances --instance-ids ${INSTANCE}`]);
  });

  it('a mutating or non-allowlisted argv that bypasses readOnlyAws is refused by the fake itself', async () => {
    const f = fakeAws({ 'ecr put-image --repository-name app': ok({}) });
    const suffix = ['--region', REGION, '--output', 'json', '--no-cli-pager'];
    await assert.rejects(f.exec(['ecr', 'put-image', '--repository-name', 'app', ...suffix]), (error) => error instanceof FakeAwsError && /non-allowlisted/.test(error.message));
    await assert.rejects(f.exec(['iam', 'get-role', '--role-name', 'x', '--endpoint-url', 'https://evil.example', ...suffix]), FakeAwsError);
    await assert.rejects(f.exec(['sts', 'get-caller-identity']), (error) => /wrapper suffix/.test(error.message));
    await assert.rejects(f.exec(['sts', 'get-caller-identity', '--region', REGION, '--output', 'text', '--no-cli-pager']), (error) => /wrapper suffix/.test(error.message));
  });
});
