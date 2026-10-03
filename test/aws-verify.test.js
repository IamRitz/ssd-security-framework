// `ssd-onboard aws verify` (Phase 2D): the deployed boundary, re-read and
// simulated. Fixture-driven (test/support/aws-verify-fake.mjs): no network, no
// AWS credentials.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { READ_ONLY_OPERATIONS, assertReadOnly } from '../onboarding/aws/aws-cli.mjs';
import { simulateProbes } from '../onboarding/aws/discover/iam-role.mjs';
import { verificationProbes } from '../onboarding/aws/policy/permissions.mjs';
import { awsVerify, deniedAccessCheck, exitCodeOf, outcomeOf, requiredAccessCheck, separationCheck, verifyAws } from '../onboarding/aws/verify.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { FRAMEWORK, capture, commitAll, config, makeRepo, write } from './support/onboarding-fixtures.mjs';
import { EXPECTED_STACK, SSD_STACK_TAGS, awsError, fakeAws, ok, trustPolicy } from './support/aws-fake.mjs';
import {
  ACCOUNT,
  DEPLOY_ROLE,
  INSTANCE,
  INSTANCE_ARN,
  INSTANCE_ROLE,
  PUSH_ROLE,
  REGION,
  REPOSITORY,
  REPO_ARN,
  SLUG,
  grants,
  inspectorFilter,
  simulationDenied,
  simulator,
  verifiedWorld
} from './support/aws-verify-fake.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ECR = 'container-ecr-framework-gated';
const ESC = '\x1b';
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]/;
const OTHER_INSTANCE_ARN = `arn:aws:ec2:${REGION}:${ACCOUNT}:instance/i-00000000000000000`;
const SSM_FILTER = JSON.stringify([{ Key: 'InstanceIds', Values: [INSTANCE] }]);

const cfg = (overrides = {}) => config(ECR, { delivery: { environment: 'production', ...overrides } });
const managedCfg = () => cfg({ ecr: { repository: REPOSITORY, ownership: 'managed' }, roles: { pushScanRoleArn: PUSH_ROLE, pushScanOwnership: 'managed', deployRoleArn: DEPLOY_ROLE, deployOwnership: 'managed' } });

async function verify(world, { config: c = cfg(), region = null, env = {} } = {}) {
  const f = fakeAws(world);
  const report = await awsVerify({ config: c, region, exec: f.exec, env });
  assert.deepEqual(f.unexpected, [], 'every AWS call was recorded');
  return { report, f, check: (id) => report.checks.find((x) => x.id === id) ?? assert.fail(`no check ${id}`) };
}

// Allow an extra "action resource" for one role in the simulator.
function grant(world, arn, ...pairs) {
  const table = grants();
  pairs.forEach((p) => table[arn].add(p));
  world[`iam simulate-principal-policy --policy-source-arn ${arn} *`] = simulator(table);
  return world;
}
function revoke(world, arn, ...pairs) {
  const table = grants();
  pairs.forEach((p) => table[arn].delete(p));
  for (const role of [PUSH_ROLE, DEPLOY_ROLE, INSTANCE_ROLE]) {
    world[`iam simulate-principal-policy --policy-source-arn ${role} *`] = simulator(table);
  }
  return world;
}

// The stack relationship ssd-onboard creates: the expected stack, the logical id
// it gives the resource, SSD stack tags.
function owned(world, physicalId, { type, logicalId, tags = SSD_STACK_TAGS, stackName = EXPECTED_STACK }) {
  const stackId = `arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/${stackName}/1`;
  world[`cloudformation describe-stack-resources --physical-resource-id ${physicalId}`] = ok({
    StackResources: [{ StackName: stackName, StackId: stackId, LogicalResourceId: logicalId, PhysicalResourceId: physicalId, ResourceType: type, ResourceStatus: 'CREATE_COMPLETE' }]
  });
  world[`cloudformation describe-stacks --stack-name ${stackId}`] = ok({ Stacks: [{ StackName: stackName, StackId: stackId, StackStatus: 'CREATE_COMPLETE', Tags: tags }] });
  return world;
}
function managedWorld() {
  const world = verifiedWorld();
  const repo = JSON.parse(world[`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`].stdout);
  repo.repositories[0].imageScanningConfiguration.scanOnPush = true;
  world[`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`] = ok(repo);
  owned(world, REPOSITORY, { type: 'AWS::ECR::Repository', logicalId: 'EcrRepository' });
  owned(world, 'app-ecr-push-scan', { type: 'AWS::IAM::Role', logicalId: 'PushScanRole' });
  owned(world, 'app-deploy', { type: 'AWS::IAM::Role', logicalId: 'DeployRole' });
  return world;
}
function setRole(world, arn, mutate) {
  const key = `iam get-role --role-name ${arn.split('/').pop()}`;
  const doc = JSON.parse(world[key].stdout);
  mutate(doc.Role);
  world[key] = ok(doc);
  return world;
}
function setRepository(world, mutate) {
  const key = `ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`;
  const doc = JSON.parse(world[key].stdout);
  mutate(doc.repositories[0]);
  world[key] = ok(doc);
  return world;
}
const setScanning = (world, scanningConfiguration) => {
  world['ecr get-registry-scanning-configuration'] = ok({ registryId: ACCOUNT, scanningConfiguration });
  return world;
};
const setPing = (world, info) => {
  world[`ssm describe-instance-information --filters ${SSM_FILTER}`] = ok({ InstanceInformationList: info });
  return world;
};
const kinds = (c) => c.findings.map((f) => f.kind);

function consumer(t, overrides = { delivery: { environment: 'production' } }, profile = ECR) {
  const root = makeRepo(t, { 'src/app.py': 'x = 1\n', Dockerfile: 'FROM scratch\n' });
  write(root, '.ssd/onboarding.yml', serializeConfig(config(profile, overrides)));
  commitAll(root, 'config');
  return root;
}
async function cli(root, args, { world = verifiedWorld(), io = {} } = {}) {
  const c = capture();
  const f = fakeAws(world);
  const code = await main([...args, '--repo', root], { framework: FRAMEWORK, awsExec: f.exec, env: {}, ...c.io, ...io });
  return { code, out: c.text(), err: c.errors(), f };
}

// --- identity -----------------------------------------------------------------------

describe('aws verify: identity, account and region', () => {
  it('1. correct account, region and caller pass; every check is evidenced', async () => {
    const { report, check } = await verify(verifiedWorld());
    for (const id of ['identity.account', 'identity.principal', 'identity.region']) {
      assert.equal(check(id).status, 'PASS', id);
    }
    assert.equal(report.awsCalls[0], 'sts get-caller-identity', 'identity is re-read first');
    assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS', 'only the advisory subject format is not verified');
    assert.deepEqual(report.checks.filter((c) => c.status !== 'PASS').map((c) => c.id), ['oidc.subject-format']);
    assert.equal(exitCodeOf(report), 0);
    assert.equal(report.target.caller.arn, `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`);
  });

  it('2. a wrong account fails before any resource is read', async () => {
    const world = verifiedWorld();
    world['sts get-caller-identity'] = ok({ Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'AROAX:y' });
    const { report, check } = await verify(world);
    assert.equal(check('identity.account').status, 'FAIL');
    assert.deepEqual(report.awsCalls, ['sts get-caller-identity']);
    assert.equal(report.outcome, 'FAILED');
    assert.equal(exitCodeOf(report), 1);
  });

  it('3. a --region that is not delivery.aws.region fails and contacts nothing', async () => {
    const { report, f, check } = await verify(verifiedWorld(), { region: 'eu-west-1' });
    assert.equal(check('identity.region').status, 'FAIL');
    assert.deepEqual(f.calls, []);
    assert.equal(report.outcome, 'FAILED');
  });

  it('4. the account root user fails before any resource is read', async () => {
    const world = verifiedWorld();
    world['sts get-caller-identity'] = ok({ Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root`, UserId: ACCOUNT });
    const { report, check } = await verify(world);
    assert.equal(check('identity.principal').status, 'FAIL');
    assert.deepEqual(report.awsCalls, ['sts get-caller-identity']);
    assert.equal(report.outcome, 'FAILED');
  });

  it('every call carries the resolved region, never the CLI default', async () => {
    const { f } = await verify(verifiedWorld());
    assert.ok(f.calls.length > 20);
    for (const call of f.calls) {
      assert.equal(call.argv[call.argv.indexOf('--region') + 1], REGION);
    }
  });
});

// --- ownership ----------------------------------------------------------------------

describe('aws verify: ownership', () => {
  it('5. a managed resource of the expected stack, tagged and under its logical id, passes as managed', async () => {
    const { report, check } = await verify(managedWorld(), { config: managedCfg() });
    for (const id of ['ownership.ecr-repository', 'ownership.push-role', 'ownership.deploy-role']) {
      assert.equal(check(id).status, 'PASS', id);
      assert.equal(check(id).ownership, 'managed', id);
    }
    assert.equal(check('ecr.managed-settings').status, 'PASS');
    assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS');
  });

  it('6. the same names without ownership tags are not managed, and managed mode fails', async () => {
    const world = managedWorld();
    for (const [id, type, logicalId] of [[REPOSITORY, 'AWS::ECR::Repository', 'EcrRepository'], ['app-ecr-push-scan', 'AWS::IAM::Role', 'PushScanRole'], ['app-deploy', 'AWS::IAM::Role', 'DeployRole']]) {
      owned(world, id, { type, logicalId, tags: [] });
    }
    const { report, check } = await verify(world, { config: managedCfg() });
    for (const id of ['ownership.ecr-repository', 'ownership.push-role', 'ownership.deploy-role']) {
      assert.equal(check(id).ownership, 'exists-not-owned', id);
      assert.equal(check(id).status, 'FAIL', id);
      assert.ok(kinds(check(id)).includes('present-unowned'), id);
    }
    assert.equal(report.outcome, 'FAILED');
  });

  it('a name-only resource (no stack at all) is exists-not-owned: FAIL when managed, accepted in place when existing', async () => {
    const managed = await verify(verifiedWorld(), { config: managedCfg() });
    assert.equal(managed.check('ownership.ecr-repository').status, 'FAIL');
    const existing = await verify(verifiedWorld());
    assert.equal(existing.check('ownership.ecr-repository').ownership, 'exists-not-owned');
    assert.equal(existing.check('ownership.ecr-repository').status, 'PASS', 'existing mode validates in place; it never claims management');
  });

  it('a managed resource of the expected stack under another logical id fails', async () => {
    const world = owned(managedWorld(), 'app-deploy', { type: 'AWS::IAM::Role', logicalId: 'PushScanRole' });
    const { check } = await verify(world, { config: managedCfg() });
    assert.equal(check('ownership.deploy-role').status, 'FAIL');
    assert.ok(kinds(check('ownership.deploy-role')).includes('logical-id-mismatch'));
  });

  it('a stack for another consumer is not the owner', async () => {
    const tags = SSD_STACK_TAGS.map((t) => (t.Key === 'ssd:consumer-repository' ? { ...t, Value: 'acme/other' } : t));
    const world = owned(managedWorld(), REPOSITORY, { type: 'AWS::ECR::Repository', logicalId: 'EcrRepository', tags });
    const { check } = await verify(world, { config: managedCfg() });
    assert.equal(check('ownership.ecr-repository').status, 'FAIL');
  });
});

// --- push/scan role -------------------------------------------------------------------

describe('aws verify: push/scan role', () => {
  it('7. exact trust passes; trust, required and negative access are separate checks', async () => {
    const { check } = await verify(verifiedWorld());
    for (const id of ['iam.push-role', 'iam.push-trust', 'iam.push-required-access', 'iam.push-negative-access']) {
      assert.equal(check(id).status, 'PASS', id);
      assert.equal(check(id).section, 'Push/scan role');
    }
    assert.equal(check('iam.push-required-access').basis, 'simulation');
  });

  for (const [n, name, subject] of [
    ['8', 'a wildcard repository', 'repo:acme/*:ref:refs/heads/main'],
    ['8', 'any repository', 'repo:*'],
    ['9', 'a wildcard branch', `repo:${SLUG}:ref:refs/heads/*`],
    ['9', 'a wildcard context', `repo:${SLUG}:*`]
  ]) {
    it(`${n}. trust with ${name} (${subject}) fails`, async () => {
      const world = setRole(verifiedWorld(), PUSH_ROLE, (r) => {
        r.AssumeRolePolicyDocument = trustPolicy({ subjects: [subject], operator: 'StringLike' });
      });
      const { report, check } = await verify(world);
      assert.equal(check('iam.push-trust').status, 'FAIL');
      assert.ok(kinds(check('iam.push-trust')).some((k) => ['any-repository', 'organization-wide', 'wildcard-subject'].includes(k)), 'rejected AS a wildcard');
      assert.equal(report.outcome, 'FAILED');
    });
  }

  it('trust for another repository, another branch, a pull_request, another provider or audience fails', async () => {
    for (const trust of [
      trustPolicy({ subjects: ['repo:acme/other:ref:refs/heads/main'] }),
      trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/dev`] }),
      trustPolicy({ subjects: [`repo:${SLUG}:pull_request`] }),
      trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], provider: `arn:aws:iam::${ACCOUNT}:oidc-provider/evil.example.com` }),
      trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], audience: ['sts.amazonaws.com', 'other'] })
    ]) {
      const { check } = await verify(setRole(verifiedWorld(), PUSH_ROLE, (r) => (r.AssumeRolePolicyDocument = trust)));
      assert.equal(check('iam.push-trust').status, 'FAIL', JSON.stringify(trust));
    }
  });

  it('10. every required push action is simulated and must be ALLOWED', async () => {
    const { check, f } = await verify(verifiedWorld());
    const c = check('iam.push-required-access');
    for (const action of ['ecr:GetAuthorizationToken', 'ecr:BatchCheckLayerAvailability', 'ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload', 'ecr:PutImage', 'ecr:DescribeImageScanFindings']) {
      assert.ok(c.observed.some((line) => line.startsWith(`${action} on`) && line.includes(': allowed')), action);
    }
    assert.ok(f.keys().some((k) => k.startsWith(`iam simulate-principal-policy --policy-source-arn ${PUSH_ROLE}`)));
  });

  it('a required push action that is denied fails', async () => {
    const { check, report } = await verify(revoke(verifiedWorld(), PUSH_ROLE, `ecr:PutImage ${REPO_ARN}`));
    assert.equal(check('iam.push-required-access').status, 'FAIL');
    assert.ok(kinds(check('iam.push-required-access')).includes('required-access-denied'));
    assert.equal(report.outcome, 'FAILED');
  });

  for (const [name, pair] of [
    ['deploy to the instance', `ssm:SendCommand ${INSTANCE_ARN}`],
    ['push to an unrelated repository', `ecr:PutImage arn:aws:ecr:${REGION}:${ACCOUNT}:repository/ssd-onboard-probe/not-${REPOSITORY}`],
    ['assume an unrelated role', `sts:AssumeRole arn:aws:iam::${ACCOUNT}:role/ssd-onboard-probe/unrelated`],
    ['read an arbitrary secret', `secretsmanager:GetSecretValue arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:ssd-onboard-probe/unrelated-AbCdEf`],
    ['rewrite its own policy', `iam:PutRolePolicy ${PUSH_ROLE}`],
    ['pass roles', 'iam:PassRole *'],
    ['change registry scanning', 'ecr:PutRegistryScanningConfiguration *']
  ]) {
    it(`11. the push role able to ${name} fails (forbidden action unexpectedly ALLOWED)`, async () => {
      const { check, report } = await verify(grant(verifiedWorld(), PUSH_ROLE, pair));
      const c = check('iam.push-negative-access');
      assert.equal(c.status, 'FAIL');
      assert.ok(kinds(c).includes('forbidden-access-allowed'));
      assert.ok(c.remediation.length > 0);
      assert.equal(report.outcome, 'FAILED');
    });
  }

  it('an unconditional administrator grant in the policy text fails even if no probe matched it', async () => {
    const world = verifiedWorld();
    world['iam list-role-policies --role-name app-ecr-push-scan'] = ok({ PolicyNames: ['push', 'admin'] });
    world['iam get-role-policy --role-name app-ecr-push-scan --policy-name admin'] = ok({ PolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } });
    const { check } = await verify(world);
    assert.equal(check('iam.push-negative-access').status, 'FAIL');
    assert.ok(kinds(check('iam.push-negative-access')).includes('administrator'));
  });
});

// --- deploy role ----------------------------------------------------------------------

describe('aws verify: deploy role', () => {
  it('12. exact deploy trust (environment context) passes', async () => {
    const { check } = await verify(verifiedWorld());
    assert.equal(check('iam.deploy-trust').status, 'PASS');
    assert.ok(check('iam.deploy-trust').observed.includes('sub repo:acme/app:environment:production'));
    assert.equal(check('iam.deploy-required-access').status, 'PASS');
  });

  it('deploy trust for another environment fails', async () => {
    const world = setRole(verifiedWorld(), DEPLOY_ROLE, (r) => (r.AssumeRolePolicyDocument = trustPolicy({ subjects: [`repo:${SLUG}:environment:staging`] })));
    const { check } = await verify(world);
    assert.equal(check('iam.deploy-trust').status, 'FAIL');
  });

  it('13. a deploy role that can target another SSM instance fails', async () => {
    const { check, report } = await verify(grant(verifiedWorld(), DEPLOY_ROLE, `ssm:SendCommand ${OTHER_INSTANCE_ARN}`));
    assert.equal(check('iam.deploy-negative-access').status, 'FAIL');
    assert.ok(check('iam.deploy-negative-access').findings.some((f) => f.message.includes(OTHER_INSTANCE_ARN)));
    assert.equal(report.outcome, 'FAILED');
  });

  it('a deploy role that can push images fails, in negative access AND separation of duties', async () => {
    const { check } = await verify(grant(verifiedWorld(), DEPLOY_ROLE, `ecr:PutImage ${REPO_ARN}`));
    assert.equal(check('iam.deploy-negative-access').status, 'FAIL');
    assert.equal(check('separation.roles').status, 'FAIL');
    assert.ok(kinds(check('separation.roles')).includes('duties-not-separated'));
  });

  it('a deploy role unable to send to the instance or the document fails required access', async () => {
    for (const pair of [`ssm:SendCommand ${INSTANCE_ARN}`, 'ssm:SendCommand arn:aws:ssm:us-east-1::document/AWS-RunShellScript', 'ssm:GetCommandInvocation *']) {
      const { check } = await verify(revoke(verifiedWorld(), DEPLOY_ROLE, pair));
      assert.equal(check('iam.deploy-required-access').status, 'FAIL', pair);
    }
  });

  it('a push role that can deploy fails separation of duties', async () => {
    const { check } = await verify(grant(verifiedWorld(), PUSH_ROLE, `ssm:SendCommand ${INSTANCE_ARN}`));
    assert.equal(check('separation.roles').status, 'FAIL');
  });
});

// --- separation -------------------------------------------------------------------------

describe('aws verify: separation of duties', () => {
  const simulation = { state: 'present', value: [] };
  const target = { partition: 'aws', account: ACCOUNT, region: REGION, repository: REPOSITORY, instanceId: INSTANCE };
  const live = (arn, roleId) => ({ state: 'present', value: { arn, roleId } });

  it('14. one role configured for both duties fails', () => {
    const config = { delivery: { roles: { pushScanRoleArn: PUSH_ROLE, deployRoleArn: PUSH_ROLE.toUpperCase().replace('ARN:AWS:IAM::', 'arn:aws:iam::') } } };
    const c = separationCheck({ config, target, roles: [{ key: 'push', label: 'Push/scan', arn: PUSH_ROLE, role: live(PUSH_ROLE, 'A'), simulation }, { key: 'deploy', label: 'Deploy', arn: PUSH_ROLE, role: live(PUSH_ROLE, 'A'), simulation }] });
    assert.equal(c.status, 'FAIL');
    assert.ok(kinds(c).filter((k) => k === 'same-role').length >= 2);
  });

  it('14. two configured ARNs that resolve to one live identity (same RoleId) fail', async () => {
    const world = setRole(verifiedWorld(), DEPLOY_ROLE, (r) => (r.RoleId = 'AROAPUSHPUSHPUSHPUSH1'));
    const { check, report } = await verify(world);
    assert.equal(check('separation.roles').status, 'FAIL');
    assert.equal(report.outcome, 'FAILED');
  });

  it('14. the CLI refuses a configuration with one ARN for both roles before AWS', async (t) => {
    const root = consumer(t);
    const text = readFileSync(join(root, '.ssd/onboarding.yml'), 'utf8').replace(DEPLOY_ROLE, PUSH_ROLE);
    write(root, '.ssd/onboarding.yml', text);
    const { code, f } = await cli(root, ['aws', 'verify']);
    assert.equal(code, 1);
    assert.deepEqual(f.calls, []);
  });

  it('a missing RoleId is NOT VERIFIED, never PASS', async () => {
    const { check } = await verify(setRole(verifiedWorld(), PUSH_ROLE, (r) => delete r.RoleId));
    assert.equal(check('separation.roles').status, 'NOT VERIFIED');
  });
});

// --- ECR --------------------------------------------------------------------------------

describe('aws verify: ECR repository, registry scanning and Inspector', () => {
  it('15. a managed repository that is IMMUTABLE passes', async () => {
    const { check } = await verify(managedWorld(), { config: managedCfg() });
    assert.equal(check('ecr.repository').status, 'PASS');
    assert.equal(check('ecr.tag-immutability').status, 'PASS');
    assert.equal(check('ecr.tag-immutability').required, true);
  });

  it('16. a managed repository that is MUTABLE fails (drift from its stack)', async () => {
    const world = setRepository(managedWorld(), (r) => (r.imageTagMutability = 'MUTABLE'));
    const { check, report } = await verify(world, { config: managedCfg() });
    assert.equal(check('ecr.tag-immutability').status, 'FAIL');
    assert.equal(report.outcome, 'FAILED');
  });

  it('an existing MUTABLE repository stays the advisory WARN of the Phase 2 contract', async () => {
    const { check, report } = await verify(setRepository(verifiedWorld(), (r) => (r.imageTagMutability = 'MUTABLE')));
    assert.equal(check('ecr.tag-immutability').status, 'WARN');
    assert.equal(check('ecr.tag-immutability').required, false);
    assert.equal(exitCodeOf(report), 0);
  });

  it('managed settings drift (scanOnPush off, KMS instead of AES256) fails', async () => {
    const world = setRepository(managedWorld(), (r) => {
      r.imageScanningConfiguration.scanOnPush = false;
      r.encryptionConfiguration.encryptionType = 'KMS';
    });
    const { check } = await verify(world, { config: managedCfg() });
    assert.equal(check('ecr.managed-settings').status, 'FAIL');
  });

  it('a repository ARN in another region or account fails', async () => {
    const world = setRepository(verifiedWorld(), (r) => (r.repositoryArn = `arn:aws:ecr:eu-west-1:${ACCOUNT}:repository/${REPOSITORY}`));
    world[`ecr list-tags-for-resource --resource-arn arn:aws:ecr:eu-west-1:${ACCOUNT}:repository/${REPOSITORY}`] = ok({ tags: [] });
    const { check } = await verify(world);
    assert.equal(check('ecr.repository').status, 'FAIL');
    assert.ok(kinds(check('ecr.repository')).includes('repository-location'));
  });

  it('a missing repository fails', async () => {
    const world = verifiedWorld();
    world[`ecr describe-repositories --registry-id ${ACCOUNT} --repository-names ${REPOSITORY}`] = awsError('RepositoryNotFoundException', 'DescribeRepositories');
    const { check, report } = await verify(world);
    assert.equal(check('ecr.repository').status, 'FAIL');
    assert.equal(report.outcome, 'FAILED');
  });

  it('17. a registry rule for exactly this repository covers it', async () => {
    const { check } = await verify(verifiedWorld());
    assert.equal(check('ecr.scanning').status, 'PASS');
    assert.equal(check('ecr.scanning').coverage.filter, REPOSITORY);
  });

  it('18. a scanning configuration that exists but does not cover the repository fails', async () => {
    const world = setScanning(verifiedWorld(), { scanType: 'BASIC', rules: [{ scanFrequency: 'SCAN_ON_PUSH', repositoryFilters: [{ filter: 'other', filterType: 'WILDCARD' }] }] });
    const { check, report } = await verify(world);
    assert.equal(check('ecr.scanning').status, 'FAIL');
    assert.ok(kinds(check('ecr.scanning')).includes('not-covered'));
    assert.equal(report.outcome, 'FAILED');
  });

  it('19. wildcard filters are evaluated against the repository name', async () => {
    for (const [filter, status] of [['ap*', 'PASS'], ['*', 'PASS'], ['*p', 'PASS'], ['a*p', 'PASS'], ['app-*', 'FAIL'], ['other*', 'FAIL'], ['ap', 'FAIL']]) {
      const world = setScanning(verifiedWorld(), { scanType: 'BASIC', rules: [{ scanFrequency: 'SCAN_ON_PUSH', repositoryFilters: [{ filter, filterType: 'WILDCARD' }] }] });
      const { check } = await verify(world);
      assert.equal(check('ecr.scanning').status, status, filter);
    }
  });

  it('a MANUAL-only rule, or a CONTINUOUS_SCAN rule under BASIC, is not automatic coverage', async () => {
    for (const rule of [{ scanFrequency: 'MANUAL', repositoryFilters: [{ filter: REPOSITORY, filterType: 'WILDCARD' }] }]) {
      const { check } = await verify(setScanning(verifiedWorld(), { scanType: 'BASIC', rules: [rule] }));
      assert.equal(check('ecr.scanning').status, 'FAIL');
    }
    const { check } = await verify(setScanning(verifiedWorld(), { scanType: 'BASIC', rules: [{ scanFrequency: 'CONTINUOUS_SCAN', repositoryFilters: [{ filter: REPOSITORY, filterType: 'WILDCARD' }] }] }));
    assert.notEqual(check('ecr.scanning').status, 'PASS');
  });

  it('a scanning configuration of another registry fails', async () => {
    const world = verifiedWorld();
    world['ecr get-registry-scanning-configuration'] = ok({ registryId: '999999999999', scanningConfiguration: { scanType: 'BASIC', rules: [{ scanFrequency: 'SCAN_ON_PUSH', repositoryFilters: [{ filter: '*', filterType: 'WILDCARD' }] }] } });
    const { check } = await verify(world);
    assert.equal(check('ecr.scanning').status, 'FAIL');
  });

  it('ENHANCED with Inspector enabled, ACTIVE coverage and evidence access passes, as three separate facts', async () => {
    const { check, report } = await verify(verifiedWorld({ enhanced: true }));
    for (const id of ['ecr.scanning', 'ecr.inspector-account', 'ecr.inspector-coverage', 'ecr.inspector-evidence']) {
      assert.equal(check(id).status, 'PASS', id);
    }
    assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS');
  });

  it('20. ENHANCED scanning with Inspector ECR scanning disabled fails', async () => {
    const world = verifiedWorld({ enhanced: true });
    world[`inspector2 batch-get-account-status --account-ids ${ACCOUNT}`] = ok({ accounts: [{ accountId: ACCOUNT, state: { status: 'ENABLED' }, resourceState: { ecr: { status: 'DISABLED' } } }] });
    const { check, report } = await verify(world);
    assert.equal(check('ecr.inspector-account').status, 'FAIL');
    assert.equal(report.outcome, 'FAILED');
  });

  it('Inspector enabled but no coverage record for the repository is NOT VERIFIED (exit 1), never PASS', async () => {
    const world = verifiedWorld({ enhanced: true });
    world[`inspector2 list-coverage --filter-criteria ${inspectorFilter()}`] = ok({ coveredResources: [] });
    const { check, report } = await verify(world);
    assert.equal(check('ecr.inspector-account').status, 'PASS');
    assert.equal(check('ecr.inspector-coverage').status, 'NOT VERIFIED');
    assert.equal(report.outcome, 'NOT_VERIFIED');
    assert.equal(exitCodeOf(report), 1);
  });

  it('an inactive Inspector coverage record fails', async () => {
    const world = verifiedWorld({ enhanced: true });
    world[`inspector2 list-coverage --filter-criteria ${inspectorFilter()}`] = ok({ coveredResources: [{ resourceId: REPO_ARN, scanStatus: { statusCode: 'INACTIVE', reason: 'EXCLUDED_BY_RULE' } }] });
    const { check } = await verify(world);
    assert.equal(check('ecr.inspector-coverage').status, 'FAIL');
  });

  it('a push role that cannot read Inspector evidence fails, when ENHANCED requires it', async () => {
    const table = grants({ enhanced: true });
    table[PUSH_ROLE].delete('inspector2:ListFindings *');
    const world = verifiedWorld({ enhanced: true, table });
    const { check } = await verify(world);
    assert.equal(check('ecr.inspector-evidence').status, 'FAIL');
    assert.equal(check('iam.push-required-access').status, 'FAIL');
  });

  it('BASIC scanning reads no Inspector state', async () => {
    const { report, f } = await verify(verifiedWorld());
    assert.ok(!f.operations().some((op) => op.startsWith('inspector2')));
    assert.ok(!report.checks.some((c) => c.id.startsWith('ecr.inspector')));
  });
});

// --- SSM --------------------------------------------------------------------------------

describe('aws verify: SSM deployment target', () => {
  it('21. an Online managed instance with pull access passes', async () => {
    const { check } = await verify(verifiedWorld());
    for (const id of ['ssm.instance', 'ssm.managed', 'ssm.instance-pull']) {
      assert.equal(check(id).status, 'PASS', id);
    }
    assert.equal(check('ssm.instance-pull').basis, 'simulation');
  });

  it('22. an instance whose agent is not Online fails', async () => {
    for (const ping of ['ConnectionLost', 'Inactive']) {
      const { check, report } = await verify(setPing(verifiedWorld(), [{ InstanceId: INSTANCE, PingStatus: ping }]));
      assert.equal(check('ssm.managed').status, 'FAIL', ping);
      assert.equal(report.outcome, 'FAILED');
    }
  });

  it('23. an instance SSM does not list, or EC2 does not know, fails', async () => {
    const unmanaged = await verify(setPing(verifiedWorld(), [{ InstanceId: 'i-0aaaaaaaaaaaaaaaa', PingStatus: 'Online' }]));
    assert.equal(unmanaged.check('ssm.managed').status, 'FAIL', 'another instance being Online proves nothing');
    const world = verifiedWorld();
    world[`ec2 describe-instances --instance-ids ${INSTANCE}`] = awsError('InvalidInstanceID.NotFound', 'DescribeInstances');
    const missing = await verify(world);
    assert.equal(missing.check('ssm.instance').status, 'FAIL');
    assert.equal(missing.report.outcome, 'FAILED');
  });

  it('24. an instance role without ECR pull fails, and only a recommendation is printed', async () => {
    const { check, report, f } = await verify(revoke(verifiedWorld(), INSTANCE_ROLE, `ecr:BatchGetImage ${REPO_ARN}`));
    const c = check('ssm.instance-pull');
    assert.equal(c.status, 'FAIL');
    assert.ok(kinds(c).includes('required-access-denied'));
    assert.match(c.remediation.join('\n'), /RECOMMENDATION/);
    assert.match(c.remediation.join('\n'), /ecr:BatchGetImage/);
    assert.equal(report.outcome, 'FAILED');
    assert.ok(!f.operations().some((op) => /^\S+ (?:attach|put|create|update)-/.test(op)), 'nothing is attached');
  });

  it('an instance without an instance profile fails', async () => {
    const world = verifiedWorld();
    world[`ec2 describe-instances --instance-ids ${INSTANCE}`] = ok({ Reservations: [{ OwnerId: ACCOUNT, Instances: [{ InstanceId: INSTANCE, State: { Name: 'running' } }] }] });
    const { check } = await verify(world);
    assert.equal(check('ssm.instance-pull').status, 'FAIL');
  });
});

// --- fail closed --------------------------------------------------------------------------

describe('aws verify: uncertainty is never PASS', () => {
  it('25. malformed simulation output is NOT VERIFIED and fails the command', async () => {
    const world = verifiedWorld();
    world[`iam simulate-principal-policy --policy-source-arn ${PUSH_ROLE} *`] = { stdout: 'not json', stderr: '', exitCode: 0 };
    const { check, report } = await verify(world);
    assert.equal(check('iam.push-required-access').status, 'NOT VERIFIED');
    assert.equal(check('iam.push-negative-access').status, 'NOT VERIFIED');
    assert.equal(report.outcome, 'NOT_VERIFIED');
    assert.equal(exitCodeOf(report), 1);
  });

  it('25. malformed caller identity ends the run as ERROR (exit 1)', async (t) => {
    const world = verifiedWorld();
    world['sts get-caller-identity'] = ok({ Account: ACCOUNT });
    const { code, out } = await cli(consumer(t), ['aws', 'verify', '--json'], { world });
    assert.equal(code, 1);
    assert.equal(JSON.parse(out).outcome, 'ERROR');
  });

  for (const [name, mutate] of [
    ['no EvalDecision', (r) => delete r.EvalDecision],
    ['an unknown decision', (r) => (r.EvalDecision = 'probablyAllowed')],
    ['another resource', (r) => (r.EvalResourceName = 'arn:aws:ecr:us-east-1:012345678901:repository/other')]
  ]) {
    it(`26. a simulation answer with ${name} is NOT VERIFIED`, async () => {
      const world = verifiedWorld();
      const base = simulator(grants());
      world[`iam simulate-principal-policy --policy-source-arn ${DEPLOY_ROLE} *`] = (argv) => {
        const doc = JSON.parse(base(argv).stdout);
        doc.EvaluationResults.forEach(mutate);
        return ok(doc);
      };
      const { check, report } = await verify(world);
      assert.equal(check('iam.deploy-required-access').status, 'NOT VERIFIED');
      assert.equal(check('iam.deploy-negative-access').status, 'NOT VERIFIED');
      assert.equal(report.outcome, 'NOT_VERIFIED');
    });
  }

  it('26. a missing or duplicated probe answer, or a truncated page, is NOT VERIFIED', async () => {
    const base = simulator(grants());
    for (const transform of [(doc) => doc.EvaluationResults.pop(), (doc) => doc.EvaluationResults.push(doc.EvaluationResults[0]), (doc) => (doc.IsTruncated = true), (doc) => delete doc.EvaluationResults]) {
      const world = verifiedWorld();
      world[`iam simulate-principal-policy --policy-source-arn ${PUSH_ROLE} *`] = (argv) => {
        const doc = JSON.parse(base(argv).stdout);
        transform(doc);
        return ok(doc);
      };
      const { report } = await verify(world);
      assert.equal(report.outcome, 'NOT_VERIFIED', transform.toString());
    }
  });

  it('26. missing AWS fields: PingStatus fails, registryId and imageTagMutability are NOT VERIFIED', async () => {
    const ping = await verify(setPing(verifiedWorld(), [{ InstanceId: INSTANCE }]));
    assert.equal(ping.check('ssm.managed').status, 'FAIL');
    const registry = await verify(setRepository(verifiedWorld(), (r) => delete r.registryId));
    assert.equal(registry.check('ecr.repository').status, 'NOT VERIFIED');
    assert.equal(registry.report.outcome, 'NOT_VERIFIED');
    const tag = await verify(setRepository(managedWorld(), (r) => delete r.imageTagMutability), { config: managedCfg() });
    assert.equal(tag.check('ecr.tag-immutability').status, 'NOT VERIFIED');
    const trust = await verify(setRole(verifiedWorld(), PUSH_ROLE, (r) => delete r.AssumeRolePolicyDocument));
    assert.equal(trust.check('iam.push-trust').status, 'FAIL');
  });

  it('simulation denied to the operator is NOT VERIFIED (exit 1), with remediation', async () => {
    const { check, report } = await verify(simulationDenied(verifiedWorld(), DEPLOY_ROLE));
    assert.equal(check('iam.deploy-required-access').status, 'NOT VERIFIED');
    assert.equal(check('iam.deploy-negative-access').status, 'NOT VERIFIED');
    assert.equal(check('separation.roles').status, 'NOT VERIFIED');
    assert.match(check('iam.deploy-required-access').remediation.join(' '), /iam:SimulatePrincipalPolicy/);
    assert.equal(report.outcome, 'NOT_VERIFIED');
  });

  it('a denial that depends on missing context values is not proof of denial (or of access)', () => {
    const probe = { action: 'ssm:SendCommand', resource: OTHER_INSTANCE_ARN, severity: 'FAIL', why: 'x' };
    const sim = { state: 'present', value: [{ action: 'ssm:SendCommand', resource: OTHER_INSTANCE_ARN, decision: 'implicitDeny', missingContext: ['aws:SourceIp'] }] };
    assert.equal(deniedAccessCheck({ id: 'x', section: 's', title: 't', why: '', simulation: sim, probes: [probe] }).status, 'NOT VERIFIED');
    assert.equal(requiredAccessCheck({ id: 'x', section: 's', title: 't', why: '', simulation: sim, probes: [probe] }).status, 'NOT VERIFIED');
    const explicit = { state: 'present', value: [{ ...sim.value[0], decision: 'explicitDeny' }] };
    assert.equal(deniedAccessCheck({ id: 'x', section: 's', title: 't', why: '', simulation: explicit, probes: [probe] }).status, 'PASS');
    assert.equal(requiredAccessCheck({ id: 'x', section: 's', title: 't', why: '', simulation: explicit, probes: [probe] }).status, 'NOT VERIFIED');
  });

  it('ALLOW and DENY are read the right way round', () => {
    const probe = { action: 'a:B', resource: '*', severity: 'FAIL', why: 'x' };
    const at = (decision) => ({ state: 'present', value: [{ action: 'a:B', resource: '*', decision, missingContext: [] }] });
    const args = { id: 'x', section: 's', title: 't', why: '', probes: [probe] };
    assert.equal(requiredAccessCheck({ ...args, simulation: at('allowed') }).status, 'PASS');
    assert.equal(requiredAccessCheck({ ...args, simulation: at('implicitDeny') }).status, 'FAIL');
    assert.equal(requiredAccessCheck({ ...args, simulation: at('explicitDeny') }).status, 'FAIL');
    assert.equal(deniedAccessCheck({ ...args, simulation: at('allowed') }).status, 'FAIL');
    assert.equal(deniedAccessCheck({ ...args, simulation: at('implicitDeny') }).status, 'PASS');
    assert.equal(deniedAccessCheck({ ...args, simulation: at('explicitDeny') }).status, 'PASS');
    assert.equal(requiredAccessCheck({ ...args, simulation: { state: 'present', value: [] } }).status, 'NOT VERIFIED');
    assert.equal(deniedAccessCheck({ ...args, simulation: { state: 'present', value: [] } }).status, 'NOT VERIFIED');
    assert.equal(deniedAccessCheck({ ...args, simulation: null }).status, 'NOT VERIFIED');
  });

  it('the outcome contract: FAIL > required NOT VERIFIED > warnings > PASS', () => {
    const c = (status, required = true) => ({ status, required });
    assert.equal(outcomeOf([c('PASS'), c('NOT VERIFIED'), c('FAIL')]), 'FAILED');
    assert.equal(outcomeOf([c('PASS'), c('NOT VERIFIED')]), 'NOT_VERIFIED');
    assert.equal(outcomeOf([c('PASS'), c('NOT VERIFIED', false), c('WARN')]), 'VERIFIED_WITH_WARNINGS');
    assert.equal(outcomeOf([c('PASS')]), 'VERIFIED');
  });

  it('mixed state: every other check passes, one critical IAM negative check fails -> exit 1', async (t) => {
    const world = grant(verifiedWorld(), DEPLOY_ROLE, `iam:AttachRolePolicy ${DEPLOY_ROLE}`);
    const { report } = await verify(world);
    const failing = report.checks.filter((c) => c.status === 'FAIL').map((c) => c.id);
    assert.deepEqual(failing, ['iam.deploy-negative-access']);
    assert.ok(report.checks.filter((c) => c.status === 'PASS').length >= 10);
    const { code, out } = await cli(consumer(t), ['aws', 'verify'], { world: grant(verifiedWorld(), DEPLOY_ROLE, `iam:AttachRolePolicy ${DEPLOY_ROLE}`) });
    assert.equal(code, 1);
    assert.match(out, /FAILED/);
  });
});

// --- read-only boundary ---------------------------------------------------------------

describe('aws verify: read-only by construction', () => {
  const read = (path) => readFileSync(join(ROOT, path), 'utf8');

  it('27. verify uses the read-only wrapper: every forbidden verb is refused before anything runs', async () => {
    assert.equal(verifyAws.name, 'readOnlyAws');
    const executed = [];
    const aws = verifyAws({ region: REGION, exec: async (argv) => (executed.push(argv), ok({})) });
    for (const argv of [
      ['iam', 'create-role', '--role-name', 'x'],
      ['iam', 'update-assume-role-policy', '--role-name', 'x'],
      ['iam', 'delete-role', '--role-name', 'x'],
      ['iam', 'attach-role-policy', '--role-name', 'x'],
      ['iam', 'detach-role-policy', '--role-name', 'x'],
      ['iam', 'put-role-policy', '--role-name', 'x'],
      ['ecr', 'set-repository-policy', '--repository-name', 'x'],
      ['ecr', 'put-image-tag-mutability', '--repository-name', 'x'],
      ['ecr', 'put-registry-scanning-configuration'],
      ['ecr', 'tag-resource', '--resource-arn', 'x'],
      ['ecr', 'untag-resource', '--resource-arn', 'x'],
      ['inspector2', 'enable', '--resource-types', 'ECR'],
      ['ssm', 'send-command', '--instance-ids', INSTANCE],
      ['ssm', 'register-target-with-maintenance-window'],
      ['ssm', 'deregister-managed-instance', '--instance-id', INSTANCE],
      ['ec2', 'modify-instance-attribute', '--instance-id', INSTANCE],
      ['ec2', 'associate-iam-instance-profile', '--instance-id', INSTANCE],
      ['cloudformation', 'create-change-set', '--stack-name', EXPECTED_STACK],
      ['cloudformation', 'execute-change-set', '--change-set-name', 'x'],
      ['cloudformation', 'update-stack', '--stack-name', EXPECTED_STACK],
      ['sts', 'assume-role', '--role-arn', PUSH_ROLE]
    ]) {
      await assert.rejects(aws(argv), (error) => error.kind === 'refused', argv.join(' '));
    }
    assert.deepEqual(executed, []);
  });

  it('27. every call a full verify run makes passes the read-only allowlist and is a read verb', async () => {
    const { f } = await verify(verifiedWorld({ enhanced: true }), { config: managedCfg() });
    for (const call of f.calls) {
      const argv = call.argv.slice(0, call.argv.indexOf('--region'));
      assert.doesNotThrow(() => assertReadOnly(argv), argv.join(' '));
      assert.match(argv[1], /^(?:get|list|describe|simulate|batch-get)-/, argv.join(' '));
    }
    for (const [service, operations] of Object.entries(READ_ONLY_OPERATIONS)) {
      for (const operation of Object.keys(operations)) {
        assert.match(operation, /^(?:get|list|describe|simulate|batch-get)-/, `${service} ${operation}`);
      }
    }
  });

  it('27. a verify path that tried a mutating verb would fail the run, not degrade it', async () => {
    const f = fakeAws(verifiedWorld());
    await assert.rejects(f.exec(['iam', 'put-role-policy', '--role-name', 'x', '--region', REGION, '--output', 'json', '--no-cli-pager']), /non-allowlisted argv/);
  });

  it('verify cannot reach the planner, a writer, or a process of its own', () => {
    const importsOf = (path) => [...read(path).matchAll(/^\s*(?:import|export)\s[^;]*?from\s+'([^']+)';/gms)].map((m) => m[1]);
    const seen = new Set();
    const visit = (path) => {
      if (seen.has(path)) return;
      seen.add(path);
      importsOf(path).filter((s) => s.startsWith('.')).forEach((s) => visit(join(dirname(path), s)));
    };
    visit(join('onboarding', 'aws', 'verify.mjs'));
    visit(join('onboarding', 'aws', 'verify-report.mjs'));
    for (const path of seen) {
      assert.ok(!path.startsWith(join('onboarding', 'aws', 'plan')), `verify reaches ${path}`);
      assert.ok(!/apply|safe-path|files\.mjs|baseline|render/.test(path), `verify reaches ${path}`);
    }
    for (const path of [...seen].filter((p) => p !== join('onboarding', 'aws', 'aws-cli.mjs'))) {
      assert.ok(!importsOf(path).some((s) => s === 'node:child_process' || s.startsWith('node:fs')), `${path} runs a process or touches files`);
    }
  });

  it('verify writes nothing to the repository', async (t) => {
    const root = consumer(t);
    await cli(root, ['aws', 'verify']);
    await cli(root, ['aws', 'verify', '--json'], { world: grant(verifiedWorld(), PUSH_ROLE, `ssm:SendCommand ${INSTANCE_ARN}`) });
    assert.equal(execFileSync('git', ['-C', root, 'status', '--porcelain'], { encoding: 'utf8' }), '');
  });
});

// --- the strict simulation reader -----------------------------------------------------

describe('aws verify: simulateProbes', () => {
  it('one call per resource; each probe matched by action and resource', async () => {
    const f = fakeAws(verifiedWorld());
    const aws = verifyAws({ region: REGION, exec: f.exec });
    const probes = verificationProbes('deploy', { partition: 'aws', account: ACCOUNT, region: REGION, repository: REPOSITORY, instanceId: INSTANCE }, { enhanced: false, self: DEPLOY_ROLE });
    const result = await simulateProbes(aws, DEPLOY_ROLE, [...probes.required, ...probes.denied]);
    assert.equal(result.state, 'present');
    const resources = new Set([...probes.required, ...probes.denied].map((p) => p.resource));
    assert.equal(f.calls.length, resources.size);
    assert.equal(result.value.length, new Set([...probes.required, ...probes.denied].map((p) => `${p.action} ${p.resource}`)).size);
    assert.ok(result.value.find((r) => r.action === 'ssm:SendCommand' && r.resource === INSTANCE_ARN).decision === 'allowed');
  });

  it('the probe contract is built on the role contract (roleRequirements), not a second list', () => {
    const t = { partition: 'aws', account: ACCOUNT, region: REGION, repository: REPOSITORY, instanceId: INSTANCE };
    const push = verificationProbes('push', t, { enhanced: false, self: PUSH_ROLE });
    assert.ok(push.denied.some((p) => p.action === 'ssm:SendCommand' && p.resource === INSTANCE_ARN));
    assert.ok(push.denied.some((p) => p.action === 'iam:PutRolePolicy' && p.resource === PUSH_ROLE));
    assert.ok(!push.required.some((p) => p.action.startsWith('inspector2:')));
    assert.ok(verificationProbes('push', t, { enhanced: true, self: PUSH_ROLE }).required.some((p) => p.action === 'inspector2:ListFindings'));
    const deploy = verificationProbes('deploy', t, { enhanced: false, self: DEPLOY_ROLE });
    assert.ok(deploy.denied.some((p) => p.action === 'ecr:PutImage' && p.resource === REPO_ARN));
    assert.ok(deploy.denied.some((p) => p.action === 'ssm:SendCommand' && p.resource === OTHER_INSTANCE_ARN));
    const instance = verificationProbes('instance', t, { enhanced: false, self: null });
    assert.deepEqual(instance.required.map((p) => p.action).sort(), ['ecr:BatchGetImage', 'ecr:GetAuthorizationToken', 'ecr:GetDownloadUrlForLayer']);
  });
});

// --- CLI ------------------------------------------------------------------------------------

describe('aws verify: CLI', () => {
  it('human output: target, sections per concern, status words, result', async (t) => {
    const { code, out, err } = await cli(consumer(t), ['aws', 'verify']);
    assert.equal(code, 0);
    assert.equal(err, '');
    assert.ok(!out.includes(ESC));
    for (const expected of ['SSD AWS Verify', `Account      ${ACCOUNT}`, 'Region       us-east-1', 'Caller       arn:aws:sts::', 'AWS profile', 'Push/scan role', 'Deploy role', 'Separation of duties', 'Required access', 'Negative access', 'Registry scanning coverage', 'ECR pull access', 'Online', 'VERIFIED WITH WARNINGS']) {
      assert.ok(out.includes(expected), expected);
    }
  });

  it('a failure prints observed, expected, why it matters and remediation', async (t) => {
    const { code, out } = await cli(consumer(t), ['aws', 'verify'], { world: grant(verifiedWorld(), DEPLOY_ROLE, `ssm:SendCommand ${OTHER_INSTANCE_ARN}`) });
    assert.equal(code, 1);
    for (const expected of ['Observed', 'Problem', 'Expected', 'Why', 'Remediate', 'FAILED', OTHER_INSTANCE_ARN]) {
      assert.ok(out.includes(expected), expected);
    }
  });

  it('28. --json: one deterministic document, no ANSI or control characters, explicit status per check', async (t) => {
    const root = consumer(t);
    const first = await cli(root, ['aws', 'verify', '--json'], { io: { color: true, env: { AWS_PROFILE: 'ops' } } });
    const second = await cli(root, ['aws', 'verify', '--json'], { io: { color: true, env: { AWS_PROFILE: 'ops' } } });
    assert.equal(first.code, 0);
    assert.equal(first.out, second.out, 'deterministic');
    assert.doesNotMatch(first.out, CONTROL);
    const doc = JSON.parse(first.out);
    assert.deepEqual(Object.keys(doc).sort(), ['awsCalls', 'checks', 'command', 'counts', 'outcome', 'schemaVersion', 'skipped', 'target']);
    assert.equal(doc.schemaVersion, 1);
    assert.equal(doc.command, 'aws verify');
    assert.deepEqual(Object.keys(doc.target).sort(), ['account', 'awsProfile', 'caller', 'region', 'regionSource', 'repository']);
    assert.equal(doc.target.awsProfile, 'ops');
    assert.equal(doc.target.repository, SLUG);
    assert.equal(doc.target.caller.arn, `arn:aws:sts::${ACCOUNT}:assumed-role/ssd-operator/alice`);
    for (const c of doc.checks) {
      assert.ok(['PASS', 'WARN', 'FAIL', 'NOT VERIFIED'].includes(c.status), c.id);
      for (const key of ['id', 'section', 'title', 'required', 'basis', 'why', 'observed', 'expected', 'findings', 'remediation']) {
        assert.ok(Object.hasOwn(c, key), `${c.id}.${key}`);
      }
    }
    assert.ok(!first.out.includes('✓'));
  });

  it('credential values never reach the output', async (t) => {
    const world = verifiedWorld();
    world['iam get-role --role-name app-deploy'] = awsError('AccessDenied', 'GetRole', 'token=SESSIONTOKENVALUE-abcdef key AKIAIOSFODNN7EXAMPLE');
    const env = { AWS_SESSION_TOKEN: 'SESSIONTOKENVALUE-abcdef', AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };
    for (const args of [['aws', 'verify'], ['aws', 'verify', '--json']]) {
      const { out, code } = await cli(consumer(t), args, { world, io: { env } });
      assert.equal(code, 1);
      assert.ok(!out.includes('SESSIONTOKENVALUE-abcdef'));
      assert.ok(!out.includes('AKIAIOSFODNN7EXAMPLE'));
      assert.ok(!out.includes(env.AWS_SECRET_ACCESS_KEY));
    }
  });

  it('exit 2 for usage errors, before anything is read', async (t) => {
    const root = consumer(t);
    for (const args of [['aws', 'verify', '--scope', 'repo'], ['aws', 'verify', '--region', 'nowhere'], ['aws', 'verify', 'extra'], ['aws', 'verify', '--bogus']]) {
      const { code, f } = await cli(root, args);
      assert.equal(code, 2, args.join(' '));
      assert.deepEqual(f.calls, []);
    }
  });

  it('a profile without delivery is a configuration error, and AWS is not contacted', async (t) => {
    const { code, out, f } = await cli(consumer(t, {}, 'source-only'), ['aws', 'verify', '--json']);
    assert.equal(code, 1);
    assert.equal(JSON.parse(out).error.kind, 'configuration');
    assert.match(JSON.parse(out).error.message, /aws verify verifies/);
    assert.deepEqual(f.calls, []);
  });

  it('missing credentials end the run as ERROR (exit 1), never as a verdict', async (t) => {
    const world = { 'sts get-caller-identity': { stdout: '', stderr: 'Unable to locate credentials.', exitCode: 253 } };
    const { code, out, err } = await cli(consumer(t), ['aws', 'verify'], { world });
    assert.equal(code, 1);
    assert.equal(out, '');
    assert.match(err, /AWS authentication failed/);
    assert.match(err, /nothing is verified/);
  });
});
