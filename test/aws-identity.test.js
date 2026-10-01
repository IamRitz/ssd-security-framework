// Identity and region come first (onboarding/aws/identity.mjs + doctor.mjs):
// a wrong account, a wrong region or the root user stops the run before any
// resource is read, and the AWS CLI default region is never used.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { awsDoctor } from '../onboarding/aws/doctor.mjs';
import { IdentityError, parseCallerIdentity, principalKind, resolveRegion } from '../onboarding/aws/identity.mjs';
import { config } from './support/onboarding-fixtures.mjs';
import { ACCOUNT, CALLER, awsError, fakeAws, ok, readyWorld } from './support/aws-fake.mjs';

const ECR = 'container-ecr-framework-gated';
const run = async (world, { region = null, overrides = { delivery: { environment: 'production' } } } = {}) => {
  const f = fakeAws(world);
  const report = await awsDoctor({ config: config(ECR, overrides), region, exec: f.exec, env: {} });
  return { report, f };
};
const statusOf = (report, id) => report.checks.find((c) => c.id === id)?.status;

describe('region resolution', () => {
  it('explicit --region wins as the value; the configured region is the fallback', () => {
    assert.deepEqual(resolveRegion({ explicit: 'eu-west-1', configured: null }), { region: 'eu-west-1', source: 'flag', configured: null });
    assert.deepEqual(resolveRegion({ explicit: 'us-east-1', configured: 'us-east-1' }), { region: 'us-east-1', source: 'flag', configured: 'us-east-1' });
    assert.deepEqual(resolveRegion({ explicit: null, configured: 'us-east-1' }), { region: 'us-east-1', source: 'config', configured: 'us-east-1' });
  });

  it('no region anywhere is refused (never the AWS CLI default)', () => {
    assert.throws(() => resolveRegion({}), (error) => error instanceof IdentityError && error.kind === 'region-missing');
    assert.throws(() => resolveRegion({ explicit: 'us-east-1; rm -rf /' }), (error) => error.kind === 'configuration');
  });

  it('every AWS call carries the resolved region explicitly', async () => {
    const { f } = await run(readyWorld());
    assert.ok(f.calls.length > 10);
    for (const call of f.calls) {
      assert.deepEqual(call.argv.slice(call.argv.indexOf('--region')), ['--region', 'us-east-1', '--output', 'json', '--no-cli-pager']);
    }
  });

  it('an explicit region that matches the configuration is used', async () => {
    const { report } = await run(readyWorld(), { region: 'us-east-1' });
    assert.equal(report.target.regionSource, 'flag');
    assert.equal(statusOf(report, 'identity.region'), 'PASS');
  });

  it('a region mismatch blocks and contacts AWS not at all', async () => {
    const { report, f } = await run(readyWorld(), { region: 'eu-west-1' });
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(statusOf(report, 'identity.region'), 'FAIL');
    assert.equal(report.checks.find((c) => c.id === 'identity.region').findings[0].kind, 'region-mismatch');
    assert.deepEqual(f.calls, []);
  });
});

describe('caller identity', () => {
  it('the expected account passes and the run continues', async () => {
    const { report, f } = await run(readyWorld());
    assert.equal(statusOf(report, 'identity.account'), 'PASS');
    assert.equal(statusOf(report, 'identity.principal'), 'PASS');
    assert.equal(f.keys()[0], 'sts get-caller-identity', 'identity is resolved first');
    assert.deepEqual(report.target.caller, { account: ACCOUNT, arn: CALLER, userId: 'AROAEXAMPLEEXAMPLE01:alice', kind: 'assumed-role', partition: 'aws' });
  });

  it('a wrong account blocks before any resource is read', async () => {
    const world = readyWorld();
    world['sts get-caller-identity'] = ok({ Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'AROAX:y' });
    const { report, f } = await run(world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(statusOf(report, 'identity.account'), 'FAIL');
    assert.deepEqual(f.keys(), ['sts get-caller-identity']);
  });

  it('the account root user is refused before any resource is read', async () => {
    const world = readyWorld();
    world['sts get-caller-identity'] = ok({ Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root`, UserId: ACCOUNT });
    const { report, f } = await run(world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(statusOf(report, 'identity.principal'), 'FAIL');
    assert.equal(report.checks.find((c) => c.id === 'identity.principal').findings[0].kind, 'root-principal');
    assert.deepEqual(f.keys(), ['sts get-caller-identity']);
  });

  it('missing credentials end the run as an authentication error', async () => {
    const world = { 'sts get-caller-identity': { stdout: '', stderr: 'Unable to locate credentials. You can configure credentials by running "aws configure".', exitCode: 253 } };
    const f = fakeAws(world);
    await assert.rejects(awsDoctor({ config: config(ECR), exec: f.exec, env: {} }), (error) => error.kind === 'authentication');
    assert.deepEqual(f.keys(), ['sts get-caller-identity']);
  });

  it('an expired token ends the run as an authentication error', async () => {
    const f = fakeAws({ 'sts get-caller-identity': awsError('ExpiredToken', 'GetCallerIdentity') });
    await assert.rejects(awsDoctor({ config: config(ECR), exec: f.exec, env: {} }), (error) => error.kind === 'authentication');
  });

  it('a caller document that does not add up is refused', () => {
    assert.throws(() => parseCallerIdentity({ Account: ACCOUNT, Arn: 'arn:aws:sts::999999999999:assumed-role/x/y', UserId: 'x' }), IdentityError);
    assert.throws(() => parseCallerIdentity({ Account: '12', Arn: CALLER, UserId: 'x' }), IdentityError);
    assert.throws(() => parseCallerIdentity({}), IdentityError);
    assert.throws(() => parseCallerIdentity({ Account: ACCOUNT, Arn: 'not-an-arn', UserId: 'x' }), IdentityError);
  });

  it('principal kinds', () => {
    assert.equal(principalKind(`arn:aws:iam::${ACCOUNT}:root`), 'root');
    assert.equal(principalKind(`arn:aws-us-gov:iam::${ACCOUNT}:root`), 'root');
    assert.equal(principalKind(`arn:aws:iam::${ACCOUNT}:user/alice`), 'user');
    assert.equal(principalKind(CALLER), 'assumed-role');
    assert.equal(principalKind(`arn:aws:sts::${ACCOUNT}:federated-user/bob`), 'federated-user');
  });
});
