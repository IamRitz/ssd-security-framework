// The framework commit policy (Phase 3D, docs/break-glass-repositories.md) and
// the CI broker's lazy secrets.
//
// The policy module is driven directly (every state, every malformed shape).
// The runtime is driven through the REAL buildBroker with a fake AWS SDK, so
// these tests see exactly which secrets and parameters the deployed wiring
// reads, and in what order.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  MAX_ALLOWED_FRAMEWORK_SHAS,
  createFrameworkPolicy,
  decideFramework,
  frameworkPolicyParameterName,
  parseFrameworkPolicy,
  renderFrameworkPolicy
} from '../broker/identity/framework-policy.mjs';
import { createJwksCache } from '../broker/identity/github-oidc.mjs';
import { createCiHandler } from '../broker/lambda/handlers.mjs';
import { buildBroker, lazySecret } from '../broker/lambda/runtime.mjs';
import { ssmError } from './support/fake-approvers.mjs';
import { createFakeDynamo } from './support/fake-dynamodb.mjs';
import { FRAMEWORK_SHA, REPO_A, SHA_A, createSigningKey, fakeJwksFetch, githubClaims, signToken } from './support/jwt-fixtures.mjs';

const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const C = 'c'.repeat(40);
const canonical = (environment, shas) => JSON.stringify({ schemaVersion: 1, environment, shas });

// =================================================================================
describe('framework policy: parameter name and canonical value', () => {
  it('names one parameter per environment, outside the approver path', () => {
    assert.equal(frameworkPolicyParameterName('production'), '/ssd/break-glass/production/governance/allowed-framework-shas');
    assert.equal(frameworkPolicyParameterName('synthetic'), '/ssd/break-glass/synthetic/governance/allowed-framework-shas');
    for (const bad of ['', 'Production', 'staging', undefined, '../production']) {
      assert.equal(frameworkPolicyParameterName(bad), null);
    }
  });

  it('renders exactly one canonical value: fixed key order, SHAs ascending', () => {
    assert.equal(renderFrameworkPolicy('synthetic', [C, A, B]), `{"schemaVersion":1,"environment":"synthetic","shas":["${A}","${B}","${C}"]}`);
    assert.equal(renderFrameworkPolicy('production', []), '{"schemaVersion":1,"environment":"production","shas":[]}');
  });

  it('parses the canonical value, including the empty set', () => {
    const parsed = parseFrameworkPolicy(canonical('production', [A, B]), 'production');
    assert.equal(parsed.state, 'valid');
    assert.deepEqual([...parsed.shas], [A, B]);
    assert.equal(parseFrameworkPolicy(canonical('production', []), 'production').shas.size, 0);
    const max = Array.from({ length: MAX_ALLOWED_FRAMEWORK_SHAS }, (_, i) => i.toString(16).padStart(40, '0'));
    assert.equal(parseFrameworkPolicy(canonical('production', max), 'production').state, 'valid');
  });

  for (const [name, value] of [
    ['not a string', 7],
    ['over 4096 bytes', `${canonical('production', [A])}${' '.repeat(4096)}`],
    ['not JSON', '{'],
    ['a JSON array', `["${A}"]`],
    ['JSON null', 'null'],
    ['keys out of order', JSON.stringify({ environment: 'production', schemaVersion: 1, shas: [A] })],
    ['an extra key', JSON.stringify({ schemaVersion: 1, environment: 'production', shas: [A], note: 'x' })],
    ['a missing key', JSON.stringify({ schemaVersion: 1, environment: 'production' })],
    ['another schemaVersion', JSON.stringify({ schemaVersion: 2, environment: 'production', shas: [A] })],
    ['a string schemaVersion', JSON.stringify({ schemaVersion: '1', environment: 'production', shas: [A] })],
    ['the other environment\'s value', canonical('synthetic', [A])],
    ['no environment', JSON.stringify({ schemaVersion: 1, environment: null, shas: [A] })],
    ['shas not an array', JSON.stringify({ schemaVersion: 1, environment: 'production', shas: A })],
    ['too many SHAs', canonical('production', Array.from({ length: MAX_ALLOWED_FRAMEWORK_SHAS + 1 }, (_, i) => i.toString(16).padStart(40, '0')))],
    ['an upper-case SHA', canonical('production', [A.toUpperCase()])],
    ['a short SHA', canonical('production', [A.slice(1)])],
    ['a non-string entry', JSON.stringify({ schemaVersion: 1, environment: 'production', shas: [1] })],
    ['unsorted SHAs', canonical('production', [B, A])],
    ['a duplicate SHA', canonical('production', [A, A])]
  ]) {
    it(`a value with ${name} is malformed, never partially used`, () => {
      const parsed = parseFrameworkPolicy(value, 'production');
      assert.equal(parsed.state, 'malformed');
      assert.equal(parsed.shas, null);
    });
  }
});

// =================================================================================
describe('framework policy: every lookup state fails closed except allowed', () => {
  const NAME = '/ssd/break-glass/production/governance/allowed-framework-shas';
  const policyWith = (entry, environment = 'production') => {
    const requested = [];
    const policy = createFrameworkPolicy({
      environment,
      getParameter: async (name) => {
        requested.push(name);
        if (entry instanceof Error) throw entry;
        if (entry === undefined) throw ssmError('ParameterNotFound');
        return typeof entry === 'string' ? { Name: name, Type: 'String', Value: entry } : entry;
      }
    });
    return { policy, requested };
  };

  it('allowed only for a commit in the set; reads exactly this environment\'s parameter', async () => {
    const { policy, requested } = policyWith(canonical('production', [A, B]));
    assert.equal((await policy.check(A)).state, 'allowed');
    assert.equal((await policy.check(C)).state, 'not_allowed');
    assert.deepEqual(requested, [NAME, NAME], 'no cache: every check reads');
  });

  for (const [name, entry, state] of [
    ['an empty set', canonical('production', []), 'not_allowed'],
    ['no parameter', undefined, 'absent'],
    ['access denied', ssmError('AccessDeniedException'), 'unverified'],
    ['a timeout', ssmError('TimeoutError'), 'unverified'],
    ['a SecureString parameter', { Type: 'SecureString', Value: canonical('production', [A]) }, 'malformed'],
    ['a StringList parameter', { Type: 'StringList', Value: A }, 'malformed'],
    ['a malformed value', canonical('production', [B, A]), 'malformed']
  ]) {
    it(`${name} -> ${state}`, async () => {
      assert.equal((await policyWith(entry).policy.check(A)).state, state);
    });
  }

  for (const [name, environment, sha] of [
    ['an unknown environment', 'staging', A],
    ['no environment', null, A],
    ['no commit', 'production', undefined],
    ['an upper-case commit', 'production', A.toUpperCase()],
    ['a short commit', 'production', A.slice(1)]
  ]) {
    it(`${name} is misconfigured and reads nothing`, async () => {
      const { policy, requested } = policyWith(canonical('production', [A]), environment);
      assert.equal((await policy.check(sha)).state, 'misconfigured');
      assert.deepEqual(requested, []);
    });
  }

  it('decideFramework: only an exact `allowed` passes; nothing else is ever promoted', async () => {
    assert.equal((await decideFramework({ check: async () => ({ state: 'allowed' }) }, A)).state, 'allowed');
    for (const [policy, state] of [
      [undefined, 'misconfigured'],
      [{}, 'misconfigured'],
      [{ check: async () => { throw new Error('x'); } }, 'unverified'],
      [{ check: async () => ({ state: 'Allowed' }) }, 'misconfigured'],
      [{ check: async () => ({ state: 'not_allowed' }) }, 'not_allowed'],
      [{ check: async () => ({ state: 'absent' }) }, 'absent'],
      [{ check: async () => null }, 'misconfigured'],
      [{ check: async () => true }, 'misconfigured']
    ]) {
      assert.equal((await decideFramework(policy, A)).state, state);
    }
  });
});

// =================================================================================
// The real runtime wiring, over a fake AWS SDK.

const KEY = createSigningKey({ kid: 'runtime-key' });
const ARNS = {
  bot: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:ssd/break-glass/synthetic/slack-bot-token-AbC123',
  signing: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:ssd/break-glass/synthetic/slack-signing-secret-AbC123',
  github: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:ssd/break-glass/synthetic/github-token-AbC123'
};
const POLICY_NAME = '/ssd/break-glass/synthetic/governance/allowed-framework-shas';

const named = (name) => Object.assign(new Error(`${name} (fake)`), { name });

function fakeAws({ secrets = {}, parameters = {} } = {}) {
  const events = [];
  const secretReads = [];
  const dynamo = createFakeDynamo();
  const command = (op) =>
    class {
      constructor(input) {
        this.op = op;
        this.input = input;
      }
    };
  const sdk = {
    dynamodb: new Proxy(
      {
        DynamoDBClient: class {
          send(cmd) {
            events.push(cmd.op);
            return dynamo.client.call(cmd.op, cmd.input);
          }
        }
      },
      { get: (target, name) => target[name] ?? (String(name).endsWith('Command') ? command(String(name).slice(0, -'Command'.length)) : undefined) }
    ),
    secrets: {
      SecretsManagerClient: class {
        async send(cmd) {
          const arn = cmd.input.SecretId;
          events.push('secret');
          secretReads.push(arn);
          const value = secrets[arn];
          if (value instanceof Error) throw value;
          // An empty secret container (no AWSCURRENT) is what 3C creates.
          if (value === undefined) throw named('ResourceNotFoundException');
          return { SecretString: value };
        }
      },
      GetSecretValueCommand: command('GetSecretValue')
    },
    ssm: {
      SSMClient: class {
        async send(cmd) {
          events.push(`ssm:${cmd.input.Name}`);
          const value = parameters[cmd.input.Name];
          if (value === undefined) throw named('ParameterNotFound');
          return { Parameter: { Name: cmd.input.Name, Type: 'String', Value: value } };
        }
      },
      GetParameterCommand: command('GetParameter')
    }
  };
  const slackCalls = [];
  const fetchImpl = async (url, init) => {
    slackCalls.push({ url: String(url), authorization: init.headers.authorization });
    events.push('slack');
    return { ok: true, status: 200, json: async () => ({ ok: true, channel: 'C', ts: '1.2' }) };
  };
  return { sdk, events, secretReads, dynamo, secrets, parameters, slackCalls, fetchImpl };
}

const CI_ENV = {
  TABLE_NAME: 'ssd-break-glass-synthetic-requests',
  SLACK_CHANNEL_ID: 'C0SYNTHETIC1',
  BREAK_GLASS_ENVIRONMENT: 'synthetic',
  SLACK_BOT_TOKEN_SECRET_ARN: ARNS.bot
};
const INTERACTIONS_ENV = {
  TABLE_NAME: 'ssd-break-glass-synthetic-requests',
  BREAK_GLASS_ENVIRONMENT: 'synthetic',
  SLACK_BOT_TOKEN_SECRET_ARN: ARNS.bot,
  SLACK_SIGNING_SECRET_ARN: ARNS.signing,
  GITHUB_TOKEN_SECRET_ARN: ARNS.github
};

const payload = () => ({
  schemaVersion: 1,
  environment: CI_ENV.BREAK_GLASS_ENVIRONMENT,
  gateDigest: 'a'.repeat(64),
  timeoutSeconds: 900,
  context: { repository: REPO_A.repository, commitSha: SHA_A, pullRequest: '51' },
  findings: [{ source: 'semgrep', id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }]
});

async function ciBroker(aws, env = CI_ENV) {
  const jwks = createJwksCache({ fetchImpl: fakeJwksFetch([KEY]).fetchImpl });
  const broker = await buildBroker(env, { role: 'ci', sdk: aws.sdk, jwks, fetchImpl: aws.fetchImpl });
  const ci = createCiHandler({ getBroker: async () => broker });
  const token = (overrides = {}) => signToken(githubClaims(overrides), { key: KEY });
  return { notify: (identityToken) => ci({ action: 'notify', payload: payload(), identityToken }), token };
}

describe('CI broker secrets: read only after identity and framework acceptance, only when posting', () => {
  it('building the CI broker reads no secret', async () => {
    const aws = fakeAws({ parameters: { [POLICY_NAME]: renderFrameworkPolicy('synthetic', [FRAMEWORK_SHA]) } });
    await ciBroker(aws);
    assert.deepEqual(aws.secretReads, []);
  });

  for (const [name, arrange, expected] of [
    ['a missing identity token', () => ({ identityToken: '' }), 401],
    ['a commit not in the set', (aws) => { aws.parameters[POLICY_NAME] = renderFrameworkPolicy('synthetic', ['e'.repeat(40)]); }, 403],
    ['no policy parameter', (aws) => { delete aws.parameters[POLICY_NAME]; }, 503],
    ['another environment\'s policy value', (aws) => { aws.parameters[POLICY_NAME] = renderFrameworkPolicy('production', [FRAMEWORK_SHA]); }, 503]
  ]) {
    it(`${name}: refused (${expected}) without reading any secret`, async () => {
      const aws = fakeAws({
        secrets: { [ARNS.bot]: 'xoxb-synthetic' },
        parameters: { [POLICY_NAME]: renderFrameworkPolicy('synthetic', [FRAMEWORK_SHA]) }
      });
      const override = arrange(aws) ?? {};
      const { notify, token } = await ciBroker(aws);
      const result = await notify('identityToken' in override ? override.identityToken : token());
      assert.equal(result.statusCode, expected);
      assert.deepEqual(aws.secretReads, []);
      assert.ok(!aws.events.includes('secret'));
      assert.equal(aws.slackCalls.length, 0);
    });
  }

  it('an admitted request reads the Slack token after the policy and the store, just before posting', async () => {
    const aws = fakeAws({
      secrets: { [ARNS.bot]: 'xoxb-synthetic' },
      parameters: { [POLICY_NAME]: renderFrameworkPolicy('synthetic', [FRAMEWORK_SHA]) }
    });
    const { notify, token } = await ciBroker(aws);
    assert.equal((await notify(token())).statusCode, 201);
    const at = (event) => aws.events.indexOf(event);
    assert.ok(at(`ssm:${POLICY_NAME}`) >= 0 && at(`ssm:${POLICY_NAME}`) < at('PutItem'), 'policy before the first write');
    assert.ok(at('PutItem') < at('secret') && at('secret') < at('slack'), 'the secret is read only to post');
    assert.equal(aws.slackCalls[0].authorization, 'Bearer xoxb-synthetic');
  });

  it('an empty Slack secret: the admitted request is rolled back (502), and the failure is not cached', async () => {
    const aws = fakeAws({ parameters: { [POLICY_NAME]: renderFrameworkPolicy('synthetic', [FRAMEWORK_SHA]) } });
    const { notify, token } = await ciBroker(aws);
    const failed = await notify(token());
    assert.equal(failed.statusCode, 502);
    assert.match(failed.error, /^slack_post_failed: /);
    assert.equal([...aws.dynamo.table.values()].filter((item) => item.doc).length, 0, 'the pending request was rolled back');
    assert.equal(aws.secretReads.length, 1);
    // The value is put: the next post reads it again (failure not cached) ...
    aws.secrets[ARNS.bot] = 'xoxb-now-set';
    assert.equal((await notify(token())).statusCode, 201);
    assert.equal(aws.secretReads.length, 2);
    // ... and then keeps it (success cached).
    assert.equal((await notify(token())).statusCode, 201);
    assert.equal(aws.secretReads.length, 2);
    assert.deepEqual(aws.slackCalls.map((call) => call.authorization), ['Bearer xoxb-now-set', 'Bearer xoxb-now-set']);
  });

  it('the CI function reads its own environment\'s policy, and none without an environment', async () => {
    const aws = fakeAws({ parameters: { [POLICY_NAME]: renderFrameworkPolicy('synthetic', [FRAMEWORK_SHA]) } });
    const { notify, token } = await ciBroker(aws, { ...CI_ENV, BREAK_GLASS_ENVIRONMENT: undefined });
    const refused = await notify(token());
    // Without an environment the broker refuses every request first (Phase 3E
    // environment binding), before the token or any policy is read.
    assert.deepEqual([refused.statusCode, refused.error], [500, 'environment_misconfigured']);
    assert.ok(!aws.events.some((event) => event.startsWith('ssm:')), 'no SSM call without an environment');
  });
});

describe('interaction function secrets: unchanged, read at start-up', () => {
  it('reads all three secrets while building, before any request', async () => {
    const aws = fakeAws({ secrets: { [ARNS.bot]: 'xoxb', [ARNS.signing]: 'signing', [ARNS.github]: 'ghp' } });
    await buildBroker(INTERACTIONS_ENV, { role: 'interactions', sdk: aws.sdk, jwks: createJwksCache({ fetchImpl: fakeJwksFetch([KEY]).fetchImpl }) });
    assert.deepEqual([...aws.secretReads].sort(), [ARNS.bot, ARNS.github, ARNS.signing].sort());
  });

  it('a secret it cannot read fails the cold start, as before', async () => {
    const aws = fakeAws({ secrets: { [ARNS.signing]: 'signing', [ARNS.github]: 'ghp' } });
    await assert.rejects(buildBroker(INTERACTIONS_ENV, { role: 'interactions', sdk: aws.sdk }), /ResourceNotFoundException/);
  });

  it('without a role, secrets are read eagerly (the conservative default)', async () => {
    const aws = fakeAws({ secrets: { [ARNS.bot]: 'xoxb', [ARNS.signing]: 'signing', [ARNS.github]: 'ghp' } });
    await buildBroker(INTERACTIONS_ENV, { sdk: aws.sdk, jwks: createJwksCache({ fetchImpl: fakeJwksFetch([KEY]).fetchImpl }) });
    assert.equal(aws.secretReads.length, 3);
  });
});

describe('lazySecret: cache success, never failure', () => {
  it('reads once on success, shares a concurrent read, and retries after a failure', async () => {
    let reads = 0;
    let next = () => Promise.reject(named('ResourceNotFoundException'));
    const get = lazySecret(() => {
      reads += 1;
      return next();
    });
    await assert.rejects(get(), /ResourceNotFoundException/);
    next = () => Promise.resolve('');
    await assert.rejects(get(), /secret has no value/);
    next = () => Promise.resolve('value');
    assert.deepEqual(await Promise.all([get(), get(), get()]), ['value', 'value', 'value']);
    assert.equal(await get(), 'value');
    assert.equal(reads, 3, 'two failed reads were retried; the success was read once and shared');
  });
});
