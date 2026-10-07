// Phase 3C: the shared break-glass stacks as rendered — the operator config,
// the derived names, production/synthetic separation, the template's
// DynamoDB/TTL/secrets/Lambda/IAM content, determinism and the scope
// boundary. No test talks to AWS.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { OperatorConfigError, parseOperatorConfig, validateOperatorConfig } from '../onboarding/aws/break-glass/operator-config.mjs';
import { assertSeparated, breakGlassArns, breakGlassNames, codeSha256Of, separationIdentifiers, separationProblems } from '../onboarding/aws/break-glass/names.mjs';
import { ScopeError, assertChangeScope, assertTemplateScope } from '../onboarding/aws/plan/scope.mjs';
import { BREAK_GLASS_STACKS } from '../onboarding/aws/stack-names.mjs';
import { canonicalJson } from '../onboarding/aws/templates/common.mjs';
import { BREAK_GLASS_RESOURCE_TYPES, renderBreakGlassTemplate } from '../onboarding/aws/templates/shared-break-glass.mjs';
import { ARTIFACT, CHANNELS, OPERATOR_YAML, TARGET, operator, rawOperator } from './support/break-glass-fake.mjs';

const render = (environment, op = operator()) => renderBreakGlassTemplate({ operator: op, environment, partition: 'aws' });
const resources = (environment, op) => render(environment, op).template.Resources;
const props = (environment, id, op) => resources(environment, op)[id].Properties;
const statementsOf = (doc) => (Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement]);
const list = (v) => (Array.isArray(v) ? v : [v]);

describe('operator config: identifiers only, both environments, never .ssd/onboarding.yml', () => {
  it('parses the documented file', () => {
    const op = parseOperatorConfig(OPERATOR_YAML);
    assert.equal(op.environments.production.slackChannelId, CHANNELS.production);
    assert.deepEqual({ ...op.environments.synthetic.artifact }, { ...ARTIFACT });
    assert.ok(Object.isFrozen(op.environments.production.artifact));
  });

  it('refuses unknown keys, missing environments and a missing artifact field', () => {
    const cases = [
      rawOperator({ extra: 1 }),
      rawOperator({ environments: { production: rawOperator().environments.production } }),
      (() => { const r = rawOperator(); delete r.environments.synthetic.artifact.sha256; return r; })(),
      (() => { const r = rawOperator(); r.environments.production.reservedConcurrency = 5; return r; })()
    ];
    for (const raw of cases) {
      assert.throws(() => validateOperatorConfig(raw), OperatorConfigError);
    }
  });

  it('refuses a credential-shaped value anywhere', () => {
    const r = rawOperator();
    r.environments.production.slackChannelId = 'xoxb-1234567890-abcdefghij';
    assert.throws(() => validateOperatorConfig(r), (e) => e instanceof OperatorConfigError && /identifiers only/.test(e.message));
  });

  it('refuses identifiers that are not what they claim to be', () => {
    const bad = [
      ['framework.ref', (r) => (r.framework.ref = 'v1')],
      ['aws.accountId', (r) => (r.aws.accountId = '12345')],
      ['slackChannelId', (r) => (r.environments.synthetic.slackChannelId = 'U0123456789')],
      ['artifact.versionId null', (r) => (r.environments.production.artifact.versionId = 'null')],
      ['artifact.sha256', (r) => (r.environments.production.artifact.sha256 = 'ABC')],
      ['artifact.key ..', (r) => (r.environments.production.artifact.key = 'broker/../x.zip')],
      ['artifact.bucket', (r) => (r.environments.production.artifact.bucket = 'Bad.Bucket')]
    ];
    for (const [what, mutate] of bad) {
      const r = rawOperator();
      mutate(r);
      assert.throws(() => validateOperatorConfig(r), OperatorConfigError, what);
    }
  });

  it('refuses one Slack channel for production and synthetic', () => {
    const r = rawOperator();
    r.environments.synthetic.slackChannelId = r.environments.production.slackChannelId;
    assert.throws(() => validateOperatorConfig(r), /Slack channel/);
  });

  it('allows production and synthetic to share the immutable artifact', () => {
    const op = operator();
    assert.deepEqual({ ...op.environments.production.artifact }, { ...op.environments.synthetic.artifact });
  });

  it('Phase 1 never reads the operator file: no Phase 1 module imports it', () => {
    for (const file of ['onboarding/cli.mjs', 'onboarding/lib/config.mjs', 'onboarding/lib/render.mjs', 'onboarding/lib/init.mjs', 'onboarding/lib/analyze.mjs', 'onboarding/lib/inspect.mjs']) {
      const text = readFileSync(file, 'utf8');
      assert.doesNotMatch(text, /operator-file|operator-config/, file);
    }
    assert.doesNotMatch(readFileSync('onboarding/aws/break-glass/operator-config.mjs', 'utf8'), /onboarding\.yml'|CONFIG_PATH|loadConfig\(/);
  });
});

describe('production and synthetic are separate by construction', () => {
  it('every runtime and security-state name differs, stack names included', () => {
    const p = breakGlassNames('production');
    const s = breakGlassNames('synthetic');
    assert.equal(p.stack, BREAK_GLASS_STACKS.production);
    assert.equal(s.stack, BREAK_GLASS_STACKS.synthetic);
    for (const key of ['stack', 'table', 'approverPrefix']) assert.notEqual(p[key], s[key], key);
    for (const group of ['functions', 'roles', 'secrets', 'logGroups']) {
      for (const k of Object.keys(p[group])) assert.notEqual(p[group][k], s[group][k], `${group}.${k}`);
    }
    const pa = breakGlassArns('production', TARGET);
    const sa = breakGlassArns('synthetic', TARGET);
    assert.notEqual(pa.table, sa.table);
    for (const k of ['ci', 'interactions']) {
      assert.notEqual(pa.functions[k], sa.functions[k]);
      assert.notEqual(pa.roles[k], sa.roles[k]);
    }
    for (const k of Object.keys(pa.secretPatterns)) assert.notEqual(pa.secretPatterns[k], sa.secretPatterns[k]);
    assert.doesNotThrow(() => assertSeparated(TARGET, CHANNELS));
  });

  it('separationProblems names any shared identifier (and the Slack channel)', () => {
    const p = separationIdentifiers('production', TARGET, { slackChannelId: 'C0SAMECHAN1' });
    const s = separationIdentifiers('synthetic', TARGET, { slackChannelId: 'C0SAMECHAN1' });
    assert.deepEqual(separationProblems(p, s), ["Slack channel 'c0samechan1' is also the Slack channel of the other environment"]);
    const tampered = { ...s, 'DynamoDB table': p['DynamoDB table'] };
    assert.equal(separationProblems(p, tampered).filter((m) => m.includes('DynamoDB table')).length, 2);
  });

  it('the rendered production and synthetic templates share no table, function, role, secret, log group or channel', () => {
    const p = canonicalJson(render('production').template);
    const s = canonicalJson(render('synthetic').template);
    for (const id of Object.values(separationIdentifiers('synthetic', TARGET, { slackChannelId: CHANNELS.synthetic })).flat()) {
      assert.ok(!p.includes(id), `production template references synthetic ${id}`);
    }
    for (const id of Object.values(separationIdentifiers('production', TARGET, { slackChannelId: CHANNELS.production })).flat()) {
      assert.ok(!s.includes(id), `synthetic template references production ${id}`);
    }
  });

  it('production cannot reference synthetic resources and vice versa (every policy resource is its own environment\'s)', () => {
    for (const [mine, other] of [['production', 'synthetic'], ['synthetic', 'production']]) {
      const { policies } = render(mine);
      for (const { permissions } of Object.values(policies)) {
        for (const st of statementsOf(permissions)) {
          for (const r of list(st.Resource)) {
            assert.ok(!r.includes(other), `${mine} grants on ${r}`);
            assert.ok(r.includes(mine), `${mine} grants on ${r}, which is not ${mine}'s`);
          }
        }
      }
    }
  });
});

describe('the template', () => {
  it('renders deterministically, and only from its inputs', () => {
    const a = canonicalJson(render('production').template);
    const b = canonicalJson(render('production').template);
    assert.equal(a, b);
    assert.ok(Buffer.byteLength(a) < 51_200, 'fits an inline template body');
    assert.doesNotMatch(a, /\d{4}-\d{2}-\d{2}T/, 'no timestamp');
  });

  it('holds exactly the expected resources, every one retained, and passes the scope boundary', () => {
    for (const env of ['production', 'synthetic']) {
      const t = render(env).template;
      assert.deepEqual(Object.fromEntries(Object.entries(t.Resources).map(([id, r]) => [id, r.Type])), { ...BREAK_GLASS_RESOURCE_TYPES });
      assert.doesNotThrow(() => assertTemplateScope(`break-glass-${env}`, t));
      assert.deepEqual(Object.keys(t).sort(), ['AWSTemplateFormatVersion', 'Description', 'Resources']);
    }
  });

  it('DynamoDB: key requestId (S), on-demand, TTL ENABLED on exactly `ttl`, PITR, deletion protection', () => {
    const t = props('production', 'RequestTable');
    assert.equal(t.TableName, 'ssd-break-glass-production-requests');
    assert.deepEqual(t.KeySchema, [{ AttributeName: 'requestId', KeyType: 'HASH' }]);
    assert.deepEqual(t.AttributeDefinitions, [{ AttributeName: 'requestId', AttributeType: 'S' }]);
    assert.equal(t.BillingMode, 'PAY_PER_REQUEST');
    assert.deepEqual(t.TimeToLiveSpecification, { AttributeName: 'ttl', Enabled: true });
    assert.equal(t.TimeToLiveSpecification.AttributeName, 'ttl');
    assert.equal(t.TimeToLiveSpecification.Enabled, true);
    assert.deepEqual(t.PointInTimeRecoverySpecification, { PointInTimeRecoveryEnabled: true });
    assert.equal(t.DeletionProtectionEnabled, true);
    assert.notEqual(t.TableName, props('synthetic', 'RequestTable').TableName);
  });

  it('the TTL attribute is the one the broker writes', () => {
    const store = readFileSync('broker/lambda/dynamodb-store.mjs', 'utf8');
    assert.match(store, /ttl: \{ N: String\(exp \+ TOKEN_RECORD_GRACE_SECONDS\) \}/, 'replay records carry `ttl`');
    assert.match(store, /ttl: \{ N: String\(Math\.floor/, 'requests carry `ttl`');
  });

  it('secrets are containers only: no value, no generated value, anywhere in the template', () => {
    for (const env of ['production', 'synthetic']) {
      for (const id of ['SlackBotTokenSecret', 'SlackSigningSecret', 'GithubTokenSecret']) {
        const p = props(env, id);
        assert.deepEqual(Object.keys(p).sort(), ['Description', 'Name', 'Tags']);
        assert.ok(p.Name.startsWith(`ssd/break-glass/${env}/`));
      }
      const text = canonicalJson(render(env).template);
      assert.doesNotMatch(text, /SecretString|GenerateSecretString|xox[abpr]-|ghp_|github_pat_/);
    }
  });

  it('the CI broker: own role, own table/channel/bot token, pinned runtime and artifact version, no URL, no permission', () => {
    const r = resources('production');
    const ci = r.CiFunction.Properties;
    assert.deepEqual(ci.Role, { 'Fn::GetAtt': ['CiExecutionRole', 'Arn'] });
    assert.equal(ci.Runtime, 'nodejs24.x');
    assert.deepEqual(ci.Architectures, ['arm64']);
    assert.equal(ci.Handler, 'broker/lambda/index.ciHandler');
    assert.deepEqual(ci.Code, { S3Bucket: ARTIFACT.bucket, S3Key: ARTIFACT.key, S3ObjectVersion: ARTIFACT.versionId });
    assert.deepEqual(ci.Environment.Variables, { TABLE_NAME: 'ssd-break-glass-production-requests', SLACK_CHANNEL_ID: CHANNELS.production, SLACK_BOT_TOKEN_SECRET_ARN: { Ref: 'SlackBotTokenSecret' } });
    assert.equal(ci.VpcConfig, undefined);
    assert.equal(ci.ReservedConcurrentExecutions, undefined, 'the IAM-only CI broker has no reservation');
    for (const [id, res] of Object.entries(r)) {
      if (['AWS::Lambda::Url', 'AWS::Lambda::Permission', 'AWS::Lambda::EventInvokeConfig'].includes(res.Type)) {
        const target = res.Properties.TargetFunctionArn ?? res.Properties.FunctionName;
        assert.notDeepEqual(target, { Ref: 'CiFunction' }, `${id} targets the CI broker`);
        assert.notDeepEqual(target, { 'Fn::GetAtt': ['CiFunction', 'Arn'] }, `${id} targets the CI broker`);
      }
    }
  });

  it('the interaction function: BREAK_GLASS_ENVIRONMENT, its three secrets, no approver map, one URL with exactly two URL-scoped permissions, no async retries', () => {
    const r = resources('synthetic');
    const i = r.InteractionsFunction.Properties;
    assert.deepEqual(i.Environment.Variables, {
      TABLE_NAME: 'ssd-break-glass-synthetic-requests',
      BREAK_GLASS_ENVIRONMENT: 'synthetic',
      SLACK_BOT_TOKEN_SECRET_ARN: { Ref: 'SlackBotTokenSecret' },
      SLACK_SIGNING_SECRET_ARN: { Ref: 'SlackSigningSecret' },
      GITHUB_TOKEN_SECRET_ARN: { Ref: 'GithubTokenSecret' }
    });
    assert.deepEqual(r.InteractionsFunctionUrl.Properties, { TargetFunctionArn: { 'Fn::GetAtt': ['InteractionsFunction', 'Arn'] }, AuthType: 'NONE' });
    assert.deepEqual(r.InteractionsUrlPermission.Properties, { FunctionName: { Ref: 'InteractionsFunction' }, Action: 'lambda:InvokeFunctionUrl', Principal: '*', FunctionUrlAuthType: 'NONE' });
    assert.deepEqual(r.InteractionsUrlInvokePermission.Properties, { FunctionName: { Ref: 'InteractionsFunction' }, Action: 'lambda:InvokeFunction', Principal: '*', InvokedViaFunctionUrl: true });
    assert.equal(r.InteractionsEventInvokeConfig.Properties.MaximumRetryAttempts, 0);
    assert.equal(i.ReservedConcurrentExecutions, 5, 'the public function is capped');
    assert.equal(resources('production').InteractionsFunction.Properties.ReservedConcurrentExecutions, 5, 'production too');
  });

  it('tags: framework, managed-by and the stack\'s own environment on every taggable resource; no consumer repository', () => {
    for (const env of ['production', 'synthetic']) {
      for (const [id, res] of Object.entries(resources(env))) {
        if (!res.Properties.Tags) continue;
        assert.deepEqual(res.Properties.Tags, [
          { Key: 'ssd:environment', Value: env },
          { Key: 'ssd:framework', Value: 'ssd-security-framework' },
          { Key: 'ssd:managed-by', Value: 'ssd-onboard' }
        ], `${env} ${id}`);
      }
    }
  });

  it('IAM policies use exact resources: no Action or Resource "*", only the documented wildcards', () => {
    for (const env of ['production', 'synthetic']) {
      const a = breakGlassArns(env, TARGET);
      const allowed = new Set([...Object.values(a.secretPatterns), ...Object.values(a.logStreams), a.approverParameters]);
      for (const { permissions } of Object.values(render(env).policies)) {
        for (const st of statementsOf(permissions)) {
          for (const action of list(st.Action)) assert.doesNotMatch(action, /[*?]/);
          for (const resource of list(st.Resource)) {
            assert.notEqual(resource, '*');
            if (/[*?]/.test(resource)) assert.ok(allowed.has(resource), `undocumented wildcard ${resource}`);
          }
        }
      }
    }
  });

  it('the CI execution role holds dynamodb:PutItem on exactly its own table', () => {
    for (const env of ['production', 'synthetic']) {
      const ci = render(env).policies.CiExecutionRole.permissions;
      const grant = statementsOf(ci).filter((s) => list(s.Action).includes('dynamodb:PutItem'));
      assert.equal(grant.length, 1);
      assert.deepEqual(list(grant[0].Resource), [breakGlassArns(env, TARGET).table]);
      const interactions = render(env).policies.InteractionsExecutionRole.permissions;
      assert.ok(!statementsOf(interactions).some((s) => list(s.Action).includes('dynamodb:PutItem')), 'the interaction function never puts');
    }
  });

  it('refuses to render when the two environments would share a Slack channel', () => {
    const op = { ...operator(), environments: { production: operator().environments.production, synthetic: { ...operator().environments.synthetic, slackChannelId: CHANNELS.production } } };
    assert.throws(() => render('production', op), /not separate/);
  });
});

describe('scope boundary: IAM roles only in the named break-glass kinds', () => {
  const role = { Type: 'AWS::IAM::Role', DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain', Properties: {} };
  const tpl = (resources) => ({ AWSTemplateFormatVersion: '2010-09-09', Description: 'x', Resources: resources });

  it('the shared OIDC kind still refuses an IAM role', () => {
    assert.throws(() => assertTemplateScope('shared-github-oidc', tpl({ CiExecutionRole: role })), ScopeError);
  });

  it('a break-glass kind refuses an ECR repository, an OIDC provider, or an unknown logical id', () => {
    for (const r of [{ X: { ...role, Type: 'AWS::ECR::Repository' } }, { GitHubOidcProvider: { ...role, Type: 'AWS::IAM::OIDCProvider' } }, { InvokerRole: role }]) {
      assert.throws(() => assertTemplateScope('break-glass-production', tpl(r)), ScopeError);
    }
    assert.throws(() => assertChangeScope('break-glass-synthetic', [{ logicalId: 'EcrRepository', type: 'AWS::ECR::Repository' }]), ScopeError);
  });

  it('a repo kind refuses break-glass resources', () => {
    assert.throws(() => assertTemplateScope('repo', tpl({ RequestTable: { ...role, Type: 'AWS::DynamoDB::Table' } })), ScopeError);
  });
});

describe('Lambda CodeSha256 is base64(sha256(zip bytes)), not hex', () => {
  it('the configured hex digest converts to the base64 Lambda reports', () => {
    const zip = Buffer.from('PK\u0003\u0004 a stand-in for the bundle bytes');
    const hex = createHash('sha256').update(zip).digest('hex');
    assert.equal(codeSha256Of(hex), createHash('sha256').update(zip).digest('base64'));
    assert.equal(codeSha256Of(hex).length, 44, 'the length of every CodeSha256 in the AWS CLI examples');
    assert.notEqual(codeSha256Of(hex), hex);
    assert.throws(() => codeSha256Of(codeSha256Of(hex)), /64 lower-case hex/);
  });
});
