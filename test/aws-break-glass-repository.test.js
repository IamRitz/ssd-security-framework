// Phase 3D (C6): the per-repository break-glass stack — the repository file,
// names, the invoker role's trust and permissions, the template and scope,
// `aws plan --scope break-glass-repo`, apply intent, `aws verify --scope
// break-glass-repo`, the GitHub identity reader and the CLI. No test talks to
// AWS or GitHub.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { assertBreakGlassPlanning, assertGovernancePlanning, assertRepositoryPlanning, assertRepositoryRead } from '../onboarding/aws/aws-cli.mjs';
import { awsApply } from '../onboarding/aws/apply.mjs';
import { checkIntent, checkPlanRecord } from '../onboarding/aws/apply/plan-check.mjs';
import { invokerNames } from '../onboarding/aws/break-glass/names.mjs';
import { RepositoryConfigError, parseRepositoryConfig, validateRepositoryConfig } from '../onboarding/aws/break-glass/repository-config.mjs';
import { awsPlanBreakGlassRepository } from '../onboarding/aws/break-glass/repository-plan.mjs';
import { awsVerifyBreakGlassRepository } from '../onboarding/aws/break-glass/repository-verify.mjs';
import { planDirOf, readPlan } from '../onboarding/aws/plan/record.mjs';
import { ScopeError, assertTemplateScope } from '../onboarding/aws/plan/scope.mjs';
import { assumes, invokerPermissionPolicy, invokerProbes, invokerTrustPolicy, invokerTrustProblems } from '../onboarding/aws/policy/break-glass-invoker.mjs';
import { breakGlassKindOf, breakGlassRepoStackName, repositoryIdOfStack } from '../onboarding/aws/stack-names.mjs';
import { renderRepositoryTemplate } from '../onboarding/aws/templates/break-glass-repository.mjs';
import { assertIdentityRead, identityEndpoints, readArgv } from '../onboarding/github/gh-cli.mjs';
import { discoverRepositoryIdentity } from '../onboarding/github/repository-identity.mjs';
import { FRAMEWORK, capture, tempDir } from './support/onboarding-fixtures.mjs';
import { fakeAws } from './support/aws-fake.mjs';
import { applyWorld, mutations } from './support/aws-apply-fake.mjs';
import { withStack } from './support/aws-plan-fake.mjs';
import { OPERATOR_YAML, operator, tagsFor } from './support/break-glass-fake.mjs';
import { policy } from './support/governance-fake.mjs';
import {
  ACCOUNT,
  APPROVERS,
  PROVIDER,
  REGION,
  REPOSITORY_YAML,
  REPO_ID,
  SLUG,
  SUBJECT,
  TARGET,
  deployedRepository,
  existingResource,
  github,
  greenfieldRepository,
  oidcProvider,
  rawRepository,
  repository,
  sharedStack
} from './support/repository-fake.mjs';

const quiet = async () => {};
const kinds = (findings) => findings.map((f) => f.kind);
const STACK = (env, id = REPO_ID) => `ssd-break-glass-${env}-repo-${id}`;
const ROLE = (env, id = REPO_ID) => `ssd-break-glass-${env}-invoker-${id}`;
const PARAM = (env, id = REPO_ID) => `/ssd/break-glass/${env}/approvers/${id}`;
const refusedBy = (assertFn, argv) => assert.throws(() => assertFn(argv), (e) => e.kind === 'refused', argv.join(' '));

async function plan(t, world, { environment = 'synthetic', config = repository(), gh = github(), framework = FRAMEWORK, root = tempDir(t) } = {}) {
  const f = fakeAws(world, { allowlist: assertRepositoryPlanning });
  const report = await awsPlanBreakGlassRepository({ operator: operator(), repository: config, environment, github: gh, exec: f.exec, env: {}, framework, root, sleep: quiet });
  assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
  return { report, f, root, gh, unit: report.units[0], created: world.__changeSets?.created ?? [] };
}

describe('repository: the configuration file', () => {
  it('accepts the documented shape; [] is valid; only configured environments exist', () => {
    const c = parseRepositoryConfig(REPOSITORY_YAML);
    assert.deepEqual(c.repository, { slug: SLUG, id: REPO_ID });
    assert.deepEqual(c.environments.synthetic.approvers, [...APPROVERS]);
    assert.deepEqual(c.environments.production.approvers, []);
    const only = repository({ environments: { synthetic: { approvers: [] } } });
    assert.deepEqual(Object.keys(only.environments), ['synthetic']);
    assert.ok(Object.isFrozen(c) && Object.isFrozen(c.environments.synthetic.approvers));
  });

  const refused = (raw, pattern) => assert.throws(() => validateRepositoryConfig(raw), (e) => e instanceof RepositoryConfigError && (!pattern || e.problems.some((p) => pattern.test(p))), JSON.stringify(raw).slice(0, 160));
  it('refuses a customized-subject override: this version never plans one', () => {
    refused({ ...rawRepository(), oidc: { subject: 'repo:acme@1/x@2:pull_request', observedRunId: '1' } }, /customized OIDC subject is not supported/);
  });

  it('refuses a bad id (unquoted, zero, leading zero, non-numeric), a bad slug, no environment, and unknown keys', () => {
    for (const id of [424242, '0', '0424242', 'abc', '1'.repeat(21), '']) refused(rawRepository({ repository: { slug: SLUG, id } }), /repository\.id/);
    for (const slug of ['acme', 'acme/x/y', '-acme/x', 'acme/x y', 7]) refused(rawRepository({ repository: { slug, id: REPO_ID } }), /repository\.slug/);
    refused(rawRepository({ environments: {} }), /at least one/);
    refused(rawRepository({ environments: { staging: { approvers: [] } } }), /unknown key/);
    refused(rawRepository({ environments: { synthetic: { approvers: [], extra: 1 } } }), /unknown key/);
    refused({ ...rawRepository(), extra: true }, /unknown key/);
    refused(rawRepository({ kind: 'break-glass-framework-policy' }), /kind/);
  });

  it("approvers are validated by the broker's own parser", () => {
    for (const approvers of [['u0lowercase1'], ['U0APPROVER1', 'U0APPROVER1'], Array.from({ length: 51 }, (_, i) => `U${String(i).padStart(10, '0')}`), 'U0APPROVER1', [7]]) {
      refused(rawRepository({ environments: { synthetic: { approvers } } }));
    }
  });

  it('refuses a credential-shaped value without echoing it', () => {
    assert.throws(() => validateRepositoryConfig(rawRepository({ note: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' })), (e) => e.problems.every((p) => /looks like a/.test(p)) && !e.message.includes('ghp_abc'));
  });
});

describe('repository: names, kinds and the invoker policy', () => {
  it('every name derives from the environment and the immutable repository_id', () => {
    assert.deepEqual(invokerNames('synthetic', REPO_ID), { environment: 'synthetic', repositoryId: REPO_ID, stack: STACK('synthetic'), role: ROLE('synthetic'), policyName: 'ssd-break-glass-invoke-ci', approverParameter: PARAM('synthetic') });
    assert.equal(breakGlassRepoStackName('production', '1'), 'ssd-break-glass-production-repo-1');
    for (const [env, id] of [['staging', '1'], ['production', '01'], ['production', 'x'], ['production', 1]]) assert.throws(() => breakGlassRepoStackName(env, id));
    assert.equal(repositoryIdOfStack('synthetic', STACK('synthetic')), REPO_ID);
    for (const name of [STACK('production'), 'ssd-break-glass-synthetic-repo-', 'ssd-break-glass-synthetic-repo-01', 'ssd-break-glass-synthetic-repo-1-x', 'ssd-break-glass-synthetic']) assert.equal(repositoryIdOfStack('synthetic', name), null, name);
    assert.deepEqual(breakGlassKindOf('break-glass-repo-production'), { family: 'repo', environment: 'production' });
    assert.ok(ROLE('synthetic', '9'.repeat(20)).length <= 64, 'IAM role names are at most 64 characters');
  });

  it('trust: exactly one StringEquals statement on the default pull_request subject', () => {
    const trust = invokerTrustPolicy({ partition: 'aws', account: ACCOUNT, subject: SUBJECT });
    assert.deepEqual(trust, {
      Version: '2012-10-17',
      Statement: [{ Sid: 'PullRequestRunsOfOneRepository', Effect: 'Allow', Principal: { Federated: PROVIDER }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com', 'token.actions.githubusercontent.com:sub': SUBJECT } } }]
    });
    assert.deepEqual(invokerTrustProblems(trust, { account: ACCOUNT, fullName: SLUG, repositoryId: REPO_ID }), []);
  });

  it('the offline evaluator catches every broadening of the trust', () => {
    const base = () => invokerTrustPolicy({ partition: 'aws', account: ACCOUNT, subject: SUBJECT });
    const variants = {
      'StringLike wildcard subject': (d) => { d.Statement[0].Condition = { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' }, StringLike: { 'token.actions.githubusercontent.com:sub': `repo:${SLUG}:*` } }; },
      'a second subject (push to main)': (d) => { d.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'] = [SUBJECT, `repo:${SLUG}:ref:refs/heads/main`]; },
      'no audience condition': (d) => { delete d.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:aud']; },
      'no subject condition': (d) => { delete d.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub']; },
      'a second statement': (d) => { d.Statement.push({ ...d.Statement[0], Condition: { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com', 'token.actions.githubusercontent.com:sub': 'repo:acme/other:pull_request' } } }); },
      'another repository': (d) => { d.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'] = 'repo:Acme/Other:pull_request'; },
      'principal *': (d) => { d.Statement[0].Principal = '*'; d.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'] = [SUBJECT, 'repo:Acme/Payments-API-other:pull_request']; }
    };
    for (const [name, mutate] of Object.entries(variants)) {
      const d = base();
      mutate(d);
      assert.ok(invokerTrustProblems(d, { account: ACCOUNT, fullName: SLUG, repositoryId: REPO_ID }).length > 0, name);
    }
    assert.equal(assumes(base(), { provider: PROVIDER, claims: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com', 'token.actions.githubusercontent.com:sub': SUBJECT } }), true);
  });

  it('permissions: InvokeFunction on the unqualified CI broker of its own environment, nothing else', () => {
    assert.deepEqual(invokerPermissionPolicy('synthetic', TARGET), { Version: '2012-10-17', Statement: [{ Sid: 'InvokeCiBrokerOnly', Effect: 'Allow', Action: 'lambda:InvokeFunction', Resource: `arn:aws:lambda:${REGION}:${ACCOUNT}:function:ssd-break-glass-synthetic-ci` }] });
  });

  it("the negative probes cover the contract's table", () => {
    const { required, denied } = invokerProbes('synthetic', TARGET, { repositoryId: REPO_ID });
    assert.deepEqual(required.map((p) => [p.action, p.resource]), [['lambda:InvokeFunction', `arn:aws:lambda:${REGION}:${ACCOUNT}:function:ssd-break-glass-synthetic-ci`]]);
    const has = (action, fragment) => assert.ok(denied.some((p) => p.action === action && p.resource.includes(fragment) && p.severity === 'FAIL'), `${action} ${fragment}`);
    has('lambda:InvokeFunction', 'ssd-break-glass-synthetic-ci:$LATEST');
    has('lambda:InvokeFunction', 'ssd-break-glass-synthetic-interactions');
    has('lambda:InvokeFunction', 'ssd-break-glass-production-ci');
    has('lambda:InvokeFunction', 'unrelated-function');
    has('lambda:InvokeFunctionUrl', 'ssd-break-glass-synthetic-interactions');
    has('lambda:UpdateFunctionCode', 'ssd-break-glass-synthetic-ci');
    for (const action of ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Scan']) has(action, 'ssd-break-glass-production-requests');
    has('secretsmanager:GetSecretValue', 'ssd/break-glass/production/slack-bot-token');
    has('ssm:GetParameter', PARAM('synthetic'));
    has('ssm:PutParameter', PARAM('synthetic', '424243'));
    has('ssm:PutParameter', '/ssd/break-glass/production/governance/allowed-framework-shas');
    has('iam:PassRole', 'ssd-break-glass-synthetic-ci-execution');
    has('sts:AssumeRole', ROLE('synthetic', '424243'));
    has('logs:PutLogEvents', '/aws/lambda/ssd-break-glass-production-interactions');
    assert.equal(denied.length, 5 + 4 + 7 + 12 + 18 + 12 + 10 + 8);
  });
});

describe('repository: template and scope', () => {
  for (const environment of ['production', 'synthetic']) {
    it(`${environment}: exactly the retained invoker role and approver parameter`, () => {
      const c = repository();
      const { template } = renderRepositoryTemplate({ config: c, environment, fullName: SLUG, ...TARGET });
      assert.deepEqual(Object.keys(template.Resources).sort(), ['ApproverParameter', 'InvokerRole']);
      const role = template.Resources.InvokerRole;
      assert.equal(role.Type, 'AWS::IAM::Role');
      assert.equal(role.DeletionPolicy, 'Retain');
      assert.equal(role.UpdateReplacePolicy, 'Retain');
      assert.equal(role.Properties.RoleName, ROLE(environment));
      assert.equal(role.Properties.MaxSessionDuration, 3600);
      assert.deepEqual(role.Properties.AssumeRolePolicyDocument, invokerTrustPolicy({ partition: 'aws', account: ACCOUNT, subject: SUBJECT }));
      assert.deepEqual(role.Properties.Policies, [{ PolicyName: 'ssd-break-glass-invoke-ci', PolicyDocument: invokerPermissionPolicy(environment, TARGET) }]);
      assert.equal(role.Properties.ManagedPolicyArns, undefined);
      assert.equal(role.Properties.PermissionsBoundary, undefined);
      assert.deepEqual(role.Properties.Tags, tagsFor(environment));
      const p = template.Resources.ApproverParameter;
      assert.equal(p.Type, 'AWS::SSM::Parameter');
      assert.equal(p.DeletionPolicy, 'Retain');
      assert.equal(p.UpdateReplacePolicy, 'Retain');
      assert.deepEqual([p.Properties.Name, p.Properties.Type, p.Properties.Tier, p.Properties.DataType], [PARAM(environment), 'String', 'Standard', 'text']);
      assert.equal(p.Properties.Value, JSON.stringify(c.environments[environment].approvers));
      assert.doesNotMatch(JSON.stringify(template), /StringLike|\*/);
      assertTemplateScope(`break-glass-repo-${environment}`, template);
    });
  }

  it('the subject uses GitHub\'s spelling; another repository or environment is never rendered', () => {
    const c = repository();
    const lower = renderRepositoryTemplate({ config: c, environment: 'synthetic', fullName: 'acme/payments-api', ...TARGET }).template;
    assert.equal(lower.Resources.InvokerRole.Properties.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'], 'repo:acme/payments-api:pull_request');
    assert.throws(() => renderRepositoryTemplate({ config: c, environment: 'synthetic', fullName: 'acme/other', ...TARGET }));
    assert.throws(() => renderRepositoryTemplate({ config: repository({ environments: { synthetic: { approvers: [] } } }), environment: 'production', fullName: SLUG, ...TARGET }));
  });

  it('the repository kind holds only its role and parameter; other kinds never hold them', () => {
    const { template } = renderRepositoryTemplate({ config: repository(), environment: 'synthetic', fullName: SLUG, ...TARGET });
    const kind = 'break-glass-repo-synthetic';
    const extra = (id, type) => ({ ...template, Resources: { ...template.Resources, [id]: { Type: type, DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain', Properties: {} } } });
    for (const [id, type] of [['Fn', 'AWS::Lambda::Function'], ['Table', 'AWS::DynamoDB::Table'], ['Second', 'AWS::IAM::Role'], ['Policy', 'AWS::IAM::ManagedPolicy']]) assert.throws(() => assertTemplateScope(kind, extra(id, type)), ScopeError, type);
    for (const other of ['break-glass-synthetic', 'break-glass-governance-synthetic', 'repo']) assert.throws(() => assertTemplateScope(other, template), ScopeError, other);
  });
});

describe('repository: the allowlists', () => {
  const body = JSON.stringify({ Resources: {} });
  const cs = (stack, extra = ['--capabilities', 'CAPABILITY_NAMED_IAM']) => ['cloudformation', 'create-change-set', '--stack-name', stack, '--change-set-name', `ssd-plan-${'0'.repeat(64)}`, '--change-set-type', 'CREATE', '--template-body', body, '--tags', JSON.stringify(tagsFor('synthetic')), ...extra];
  it('the repository planner reaches only repository stacks, invoker roles and approver parameters', () => {
    assertRepositoryPlanning(cs(STACK('synthetic')));
    assertRepositoryPlanning(['iam', 'get-role', '--role-name', ROLE('production')]);
    assertRepositoryPlanning(['ssm', 'get-parameter', '--name', PARAM('synthetic')]);
    for (const argv of [
      cs('ssd-break-glass-synthetic'),
      cs('ssd-break-glass-synthetic-governance'),
      cs('ssd-delivery-acme-app-12345678'),
      cs(STACK('synthetic')).map((v) => (v === 'CREATE' ? 'IMPORT' : v)),
      ['iam', 'get-role', '--role-name', 'ssd-break-glass-synthetic-ci-execution'],
      ['iam', 'get-role', '--role-name', 'admin'],
      ['iam', 'create-role', '--role-name', ROLE('synthetic')],
      ['iam', 'put-role-policy', '--role-name', ROLE('synthetic')],
      ['iam', 'simulate-principal-policy', '--policy-source-arn', `arn:aws:iam::${ACCOUNT}:role/${ROLE('synthetic')}`],
      ['ssm', 'get-parameter', '--name', '/ssd/break-glass/synthetic/governance/allowed-framework-shas'],
      ['ssm', 'get-parameter', '--name', `${PARAM('synthetic')}/x`],
      ['ssm', 'get-parameter'],
      ['ssm', 'put-parameter', '--name', PARAM('synthetic')],
      ['secretsmanager', 'describe-secret', '--secret-id', 'ssd/break-glass/synthetic/slack-bot-token'],
      ['lambda', 'get-function-configuration', '--function-name', 'ssd-break-glass-synthetic-ci'],
      ['cloudformation', 'execute-change-set', '--stack-name', STACK('synthetic'), '--change-set-name', 'x']
    ]) refusedBy(assertRepositoryPlanning, argv);
    refusedBy(assertBreakGlassPlanning, cs(STACK('synthetic')));
    refusedBy(assertGovernancePlanning, cs(STACK('synthetic'), []));
  });

  it('repository verify simulates only invoker and execution roles, and reads one approver tier', () => {
    const filter = (v) => JSON.stringify([{ Key: 'Name', Option: 'Equals', Values: v }]);
    assertRepositoryRead(['ssm', 'describe-parameters', '--parameter-filters', filter([PARAM('synthetic')])]);
    assertRepositoryRead(['iam', 'simulate-principal-policy', '--policy-source-arn', `arn:aws:iam::${ACCOUNT}:role/${ROLE('synthetic')}`, '--action-names', '[]', '--resource-arns', '[]']);
    assertRepositoryRead(['iam', 'simulate-principal-policy', '--policy-source-arn', `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-production-interactions-execution`, '--action-names', '[]', '--resource-arns', '[]']);
    for (const argv of [
      ['ssm', 'describe-parameters'],
      ['ssm', 'describe-parameters', '--parameter-filters', filter(['/ssd/break-glass/synthetic/approvers/'])],
      ['ssm', 'describe-parameters', '--parameter-filters', filter([PARAM('synthetic'), PARAM('production')])],
      ['iam', 'simulate-principal-policy', '--policy-source-arn', `arn:aws:iam::${ACCOUNT}:role/admin`, '--action-names', '[]', '--resource-arns', '[]'],
      cs(STACK('synthetic'))
    ]) refusedBy(assertRepositoryRead, argv);
  });

  it('the GitHub identity reader makes exactly two GETs of one repository', () => {
    const e = identityEndpoints(SLUG);
    const check = assertIdentityRead(SLUG);
    check(readArgv(e.repository()));
    check(readArgv(e.oidcSubject()));
    for (const argv of [readArgv('repos/acme/other'), readArgv(`repos/${SLUG}/actions/secrets`), readArgv(`repos/${SLUG}/actions/runs/1/logs`), ['api', '--method', 'PUT', '-H', 'x', '-H', 'y', `repos/${SLUG}/actions/oidc/customization/sub`]]) {
      assert.throws(() => check(argv), (err) => err.kind === 'refused', argv.join(' '));
    }
    assert.throws(() => identityEndpoints('not a slug'), (err) => err.kind === 'refused');
  });

  it('identity discovery: id and full_name, default subject; 404 is absent; anything else unverified', async () => {
    const exec = (routes) => async (argv) => {
      const r = routes[argv[7]];
      if (!r) return { stdout: '{"message":"Not Found","status":"404"}', stderr: 'gh: Not Found (HTTP 404)', exitCode: 1 };
      if (r.error) return { stdout: JSON.stringify(r.error), stderr: `gh: ${r.error.message} (HTTP ${r.error.status})`, exitCode: 1 };
      return { stdout: JSON.stringify(r), stderr: '', exitCode: 0 };
    };
    const good = await discoverRepositoryIdentity({ slug: SLUG, env: {}, exec: exec({ [`repos/${SLUG}`]: { id: 424242, full_name: SLUG }, [`repos/${SLUG}/actions/oidc/customization/sub`]: { use_default: true } }) });
    assert.deepEqual(good, { repository: { state: 'present', value: { id: REPO_ID, fullName: SLUG } }, oidc: { state: 'present', value: { useDefault: true, includeClaimKeys: [] } } });
    const missing = await discoverRepositoryIdentity({ slug: SLUG, env: {}, exec: exec({}) });
    assert.equal(missing.repository.state, 'absent');
    const forbidden = await discoverRepositoryIdentity({ slug: SLUG, env: {}, exec: exec({ [`repos/${SLUG}`]: { id: '424242', full_name: SLUG }, [`repos/${SLUG}/actions/oidc/customization/sub`]: { error: { message: 'Forbidden', status: '403' } } }) });
    assert.equal(forbidden.repository.state, 'unverified', 'a string id is not GitHub\'s numeric id');
    assert.equal(forbidden.oidc.state, 'unverified');
    const noGh = await discoverRepositoryIdentity({ slug: SLUG, env: {}, exec: async () => ({ stdout: '', stderr: '', exitCode: null, error: { code: 'ENOENT' } }) });
    assert.equal(noGh.repository.state, 'unverified');
  });
});

describe('aws plan --scope break-glass-repo', () => {
  it('a framework checkout not bound to framework.ref blocks before GitHub and AWS', async (t) => {
    const { report, f, gh } = await plan(t, greenfieldRepository(), { framework: { ...FRAMEWORK, clean: false, dirtyPaths: ['x'] } });
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(f.calls.length, 0);
    assert.deepEqual(gh.calls, []);
  });

  it('GitHub must prove the repository_id, slug and default subject before AWS is contacted', async (t) => {
    for (const [gh, kind] of [
      [github({ id: '999' }), 'repository-id-mismatch'],
      [github({ fullName: 'Acme/Other' }), 'repository-slug-mismatch'],
      [github({ useDefault: false }), 'oidc-subject-customized'],
      [github({ repository: { state: 'absent', error: { kind: 'not-found', status: 404, message: 'Not Found' } } }), 'repository-unverified'],
      [github({ oidc: { state: 'unverified', error: { kind: 'authorization', status: 403, message: 'Forbidden' } } }), 'oidc-subject-unverified'],
      [null, 'repository-unverified']
    ]) {
      const { report, f, created } = await plan(t, greenfieldRepository(), { gh });
      assert.equal(report.outcome, 'BLOCKED', kind);
      assert.ok(kinds(report.findings).includes(kind), `${kind}: ${JSON.stringify(report.findings)}`);
      assert.equal(f.calls.length, 0, `${kind}: AWS not contacted`);
      assert.equal(created.length, 0);
    }
  });

  it('a repository not configured for the environment is refused', async (t) => {
    await assert.rejects(plan(t, greenfieldRepository('production'), { environment: 'production', config: repository({ environments: { synthetic: { approvers: [] } } }) }), (e) => e.kind === 'environment-not-configured');
  });

  it('synthetic greenfield: one CREATE change set with CAPABILITY_NAMED_IAM, exactly the reviewed role and parameter', async (t) => {
    const { report, unit, created, root } = await plan(t, greenfieldRepository());
    assert.equal(report.outcome, 'PLANNED', JSON.stringify(report.units[0]?.findings ?? report.findings));
    assert.equal(created.length, 1);
    const cs = created[0];
    assert.equal(cs.stackName, STACK('synthetic'));
    assert.equal(cs.type, 'CREATE');
    assert.deepEqual(cs.capabilities, ['CAPABILITY_NAMED_IAM']);
    assert.deepEqual(cs.tags, tagsFor('synthetic'));
    assert.deepEqual(cs.template, renderRepositoryTemplate({ config: repository(), environment: 'synthetic', fullName: SLUG, ...TARGET }).template);
    const planJson = JSON.parse(readFileSync(join(root, planDirOf(unit.planId), 'plan.json'), 'utf8'));
    assert.equal(planJson.stackKind, 'break-glass-repo-synthetic');
    assert.equal(planJson.repository, null);
    assert.deepEqual(planJson.repositoryIdentity, { repositoryId: REPO_ID, fullName: SLUG, subject: SUBJECT, oidcSubject: 'default' });
    const policies = JSON.parse(readFileSync(join(root, planDirOf(unit.planId), 'policies.json'), 'utf8'));
    assert.deepEqual(policies.InvokerRole.trust.after, invokerTrustPolicy({ partition: 'aws', account: ACCOUNT, subject: SUBJECT }));
    assert.deepEqual(checkPlanRecord(await readPlan(root, unit.planId)).findings, []);
  });

  it('production with approvers [] plans, with a WARN (nobody is authorized)', async (t) => {
    const { report, unit } = await plan(t, greenfieldRepository('production'), { environment: 'production' });
    assert.equal(report.outcome, 'PLANNED');
    assert.ok(unit.findings.some((f) => f.severity === 'WARN' && f.kind === 'no-approvers'));
  });

  it('a slug spelled in another case plans with GitHub\'s spelling in the subject (WARN)', async (t) => {
    const { report, unit, created } = await plan(t, greenfieldRepository(), { gh: github({ fullName: 'acme/payments-api' }) });
    assert.equal(report.outcome, 'PLANNED');
    assert.ok(kinds(unit.findings).includes('slug-case'));
    assert.equal(created[0].template.Resources.InvokerRole.Properties.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'], 'repo:acme/payments-api:pull_request');
  });

  it('no OIDC provider, a provider without sts.amazonaws.com, or a shared stack that is not ready blocks', async (t) => {
    for (const [mutate, kind] of [
      [(w) => oidcProvider(w, { present: false }), 'oidc-provider-missing'],
      [(w) => oidcProvider(w, { clientIds: ['sigstore'] }), 'oidc-provider-mismatch'],
      [(w) => sharedStack(w, 'synthetic', { present: false }), 'shared-stack-not-ready'],
      [(w) => sharedStack(w, 'synthetic', { tags: tagsFor('production') }), 'shared-stack-not-ready'],
      [(w) => sharedStack(w, 'synthetic', { status: 'UPDATE_ROLLBACK_FAILED' }), 'shared-stack-not-ready']
    ]) {
      const world = greenfieldRepository();
      mutate(world);
      const { report, created } = await plan(t, world);
      assert.equal(report.outcome, 'BLOCKED', kind);
      assert.ok(kinds(report.units[0].findings).includes(kind), kind);
      assert.equal(created.length, 0);
    }
  });

  it('a role or parameter that merely has the name is never adopted (no stack, another stack, the other environment)', async (t) => {
    for (const kind of ['role', 'parameter']) {
      for (const owner of [null, 'ssd-break-glass-synthetic', STACK('production'), STACK('synthetic', '1')]) {
        const world = existingResource(greenfieldRepository(), 'synthetic', kind, { stackName: owner });
        const { report, created } = await plan(t, world);
        assert.equal(report.outcome, 'BLOCKED', `${kind} ${owner}`);
        assert.ok(kinds(report.units[0].findings).includes('exists-not-owned'), `${kind} ${owner}`);
        assert.equal(created.length, 0);
      }
    }
  });

  it('a role whose ARN differs (a case-variant name) is a collision', async (t) => {
    const world = existingResource(greenfieldRepository(), 'synthetic', 'role', { arn: `arn:aws:iam::${ACCOUNT}:role/SSD-BREAK-GLASS-SYNTHETIC-INVOKER-${REPO_ID}` });
    const { report } = await plan(t, world);
    assert.ok(kinds(report.units[0].findings).includes('role-name-collision'));
  });

  it('a stack of that name tagged for the other environment is never updated', async (t) => {
    const world = withStack(greenfieldRepository(), { name: STACK('synthetic'), tags: tagsFor('production'), resources: [] });
    const { report, created } = await plan(t, world);
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(created.length, 0);
  });
});

describe('aws apply of a repository plan', () => {
  async function planned(t) {
    const r = await plan(t, greenfieldRepository());
    assert.equal(r.report.outcome, 'PLANNED');
    return { root: r.root, planId: r.unit.planId };
  }

  it('applies exactly the reviewed change set once with the two files', async (t) => {
    const p = await planned(t);
    const w = applyWorld({ root: p.root, planId: p.planId });
    const report = await awsApply({ operator: operator(), repository: repository(), planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
    assert.equal(report.outcome, 'APPLIED', JSON.stringify(report.findings));
    assert.equal(mutations(w.fake), 1);
    assert.ok(report.nextSteps.some((s) => s.includes('aws verify --scope break-glass-repo --environment synthetic')));
  });

  it('refuses without the repository file, a changed one, another repository, or a policy file instead', async (t) => {
    const p = await planned(t);
    const { plan: planJson } = await readPlan(p.root, p.planId);
    const intent = (extra) => kinds(checkIntent({ plan: planJson, operator: operator(), framework: FRAMEWORK, account: ACCOUNT, region: REGION, ...extra }));
    assert.deepEqual(intent({ repository: repository() }), []);
    assert.deepEqual(intent({}), ['config-kind-mismatch']);
    assert.deepEqual(intent({ repository: repository({ environments: { synthetic: { approvers: ['U0APPROVER1'] }, production: { approvers: [] } } }) }), ['config-changed']);
    assert.deepEqual(intent({ repository: repository({ repository: { slug: SLUG, id: '424243' } }) }).sort(), ['config-changed', 'stack-mismatch']);
    assert.ok(intent({ repository: repository({ environments: { production: { approvers: [] } } }) }).includes('environment-mismatch'));
    assert.deepEqual(intent({ policy: policy('synthetic', []) }), ['config-kind-mismatch']);
    const w = applyWorld({ root: p.root, planId: p.planId });
    const report = await awsApply({ operator: operator(), planId: p.planId, account: ACCOUNT, region: REGION, yes: true, exec: w.fake.exec, env: {}, framework: FRAMEWORK, root: p.root, sleep: quiet });
    assert.equal(report.outcome, 'REFUSED');
    assert.equal(w.fake.calls.length, 0);
  });

  it('a governance or shared plan is never applied with a repository file', () => {
    for (const [stackKind, stackName] of [['break-glass-governance-synthetic', 'ssd-break-glass-synthetic-governance'], ['break-glass-synthetic', 'ssd-break-glass-synthetic']]) {
      assert.deepEqual(kinds(checkIntent({ plan: { scope: 'break-glass', stackKind, stackName, account: ACCOUNT, region: REGION }, operator: operator(), repository: repository(), framework: FRAMEWORK, account: ACCOUNT, region: REGION })), ['config-kind-mismatch']);
    }
  });
});

describe('aws verify --scope break-glass-repo', () => {
  async function verify(world, { environment = 'synthetic', config = repository(), gh = github() } = {}) {
    const f = fakeAws(world, { allowlist: assertRepositoryRead });
    const report = await awsVerifyBreakGlassRepository({ operator: operator(), repository: config, environment, github: gh, exec: f.exec, env: {} });
    assert.deepEqual(f.unexpected, [], 'no unrecorded AWS call');
    return { report, f, byId: Object.fromEntries(report.checks.map((c) => [c.id, c])) };
  }
  const status = (byId, id) => byId[id]?.status;

  it('synthetic: the deployed stack VERIFIES, with no write call', async () => {
    const { report, f } = await verify(deployedRepository());
    assert.deepEqual(report.checks.filter((c) => c.status !== 'PASS').map((c) => [c.id, c.findings]), []);
    assert.equal(report.outcome, 'VERIFIED');
    assert.ok(!f.operations().some((op) => /^(put|delete|create|update|attach|execute|tag)/.test(op.split(' ')[1])));
  });

  it('production with approvers []: VERIFIED WITH WARNINGS, never a reason to authorize', async () => {
    const { report, byId } = await verify(deployedRepository('production'), { environment: 'production' });
    assert.equal(status(byId, 'bg.repo.approvers'), 'WARN');
    assert.equal(report.outcome, 'VERIFIED_WITH_WARNINGS');
  });

  it('GitHub identity: a changed id or a customized subject FAILs; an unreadable GitHub is NOT VERIFIED (and the trust is not judged)', async () => {
    assert.equal(status((await verify(deployedRepository(), { gh: github({ id: '1' }) })).byId, 'bg.repo.github'), 'FAIL');
    assert.equal(status((await verify(deployedRepository(), { gh: github({ useDefault: false }) })).byId, 'bg.repo.github'), 'FAIL');
    const r = await verify(deployedRepository(), { gh: null });
    assert.equal(status(r.byId, 'bg.repo.github'), 'NOT VERIFIED');
    assert.equal(status(r.byId, 'bg.repo.trust'), 'NOT VERIFIED');
    assert.equal(r.report.outcome, 'NOT_VERIFIED');
  });

  it('trust drift FAILs: broadened, another subject, StringLike', async () => {
    for (const mutate of [
      (w) => { w.__trust.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'] = [SUBJECT, `repo:${SLUG}:ref:refs/heads/main`]; },
      (w) => { w.__trust.Statement[0].Condition = { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' }, StringLike: { 'token.actions.githubusercontent.com:sub': `repo:${SLUG}:*` } }; },
      (w) => { w.__trust.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'] = 'repo:Acme/Other:pull_request'; },
      (w) => { w.__trust.Statement[0].Sid = 'Renamed'; }
    ]) {
      const world = deployedRepository();
      mutate(world);
      assert.equal(status((await verify(world)).byId, 'bg.repo.trust'), 'FAIL');
    }
  });

  it('permission drift FAILs, and the simulator independently catches what it grants', async () => {
    const qualified = deployedRepository();
    qualified.__inline['ssd-break-glass-invoke-ci'].Statement[0].Resource = 'arn:aws:lambda:us-east-1:012345678901:function:ssd-break-glass-*';
    const r1 = await verify(qualified);
    assert.equal(status(r1.byId, 'bg.repo.permissions'), 'FAIL');
    assert.equal(status(r1.byId, 'bg.repo.negative-access'), 'FAIL');
    const extra = deployedRepository();
    extra.__inline['ssd-break-glass-invoke-ci'].Statement.push({ Effect: 'Allow', Action: 'ssm:GetParameter', Resource: '*' });
    assert.equal(status((await verify(extra)).byId, 'bg.repo.negative-access'), 'FAIL');
    const removed = deployedRepository();
    removed.__inline['ssd-break-glass-invoke-ci'].Statement = [];
    assert.equal(status((await verify(removed)).byId, 'bg.repo.invoke'), 'FAIL');
  });

  it('an extra inline or attached policy, or session-duration drift, FAILs the role', async () => {
    const inline = deployedRepository();
    inline.__inline.extra = { Version: '2012-10-17', Statement: [] };
    assert.equal(status((await verify(inline)).byId, 'bg.repo.role'), 'FAIL');
    const attached = deployedRepository();
    attached.__attached.push({ name: 'Admin', arn: 'arn:aws:iam::aws:policy/AdministratorAccess', document: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } });
    const r = await verify(attached);
    assert.equal(status(r.byId, 'bg.repo.role'), 'FAIL');
    assert.equal(status(r.byId, 'bg.repo.negative-access'), 'FAIL');
    const session = deployedRepository();
    session.__role.MaxSessionDuration = 43200;
    assert.equal(status((await verify(session)).byId, 'bg.repo.role'), 'FAIL');
  });

  it('the stack must be ours with exactly its two resources', async () => {
    for (const mutate of [
      (w) => { w.__stack.Tags = tagsFor('production'); },
      (w) => { w.__resources.push({ ...w.__resources[0], LogicalResourceId: 'Extra', ResourceType: 'AWS::Lambda::Function' }); },
      (w) => { w.__resources[1].PhysicalResourceId = PARAM('synthetic', '1'); },
      (w) => { w.__resources.pop(); }
    ]) {
      const world = deployedRepository();
      mutate(world);
      assert.equal(status((await verify(world)).byId, 'bg.repo.stack'), 'FAIL');
    }
  });

  it('approver parameter drift FAILs: value, type, tier, malformed, missing', async () => {
    for (const mutate of [
      (w) => { w.__parameter.Value = '["U0INTRUDER1"]'; },
      (w) => { w.__parameter.Value = '[]'; },
      (w) => { w.__parameter.Value = 'not json'; },
      (w) => { w.__parameter.Type = 'SecureString'; },
      (w) => { w.__tier = 'Advanced'; },
      (w) => { w.__parameter = null; }
    ]) {
      const world = deployedRepository();
      mutate(world);
      assert.equal(status((await verify(world)).byId, 'bg.repo.approvers'), 'FAIL');
    }
  });

  it("approver readers: this environment's interaction role only; an absent other environment holds no access", async () => {
    const ciReads = deployedRepository();
    const ci = `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-synthetic-ci-execution`;
    const original = ciReads.__principals[ci];
    ciReads.__principals[ci] = () => [...original(), { Statement: [{ Effect: 'Allow', Action: 'ssm:GetParameter', Resource: 'arn:aws:ssm:*:*:parameter/ssd/break-glass/*' }] }];
    assert.equal(status((await verify(ciReads)).byId, 'bg.repo.approvers-ci'), 'FAIL');
    const cross = deployedRepository();
    const prodInt = `arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-production-interactions-execution`;
    cross.__principals[prodInt] = () => [{ Statement: [{ Effect: 'Allow', Action: 'ssm:GetParameter', Resource: 'arn:aws:ssm:*:*:parameter/ssd/break-glass/*' }] }];
    assert.equal(status((await verify(cross)).byId, 'bg.repo.approvers-other-environment'), 'FAIL');
    const absent = deployedRepository();
    absent.__absent.push(prodInt);
    const r = await verify(absent);
    assert.equal(status(r.byId, 'bg.repo.approvers-other-environment'), 'PASS');
    assert.equal(r.report.outcome, 'VERIFIED');
    const denied = deployedRepository();
    const simulate = denied['iam simulate-principal-policy *'];
    denied['iam simulate-principal-policy *'] = (argv) => (argv.includes(prodInt) ? { stdout: '', stderr: '\nAn error occurred (AccessDenied) when calling the SimulatePrincipalPolicy operation: no\n', exitCode: 254 } : simulate(argv));
    assert.equal(status((await verify(denied)).byId, 'bg.repo.approvers-other-environment'), 'NOT VERIFIED', 'only NoSuchEntity proves absence');
    const noReader = deployedRepository();
    noReader.__absent.push(`arn:aws:iam::${ACCOUNT}:role/ssd-break-glass-synthetic-interactions-execution`);
    assert.equal(status((await verify(noReader)).byId, 'bg.repo.approvers-reader'), 'NOT VERIFIED');
  });

  it('a repository not configured for the environment is refused before AWS', async () => {
    await assert.rejects(awsVerifyBreakGlassRepository({ operator: operator(), repository: repository({ environments: { synthetic: { approvers: [] } } }), environment: 'production', github: github(), exec: async () => { throw new Error('no AWS'); }, env: {} }), (e) => e.kind === 'configuration');
  });
});

describe('ssd-onboard aws … --scope break-glass-repo (CLI)', () => {
  const files = (t) => {
    const dir = tempDir(t);
    writeFileSync(join(dir, 'break-glass.yml'), OPERATOR_YAML);
    writeFileSync(join(dir, 'repository.yml'), REPOSITORY_YAML);
    writeFileSync(join(dir, 'policy.yml'), 'schemaVersion: "1"\nkind: break-glass-framework-policy\nenvironment: synthetic\nallowedFrameworkShas: []\n');
    return dir;
  };
  const cli = async (args, extra = {}) => {
    const c = capture();
    const code = await main(['aws', ...args], { ...c.io, framework: FRAMEWORK, repositoryIdentity: github(), env: {}, awsSleep: quiet, ...extra });
    return { code, out: c.text(), err: c.errors() };
  };

  it('usage: --repository-config is required for the repo scope and refused elsewhere', async (t) => {
    const dir = files(t);
    const op = join(dir, 'break-glass.yml');
    const repo = join(dir, 'repository.yml');
    const pol = join(dir, 'policy.yml');
    for (const args of [
      ['plan', '--scope', 'break-glass-repo', '--environment', 'synthetic', '--operator-config', op],
      ['plan', '--scope', 'break-glass', '--environment', 'synthetic', '--operator-config', op, '--repository-config', repo],
      ['plan', '--scope', 'break-glass-governance', '--environment', 'synthetic', '--operator-config', op, '--policy-config', pol, '--repository-config', repo],
      ['plan', '--repository-config', repo],
      ['verify', '--scope', 'break-glass-repo', '--operator-config', op, '--repository-config', repo],
      ['apply', '--plan-id', '0'.repeat(64), '--account', ACCOUNT, '--region', REGION, '--repository-config', repo, '--yes'],
      ['apply', '--plan-id', '0'.repeat(64), '--account', ACCOUNT, '--region', REGION, '--operator-config', op, '--repository-config', repo, '--policy-config', pol, '--yes']
    ]) {
      assert.equal((await cli(args)).code, 2, args.join(' '));
    }
  });

  it('plans end to end from the two files, as JSON, with the injected GitHub identity', async (t) => {
    const dir = files(t);
    const f = fakeAws(greenfieldRepository(), { allowlist: assertRepositoryPlanning });
    const gh = github();
    const r = await cli(['plan', '--scope', 'break-glass-repo', '--environment', 'synthetic', '--operator-config', join(dir, 'break-glass.yml'), '--repository-config', join(dir, 'repository.yml'), '--repo', dir, '--json'], { awsExec: f.exec, repositoryIdentity: gh });
    assert.equal(r.code, 0, r.err);
    const report = JSON.parse(r.out);
    assert.equal(report.outcome, 'PLANNED');
    assert.equal(report.units[0].stackName, STACK('synthetic'));
    assert.deepEqual(gh.calls, [SLUG]);
    assert.equal(readdirSync(join(dir, '.ssd', 'aws-plans')).length, 1);
  });

  it('without an injected lookup, the dispatcher supplies the read-only GitHub one (gh is never reached by onboarding/aws)', async (t) => {
    const dir = files(t);
    let awsCalled = false;
    const ghCalls = [];
    const r = await cli(['plan', '--scope', 'break-glass-repo', '--environment', 'synthetic', '--operator-config', join(dir, 'break-glass.yml'), '--repository-config', join(dir, 'repository.yml'), '--repo', dir, '--json'], {
      repositoryIdentity: undefined,
      ghExec: async (argv) => {
        ghCalls.push(argv);
        return { stdout: '', stderr: 'gh: Not Found (HTTP 404)', exitCode: 1 };
      },
      awsExec: async () => {
        awsCalled = true;
        throw new Error('no AWS');
      }
    });
    assert.equal(r.code, 1);
    assert.equal(JSON.parse(r.out).outcome, 'BLOCKED');
    assert.equal(awsCalled, false);
    assert.deepEqual(ghCalls.map((a) => a.slice(0, 3).concat(a.at(-1))), [['api', '--method', 'GET', `repos/${SLUG}`], ['api', '--method', 'GET', `repos/${SLUG}/actions/oidc/customization/sub`]]);
  });
});
