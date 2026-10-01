// Phase 2B rendering: deterministic templates, the repo/shared boundary, IAM
// documents built from (and accepted by) the doctor's own evaluators, the
// registry-scanning merge proposal, and the semantic IAM diff.
import assert from 'node:assert/strict';
import { hostname, userInfo } from 'node:os';
import { describe, it } from 'node:test';

import { mergeScanningRules } from '../onboarding/aws/discover/ecr.mjs';
import { grants, statements } from '../onboarding/aws/policy/evaluate.mjs';
import { diffLines, semanticPolicyDiff } from '../onboarding/aws/policy/diff.mjs';
import { analyzePermissions, rolePolicyDocument } from '../onboarding/aws/policy/permissions.mjs';
import { TrustBuildError, buildTrustPolicy, evaluateTrust, intendedContexts } from '../onboarding/aws/policy/trust.mjs';
import { STACK_KINDS, ScopeError, assertChangeScope, assertTemplateScope } from '../onboarding/aws/plan/scope.mjs';
import { canonicalJson } from '../onboarding/aws/templates/common.mjs';
import { renderRepoTemplate, rolePath } from '../onboarding/aws/templates/repo-ecr-delivery.mjs';
import { renderOidcTemplate } from '../onboarding/aws/templates/shared-github-oidc.mjs';
import { config } from './support/onboarding-fixtures.mjs';
import { MANAGED } from './support/aws-plan-fake.mjs';

const ECR = 'container-ecr-framework-gated';
const ACCOUNT = '012345678901';
const TARGET = { partition: 'aws', account: ACCOUNT, region: 'us-east-1', repository: 'app', instanceId: 'i-0123456789abcdef0' };
const managed = (extra = {}) => config(ECR, { ...MANAGED, delivery: { ...MANAGED.delivery, ...extra } });
const SHARED_TYPES = ['AWS::IAM::OIDCProvider', 'AWS::ECR::RegistryScanningConfiguration', 'AWS::InspectorV2::Filter', 'AWS::Lambda::Function', 'AWS::DynamoDB::Table', 'AWS::SecretsManager::Secret'];
const retainedResource = (type, properties = {}) => ({ Type: type, DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain', Properties: properties });

describe('templates are deterministic', () => {
  it('same config -> byte-identical template; no timestamp, caller, host or user', () => {
    const a = canonicalJson(renderRepoTemplate({ config: managed(), partition: 'aws', enhanced: false }).template);
    const b = canonicalJson(renderRepoTemplate({ config: managed(), partition: 'aws', enhanced: false }).template);
    assert.equal(a, b);
    assert.doesNotMatch(a, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, 'no timestamp');
    for (const incidental of [hostname(), userInfo().username, 'alice', 'assumed-role', 'sts::']) {
      assert.ok(!a.includes(`"${incidental}"`) && !a.includes(`/${incidental}`), incidental);
    }
    assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), canonicalJson({ a: { c: 3, d: 2 }, b: 1 }), 'key order is not meaningful');
  });

  it('a different input changes the bytes', () => {
    const a = canonicalJson(renderRepoTemplate({ config: managed(), partition: 'aws', enhanced: false }).template);
    const b = canonicalJson(renderRepoTemplate({ config: managed({ ssm: { instanceId: 'i-0fedcba9876543210', appPort: '8080', containerName: 'app' } }), partition: 'aws', enhanced: false }).template);
    assert.notEqual(a, b);
  });
});

describe('repo template contents', () => {
  it('every managed resource is tagged and retained; ECR is IMMUTABLE with scan-on-push and no lifecycle policy', () => {
    const { template } = renderRepoTemplate({ config: managed(), partition: 'aws', enhanced: false });
    assert.deepEqual(Object.keys(template.Resources).sort(), ['DeployRole', 'EcrRepository', 'PushScanRole']);
    for (const resource of Object.values(template.Resources)) {
      assert.equal(resource.DeletionPolicy, 'Retain');
      assert.equal(resource.UpdateReplacePolicy, 'Retain');
      assert.deepEqual(Object.fromEntries(resource.Properties.Tags.map((t) => [t.Key, t.Value])), {
        'ssd:framework': 'ssd-security-framework',
        'ssd:managed-by': 'ssd-onboard',
        'ssd:environment': 'production',
        'ssd:consumer-repository': 'acme/app'
      });
    }
    const repo = template.Resources.EcrRepository.Properties;
    assert.equal(repo.ImageTagMutability, 'IMMUTABLE');
    assert.deepEqual(repo.ImageScanningConfiguration, { ScanOnPush: true });
    assert.equal(repo.LifecyclePolicy, undefined, 'no implicit image retention');
    assert.equal(repo.EmptyOnDelete, undefined);
    assertTemplateScope('repo', template);
  });

  it('an existing resource never appears in the template', () => {
    for (const [extra, expected] of [
      [{ ecr: { ownership: 'existing' } }, ['DeployRole', 'PushScanRole']],
      [{ roles: { pushScanOwnership: 'existing', deployOwnership: 'managed' } }, ['DeployRole', 'EcrRepository']],
      [{ roles: { pushScanOwnership: 'managed', deployOwnership: 'existing' } }, ['EcrRepository', 'PushScanRole']],
      [{ ecr: { ownership: 'existing' }, roles: { pushScanOwnership: 'existing', deployOwnership: 'existing' } }, []]
    ]) {
      const { template } = renderRepoTemplate({ config: managed(extra), partition: 'aws', enhanced: false });
      assert.deepEqual(Object.keys(template.Resources).sort(), expected, JSON.stringify(extra));
    }
  });

  it('role name and path come from the configured ARN', () => {
    assert.equal(rolePath(`arn:aws:iam::${ACCOUNT}:role/app`), '/');
    assert.equal(rolePath(`arn:aws:iam::${ACCOUNT}:role/ci/delivery/app`), '/ci/delivery/');
    const { template } = renderRepoTemplate({ config: managed({ roles: { pushScanRoleArn: `arn:aws:iam::${ACCOUNT}:role/ci/app-push`, pushScanOwnership: 'managed', deployOwnership: 'managed' } }), partition: 'aws', enhanced: false });
    assert.equal(template.Resources.PushScanRole.Properties.RoleName, 'app-push');
    assert.equal(template.Resources.PushScanRole.Properties.Path, '/ci/');
  });
});

describe('the repo/shared boundary', () => {
  it('a repo-scope template can never hold a shared resource', () => {
    const { template } = renderRepoTemplate({ config: managed(), partition: 'aws', enhanced: false });
    for (const type of SHARED_TYPES) {
      const bad = { ...template, Resources: { ...template.Resources, Extra: retainedResource(type) } };
      assert.throws(() => assertTemplateScope('repo', bad), ScopeError, type);
      assert.throws(() => assertChangeScope('repo', [{ logicalId: 'Extra', type, action: 'CREATE' }]), ScopeError, type);
    }
    // Even under an allowed logical id.
    assert.throws(() => assertTemplateScope('repo', { ...template, Resources: { EcrRepository: retainedResource('AWS::ECR::RegistryScanningConfiguration') } }), ScopeError);
  });

  it('a shared-scope template can never hold a per-repository resource', () => {
    const { template } = renderOidcTemplate();
    assertTemplateScope('shared-github-oidc', template);
    assert.deepEqual(Object.values(template.Resources).map((r) => r.Type), ['AWS::IAM::OIDCProvider']);
    for (const type of ['AWS::ECR::Repository', 'AWS::IAM::Role']) {
      assert.throws(() => assertTemplateScope('shared-github-oidc', { ...template, Resources: { ...template.Resources, Extra: retainedResource(type) } }), ScopeError);
      assert.throws(() => assertChangeScope('shared-github-oidc', [{ logicalId: 'GitHubOidcProvider', type, action: 'CREATE' }]), ScopeError);
    }
    assert.ok(!Object.hasOwn(STACK_KINDS, 'shared-ecr-scanning'), 'registry scanning has no plannable stack kind in Phase 2B');
  });

  it('refuses templates that could pull in or run anything else, or lose Retain', () => {
    const { template } = renderOidcTemplate();
    for (const key of ['Transform', 'Parameters', 'Conditions', 'Outputs', 'Mappings', 'Metadata']) {
      assert.throws(() => assertTemplateScope('shared-github-oidc', { ...template, [key]: {} }), ScopeError, key);
    }
    const r = template.Resources.GitHubOidcProvider;
    assert.throws(() => assertTemplateScope('shared-github-oidc', { ...template, Resources: { GitHubOidcProvider: { ...r, DeletionPolicy: 'Delete' } } }), ScopeError);
    assert.throws(() => assertTemplateScope('shared-github-oidc', { ...template, Resources: { GitHubOidcProvider: { ...r, UpdateReplacePolicy: undefined } } }), ScopeError);
    assert.throws(() => assertTemplateScope('shared-github-oidc', { ...template, Resources: {} }), ScopeError);
  });
});

describe('generated trust is accepted by the doctor trust evaluator', () => {
  const cases = [
    ['push', { environment: 'production' }, 'ref:refs/heads/main'],
    ['deploy', { environment: 'production' }, 'environment:production'],
    ['deploy', { environment: '' }, 'ref:refs/heads/main']
  ];
  for (const [role, { environment }, context] of cases) {
    it(`${role} (environment '${environment}') -> exact subject repo:acme/app:${context}`, () => {
      const doc = buildTrustPolicy(role, { account: ACCOUNT, slug: 'acme/app', defaultBranch: 'main', environment });
      const contexts = intendedContexts(role, { defaultBranch: 'main', environment });
      const evaluation = evaluateTrust(doc, { account: ACCOUNT, slug: 'acme/app', contexts });
      assert.equal(evaluation.verdict, 'accepted');
      assert.deepEqual(evaluation.subjects.map((s) => s.value), [`repo:acme/app:${context}`]);
      const text = JSON.stringify(doc);
      assert.ok(!text.includes('StringLike'));
      assert.ok(!/[*?]/.test(text), 'no wildcard anywhere');
      assert.deepEqual(doc.Statement[0].Principal, { Federated: `arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com` });
      // The same document does NOT admit another repository, branch, environment or a fork PR.
      for (const other of [
        { slug: 'acme/other', contexts },
        { slug: 'acme/app', contexts: ['ref:refs/heads/dev'] },
        { slug: 'acme/app', contexts: ['environment:staging'] },
        { slug: 'acme/app', contexts: ['pull_request'] }
      ]) {
        assert.equal(evaluateTrust(doc, { account: ACCOUNT, ...other }).verdict, 'rejected', JSON.stringify(other));
      }
    });
  }

  it('the builder refuses a wildcard rather than generate it', () => {
    assert.throws(() => buildTrustPolicy('push', { account: ACCOUNT, slug: 'acme/app', defaultBranch: 'release/*', environment: '' }), TrustBuildError);
    assert.throws(() => buildTrustPolicy('deploy', { account: ACCOUNT, slug: 'acme/app', defaultBranch: 'main', environment: 'prod?' }), TrustBuildError);
  });
});

describe('generated permissions come from roleRequirements and keep the roles separate', () => {
  it('both documents PASS the doctor permission analysis', () => {
    for (const role of ['push', 'deploy']) {
      for (const enhanced of [true, false]) {
        const document = rolePolicyDocument(role, TARGET, { enhanced });
        assert.equal(analyzePermissions(role, TARGET, { policies: [{ name: 'g', document }], complete: true, enhanced }).status, 'PASS', `${role} ${enhanced}`);
      }
    }
  });

  it('push: no SSM, no PassRole, no other repository; deploy: no ECR write, no PassRole, no other instance', () => {
    const push = statements(rolePolicyDocument('push', TARGET, { enhanced: true }));
    const deploy = statements(rolePolicyDocument('deploy', TARGET, { enhanced: false }));
    const instance = `arn:aws:ec2:us-east-1:${ACCOUNT}:instance/i-0123456789abcdef0`;
    const repo = `arn:aws:ecr:us-east-1:${ACCOUNT}:repository/app`;
    for (const [action, resource] of [['ssm:SendCommand', instance], ['ssm:SendCommand', '*'], ['iam:PassRole', '*'], ['ecr:PutImage', `arn:aws:ecr:us-east-1:${ACCOUNT}:repository/other`]]) {
      assert.equal(grants(push, action, resource).decision, 'not-granted', `push ${action} ${resource}`);
    }
    for (const [action, resource] of [['ecr:PutImage', repo], ['ecr:InitiateLayerUpload', repo], ['iam:PassRole', '*'], ['ssm:SendCommand', `arn:aws:ec2:us-east-1:${ACCOUNT}:instance/i-00000000000000000`]]) {
      assert.equal(grants(deploy, action, resource).decision, 'not-granted', `deploy ${action} ${resource}`);
    }
    assert.ok(JSON.stringify(rolePolicyDocument('push', TARGET, { enhanced: true })).includes('inspector2:ListFindings'));
    assert.ok(!JSON.stringify(rolePolicyDocument('push', TARGET, { enhanced: false })).includes('inspector2'));
  });

  it('an undecided scan type or an unknown role is refused', () => {
    assert.throws(() => rolePolicyDocument('push', TARGET, { enhanced: null }));
    assert.throws(() => rolePolicyDocument('instance', TARGET, { enhanced: false }));
  });
});

describe('registry scanning proposal = current rules + required coverage', () => {
  const rule = (frequency, ...filters) => ({ frequency, filters: filters.map((filter) => ({ filter, type: 'WILDCARD' })) });
  const keepsEverything = (before, proposed) => {
    assert.equal(proposed.scanType, before.scanType, 'scan type never changes');
    for (const [i, r] of before.rules.entries()) {
      const after = proposed.rules.find((p) => p.frequency === r.frequency);
      assert.ok(after, `rule ${i + 1} kept`);
      assert.deepEqual(after.filters.slice(0, r.filters.length), r.filters, `rule ${i + 1} filters kept in order`);
    }
  };

  it('already covered by a wildcard rule: no change', () => {
    const scanning = { scanType: 'BASIC', rules: [rule('SCAN_ON_PUSH', 'a*')] };
    assert.equal(mergeScanningRules(scanning, 'app').changed, false);
  });

  it('BASIC: appends to the SCAN_ON_PUSH rule, keeping unrelated filters before and after', () => {
    const scanning = { scanType: 'BASIC', rules: [rule('SCAN_ON_PUSH', 'payments', 'team-*', 'zeta')] };
    const m = mergeScanningRules(scanning, 'app');
    assert.equal(m.changed, true);
    keepsEverything(scanning, m.proposed);
    assert.deepEqual(m.proposed.rules[0].filters.map((f) => f.filter), ['payments', 'team-*', 'zeta', 'app']);
  });

  it('BASIC with only a MANUAL rule: the MANUAL rule is kept and a SCAN_ON_PUSH rule is added', () => {
    const scanning = { scanType: 'BASIC', rules: [rule('MANUAL', '*')] };
    const m = mergeScanningRules(scanning, 'app');
    keepsEverything(scanning, m.proposed);
    assert.deepEqual(m.proposed.rules, [rule('MANUAL', '*'), rule('SCAN_ON_PUSH', 'app')]);
  });

  it('ENHANCED: uses CONTINUOUS_SCAN when there is no SCAN_ON_PUSH rule; never rewrites the type', () => {
    const scanning = { scanType: 'ENHANCED', rules: [rule('CONTINUOUS_SCAN', 'prod-*', 'billing')] };
    const m = mergeScanningRules(scanning, 'app');
    keepsEverything(scanning, m.proposed);
    assert.deepEqual(m.proposed.rules[0].filters.map((f) => f.filter), ['prod-*', 'billing', 'app']);
    const both = { scanType: 'ENHANCED', rules: [rule('CONTINUOUS_SCAN', 'x'), rule('SCAN_ON_PUSH', 'y')] };
    assert.deepEqual(mergeScanningRules(both, 'app').proposed.rules, [rule('CONTINUOUS_SCAN', 'x'), rule('SCAN_ON_PUSH', 'y', 'app')]);
  });

  it('no rules at all: one SCAN_ON_PUSH rule for this repository only', () => {
    assert.deepEqual(mergeScanningRules({ scanType: 'BASIC', rules: [] }, 'app').proposed.rules, [rule('SCAN_ON_PUSH', 'app')]);
  });

  it('never deletes coverage to make room: impossible instead', () => {
    const full = { scanType: 'BASIC', rules: [rule('SCAN_ON_PUSH', ...Array.from({ length: 100 }, (_, i) => `r${i}`))] };
    assert.ok(mergeScanningRules(full, 'app').impossible);
    const twoManual = { scanType: 'BASIC', rules: [rule('MANUAL', 'a'), rule('MANUAL', 'b')] };
    assert.ok(mergeScanningRules(twoManual, 'app').impossible);
    assert.ok(mergeScanningRules({ scanType: null, rules: [] }, 'app').impossible);
  });
});

describe('semantic IAM diff', () => {
  const trust = (sub, operator = 'StringEquals', principal = `arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com`) => ({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { Federated: principal }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { [operator]: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com', 'token.actions.githubusercontent.com:sub': sub } } }]
  });

  it('key order, statement order, Sids and string-vs-array are not changes', () => {
    const a = { Version: '2012-10-17', Statement: [{ Sid: 'A', Effect: 'Allow', Action: 'ecr:PutImage', Resource: 'r1' }, { Effect: 'Allow', Action: ['s3:GetObject'], Resource: ['r2'] }] };
    const b = { Statement: [{ Resource: ['r2'], Action: 's3:GetObject', Effect: 'Allow' }, { Resource: 'r1', Effect: 'Allow', Action: ['ECR:PutImage'], Sid: 'B' }], Version: '2012-10-17' };
    assert.equal(semanticPolicyDiff(a, b).changed, false);
  });

  it('subject, operator, audience and principal changes are each visible', () => {
    const before = trust('repo:acme/app:ref:refs/heads/main');
    const subject = semanticPolicyDiff(before, trust('repo:acme/app:environment:production'));
    assert.deepEqual(subject.dimensions.subjects, { added: ['Allow StringEquals repo:acme/app:environment:production'], removed: ['Allow StringEquals repo:acme/app:ref:refs/heads/main'] });
    const operator = semanticPolicyDiff(before, trust('repo:acme/app:ref:refs/heads/main', 'StringLike'));
    assert.ok(operator.dimensions.subjects.added.some((s) => s.startsWith('Allow StringLike')));
    const principal = semanticPolicyDiff(before, trust('repo:acme/app:ref:refs/heads/main', 'StringEquals', 'arn:aws:iam::999999999999:oidc-provider/x'));
    assert.equal(principal.dimensions.principals.added.length, 1);
    assert.equal(principal.dimensions.principals.removed.length, 1);
    assert.ok(diffLines(subject).includes('+ subject Allow StringEquals repo:acme/app:environment:production'));
  });

  it('an action moving to a wider resource is shown even when the action and resource sets are unchanged', () => {
    const before = { Statement: [{ Effect: 'Allow', Action: 'ecr:GetAuthorizationToken', Resource: '*' }, { Effect: 'Allow', Action: 'ecr:PutImage', Resource: 'repo-arn' }, { Effect: 'Allow', Action: 'ecr:BatchGetImage', Resource: 'repo-arn' }] };
    const after = { Statement: [{ Effect: 'Allow', Action: ['ecr:GetAuthorizationToken', 'ecr:PutImage'], Resource: '*' }, { Effect: 'Allow', Action: 'ecr:BatchGetImage', Resource: 'repo-arn' }] };
    const d = semanticPolicyDiff(before, after);
    assert.equal(d.changed, true);
    assert.deepEqual(d.dimensions.actions, { added: [], removed: [] });
    assert.deepEqual(d.dimensions.resources, { added: [], removed: [] });
    assert.deepEqual(diffLines(d), ['- grant Allow ecr:putimage on repo-arn', '+ grant Allow ecr:putimage on *']);
  });

  it('a new document is everything added, shown as grants', () => {
    const d = semanticPolicyDiff(null, { Statement: [{ Effect: 'Allow', Action: 'ssm:SendCommand', Resource: 'i-arn' }] });
    assert.equal(d.created, true);
    assert.deepEqual(diffLines(d), ['+ grant Allow ssm:sendcommand on i-arn']);
  });
});
