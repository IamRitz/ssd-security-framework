// The offline GitHub OIDC trust evaluator (onboarding/aws/policy/trust.mjs).
// "The policy mentions GitHub" is never proof: every trust path must be bounded
// to this repository and the role's intended context, with aud = sts.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { classifySubject, evaluateTrust, intendedContexts, providerArn } from '../onboarding/aws/policy/trust.mjs';
import { ACCOUNT, PROVIDER, SLUG, trustPolicy } from './support/aws-fake.mjs';

const MAIN = ['ref:refs/heads/main'];
const PROD = ['environment:production'];
const evaluate = (document, contexts = MAIN) => evaluateTrust(document, { account: ACCOUNT, slug: SLUG, contexts });
const kinds = (result) => result.findings.map((f) => f.kind);
const fails = (result) => result.findings.filter((f) => f.severity === 'FAIL').map((f) => f.kind);

describe('intended contexts', () => {
  it('push+scan: the default branch only; deploy: the configured environment', () => {
    assert.deepEqual(intendedContexts('push', { defaultBranch: 'main', environment: 'production' }), MAIN);
    assert.deepEqual(intendedContexts('deploy', { defaultBranch: 'main', environment: 'production' }), PROD);
    assert.deepEqual(intendedContexts('deploy', { defaultBranch: 'main', environment: '' }), MAIN);
  });

  it('the expected provider ARN is exact', () => {
    assert.equal(providerArn(ACCOUNT), PROVIDER);
  });
});

describe('trust evaluation', () => {
  it('exact repository + branch with StringEquals is accepted', () => {
    const result = evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] }));
    assert.equal(result.verdict, 'accepted');
    assert.deepEqual(result.findings, []);
    assert.equal(result.format, 'legacy');
    assert.equal(result.reachable, true);
  });

  it('exact environment subject is accepted for the deploy context', () => {
    assert.equal(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:environment:production`] }), PROD).verdict, 'accepted');
  });

  it('another repository is rejected', () => {
    const result = evaluate(trustPolicy({ subjects: ['repo:acme/other:ref:refs/heads/main'] }));
    assert.equal(result.verdict, 'rejected');
    assert.ok(fails(result).includes('wrong-repository'));
  });

  it('an extra subject for another repository is rejected even beside the right one', () => {
    const result = evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`, 'repo:evil/app:ref:refs/heads/main'] }));
    assert.equal(result.verdict, 'rejected');
    assert.ok(fails(result).includes('wrong-repository'));
  });

  it('another branch, a pull_request, another environment, a tag are rejected', () => {
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/dev`] }))).includes('wrong-branch'));
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:pull_request`] }))).includes('pull-request-context'));
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:environment:staging`] }), PROD)).includes('wrong-environment'));
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/tags/v1`] }))).includes('wrong-context'));
    // The deploy role must not trust the push context when an environment is configured.
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] }), PROD)).includes('wrong-branch'));
  });

  it('wildcard subjects are rejected: repository-wide, organization-wide, anything', () => {
    const repoWide = evaluate(trustPolicy({ operator: 'StringLike', subjects: [`repo:${SLUG}:*`] }));
    assert.equal(repoWide.verdict, 'rejected');
    assert.ok(fails(repoWide).includes('wildcard-subject'));
    assert.ok(fails(evaluate(trustPolicy({ operator: 'StringLike', subjects: ['repo:acme/*'] }))).includes('organization-wide'));
    assert.ok(fails(evaluate(trustPolicy({ operator: 'StringLike', subjects: ['*'] }))).includes('any-repository'));
    assert.ok(fails(evaluate(trustPolicy({ operator: 'StringLike', subjects: [`repo:${SLUG}:ref:refs/heads/mai?`] }))).includes('wildcard-subject'));
    assert.ok(fails(evaluate(trustPolicy({ operator: 'StringLike', subjects: [`repo:${SLUG}:ref:refs/heads/main*`] }))).includes('wildcard-subject'));
  });

  it('StringLike with an exact value is equivalent but WARNs (StringEquals is expected)', () => {
    const result = evaluate(trustPolicy({ operator: 'StringLike', subjects: [`repo:${SLUG}:ref:refs/heads/main`] }));
    assert.equal(result.verdict, 'accepted-with-warnings');
    assert.ok(kinds(result).includes('stringlike-exact'));
  });

  it('a wrong or missing audience is rejected', () => {
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], audience: ['https://github.com/acme'] }))).includes('wrong-audience'));
    assert.ok(fails(evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], audience: ['sts.amazonaws.com', 'other'] }))).includes('wrong-audience'));
    const noAud = trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] });
    delete noAud.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:aud'];
    assert.ok(fails(evaluate(noAud)).includes('audience-unconstrained'));
  });

  it('a missing subject condition is rejected: any GitHub repository could assume', () => {
    const doc = trustPolicy({ subjects: ['x'] });
    delete doc.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'];
    assert.ok(fails(evaluate(doc)).includes('subject-unconstrained'));
  });

  it('a wrong provider is rejected, and an unrelated provider is not proof of GitHub trust', () => {
    const other = `arn:aws:iam::${ACCOUNT}:oidc-provider/gitlab.example.com`;
    const result = evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], provider: other }));
    assert.ok(fails(result).includes('wrong-provider'));
    assert.ok(fails(result).includes('no-github-trust'));
    const otherAccount = evaluate(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], provider: PROVIDER.replace(ACCOUNT, '999999999999') }));
    assert.ok(fails(otherAccount).includes('wrong-provider'));
  });

  it('unsupported conditions and constructs fail conservatively', () => {
    const notEquals = trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], extra: { StringNotEquals: { 'token.actions.githubusercontent.com:sub': 'repo:x/y:ref:refs/heads/main' } } });
    assert.ok(fails(evaluate(notEquals)).includes('unsupported-condition'));
    const forAny = trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], extra: { 'ForAnyValue:StringLike': { 'token.actions.githubusercontent.com:sub': '*' } } });
    assert.ok(fails(evaluate(forAny)).includes('unsupported-condition'));
    const ifExists = trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], extra: { StringEqualsIfExists: { 'token.actions.githubusercontent.com:sub': 'x' } } });
    assert.ok(fails(evaluate(ifExists)).includes('unsupported-condition'));
    const notPrincipal = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', NotPrincipal: { AWS: 'x' }, Action: 'sts:AssumeRole' }] };
    assert.ok(fails(evaluate(notPrincipal)).includes('unsupported-construct'));
  });

  it('extra principals: "*" and cross-account FAIL, same-account WARN', () => {
    const doc = trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] });
    const withAny = structuredClone(doc);
    withAny.Statement.push({ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' });
    assert.ok(fails(evaluate(withAny)).includes('any-principal'));
    const cross = structuredClone(doc);
    cross.Statement.push({ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' });
    assert.ok(fails(evaluate(cross)).includes('cross-account-principal'));
    const same = structuredClone(doc);
    same.Statement.push({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${ACCOUNT}:role/admin` }, Action: 'sts:AssumeRole' });
    const sameResult = evaluate(same);
    assert.equal(sameResult.verdict, 'accepted-with-warnings');
    assert.ok(kinds(sameResult).includes('additional-principal'));
  });

  it('a malformed document is rejected, and a URL-encoded one is read', () => {
    assert.equal(evaluate('{not json').verdict, 'rejected');
    assert.equal(evaluate(encodeURIComponent(JSON.stringify(trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`] })))).verdict, 'accepted');
  });

  it('the immutable subject format is accepted only with an unverified-IDs warning', () => {
    const result = evaluate(trustPolicy({ subjects: ['repo:acme@123/app@456:ref:refs/heads/main'] }));
    assert.equal(result.verdict, 'accepted-with-warnings');
    assert.equal(result.format, 'immutable');
    assert.ok(kinds(result).includes('immutable-ids-unverified'));
    assert.ok(fails(evaluate(trustPolicy({ subjects: ['repo:evil@123/app@456:ref:refs/heads/main'] }))).includes('wrong-repository'));
  });

  it('a narrowing extra condition is not evaluated but cannot widen', () => {
    const doc = trustPolicy({ subjects: [`repo:${SLUG}:ref:refs/heads/main`], extra: { StringLike: { 'token.actions.githubusercontent.com:job_workflow_ref': 'acme/app/.github/workflows/deploy.yml@*' } } });
    const result = evaluate(doc);
    assert.equal(result.verdict, 'accepted-with-warnings');
    assert.ok(kinds(result).includes('condition-not-evaluated'));
  });
});

describe('subject classification', () => {
  it('case-only difference WARNs, any other difference FAILs', () => {
    assert.deepEqual(classifySubject('repo:Acme/App:ref:refs/heads/main', { slug: SLUG, contexts: MAIN }).findings.map((f) => f.severity), ['WARN']);
    assert.equal(classifySubject('repo:acme/app-evil:ref:refs/heads/main', { slug: SLUG, contexts: MAIN }).expected, false);
    assert.equal(classifySubject('not-a-subject', { slug: SLUG, contexts: MAIN }).expected, false);
  });
});
