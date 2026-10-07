// Phase 3C: the break-glass execution-role contract, analysed offline
// (policy/break-glass.mjs over policy/evaluate.mjs). The generated documents
// must PASS; every broadening, removal or cross-environment grant must FAIL.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { breakGlassArns } from '../onboarding/aws/break-glass/names.mjs';
import { analyzeExecutionRole, executionProbes, executionRequirements, executionRolePolicy, executionTrustPolicy, trustProblems, wildcardProblems } from '../onboarding/aws/policy/break-glass.mjs';
import { grants, statements } from '../onboarding/aws/policy/evaluate.mjs';
import { TARGET } from './support/break-glass-fake.mjs';

const analyze = (role, env, document) => analyzeExecutionRole(role, env, TARGET, { policies: [{ name: 'inline:p', kind: 'inline', document }], complete: true });
const kinds = (a) => a.findings.map((f) => f.kind);
const clone = (v) => JSON.parse(JSON.stringify(v));
const decision = (document, action, resource) => grants(statements(document), action, resource).decision;

describe('the generated execution policies pass their own contract', () => {
  for (const env of ['production', 'synthetic']) {
    for (const role of ['ci', 'interactions']) {
      it(`${env} ${role}`, () => {
        const a = analyze(role, env, executionRolePolicy(role, env, TARGET));
        assert.equal(a.status, 'PASS', JSON.stringify(a.findings));
        assert.ok(a.required.every((r) => r.decision === 'allowed'));
      });
    }
  }

  it('the CI role is granted dynamodb:PutItem on its own table and nothing else of the table family beyond Get/Update/Delete', () => {
    for (const env of ['production', 'synthetic']) {
      const doc = executionRolePolicy('ci', env, TARGET);
      const own = breakGlassArns(env, TARGET).table;
      const other = breakGlassArns(env === 'production' ? 'synthetic' : 'production', TARGET).table;
      assert.equal(decision(doc, 'dynamodb:PutItem', own), 'allowed');
      assert.equal(decision(doc, 'dynamodb:PutItem', other), 'not-granted');
      for (const action of ['dynamodb:Scan', 'dynamodb:Query', 'dynamodb:DeleteTable', 'dynamodb:UpdateTimeToLive']) {
        assert.equal(decision(doc, action, own), 'not-granted', action);
      }
    }
  });

  it('PutItem is a REQUIRED probe of the CI role and a FORBIDDEN one on the other environment', () => {
    const req = executionRequirements('ci', 'production', TARGET);
    assert.ok(req.required.some((r) => r.action === 'dynamodb:PutItem' && r.resource === breakGlassArns('production', TARGET).table));
    assert.ok(req.forbidden.some((r) => r.action === 'dynamodb:PutItem' && r.resource === breakGlassArns('synthetic', TARGET).table && r.severity === 'FAIL'));
    const synth = executionRequirements('ci', 'synthetic', TARGET);
    assert.ok(synth.forbidden.some((r) => r.action === 'dynamodb:PutItem' && r.resource === breakGlassArns('production', TARGET).table));
    assert.deepEqual(executionProbes('ci', 'production', TARGET).required, req.required);
  });
});

describe('negative policies FAIL the offline analysis', () => {
  const ci = () => clone(executionRolePolicy('ci', 'production', TARGET));
  const interactions = () => clone(executionRolePolicy('interactions', 'production', TARGET));
  const prod = breakGlassArns('production', TARGET);
  const synth = breakGlassArns('synthetic', TARGET);

  it('deleting dynamodb:PutItem', () => {
    const doc = ci();
    doc.Statement[0].Action = doc.Statement[0].Action.filter((a) => a !== 'dynamodb:PutItem');
    const a = analyze('ci', 'production', doc);
    assert.equal(a.status, 'FAIL');
    assert.ok(a.findings.some((f) => f.kind === 'permission-missing' && f.message.includes('dynamodb:PutItem')));
  });

  it('broadening the DynamoDB resource to *', () => {
    const doc = ci();
    doc.Statement[0].Resource = '*';
    const a = analyze('ci', 'production', doc);
    assert.equal(a.status, 'FAIL');
    assert.ok(kinds(a).includes('wildcard-resource'));
    assert.ok(kinds(a).includes('permission-too-broad'), 'the synthetic table becomes writable');
  });

  it('a production role granted the synthetic table, secrets, approvers or functions', () => {
    for (const [what, mutate] of [
      ['table', (d) => (d.Statement[0].Resource = [prod.table, synth.table])],
      ['secret', (d) => (d.Statement[1].Resource = [d.Statement[1].Resource].flat().concat(synth.secretPatterns.slackBotToken))],
      ['approvers', (d) => d.Statement.push({ Effect: 'Allow', Action: 'ssm:GetParameter', Resource: synth.approverParameters })],
      ['function', (d) => d.Statement.push({ Effect: 'Allow', Action: 'lambda:InvokeFunction', Resource: synth.functions.ci })]
    ]) {
      const doc = interactions();
      mutate(doc);
      const a = analyze('interactions', 'production', doc);
      assert.equal(a.status, 'FAIL', what);
      assert.ok(a.findings.some((f) => f.kind === 'permission-too-broad' && f.message.includes('synthetic')), `${what}: ${JSON.stringify(a.findings)}`);
    }
  });

  it('an action wildcard, NotAction, or an administrator statement', () => {
    for (const extra of [
      { Effect: 'Allow', Action: 'dynamodb:*', Resource: prod.table },
      { Effect: 'Allow', NotAction: 'iam:*', Resource: prod.table },
      { Effect: 'Allow', Action: '*', Resource: '*' }
    ]) {
      const doc = ci();
      doc.Statement.push(extra);
      assert.equal(analyze('ci', 'production', doc).status, 'FAIL', JSON.stringify(extra));
    }
  });

  it('the interaction role given PutItem / DeleteItem, or the CI role given the signing secret', () => {
    const i = interactions();
    i.Statement[0].Action.push('dynamodb:PutItem');
    assert.ok(analyze('interactions', 'production', i).findings.some((f) => f.kind === 'permission-too-broad' && f.message.includes('dynamodb:PutItem')));
    const c = ci();
    c.Statement[1].Resource = [c.Statement[1].Resource, prod.secretPatterns.slackSigningSecret];
    assert.ok(analyze('ci', 'production', c).findings.some((f) => f.kind === 'permission-too-broad' && f.message.includes('slack-signing-secret')));
  });

  it('the approver path broadened beyond /approvers/*', () => {
    const doc = interactions();
    doc.Statement.find((s) => s.Action === 'ssm:GetParameter').Resource = `arn:aws:ssm:${TARGET.region}:${TARGET.account}:parameter/ssd/break-glass/*`;
    const a = analyze('interactions', 'production', doc);
    assert.equal(a.status, 'FAIL');
    assert.ok(kinds(a).includes('wildcard-resource'));
  });

  it('wildcardProblems accepts exactly the documented patterns', () => {
    assert.deepEqual(wildcardProblems([{ name: 'p', document: executionRolePolicy('interactions', 'synthetic', TARGET) }], 'interactions', 'synthetic', TARGET), []);
  });
});

describe('trust: lambda.amazonaws.com only', () => {
  it('accepts the generated trust policy', () => {
    assert.deepEqual(trustProblems(executionTrustPolicy()), []);
    assert.deepEqual(trustProblems(encodeURIComponent(JSON.stringify(executionTrustPolicy()))), []);
  });

  it('refuses any other principal or an extra statement', () => {
    for (const doc of [
      { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }] },
      { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: ['lambda.amazonaws.com', 'ec2.amazonaws.com'] }, Action: 'sts:AssumeRole' }] },
      { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111111111111:root' }, Action: 'sts:AssumeRole' }] },
      { Version: '2012-10-17', Statement: [executionTrustPolicy().Statement[0], { Effect: 'Allow', Principal: { Federated: 'x' }, Action: 'sts:AssumeRoleWithWebIdentity' }] }
    ]) {
      assert.ok(trustProblems(doc).length > 0, JSON.stringify(doc));
    }
  });
});

// A grant with no caller is unexplained privilege. These tie each least-obvious
// permission to the exact broker code that uses it (read from source, so a
// broker change that drops the call fails here and the grant must be revisited).
describe('every granted action has a runtime call site', () => {
  const src = (f) => readFileSync(`broker/lambda/${f}`, 'utf8');
  const notifyBody = () => {
    const b = src('broker.mjs');
    const start = b.indexOf('async function notify(');
    return b.slice(start, b.indexOf('\n  async function ', start + 1));
  };

  it('CI dynamodb:DeleteItem: ciHandler -> broker.notify -> store.deletePending -> DeleteItem', () => {
    assert.match(src('handlers.mjs'), /if \(event\?\.action === 'notify'\) return broker\.notify\(/, 'the CI handler routes notify');
    assert.match(notifyBody(), /await store\.deletePending\(request\.requestId\)/, 'notify rolls back with deletePending');
    assert.match(src('dynamodb-store.mjs'), /deletePending: \(requestId\) =>\n\s+conditional\('DeleteItem',/, 'deletePending is a conditional DeleteItem');
    const ci = executionRolePolicy('ci', 'production', TARGET);
    assert.equal(decision(ci, 'dynamodb:DeleteItem', breakGlassArns('production', TARGET).table), 'allowed');
    const interactions = executionRolePolicy('interactions', 'production', TARGET);
    assert.equal(decision(interactions, 'dynamodb:DeleteItem', breakGlassArns('production', TARGET).table), 'not-granted', 'the interaction function has no DeleteItem consumer');
  });

  it('interaction lambda:InvokeFunction on ITSELF: interactionsHandler -> enqueue -> enqueueSelf -> InvokeCommand(AWS_LAMBDA_FUNCTION_NAME)', () => {
    assert.match(src('index.mjs'), /interactionsHandler = createInteractionsHandler\(\{[\s\S]*enqueue: \(job\) => enqueueSelf\(job\)/, 'the interaction handler is wired to enqueueSelf');
    assert.match(src('handlers.mjs'), /await enqueue\(result\.followUp\)/, 'the follow-up is enqueued');
    assert.match(src('runtime.mjs'), /new lambda\.InvokeCommand\(\{\s+FunctionName: env\.AWS_LAMBDA_FUNCTION_NAME,\s+InvocationType: 'Event'/, 'enqueueSelf invokes its own function, asynchronously');
    const a = breakGlassArns('production', TARGET);
    const interactions = executionRolePolicy('interactions', 'production', TARGET);
    assert.equal(decision(interactions, 'lambda:InvokeFunction', a.functions.interactions), 'allowed');
    assert.equal(decision(interactions, 'lambda:InvokeFunction', a.functions.ci), 'not-granted', 'only itself');
    const ci = executionRolePolicy('ci', 'production', TARGET);
    assert.ok(!statements(ci).some((st) => st.actions.includes('lambda:InvokeFunction')), 'the CI broker has no InvokeFunction consumer');
    assert.doesNotMatch(src('runtime.mjs').replace(/export async function enqueueSelf[\s\S]*$/, ''), /InvokeCommand/, 'enqueueSelf is the only invoke');
  });
});
