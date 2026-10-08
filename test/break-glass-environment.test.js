// Phase 3E broker-side environment binding
// (docs/break-glass-validation.md § Environment binding).
//
// The client's isolation compares identifiers the CALLER supplies, so on its
// own it cannot establish which environment the receiving broker serves. The
// framework therefore derives the request's environment from its validated gate
// evidence, and the broker refuses one that is not its own
// BREAK_GLASS_ENVIRONMENT before anything is verified or written. A misrouting
// defence, not an approval control.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { buildApprovalMessage, buildDecisionUpdate } from '../broker/messages.mjs';
import { notifyBreakGlass, requestEnvironment } from '../security/scripts/break-glass-notify.mjs';
import { brokerEnv, fileRequest, payloadFor, signedClick } from './support/broker-env.mjs';
import { SLACK_A, approversById } from './support/fake-approvers.mjs';
import { REPO_A, SHA_A } from './support/jwt-fixtures.mjs';

const OTHER = { production: 'synthetic', synthetic: 'production' };
const FINDING = { source: 'semgrep', id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' };
const gateFor = (active) => ({ verdict: 'BLOCK', synthetic: { active, fixture: active ? 'sast' : null }, breakGlass: { eligible: true, eligibleFindings: [FINDING], ineligibleFindings: [] } });

// Nothing written: no replay record, no request, nobody paged, no token verified.
function assertNothingHappened(env, events) {
  assert.equal(env.tokenRecords().length, 0, 'the token is not spent');
  assert.equal(env.requests().length, 0, 'no request is stored');
  assert.equal(env.slack.posted.length, 0, 'nobody is paged');
  assert.ok(!events.includes('verify') && !events.includes('policy'), 'refused before the token or the framework policy is read');
}
const broker = (environment, options = {}) => {
  const events = [];
  const env = brokerEnv({ environment, events, approvers: approversById({ [REPO_A.repositoryId]: [SLACK_A] }, { environment }), ...options });
  return { env, events };
};

describe('broker: a request must be of this broker\'s environment', () => {
  for (const environment of ['production', 'synthetic']) {
    it(`a ${environment} broker accepts a ${environment} request and stores its environment`, async () => {
      const { env } = broker(environment);
      const requestId = await fileRequest(env, { environment });
      const stored = JSON.parse(env.requests()[0].doc.S);
      assert.deepEqual([stored.requestId, stored.environment], [requestId, environment]);
    });

    it(`a ${OTHER[environment]} request sent to the ${environment} broker is refused, and nothing is written`, async () => {
      const { env, events } = broker(environment);
      const result = await env.notify(payloadFor(REPO_A, { environment: OTHER[environment] }), env.tokenFor());
      assert.deepEqual([result.statusCode, result.error], [403, 'environment_mismatch']);
      assertNothingHappened(env, events);
      assert.deepEqual(env.logs.at(-1), { event: 'environment_rejected', reason: 'mismatch', requested: OTHER[environment], environment });
    });
  }

  for (const [name, value] of [
    ['omitted', undefined],
    ['empty', ''],
    ['differently spelled', 'Production'],
    ['an unknown environment', 'staging'],
    ['null', null],
    ['an array', ['synthetic']],
    ['an object', { environment: 'production' }]
  ]) {
    it(`an ${name} request environment is refused (400), and nothing is written`, async () => {
      const { env, events } = broker('production');
      const payload = payloadFor(REPO_A);
      if (value === undefined) delete payload.environment;
      else payload.environment = value;
      const result = await env.notify(payload, env.tokenFor());
      assert.deepEqual([result.statusCode, result.error], [400, 'invalid request environment']);
      assertNothingHappened(env, events);
    });
  }

  for (const [name, value] of [['no', undefined], ['an invalid', 'prod']]) {
    it(`a broker with ${name} BREAK_GLASS_ENVIRONMENT refuses every request`, async () => {
      const { env, events } = broker('production', { brokerEnvironment: value });
      for (const environment of ['production', 'synthetic']) {
        const result = await env.notify(payloadFor(REPO_A, { environment }), env.tokenFor());
        assert.deepEqual([result.statusCode, result.error], [500, 'environment_misconfigured']);
      }
      assertNothingHappened(env, events);
    });
  }
});

describe('broker: status and clicks act only on a request of this environment', () => {
  // A stored request that records another environment (or none) cannot come
  // from this broker; it stands for any request the binding must not serve.
  function restamp(env, requestId, environment) {
    const item = env.dynamo.table.get(requestId);
    const doc = JSON.parse(item.doc.S);
    if (environment === undefined) delete doc.environment;
    else doc.environment = environment;
    env.dynamo.table.set(requestId, { ...item, doc: { S: JSON.stringify(doc) } });
  }

  for (const [name, stamp] of [['another environment', 'synthetic'], ['no environment', undefined]]) {
    it(`status of a request recording ${name} is refused`, async () => {
      const { env } = broker('production');
      const requestId = await fileRequest(env);
      assert.equal((await env.status(requestId, env.tokenFor({ runId: '700001' }))).statusCode, 200, 'fixture sanity');
      restamp(env, requestId, stamp);
      const result = await env.status(requestId, env.tokenFor({ runId: '700001' }));
      assert.deepEqual([result.statusCode, result.error], [403, 'request_environment_mismatch']);
    });

    it(`a click on a request recording ${name} is rejected with no lookup and no state change`, async () => {
      const { env } = broker('production');
      const requestId = await fileRequest(env);
      restamp(env, requestId, stamp);
      env.approvers.requested.length = 0;
      const response = await env.interactions(signedClick(requestId, SLACK_A));
      assert.equal(response.headers['x-break-glass-outcome'], 'rejected');
      assert.equal(env.approvers.requested.length, 0, 'no approver lookup');
      assert.equal(JSON.parse(env.dynamo.table.get(requestId).doc.S).status, 'pending');
      assert.ok(!env.enqueued.some((job) => job.kind === 'side-effects'));
    });
  }
});

describe('Slack: a synthetic request says so first', () => {
  it('the synthetic approval message and decision update are labelled; production ones are not', async () => {
    const { env } = broker('synthetic');
    const requestId = await fileRequest(env);
    const [message] = env.slack.posted;
    assert.match(message.text, /^\[SYNTHETIC\] /);
    assert.match(message.blocks[0].text.text, /^\[SYNTHETIC\] /);
    assert.match(message.blocks[1].elements[0].text, /Synthetic test request.*Not a production approval/);
    await env.interactions(signedClick(requestId, SLACK_A));
    const decided = JSON.parse(env.requests()[0].doc.S);
    assert.match(buildDecisionUpdate(decided).blocks[0].text.text, /^\*\[SYNTHETIC\] Break-glass APPROVED\*/);

    const { env: prod } = broker('production');
    await fileRequest(prod);
    assert.ok(!JSON.stringify(prod.slack.posted).includes('SYNTHETIC'), 'production is never labelled synthetic');
  });

  it('the label follows the stored environment only', () => {
    const request = { requestId: 'r', environment: 'production', findings: [FINDING], context: { repository: 'a/b', pullRequest: '1', commitSha: SHA_A }, expiresAt: 'e' };
    assert.ok(!buildApprovalMessage(request, 'C').text.includes('SYNTHETIC'));
    assert.ok(buildApprovalMessage({ ...request, environment: 'synthetic' }, 'C').text.startsWith('[SYNTHETIC]'));
  });
});

describe('client: the environment is derived from the gate evidence, never chosen', () => {
  it('a recorded fixture is synthetic; a recorded absence is production', () => {
    assert.equal(requestEnvironment(gateFor(true)), 'synthetic');
    assert.equal(requestEnvironment(gateFor(false)), 'production');
  });

  for (const [name, synthetic] of [['no record', undefined], ['a string', { active: 'true' }], ['null', null]]) {
    it(`evidence with ${name} refuses before any call`, async () => {
      let invoked = 0;
      const gate = { ...gateFor(false), synthetic };
      assert.throws(() => requestEnvironment(gate), /does not record whether it is synthetic/);
      await assert.rejects(
        notifyBreakGlass({ gate, context: { repository: 'a/b', commitSha: SHA_A }, invoke: async () => { invoked += 1; }, mintIdentityToken: async () => 't' }),
        /does not record whether it is synthetic/
      );
      assert.equal(invoked, 0);
    });
  }

  for (const active of [true, false]) {
    const environment = active ? 'synthetic' : 'production';
    it(`the Lambda payload names ${environment} for ${active ? 'synthetic' : 'production'} evidence`, async () => {
      const sent = [];
      const invoke = async (event) => {
        sent.push(event);
        return { ok: true, body: { requestId: 'r-1', status: 'pending' } };
      };
      await notifyBreakGlass({ gate: gateFor(active), context: { repository: 'a/b', commitSha: SHA_A }, invoke, mintIdentityToken: async () => 't', route: environment });
      assert.equal(sent[0].payload.environment, environment);
    });

    it(`a preflight route that disagrees with ${environment} evidence refuses before any call`, async () => {
      let invoked = 0;
      await assert.rejects(
        notifyBreakGlass({ gate: gateFor(active), context: { repository: 'a/b', commitSha: SHA_A }, invoke: async () => { invoked += 1; }, mintIdentityToken: async () => 't', route: OTHER[environment] }),
        /disagrees with the gate evidence/
      );
      assert.equal(invoked, 0);
    });
  }

  it('the legacy HTTP payload is unchanged (no environment field)', async () => {
    const bodies = [];
    const fetchImpl = async (url, init) => {
      bodies.push(JSON.parse(init.body));
      return { ok: true, json: async () => ({ requestId: 'r-1', status: 'pending' }) };
    };
    await notifyBreakGlass({ gate: gateFor(false), context: { repository: 'a/b', commitSha: SHA_A }, endpoint: 'https://broker.example/notify', sharedSecret: 's', fetchImpl });
    assert.ok(!('environment' in bodies[0]));
  });
});

describe('end to end: misrouted evidence never becomes a request', () => {
  for (const [evidence, brokerEnvironment] of [['synthetic', 'production'], ['production', 'synthetic']]) {
    it(`${evidence} evidence delivered to a ${brokerEnvironment} broker is refused, and nothing is written`, async () => {
      const { env, events } = broker(brokerEnvironment);
      await assert.rejects(
        notifyBreakGlass({
          gate: gateFor(evidence === 'synthetic'),
          context: { repository: REPO_A.repository, commitSha: SHA_A, pullRequest: '51' },
          invoke: (event) => env.ci(event),
          mintIdentityToken: async () => env.tokenFor(),
          route: evidence
        }),
        /broker rejected notify: environment_mismatch/
      );
      assertNothingHappened(env, events);
    });
  }
});

describe('_break-glass-lambda.yml: no caller can choose the environment', () => {
  const workflow = readFileSync('.github/workflows/_break-glass-lambda.yml', 'utf8');
  const executable = workflow.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
  const step = (name) => {
    const start = executable.indexOf(`- name: ${name}\n`);
    assert.notEqual(start, -1, `step '${name}'`);
    const rest = executable.slice(start + 1);
    const next = rest.search(/\n {6}- name: /);
    return next === -1 ? rest : rest.slice(0, next);
  };

  it('declares no input that names an environment or a route', () => {
    const inputs = executable.slice(executable.indexOf('    inputs:\n'), executable.indexOf('\njobs:'));
    const names = [...inputs.matchAll(/^ {6}([a-z0-9_]+):\s*$/gm)].map((m) => m[1]);
    assert.ok(names.length > 5, 'fixture sanity: inputs found');
    assert.deepEqual(names.filter((n) => /environment|route/.test(n)), []);
  });

  it('the request step takes its route from the preflight\'s output only', () => {
    const request = step('Request break-glass decision');
    assert.match(request, /^ {10}BREAK_GLASS_ROUTE: \$\{\{ steps\.preflight\.outputs\.route \}\}$/m);
    assert.ok(!/BREAK_GLASS_ROUTE: .*inputs\./.test(request), 'never from an input');
    assert.ok(!/ENVIRONMENT/.test(request), 'no environment variable is passed: the script derives it from the gate');
  });

  it('the notify script reads the environment from the gate and the route, nothing else', () => {
    const script = readFileSync('security/scripts/break-glass-notify.mjs', 'utf8');
    const envReads = [...script.matchAll(/process\.env\.([A-Z_]+)/g)].map((m) => m[1]);
    assert.deepEqual(envReads.filter((n) => /ENVIRONMENT|ROUTE/.test(n)), ['BREAK_GLASS_ROUTE']);
  });
});
