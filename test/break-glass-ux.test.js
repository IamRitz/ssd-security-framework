// Human-readable break-glass UX. Presentation only: the machine-readable result
// vocabulary, the outputs, the exit codes and the final gate are asserted
// unchanged alongside it.
//
//   poll step       APPROVED / DENIED / EXPIRED / TIMEOUT / ERROR, never a
//                   timeout or an exception labelled as a denial
//   break-glass job its summary headlines the break-glass REVIEW (source verdict,
//                   decision, effective disposition), never "Security gate: BLOCK"
//   source job      unchanged: "Security gate: BLOCK"
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { describePollOutcome, runPoll } from '../security/scripts/break-glass-poll.mjs';
import { DECISION_STATUSES, deriveBreakGlassResult, renderBreakGlassSummary } from '../security/scripts/break-glass-result.mjs';
import { decideSourceGate } from '../security/scripts/final-gate.mjs';
import { buildReport, renderMarkdown } from '../security/scripts/format-findings.mjs';

const SCRIPTS = resolve('security/scripts');
const DIGEST = 'd'.repeat(64);
const REQUEST = { requestId: 'req-1', gateDigest: DIGEST };
const BLOCK_GATE = {
  verdict: 'BLOCK',
  findings: [{ source: 'semgrep', id: 'r', action: 'BLOCK', severity: 'high', policyRule: 'sast.high_new', baselineState: 'new' }],
  breakGlass: { eligible: true }
};

async function withTempDir(work) {
  const directory = await mkdtemp(join(tmpdir(), 'break-glass-ux-'));
  try {
    return await work(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const capture = () => {
  const out = [];
  const err = [];
  return { out, err, log: { log: (line) => out.push(line), error: (line) => err.push(line) } };
};

// =================================================================================
describe('poll step: terminal and error states keep distinct labels', () => {
  const decision = (status, extra = {}) => ({ requestId: 'req-1', gateDigest: DIGEST, status, ...extra });

  async function pollWith(poll) {
    return withTempDir(async (directory) => {
      const requestPath = join(directory, 'request.json');
      const outputPath = join(directory, 'out', 'decision.json');
      await writeFile(requestPath, JSON.stringify(REQUEST));
      const io = capture();
      const code = await runPoll({ requestPath, outputPath, env: {}, poll, log: io.log });
      const written = await readFile(outputPath, 'utf8').then(JSON.parse, () => null);
      return { code, ...io, written };
    });
  }

  it('approved -> BREAK-GLASS: APPROVED, exit 0', async () => {
    const r = await pollWith(async () => decision('approved', { approver: { username: 'alice' } }));
    assert.equal(r.code, 0);
    assert.deepEqual(r.out, ['BREAK-GLASS: APPROVED by verified approver alice']);
    assert.deepEqual(r.err, []);
    assert.equal(r.written.status, 'approved');
  });

  for (const [status, label] of [['denied', 'DENIED'], ['expired', 'EXPIRED'], ['timeout', 'TIMEOUT']]) {
    it(`${status} -> BREAK-GLASS: ${label}, exit 1, decision recorded as ${status}`, async () => {
      const r = await pollWith(async () => decision(status));
      assert.equal(r.code, 1);
      assert.deepEqual(r.out, []);
      assert.equal(r.err.length, 1);
      assert.match(r.err[0], new RegExp(`^BREAK-GLASS: ${label} \\(`));
      assert.match(r.err[0], /the BLOCK stands/);
      // The decision file keeps the machine status; the label is not a new vocabulary.
      assert.equal(r.written.status, status);
    });
  }

  it('timeout and expired are never labelled as a denial', async () => {
    for (const status of ['timeout', 'expired']) {
      const r = await pollWith(async () => decision(status));
      assert.doesNotMatch(r.err.join('\n'), /DENIED|denied/, status);
    }
  });

  for (const [name, error] of [
    ['broker rejection', new Error('break-glass broker rejected status: unknown_request')],
    ['transport failure', new Error('connect ETIMEDOUT')],
    ['malformed response', new Error('status response gateDigest mismatch')],
    ['unexpected exception', new TypeError("Cannot read properties of undefined (reading 'status')")]
  ]) {
    it(`${name} -> BREAK-GLASS: ERROR, exit 1, no decision file`, async () => {
      const r = await pollWith(async () => {
        throw error;
      });
      assert.equal(r.code, 1);
      assert.equal(r.err.length, 1);
      assert.match(r.err[0], /^BREAK-GLASS: ERROR \(/);
      assert.ok(r.err[0].includes(error.message));
      assert.doesNotMatch(r.err[0], /DENIED/);
      assert.equal(r.written, null, 'an error manufactures no decision');
    });
  }

  it('an unreadable request file -> ERROR', async () => {
    const io = capture();
    const code = await runPoll({ requestPath: '/nonexistent/request.json', outputPath: '/nonexistent/out.json', env: {}, poll: async () => decision('approved'), log: io.log });
    assert.equal(code, 1);
    assert.match(io.err[0], /^BREAK-GLASS: ERROR \(/);
  });

  it('an unrecognized status is an ERROR, not a denial', () => {
    const outcome = describePollOutcome({ result: decision('maybe') });
    assert.equal(outcome.approved, false);
    assert.match(outcome.line, /^BREAK-GLASS: ERROR /);
  });

  it('only approved is approved', () => {
    for (const status of ['denied', 'expired', 'timeout', 'pending', undefined]) {
      assert.equal(describePollOutcome({ result: decision(status) }).approved, false, String(status));
    }
    assert.equal(describePollOutcome({ error: new Error('x') }).approved, false);
    assert.equal(describePollOutcome({ result: decision('approved') }).approved, true);
  });

  describe('the real CLI, as the workflow runs it', () => {
    const run = (args, env) =>
      spawnSync(process.execPath, [join(SCRIPTS, 'break-glass-poll.mjs'), ...args], {
        encoding: 'utf8',
        env: { PATH: process.env.PATH, ...env }
      });

    it('reproduces the live timeout: labelled TIMEOUT, exit 1, decision status timeout', async () => {
      await withTempDir(async (directory) => {
        const requestPath = join(directory, 'request.json');
        const outputPath = join(directory, 'decision.json');
        await writeFile(requestPath, JSON.stringify(REQUEST));
        // A zero deadline times out before any broker call, so no AWS is needed.
        const r = run([requestPath, outputPath], {
          BREAK_GLASS_TRANSPORT: 'lambda',
          BREAK_GLASS_FUNCTION_NAME: 'break-glass-ci',
          AWS_REGION: 'us-east-1',
          BREAK_GLASS_TIMEOUT_SECONDS: '0'
        });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /^BREAK-GLASS: TIMEOUT \(/m);
        assert.doesNotMatch(r.stderr, /DENIED/);
        assert.equal(JSON.parse(await readFile(outputPath, 'utf8')).status, 'timeout');
      });
    });

    it('a broker invocation failure is labelled ERROR, exit 1', async () => {
      await withTempDir(async (directory) => {
        const bin = join(directory, 'bin');
        await mkdir(bin);
        // Stands in for the AWS CLI: the invocation itself fails.
        await writeFile(join(bin, 'aws'), '#!/bin/sh\necho "An error occurred (AccessDeniedException)" >&2\nexit 255\n');
        await chmod(join(bin, 'aws'), 0o755);
        const requestPath = join(directory, 'request.json');
        await writeFile(requestPath, JSON.stringify(REQUEST));
        const r = run([requestPath, join(directory, 'decision.json')], {
          PATH: `${bin}:${process.env.PATH}`,
          BREAK_GLASS_TRANSPORT: 'lambda',
          BREAK_GLASS_FUNCTION_NAME: 'break-glass-ci',
          AWS_REGION: 'us-east-1',
          BREAK_GLASS_TIMEOUT_SECONDS: '60'
        });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /^BREAK-GLASS: ERROR \(/m);
        assert.doesNotMatch(r.stderr, /DENIED/);
      });
    });

    it('a missing request file is labelled ERROR, exit 1', () => {
      const r = run(['/nonexistent/request.json', '/nonexistent/decision.json'], {});
      assert.equal(r.status, 1);
      assert.match(r.stderr, /^BREAK-GLASS: ERROR \(/m);
    });
  });
});

// =================================================================================
describe('break-glass job summary: source verdict, decision and disposition stay separate', () => {
  const preflight = { accepted: true, gateDigest: DIGEST, synthetic: false, route: 'production' };
  const ok = { preflightOutcome: 'success', requestOutcome: 'success', pollOutcome: 'success', preflight, request: REQUEST };
  const decision = (status, extra = {}) => ({ requestId: 'req-1', gateDigest: DIGEST, status, ...extra });
  const summaryFor = (input, verdict = 'BLOCK') => renderBreakGlassSummary(deriveBreakGlassResult(input), { verdict });
  const row = (markdown, name) => {
    const line = markdown.split('\n').find((l) => l.startsWith(`| ${name} |`));
    assert.ok(line, `row ${name} missing`);
    return line;
  };

  it('approved: BLOCK stays BLOCK, the disposition is an OVERRIDDEN BLOCK for this run only', () => {
    const md = summaryFor({ ...ok, decision: decision('approved', { approver: { username: 'alice' } }) });
    assert.match(md, /^## .*Break-glass review: APPROVED$/m);
    assert.match(row(md, 'Source policy verdict'), /\*\*BLOCK\*\*/);
    assert.match(row(md, 'Request delivered'), /\| yes \(request `req-1`\) \|/);
    assert.match(row(md, 'Decision'), /APPROVED by `alice`/);
    assert.match(row(md, 'Effective disposition'), /OVERRIDDEN BLOCK\*\* for this run only/);
    assert.ok(row(md, 'Gate digest').includes(`sha256:${DIGEST}`));
    assert.match(md, /source policy verdict remains \*\*BLOCK\*\*/);
    assert.doesNotMatch(md, /Security gate: BLOCK/);
    assert.doesNotMatch(md, /\bPASS\b/, 'the policy verdict is never rewritten to PASS');
  });

  for (const [status, label] of [['denied', 'DENIED'], ['timeout', 'TIMEOUT'], ['expired', 'EXPIRED']]) {
    it(`${status}: delivered, decision ${label}, BLOCK STANDS`, () => {
      const md = summaryFor({ ...ok, pollOutcome: 'failure', decision: decision(status) });
      assert.match(md, new RegExp(`^## .*Break-glass review: ${label}$`, 'm'));
      assert.match(row(md, 'Source policy verdict'), /\*\*BLOCK\*\*/);
      assert.match(row(md, 'Request delivered'), /\| yes/);
      assert.match(row(md, 'Decision'), new RegExp(`\\| ${label} \\|`));
      assert.match(row(md, 'Effective disposition'), /BLOCK STANDS/);
      assert.doesNotMatch(md, /OVERRIDDEN/);
      assert.match(md, /No override is active/);
    });
  }

  it('refused by the preflight: nothing was delivered, no verified approval, BLOCK STANDS', () => {
    const md = summaryFor({ preflightOutcome: 'failure', preflight: { accepted: false, refusal: { code: 'hard-block', reason: 'verified secret' } } });
    assert.match(md, /Break-glass review: REFUSED/);
    assert.match(row(md, 'Request delivered'), /\| no — no approval request reached the broker \|/);
    assert.match(row(md, 'Decision'), /REFUSED — this BLOCK is not eligible/);
    assert.match(row(md, 'Effective disposition'), /BLOCK STANDS\*\* — no verified approval exists/);
    assert.match(row(md, 'Gate digest'), /none validated/);
    assert.doesNotMatch(md, /OVERRIDDEN|\| yes/);
  });

  for (const [name, input] of [
    ['preflight never ran', {}],
    ['preflight configuration error', { preflightOutcome: 'failure', preflight: { accepted: false, refusal: { code: 'configuration', reason: 'no broker' } } }],
    ['request step failed', { ...ok, requestOutcome: 'failure', pollOutcome: 'skipped' }]
  ]) {
    it(`error before delivery (${name}): does not claim delivery, BLOCK STANDS`, () => {
      const result = deriveBreakGlassResult(input);
      assert.equal(result.requestDelivered, false);
      const md = renderBreakGlassSummary(result, { verdict: 'BLOCK' });
      assert.match(md, /Break-glass review: ERROR/);
      assert.match(row(md, 'Request delivered'), /\| no /);
      assert.doesNotMatch(md, /\| yes/);
      assert.match(row(md, 'Decision'), /ERROR — no verified decision was obtained/);
      assert.match(row(md, 'Effective disposition'), /BLOCK STANDS\*\* — no verified approval exists/);
    });
  }

  it('error after delivery (broker unreachable while polling): delivered yes, ERROR, BLOCK STANDS', () => {
    const md = summaryFor({ ...ok, pollOutcome: 'failure', decision: null });
    assert.match(row(md, 'Request delivered'), /\| yes \(request `req-1`\) \|/);
    assert.match(row(md, 'Decision'), /ERROR/);
    assert.match(row(md, 'Effective disposition'), /BLOCK STANDS/);
  });

  it('an unreadable gate is not presented as BLOCK or PASS', () => {
    const md = renderBreakGlassSummary(deriveBreakGlassResult({}), { verdict: undefined });
    assert.match(row(md, 'Source policy verdict'), /unavailable/);
    assert.match(row(md, 'Effective disposition'), /BLOCK STANDS/);
  });

  it('an unknown decision status renders as ERROR, never approval', () => {
    const md = renderBreakGlassSummary({ decisionStatus: 'APPROVED', requestDelivered: true, gateDigest: DIGEST }, { verdict: 'BLOCK' });
    assert.match(md, /Break-glass review: ERROR/);
    assert.doesNotMatch(md, /OVERRIDDEN/);
  });

  it('broker-supplied text cannot break out of its table cell', () => {
    const md = renderBreakGlassSummary(
      { decisionStatus: 'approved', requestDelivered: true, requestId: 'req-1', gateDigest: DIGEST, approver: 'x`|\n## PASS', reason: 'r' },
      { verdict: 'BLOCK' }
    );
    assert.doesNotMatch(md, /^## PASS/m);
    assert.equal(row(md, 'Decision').split('|').length, 4);
  });

  it('synthetic routing is stated', () => {
    const md = summaryFor({ ...ok, preflight: { ...preflight, synthetic: true }, decision: decision('approved') });
    assert.match(md, /synthetic fixture — isolated test broker/);
  });

  describe('break-glass-result CLI: summary is additive, outputs unchanged', () => {
    async function runResult(directory, { decisionStatus, summaryPath }) {
      const paths = {
        SSD_GATE_PATH: join(directory, 'security-gate.json'),
        SSD_PREFLIGHT_PATH: join(directory, 'preflight.json'),
        SSD_REQUEST_PATH: join(directory, 'request.json'),
        SSD_DECISION_PATH: join(directory, 'decision.json'),
        SSD_RESULT_PATH: join(directory, 'result.json'),
        GITHUB_OUTPUT: join(directory, 'output.txt')
      };
      await writeFile(paths.SSD_GATE_PATH, JSON.stringify(BLOCK_GATE));
      await writeFile(paths.SSD_PREFLIGHT_PATH, JSON.stringify(preflight));
      await writeFile(paths.SSD_REQUEST_PATH, JSON.stringify(REQUEST));
      await writeFile(paths.SSD_DECISION_PATH, JSON.stringify(decision(decisionStatus, { approver: { username: 'alice' } })));
      const r = spawnSync(process.execPath, [join(SCRIPTS, 'break-glass-result.mjs')], {
        encoding: 'utf8',
        env: {
          PATH: process.env.PATH,
          ...paths,
          GITHUB_STEP_SUMMARY: summaryPath,
          PREFLIGHT_OUTCOME: 'success',
          REQUEST_OUTCOME: 'success',
          POLL_OUTCOME: decisionStatus === 'approved' ? 'success' : 'failure'
        }
      });
      return { ...r, outputs: await readFile(paths.GITHUB_OUTPUT, 'utf8') };
    }

    it('approved: exact machine outputs, plus the review summary', async () => {
      await withTempDir(async (directory) => {
        const summaryPath = join(directory, 'summary.md');
        const r = await runResult(directory, { decisionStatus: 'approved', summaryPath });
        assert.equal(r.status, 0);
        assert.equal(
          r.outputs,
          ['decision_status=approved', 'request_delivered=true', `gate_digest=${DIGEST}`, 'control_result=success', 'synthetic=false', 'request_id=req-1'].join('\n') + '\n'
        );
        const md = await readFile(summaryPath, 'utf8');
        assert.match(md, /Break-glass review: APPROVED/);
        assert.match(md, /Source policy verdict \| \*\*BLOCK\*\*/);
        assert.match(md, /OVERRIDDEN BLOCK/);
      });
    });

    it('timeout: exact machine outputs, BLOCK STANDS', async () => {
      await withTempDir(async (directory) => {
        const summaryPath = join(directory, 'summary.md');
        const r = await runResult(directory, { decisionStatus: 'timeout', summaryPath });
        assert.equal(r.status, 0);
        assert.match(r.outputs, /^decision_status=timeout$/m);
        assert.match(r.outputs, /^control_result=failure$/m);
        assert.match(r.outputs, /^request_delivered=true$/m);
        assert.match(await readFile(summaryPath, 'utf8'), /BLOCK STANDS/);
      });
    });

    it('a summary write failure never changes the outputs or the exit code', async () => {
      await withTempDir(async (directory) => {
        // A directory cannot be appended to.
        const r = await runResult(directory, { decisionStatus: 'approved', summaryPath: directory });
        assert.equal(r.status, 0);
        assert.match(r.outputs, /^decision_status=approved$/m);
        assert.match(r.stderr, /job summary not written/);
      });
    });
  });
});

// =================================================================================
describe('findings summary: raw source-gate rendering is unchanged', () => {
  it('the source job headlines the raw policy verdict', () => {
    const md = renderMarkdown(buildReport({ gate: BLOCK_GATE, context: {} }));
    assert.match(md, /^## ⛔ Security gate: BLOCK$/m);
    assert.doesNotMatch(md, /Source findings behind this review/);
  });

  it('an unrecognized role is the source rendering, byte for byte', () => {
    const plain = renderMarkdown(buildReport({ gate: BLOCK_GATE, context: {} }));
    assert.equal(renderMarkdown(buildReport({ gate: BLOCK_GATE, context: { summaryRole: 'other' } })), plain);
  });

  it('the break-glass job demotes the findings under the review and still shows BLOCK verbatim', () => {
    const report = buildReport({ gate: BLOCK_GATE, context: { summaryRole: 'break-glass' } });
    assert.equal(report.verdict, 'BLOCK');
    const md = renderMarkdown(report);
    assert.doesNotMatch(md, /^## .*Security gate:/m);
    assert.match(md, /^### ⛔ Source findings behind this review — source policy verdict: BLOCK$/m);
    assert.match(md, /Break-glass review\*\* above/);
  });

  it('the notifier CLI selects the break-glass role only from SECURITY_SUMMARY_ROLE=break-glass', async () => {
    await withTempDir(async (directory) => {
      const gatePath = join(directory, 'security-gate.json');
      await writeFile(gatePath, JSON.stringify(BLOCK_GATE));
      const render = (role) => {
        const summary = join(directory, `summary-${role || 'none'}.md`);
        const r = spawnSync(process.execPath, [join(SCRIPTS, 'notify.mjs'), '--gate', gatePath], {
          encoding: 'utf8',
          env: { PATH: process.env.PATH, GITHUB_STEP_SUMMARY: summary, GATE_MODE: 'enforce', ...(role ? { SECURITY_SUMMARY_ROLE: role } : {}) }
        });
        assert.equal(r.status, 0, r.stderr);
        return readFile(summary, 'utf8');
      };
      assert.match(await render(''), /^## ⛔ Security gate: BLOCK$/m);
      assert.match(await render('BREAK-GLASS'), /^## ⛔ Security gate: BLOCK$/m);
      assert.match(await render('break-glass'), /^### ⛔ Source findings behind this review — source policy verdict: BLOCK$/m);
    });
  });

  it('only the Lambda break-glass notifier step sets the role', async () => {
    const bg = await readFile('.github/workflows/_break-glass-lambda.yml', 'utf8');
    assert.equal(bg.match(/SECURITY_SUMMARY_ROLE: break-glass/g)?.length, 1);
    for (const path of ['.github/workflows/_source-security.yml', '.github/workflows/_source-scan.yml']) {
      assert.doesNotMatch(await readFile(path, 'utf8'), /SECURITY_SUMMARY_ROLE/, path);
    }
  });
});

// =================================================================================
describe('machine semantics are unchanged', () => {
  it('the bounded result vocabulary is exactly the documented one', () => {
    assert.deepEqual(DECISION_STATUSES, ['approved', 'denied', 'expired', 'timeout', 'refused', 'error']);
  });

  const override = {
    sourceResult: 'failure',
    verdict: 'BLOCK',
    gateMode: 'enforce',
    integrityTrusted: 'true',
    breakGlassEligible: 'true',
    breakGlassDelegated: 'true',
    secretScanResult: 'success',
    dependencyScanResult: 'success',
    sastResult: 'success',
    sourceGateDigest: DIGEST,
    breakGlassResult: 'success',
    breakGlassDecision: 'approved',
    breakGlassDelivered: 'true',
    breakGlassGateDigest: DIGEST
  };

  it('final gate: only an exact approved decision is an overridden block', () => {
    assert.equal(decideSourceGate(override).outcome, 'overridden-block');
    for (const status of DECISION_STATUSES.filter((s) => s !== 'approved')) {
      assert.equal(decideSourceGate({ ...override, breakGlassResult: 'failure', breakGlassDecision: status }).outcome, 'block', status);
      assert.equal(decideSourceGate({ ...override, breakGlassDecision: status }).outcome, 'block', status);
    }
  });

  it('control_result is success only for approved', () => {
    const preflight = { accepted: true, gateDigest: DIGEST };
    for (const status of ['approved', 'denied', 'expired', 'timeout']) {
      const r = deriveBreakGlassResult({
        preflightOutcome: 'success',
        requestOutcome: 'success',
        pollOutcome: status === 'approved' ? 'success' : 'failure',
        preflight,
        request: REQUEST,
        decision: { requestId: 'req-1', gateDigest: DIGEST, status }
      });
      assert.equal(r.decisionStatus, status);
      assert.equal(r.controlResult, status === 'approved' ? 'success' : 'failure');
    }
  });
});

// =================================================================================
describe('request step: a failed request is an ERROR, never a decision', () => {
  const ELIGIBLE_GATE = {
    verdict: 'BLOCK',
    breakGlass: {
      eligible: true,
      eligibleFindings: [{ id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }],
      ineligibleFindings: []
    }
  };
  const CI = { CI_REPOSITORY: 'owner/repo', CI_COMMIT_SHA: 'abc123', CI_SYSTEM: 'github-actions' };
  const LAMBDA = { BREAK_GLASS_TRANSPORT: 'lambda', BREAK_GLASS_FUNCTION_NAME: 'break-glass-ci', AWS_REGION: 'us-east-1' };
  const DECISION_WORDS = /DENIED|APPROVED|EXPIRED|TIMEOUT|denied|approved/;

  // Stands in for the AWS CLI: writes `response` (verbatim) to the output file
  // and prints the invoke metadata, or fails the invocation outright.
  async function fakeAws(directory, { response = null, meta = { StatusCode: 200 }, exitCode = 0 } = {}) {
    const bin = join(directory, 'bin');
    await mkdir(bin, { recursive: true });
    const script = exitCode !== 0
      ? `#!/bin/sh\necho "An error occurred (AccessDeniedException)" >&2\nexit ${exitCode}\n`
      : `#!${process.execPath}\nrequire('node:fs').writeFileSync(process.argv.at(-1), ${JSON.stringify(response)});\nconsole.log(${JSON.stringify(JSON.stringify(meta))});\n`;
    await writeFile(join(bin, 'aws'), script);
    await chmod(join(bin, 'aws'), 0o755);
    return `${bin}:${process.env.PATH}`;
  }

  async function request(directory, { gate = ELIGIBLE_GATE, gateText = null, env = {}, args = null } = {}) {
    const gatePath = join(directory, 'security-gate.json');
    const output = join(directory, 'out', 'break-glass-request.json');
    await writeFile(gatePath, gateText ?? JSON.stringify(gate));
    const r = spawnSync(process.execPath, [join(SCRIPTS, 'break-glass-notify.mjs'), ...(args ?? ['--gate', gatePath, '--output', output])], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH, ...CI, ...env }
    });
    const written = await readFile(output, 'utf8').then(JSON.parse, () => null);
    return { ...r, written };
  }

  const assertRequestError = (r, reason) => {
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /^BREAK-GLASS: ERROR \(request not delivered: /m);
    assert.match(r.stderr, reason);
    assert.doesNotMatch(r.stdout + r.stderr, DECISION_WORDS, 'a failed request claims no decision');
    assert.doesNotMatch(r.stdout, /pending/);
    assert.equal(r.written, null, 'no request record is written for a failed request');
  };

  it('a successful Lambda request still reports pending and writes the request record', async () => {
    await withTempDir(async (directory) => {
      const PATH = await fakeAws(directory, { response: JSON.stringify({ ok: true, statusCode: 201, body: { requestId: 'r-1', status: 'pending', createdAt: 'c', expiresAt: 'e' } }) });
      const r = await request(directory, { env: { ...LAMBDA, PATH } });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /^Break-glass request r-1 is pending$/m);
      assert.equal(r.stderr, '');
      assert.equal(r.written.requestId, 'r-1');
      assert.match(r.written.gateDigest, /^[0-9a-f]{64}$/);
    });
  });

  it('broker rejection -> ERROR, not DENIED', async () => {
    await withTempDir(async (directory) => {
      const PATH = await fakeAws(directory, { response: JSON.stringify({ ok: false, statusCode: 400, error: 'payload contains a non-overridable finding' }) });
      assertRequestError(await request(directory, { env: { ...LAMBDA, PATH } }), /rejected notify: payload contains a non-overridable finding/);
    });
  });

  it('broker function error -> ERROR, not DENIED', async () => {
    await withTempDir(async (directory) => {
      const PATH = await fakeAws(directory, { response: '{"errorMessage":"boom"}', meta: { StatusCode: 200, FunctionError: 'Unhandled' } });
      assertRequestError(await request(directory, { env: { ...LAMBDA, PATH } }), /broker failed: Unhandled/);
    });
  });

  it('invocation / transport failure -> ERROR, not DENIED', async () => {
    await withTempDir(async (directory) => {
      const PATH = await fakeAws(directory, { exitCode: 255 });
      assertRequestError(await request(directory, { env: { ...LAMBDA, PATH } }), /AccessDenied|Command failed/);
    });
  });

  for (const [name, response, reason] of [
    ['a response without a requestId', JSON.stringify({ ok: true, body: { status: 'pending' } }), /response lacks requestId/],
    ['a request not recorded as pending', JSON.stringify({ ok: true, body: { requestId: 'r-1', status: 'approved' } }), /not recorded as pending/],
    ['a response that is not JSON', 'not json', /JSON/]
  ]) {
    it(`malformed broker response (${name}) -> ERROR, not DENIED`, async () => {
      await withTempDir(async (directory) => {
        const PATH = await fakeAws(directory, { response });
        assertRequestError(await request(directory, { env: { ...LAMBDA, PATH } }), reason);
      });
    });
  }

  for (const [name, options, reason] of [
    ['Lambda selected without a function name', { env: { BREAK_GLASS_TRANSPORT: 'lambda', AWS_REGION: 'us-east-1' } }, /FUNCTION_NAME is not configured/],
    ['legacy HTTP without an endpoint', { env: { BREAK_GLASS_SHARED_SECRET: 's' } }, /BREAK_GLASS_NOTIFY_URL is not configured/],
    ['legacy HTTP over plain http', { env: { BREAK_GLASS_NOTIFY_URL: 'http://example.invalid/notify', BREAK_GLASS_SHARED_SECRET: 's' } }, /must use HTTPS/],
    ['legacy HTTP without a shared secret', { env: { BREAK_GLASS_NOTIFY_URL: 'https://example.invalid/notify' } }, /shared secret is not configured/],
    ['missing CI context', { env: { ...CI, CI_REPOSITORY: '', BREAK_GLASS_NOTIFY_URL: 'https://example.invalid/notify', BREAK_GLASS_SHARED_SECRET: 's' } }, /repository is required/],
    ['a malformed gate report', { gateText: '{not json' }, /security gate report is malformed JSON/],
    ['an ineligible (hard-block) gate', { gate: { ...ELIGIBLE_GATE, breakGlass: { ...ELIGIBLE_GATE.breakGlass, ineligibleFindings: [{ id: 'secret' }] } } }, /hard-block findings cannot be overridden/],
    ['a PASS gate', { gate: { verdict: 'PASS' } }, /only available for a BLOCK verdict/],
    ['an unknown argument', { args: ['--bogus'] }, /unknown argument --bogus/]
  ]) {
    it(`configuration / read / validation error (${name}) -> ERROR, not DENIED`, async () => {
      await withTempDir(async (directory) => {
        assertRequestError(await request(directory, options), reason);
      });
    });
  }

  it('an unreadable gate report -> ERROR, not DENIED', async () => {
    await withTempDir(async (directory) => {
      assertRequestError(await request(directory, { args: ['--gate', join(directory, 'absent.json'), '--output', join(directory, 'out', 'r.json')] }), /security gate report cannot be read/);
    });
  });

  it('--check-only failure (source workflows\' eligibility check) -> ERROR, not DENIED', async () => {
    await withTempDir(async (directory) => {
      const gatePath = join(directory, 'security-gate.json');
      await writeFile(gatePath, JSON.stringify({ verdict: 'PASS' }));
      const r = await request(directory, { gate: { verdict: 'PASS' }, args: ['--check-only', '--gate', gatePath] });
      assertRequestError(r, /only available for a BLOCK verdict/);
    });
  });

  it('--check-only success is unchanged', async () => {
    await withTempDir(async (directory) => {
      const gatePath = join(directory, 'security-gate.json');
      await writeFile(gatePath, JSON.stringify(ELIGIBLE_GATE));
      const r = await request(directory, { args: ['--check-only', '--gate', gatePath] });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /^Break-glass eligible: 1 BLOCK finding\(s\)$/m);
    });
  });
});
