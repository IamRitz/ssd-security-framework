// Every developer-visible statement must be backed by state the workflow
// actually observed.
//
// Regressions this file exists for (found in live validation from a scratch
// consumer): an eligible BLOCK in a repository with break-glass DISABLED told the
// developer "an interactive approval request has been sent to Slack" and
// suppressed the normal Slack alert, although no request path ran. A Semgrep
// finding from a LOCAL rule was given a fabricated semgrep.dev Registry URL and a
// `--config p/owasp-top-ten` reproduce command that could never reproduce it.
//
// Findings here are produced by the REAL gates from scanner-shaped reports, then
// rendered, so a field the gate stops recording fails a test rather than
// silently degrading the guidance.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import {
  breakGlassNotice,
  buildReport,
  deriveBreakGlassState,
  renderEvidenceMarkdown,
  renderMarkdown,
  renderSlack
} from '../security/scripts/format-findings.mjs';
import { runImageGate } from '../security/scripts/image-gate.mjs';
import {
  breakGlassStateFromEnv,
  classifyPrCommentError,
  dispatch,
  GitHubApiError,
  upsertPrComment
} from '../security/scripts/notify.mjs';
import { normalizeEcrResponse } from '../security/scripts/poll-ecr-scan.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const POLICY = resolve('security/policy.yaml');
const SLACK_URL = 'https://slack.example/hook';
const CONTEXT = {
  repository: 'acme/widgets',
  sha: 'abc123def4567890',
  prNumber: 42,
  runUrl: 'https://github.com/acme/widgets/actions/runs/1'
};

// --- helpers -----------------------------------------------------------------

async function withTempDir(fn) {
  const directory = await mkdtemp(join(tmpdir(), 'developer-feedback-'));
  try {
    return await fn(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

// Runs the real source gate with the given scanner reports replacing the clean ones.
async function sourceGate(reports = {}, { bootstrap = false } = {}) {
  return withTempDir(async (directory) => {
    const paths = {
      policy: POLICY,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      npmAudit: join(CLEAN, 'npm-audit.json'),
      osv: join(CLEAN, 'osv-scanner.json'),
      semgrep: join(CLEAN, 'semgrep.json'),
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      pipAudit: join(directory, 'absent-pip-audit.json'),
      output: join(directory, 'security-gate.json'),
      exceptions: join(directory, 'gate-exceptions.json')
    };
    for (const [key, value] of Object.entries(reports)) {
      const path = join(directory, `${key}.json`);
      await writeFile(path, typeof value === 'string' ? value : JSON.stringify(value));
      paths[key] = path;
    }
    if (bootstrap) {
      paths.baseline = join(directory, 'no-baseline.json');
    }
    return runSecurityGate({ ...paths, bootstrap });
  });
}

async function imageGate(report, source) {
  return withTempDir(async (directory) => {
    const path = join(directory, 'report.json');
    await writeFile(path, JSON.stringify(report));
    return runImageGate({
      policy: POLICY,
      report: path,
      output: join(directory, 'image-gate.json'),
      ...(source ? { source } : {})
    });
  });
}

function render(gate, { context = CONTEXT, mode = 'enforce', breakGlass } = {}) {
  const report = buildReport({ gate, context, mode, breakGlass });
  const comment = renderMarkdown(report, { includeMarker: true });
  const summary = renderMarkdown(report, { includeMarker: false });
  const slack = JSON.stringify(renderSlack(report));
  // The bounded summary shows INFO issues as table rows only; their full cards
  // live in the evidence document. `all` spans every surface, so a wording rule
  // (and every doesNotMatch) holds wherever the card is rendered.
  const evidence = renderEvidenceMarkdown(report);
  return { report, comment, summary, slack, evidence, all: `${comment}\n${summary}\n${slack}\n${evidence}` };
}

function fakeSurfaces() {
  const calls = [];
  const appended = [];
  const logs = [];
  return {
    calls,
    appended,
    logs,
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET', body: options.body });
      if (url.includes('/comments') && options.method === undefined) {
        return { ok: true, json: async () => [] };
      }
      return { ok: true, json: async () => ({}) };
    },
    appendImpl: async (_path, data) => appended.push(data),
    logger: { log: (line) => logs.push(line), error: (line) => logs.push(line) }
  };
}

const semgrepReport = (results) => ({
  version: '1.176.0',
  results,
  errors: [],
  paths: { scanned: results.map((result) => result.path) }
});

// A local rule exactly as the scratch consumer produced it: the config file's
// directory (security/semgrep/) becomes a dotted prefix, and there is no
// Registry metadata.
const LOCAL_RULE_RESULT = {
  check_id: 'security.semgrep.lab-dangerous-eval',
  path: 'src/lab-vulns.js',
  start: { line: 2 },
  extra: { severity: 'ERROR', message: 'Lab: use of dynamic eval()', lines: '  return eval(input);', metadata: {} }
};

// A Registry rule as Semgrep emits it (shape captured from a real scan).
const REGISTRY_RULE_RESULT = {
  check_id: 'javascript.lang.security.audit.detect-eval-with-expression.detect-eval-with-expression',
  path: 'src/app.js',
  start: { line: 7 },
  extra: {
    severity: 'WARNING',
    message: 'Detected eval with a non-literal argument.',
    lines: 'eval(userInput);',
    metadata: {
      references: ['https://owasp.org/Top10/A03_2021-Injection/'],
      source: 'https://semgrep.dev/r/javascript.lang.security.audit.detect-eval-with-expression.detect-eval-with-expression',
      shortlink: 'https://sg.run/6nwK'
    }
  }
};

// --- 1. break-glass state matrix ------------------------------------------------

describe('break-glass state: eligibility never implies a request, delivery, or decision', () => {
  let eligibleGate;
  let ineligibleGate;

  it('produces real eligible and ineligible BLOCK gate results', async () => {
    eligibleGate = await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) });
    assert.equal(eligibleGate.verdict, 'BLOCK');
    assert.equal(eligibleGate.breakGlass.eligible, true);
    ineligibleGate = await sourceGate({ trufflehog: [{ DetectorName: 'AWS', Verified: true }] });
    assert.equal(ineligibleGate.verdict, 'BLOCK');
    assert.equal(ineligibleGate.breakGlass.eligible, false);
  });

  // Each row: the environment the workflow passes (step outcomes are exactly what
  // GitHub reports: a step whose `if` was false is 'skipped'), the break-glass
  // artifacts on disk, and what every surface must then say and do.
  const MATRIX = [
    {
      name: 'eligible=false, enabled=false',
      gate: () => ineligibleGate,
      env: { BREAK_GLASS_ENABLED: 'false', BREAK_GLASS_CHECK_OUTCOME: 'skipped', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      state: { eligible: false, enabled: false, requestPathEntered: false, requested: false, delivered: false, decision: 'not-requested' },
      notice: null,
      slack: true
    },
    {
      name: 'eligible=true, enabled=false (the scratch-consumer case)',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'false', BREAK_GLASS_CHECK_OUTCOME: 'skipped', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      state: { eligible: true, enabled: false, requestPathEntered: false, requested: false, delivered: false, decision: 'not-requested' },
      notice: /eligible for break-glass by policy, but break-glass is not enabled for this repository/,
      slack: true
    },
    {
      name: 'eligible=true, enabled=true, request sent (no decision retrievable)',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'success', BREAK_GLASS_POLL_OUTCOME: 'failure' },
      request: { requestId: 'req-123', gateDigest: 'd' },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: true, delivered: true, decision: 'decision-unavailable', requestId: 'req-123' },
      notice: /entered break-glass review: an interactive approval request was sent successfully \(request `req-123`\)\. No verified decision could be retrieved, so no override is active/,
      slack: false
    },
    {
      name: 'eligible=true, enabled=true, request step ran and failed; poll never ran',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'failure', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      // A stale decision file must not manufacture a denied/timeout state.
      decision: { requestId: 'stale', gateDigest: 'd', status: 'denied' },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: true, delivered: false, decision: 'request-failed' },
      notice: /An approval request was attempted, but it failed and could not be confirmed as delivered\. No override is active/,
      forbid: /denied|timed out|was sent successfully/,
      slack: true
    },
    {
      name: 'eligible=true, enabled=true, check passed but transport validation failed before the request step',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: false, delivered: false, decision: 'request-not-attempted' },
      notice: /stopped before any request was attempted\. No approval request was made and no override is active/,
      forbid: /request was attempted,|was sent successfully|could not be confirmed as delivered/,
      slack: true
    },
    {
      name: 'eligible=true, enabled=true, eligibility check itself did not pass',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'failure', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      state: { eligible: true, enabled: true, requestPathEntered: false, requested: false, delivered: false, decision: 'request-not-attempted' },
      notice: /stopped before any request was attempted/,
      forbid: /request was attempted,|was sent successfully/,
      slack: true
    },
    {
      name: 'eligible=true, enabled=true, decision approved',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'success', BREAK_GLASS_POLL_OUTCOME: 'success' },
      request: { requestId: 'req-ok', gateDigest: 'd' },
      decision: { requestId: 'req-ok', gateDigest: 'd', status: 'approved', approver: { username: 'lead' } },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: true, delivered: true, decision: 'approved', requestId: 'req-ok', approver: 'lead' },
      notice: /A verified break-glass approval by `lead` overrode this BLOCK for this run/,
      slack: false
    },
    {
      name: 'eligible=true, enabled=true, decision denied',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'success', BREAK_GLASS_POLL_OUTCOME: 'failure' },
      request: { requestId: 'req-no', gateDigest: 'd' },
      decision: { requestId: 'req-no', gateDigest: 'd', status: 'denied' },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: true, delivered: true, decision: 'denied', requestId: 'req-no' },
      notice: /Break-glass review was denied\. The BLOCK remains enforced/,
      slack: false
    },
    {
      name: 'eligible=true, enabled=true, decision timeout',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'success', BREAK_GLASS_POLL_OUTCOME: 'failure' },
      request: { requestId: 'req-late', gateDigest: 'd' },
      decision: { requestId: 'req-late', gateDigest: 'd', status: 'timeout' },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: true, delivered: true, decision: 'timeout', requestId: 'req-late' },
      notice: /Break-glass review timed out without an authorized decision\. The BLOCK remains enforced/,
      slack: false
    },
    {
      name: 'eligible=true, enabled=true, broker expired the request',
      gate: () => eligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'success', BREAK_GLASS_POLL_OUTCOME: 'failure' },
      request: { requestId: 'req-exp', gateDigest: 'd' },
      decision: { requestId: 'req-exp', gateDigest: 'd', status: 'expired' },
      state: { eligible: true, enabled: true, requestPathEntered: true, requested: true, delivered: true, decision: 'expired', requestId: 'req-exp' },
      notice: /timed out without an authorized decision\. The BLOCK remains enforced/,
      slack: false
    },
    {
      name: 'log-only + eligible',
      gate: () => eligibleGate,
      mode: 'log-only',
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'skipped', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      state: { eligible: true, enabled: true, requestPathEntered: false, requested: false, delivered: false, decision: 'not-requested' },
      notice: /eligible for break-glass by policy, but `gate_mode` is log-only, so nothing is enforced and no approval request was made/,
      slack: false
    },
    {
      name: 'enabled=true but the BLOCK is not eligible',
      gate: () => ineligibleGate,
      env: { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'failure', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
      state: { eligible: false, enabled: true, requestPathEntered: false, requested: false, delivered: false, decision: 'not-eligible' },
      notice: /Break-glass is enabled, but this BLOCK is not eligible/,
      slack: true
    },
    {
      name: 'eligible, but the notifier was given no break-glass state at all',
      gate: () => eligibleGate,
      env: {},
      state: { eligible: true, enabled: null, requestPathEntered: false, requested: false, delivered: false, decision: 'unknown' },
      notice: /makes no claim about whether an approval request was made/,
      slack: true
    }
  ];

  for (const row of MATRIX) {
    it(row.name, async () => {
      await withTempDir(async (directory) => {
        const mode = row.mode || 'enforce';
        const env = {
          ...row.env,
          BREAK_GLASS_REQUEST_PATH: join(directory, 'break-glass-request.json'),
          BREAK_GLASS_DECISION_PATH: join(directory, 'break-glass-decision.json')
        };
        if (row.request) await writeFile(env.BREAK_GLASS_REQUEST_PATH, JSON.stringify(row.request));
        if (row.decision) await writeFile(env.BREAK_GLASS_DECISION_PATH, JSON.stringify(row.decision));

        const gate = row.gate();
        const state = await breakGlassStateFromEnv(env, { gate, mode });
        assert.deepEqual(state, row.state);

        const surfaces = fakeSurfaces();
        const performed = await dispatch({
          gate,
          context: CONTEXT,
          mode,
          breakGlass: state,
          slackUrl: SLACK_URL,
          token: 'gh-token',
          summaryPath: '/tmp/summary',
          fetchImpl: surfaces.fetchImpl,
          appendImpl: surfaces.appendImpl,
          logger: surfaces.logger
        });

        // Routing never changes the verdict.
        assert.equal(performed.verdict, 'BLOCK');

        // Slack routing.
        const slackCall = surfaces.calls.find((call) => call.url === SLACK_URL);
        assert.equal(Boolean(slackCall), row.slack, `Slack posted=${Boolean(slackCall)}`);
        assert.equal(performed.slack, row.slack);

        // Rendered text: job summary and PR comment carry the same notice.
        const summary = surfaces.appended[0];
        const comment = JSON.parse(surfaces.calls.find((call) => call.method === 'POST' && call.url.includes('/comments')).body).body;
        for (const [surface, text] of [['summary', summary], ['PR comment', comment]]) {
          if (row.notice) {
            assert.match(text, row.notice, `${surface} must describe the observed state`);
          } else {
            // No break-glass notice at all (a card may still state a policy fact
            // such as "never allows break-glass for a verified secret").
            assert.doesNotMatch(text, /^> .*break-glass/im, `${surface} must carry no break-glass notice`);
            assert.doesNotMatch(text, /approval request/, `${surface} must not mention an approval request`);
          }
          if (row.forbid) {
            assert.doesNotMatch(text, row.forbid, `${surface} must not claim more than was observed`);
          }
          // The original bug's sentence, and any claim of sending, only when delivered.
          assert.doesNotMatch(text, /has been sent to Slack/);
          if (!state.delivered) {
            assert.doesNotMatch(text, /request was sent successfully/);
          }
        }
        // Slack, when posted, carries the same fact.
        if (slackCall && row.notice) {
          assert.match(slackCall.body.replaceAll('\\"', '"'), new RegExp(row.notice.source.replaceAll('`', '`?')));
        }

        // The notifier log never claims a request owns Slack unless one was delivered.
        const log = surfaces.logs.join('\n');
        assert.doesNotMatch(log, /owns the Slack channel/);
        if (!row.slack && mode === 'log-only') assert.match(log, /log-only/);
        if (!row.slack && mode !== 'log-only') assert.match(log, /break-glass request was delivered/);
      });
    });
  }

  it('the approved decision follows the poll step outcome, exactly as enforcement does', () => {
    // A decision file that SAYS approved, without the poll step succeeding, is
    // not an approval: the enforce step would still fail the job.
    const state = deriveBreakGlassState({
      verdict: 'BLOCK',
      eligible: true,
      enabled: true,
      checkOutcome: 'success',
      requestOutcome: 'success',
      pollOutcome: 'failure',
      decision: { status: 'approved' }
    });
    assert.equal(state.decision, 'decision-unavailable');
    assert.doesNotMatch(breakGlassNotice(state), /overrode/);
  });

  it('requested follows the Request step running, not the eligibility check', () => {
    const base = { verdict: 'BLOCK', eligible: true, enabled: true, checkOutcome: 'success' };
    const pick = ({ requestPathEntered, requested, delivered, decision }) => ({ requestPathEntered, requested, delivered, decision });
    // 1. transport validation failed before the request step: request skipped
    assert.deepEqual(pick(deriveBreakGlassState({ ...base, requestOutcome: 'skipped', pollOutcome: 'skipped' })), {
      requestPathEntered: true, requested: false, delivered: false, decision: 'request-not-attempted'
    });
    // 2. request step ran and failed
    assert.deepEqual(pick(deriveBreakGlassState({ ...base, requestOutcome: 'failure', pollOutcome: 'skipped' })), {
      requestPathEntered: true, requested: true, delivered: false, decision: 'request-failed'
    });
    // a request step cancelled mid-run did run, but was not delivered
    assert.deepEqual(pick(deriveBreakGlassState({ ...base, requestOutcome: 'cancelled' })), {
      requestPathEntered: true, requested: true, delivered: false, decision: 'request-failed'
    });
    // 3. request step succeeded
    const sent = deriveBreakGlassState({ ...base, requestOutcome: 'success', pollOutcome: 'failure', decision: { status: 'denied' } });
    assert.deepEqual(pick(sent), { requestPathEntered: true, requested: true, delivered: true, decision: 'denied' });
    // 4. poll never ran after a request failure: no denied/timeout is manufactured,
    //    even with decision files present, and even if a poll outcome were claimed
    for (const decision of [{ status: 'denied' }, { status: 'timeout' }, { status: 'approved' }]) {
      for (const pollOutcome of ['skipped', '', 'success']) {
        const state = deriveBreakGlassState({ ...base, requestOutcome: 'failure', pollOutcome, decision });
        assert.equal(state.decision, 'request-failed');
        assert.doesNotMatch(breakGlassNotice(state), /denied|timed out|overrode/);
      }
    }
    // an eligibility check that did not pass cannot yield an attempted request
    assert.equal(deriveBreakGlassState({ ...base, checkOutcome: 'failure', requestOutcome: 'success' }).requested, false);
  });

  it('a non-BLOCK verdict has no break-glass state to describe', () => {
    const state = deriveBreakGlassState({ verdict: 'PASS', eligible: false, enabled: true });
    assert.equal(state.decision, 'not-applicable');
    assert.equal(breakGlassNotice(state), null);
  });

  it('the notice never names a chat tool: the framework observes the broker, not Slack', () => {
    for (const decision of ['approved', 'denied', 'timeout', 'request-failed', 'request-not-attempted', 'decision-unavailable']) {
      const text = breakGlassNotice({ eligible: true, enabled: true, requested: true, delivered: decision !== 'request-failed', decision });
      assert.doesNotMatch(text, /Slack/);
    }
  });
});

// --- 2. every scanner: guidance claims only what the scanner provided ----------

describe('Semgrep: Registry and local rules are distinguished by evidence, not by id shape', () => {
  it('a local rule gets NO fabricated semgrep.dev Registry URL', async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) });
    const finding = gate.findings[0];
    assert.equal(finding.id, 'security.semgrep.lab-dangerous-eval');
    assert.equal(finding.registryUrl, undefined);
    const { all, report } = render(gate);
    assert.doesNotMatch(all, /semgrep\.dev\/r\//);
    assert.equal(report.cards[0].referenceUrl, null);
    assert.match(all, /carries no Semgrep Registry metadata/);
  });

  it("a local rule's reproduce command is the run's own configs, not a generic p/owasp-top-ten", async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) });
    const scan = { semgrepConfigs: ['p/owasp-top-ten', 'p/javascript', 'security/semgrep/lab-rules.yml'], semgrepPaths: ['src'] };
    const { report, all } = render(gate, { context: { ...CONTEXT, scan } });
    assert.equal(
      report.cards[0].reproduce,
      'semgrep scan --config p/owasp-top-ten --config p/javascript --config security/semgrep/lab-rules.yml src'
    );
    assert.doesNotMatch(all, /semgrep scan --config p\/owasp-top-ten \.`/);
  });

  it('with no config information, a local rule gets no reproduce command rather than a wrong one', async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) });
    assert.equal(render(gate).report.cards[0].reproduce, null);
  });

  it('a Registry rule keeps its Registry URL from metadata, and can be reproduced by id', async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([REGISTRY_RULE_RESULT]) });
    assert.equal(gate.findings[0].registryUrl, REGISTRY_RULE_RESULT.extra.metadata.source);
    const { report, all } = render(gate);
    assert.match(all, /Semgrep Registry rule/);
    assert.ok(all.includes(REGISTRY_RULE_RESULT.extra.metadata.source));
    assert.equal(report.cards[0].reproduce, `semgrep scan --config r/${REGISTRY_RULE_RESULT.check_id} .`);
  });

  it('a non-semgrep.dev metadata.source is not treated as Registry evidence', async () => {
    const spoof = structuredClone(LOCAL_RULE_RESULT);
    spoof.extra.metadata.source = 'https://example.com/r/security.semgrep.lab-dangerous-eval';
    const gate = await sourceGate({ semgrep: semgrepReport([spoof]) });
    assert.equal(gate.findings[0].registryUrl, undefined);
  });

  it('states the policy severity mapping instead of implying Semgrep said "high"', async () => {
    const { all } = render(await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) }));
    assert.match(all, /Semgrep reported ERROR; policy maps it to high/);
  });

  it('baseline semantics are untouched: fingerprint and policy rule are unchanged by the new metadata', async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([REGISTRY_RULE_RESULT]) });
    const { createHash } = await import('node:crypto');
    const expected = createHash('sha256')
      .update(`${REGISTRY_RULE_RESULT.check_id}\0${REGISTRY_RULE_RESULT.path}\0${REGISTRY_RULE_RESULT.extra.lines.trim()}`)
      .digest('hex');
    assert.equal(gate.findings[0].fingerprint, expected);
    assert.equal(gate.findings[0].policyRule, 'sast.medium');
  });

  it('a bootstrap finding is labelled Unbaselined, never New', async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) }, { bootstrap: true });
    assert.equal(gate.findings[0].baselineState, 'unbaselined');
    const { all } = render(gate, { mode: 'log-only' });
    assert.match(all, /Unbaselined high-severity code security issue/);
    assert.doesNotMatch(all, /\bNew high-severity/);
    assert.match(gate.findings[0].reason, /unbaselined/);
  });
});

describe('Gitleaks: never described as verified; config-aware reproduction', () => {
  const CUSTOM = [{ RuleID: 'acme-internal-token', Description: 'ACME internal API token', File: 'src/config.js', StartLine: 3 }];

  it('a custom rule stays an unverified pattern match', async () => {
    const gate = await sourceGate({ gitleaks: CUSTOM });
    assert.equal(gate.findings[0].policyRule, 'secrets.unverified');
    const { all } = render(gate);
    assert.match(all, /Potential secret — unverified pattern match \(Gitleaks rule `acme-internal-token`\)/);
    assert.match(all, /ACME internal API token/);
    assert.match(all, /Gitleaks does not verify credentials/);
    assert.doesNotMatch(all, /\bVerified live credential\b/);
    assert.doesNotMatch(all, /confirmed this credential is live/);
  });

  it('ignore advice names mechanisms Gitleaks actually supports', async () => {
    const { all } = render(await sourceGate({ gitleaks: CUSTOM }));
    assert.match(all, /\.gitleaksignore/);
    assert.match(all, /gitleaks:allow/);
  });

  it('the reproduce command includes a configured .gitleaks.toml only when one was used', async () => {
    const gate = await sourceGate({ gitleaks: CUSTOM });
    assert.equal(render(gate).report.cards[0].reproduce, 'gitleaks git . --redact=100');
    const withConfig = render(gate, { context: { ...CONTEXT, scan: { gitleaksConfig: '.gitleaks.toml' } } });
    assert.equal(withConfig.report.cards[0].reproduce, 'gitleaks git . --config .gitleaks.toml --redact=100');
  });

  it('the dedicated demo marker is never described as a real credential', async () => {
    const gate = await sourceGate({ gitleaks: JSON.parse(await readFile(join(FIXTURES, 'demo-dummy-secret/gitleaks.json'), 'utf8')) });
    assert.equal(gate.findings[0].policyRule, 'secrets.demo_dummy');
    const { all } = render(gate);
    assert.match(all, /not a real credential/);
    assert.match(all, /nothing to rotate/);
    assert.doesNotMatch(all, /rotate it|Rotate\/revoke|compromised/);
  });
});

describe('TruffleHog: verified and unverified are different facts', () => {
  const git = (file, line) => ({ SourceMetadata: { Data: { Git: { file, line, commit: 'abc' } } } });

  it('Verified=true says verified, and never eligible for break-glass', async () => {
    const gate = await sourceGate({ trufflehog: [{ DetectorName: 'AWS', Verified: true, ...git('src/aws.js', 9) }] });
    assert.equal(gate.findings[0].breakGlassEligible, false);
    assert.equal(gate.breakGlass.eligible, false);
    const { all, report } = render(gate, { breakGlass: deriveBreakGlassState({ verdict: 'BLOCK', eligible: false, enabled: false }) });
    assert.match(all, /Verified live credential \(TruffleHog detector `AWS`\)/);
    assert.match(all, /Policy never allows break-glass for a verified secret/);
    assert.doesNotMatch(all, /eligible for break-glass by policy/);
    assert.equal(report.cards[0].deepLink, 'https://github.com/acme/widgets/blob/abc123def4567890/src/aws.js#L9');
  });

  it('Verified=false never claims provider verification', async () => {
    const gate = await sourceGate({ trufflehog: [{ DetectorName: 'Github', Verified: false, VerificationError: 'timeout', ...git('src/gh.js', 1) }] });
    assert.equal(gate.findings[0].policyRule, 'secrets.unverified');
    assert.equal(gate.findings[0].verificationErrored, true);
    const { all } = render(gate);
    assert.match(all, /Potential credential — not verified \(TruffleHog detector `Github`\)/);
    assert.match(all, /verification was attempted and errored/);
    assert.doesNotMatch(all, /Verified live credential|verified this credential with its provider/);
  });

  it('reproduction and exclusion advice reflect the configured exclude-paths file', async () => {
    const gate = await sourceGate({ trufflehog: [{ DetectorName: 'Github', Verified: false }] });
    const scan = { trufflehogExcludePaths: 'config/th-exclude.txt' };
    const { report, all } = render(gate, { context: { ...CONTEXT, scan } });
    assert.equal(
      report.cards[0].reproduce,
      'trufflehog git file://. --results=verified,unverified,unknown --exclude-paths=config/th-exclude.txt'
    );
    assert.match(all, /config\/th-exclude\.txt/);
  });
});

describe('npm audit: fix data is attributed to the package npm names', () => {
  const report = (vulnerabilities) => ({
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: { total: Object.keys(vulnerabilities).length } }
  });

  it('an object-valued fix for a DIFFERENT package never suggests installing that version of the vulnerable one', async () => {
    const gate = await sourceGate({
      npmAudit: report({
        minimist: {
          name: 'minimist',
          severity: 'critical',
          via: [{ title: 'Prototype Pollution in minimist', url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h' }],
          fixAvailable: { name: 'mkdirp', version: '1.0.4', isSemVerMajor: true }
        }
      })
    });
    const finding = gate.findings.find((f) => f.source === 'npm-audit');
    assert.equal(finding.fixPackage, 'mkdirp');
    const { all } = render(gate);
    assert.match(all, /updating `mkdirp` to 1\.0\.4, which pulls in a fixed `minimist`/);
    assert.match(all, /npm install mkdirp@1\.0\.4/);
    assert.match(all, /semver-major/);
    assert.doesNotMatch(all, /npm install minimist@1\.0\.4/);
    assert.match(all, /Prototype Pollution in minimist/);
    assert.match(all, /GHSA-xvch-5gv4-984h/);
  });

  it('fixAvailable:true without a target says so, and suggests npm audit fix', async () => {
    const gate = await sourceGate({ npmAudit: report({ lodash: { name: 'lodash', severity: 'high', via: ['lodash.merge'], fixAvailable: true } }) });
    const { all } = render(gate);
    assert.match(all, /did not name a target version/);
    assert.match(all, /npm audit fix/);
    assert.match(all, /depends on vulnerable `lodash\.merge`/);
  });

  it('fixAvailable:false Critical is an EXCEPTION without claiming who introduced it', async () => {
    const gate = await sourceGate({ npmAudit: JSON.parse(await readFile(join(FIXTURES, 'critical-no-fix/npm-audit.json'), 'utf8')) });
    const { all, report: built } = render(gate);
    assert.equal(built.cards[0].action, 'EXCEPTION');
    assert.equal(built.cards[0].fixedVersion, null);
    assert.match(all, /No fix is available according to the scanner data/);
    assert.doesNotMatch(all, /not something your change introduced/);
    assert.doesNotMatch(all, /npm install/);
  });
});

describe('pip-audit: the high severity is the framework default, not pip-audit', () => {
  it('fallback severity is attributed to the framework, and fix versions come from pip-audit', async () => {
    await withTempDir(async (repoDir) => {
      await writeFile(join(repoDir, 'requirements.txt'), 'requests==2.19.1\n');
      const gate = await withTempDir(async (directory) =>
        runSecurityGate({
          policy: POLICY,
          repoDir,
          gitleaks: join(CLEAN, 'gitleaks.json'),
          trufflehog: join(CLEAN, 'trufflehog.json'),
          npmAudit: join(directory, 'none.json'),
          pipAudit: join(FIXTURES, 'pip-audit/high-with-fix.json'),
          osv: join(CLEAN, 'osv-scanner.json'),
          semgrep: join(CLEAN, 'semgrep.json'),
          baseline: join(CLEAN, 'semgrep-baseline.json'),
          output: join(directory, 'gate.json'),
          exceptions: join(directory, 'exceptions.json')
        })
      );
      const finding = gate.findings.find((f) => f.source === 'pip-audit');
      assert.equal(finding.severity, 'high');
      assert.equal(finding.severitySource, 'framework-default');
      assert.deepEqual(finding.fixVersions, ['2.20.0']);
      const { all } = render(gate);
      assert.match(all, /pip-audit reports no severity\. The framework classifies every pip-audit advisory as high/);
      assert.match(all, /this is not a severity pip-audit assigned/);
      assert.match(all, /pip-audit lists fixed version\(s\): 2\.20\.0/);
      assert.match(all, /pip install 'requests==2\.20\.0'/);
      assert.doesNotMatch(all, /npm install/);
      assert.doesNotMatch(all, /High-severity vulnerability/);
    });
  });

  it('a malicious package is not rendered as a "None-severity vulnerability"', async () => {
    const gate = {
      verdict: 'BLOCK',
      findings: [{ source: 'pip-audit', id: 'MAL-2024-10573', package: 'fabrice', action: 'BLOCK', policyRule: 'dependencies.malicious_package', reason: 'x', breakGlassEligible: false }],
      breakGlass: { eligible: false }
    };
    const { all } = render(gate);
    assert.match(all, /Known-malicious package `fabrice`/);
    assert.match(all, /never allows break-glass for a malicious package/);
    assert.doesNotMatch(all, /None-severity/);
  });
});

describe('OSV-Scanner: derived severity and fix data are described as derived', () => {
  const osv = (vulnerability, pkg = { name: 'left-pad', version: '1.0.0', ecosystem: 'npm' }) => ({
    results: [{ packages: [{ package: pkg, vulnerabilities: [vulnerability] }] }]
  });

  it('a CVSS-derived severity cites the score and the framework thresholds', async () => {
    const gate = await sourceGate({ osv: JSON.parse(await readFile(join(FIXTURES, 'osv-critical-with-fix/osv-scanner.json'), 'utf8')) });
    const finding = gate.findings.find((f) => f.source === 'osv-scanner');
    assert.equal(finding.severitySource, 'cvss');
    assert.deepEqual(finding.fixVersions, ['2.0.0']);
    const { all, report } = render(gate);
    assert.match(all, /classified critical by the framework's CVSS thresholds from the record's CVSS v3 base score 9\.8/);
    assert.match(all, /OSV records a fix in version\(s\): 2\.0\.0/);
    assert.equal(report.cards[0].referenceUrl, 'https://osv.dev/vulnerability/GHSA-DEMO-WITH-FIX');
  });

  it('missing CVSS falls back to high and says it is the fail-closed default, not OSV', async () => {
    const gate = await sourceGate({
      osv: osv(
        {
          id: 'PYSEC-2099-1',
          aliases: ['CVE-2099-1'],
          affected: [{ package: { name: 'flask', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.3.2' }] }] }]
        },
        { name: 'flask', version: '2.0.0', ecosystem: 'PyPI' }
      )
    });
    const finding = gate.findings.find((f) => f.source === 'osv-scanner');
    assert.equal(finding.severity, 'high');
    assert.equal(finding.severitySource, 'framework-default');
    const { all } = render(gate);
    assert.match(all, /carries no CVSS v3 score\. The framework classifies it as high \(fail-closed\); this is not a severity OSV assigned/);
    assert.match(all, /aliases: CVE-2099-1/);
    // A PyPI package never gets an npm command. Nothing proves how flask is
    // declared (no manifest was analyzed), so no pip pin is offered either.
    assert.doesNotMatch(all, /npm install/);
    assert.doesNotMatch(all, /pip install/);
    assert.match(all, /Dependency relationship: unknown/);
    assert.match(all, /no direct pin is suggested/);
  });

  it('no fixed event means no claimed fix', async () => {
    const gate = await sourceGate({ osv: JSON.parse(await readFile(join(FIXTURES, 'osv-critical-no-fix/osv-scanner.json'), 'utf8')) });
    const { report } = render(gate);
    const card = report.cards.find((c) => c.source === 'osv-scanner');
    assert.equal(card.action, 'EXCEPTION');
    assert.equal(card.fixedVersion, null);
    assert.equal(gate.findings.find((f) => f.source === 'osv-scanner').fixVersions, undefined);
  });

  it('reproduce matches the OSV-Scanner v2 CLI the framework runs', async () => {
    const gate = await sourceGate({ osv: JSON.parse(await readFile(join(FIXTURES, 'osv-critical-with-fix/osv-scanner.json'), 'utf8')) });
    assert.equal(render(gate).report.cards[0].reproduce, 'osv-scanner scan source --recursive .');
  });
});

describe('Trivy (pre-push): vulnerability vs secret, and realistic reproduction', () => {
  it('a vulnerability carries Trivy fix data, the image target, and a tarball reproduce command', async () => {
    const gate = await imageGate(JSON.parse(await readFile(join(FIXTURES, 'image-gate/trivy-critical.json'), 'utf8')), 'trivy');
    const { report, all } = render(gate, { context: { ...CONTEXT, scan: { imageTarball: 'application-image.tar' } } });
    const card = report.cards.find((c) => c.id === 'CVE-2099-0001');
    assert.equal(card.fixedVersion, '3.5.8');
    assert.equal(card.target, 'alpine');
    assert.equal(card.deepLink, null);
    assert.equal(card.reproduce, 'trivy image --input application-image.tar --scanners vuln,secret --pkg-types os,library');
    assert.match(all, /Trivy reports a fix in 3\.5\.8/);
    assert.match(all, /libssl3` 3\.5\.7/);
  });

  it('a secret in an image is a pattern match, and never suggests break-glass', async () => {
    const gate = await imageGate(JSON.parse(await readFile(join(FIXTURES, 'image-gate/trivy-secret.json'), 'utf8')), 'trivy');
    const { all, report } = render(gate);
    const card = report.cards.find((c) => c.policyRule === 'image.secret');
    assert.equal(card.target, 'app/.npmrc');
    assert.equal(card.deepLink, null, 'an image path is not a repository path');
    assert.match(all, /Potential secret in an image layer \(Trivy rule `npm-token`\)/);
    assert.match(all, /Trivy rated it HIGH; policy blocks every secret found in an image/);
    assert.match(all, /does not verify secrets/);
    assert.match(all, /no break-glass path/);
    assert.doesNotMatch(all, /eligible for break-glass/);
  });

  it('an UNKNOWN Trivy severity is attributed to the framework default', async () => {
    const gate = await imageGate(JSON.parse(await readFile(join(FIXTURES, 'image-gate/trivy-unknown-severity.json'), 'utf8')), 'trivy');
    assert.match(render(gate).all, /Trivy reported UNKNOWN\. The framework classifies it as high \(fail-closed\)/);
  });
});

describe('ECR basic vs enhanced: only enhanced has package and fix data', () => {
  const DIGEST = 'sha256:7bb2656c990a9e3c82aa44a28bee2ee14fbcabbc9cf30c642f5c79f112b7b7d1';

  it('ECR basic does not invent fixed-version or package data', async () => {
    const gate = await imageGate(JSON.parse(await readFile(join(FIXTURES, 'image-gate/critical.json'), 'utf8')));
    const { all, report } = render(gate);
    const card = report.cards[0];
    assert.equal(card.fixedVersion, null);
    assert.equal(card.fixAvailable, undefined);
    assert.equal(card.package, null);
    assert.match(all, /ECR basic scanning/);
    assert.match(all, /supplies only a vulnerability ID and severity/);
    assert.doesNotMatch(all, /fix in \d|fixed version\(s\):|Upgrade `/);
    assert.equal(
      card.reproduce,
      'aws ecr describe-image-scan-findings --repository-name secure-software-delivery --image-id imageDigest=sha256:critical'
    );
    assert.doesNotMatch(card.reproduce, /trivy/);
  });

  it('Inspector (enhanced) findings retain per-package fix information', async () => {
    const normalized = normalizeEcrResponse(JSON.parse(await readFile(join(FIXTURES, 'ecr-enhanced/with-fix.json'), 'utf8')), {
      repository: 'secure-software-delivery',
      image_tag: 'f947250',
      image_digest: DIGEST
    });
    const gate = await imageGate(normalized);
    const finding = gate.findings[0];
    assert.equal(finding.scannerSeverity, 'CRITICAL');
    assert.equal(finding.fixAvailability, 'YES');
    assert.deepEqual(finding.packages, [{ name: 'openssl/openssl', version: '3.5.7', fixedInVersion: '4.0.2' }]);
    const { all } = render(gate);
    assert.match(all, /Amazon Inspector reports fixed version\(s\): `openssl\/openssl` 3\.5\.7 → 4\.0\.2/);
    assert.match(all, /\(Amazon Inspector\)/);
  });

  it('an Inspector UNTRIAGED severity is attributed to the framework, not Inspector', () => {
    const gate = {
      verdict: 'BLOCK_DEPLOY',
      image: { repository: 'r', imageDigest: 'sha256:x' },
      findings: [{ source: 'ecr-enhanced-scan', id: 'CVE-1', severity: 'high', scannerSeverity: 'UNTRIAGED', fixAvailable: true, fixAvailability: 'PARTIAL', action: 'BLOCK_DEPLOY', policyRule: 'image.high_with_fix', reason: 'x' }]
    };
    const { all } = render(gate);
    assert.match(all, /Amazon Inspector reported UNTRIAGED; the framework classifies it as high/);
    assert.match(all, /PARTIAL/);
    assert.doesNotMatch(all, /Inspector reported CVE-1 at high/);
  });
});

describe('report-integrity failures never look like ordinary vulnerabilities', () => {
  it('source gate: malformed Semgrep report', async () => {
    const gate = await sourceGate({ semgrep: '{ not json' });
    assert.equal(gate.integrity.trusted, false);
    const { all, report } = render(gate, { breakGlass: deriveBreakGlassState({ verdict: 'BLOCK', eligible: false, enabled: true }) });
    const card = report.cards[0];
    assert.equal(card.isIntegrity, true);
    assert.equal(card.reproduce, null);
    assert.equal(card.fixedVersion, null);
    assert.equal(report.counts.block, 0, 'an integrity failure is not also counted as a blocking finding');
    assert.equal(report.counts.integrity, 1);
    assert.match(all, /results are UNKNOWN, not clean/);
    assert.match(all, /fails closed/);
    assert.match(all, /Diagnose the scanner\/report step/);
    assert.match(all, /Do not generate or update a baseline from this run/);
    assert.match(all, /can never be overridden with break-glass/);
    assert.doesNotMatch(all, /severity vulnerability|Reproduce locally|eligible for break-glass by policy/);
  });

  it('image gate: Trivy false clean', async () => {
    const gate = await imageGate(JSON.parse(await readFile(join(FIXTURES, 'image-gate/trivy-false-clean-no-os.json'), 'utf8')), 'trivy');
    const { all, slack } = render(gate);
    assert.match(all, /UNKNOWN, not clean/);
    assert.match(slack, /Integrity failures/);
    assert.doesNotMatch(all, /vulnerability in image/);
  });

  it('log-only does not tell the developer the BLOCK must be resolved before merge', async () => {
    const gate = await sourceGate({ semgrep: '{ not json' });
    const { all } = render(gate, { mode: 'log-only' });
    assert.match(all, /NOT enforced/);
    assert.doesNotMatch(all, /must be resolved before merge/);
  });
});

// --- 3. PR comment: not applicable vs permission vs failure --------------------

describe('PR comment delivery distinguishes expected absence from failure', () => {
  const gate = { verdict: 'BLOCK', findings: [{ source: 'trufflehog', id: 'AWS', action: 'BLOCK', policyRule: 'secrets.verified', reason: 'x' }], breakGlass: { eligible: false } };

  it('workflow_dispatch without a PR is an expected, non-failing skip', async () => {
    const surfaces = fakeSurfaces();
    const performed = await dispatch({
      gate,
      context: { ...CONTEXT, prNumber: null, eventName: 'workflow_dispatch' },
      slackUrl: SLACK_URL,
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl: surfaces.fetchImpl,
      appendImpl: surfaces.appendImpl,
      logger: surfaces.logger
    });
    assert.equal(performed.prComment, false);
    assert.equal(performed.prCommentSkip, 'not-applicable');
    assert.deepEqual(performed.failures, []);
    assert.match(surfaces.logs.join('\n'), /PR comment not applicable: no pull request is associated with this run \(event: workflow_dispatch\)/);
    assert.ok(!surfaces.appended.some((chunk) => /Notification delivery incomplete/.test(chunk)));
    assert.ok(!surfaces.calls.some((call) => call.url.includes('api.github.com')));
  });

  for (const eventName of ['push', 'schedule']) {
    it(`${eventName} without a PR is not applicable`, async () => {
      const result = await upsertPrComment({ repository: 'acme/widgets', prNumber: null, token: 't', body: 'x', eventName });
      assert.equal(result.category, 'not-applicable');
    });
  }

  it('a 403 on a fork PR is expected (read-only token by design), noted but not a failure', async () => {
    const surfaces = fakeSurfaces();
    const performed = await dispatch({
      gate,
      context: { ...CONTEXT, eventName: 'pull_request', isForkPullRequest: true },
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl: async () => ({ ok: false, status: 403, json: async () => ({}) }),
      appendImpl: surfaces.appendImpl,
      logger: surfaces.logger
    });
    assert.deepEqual(performed.failures, []);
    assert.equal(performed.prCommentSkip, 'fork-read-only');
    assert.ok(surfaces.appended.some((chunk) => /Fork PRs get a read-only token by design/.test(chunk)));
  });

  it('a 403 on a same-repo PR is a permission failure with the fix named', async () => {
    const surfaces = fakeSurfaces();
    const performed = await dispatch({
      gate,
      context: { ...CONTEXT, eventName: 'pull_request', isForkPullRequest: false },
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl: async () => ({ ok: false, status: 403, json: async () => ({}) }),
      appendImpl: surfaces.appendImpl,
      logger: surfaces.logger
    });
    assert.equal(performed.prCommentSkip, 'permission');
    assert.equal(performed.failures.length, 1);
    assert.match(performed.failures[0], /pull-requests: write/);
  });

  it('a 500 is an API failure', () => {
    const classified = classifyPrCommentError(new GitHubApiError('creating PR comment failed: HTTP 500', 500), { isForkPullRequest: true });
    assert.equal(classified.category, 'api-failure');
    assert.equal(classified.expected, false);
  });

  it('a missing token on a real PR is a permission problem, not "not applicable"', async () => {
    const result = await upsertPrComment({ repository: 'acme/widgets', prNumber: 42, token: '', body: 'x', eventName: 'pull_request' });
    assert.equal(result.category, 'permission');
  });
});

// --- 4. one set of facts across all three surfaces -------------------------------

describe('Slack, PR comment and job summary present the same facts', () => {
  it('the break-glass notice and verdict blurb are identical on every surface', async () => {
    const gate = await sourceGate({ semgrep: semgrepReport([LOCAL_RULE_RESULT]) });
    const breakGlass = deriveBreakGlassState({ verdict: 'BLOCK', eligible: true, enabled: true, checkOutcome: 'success', requestOutcome: 'failure' });
    const { report, comment, summary, slack } = render(gate, { breakGlass });
    const plain = report.breakGlassNotice.replaceAll('**', '');
    assert.ok(comment.includes(report.breakGlassNotice));
    assert.ok(summary.includes(report.breakGlassNotice));
    assert.ok(JSON.parse(slack).blocks.some((block) => block.text?.text === plain));
    for (const surface of [comment, summary, slack]) {
      assert.ok(surface.includes(report.blurb));
    }
  });
});
