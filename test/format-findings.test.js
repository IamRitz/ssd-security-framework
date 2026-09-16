import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  buildReport,
  renderMarkdown,
  renderSlack,
  route,
  resolveReproduceCommands,
  DEFAULT_REPRODUCE_COMMANDS,
  PR_COMMENT_MARKER
} from '../security/scripts/format-findings.mjs';
import { dispatch, upsertPrComment } from '../security/scripts/notify.mjs';

const CONTEXT = {
  repository: 'acme/widgets',
  sha: 'abc123def4567890',
  prNumber: 42,
  runUrl: 'https://github.com/acme/widgets/actions/runs/1'
};

// Renders all three surfaces from one gate result and returns them together.
function renderAll(gate, { mode = 'enforce' } = {}) {
  const report = buildReport({ gate, context: CONTEXT, mode });
  return {
    report,
    markdown: renderMarkdown(report, { includeMarker: true }),
    summary: renderMarkdown(report, { includeMarker: false }),
    slack: renderSlack(report)
  };
}

function slackText(slack) {
  return JSON.stringify(slack.blocks);
}

// --- one gate result per finding type ---------------------------------------

const SECRET_GATE = {
  verdict: 'BLOCK',
  findings: [
    {
      source: 'trufflehog',
      id: 'AWS',
      action: 'BLOCK',
      policyRule: 'secrets.verified',
      reason: 'TruffleHog verified the credential with its provider'
    }
  ],
  breakGlass: { eligible: false }
};

const DEP_WITH_FIX_GATE = {
  verdict: 'BLOCK',
  findings: [
    {
      source: 'npm-audit',
      id: 'dangerous-package',
      severity: 'critical',
      fixAvailable: true,
      fixedVersion: '2.0.0',
      title: 'Prototype pollution in dangerous-package',
      url: 'https://github.com/advisories/GHSA-xxxx',
      action: 'BLOCK',
      policyRule: 'dependencies.critical_with_fix',
      reason: 'critical npm advisory; fix available'
    }
  ],
  breakGlass: { eligible: true }
};

const DEP_NO_FIX_GATE = {
  verdict: 'PASS-WITH-EXCEPTIONS',
  findings: [
    {
      source: 'osv-scanner',
      id: 'GHSA-nofix',
      package: 'stuck-lib',
      severity: 'high',
      fixAvailable: false,
      summary: 'Denial of service in stuck-lib',
      action: 'EXCEPTION',
      policyRule: 'dependencies.high_no_fix',
      reason: 'high OSV advisory; fix not available'
    }
  ],
  breakGlass: { eligible: false }
};

const SAST_GATE = {
  verdict: 'BLOCK',
  findings: [
    {
      source: 'semgrep',
      id: 'javascript.express.security.audit.xss',
      location: 'routes/user.js:88',
      severity: 'high',
      baselineState: 'new',
      message: 'Untrusted input reaches res.send without escaping (reflected XSS).',
      action: 'BLOCK',
      policyRule: 'sast.high_new',
      reason: 'high Semgrep finding is new'
    }
  ],
  breakGlass: { eligible: true }
};

const TRIVY_WITH_FIX_GATE = {
  verdict: 'BLOCK_DEPLOY',
  findings: [
    {
      source: 'trivy',
      id: 'CVE-2099-0001',
      package: 'libssl3',
      severity: 'critical',
      fixAvailable: true,
      fixedVersion: '3.5.8',
      title: 'OpenSSL buffer overflow',
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.critical_with_fix',
      reason: 'critical image finding; fix available'
    }
  ]
};

const TRIVY_NO_FIX_GATE = {
  verdict: 'DEPLOY-WITH-EXCEPTIONS',
  findings: [
    {
      source: 'trivy',
      id: 'CVE-2099-0002',
      package: 'zlib',
      severity: 'high',
      fixAvailable: false,
      action: 'EXCEPTION',
      policyRule: 'image.high_no_fix',
      reason: 'high image finding; fix not available'
    }
  ]
};

const TRIVY_SECRET_GATE = {
  verdict: 'BLOCK_DEPLOY',
  findings: [
    {
      source: 'trivy',
      id: 'aws-access-key',
      severity: 'critical',
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.secret',
      reason: 'secret detected in image layer (AWS Access Key)'
    }
  ]
};

const TRIVY_FALSE_CLEAN_GATE = {
  verdict: 'BLOCK_DEPLOY',
  findings: [
    {
      source: 'image-gate',
      id: 'report-integrity',
      severity: 'unknown',
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.report_integrity',
      reason: 'Trivy did not detect an OS family — a zero-finding result would be a false clean'
    }
  ]
};

const TRIVY_EOSL_GATE = {
  verdict: 'BLOCK_DEPLOY',
  findings: [
    {
      source: 'image-gate',
      id: 'report-integrity',
      severity: 'unknown',
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.report_integrity',
      reason: 'OS debian is end-of-life (EOSL) — no advisories'
    }
  ]
};

const ECR_SEVERITY_ONLY_GATE = {
  verdict: 'BLOCK_DEPLOY',
  findings: [
    {
      source: 'ecr-image-scan',
      id: 'CVE-2098-1111',
      severity: 'high',
      action: 'BLOCK_DEPLOY',
      policyRule: 'image.high',
      reason: 'high image finding'
    }
  ]
};

const INTEGRITY_GATE = {
  verdict: 'BLOCK',
  findings: [
    {
      source: 'security-gate',
      id: 'report-integrity',
      action: 'BLOCK',
      policyRule: 'gate.report_integrity',
      reason: 'Semgrep: malformed JSON in reports/semgrep.json',
      breakGlassEligible: false
    }
  ],
  breakGlass: { eligible: false }
};

const CASES = [
  ['secret (verified)', SECRET_GATE, /Verified leaked credential/],
  ['dependency with_fix', DEP_WITH_FIX_GATE, /dependency `dangerous-package`/],
  ['dependency no_fix (exception)', DEP_NO_FIX_GATE, /dependency `stuck-lib`/],
  ['sast', SAST_GATE, /code security issue in `routes\/user\.js`/],
  ['trivy image with_fix', TRIVY_WITH_FIX_GATE, /image package `libssl3`/],
  ['trivy image no_fix (exception)', TRIVY_NO_FIX_GATE, /image package `zlib`/],
  ['trivy layer secret', TRIVY_SECRET_GATE, /Secret baked into an image layer/],
  ['trivy false-clean integrity', TRIVY_FALSE_CLEAN_GATE, /Scan integrity failure/],
  ['trivy eosl integrity', TRIVY_EOSL_GATE, /Scan integrity failure/],
  ['ecr severity-only', ECR_SEVERITY_ONLY_GATE, /vulnerability in image \(CVE-2098-1111\)/],
  ['generic integrity (malformed report)', INTEGRITY_GATE, /Scan integrity failure/]
];

describe('format-findings: every finding type renders on all three surfaces', () => {
  for (const [name, gate, titlePattern] of CASES) {
    it(name, () => {
      const { markdown, summary, slack } = renderAll(gate);
      // PR comment carries the plain-language title and the update marker.
      assert.match(markdown, titlePattern);
      assert.ok(markdown.includes(PR_COMMENT_MARKER));
      // Job summary is the same content without the marker.
      assert.match(summary, titlePattern);
      assert.ok(!summary.includes(PR_COMMENT_MARKER));
      // Slack renders a valid Block Kit payload with a header + the verdict.
      assert.equal(slack.blocks[0].type, 'header');
      assert.ok(typeof slack.text === 'string' && slack.text.length > 0);
      assert.ok(slackText(slack).length > 0);
    });
  }
});

describe('format-findings: integrity failures are not rendered as vulnerabilities', () => {
  it('says plainly it is an integrity failure, not a code defect', () => {
    const { markdown } = renderAll(TRIVY_FALSE_CLEAN_GATE);
    assert.match(markdown, /not a (code defect|vulnerability you introduced)/);
    assert.match(markdown, /blocked deliberately rather than passed/);
  });
});

describe('format-findings: exceptions are labelled as passed-deliberately, not-your-fault', () => {
  it('dependency no_fix exception explains it passed and is not actionable', () => {
    const { markdown } = renderAll(DEP_NO_FIX_GATE);
    assert.match(markdown, /No upstream fix is available/);
    assert.match(markdown, /tracked EXCEPTION/);
  });
});

describe('format-findings: fix rendering asymmetry (Trivy fix data vs ECR severity-only)', () => {
  it('Trivy with_fix surfaces the fixed version and upgrade command', () => {
    const { markdown } = renderAll(TRIVY_WITH_FIX_GATE);
    assert.match(markdown, /3\.5\.8/);
  });
  it('ECR severity-only does not fabricate fix data', () => {
    const { markdown } = renderAll(ECR_SEVERITY_ONLY_GATE);
    assert.match(markdown, /does not report a fixed version/);
    assert.ok(!/Upgrade image package .* to \d/.test(markdown));
  });
});

describe('format-findings: every verdict renders distinctly', () => {
  const verdicts = [
    ['PASS', { verdict: 'PASS', findings: [] }, 'PASS'],
    ['BLOCK', SECRET_GATE, 'BLOCK'],
    ['EXCEPTION', DEP_NO_FIX_GATE, 'EXCEPTION'],
    ['DEPLOY-WITH-EXCEPTIONS', TRIVY_NO_FIX_GATE, 'DEPLOY-WITH-EXCEPTIONS'],
    ['BLOCK_DEPLOY', TRIVY_WITH_FIX_GATE, 'BLOCK_DEPLOY']
  ];
  const labels = new Set();
  for (const [name, gate, expectedLabel] of verdicts) {
    it(name, () => {
      const report = buildReport({ gate, context: CONTEXT });
      assert.equal(report.verdictLabel, expectedLabel);
      const md = renderMarkdown(report);
      assert.match(md, new RegExp(`Security gate: ${expectedLabel.replace(/[-]/g, '\\-')}`));
      labels.add(report.verdictLabel);
    });
  }
  it('all five labels are unique', () => {
    assert.equal(labels.size, 5);
  });
});

// --- routing -----------------------------------------------------------------

describe('route: per-verdict and per-mode', () => {
  it('BLOCK routes to all three surfaces', () => {
    assert.deepEqual(route({ verdict: 'BLOCK' }), { slack: true, prComment: true, summary: true });
  });
  it('BLOCK_DEPLOY routes to all three surfaces', () => {
    assert.deepEqual(route({ verdict: 'BLOCK_DEPLOY' }), { slack: true, prComment: true, summary: true });
  });
  it('EXCEPTION verdict routes to PR + summary, not Slack', () => {
    assert.deepEqual(route({ verdict: 'PASS-WITH-EXCEPTIONS' }), {
      slack: false,
      prComment: true,
      summary: true
    });
  });
  it('log-only mode never routes Slack even on BLOCK', () => {
    assert.deepEqual(route({ verdict: 'BLOCK', mode: 'log-only' }), {
      slack: false,
      prComment: true,
      summary: true
    });
  });
  it('break-glass eligible BLOCK suppresses the plain Slack ping', () => {
    assert.equal(route({ verdict: 'BLOCK', isBreakGlassEligible: true }).slack, false);
  });
});

// --- dispatch honours routing with fake surfaces -----------------------------

function fakeSurfaces() {
  const calls = { fetch: [], append: [] };
  const fetchImpl = async (url, options) => {
    calls.fetch.push({ url, options });
    // GET comment list -> empty; everything else -> ok.
    if (typeof url === 'string' && url.includes('/comments') && (!options || options.method === undefined)) {
      return { ok: true, json: async () => [] };
    }
    return { ok: true, json: async () => ({}) };
  };
  const appendImpl = async (path, data) => {
    calls.append.push({ path, data });
  };
  return { calls, fetchImpl, appendImpl };
}

describe('dispatch: routing produces the right surface calls', () => {
  it('log-only mode makes no Slack call', async () => {
    const { calls, fetchImpl, appendImpl } = fakeSurfaces();
    const performed = await dispatch({
      gate: SECRET_GATE,
      context: CONTEXT,
      mode: 'log-only',
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl,
      logger: { log() {} }
    });
    assert.equal(performed.slack, false);
    assert.equal(performed.summary, true);
    assert.equal(performed.prComment, true);
    // No fetch call targeted the Slack URL.
    assert.ok(!calls.fetch.some((c) => c.url === 'https://slack.example/hook'));
  });

  it('EXCEPTION routes to PR + summary but not Slack', async () => {
    const { calls, fetchImpl, appendImpl } = fakeSurfaces();
    const performed = await dispatch({
      gate: DEP_NO_FIX_GATE,
      context: CONTEXT,
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl,
      logger: { log() {} }
    });
    assert.equal(performed.slack, false);
    assert.equal(performed.prComment, true);
    assert.equal(performed.summary, true);
    assert.ok(!calls.fetch.some((c) => c.url === 'https://slack.example/hook'));
  });

  it('BLOCK posts to Slack, PR, and summary', async () => {
    const { calls, fetchImpl, appendImpl } = fakeSurfaces();
    const performed = await dispatch({
      gate: SECRET_GATE,
      context: CONTEXT,
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl,
      logger: { log() {} }
    });
    assert.equal(performed.slack, true);
    assert.equal(performed.prComment, true);
    assert.equal(performed.summary, true);
    assert.ok(calls.fetch.some((c) => c.url === 'https://slack.example/hook'));
    assert.equal(calls.append.length, 1);
  });

  it('break-glass eligible BLOCK does not post the plain Slack ping', async () => {
    const { calls, fetchImpl, appendImpl } = fakeSurfaces();
    const performed = await dispatch({
      gate: DEP_WITH_FIX_GATE,
      context: CONTEXT,
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl,
      logger: { log() {} }
    });
    assert.equal(performed.slack, false);
    assert.ok(!calls.fetch.some((c) => c.url === 'https://slack.example/hook'));
  });
});

// --- PR comment hygiene: find-by-marker then update --------------------------

describe('upsertPrComment: updates the existing marked comment', () => {
  it('PATCHes the marked comment instead of posting a new one', async () => {
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' });
      if (url.includes('/comments') && options.method === undefined) {
        return {
          ok: true,
          json: async () => [{ id: 7, body: `stale\n${PR_COMMENT_MARKER}` }]
        };
      }
      return { ok: true, json: async () => ({}) };
    };
    const result = await upsertPrComment({
      repository: 'acme/widgets',
      prNumber: 42,
      token: 'gh',
      body: `fresh\n${PR_COMMENT_MARKER}`,
      fetchImpl
    });
    assert.deepEqual(result, { updated: true, id: 7 });
    assert.ok(calls.some((c) => c.method === 'PATCH' && c.url.includes('/comments/7')));
    assert.ok(!calls.some((c) => c.method === 'POST'));
  });

  it('POSTs a new comment when none is marked', async () => {
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' });
      if (url.includes('/comments') && options.method === undefined) {
        return { ok: true, json: async () => [{ id: 1, body: 'unrelated' }] };
      }
      return { ok: true, json: async () => ({}) };
    };
    const result = await upsertPrComment({
      repository: 'acme/widgets',
      prNumber: 42,
      token: 'gh',
      body: `fresh\n${PR_COMMENT_MARKER}`,
      fetchImpl
    });
    assert.deepEqual(result, { created: true });
    assert.ok(calls.some((c) => c.method === 'POST'));
  });
});

describe('dispatch: resilience when a remote surface fails on a BLOCK', () => {
  it('still writes the full job summary and records the failure instead of throwing', async () => {
    const appended = [];
    const appendImpl = async (_path, data) => {
      appended.push(data);
    };
    // Every network call fails (e.g. a 403 read-only token on a fork PR, or an
    // outage). The local job summary must still land, carrying the full findings.
    const fetchImpl = async () => {
      throw new Error('network down');
    };
    const performed = await dispatch({
      gate: SECRET_GATE,
      context: CONTEXT,
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl,
      logger: { log() {}, error() {} }
    });

    // Did not throw; failure is reported, not silent.
    assert.equal(performed.summary, true);
    assert.equal(performed.prComment, false);
    assert.equal(performed.slack, false);
    assert.equal(performed.failures.length, 2);
    // The primary summary content landed first...
    assert.match(appended[0], /Verified leaked credential/);
    assert.match(appended[0], /Security gate: BLOCK/);
    // ...and a visible delivery-failure note was appended afterwards.
    assert.ok(appended.some((chunk) => /Notification delivery incomplete/.test(chunk)));
  });

  it('a Slack failure does not suppress the PR comment (surfaces are independent)', async () => {
    const appended = [];
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' });
      if (url === 'https://slack.example/hook') {
        throw new Error('slack outage');
      }
      if (url.includes('/comments') && options.method === undefined) {
        return { ok: true, json: async () => [] };
      }
      return { ok: true, json: async () => ({}) };
    };
    const performed = await dispatch({
      gate: SECRET_GATE,
      context: CONTEXT,
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl: async (_p, d) => appended.push(d),
      logger: { log() {}, error() {} }
    });
    assert.equal(performed.prComment, true); // posted despite Slack failing
    assert.equal(performed.slack, false);
    assert.deepEqual(performed.failures, [performed.failures[0]].filter(Boolean));
    assert.ok(performed.failures[0].startsWith('Slack'));
    assert.ok(calls.some((c) => c.method === 'POST' && c.url.includes('/comments')));
  });
});

describe('upsertPrComment: clean-run update-only behaviour', () => {
  it('does NOT create a comment on a clean run when none exists (updateOnly)', async () => {
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' });
      if (url.includes('/comments') && options.method === undefined) {
        return { ok: true, json: async () => [] }; // no existing comment
      }
      return { ok: true, json: async () => ({}) };
    };
    const result = await upsertPrComment({
      repository: 'acme/widgets',
      prNumber: 41,
      token: 'gh',
      body: `clean\n${PR_COMMENT_MARKER}`,
      updateOnly: true,
      fetchImpl
    });
    assert.equal(result.skipped, true);
    assert.ok(!calls.some((c) => c.method === 'POST'));
  });

  it('DOES flip an existing red comment to green on a clean run (updateOnly)', async () => {
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' });
      if (url.includes('/comments') && options.method === undefined) {
        return { ok: true, json: async () => [{ id: 9, body: `⛔ BLOCK\n${PR_COMMENT_MARKER}` }] };
      }
      return { ok: true, json: async () => ({}) };
    };
    const result = await upsertPrComment({
      repository: 'acme/widgets',
      prNumber: 41,
      token: 'gh',
      body: `✅ DEPLOY\n${PR_COMMENT_MARKER}`,
      updateOnly: true,
      fetchImpl
    });
    assert.deepEqual(result, { updated: true, id: 9 });
    assert.ok(calls.some((c) => c.method === 'PATCH' && c.url.includes('/comments/9')));
  });
});

describe('dispatch: a clean DEPLOY posts no new PR comment but still writes the summary', () => {
  it('skips creating a PR comment when the run is clean and none exists', async () => {
    const cleanGate = { verdict: 'DEPLOY', findings: [] };
    const appended = [];
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' });
      if (url.includes('/comments') && options.method === undefined) {
        return { ok: true, json: async () => [] };
      }
      return { ok: true, json: async () => ({}) };
    };
    const performed = await dispatch({
      gate: cleanGate,
      context: CONTEXT,
      slackUrl: 'https://slack.example/hook',
      token: 'gh-token',
      summaryPath: '/tmp/summary',
      fetchImpl,
      appendImpl: async (_p, d) => appended.push(d),
      logger: { log() {}, error() {} }
    });
    assert.equal(performed.prComment, false); // nothing created
    assert.equal(performed.summary, true); // summary still written
    assert.equal(performed.slack, false); // clean -> no ping
    assert.ok(!calls.some((c) => c.method === 'POST'));
    assert.match(appended[0], /Security gate: DEPLOY/);
  });
});

// --- scale: a repo-sized finding count stays readable ------------------------

describe('format-findings: repo-scale finding count renders readably', () => {
  // Mirrors the real Trivy scan of node:22.23.2-alpine3.24: 38 findings,
  // 12 block / 0 exception / 26 log.
  function scaleGate() {
    const findings = [];
    for (let i = 0; i < 12; i += 1) {
      findings.push({
        source: 'trivy',
        id: `CVE-2099-1${String(i).padStart(3, '0')}`,
        package: `pkg-block-${i}`,
        severity: i % 2 ? 'critical' : 'high',
        fixAvailable: true,
        fixedVersion: '1.2.3',
        action: 'BLOCK_DEPLOY',
        policyRule: 'image.critical_with_fix',
        reason: 'fix available'
      });
    }
    for (let i = 0; i < 26; i += 1) {
      findings.push({
        source: 'trivy',
        id: `CVE-2099-2${String(i).padStart(3, '0')}`,
        package: `pkg-log-${i}`,
        severity: 'medium',
        fixAvailable: false,
        action: 'LOG',
        policyRule: 'image.medium',
        reason: 'logged'
      });
    }
    return { verdict: 'BLOCK_DEPLOY', findings };
  }

  it('collapses long lists behind <details> and keeps blocking findings visible', () => {
    const report = buildReport({ gate: scaleGate(), context: CONTEXT });
    assert.deepEqual(report.counts, { block: 12, exception: 0, log: 26, integrity: 0 });
    const md = renderMarkdown(report);
    // The 26 logged findings collapse; the 12 blocking findings do not.
    assert.match(md, /<details><summary>Show 26 findings<\/summary>/);
    assert.ok(!/<details><summary>Show 12/.test(md));
    // Slack stays concise: at most 5 highlighted blocking findings + a "more" note.
    const slack = renderSlack(report);
    assert.match(slackText(slack), /and 7 more/);
  });
});

// Developer guidance must be portable: a consumer repo has no Makefile of ours,
// and a wrong local command is worse than none.
describe('format-findings: reproduce commands are per-repo, not this repo', () => {
  const SEMGREP_GATE = {
    verdict: 'BLOCK',
    findings: [
      {
        source: 'semgrep',
        id: 'rules.command-injection',
        severity: 'high',
        action: 'BLOCK',
        policyRule: 'sast.high_new',
        location: 'src/app.js:10',
        message: 'Command injection',
        reason: 'high Semgrep finding is new'
      }
    ]
  };

  it('defaults to a direct scanner invocation, never a Makefile target', () => {
    const report = buildReport({ gate: SEMGREP_GATE, context: CONTEXT });
    assert.equal(report.cards[0].reproduce, DEFAULT_REPRODUCE_COMMANDS.semgrep);
    assert.ok(!/\bmake\b/.test(report.cards[0].reproduce));
    assert.match(renderMarkdown(report), /Reproduce locally/);
  });

  it('uses the per-repo override when the workflow supplies one', () => {
    const report = buildReport({
      gate: SEMGREP_GATE,
      context: { ...CONTEXT, reproduceCommands: resolveReproduceCommands('{"semgrep":"make sast"}') }
    });
    assert.equal(report.cards[0].reproduce, 'make sast');
  });

  it('keeps the portable defaults for sources the override omits', () => {
    const commands = resolveReproduceCommands('{"semgrep":"make sast"}');
    assert.equal(commands.semgrep, 'make sast');
    assert.equal(commands['npm-audit'], DEFAULT_REPRODUCE_COMMANDS['npm-audit']);
  });

  it('falls back to the defaults rather than crashing on unusable input', () => {
    for (const raw of ['', '   ', 'not json', '["a"]', 'null', '42', undefined]) {
      assert.deepEqual(resolveReproduceCommands(raw), DEFAULT_REPRODUCE_COMMANDS);
    }
    // Non-string values inside a valid object are ignored, not rendered.
    assert.equal(resolveReproduceCommands('{"semgrep":7}').semgrep, DEFAULT_REPRODUCE_COMMANDS.semgrep);
  });
});
