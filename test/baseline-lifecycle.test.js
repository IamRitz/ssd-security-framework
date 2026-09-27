// The Semgrep baseline LIFECYCLE at runtime: `absent` vs `accepted`, and the
// legacy caller that declares neither.
//
// Live reproducer (ssd-scratch-consumer PR #1, run 35621646051): a source-only
// consumer in onboarding — semgrep.baseline.state: absent, no baseline file,
// log-only, an ordinary pull_request, bootstrap_baseline false. Every scanner
// succeeded, yet the gate reported
//
//   BLOCK security-gate report-integrity (gate.report_integrity):
//   Semgrep baseline: missing report file security/baseline/semgrep-baseline.json
//   scan trusted: false
//
// because the runtime was never told the state: it saw only a path, and a
// missing path is indistinguishable from a deleted baseline. The caller now
// declares the lifecycle (`semgrep_baseline_state`), and these tests pin:
//
//   absent   + no file        trusted, empty accepted set, findings are NEW,
//                             no candidate unless this run is a bootstrap
//   absent   + file exists    fail closed (inconsistent lifecycle)
//   accepted + missing/broken fail closed
//   unspecified (legacy)      exactly the old behaviour: missing is a BLOCK
//
// and that `absent` never masks an unrelated scanner-report failure.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, describe, it } from 'node:test';

import { buildProvenance } from '../security/scripts/baseline-provenance.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';
import { stepScript } from './support/workflow-steps.mjs';

const FRAMEWORK = resolve('.');
const FIXTURES = join(FRAMEWORK, 'security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
// One new high-severity SAST finding: with an empty accepted set it is `new`
// and BLOCKs on its own merits, which is how a real finding must still surface.
const NEW_HIGH_SEMGREP = join(FIXTURES, 'new-high-sast/semgrep.json');
const POLICY = join(FRAMEWORK, 'security/policy.yaml');
const BASELINE = 'security/baseline/semgrep-baseline.json';
const LIVE_MESSAGE = `Semgrep baseline: missing report file ${BASELINE}`;

const WORK = mkdtempSync(join(tmpdir(), 'baseline-lifecycle-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

let consumers = 0;
// A consumer checkout as the gate job sees it: every scanner report downloaded
// into reports/, and (optionally) something at the baseline path.
function consumer({ baseline, semgrep = NEW_HIGH_SEMGREP, omit = [] } = {}) {
  const dir = join(WORK, `consumer-${(consumers += 1)}`);
  mkdirSync(join(dir, 'reports'), { recursive: true });
  mkdirSync(join(dir, 'security/baseline'), { recursive: true });
  for (const name of ['gitleaks.json', 'trufflehog.json', 'osv-scanner.json']) {
    if (!omit.includes(name)) {
      writeFileSync(join(dir, 'reports', name), readFileSync(join(CLEAN, name)));
    }
  }
  writeFileSync(join(dir, 'reports/semgrep.json'), typeof semgrep === 'string' && semgrep.startsWith('/') ? readFileSync(semgrep) : semgrep);
  if (typeof baseline === 'function') {
    baseline(join(dir, BASELINE));
  } else if (baseline !== undefined) {
    writeFileSync(join(dir, BASELINE), typeof baseline === 'string' ? baseline : JSON.stringify(baseline));
  }
  return dir;
}

function gate(dir, { state, bootstrap = false } = {}) {
  return runSecurityGate({
    policy: POLICY,
    repoDir: dir,
    gitleaks: join(dir, 'reports/gitleaks.json'),
    trufflehog: join(dir, 'reports/trufflehog.json'),
    npmAudit: join(dir, 'reports/npm-audit.json'),
    pipAudit: join(dir, 'reports/pip-audit.json'),
    osv: join(dir, 'reports/osv-scanner.json'),
    semgrep: join(dir, 'reports/semgrep.json'),
    semgrepExecution: join(dir, 'reports/scanner-execution-semgrep.json'),
    baseline: join(dir, BASELINE),
    output: join(dir, 'reports/security-gate.json'),
    exceptions: join(dir, 'reports/gate-exceptions.json'),
    ...(state === undefined ? {} : { baselineState: state }),
    ...(bootstrap ? { bootstrap: true } : {})
  });
}

const semgrepFindings = (result) => result.findings.filter((finding) => finding.source === 'semgrep');
const acceptedBaselineFor = (dir) => {
  const [finding] = semgrepFindings(JSON.parse(readFileSync(join(dir, 'reports/security-gate.json'), 'utf8')));
  return { schemaVersion: 1, findings: [{ fingerprint: finding.fingerprint, checkId: finding.id, path: 'app.js' }] };
};

// Would this gate result let a candidate baseline be recorded? Provenance is
// what `ssd-onboard baseline prepare/accept` requires, so a refusal here means
// no candidate can come out of the run.
function provenanceFor(result) {
  return buildProvenance({
    env: {
      CI_REPOSITORY: 'acme/app', CI_REPOSITORY_ID: '1', CI_DEFAULT_BRANCH: 'main', CI_SHA: 'a'.repeat(40),
      CI_REF: 'refs/heads/main', CI_EVENT: 'workflow_dispatch', CI_RUN_ID: '1', CI_RUN_ATTEMPT: '1',
      TOOLKIT_REPOSITORY: 'IamRitz/ssd-security-framework', TOOLKIT_REF: 'b'.repeat(40),
      SEMGREP_CONFIGS: 'p/owasp-top-ten', SEMGREP_PATHS: '.', BASELINE_PATH: BASELINE
    },
    candidateBytes: Buffer.from(JSON.stringify({ schemaVersion: 1, findings: [] })),
    gate: result,
    semgrepignoreBytes: null
  });
}

// ---- absent -------------------------------------------------------------------

describe('state absent, no baseline file (onboarding)', () => {
  it('an ordinary run (the live PR reproducer) is TRUSTED and evaluates against an empty accepted set', async () => {
    const result = await gate(consumer(), { state: 'absent' });

    assert.equal(result.integrity.trusted, true, JSON.stringify(result.integrity.failures));
    assert.deepEqual(result.integrity.failures, []);
    assert.ok(!result.findings.some((f) => f.id === 'report-integrity'), 'a missing baseline is not a report-integrity failure');
    assert.deepEqual(result.semgrepBaseline, { state: 'absent', acceptedFindings: 0 });
    assert.equal(result.bootstrap.active, false, 'absent is not bootstrap');
  });

  it('findings are still evaluated normally: NEW, and a real BLOCK stays a BLOCK', async () => {
    const result = await gate(consumer(), { state: 'absent' });
    const [finding] = semgrepFindings(result);

    assert.equal(finding.baselineState, 'new');
    assert.equal(finding.policyRule, 'sast.high_new');
    assert.equal(finding.action, 'BLOCK');
    assert.equal(result.verdict, 'BLOCK', 'finding-driven, and log-only may suppress it — but trust stays true');
    assert.equal(result.integrity.trusted, true);
  });

  it('with no findings, the verdict is PASS', async () => {
    const result = await gate(consumer({ semgrep: join(CLEAN, 'semgrep.json') }), { state: 'absent' });
    assert.equal(result.verdict, 'PASS');
    assert.equal(result.integrity.trusted, true);
  });

  it('without bootstrap, NO candidate can come out of the run (PR, or a dispatch with the box unticked)', async () => {
    const result = await gate(consumer(), { state: 'absent' });
    assert.throws(() => provenanceFor(result), /was not a baseline bootstrap/);
  });

  it('with bootstrap (dispatch), the run is trusted, auditable, and a candidate CAN be recorded', async () => {
    const result = await gate(consumer(), { state: 'absent', bootstrap: true });

    assert.equal(result.integrity.trusted, true);
    assert.equal(result.bootstrap.active, true);
    assert.deepEqual(result.semgrepBaseline, { state: 'absent', acceptedFindings: 0 });
    assert.equal(semgrepFindings(result)[0].baselineState, 'unbaselined');
    assert.equal(provenanceFor(result).gate.bootstrapActive, true);
  });

  it('does NOT mask an unrelated report failure: a malformed Semgrep report is still untrusted', async () => {
    const result = await gate(consumer({ semgrep: '{"not":"semgrep"' }), { state: 'absent' });
    assert.equal(result.integrity.trusted, false);
    assert.equal(result.integrity.failures[0].control, 'sast');
  });

  it('does NOT mask an unrelated report failure: a Semgrep report with scan errors is still untrusted', async () => {
    const errored = JSON.stringify({ version: '1', results: [], errors: [{ message: 'boom' }], paths: { scanned: [] } });
    const result = await gate(consumer({ semgrep: errored }), { state: 'absent' });
    assert.equal(result.integrity.trusted, false);
    assert.match(result.integrity.failures[0].reason, /contains 1 errors/);
  });

  it('does NOT mask an unrelated report failure: a missing secret-scan report is still untrusted', async () => {
    const result = await gate(consumer({ omit: ['gitleaks.json'] }), { state: 'absent' });
    assert.equal(result.integrity.trusted, false);
    assert.equal(result.integrity.failures[0].control, 'secret-scan');
  });
});

describe('state absent, but something exists at the baseline path (inconsistent lifecycle)', () => {
  it('a valid baseline that exists anyway fails closed and is NOT silently used', async () => {
    const dir = consumer();
    await gate(dir, { state: 'absent' });
    // A baseline that WOULD accept the finding: if it were used, the verdict
    // would pass. It must not be.
    writeFileSync(join(dir, BASELINE), JSON.stringify(acceptedBaselineFor(dir)));
    const result = await gate(dir, { state: 'absent' });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(result.integrity.trusted, false);
    assert.equal(result.integrity.failures[0].control, 'source-gate');
    assert.match(result.integrity.failures[0].reason, /inconsistent lifecycle: semgrep baseline state is 'absent' but .* exists/);
  });

  it('a directory or a dangling symbolic link at the path is also inconsistent', async () => {
    for (const make of [(path) => mkdirSync(path), (path) => symlinkSync(join(WORK, 'nowhere.json'), path)]) {
      const result = await gate(consumer({ baseline: make }), { state: 'absent' });
      assert.equal(result.integrity.trusted, false);
      assert.match(result.integrity.failures[0].reason, /inconsistent lifecycle/);
    }
  });

  it('bootstrap over an existing file is refused, exactly as before', async () => {
    const result = await gate(consumer({ baseline: { schemaVersion: 1, findings: [] } }), { state: 'absent', bootstrap: true });
    assert.equal(result.integrity.trusted, false);
    assert.match(result.integrity.failures[0].reason, /^bootstrap refused: a Semgrep baseline already exists/);
  });
});

// ---- accepted -----------------------------------------------------------------

describe('state accepted', () => {
  it('a missing baseline fails closed: BLOCK, untrusted, blamed on the gate', async () => {
    const result = await gate(consumer(), { state: 'accepted' });
    assert.equal(result.verdict, 'BLOCK');
    assert.equal(result.integrity.trusted, false);
    assert.equal(result.integrity.failures[0].control, 'source-gate');
    assert.match(result.integrity.failures[0].reason, /^Semgrep baseline: missing report file /);
    assert.deepEqual(result.semgrepBaseline, { state: 'accepted' });
  });

  it('a malformed baseline fails closed: invalid JSON', async () => {
    const result = await gate(consumer({ baseline: '{"schemaVersion": 1, "findings": [' }), { state: 'accepted' });
    assert.equal(result.verdict, 'BLOCK');
    assert.equal(result.integrity.trusted, false);
    assert.match(result.integrity.failures[0].reason, /Semgrep baseline: malformed JSON/);
  });

  it('a malformed baseline fails closed: wrong shape', async () => {
    for (const bad of [{ schemaVersion: 2, findings: [] }, { schemaVersion: 1 }, { schemaVersion: 1, findings: [{ checkId: 'x', path: 'y' }] }]) {
      const result = await gate(consumer({ baseline: bad }), { state: 'accepted' });
      assert.equal(result.verdict, 'BLOCK', JSON.stringify(bad));
      assert.equal(result.integrity.trusted, false, JSON.stringify(bad));
      assert.equal(result.integrity.failures[0].control, 'source-gate');
    }
  });

  it('a valid baseline is used: the finding it accepts is existing, the run is trusted', async () => {
    const dir = consumer();
    await gate(dir, { state: 'absent' });
    writeFileSync(join(dir, BASELINE), JSON.stringify(acceptedBaselineFor(dir)));
    const result = await gate(dir, { state: 'accepted' });

    assert.equal(result.integrity.trusted, true);
    assert.equal(semgrepFindings(result)[0].baselineState, 'existing');
    assert.deepEqual(result.semgrepBaseline, { state: 'accepted', acceptedFindings: 1 });
  });

  it('bootstrap is refused: a candidate can never replace an accepted baseline', async () => {
    for (const baseline of [undefined, { schemaVersion: 1, findings: [] }]) {
      const result = await gate(consumer({ baseline }), { state: 'accepted', bootstrap: true });
      assert.equal(result.integrity.trusted, false);
      assert.match(result.integrity.failures[0].reason, /^bootstrap refused: semgrep baseline state is 'accepted'/);
    }
  });
});

// ---- legacy ---------------------------------------------------------------------

describe('a legacy caller that declares no lifecycle', () => {
  it('a missing baseline is still a report-integrity BLOCK — the exact live failure', async () => {
    for (const state of [undefined, null, '']) {
      const dir = consumer();
      const result = await gate(dir, { state });
      assert.equal(result.verdict, 'BLOCK');
      assert.equal(result.integrity.trusted, false);
      assert.equal(result.integrity.failures[0].reason, `Semgrep baseline: missing report file ${join(dir, BASELINE)}`);
      assert.deepEqual(result.semgrepBaseline, { state: 'unspecified' });
    }
  });

  it('legacy bootstrap is unchanged: trusted with no file, refused over an existing one', async () => {
    const fresh = await gate(consumer(), { bootstrap: true });
    assert.equal(fresh.integrity.trusted, true);
    assert.equal(fresh.bootstrap.active, true);
    const existing = await gate(consumer({ baseline: { schemaVersion: 1, findings: [] } }), { bootstrap: true });
    assert.match(existing.integrity.failures[0].reason, /^bootstrap refused: a Semgrep baseline already exists/);
  });

  it('an unsupported state is a STRUCTURED report-integrity BLOCK, never read as absent or legacy', async () => {
    for (const state of ['bogus', 'Absent', 'none', 'accepted ', 'true']) {
      const dir = consumer();
      const result = await gate(dir, { state });

      assert.equal(result.verdict, 'BLOCK', state);
      assert.equal(result.integrity.trusted, false, state);
      assert.equal(result.findings.length, 1, state);
      const [finding] = result.findings;
      assert.equal(finding.id, 'report-integrity');
      assert.equal(finding.policyRule, 'gate.report_integrity');
      assert.equal(finding.control, 'source-gate');
      assert.equal(result.integrity.failures[0].control, 'source-gate');
      assert.equal(finding.reason, `unsupported Semgrep baseline state '${state}'; expected one of absent, accepted`);
      assert.equal(finding.breakGlassEligible, false);
      assert.equal(result.breakGlass.eligible, false);
      assert.deepEqual(result.semgrepBaseline, { state: 'invalid', declared: state });
      // WRITTEN, so everything downstream explains the failure from it.
      assert.deepEqual(JSON.parse(readFileSync(join(dir, 'reports/security-gate.json'), 'utf8')), result);
    }
  });
});

// ---- the real workflow steps ------------------------------------------------------

// Executes the gate job's REAL `run:` scripts — policy evaluation, then the
// verdict publication the gate-mode and generation steps read — in a consumer
// checkout, against the toolkit in this repository. Both source workflows.
function runGateSteps(file, dir, { state = '', bootstrap = 'false', event = 'pull_request' } = {}) {
  const outputs = join(dir, 'github-output');
  writeFileSync(outputs, '');
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    SSD_TOOLKIT: join(FRAMEWORK, 'security'),
    SSD_POLICY: POLICY,
    BASELINE_PATH: BASELINE,
    BOOTSTRAP: bootstrap,
    BASELINE_STATE: state,
    SYNTHETIC_FIXTURE: 'none',
    GITHUB_OUTPUT: outputs,
    GITHUB_STEP_SUMMARY: join(dir, 'step-summary'),
    GITHUB_EVENT_NAME: event
  };
  const run = (name, extra = {}) => {
    const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript(join(FRAMEWORK, '.github/workflows', file), name)], {
      cwd: dir,
      env: { ...env, ...extra },
      encoding: 'utf8'
    });
    return { code: result.status, out: `${result.stdout}${result.stderr}` };
  };
  const evaluate = run('Evaluate security policy');
  const verdict = run('Publish gate verdict');
  const published = Object.fromEntries(
    readFileSync(outputs, 'utf8').split('\n').filter(Boolean).map((line) => line.split(/=(.*)/s).slice(0, 2))
  );
  return { evaluate, verdict, published, run, env };
}

for (const file of ['_source-security.yml', '_source-scan.yml']) {
  describe(`${file}: the gate steps honour the declared lifecycle`, () => {
    it('legacy caller (no state): reproduces the live failure verbatim', () => {
      const { evaluate, verdict, published } = runGateSteps(file, consumer());
      assert.match(evaluate.out, new RegExp(`BLOCK security-gate report-integrity \\(gate\\.report_integrity\\): ${LIVE_MESSAGE}`));
      assert.match(evaluate.out, /SECURITY GATE: BLOCK/);
      assert.match(verdict.out, /scan trusted: false/);
      assert.equal(published.integrity_trusted, 'false');
    });

    it('absent + pull_request: trusted, finding-driven verdict, notice that no candidate is generated', () => {
      const { evaluate, verdict, published } = runGateSteps(file, consumer(), { state: 'absent' });
      assert.doesNotMatch(evaluate.out, /report-integrity/);
      assert.match(evaluate.out, /BLOCK semgrep .*\(sast\.high_new\)/);
      assert.match(evaluate.out, /::notice::No Semgrep baseline accepted yet/);
      assert.match(verdict.out, /scan trusted: true/);
      assert.equal(published.integrity_trusted, 'true');
      assert.equal(published.verdict, 'BLOCK');
    });

    it('absent + workflow_dispatch without bootstrap: trusted, and still no candidate', () => {
      const dir = consumer();
      const { published } = runGateSteps(file, dir, { state: 'absent', event: 'workflow_dispatch' });
      assert.equal(published.integrity_trusted, 'true');
      const gateResult = JSON.parse(readFileSync(join(dir, 'reports/security-gate.json'), 'utf8'));
      assert.equal(gateResult.bootstrap.active, false);
      assert.throws(() => provenanceFor(gateResult), /was not a baseline bootstrap/);
      assert.ok(!existsSync(join(dir, 'reports/semgrep-baseline.candidate.json')));
    });

    it('absent + workflow_dispatch + bootstrap: trusted, and the generation step produces a candidate with provenance', () => {
      const dir = consumer();
      const { published } = runGateSteps(file, dir, { state: 'absent', bootstrap: 'true', event: 'workflow_dispatch' });
      assert.equal(published.integrity_trusted, 'true');

      const generation = spawnSync(
        'bash',
        ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript(join(FRAMEWORK, '.github/workflows', file), 'Generate the first Semgrep baseline (bootstrap only)')],
        {
          cwd: dir,
          encoding: 'utf8',
          env: {
            PATH: process.env.PATH, HOME: process.env.HOME, SSD_TOOLKIT: join(FRAMEWORK, 'security'),
            GITHUB_STEP_SUMMARY: join(dir, 'step-summary'),
            SEMGREP_CONFIGS: 'p/owasp-top-ten', SEMGREP_PATHS: '.', BASELINE_PATH: BASELINE,
            CI_REPOSITORY: 'acme/app', CI_REPOSITORY_ID: '1', CI_DEFAULT_BRANCH: 'main', CI_SHA: 'a'.repeat(40),
            CI_REF: 'refs/heads/main', CI_EVENT: 'workflow_dispatch', CI_RUN_ID: '1', CI_RUN_ATTEMPT: '1',
            TOOLKIT_REPOSITORY: 'IamRitz/ssd-security-framework', TOOLKIT_REF: 'b'.repeat(40)
          }
        }
      );
      assert.equal(generation.status, 0, `${generation.stdout}${generation.stderr}`);
      assert.equal(JSON.parse(readFileSync(join(dir, 'reports/semgrep-baseline.candidate.json'), 'utf8')).findings.length, 1);
      const provenance = JSON.parse(readFileSync(join(dir, 'reports/semgrep-baseline.candidate.provenance.json'), 'utf8'));
      assert.deepEqual(provenance.gate, { integrityTrusted: true, bootstrapActive: true });
    });

    it('accepted + missing baseline: fails closed', () => {
      const { published, evaluate } = runGateSteps(file, consumer(), { state: 'accepted' });
      assert.match(evaluate.out, new RegExp(LIVE_MESSAGE));
      assert.equal(published.integrity_trusted, 'false');
      assert.equal(published.verdict, 'BLOCK');
    });

    it('absent + an existing baseline file: fails closed', () => {
      const { published, evaluate } = runGateSteps(file, consumer({ baseline: { schemaVersion: 1, findings: [] } }), { state: 'absent' });
      assert.match(evaluate.out, /inconsistent lifecycle/);
      assert.equal(published.integrity_trusted, 'false');
    });

    it("an unsupported state ('bogus'): exit 1, a written untrusted BLOCK, and every later step names the cause", () => {
      const dir = consumer();
      const REASON = "unsupported Semgrep baseline state 'bogus'; expected one of absent, accepted";
      const { evaluate, published, run, env } = runGateSteps(file, dir, { state: 'bogus' });

      assert.equal(evaluate.code, 1);
      assert.ok(evaluate.out.includes(`BLOCK security-gate report-integrity (gate.report_integrity): ${REASON}`), evaluate.out);
      const written = JSON.parse(readFileSync(join(dir, 'reports/security-gate.json'), 'utf8'));
      assert.equal(written.integrity.failures[0].reason, REASON);
      assert.deepEqual(written.semgrepBaseline, { state: 'invalid', declared: 'bogus' });
      // Read from the written result (a digest exists), not the missing-file fallback.
      assert.equal(published.verdict, 'BLOCK');
      assert.equal(published.integrity_trusted, 'false');
      assert.equal(published.break_glass_eligible, 'false');
      assert.match(published.gate_digest, /^[0-9a-f]{64}$/);

      // The notifier succeeds and surfaces the actual reason (same command as the step).
      const notify = spawnSync(process.execPath, [join(FRAMEWORK, 'security/scripts/notify.mjs'), '--gate', 'reports/security-gate.json'], {
        cwd: dir,
        encoding: 'utf8',
        env: { ...env, GATE_MODE: 'log-only', SECRET_SCAN_JOB_RESULT: 'success', DEPENDENCY_SCAN_JOB_RESULT: 'success', SAST_JOB_RESULT: 'success' }
      });
      assert.equal(notify.status, 0, `${notify.stdout}${notify.stderr}`);
      const summary = readFileSync(join(dir, 'step-summary'), 'utf8');
      assert.ok(summary.includes(REASON), summary);
      assert.match(summary, /Security gate: BLOCK — scan untrusted/);

      const flag = run('Flag an untrusted scan (blocks baseline generation)');
      assert.equal(flag.code, 0);
      assert.ok(flag.out.includes(`::error title=Untrusted scan — do not baseline::security-gate: ${REASON}`), flag.out);
      const marker = readFileSync(join(dir, 'reports/DO-NOT-BASELINE.txt'), 'utf8');
      assert.ok(marker.includes(`Integrity failure: security-gate: ${REASON}`), marker);
      assert.match(marker, /DO NOT GENERATE A SEMGREP BASELINE FROM THIS RUN/);

      // log-only reports the BLOCK as not enforced — never as trusted or clean.
      const enforce = run('Enforce the gate verdict', { GATE_MODE: 'log-only', VERDICT: published.verdict, BREAK_GLASS_OUTCOME: 'skipped' });
      assert.equal(enforce.code, 0);
      assert.match(enforce.out, /verdict: BLOCK, but gate_mode=log-only so the BLOCK is reported and NOT enforced/);
      assert.doesNotMatch(enforce.out, /PASS/);
    });
  });
}
