// Executes the REAL `run:` scripts of workflow steps, rather than pattern-matching
// them, for the two behaviours where wording and exit status are the product:
//
//  1. gate_mode wording. A PASS in log-only has no blocking verdict to suppress
//     and must not read as "not enforced"; a BLOCK in log-only must say plainly
//     that it was not enforced; enforce + BLOCK must still fail.
//  2. scanner exit status as data. pip-audit / OSV-Scanner exit 1 when they find
//     vulnerabilities; that must produce a passing step with a usable report,
//     while a crash, an unexpected status, or a missing/empty report still fails.
//
// Scripts run under the same shell flags GitHub uses for `run:` (bash -eo
// pipefail). `docker` is replaced by a stub on PATH that emits a chosen report
// and exit status, so the workflow's own capture-and-check logic is what runs.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, describe, it } from 'node:test';

const FRAMEWORK = resolve('.');
const LIVE = join(FRAMEWORK, 'security/scripts/__fixtures__/live-python-source-only');
const PIP_FIXTURES = join(FRAMEWORK, 'security/scripts/__fixtures__/pip-audit');
const OSV_CLEAN = join(FRAMEWORK, 'security/scripts/__fixtures__/clean/osv-scanner.json');

const WORK = mkdtempSync(join(tmpdir(), 'workflow-step-execution-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

// The `run:` body of the step named `name` in `file`, dedented.
function stepScript(file, name) {
  const source = readFileSync(join(FRAMEWORK, file), 'utf8');
  const start = source.indexOf(`- name: ${name}\n`);
  assert.ok(start >= 0, `${file}: step "${name}" not found`);
  const stepIndent = source.lastIndexOf('\n', start) + 1;
  const indent = start - stepIndent;
  const lines = source.slice(start).split('\n').slice(1);
  const body = [];
  let runIndent = null;
  for (const line of lines) {
    if (runIndent === null) {
      // Stop at the next step or the end of the job.
      if (line.trim() !== '' && line.length - line.trimStart().length <= indent) {
        break;
      }
      const match = /^(\s*)run: \|\s*$/.exec(line);
      if (match) {
        runIndent = match[1].length;
      }
      continue;
    }
    if (line.trim() !== '' && line.length - line.trimStart().length <= runIndent) {
      break;
    }
    body.push(line);
  }
  assert.ok(body.length > 0, `${file}: step "${name}" has no multi-line run script`);
  const dedent = Math.min(...body.filter((line) => line.trim() !== '').map((line) => line.length - line.trimStart().length));
  return body.map((line) => line.slice(dedent)).join('\n');
}

function runStep(file, name, env = {}, { cwd = WORK, path } = {}) {
  const script = stepScript(file, name);
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
    cwd,
    env: { PATH: path ?? process.env.PATH, HOME: process.env.HOME, ...env },
    encoding: 'utf8'
  });
  return { code: result.status, out: `${result.stdout}${result.stderr}` };
}

// ---- 1. gate_mode wording ------------------------------------------------------

describe('source gate enforcement wording (_source-security.yml)', () => {
  const FILE = '.github/workflows/_source-security.yml';
  const STEP = 'Enforce the gate verdict';

  it('PASS + log-only: reports PASS and log-only, never "not enforced"', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'log-only', VERDICT: 'PASS', BREAK_GLASS_OUTCOME: 'skipped' });
    assert.equal(code, 0);
    assert.match(out, /::warning::Security gate verdict: PASS\. gate_mode=log-only; no blocking verdict exists/);
    assert.match(out, /rollout mode and a merge bypass/, 'log-only stays visible as a bypass');
    assert.doesNotMatch(out, /not enforced/i);
  });

  it('PASS-WITH-EXCEPTIONS + log-only is treated like PASS', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'log-only', VERDICT: 'PASS-WITH-EXCEPTIONS' });
    assert.equal(code, 0);
    assert.match(out, /verdict: PASS-WITH-EXCEPTIONS\. gate_mode=log-only; no blocking verdict exists/);
    assert.doesNotMatch(out, /not enforced/i);
  });

  it('BLOCK + log-only: clearly says the BLOCK is not enforced', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'log-only', VERDICT: 'BLOCK' });
    assert.equal(code, 0);
    assert.match(out, /::warning::Security gate verdict: BLOCK, but gate_mode=log-only so the BLOCK is reported and NOT enforced/);
  });

  it('enforce + BLOCK: still fails', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'enforce', VERDICT: 'BLOCK', BREAK_GLASS_OUTCOME: 'skipped' });
    assert.equal(code, 1);
    assert.match(out, /Security gate verdict is BLOCK\./);
  });

  it('enforce + BLOCK with a verified break-glass approval: unchanged override behaviour', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'enforce', VERDICT: 'BLOCK', BREAK_GLASS_OUTCOME: 'success' });
    assert.equal(code, 0);
    assert.match(out, /overridden by a verified break-glass approval/);
  });

  it('enforce + PASS passes with no log-only noise', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'enforce', VERDICT: 'PASS' });
    assert.equal(code, 0);
    assert.doesNotMatch(out, /log-only|warning/);
  });
});

describe('image and artifact gate enforcement wording', () => {
  for (const [file, step] of [
    ['.github/workflows/_image-scan-prepush.yml', 'Enforce the pre-push image verdict'],
    ['.github/workflows/_artifact-gate.yml', 'Enforce the artifact gate verdict']
  ]) {
    it(`${file}: DEPLOY + log-only never says "not enforced"`, () => {
      const { code, out } = runStep(file, step, { GATE_MODE: 'log-only', VERDICT: 'DEPLOY' });
      assert.equal(code, 0);
      assert.match(out, /verdict: DEPLOY\. gate_mode=log-only; no blocking verdict exists/);
      assert.doesNotMatch(out, /not enforced/i);
    });

    it(`${file}: BLOCK_DEPLOY + log-only says it is not enforced`, () => {
      const { code, out } = runStep(file, step, { GATE_MODE: 'log-only', VERDICT: 'BLOCK_DEPLOY' });
      assert.equal(code, 0);
      assert.match(out, /BLOCK_DEPLOY, but gate_mode=log-only so the BLOCK_DEPLOY is reported and NOT enforced/);
    });

    it(`${file}: enforce + BLOCK_DEPLOY still fails`, () => {
      assert.equal(runStep(file, step, { GATE_MODE: 'enforce', VERDICT: 'BLOCK_DEPLOY' }).code, 1);
    });
  }
});

describe('conformance enforcement wording (_conformance.yml)', () => {
  const FILE = '.github/workflows/_conformance.yml';
  const STEP = 'Enforce the conformance result';

  it('log-only with no failed control does not claim a failure was suppressed', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'log-only', FAILED: '0', EXEMPT: '0' });
    assert.equal(code, 0);
    assert.match(out, /every applicable control passed\. gate_mode=log-only; no failed control exists/);
    assert.doesNotMatch(out, /not enforced/i);
  });

  it('log-only with failed controls says they are not enforced', () => {
    const { code, out } = runStep(FILE, STEP, { GATE_MODE: 'log-only', FAILED: '1', EXEMPT: '0' });
    assert.equal(code, 0);
    assert.match(out, /1 applicable control\(s\) failed, but gate_mode=log-only so the failure is reported and NOT enforced/);
  });

  it('enforce with a failed control fails', () => {
    assert.equal(runStep(FILE, STEP, { GATE_MODE: 'enforce', FAILED: '1', EXEMPT: '0' }).code, 1);
  });

  it('the report step treats the engine\'s failed-control exit as data, and a crash as failure', () => {
    const toolkit = join(WORK, 'conformance-toolkit');
    mkdirSync(join(toolkit, 'scripts'), { recursive: true });
    const cwd = join(WORK, 'conformance-cwd');
    mkdirSync(cwd, { recursive: true });
    const outputs = join(cwd, 'outputs');
    const summary = join(cwd, 'summary');
    const env = (engine) => {
      writeFileSync(join(toolkit, 'scripts', 'conformance.mjs'), engine);
      writeFileSync(outputs, '');
      rmSync(join(cwd, 'reports'), { recursive: true, force: true });
      return { SSD_TOOLKIT: toolkit, GITHUB_OUTPUT: outputs, GITHUB_STEP_SUMMARY: summary, OBSERVED: '{}' };
    };
    const writeReport = (failed, exit) =>
      `import {mkdirSync,writeFileSync} from 'node:fs';mkdirSync('reports',{recursive:true});` +
      `writeFileSync('reports/conformance.json', JSON.stringify({summary:{failed:${failed},notApplicable:0,exempt:0,deferred:0}}));process.exitCode=${exit};`;

    const failedControl = runStep(FILE, 'Build the conformance report', env(writeReport(1, 1)), { cwd });
    assert.equal(failedControl.code, 0, 'a failed control is a result, decided by the enforce step');
    assert.match(readFileSync(outputs, 'utf8'), /^failed=1$/m);

    const crash = runStep(FILE, 'Build the conformance report', env(`throw new Error('engine crashed');`), { cwd });
    assert.notEqual(crash.code, 0, 'an engine that wrote no report must fail the step');
    assert.match(readFileSync(outputs, 'utf8'), /^failed=1$/m, 'an unreadable report counts as a failure, not zero');

    const inconsistent = runStep(FILE, 'Build the conformance report', env(writeReport(0, 3)), { cwd });
    assert.equal(inconsistent.code, 3, 'a non-zero exit that recorded no failed control is an execution failure');
  });
});

describe('example aggregate checks distinguish PASS from BLOCK in log-only', () => {
  const SOURCE_ONLY = 'examples/source-only/security.yml';
  const STEP = 'Require every security control that gates this pull request';

  it('source-only: PASS + log-only has no GREEN BY CONFIGURATION and no "not enforced"', () => {
    const { code, out } = runStep(SOURCE_ONLY, STEP, { SOURCE_RESULT: 'success', VERDICT: 'PASS', MODE: 'log-only' });
    assert.equal(code, 0);
    assert.match(out, /Source verdict PASS\. gate_mode is log-only; no blocking verdict exists/);
    assert.doesNotMatch(out, /GREEN BY CONFIGURATION/);
    assert.doesNotMatch(out, /not enforced/i);
  });

  it('source-only: BLOCK + log-only keeps the strong warning', () => {
    const { code, out } = runStep(SOURCE_ONLY, STEP, { SOURCE_RESULT: 'success', VERDICT: 'BLOCK', MODE: 'log-only' });
    assert.equal(code, 0);
    assert.match(out, /GREEN BY CONFIGURATION, not by verdict — source verdict BLOCK is reported but NOT enforced/);
  });

  it('source-only: enforce + BLOCK fails the required check', () => {
    const { code, out } = runStep(SOURCE_ONLY, STEP, { SOURCE_RESULT: 'failure', VERDICT: 'BLOCK', MODE: 'enforce' });
    assert.equal(code, 1);
    assert.match(out, /source security did not pass \(result=failure\)/);
  });

  for (const path of ['examples/container-ecr/security.yml', 'examples/python-self-managed/security.yml']) {
    it(`${path}: PASS/DEPLOY in log-only is not called green by configuration`, () => {
      const { code, out } = runStep(path, STEP, {
        SSD_TOOLKIT: join(FRAMEWORK, 'security'),
        EVENT: 'pull_request',
        SOURCE_RESULT: 'success',
        IMAGE_RESULT: 'success',
        SOURCE_VERDICT: 'PASS',
        IMAGE_VERDICT: 'DEPLOY',
        SOURCE_MODE: 'log-only',
        IMAGE_MODE: 'log-only'
      });
      assert.equal(code, 0);
      assert.match(out, /source verdict PASS\. gate_mode is log-only/);
      assert.match(out, /image verdict DEPLOY\. gate_mode is log-only/);
      assert.doesNotMatch(out, /GREEN BY CONFIGURATION|not enforced/i);
    });

    it(`${path}: an image BLOCK_DEPLOY in log-only is flagged even when source PASSes`, () => {
      const { code, out } = runStep(path, STEP, {
        SSD_TOOLKIT: join(FRAMEWORK, 'security'),
        EVENT: 'pull_request',
        SOURCE_RESULT: 'success',
        IMAGE_RESULT: 'success',
        SOURCE_VERDICT: 'PASS',
        IMAGE_VERDICT: 'BLOCK_DEPLOY',
        SOURCE_MODE: 'log-only',
        IMAGE_MODE: 'log-only'
      });
      assert.equal(code, 0);
      assert.match(out, /GREEN BY CONFIGURATION, not by verdict — image verdict BLOCK_DEPLOY is reported but NOT enforced/);
    });

    it(`${path}: enforce + source BLOCK fails`, () => {
      const { code } = runStep(path, STEP, {
        SSD_TOOLKIT: join(FRAMEWORK, 'security'),
        EVENT: 'pull_request',
        SOURCE_RESULT: 'failure',
        IMAGE_RESULT: 'success',
        SOURCE_VERDICT: 'BLOCK',
        IMAGE_VERDICT: 'DEPLOY',
        SOURCE_MODE: 'enforce',
        IMAGE_MODE: 'enforce'
      });
      assert.equal(code, 1);
    });
  }
});

// ---- 2. scanner exit status as data ---------------------------------------------

const STUB_BIN = join(WORK, 'bin');
mkdirSync(STUB_BIN, { recursive: true });
writeFileSync(
  join(STUB_BIN, 'docker'),
  [
    '#!/usr/bin/env bash',
    '# Stands in for the scanner container: emits a chosen report, exits a chosen status.',
    'if [ -n "${STUB_STDOUT_REPORT:-}" ]; then cat "$STUB_STDOUT_REPORT"; fi',
    'if [ -n "${STUB_FILE_REPORT:-}" ]; then mkdir -p "$GITHUB_WORKSPACE/reports"; cp "$STUB_FILE_REPORT" "$GITHUB_WORKSPACE/reports/$STUB_FILE_NAME"; fi',
    'if [ "${STUB_EMPTY_FILE:-}" = "1" ]; then mkdir -p "$GITHUB_WORKSPACE/reports"; : > "$GITHUB_WORKSPACE/reports/$STUB_FILE_NAME"; fi',
    'exit "${STUB_EXIT:-0}"',
    ''
  ].join('\n')
);
chmodSync(join(STUB_BIN, 'docker'), 0o755);

function scannerStep(step, stub) {
  const workspace = mkdtempSync(join(WORK, 'workspace-'));
  mkdirSync(join(workspace, 'reports'));
  const outputs = join(workspace, 'github-output');
  writeFileSync(outputs, '');
  const result = runStep(
    '.github/workflows/_source-security.yml',
    step,
    { GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: outputs, SSD_TOOLKIT: join(FRAMEWORK, 'security'), ...stub },
    { cwd: workspace, path: `${STUB_BIN}:${process.env.PATH}` }
  );
  return { ...result, outputs: readFileSync(outputs, 'utf8'), workspace };
}

describe('pip-audit step: exit status is captured and judged with the report', () => {
  const STEP = 'Run pip-audit (report only)';
  const file = (report) => ({ STUB_FILE_REPORT: report, STUB_FILE_NAME: 'pip-audit.json' });

  it('findings exit (1) with the live report is a SUCCESSFUL scan with a usable report', () => {
    const { code, out, outputs, workspace } = scannerStep(STEP, { ...file(join(LIVE, 'pip-audit.json')), STUB_EXIT: '1' });
    assert.equal(code, 0, out);
    assert.match(out, /pip-audit exited 1 \(vulnerabilities found\) with a valid report listing 2 finding\(s\)/);
    assert.match(out, /not a scanner failure/);
    assert.doesNotMatch(out, /SCANNER RUN INVALID/);
    assert.match(outputs, /^exit_code=1$/m);
    assert.match(outputs, /^outcome=findings$/m);
    assert.equal(
      readFileSync(join(workspace, 'reports/pip-audit.json'), 'utf8'),
      readFileSync(join(LIVE, 'pip-audit.json'), 'utf8'),
      'the report is left intact for the gate'
    );
  });

  it('clean exit (0) with a clean report passes', () => {
    const { code, outputs } = scannerStep(STEP, { ...file(join(PIP_FIXTURES, 'clean.json')), STUB_EXIT: '0' });
    assert.equal(code, 0);
    assert.match(outputs, /^outcome=clean$/m);
  });

  it('fatal error (exit 1, nothing written) fails closed', () => {
    const { code, out } = scannerStep(STEP, { STUB_EMPTY_FILE: '1', STUB_FILE_NAME: 'pip-audit.json', STUB_EXIT: '1' });
    assert.equal(code, 1);
    assert.match(out, /report .* is empty .* UNKNOWN, not clean/);
  });

  it('exit 1 with a report that lists no findings fails closed (pip-audit also exits 1 on errors)', () => {
    const { code, out } = scannerStep(STEP, { ...file(join(PIP_FIXTURES, 'clean.json')), STUB_EXIT: '1' });
    assert.equal(code, 1);
    assert.match(out, /also uses exit 1 for fatal errors/);
  });

  it('a malformed report fails closed whatever the exit status', () => {
    for (const exit of ['0', '1']) {
      const { code, out } = scannerStep(STEP, { ...file(join(PIP_FIXTURES, 'malformed.json')), STUB_EXIT: exit });
      assert.equal(code, 1, `exit ${exit}`);
      assert.match(out, /does not have a dependencies array/);
    }
  });

  it('an unexpected status (pip install / container failure) fails closed', () => {
    const { code, out } = scannerStep(STEP, { ...file(join(LIVE, 'pip-audit.json')), STUB_EXIT: '125' });
    assert.equal(code, 1);
    assert.match(out, /unexpected status 125/);
  });
});

describe('OSV-Scanner step: exit status is captured and judged with the report', () => {
  const STEP = 'Run OSV-Scanner (report only)';

  it('findings exit (1) with the live report succeeds', () => {
    const { code, out, outputs } = scannerStep(STEP, { STUB_STDOUT_REPORT: join(LIVE, 'osv-scanner.json'), STUB_EXIT: '1' });
    assert.equal(code, 0, out);
    assert.match(out, /osv-scanner exited 1 \(vulnerabilities found\) with a valid report listing 4 finding\(s\)/);
    assert.match(outputs, /^outcome=findings$/m);
  });

  it('clean exit (0) with a clean report succeeds', () => {
    const { code } = scannerStep(STEP, { STUB_STDOUT_REPORT: OSV_CLEAN, STUB_EXIT: '0' });
    assert.equal(code, 0);
  });

  it('general error (127) fails closed even if output looks valid', () => {
    const { code, out } = scannerStep(STEP, { STUB_STDOUT_REPORT: join(LIVE, 'osv-scanner.json'), STUB_EXIT: '127' });
    assert.equal(code, 1);
    assert.match(out, /unexpected status 127/);
  });

  it('no output at all (128 without --allow-no-lockfiles) fails closed', () => {
    const { code, out } = scannerStep(STEP, { STUB_EXIT: '128' });
    assert.equal(code, 1);
    assert.match(out, /is empty/);
  });

  it('exit 1 with a report listing nothing fails closed', () => {
    const { code, out } = scannerStep(STEP, { STUB_STDOUT_REPORT: OSV_CLEAN, STUB_EXIT: '1' });
    assert.equal(code, 1);
    assert.match(out, /exit status and the report disagree/);
  });
});

describe('secret scan report validation step', () => {
  it('fails the Secret scanning job on an uninterpretable report', () => {
    const workspace = mkdtempSync(join(WORK, 'secrets-'));
    mkdirSync(join(workspace, 'reports'));
    copyFileSync(join(FRAMEWORK, 'security/scripts/__fixtures__/clean/trufflehog.json'), join(workspace, 'reports/trufflehog.json'));
    writeFileSync(join(workspace, 'reports/gitleaks.json'), '{ "not": "an array" }');
    const bad = runStep('.github/workflows/_source-security.yml', 'Validate secret scan reports', { SSD_TOOLKIT: join(FRAMEWORK, 'security') }, { cwd: workspace });
    assert.equal(bad.code, 1);
    assert.match(bad.out, /gitleaks report must be a JSON array/);

    copyFileSync(join(FRAMEWORK, 'security/scripts/__fixtures__/clean/gitleaks.json'), join(workspace, 'reports/gitleaks.json'));
    const good = runStep('.github/workflows/_source-security.yml', 'Validate secret scan reports', { SSD_TOOLKIT: join(FRAMEWORK, 'security') }, { cwd: workspace });
    assert.equal(good.code, 0, good.out);
  });
});

describe('the scanner steps no longer mask failure', () => {
  const source = readFileSync(join(FRAMEWORK, '.github/workflows/_source-security.yml'), 'utf8');
  for (const step of ['Run pip-audit (report only)', 'Run OSV-Scanner (report only)']) {
    it(`${step} has no continue-on-error and no "|| true"`, () => {
      const start = source.indexOf(`- name: ${step}\n`);
      const block = source
        .slice(start, source.indexOf('\n      - name:', start + 1))
        .split('\n')
        .filter((line) => !/^\s*#/.test(line))
        .join('\n');
      assert.ok(!/^\s*continue-on-error:/m.test(block), 'continue-on-error would hide a scanner crash');
      assert.ok(!/\|\|\s*true/.test(block), '`|| true` would erase scanner failure semantics');
      assert.match(block, /scanner_status=\$\?/);
      assert.match(block, /check-scanner-exit\.mjs/);
    });
  }
});

// ---- 3. Semgrep: image acquisition is separate from, and retried unlike, execution ----
//
// Regression (live run IamRitz/ssd-scratch-consumer 35233605122, attempt 1): the
// pinned Semgrep image could not be pulled (connection reset talking to Docker
// Hub), the scanner never ran, and the only visible cause was a missing report.
// The REAL SAST step script runs here with a scripted `docker` that counts pulls
// and runs separately.

const SOURCE_WORKFLOW = '.github/workflows/_source-security.yml';
const SAST_STEP = 'Run Semgrep OSS (report only)';
const PINNED_SEMGREP = 'semgrep/semgrep@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e';
const REGISTRY_RESET =
  'docker: Error response from daemon: Get "https://auth.docker.io/token?scope=repository%3Asemgrep%2Fsemgrep%3Apull": read tcp 10.1.0.94:48212->98.85.153.80:443: read: connection reset by peer';

const SEMGREP_STUB_BIN = join(WORK, 'semgrep-bin');
mkdirSync(SEMGREP_STUB_BIN, { recursive: true });
writeFileSync(
  join(SEMGREP_STUB_BIN, 'docker'),
  [
    '#!/usr/bin/env bash',
    'echo "$*" >> "$STUB_CALLS"',
    'case "$1" in',
    '  image) exit 1 ;;',
    '  pull)',
    '    n=$(( $(cat "$STUB_PULLS" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STUB_PULLS"',
    '    if [ "$n" -le "${STUB_PULL_FAILURES:-0}" ]; then echo "${STUB_PULL_ERROR}" >&2; exit 1; fi',
    '    exit 0 ;;',
    '  run)',
    '    case "$*" in *--pull=never*) ;; *) echo "stub: docker run without --pull=never" >&2; exit 99 ;; esac',
    '    if [ -n "${STUB_RUN_REPORT:-}" ]; then cp "$STUB_RUN_REPORT" "$GITHUB_WORKSPACE/reports/semgrep.json"; fi',
    '    exit "${STUB_RUN_EXIT:-0}" ;;',
    'esac',
    'exit 98',
    ''
  ].join('\n')
);
chmodSync(join(SEMGREP_STUB_BIN, 'docker'), 0o755);

function stepEnvValue(file, step, name) {
  const source = readFileSync(join(FRAMEWORK, file), 'utf8');
  const start = source.indexOf(`- name: ${step}\n`);
  const block = source.slice(start, source.indexOf('\n      - name:', start + 1));
  return new RegExp(`^\\s+${name}: (.+)$`, 'm').exec(block)?.[1].trim();
}

function semgrepStep(stub) {
  const workspace = mkdtempSync(join(WORK, 'sast-'));
  mkdirSync(join(workspace, 'reports'));
  const calls = join(workspace, 'docker-calls');
  writeFileSync(calls, '');
  const result = runStep(
    SOURCE_WORKFLOW,
    SAST_STEP,
    {
      GITHUB_WORKSPACE: workspace,
      SSD_TOOLKIT: join(FRAMEWORK, 'security'),
      SEMGREP_CONFIGS: 'p/owasp-top-ten',
      SEMGREP_PATHS: '.',
      SEMGREP_BASELINE: '',
      SEMGREP_IMAGE: stepEnvValue(SOURCE_WORKFLOW, SAST_STEP, 'SEMGREP_IMAGE'),
      EXECUTION_RECORD: stepEnvValue(SOURCE_WORKFLOW, SAST_STEP, 'EXECUTION_RECORD'),
      SSD_IMAGE_ACQUIRE_BACKOFF_MS: '0',
      STUB_CALLS: calls,
      STUB_PULLS: join(workspace, 'pull-count'),
      STUB_PULL_ERROR: REGISTRY_RESET,
      ...stub
    },
    { cwd: workspace, path: `${SEMGREP_STUB_BIN}:${process.env.PATH}` }
  );
  const lines = readFileSync(calls, 'utf8').split('\n').filter(Boolean);
  let record = null;
  try {
    record = JSON.parse(readFileSync(join(workspace, 'reports/scanner-execution-semgrep.json'), 'utf8'));
  } catch {
    // absent record is asserted by the caller
  }
  return {
    ...result,
    record,
    pulls: lines.filter((line) => line.startsWith('pull ')).length,
    runs: lines.filter((line) => line.startsWith('run ')).length,
    calls: lines
  };
}

const SEMGREP_CLEAN_REPORT = join(FRAMEWORK, 'security/scripts/__fixtures__/clean/semgrep.json');

describe('Semgrep step: acquire (bounded retry) -> run once -> complete', () => {
  it('the pinned image identity is unchanged and is what gets pulled and run', () => {
    assert.equal(stepEnvValue(SOURCE_WORKFLOW, SAST_STEP, 'SEMGREP_IMAGE'), PINNED_SEMGREP);
    const { code, out, calls } = semgrepStep({ STUB_RUN_REPORT: SEMGREP_CLEAN_REPORT });
    assert.equal(code, 0, out);
    assert.ok(calls.includes(`pull ${PINNED_SEMGREP}`));
    assert.ok(calls.some((line) => line.startsWith('run --rm --pull=never') && line.includes(PINNED_SEMGREP)));
  });

  it('a transient registry failure on attempt 1 is retried, and the scan then runs exactly once', () => {
    const { code, out, record, pulls, runs } = semgrepStep({ STUB_PULL_FAILURES: '1', STUB_RUN_REPORT: SEMGREP_CLEAN_REPORT });
    assert.equal(code, 0, out);
    assert.equal(pulls, 2);
    assert.equal(runs, 1);
    assert.match(out, /attempt 1\/3/);
    assert.match(out, /Acquired .* on attempt 2\/3/);
    assert.equal(record.state, 'success');
    assert.deepEqual(record.acquisition.attempts.map((attempt) => attempt.outcome), ['failed', 'acquired']);
  });

  it('succeeds on attempt 3', () => {
    const { code, record, pulls, runs } = semgrepStep({ STUB_PULL_FAILURES: '2', STUB_RUN_REPORT: SEMGREP_CLEAN_REPORT });
    assert.equal(code, 0);
    assert.deepEqual([pulls, runs, record.state], [3, 1, 'success']);
  });

  it('exhausting 3 attempts fails the step, never runs the scanner, and records acquisition-failed', () => {
    const { code, out, record, pulls, runs } = semgrepStep({ STUB_PULL_FAILURES: '9', STUB_RUN_REPORT: SEMGREP_CLEAN_REPORT });
    assert.notEqual(code, 0, 'fail closed');
    assert.equal(pulls, 3);
    assert.equal(runs, 0);
    assert.deepEqual([record.state, record.cause, record.retryable], ['acquisition-failed', 'registry-network', true]);
    assert.match(out, /::error title=Semgrep could not start — scanner image unavailable::/);
    assert.match(out, /not a vulnerability finding/);
  });

  it('a registry auth failure is not retried', () => {
    const { code, record, pulls, runs } = semgrepStep({ STUB_PULL_FAILURES: '9', STUB_PULL_ERROR: 'unauthorized: authentication required' });
    assert.notEqual(code, 0);
    assert.deepEqual([pulls, runs, record.cause, record.retryable], [1, 0, 'registry-auth', false]);
  });

  for (const [exit, cause] of [
    ['2', 'scanner-runtime'],
    ['7', 'scanner-configuration'],
    ['137', 'scanner-runtime']
  ]) {
    it(`a scanner failure (exit ${exit}) fails the step, is NOT retried, and is not a registry cause`, () => {
      const { code, out, record, pulls, runs } = semgrepStep({ STUB_RUN_EXIT: exit, STUB_RUN_REPORT: SEMGREP_CLEAN_REPORT });
      assert.notEqual(code, 0, 'the runtime failure is not swallowed');
      assert.equal(pulls, 1);
      assert.equal(runs, 1, 'scanner execution runs exactly once');
      assert.deepEqual([record.state, record.cause], ['execution-failed', cause]);
      assert.match(out, /::error title=Semgrep execution-failed::/);
    });
  }

  it('exit 0 with no report fails as report-missing', () => {
    const { code, record, runs } = semgrepStep({});
    assert.notEqual(code, 0);
    assert.deepEqual([runs, record.state, record.cause], [1, 'report-missing', 'report-validation']);
  });

  it('exit 0 with a malformed report fails as report-invalid', () => {
    const malformed = join(WORK, 'malformed-semgrep.json');
    writeFileSync(malformed, '{ "version": "1" }');
    const { code, record } = semgrepStep({ STUB_RUN_REPORT: malformed });
    assert.notEqual(code, 0);
    assert.equal(record.state, 'report-invalid');
  });

  it('an empty ruleset is refused before any image is pulled, with a configuration record', () => {
    const { code, record, calls } = semgrepStep({ SEMGREP_CONFIGS: '' });
    assert.notEqual(code, 0);
    assert.deepEqual(calls, []);
    assert.deepEqual([record.state, record.cause], ['execution-failed', 'scanner-configuration']);
  });

  it('the step masks nothing: no `|| true`, no continue-on-error, no :latest, and no loop around the scan', () => {
    const source = readFileSync(join(FRAMEWORK, SOURCE_WORKFLOW), 'utf8');
    const start = source.indexOf(`- name: ${SAST_STEP}\n`);
    const block = source
      .slice(start, source.indexOf('\n      - name:', start + 1))
      .split('\n')
      .filter((line) => !/^\s*#/.test(line))
      .join('\n');
    assert.ok(!/^\s*continue-on-error:/m.test(block));
    assert.ok(!/\|\|\s*true/.test(block));
    assert.ok(!/:latest\b/.test(block));
    const script = stepScript(SOURCE_WORKFLOW, SAST_STEP)
      .split('\n')
      .filter((line) => !/^\s*#/.test(line))
      .join('\n');
    const acquire = script.indexOf('scanner-execution.mjs" acquire');
    const run = script.indexOf('docker run');
    const complete = script.indexOf('scanner-execution.mjs" complete');
    assert.ok(acquire >= 0 && acquire < run && run < complete, 'acquire, then run, then complete');
    assert.equal(script.split('docker run').length - 1, 1, 'exactly one scanner invocation');
    assert.doesNotMatch(script.slice(acquire, complete), /\b(for|while|until)\b/, 'no retry loop around the scanner run');
    assert.match(script, /docker run --rm --pull=never/);
  });

  it('the SAST artifact carries the execution record even when the scan failed', () => {
    const source = readFileSync(join(FRAMEWORK, SOURCE_WORKFLOW), 'utf8');
    const start = source.indexOf('- name: Upload SAST report\n');
    const block = source.slice(start, source.indexOf('\n      - name:', start + 1));
    assert.match(block, /if: always\(\)/);
    assert.match(block, /reports\/scanner-execution-semgrep\.json/);
  });
});

// ---- 3. the dependency-free import check (ci.yml) --------------------------------
//
// This is a security control, and it FALSE-PASSED: the step passed both -E and
// -P to GNU grep, which refuses ("conflicting matchers specified") and exits 2,
// and the `if grep ...; then` around it read that error as "no match" and
// printed the success line. The three grep outcomes are therefore exercised
// here against the REAL step script: a match (exit 0) fails, no match (exit 1)
// passes, and a checker error (exit > 1) fails closed.
describe('ci.yml: the dependency-free import check fails closed', () => {
  const FILE = '.github/workflows/ci.yml';
  const STEP = 'The toolkit must stay dependency-free';
  const SCRIPT = stepScript(FILE, STEP);

  // A tree shaped like the repository's, holding only the given .mjs files.
  function tree(files) {
    const root = mkdtempSync(join(WORK, 'import-check-'));
    for (const dir of ['security/scripts', 'onboarding/lib']) {
      mkdirSync(join(root, dir), { recursive: true });
    }
    for (const [path, content] of Object.entries(files)) {
      writeFileSync(join(root, path), content);
    }
    return root;
  }

  const BUILTINS = "import { readFileSync } from 'node:fs';\nimport { local } from './local.mjs';\n";
  const THIRD_PARTY = "import lodash from 'lodash';\n";
  const check = (root, { path } = {}) => runStep(FILE, STEP, {}, { cwd: root, path });

  it('the pattern is PCRE only: -E and -P are never combined (that is the bug that made it pass on error)', () => {
    assert.match(SCRIPT, /grep -rnP\b/, 'the negative lookahead needs -P');
    assert.doesNotMatch(SCRIPT, /grep[^\n|]*-[a-zA-Z]*E/, 'no -E anywhere in the grep invocation');
    assert.doesNotMatch(SCRIPT, /2>\s*\/dev\/null|2>&-/, 'stderr from the checker is never suppressed');
    assert.ok(SCRIPT.includes('security/scripts') && SCRIPT.includes('onboarding'), 'both trees stay in scope');
  });

  it('no forbidden import (grep exit 1): the control PASSES', () => {
    const root = tree({ 'security/scripts/a.mjs': BUILTINS, 'onboarding/lib/b.mjs': BUILTINS });
    const { code, out } = check(root);
    assert.equal(code, 0, out);
    assert.match(out, /Toolkit and onboarding imports are Node builtins and relative paths only/);
  });

  for (const [where, files] of [
    ['security/scripts', { 'security/scripts/a.mjs': THIRD_PARTY, 'onboarding/lib/b.mjs': BUILTINS }],
    ['onboarding', { 'security/scripts/a.mjs': BUILTINS, 'onboarding/lib/b.mjs': THIRD_PARTY }]
  ]) {
    it(`a third-party import under ${where} (grep exit 0): the control FAILS`, () => {
      const { code, out } = check(tree(files));
      assert.equal(code, 1, out);
      assert.match(out, /imports a third-party module; they must use Node builtins only/);
      assert.doesNotMatch(out, /builtins and relative paths only\./);
    });
  }

  // The regression itself: the checker cannot run. UNKNOWN must never be PASS.
  it('the checker itself failing (grep exit 2): the control FAILS, and says so', () => {
    const root = tree({ 'security/scripts/a.mjs': BUILTINS, 'onboarding/lib/b.mjs': BUILTINS });
    const stubBin = mkdtempSync(join(WORK, 'broken-grep-'));
    writeFileSync(join(stubBin, 'grep'), '#!/usr/bin/env bash\necho "grep: conflicting matchers specified" >&2\nexit 2\n');
    chmodSync(join(stubBin, 'grep'), 0o755);
    const { code, out } = check(root, { path: `${stubBin}:${process.env.PATH}` });
    assert.equal(code, 2, out);
    assert.match(out, /Dependency-free import check itself failed \(grep exit 2\)/);
    assert.doesNotMatch(out, /builtins and relative paths only\./, 'an error is never reported as a pass');
  });

  it('the real repository satisfies the control', () => {
    const { code, out } = runStep(FILE, STEP, {}, { cwd: FRAMEWORK });
    assert.equal(code, 0, out);
    assert.match(out, /Toolkit and onboarding imports are Node builtins and relative paths only/);
  });
});
