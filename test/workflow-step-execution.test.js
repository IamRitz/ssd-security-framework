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
        EVENT: 'pull_request',
        SOURCE_RESULT: 'success',
        IMAGE_RESULT: 'success',
        SOURCE_VERDICT: 'PASS',
        IMAGE_VERDICT: 'DEPLOY',
        MODE: 'log-only',
        IMAGE_MODE: 'log-only'
      });
      assert.equal(code, 0);
      assert.match(out, /source verdict PASS\. gate_mode is log-only/);
      assert.match(out, /image verdict DEPLOY\. gate_mode is log-only/);
      assert.doesNotMatch(out, /GREEN BY CONFIGURATION|not enforced/i);
    });

    it(`${path}: an image BLOCK_DEPLOY in log-only is flagged even when source PASSes`, () => {
      const { code, out } = runStep(path, STEP, {
        EVENT: 'pull_request',
        SOURCE_RESULT: 'success',
        IMAGE_RESULT: 'success',
        SOURCE_VERDICT: 'PASS',
        IMAGE_VERDICT: 'BLOCK_DEPLOY',
        MODE: 'log-only',
        IMAGE_MODE: 'log-only'
      });
      assert.equal(code, 0);
      assert.match(out, /GREEN BY CONFIGURATION, not by verdict — image verdict BLOCK_DEPLOY is reported but NOT enforced/);
    });

    it(`${path}: enforce + source BLOCK fails`, () => {
      const { code } = runStep(path, STEP, {
        EVENT: 'pull_request',
        SOURCE_RESULT: 'failure',
        IMAGE_RESULT: 'success',
        SOURCE_VERDICT: 'BLOCK',
        IMAGE_VERDICT: 'DEPLOY',
        MODE: 'enforce',
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
