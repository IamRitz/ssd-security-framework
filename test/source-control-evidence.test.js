// Per-control source evidence, end to end.
//
// Regression (live run IamRitz/ssd-scratch-consumer 35202539930): Secret
// scanning, Dependency scanning and SAST all SUCCEEDED; source-gate failed
// because the policy verdict was BLOCK. The consumer fed the reusable workflow's
// aggregate `needs.source-security.result` (`failure`) to all four controls, and
// conformance reported four failures — calling three working scanners failed.
//
// These tests drive the real gate, the real per-control derivation and the real
// conformance engine, and assert the workflow/example wiring that connects them.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { buildConformance, renderMarkdown, resolveCapabilities } from '../security/scripts/conformance.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';
import { deriveScanControlResults, SCAN_CONTROLS } from '../security/scripts/source-control-results.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const LIVE = join(FIXTURES, 'live-python-source-only');
const POLICY = resolve('security/policy.yaml');
const LIBRARY = resolveCapabilities({ artifact_type: 'library', registry: 'none', deploy_target: 'none' });

async function withTempDir(fn) {
  const directory = await mkdtemp(join(tmpdir(), 'source-control-evidence-'));
  try {
    return await fn(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

// The real gate over clean reports, with named reports replaced.
async function gateWith(overrides = {}) {
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
    for (const [key, value] of Object.entries(overrides)) {
      if (typeof value === 'string' && value.startsWith('/')) {
        paths[key] = value;
      } else {
        const path = join(directory, `${key}.json`);
        await writeFile(path, typeof value === 'string' ? value : JSON.stringify(value));
        paths[key] = path;
      }
    }
    return runSecurityGate(paths);
  });
}

// What the source-gate job publishes, and what the example callers hand to
// conformance, for one run. `gateJobResult` is the source-gate job's own result.
function observedFor({ gate, jobResults, gateJobResult, mode = 'enforce' }) {
  const scans = deriveScanControlResults({ jobResults, gate });
  return {
    'secret-scan': { status: scans['secret-scan'].result, evidence: 'Secret scanning job (per-control output)' },
    'dependency-scan': { status: scans['dependency-scan'].result, evidence: 'Dependency scanning job (per-control output)' },
    sast: { status: scans.sast.result, evidence: 'SAST job (per-control output)' },
    'source-gate': {
      status: gateJobResult,
      verdict: gate?.verdict ?? '',
      gate_mode: mode,
      integrity_trusted: String(gate?.integrity?.trusted === true),
      evidence: 'source-gate job'
    }
  };
}

const ALL_SUCCESS = { 'secret-scan': 'success', 'dependency-scan': 'success', sast: 'success' };
const status = (report, id) => report.controls.find((control) => control.id === id);

describe('regression 35202539930: a policy BLOCK is not a scanner failure', () => {
  it('scanners succeeded + source gate BLOCK => 3 applied + 1 failed, with the real reason', async () => {
    // The live requests/idna reports: pip-audit's advisory BLOCKs by policy.
    const gate = await gateWith({ pipAudit: join(LIVE, 'pip-audit.json'), osv: join(LIVE, 'osv-scanner.json') });
    assert.equal(gate.verdict, 'BLOCK');
    assert.equal(gate.integrity.trusted, true);

    const report = buildConformance({
      capabilities: LIBRARY,
      observed: observedFor({ gate, jobResults: ALL_SUCCESS, gateJobResult: 'failure' })
    });

    for (const id of ['secret-scan', 'dependency-scan', 'sast']) {
      assert.equal(status(report, id).status, 'applied', `${id} ran and produced a usable report`);
      assert.match(status(report, id).detail, /produced trustworthy evidence/);
    }
    const sourceGate = status(report, 'source-gate');
    assert.equal(sourceGate.status, 'failed');
    assert.match(sourceGate.reason, /source security policy gate returned a blocking result \(verdict BLOCK\)/);
    assert.doesNotMatch(sourceGate.reason, /observed result/);
    assert.equal(report.summary.applied, 3);
    assert.equal(report.summary.failed, 1);

    const markdown = renderMarkdown(report);
    assert.match(markdown, /\*\*3\*\* applied \(executed successfully\), \*\*1\*\* failed/);
    assert.match(markdown, /A finding is not a scanner failure/);
    assert.doesNotMatch(markdown, /Dependency scanning[^\n]*failed/, 'the dependency scanner must not be called failed');
    assert.doesNotMatch(markdown, /\*\*0\*\* applied/);
  });

  it('the OLD aggregate wiring is exactly what produced four failures (documents the bug)', async () => {
    const aggregate = { status: 'failure', evidence: 'source-security job' };
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: { 'secret-scan': aggregate, 'dependency-scan': aggregate, sast: aggregate, 'source-gate': aggregate }
    });
    assert.equal(report.summary.failed, 4);
    // Even on the legacy input, a scan failure is described as missing evidence,
    // never as "found vulnerabilities".
    assert.match(status(report, 'dependency-scan').reason, /no trustworthy report was produced/);
  });
});

describe('scanner integrity failure fails the affected control, and only it', () => {
  it('a malformed pip-audit report makes dependency-scan untrusted, never applied', async () => {
    const gate = await withTempDir(async (directory) => {
      // pip-audit is required when a requirements.txt exists.
      await writeFile(join(directory, 'requirements.txt'), 'requests==2.32.5\n');
      const malformed = join(directory, 'pip-audit.json');
      await writeFile(malformed, '{ "note": "no dependencies array present" }');
      return gateWith({ repoDir: directory, pipAudit: malformed });
    });
    assert.equal(gate.integrity.trusted, false);
    assert.equal(gate.integrity.failures[0].control, 'dependency-scan');

    const scans = deriveScanControlResults({ jobResults: ALL_SUCCESS, gate });
    assert.equal(scans['dependency-scan'].result, 'untrusted');
    assert.match(scans['dependency-scan'].reason, /could not interpret its report/);
    assert.equal(scans['secret-scan'].result, 'success');
    assert.equal(scans.sast.result, 'success');

    const report = buildConformance({
      capabilities: LIBRARY,
      observed: observedFor({ gate, jobResults: ALL_SUCCESS, gateJobResult: 'failure' })
    });
    assert.equal(status(report, 'dependency-scan').status, 'failed');
    assert.match(status(report, 'dependency-scan').reason, /report-integrity failure\); findings are UNKNOWN, not clean/);
    assert.match(status(report, 'source-gate').reason, /failed closed: a scan report could not be trusted/);
    assert.equal(status(report, 'secret-scan').status, 'applied');
    assert.equal(status(report, 'sast').status, 'applied');
  });

  it('a scanner job that failed is reported failed even if a stale report looked fine', () => {
    const scans = deriveScanControlResults({
      jobResults: { ...ALL_SUCCESS, sast: 'failure' },
      gate: { integrity: { trusted: true, failures: [] } }
    });
    assert.equal(scans.sast.result, 'failure');
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: {
        'secret-scan': { status: scans['secret-scan'].result },
        'dependency-scan': { status: scans['dependency-scan'].result },
        sast: { status: scans.sast.result },
        'source-gate': { status: 'failure', verdict: 'BLOCK', integrity_trusted: 'false' }
      }
    });
    assert.equal(status(report, 'sast').status, 'failed');
    assert.match(status(report, 'sast').reason, /scanner job failed, so no trustworthy report was produced/);
  });

  it('each report is attributed to its own control', async () => {
    const cases = [
      [{ gitleaks: '{ not json' }, 'secret-scan'],
      [{ trufflehog: '[{"DetectorName": 1}]' }, 'secret-scan'],
      [{ osv: '{ "no": "results" }' }, 'dependency-scan'],
      [{ semgrep: '{ "version": "1", "results": [], "errors": [{}], "paths": { "scanned": [] } }' }, 'sast'],
      [{ baseline: '{ "schemaVersion": 9, "findings": [] }' }, 'source-gate'],
      [{ policy: '/nonexistent/policy.yaml' }, 'source-gate']
    ];
    for (const [override, control] of cases) {
      const gate = await gateWith(override);
      assert.equal(gate.integrity.trusted, false, JSON.stringify(override));
      assert.equal(gate.integrity.failures[0].control, control, JSON.stringify(override));
    }
  });

  it('a gate-side integrity failure (baseline) blames no scanner', async () => {
    const gate = await gateWith({ baseline: '{ "schemaVersion": 9, "findings": [] }' });
    const scans = deriveScanControlResults({ jobResults: ALL_SUCCESS, gate });
    for (const control of SCAN_CONTROLS) {
      assert.equal(scans[control.id].result, 'success', control.id);
    }
  });
});

describe('a clean source run', () => {
  it('reports all four source controls applied', async () => {
    const gate = await gateWith();
    assert.equal(gate.verdict, 'PASS');
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: observedFor({ gate, jobResults: ALL_SUCCESS, gateJobResult: 'success' })
    });
    for (const id of ['secret-scan', 'dependency-scan', 'sast', 'source-gate']) {
      assert.equal(status(report, id).status, 'applied', id);
    }
    assert.equal(status(report, 'source-gate').detail, 'policy verdict PASS');
    assert.equal(report.summary.applied, 4);
    assert.equal(report.summary.failed, 0);
  });
});

describe('missing or unrecognized evidence fails closed', () => {
  it('an empty job result or unknown value never becomes success', () => {
    const scans = deriveScanControlResults({ jobResults: { 'secret-scan': '', sast: 'weird' }, gate: null });
    assert.equal(scans['secret-scan'].result, 'failure');
    assert.equal(scans['dependency-scan'].result, 'failure');
    assert.equal(scans.sast.result, 'failure');
  });

  it('an unreadable gate result does not downgrade a scanner that succeeded', () => {
    const scans = deriveScanControlResults({ jobResults: ALL_SUCCESS, gate: null });
    assert.equal(scans['dependency-scan'].result, 'success');
  });

  it('an empty published output (job never published it) is a failed control with a reason', () => {
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: {
        'secret-scan': { status: '' },
        'dependency-scan': { status: 'success' },
        sast: { status: 'cancelled' },
        'source-gate': { status: 'skipped' }
      }
    });
    assert.match(status(report, 'secret-scan').reason, /empty status\); absence of evidence/);
    assert.match(status(report, 'sast').reason, /cancelled before producing a trustworthy report/);
    assert.match(status(report, 'source-gate').reason, /skipped/);
    assert.equal(report.summary.failed, 3);
  });

  it('a gate job failure with no blocking verdict is not described as a policy BLOCK', () => {
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: {
        'secret-scan': { status: 'success' },
        'dependency-scan': { status: 'success' },
        sast: { status: 'success' },
        'source-gate': { status: 'failure', verdict: 'PASS' }
      }
    });
    assert.match(status(report, 'source-gate').reason, /failed although its verdict was PASS/);
  });

  it('a log-only BLOCK is applied but says it was not enforced', () => {
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: {
        'secret-scan': { status: 'success' },
        'dependency-scan': { status: 'success' },
        sast: { status: 'success' },
        'source-gate': { status: 'success', verdict: 'BLOCK', gate_mode: 'log-only', integrity_trusted: 'true' }
      }
    });
    assert.match(status(report, 'source-gate').detail, /verdict BLOCK reported but NOT enforced \(gate_mode=log-only\)/);
  });
});

describe('the CLI publishes per-control results to GITHUB_OUTPUT', () => {
  it('writes one line per scanning control', async () => {
    await withTempDir(async (directory) => {
      const gatePath = join(directory, 'security-gate.json');
      const outputPath = join(directory, 'output');
      await writeFile(
        gatePath,
        JSON.stringify({ integrity: { trusted: false, failures: [{ source: 'security-gate', reason: 'x', control: 'sast' }] } })
      );
      await writeFile(outputPath, '');
      execFileSync('node', ['security/scripts/source-control-results.mjs', '--gate', gatePath], {
        env: {
          ...process.env,
          GITHUB_OUTPUT: outputPath,
          SECRET_SCAN_JOB_RESULT: 'success',
          DEPENDENCY_SCAN_JOB_RESULT: 'cancelled',
          SAST_JOB_RESULT: 'success'
        }
      });
      assert.equal(
        await readFile(outputPath, 'utf8'),
        'secret_scan_result=success\ndependency_scan_result=cancelled\nsast_result=untrusted\n'
      );
    });
  });
});

// ---- workflow + example wiring -------------------------------------------------

const workflow = readFileSync('.github/workflows/_source-security.yml', 'utf8');
const gateJob = workflow.slice(workflow.indexOf('\n  source-gate:\n'));

describe('_source-security.yml exposes explicit per-control outputs', () => {
  it('declares the four control outputs next to the existing ones', () => {
    for (const output of ['verdict', 'break_glass_eligible', 'gate_mode', 'integrity_trusted']) {
      assert.match(workflow, new RegExp(`\\n {6}${output}:\\n`), `existing output ${output} must remain`);
    }
    for (const output of ['secret_scan_result', 'dependency_scan_result', 'sast_result', 'source_gate_result']) {
      assert.match(
        workflow,
        new RegExp(`\\n {6}${output}:\\n[\\s\\S]*?value: \\$\\{\\{ jobs\\.source-gate\\.outputs\\.${output} \\}\\}`),
        `${output} must be a workflow output`
      );
      assert.match(gateJob, new RegExp(`\\n {6}${output}: \\$\\{\\{ steps\\.`), `${output} must be a source-gate job output`);
    }
  });

  it('derives scan results from each scanner job, not the aggregate', () => {
    assert.match(gateJob, /SECRET_SCAN_JOB_RESULT: \$\{\{ needs\.secret-scanning\.result \}\}/);
    assert.match(gateJob, /DEPENDENCY_SCAN_JOB_RESULT: \$\{\{ needs\.dependency-scanning\.result \}\}/);
    assert.match(gateJob, /SAST_JOB_RESULT: \$\{\{ needs\.sast\.result \}\}/);
    const step = gateJob.slice(gateJob.indexOf('- name: Publish per-control scan evidence'));
    assert.match(step.slice(0, 1200), /if: always\(\)/);
    assert.match(step.slice(0, 1600), /echo "sast_result=failure"/, 'a script failure must publish failure, not nothing-or-success');
  });

  it('publishes the gate result from job.status in the LAST step', () => {
    const steps = [...gateJob.matchAll(/\n {6}- name: (.+)/g)].map((match) => match[1]);
    assert.equal(steps.at(-1), 'Publish the source gate control result');
    const last = gateJob.slice(gateJob.lastIndexOf('- name: Publish the source gate control result'));
    assert.match(last, /if: always\(\)/);
    assert.match(last, /JOB_STATUS: \$\{\{ job\.status \}\}/);
  });
});

describe('every example feeds conformance per-control evidence', () => {
  const EXAMPLES = [
    'examples/source-only/security.yml',
    'examples/python-self-managed/security.yml',
    'examples/container-ecr/security.yml',
    'examples/container-ecr/deploy.yml'
  ];
  for (const path of EXAMPLES) {
    it(`${path} uses the per-control outputs`, () => {
      const source = readFileSync(path, 'utf8');
      const conformance = source.slice(source.indexOf('\n  conformance:\n'));
      for (const [control, output] of [
        ['secret-scan', 'secret_scan_result'],
        ['dependency-scan', 'dependency_scan_result'],
        ['sast', 'sast_result'],
        ['source-gate', 'source_gate_result']
      ]) {
        assert.match(
          conformance,
          new RegExp(`"${control}":\\{"status":"\\$\\{\\{ needs\\.source-security\\.outputs\\.${output} \\}\\}"`),
          `${control} must be evidenced by ${output}`
        );
      }
      assert.ok(
        !/"status":"\$\{\{ needs\.source-security\.result \}\}"/.test(conformance),
        'no source control may be evidenced by the aggregate needs.source-security.result'
      );
      assert.match(conformance, /"verdict":"\$\{\{ needs\.source-security\.outputs\.verdict \}\}"/);
      assert.match(conformance, /"integrity_trusted":"\$\{\{ needs\.source-security\.outputs\.integrity_trusted \}\}"/);
      // The JSON must stay parseable once expressions are substituted.
      const observed = conformance.match(/observed: >-\n([\s\S]*?)\n(?:\S|$)/)[1];
      const substituted = observed.replace(/\$\{\{[^}]+\}\}/g, 'success').replace(/\n\s*/g, '');
      assert.doesNotThrow(() => JSON.parse(substituted), `${path} observed JSON must parse`);
    });
  }
});
