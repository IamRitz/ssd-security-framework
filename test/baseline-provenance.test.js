// The provenance record that binds a Semgrep baseline candidate to its scan.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { buildProvenance, canonicalJson, provenanceDigest } from '../security/scripts/baseline-provenance.mjs';
import { parseYaml } from '../onboarding/lib/yaml.mjs';

const ENV = {
  CI_REPOSITORY: 'acme/app',
  CI_REPOSITORY_ID: '1',
  CI_DEFAULT_BRANCH: 'main',
  CI_SHA: 'c'.repeat(40),
  CI_REF: 'refs/heads/main',
  CI_EVENT: 'workflow_dispatch',
  CI_RUN_ID: '7',
  CI_RUN_ATTEMPT: '1',
  TOOLKIT_REPOSITORY: 'IamRitz/ssd-security-framework',
  TOOLKIT_REF: 'a'.repeat(40),
  SEMGREP_CONFIGS: 'p/owasp-top-ten\np/python\n',
  SEMGREP_PATHS: '.',
  BASELINE_PATH: 'security/baseline/semgrep-baseline.json'
};
const GATE = {
  integrity: { trusted: true },
  bootstrap: { active: true },
  scannerExecution: { records: [{ scanner: 'semgrep', image: 'semgrep/semgrep@sha256:' + '1'.repeat(64) }] }
};
const CANDIDATE = Buffer.from(JSON.stringify({ schemaVersion: 1, generatedBy: 'semgrep 1.176.0', rulesets: ['p/owasp-top-ten', 'p/python'], findings: [] }));

describe('baseline candidate provenance', () => {
  it('records the scan: repository, commit, ref, event, run, framework, Semgrep image/version/configs/paths, ignore hash', () => {
    const p = buildProvenance({ env: ENV, candidateBytes: CANDIDATE, gate: GATE, semgrepignoreBytes: Buffer.from('dist/\n') });
    assert.equal(p.repository.slug, 'acme/app');
    assert.equal(p.scan.commit, 'c'.repeat(40));
    assert.equal(p.scan.event, 'workflow_dispatch');
    assert.equal(p.framework.ref, 'a'.repeat(40));
    assert.equal(p.semgrep.image, GATE.scannerExecution.records[0].image);
    assert.equal(p.semgrep.version, 'semgrep 1.176.0');
    assert.deepEqual(p.semgrep.configs, ['p/owasp-top-ten', 'p/python']);
    assert.deepEqual(p.semgrep.paths, ['.']);
    assert.match(p.semgrep.semgrepignoreSha256, /^[0-9a-f]{64}$/);
    assert.equal(p.candidate.findings, 0);
    assert.equal(p.digest, provenanceDigest(p));
  });

  it('records an absent .semgrepignore as null (Semgrep applied its built-in list)', () => {
    assert.equal(buildProvenance({ env: ENV, candidateBytes: CANDIDATE, gate: GATE, semgrepignoreBytes: null }).semgrep.semgrepignoreSha256, null);
  });

  it('the digest changes with any recorded field and is independent of key order', () => {
    const p = buildProvenance({ env: ENV, candidateBytes: CANDIDATE, gate: GATE, semgrepignoreBytes: null });
    assert.notEqual(provenanceDigest({ ...p, scan: { ...p.scan, commit: 'd'.repeat(40) } }), p.digest);
    assert.equal(canonicalJson({ b: 1, a: [2, { d: 3, c: 4 }] }), canonicalJson({ a: [2, { c: 4, d: 3 }], b: 1 }));
  });

  for (const [label, gate, pattern] of [
    ['an untrusted scan', { ...GATE, integrity: { trusted: false } }, /integrity\.trusted/],
    ['a run that was not a bootstrap', { ...GATE, bootstrap: { active: false } }, /not a baseline bootstrap/]
  ]) {
    it(`refuses ${label}`, () => {
      assert.throws(() => buildProvenance({ env: ENV, candidateBytes: CANDIDATE, gate, semgrepignoreBytes: null }), pattern);
    });
  }

  it('refuses when run identity is missing', () => {
    assert.throws(() => buildProvenance({ env: { ...ENV, CI_SHA: '' }, candidateBytes: CANDIDATE, gate: GATE, semgrepignoreBytes: null }), /CI_SHA/);
  });

  it('the script writes the record from the environment the workflow passes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prov-'));
    writeFileSync(join(dir, 'candidate.json'), CANDIDATE);
    writeFileSync(join(dir, 'gate.json'), JSON.stringify(GATE));
    const result = spawnSync(
      process.execPath,
      [join(process.cwd(), 'security/scripts/baseline-provenance.mjs'), '--candidate', 'candidate.json', '--gate', 'gate.json', '--semgrepignore', '.semgrepignore', '--output', 'out.json'],
      { cwd: dir, env: { PATH: process.env.PATH, ...ENV }, encoding: 'utf8' }
    );
    assert.equal(result.status, 0, result.stderr);
    const written = JSON.parse(readFileSync(join(dir, 'out.json'), 'utf8'));
    assert.equal(written.digest, provenanceDigest(written));
  });

  it('_source-security.yml produces and uploads provenance in the bootstrap step, from run context', () => {
    const { jobs } = parseYaml(readFileSync('.github/workflows/_source-security.yml', 'utf8'));
    const steps = jobs['source-gate'].steps;
    const step = steps.find((s) => s.name === 'Generate the first Semgrep baseline (bootstrap only)');
    assert.match(step.run, /baseline-provenance\.mjs/);
    assert.ok(step.run.indexOf('generate-semgrep-baseline.mjs') < step.run.indexOf('baseline-provenance.mjs'));
    assert.equal(step.env.CI_SHA, '${{ github.sha }}');
    assert.equal(step.env.CI_EVENT, '${{ github.event_name }}');
    assert.equal(step.env.TOOLKIT_REF, '${{ inputs.toolkit_ref }}');
    assert.equal(step.env.SEMGREP_PATHS, '${{ inputs.semgrep_paths }}');
    const upload = steps.find((s) => s.name === 'Upload security gate decision');
    assert.match(upload.with.path, /semgrep-baseline\.candidate\.provenance\.json/);
  });
});
