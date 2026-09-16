// The first-onboarding bootstrap, and the deadlock it resolves.
//
// Before this existed, a brand-new repository could not adopt the framework:
//
//   no baseline -> security-gate reports a report-integrity BLOCK
//               -> integrity.trusted = false
//               -> generate-semgrep-baseline.mjs correctly refuses
//               -> no baseline can ever be produced
//
// The fix must not become "a missing baseline is fine", because two situations
// are indistinguishable on disk:
//
//   A. a first onboarding, where no baseline exists yet
//   B. an onboarded repo whose baseline was deleted or lost
//
// B must keep failing closed. The discriminator is therefore explicit operator
// intent, and these tests pin both halves: bootstrap works for A, and refuses
// to touch a repo that already has a baseline.
//
// Critically, bootstrap lowers NO scanner-integrity bar. Semgrep is still
// schema-validated and still rejected when it carries scan errors, so a scan
// that never really happened can never become the permanently accepted set.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { runSecurityGate } from '../security/scripts/security-gate.mjs';
import {
  assertScansTrusted,
  buildBaseline
} from '../security/scripts/generate-semgrep-baseline.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const POLICY = resolve('security/policy.yaml');
const RULESETS = ['p/owasp-top-ten', 'p/javascript'];

// A Semgrep report with one genuine high-severity finding, written inline so the
// test controls exactly what the scanner "said".
function semgrepWith(results, overrides = {}) {
  return {
    version: '1.176.0',
    results,
    errors: [],
    paths: { scanned: ['src/app.js'] },
    ...overrides
  };
}

const HIGH_FINDING = {
  check_id: 'rules.command-injection',
  path: 'src/app.js',
  start: { line: 10 },
  extra: { lines: '  exec(req.query.cmd)', severity: 'ERROR' }
};

const SECOND_FINDING = {
  check_id: 'rules.weak-hash',
  path: 'src/hash.js',
  start: { line: 4 },
  extra: { lines: "  crypto.createHash('md5')", severity: 'WARNING' }
};

async function workspace(files = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'bootstrap-'));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(
      join(dir, name),
      typeof content === 'string' ? content : JSON.stringify(content)
    );
  }
  return dir;
}

// Runs the gate the way the workflow does: clean inputs for everything except
// Semgrep and the baseline, which are what bootstrap is about.
async function gate({ dir, semgrep, baselinePath, bootstrap }) {
  const paths = {
    policy: POLICY,
    repoDir: dir,
    gitleaks: join(CLEAN, 'gitleaks.json'),
    trufflehog: join(CLEAN, 'trufflehog.json'),
    npmAudit: join(FIXTURES, 'does-not-exist.json'),
    osv: join(CLEAN, 'osv-scanner.json'),
    semgrep,
    baseline: baselinePath,
    output: join(dir, 'security-gate.json'),
    exceptions: join(dir, 'gate-exceptions.json')
  };
  return runSecurityGate(bootstrap ? { ...paths, bootstrap: true } : paths);
}

const fingerprintOf = (finding) =>
  createHash('sha256')
    .update(`${finding.check_id}\0${finding.path}\0${finding.extra.lines.trim()}`)
    .digest('hex');

describe('baseline bootstrap: a brand-new repository can onboard', () => {
  it('bootstraps a repo that has never had a baseline', async () => {
    const dir = await workspace({ 'semgrep.json': semgrepWith([HIGH_FINDING]) });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'security/baseline/semgrep-baseline.json'),
        bootstrap: true
      });

      // The scan is TRUSTED: every scanner interpreted its input. That is the
      // only property the baseline generator requires, and it is established
      // without any baseline existing.
      assert.equal(result.integrity.trusted, true);
      assert.equal(result.bootstrap.active, true);
      assert.match(result.bootstrap.reason, /empty accepted set/);

      // Nothing is waved through: the finding is reported, just not yet accepted.
      const semgrepFinding = result.findings.find((finding) => finding.source === 'semgrep');
      assert.equal(semgrepFinding.baselineState, 'unbaselined');

      // And the generator accepts this run.
      assertScansTrusted([{ path: 'security-gate.json', result }]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('bootstraps a repo that already has Semgrep findings', async () => {
    const dir = await workspace({
      'semgrep.json': semgrepWith([HIGH_FINDING, SECOND_FINDING])
    });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'missing-baseline.json'),
        bootstrap: true
      });
      assert.equal(result.integrity.trusted, true);

      const baseline = buildBaseline(semgrepWith([HIGH_FINDING, SECOND_FINDING]), RULESETS);
      assert.equal(baseline.findings.length, 2, 'both pre-existing findings are accepted');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('bootstraps a repo with zero findings', async () => {
    const dir = await workspace({ 'semgrep.json': semgrepWith([]) });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'missing-baseline.json'),
        bootstrap: true
      });

      assert.equal(result.verdict, 'PASS');
      assert.equal(result.integrity.trusted, true);

      const baseline = buildBaseline(semgrepWith([]), RULESETS);
      assert.deepEqual(baseline.findings, []);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('baseline bootstrap: scanner integrity is still proven', () => {
  it('cannot bootstrap from malformed Semgrep JSON', async () => {
    const dir = await workspace({ 'semgrep.json': '{"version": "1.176.0", "results": [' });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'missing-baseline.json'),
        bootstrap: true
      });

      assert.equal(result.verdict, 'BLOCK');
      assert.equal(result.integrity.trusted, false);
      assert.match(result.findings[0].reason, /malformed JSON/);
      // The generator independently refuses the same run.
      assert.throws(() => assertScansTrusted([{ path: 'gate.json', result }]));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cannot bootstrap from a Semgrep report containing scan errors', async () => {
    // Zero findings plus an error means Semgrep did not finish looking. Accepting
    // that as the baseline would record "nothing to see here" permanently.
    const dir = await workspace({
      'semgrep.json': semgrepWith([], { errors: [{ message: 'rule timeout' }] })
    });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'missing-baseline.json'),
        bootstrap: true
      });

      assert.equal(result.integrity.trusted, false);
      assert.match(result.findings[0].reason, /errors/);
      assert.throws(() => assertScansTrusted([{ path: 'gate.json', result }]));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cannot bootstrap from a missing Semgrep report', async () => {
    const dir = await workspace({});
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'never-written.json'),
        baselinePath: join(dir, 'missing-baseline.json'),
        bootstrap: true
      });

      assert.equal(result.integrity.trusted, false);
      assert.match(result.findings[0].reason, /missing report file/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('refuses to bootstrap a repository that already has a baseline', async () => {
    // Case B: the baseline disappeared, or someone re-ran onboarding. Bootstrap
    // creates a FIRST baseline; it must never silently replace an existing one.
    const dir = await workspace({
      'semgrep.json': semgrepWith([HIGH_FINDING]),
      'semgrep-baseline.json': { schemaVersion: 1, rulesets: RULESETS, findings: [] }
    });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'semgrep-baseline.json'),
        bootstrap: true
      });

      assert.equal(result.verdict, 'BLOCK');
      assert.equal(result.integrity.trusted, false);
      assert.match(result.findings[0].reason, /bootstrap refused/);
      assert.match(result.findings[0].reason, /first onboarding only/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('baseline bootstrap: normal mode is unchanged', () => {
  it('a missing baseline OUTSIDE bootstrap is still a fail-closed integrity BLOCK', async () => {
    // The whole point of making bootstrap explicit: without the flag, nothing
    // about a missing baseline is tolerated.
    const dir = await workspace({ 'semgrep.json': semgrepWith([]) });
    try {
      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'missing-baseline.json'),
        bootstrap: false
      });

      assert.equal(result.verdict, 'BLOCK');
      assert.equal(result.integrity.trusted, false);
      assert.equal(result.bootstrap.active, false);
      assert.match(result.findings[0].reason, /missing report file/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('baseline bootstrap: the generated baseline is correct and usable', () => {
  it('records exact fingerprints for the findings it accepts', async () => {
    const baseline = buildBaseline(semgrepWith([HIGH_FINDING, SECOND_FINDING]), RULESETS);

    const expected = [HIGH_FINDING, SECOND_FINDING].map(fingerprintOf).sort();
    assert.deepEqual(
      baseline.findings.map((finding) => finding.fingerprint).sort(),
      expected,
      'fingerprint must be sha256(check_id\\0path\\0matched text)'
    );
    for (const finding of baseline.findings) {
      assert.equal(typeof finding.checkId, 'string');
      assert.equal(typeof finding.path, 'string');
    }
  });

  it('records the rulesets it was generated with', async () => {
    // A baseline that claims rulesets it never saw is a quieter false clean: a
    // later scan with different rules compares against findings those rules
    // never produced.
    const baseline = buildBaseline(semgrepWith([HIGH_FINDING]), RULESETS);
    assert.deepEqual(baseline.rulesets, RULESETS);
    assert.equal(baseline.schemaVersion, 1);
    assert.match(baseline.generatedBy, /^semgrep /);
  });

  it('a normal gate run then passes against the generated baseline', async () => {
    // The end of the onboarding path: bootstrap -> generate -> commit -> enforce.
    const report = semgrepWith([HIGH_FINDING]);
    const dir = await workspace({ 'semgrep.json': report });
    try {
      const bootstrapResult = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'baseline.json'),
        bootstrap: true
      });
      assert.equal(bootstrapResult.integrity.trusted, true);

      // Generate and "commit" the baseline.
      const baseline = buildBaseline(report, RULESETS);
      await writeFile(join(dir, 'baseline.json'), JSON.stringify(baseline));

      // Now run normally — no bootstrap flag at all.
      const normal = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'baseline.json'),
        bootstrap: false
      });

      assert.equal(normal.bootstrap.active, false);
      assert.equal(normal.integrity.trusted, true);
      // The finding is now baseline-known, so it logs instead of blocking.
      const semgrepFinding = normal.findings.find((finding) => finding.source === 'semgrep');
      assert.equal(semgrepFinding.baselineState, 'existing');
      assert.equal(semgrepFinding.action, 'LOG');
      assert.equal(normal.verdict, 'PASS');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('a NEW finding still blocks after the baseline is in place', async () => {
    // Proof the baseline accepted the backlog without disarming the gate.
    const dir = await workspace({});
    try {
      const baseline = buildBaseline(semgrepWith([HIGH_FINDING]), RULESETS);
      await writeFile(join(dir, 'baseline.json'), JSON.stringify(baseline));
      await writeFile(
        join(dir, 'semgrep.json'),
        JSON.stringify(semgrepWith([HIGH_FINDING, SECOND_FINDING]))
      );

      const result = await gate({
        dir,
        semgrep: join(dir, 'semgrep.json'),
        baselinePath: join(dir, 'baseline.json'),
        bootstrap: false
      });

      const fresh = result.findings.find((finding) => finding.baselineState === 'new');
      assert.ok(fresh, 'the finding absent from the baseline must be reported as new');
      assert.equal(await readFile(join(dir, 'baseline.json'), 'utf8').then(Boolean), true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
