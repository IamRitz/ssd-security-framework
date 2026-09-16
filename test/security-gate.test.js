import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';

import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const GATE_SCRIPT = resolve('security/scripts/security-gate.mjs');

async function evaluate(overrides = {}) {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'security-gate-test-'));
  const paths = {
    policy: resolve('security/policy.yaml'),
    gitleaks: join(CLEAN, 'gitleaks.json'),
    trufflehog: join(CLEAN, 'trufflehog.json'),
    npmAudit: join(CLEAN, 'npm-audit.json'),
    osv: join(CLEAN, 'osv-scanner.json'),
    semgrep: join(CLEAN, 'semgrep.json'),
    baseline: join(CLEAN, 'semgrep-baseline.json'),
    output: join(outputDirectory, 'security-gate.json'),
    exceptions: join(outputDirectory, 'gate-exceptions.json'),
    ...overrides
  };

  try {
    const result = await runSecurityGate(paths);
    const exceptions = JSON.parse(await readFile(paths.exceptions, 'utf8'));
    return { result, exceptions };
  } finally {
    await rm(outputDirectory, { recursive: true, force: true });
  }
}

function onlyFinding(result) {
  assert.equal(result.findings.length, 1);
  return result.findings[0];
}

describe('security gate', () => {
  it('passes genuinely clean reports', async () => {
    const { result, exceptions } = await evaluate();

    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(result.summary, { block: 0, exception: 0, log: 0 });
    assert.deepEqual(exceptions.exceptions, []);
  });

  it('blocks a verified secret', async () => {
    const { result } = await evaluate({
      trufflehog: join(FIXTURES, 'verified-secret/trufflehog.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'secrets.verified');
    assert.equal(result.breakGlass.eligible, false);
  });

  it('blocks the dedicated non-credential demo marker without calling it verified', async () => {
    const { result } = await evaluate({
      gitleaks: join(FIXTURES, 'demo-dummy-secret/gitleaks.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'secrets.demo_dummy');
    assert.match(onlyFinding(result).reason, /non-credential marker/);
  });

  it('blocks a critical dependency with a fix', async () => {
    const { result } = await evaluate({
      npmAudit: join(FIXTURES, 'critical-with-fix/npm-audit.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_with_fix');
    assert.equal(result.breakGlass.eligible, true);
  });

  it('passes with a visible exception for an unfixed critical dependency', async () => {
    const { result, exceptions } = await evaluate({
      npmAudit: join(FIXTURES, 'critical-no-fix/npm-audit.json')
    });

    assert.equal(result.verdict, 'PASS-WITH-EXCEPTIONS');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_no_fix');
    assert.equal(exceptions.exceptions.length, 1);
  });

  it('blocks an OSV malicious-package advisory regardless of severity', async () => {
    const { result } = await evaluate({
      osv: join(FIXTURES, 'malicious-package/osv-scanner.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.malicious_package');
    assert.equal(result.breakGlass.eligible, false);
  });

  it('blocks a critical OSV advisory when its range contains a fix', async () => {
    const { result } = await evaluate({
      osv: join(FIXTURES, 'osv-critical-with-fix/osv-scanner.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).cvssScore, 9.8);
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_with_fix');
  });

  it('excepts a critical OSV advisory when its range contains no fix', async () => {
    const { result, exceptions } = await evaluate({
      osv: join(FIXTURES, 'osv-critical-no-fix/osv-scanner.json')
    });

    assert.equal(result.verdict, 'PASS-WITH-EXCEPTIONS');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_no_fix');
    assert.equal(exceptions.exceptions.length, 1);
  });

  it('blocks a new high-severity Semgrep finding', async () => {
    const { result } = await evaluate({
      semgrep: join(FIXTURES, 'new-high-sast/semgrep.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'sast.high_new');
    assert.equal(result.breakGlass.eligible, true);
  });

  it('logs an existing critical Semgrep finding without blocking', async () => {
    const { result } = await evaluate({
      semgrep: join(FIXTURES, 'existing-critical-sast/semgrep.json'),
      baseline: join(FIXTURES, 'existing-critical-sast/semgrep-baseline.json')
    });

    assert.equal(result.verdict, 'PASS');
    assert.equal(onlyFinding(result).policyRule, 'sast.critical_existing');
    assert.equal(onlyFinding(result).action, 'LOG');
  });

  it('fails closed when a report is missing', async () => {
    // The npm-audit report is REQUIRED only where an npm lockfile exists, so this
    // test declares its own ecosystem rather than inheriting whatever repository
    // it happens to run inside. That ambient dependency was invisible until the
    // toolkit was extracted: identical code blocked in a repo with a lockfile and
    // reported PASS in one without.
    const repoDirectory = await mkdtemp(join(tmpdir(), 'gate-npm-repo-'));
    await writeFile(join(repoDirectory, 'package-lock.json'), '{}');

    try {
      const { result } = await evaluate({
        repoDir: repoDirectory,
        npmAudit: join(FIXTURES, 'does-not-exist.json')
      });

      assert.equal(result.verdict, 'BLOCK');
      assert.match(onlyFinding(result).reason, /missing report file/);
    } finally {
      await rm(repoDirectory, { recursive: true, force: true });
    }
  });

  it('fails closed when a report contains malformed JSON', async () => {
    const { result } = await evaluate({
      npmAudit: join(FIXTURES, 'malformed/npm-audit.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.match(onlyFinding(result).reason, /malformed JSON/);
  });

  it('fails closed when a finding omits a field required by policy', async () => {
    const { result } = await evaluate({
      trufflehog: join(FIXTURES, 'missing-field/trufflehog.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.match(onlyFinding(result).reason, /missing Verified/);
  });

  it('maps PASS, exception, and BLOCK verdicts directly to process exit codes', async () => {
    const outputDirectory = await mkdtemp(join(tmpdir(), 'security-gate-cli-test-'));
    // Stated, not inherited: the BLOCK case below relies on npm audit being a
    // REQUIRED report, which is only true where an npm lockfile exists.
    const repoDirectory = await mkdtemp(join(tmpdir(), 'security-gate-cli-repo-'));
    await writeFile(join(repoDirectory, 'package-lock.json'), '{}');
    const commonArguments = [
      '--repo-dir',
      repoDirectory,
      '--policy',
      resolve('security/policy.yaml'),
      '--gitleaks',
      join(CLEAN, 'gitleaks.json'),
      '--trufflehog',
      join(CLEAN, 'trufflehog.json'),
      '--osv',
      join(CLEAN, 'osv-scanner.json'),
      '--semgrep',
      join(CLEAN, 'semgrep.json'),
      '--baseline',
      join(CLEAN, 'semgrep-baseline.json'),
      '--output',
      join(outputDirectory, 'security-gate.json'),
      '--exceptions',
      join(outputDirectory, 'gate-exceptions.json')
    ];

    try {
      const pass = spawnSync(
        process.execPath,
        [GATE_SCRIPT, ...commonArguments, '--npm-audit', join(CLEAN, 'npm-audit.json')],
        { encoding: 'utf8' }
      );
      const block = spawnSync(
        process.execPath,
        [GATE_SCRIPT, ...commonArguments, '--npm-audit', join(FIXTURES, 'does-not-exist.json')],
        { encoding: 'utf8' }
      );
      const exception = spawnSync(
        process.execPath,
        [
          GATE_SCRIPT,
          ...commonArguments,
          '--npm-audit',
          join(FIXTURES, 'critical-no-fix/npm-audit.json')
        ],
        { encoding: 'utf8' }
      );

      assert.equal(pass.status, 0);
      assert.match(pass.stdout, /SECURITY GATE: PASS/);
      assert.equal(exception.status, 0);
      assert.match(exception.stdout, /SECURITY GATE: PASS-WITH-EXCEPTIONS/);
      assert.notEqual(block.status, 0);
      assert.match(block.stdout, /SECURITY GATE: BLOCK/);
    } finally {
      await rm(outputDirectory, { recursive: true, force: true });
      await rm(repoDirectory, { recursive: true, force: true });
    }
  });
});

const PIP = join(FIXTURES, 'pip-audit');
const NO_FILE = join(FIXTURES, 'does-not-exist.json');

async function repoDirWith(files) {
  const dir = await mkdtemp(join(tmpdir(), 'gate-repo-'));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content);
  }
  return dir;
}

function hasIntegrityBlock(result) {
  return result.findings.some((finding) => finding.policyRule === 'gate.report_integrity');
}

describe('security gate — pip-audit (Python) parsing', () => {
  it('blocks a fixable Python advisory and dedupes repeated (package, id) pairs', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'requests==2.19.1\n' });
    try {
      const { result } = await evaluate({
        repoDir,
        npmAudit: NO_FILE,
        pipAudit: join(PIP, 'high-with-fix.json')
      });
      const pip = result.findings.filter((finding) => finding.source === 'pip-audit');
      assert.equal(pip.length, 1); // the duplicate advisory is collapsed
      assert.equal(pip[0].policyRule, 'dependencies.high_with_fix');
      assert.equal(pip[0].action, 'BLOCK');
      assert.equal(pip[0].severity, 'high');
      assert.equal(result.verdict, 'BLOCK');
      assert.equal(result.breakGlass.eligible, true);
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('treats an unfixable Python advisory as a tracked exception', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'x\n' });
    try {
      const { result, exceptions } = await evaluate({
        repoDir,
        npmAudit: NO_FILE,
        pipAudit: join(PIP, 'high-no-fix.json')
      });
      const pip = result.findings.find((finding) => finding.source === 'pip-audit');
      assert.equal(pip.policyRule, 'dependencies.high_no_fix');
      assert.equal(pip.action, 'EXCEPTION');
      assert.equal(result.verdict, 'PASS-WITH-EXCEPTIONS');
      assert.equal(exceptions.exceptions.length, 1);
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('routes a pip-audit MAL- advisory to malicious_package (never break-glass)', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'x\n' });
    try {
      const { result } = await evaluate({
        repoDir,
        npmAudit: NO_FILE,
        pipAudit: join(PIP, 'malicious.json')
      });
      const pip = result.findings.find((finding) => finding.source === 'pip-audit');
      assert.equal(pip.policyRule, 'dependencies.malicious_package');
      assert.equal(pip.action, 'BLOCK');
      assert.equal(pip.breakGlassEligible, false);
      assert.equal(result.breakGlass.eligible, false);
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('passes clean pip-audit output (empty vulns and skipped deps)', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'x\n' });
    try {
      const { result } = await evaluate({
        repoDir,
        npmAudit: NO_FILE,
        pipAudit: join(PIP, 'clean.json')
      });
      assert.equal(result.findings.filter((finding) => finding.source === 'pip-audit').length, 0);
      assert.equal(result.verdict, 'PASS');
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('fail-closed BLOCKs on a malformed pip-audit report when Python is present', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'x\n' });
    try {
      const { result } = await evaluate({
        repoDir,
        npmAudit: NO_FILE,
        pipAudit: join(PIP, 'malformed.json')
      });
      assert.equal(result.verdict, 'BLOCK');
      assert.equal(onlyFinding(result).policyRule, 'gate.report_integrity');
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('requires a pip-audit report when Python is detected (missing => integrity BLOCK)', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'x\n' });
    try {
      const { result } = await evaluate({ repoDir, npmAudit: NO_FILE, pipAudit: NO_FILE });
      assert.equal(result.verdict, 'BLOCK');
      assert.match(onlyFinding(result).reason, /missing report file/);
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });
});

describe('security gate — ecosystem detect-and-skip', () => {
  it('a Python-only repo skips npm audit cleanly and runs pip-audit', async () => {
    const repoDir = await repoDirWith({ 'requirements.txt': 'requests==2.19.1\n' });
    try {
      const { result } = await evaluate({
        repoDir,
        npmAudit: NO_FILE,
        pipAudit: join(PIP, 'high-with-fix.json')
      });
      assert.equal(result.findings.some((finding) => finding.source === 'npm-audit'), false);
      assert.equal(result.findings.some((finding) => finding.source === 'pip-audit'), true);
      assert.equal(hasIntegrityBlock(result), false); // absent npm audit is a clean skip
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('a repo with neither ecosystem skips both audits cleanly (no confusing failure)', async () => {
    const repoDir = await repoDirWith({ 'README.md': '# hi' });
    try {
      const { result } = await evaluate({ repoDir, npmAudit: NO_FILE, pipAudit: NO_FILE });
      assert.equal(result.findings.some((finding) => finding.source === 'npm-audit'), false);
      assert.equal(result.findings.some((finding) => finding.source === 'pip-audit'), false);
      assert.equal(hasIntegrityBlock(result), false);
      assert.equal(result.verdict, 'PASS');
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('a monorepo with both ecosystems runs both audits', async () => {
    const repoDir = await repoDirWith({ 'package-lock.json': '{}', 'requirements.txt': 'x\n' });
    try {
      const { result } = await evaluate({
        repoDir,
        npmAudit: join(CLEAN, 'npm-audit.json'),
        pipAudit: join(PIP, 'high-no-fix.json')
      });
      assert.equal(hasIntegrityBlock(result), false);
      assert.equal(result.findings.some((finding) => finding.source === 'pip-audit'), true);
      assert.equal(result.verdict, 'PASS-WITH-EXCEPTIONS');
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });
});
