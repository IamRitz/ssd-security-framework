import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';

import { runImageGate } from '../security/scripts/image-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__/image-gate');
const POLICY = resolve('security/policy.yaml');
const SCRIPT = resolve('security/scripts/image-gate.mjs');

async function evaluate(report) {
  const directory = await mkdtemp(join(tmpdir(), 'image-gate-test-'));
  try {
    return await runImageGate({
      policy: POLICY,
      report,
      output: join(directory, 'image-gate.json')
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe('image deploy gate', () => {
  it('allows deploy only for a genuinely parsed clean scan', async () => {
    const result = await evaluate(join(FIXTURES, 'clean.json'));

    assert.equal(result.verdict, 'DEPLOY');
    assert.deepEqual(result.summary, { blockDeploy: 0, log: 0 });
  });

  it('blocks deploy for a critical image finding', async () => {
    const result = await evaluate(join(FIXTURES, 'critical.json'));

    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.critical');
    assert.equal(result.findings[0].action, 'BLOCK_DEPLOY');
  });

  it('fails closed when the scan report is missing', async () => {
    const result = await evaluate(join(FIXTURES, 'missing.json'));

    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.match(result.findings[0].reason, /missing image scan report/);
  });

  it('fails closed when the scan report is malformed', async () => {
    const result = await evaluate(join(FIXTURES, 'malformed.json'));

    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.match(result.findings[0].reason, /malformed JSON/);
  });

  it('maps deploy decisions directly to process exit codes', async () => {
    return runCliExitCodeCheck();
  });
});

async function evaluateTrivy(report) {
  const directory = await mkdtemp(join(tmpdir(), 'image-gate-trivy-test-'));
  try {
    return await runImageGate({
      policy: POLICY,
      source: 'trivy',
      report,
      output: join(directory, 'image-gate.json')
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe('image deploy gate — Trivy pre-push source', () => {
  it('blocks a critical fixable image finding and records the scanned ImageID', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-critical.json'));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    const critical = result.findings.find((f) => f.policyRule === 'image.critical_with_fix');
    assert.equal(critical.action, 'BLOCK_DEPLOY');
    assert.equal(critical.fixAvailable, true);
    assert.equal(result.image.imageId, 'sha256:1111111111111111111111111111111111111111111111111111111111111111');
  });

  // Phase-8 EXCEPTION state: an unfixable Critical is a tracked exception (deploy
  // proceeds, exit 0) rather than a permanent block waiting on an upstream patch.
  it('treats an unfixable Critical as a tracked EXCEPTION, not a hard block', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-critical-no-fix.json'));
    assert.equal(result.verdict, 'DEPLOY-WITH-EXCEPTIONS');
    assert.equal(result.summary.blockDeploy, 0);
    assert.equal(result.summary.exception, 1);
    const finding = result.findings.find((f) => f.policyRule === 'image.critical_no_fix');
    assert.equal(finding.action, 'EXCEPTION');
    assert.equal(finding.fixAvailable, false);
    assert.equal(result.exceptions.length, 1);
  });

  it('allows deploy for a genuinely parsed clean Trivy scan', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-clean.json'));
    assert.equal(result.verdict, 'DEPLOY');
    assert.equal(result.image.os.family, 'alpine');
  });

  // §5.5 priority case #1: a scan that could not detect the OS reports zero
  // findings — a false clean — and MUST block, not pass.
  it('fails closed when Trivy detected no OS family (false clean)', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-false-clean-no-os.json'));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.report_integrity');
    assert.match(result.findings[0].reason, /did not detect an OS family|false clean/i);
  });

  // §5.5 priority case #2: an end-of-life OS no longer receives advisories, so
  // "clean" means "unknown" and MUST block.
  it('fails closed on an end-of-life (EOSL) OS', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-eosl.json'));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.report_integrity');
    assert.match(result.findings[0].reason, /end-of-life|EOSL/i);
  });

  it('blocks (never overridable) on a secret baked into a layer', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-secret.json'));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    const secret = result.findings.find((f) => f.policyRule === 'image.secret');
    assert.equal(secret.action, 'BLOCK_DEPLOY');
  });

  it('treats UNKNOWN Trivy severity as high (fail-closed)', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'trivy-unknown-severity.json'));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].severity, 'high');
    assert.equal(result.findings[0].policyRule, 'image.high_with_fix');
  });

  it('fails closed when a Trivy report is malformed', async () => {
    const result = await evaluateTrivy(join(FIXTURES, 'malformed.json'));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.match(result.findings[0].reason, /malformed JSON/);
  });
});

async function runCliExitCodeCheck() {
    const directory = await mkdtemp(join(tmpdir(), 'image-gate-cli-test-'));
    const arguments_ = ['--policy', POLICY, '--output', join(directory, 'result.json')];

    try {
      const deploy = spawnSync(
        process.execPath,
        [SCRIPT, ...arguments_, '--report', join(FIXTURES, 'clean.json')],
        { encoding: 'utf8' }
      );
      const block = spawnSync(
        process.execPath,
        [SCRIPT, ...arguments_, '--report', join(FIXTURES, 'critical.json')],
        { encoding: 'utf8' }
      );

      assert.equal(deploy.status, 0);
      assert.match(deploy.stdout, /IMAGE GATE: DEPLOY/);
      assert.notEqual(block.status, 0);
      assert.match(block.stdout, /IMAGE GATE: BLOCK_DEPLOY/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
}
