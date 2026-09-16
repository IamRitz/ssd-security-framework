// The artifact gate over NORMALIZED registry reports, in both ECR scanning modes.
//
// These fixtures are written in our own normalized schema, not in AWS's response
// shape: the collector owns the AWS -> normalized mapping (and is tested against
// the live-captured response separately). What is pinned here is the gate's side
// of the contract — which source strings are admitted, and what each mode may
// conclude from a finding.
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { runImageGate } from '../security/scripts/image-gate.mjs';

const POLICY = resolve('security/policy.yaml');

function report(source, findings, overrides = {}) {
  const severityCounts = {};
  for (const finding of findings) {
    const severity = String(finding.severity).toLowerCase();
    severityCounts[severity] = (severityCounts[severity] ?? 0) + 1;
  }
  return {
    schemaVersion: 1,
    source,
    scanStatus: 'COMPLETE',
    image: { repository: 'secure-software-delivery', imageTag: 'test', imageDigest: 'sha256:abc' },
    severityCounts,
    findings,
    ...overrides
  };
}

async function gate(body) {
  const directory = await mkdtemp(join(tmpdir(), 'registry-gate-'));
  try {
    const path = join(directory, 'report.json');
    await writeFile(path, JSON.stringify(body));
    return await runImageGate({ policy: POLICY, report: path, output: join(directory, 'out.json') });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const CRITICAL_WITH_FIX = {
  id: 'CVE-2099-0001',
  severity: 'critical',
  fixAvailable: true,
  package: 'openssl',
  fixedVersion: '3.3.2-r0'
};
const CRITICAL_NO_FIX = { id: 'CVE-2099-0002', severity: 'critical', fixAvailable: false, package: 'busybox' };
const HIGH_NO_FIX = { id: 'CVE-2099-0003', severity: 'high', fixAvailable: false, package: 'musl' };
const MEDIUM = { id: 'CVE-2099-0004', severity: 'medium', fixAvailable: true, package: 'zlib' };

describe('registry gate: aws-ecr-enhanced uses the fix-availability model', () => {
  it('blocks a Critical with a fix available', async () => {
    const result = await gate(report('aws-ecr-enhanced', [CRITICAL_WITH_FIX]));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.critical_with_fix');
    assert.equal(result.findings[0].source, 'ecr-enhanced-scan');
    assert.equal(result.findings[0].fixedVersion, '3.3.2-r0');
  });

  it('turns a Critical/High with no upstream fix into a tracked EXCEPTION, not a block', async () => {
    const result = await gate(report('aws-ecr-enhanced', [CRITICAL_NO_FIX, HIGH_NO_FIX]));
    assert.equal(result.verdict, 'DEPLOY-WITH-EXCEPTIONS');
    assert.deepEqual(
      result.findings.map((finding) => [finding.policyRule, finding.action]),
      [
        ['image.critical_no_fix', 'EXCEPTION'],
        ['image.high_no_fix', 'EXCEPTION']
      ]
    );
    assert.equal(result.exceptions.length, 2);
  });

  it('lets one fixable block win over exceptions in a mixed report', async () => {
    const result = await gate(
      report('aws-ecr-enhanced', [CRITICAL_NO_FIX, CRITICAL_WITH_FIX, MEDIUM])
    );
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.deepEqual(result.summary, { blockDeploy: 1, exception: 1, log: 1 });
  });

  it('keeps Medium/Low severity-only even when fix data exists', async () => {
    const result = await gate(report('aws-ecr-enhanced', [MEDIUM]));
    assert.equal(result.verdict, 'DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.medium');
  });

  it('passes a genuinely clean, complete enhanced report', async () => {
    const result = await gate(report('aws-ecr-enhanced', []));
    assert.equal(result.verdict, 'DEPLOY');
    assert.equal(result.integrity.trusted, true);
  });

  it('fails closed when a fix-aware finding omits fixAvailable, rather than assuming no fix', async () => {
    // Defaulting to "no fix" would convert this BLOCK_DEPLOY into an EXCEPTION.
    const withoutFlag = { ...CRITICAL_WITH_FIX };
    delete withoutFlag.fixAvailable;
    const result = await gate(report('aws-ecr-enhanced', [withoutFlag]));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.integrity.trusted, false);
    assert.match(result.findings[0].reason, /lacks a boolean fixAvailable/);
  });

  it('fails closed on a non-boolean fixAvailable', async () => {
    const result = await gate(
      report('aws-ecr-enhanced', [{ ...CRITICAL_WITH_FIX, fixAvailable: 'YES' }])
    );
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.integrity.trusted, false);
  });
});

describe('registry gate: aws-ecr-basic stays severity-only', () => {
  it('blocks every Critical, ignoring any fix field a basic report might carry', async () => {
    const result = await gate(report('aws-ecr-basic', [CRITICAL_NO_FIX]));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.critical');
    assert.equal(result.findings[0].source, 'ecr-image-scan');
  });

  it('keeps the basic output shape unchanged (no exception fields)', async () => {
    const result = await gate(report('aws-ecr-basic', []));
    assert.deepEqual(result.summary, { blockDeploy: 0, log: 0 });
    assert.equal(result.exceptions, undefined);
  });
});

describe('registry gate: the source assertion stays strict', () => {
  for (const source of ['aws-ecr', 'aws-ecr-inspector', 'AWS-ECR-ENHANCED', '', undefined, 'toString', '__proto__']) {
    it(`rejects source ${JSON.stringify(source)}`, async () => {
      const result = await gate(report(source, []));
      assert.equal(result.verdict, 'BLOCK_DEPLOY');
      assert.equal(result.integrity.trusted, false);
      assert.match(result.findings[0].reason, /unsupported source/);
    });
  }

  it('produces the same internal finding shape from both modes for the same CVE', async () => {
    // What _artifact-gate.yml and the formatter consume must not depend on mode
    // beyond the fields a mode genuinely cannot supply.
    const basic = await gate(report('aws-ecr-basic', [{ id: 'CVE-2099-9', severity: 'medium' }]));
    const enhanced = await gate(
      report('aws-ecr-enhanced', [{ id: 'CVE-2099-9', severity: 'medium', fixAvailable: false }])
    );
    for (const key of ['id', 'severity', 'action', 'policyRule']) {
      assert.equal(basic.findings[0][key], enhanced.findings[0][key], `mismatch on ${key}`);
    }
  });
});
