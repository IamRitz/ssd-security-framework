// ECR response normalization in both scanning modes, against fixtures captured
// from the live API (see security/scripts/__fixtures__/ecr-enhanced/README.md).
//
// The regression this file exists for: a COMPLETE enhanced response also carries
// an empty basic `findings` array. A basic-only normalizer accepted it as a clean
// scan, 1 Critical + 4 High findings normalized to zero, and the image deployed.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { runImageGate } from '../security/scripts/image-gate.mjs';
import { isPermanentAwsError, normalizeEcrResponse } from '../security/scripts/poll-ecr-scan.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__/ecr-enhanced');
const DIGEST = 'sha256:7bb2656c990a9e3c82aa44a28bee2ee14fbcabbc9cf30c642f5c79f112b7b7d1';
const OPTIONS = { repository: 'secure-software-delivery', image_tag: 'f947250', image_digest: DIGEST };

async function fixture(name) {
  return JSON.parse(await readFile(join(FIXTURES, name), 'utf8'));
}

async function gate(report) {
  const directory = await mkdtemp(join(tmpdir(), 'ecr-enhanced-'));
  try {
    const path = join(directory, 'report.json');
    await writeFile(path, JSON.stringify(report));
    return await runImageGate({
      policy: resolve('security/policy.yaml'),
      report: path,
      output: join(directory, 'out.json')
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe('enhanced normalization: the live-captured response', () => {
  it('normalizes the real mixed-severity body as aws-ecr-enhanced with every finding', async () => {
    const report = normalizeEcrResponse(await fixture('complete-mixed.json'), OPTIONS);
    assert.equal(report.source, 'aws-ecr-enhanced');
    assert.equal(report.findings.length, 6);
    assert.deepEqual(report.severityCounts, { critical: 1, high: 4, medium: 1 });

    const critical = report.findings.find((finding) => finding.severity === 'critical');
    assert.deepEqual(
      { id: critical.id, fixAvailable: critical.fixAvailable, package: critical.package, fixedVersion: critical.fixedVersion },
      { id: 'CVE-2026-63073', fixAvailable: true, package: 'openssl/openssl', fixedVersion: '4.0.2' }
    );
  });

  it('blocks deploy end to end for the image that actually shipped', async () => {
    const result = await gate(normalizeEcrResponse(await fixture('complete-mixed.json'), OPTIONS));
    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.integrity.trusted, true);
    assert.deepEqual(result.summary, { blockDeploy: 5, exception: 0, log: 1 });
    assert.ok(result.findings.some((finding) => finding.policyRule === 'image.critical_with_fix'));
  });
});

describe('enhanced normalization: the fail-open regression', () => {
  it('never reads a populated enhanced body as a clean basic scan', async () => {
    const report = normalizeEcrResponse(await fixture('failed-open-regression.json'), OPTIONS);
    assert.notEqual(report.source, 'aws-ecr-basic');
    assert.notEqual(report.findings.length, 0);
  });

  it('refuses to under-report even if enhancedFindings were invisible to the parser', async () => {
    // Guard 2 on its own: strip the enhanced array so only `findings: []` is seen,
    // exactly what the old normalizer saw. ECR's own counts still say 6.
    const body = await fixture('failed-open-regression.json');
    delete body.imageScanFindings.enhancedFindings;
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /refusing to under-report/);
  });

  it('applies the same count reconciliation to basic mode', () => {
    const body = {
      imageScanStatus: { status: 'COMPLETE' },
      imageId: { imageDigest: DIGEST },
      imageScanFindings: { findingSeverityCounts: { HIGH: 2 }, findings: [{ name: 'CVE-2099-1', severity: 'HIGH' }] }
    };
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /reported 2 high .* 1 were parsed/);
  });
});

describe('enhanced normalization: fix availability', () => {
  it('with fix -> BLOCK_DEPLOY', async () => {
    const report = normalizeEcrResponse(await fixture('with-fix.json'), OPTIONS);
    assert.equal(report.findings[0].fixAvailable, true);
    assert.equal((await gate(report)).verdict, 'BLOCK_DEPLOY');
  });

  it('no fix -> tracked EXCEPTION, and no bogus "NotAvailable" fixed version', async () => {
    const report = normalizeEcrResponse(await fixture('no-fix.json'), OPTIONS);
    assert.equal(report.findings[0].fixAvailable, false);
    assert.equal(report.findings[0].fixedVersion, undefined);
    const result = await gate(report);
    assert.equal(result.verdict, 'DEPLOY-WITH-EXCEPTIONS');
    assert.equal(result.findings[0].policyRule, 'image.critical_no_fix');
  });

  it('PARTIAL is fix-available (developer can act), never downgraded to an exception', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.enhancedFindings[0].fixAvailable = 'PARTIAL';
    assert.equal(normalizeEcrResponse(body, OPTIONS).findings[0].fixAvailable, true);
  });

  for (const value of ['MAYBE', '', null, true, undefined]) {
    it(`fails closed on fixAvailable ${JSON.stringify(value)}`, async () => {
      const body = await fixture('with-fix.json');
      body.imageScanFindings.enhancedFindings[0].fixAvailable = value;
      assert.throws(() => normalizeEcrResponse(body, OPTIONS), /unsupported fixAvailable/);
    });
  }
});

describe('enhanced normalization: complete-but-empty vs not-yet-scanned', () => {
  it('a complete scan with no findings is a genuine clean result', async () => {
    const report = normalizeEcrResponse(await fixture('empty-complete.json'), OPTIONS);
    assert.equal(report.source, 'aws-ecr-enhanced');
    assert.equal(report.findings.length, 0);
    assert.equal((await gate(report)).verdict, 'DEPLOY');
  });

  it('the real PENDING body is not complete', async () => {
    const body = await fixture('pending.json');
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /not complete/);
  });

  it('a PENDING body mislabelled COMPLETE still cannot pass as empty-but-complete', async () => {
    // The live PENDING body has `findings: []` and no severity counts.
    const body = await fixture('pending.json');
    body.imageScanStatus.status = 'COMPLETE';
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /lacks findingSeverityCounts/);
  });

  it('keeps the first-attempt ScanNotFoundException retryable (it is always the first answer)', async () => {
    const stderr = await readFile(join(FIXTURES, 'scan-not-found.stderr.txt'), 'utf8');
    assert.match(stderr, /ScanNotFoundException/);
    assert.equal(isPermanentAwsError(stderr), false);
  });
});

describe('enhanced normalization: unrecognized shapes fail closed', () => {
  it('rejects malformed JSON', async () => {
    const raw = await readFile(join(FIXTURES, 'malformed.json'), 'utf8');
    assert.throws(() => JSON.parse(raw));
  });

  it('rejects a body with both basic and enhanced findings populated', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.findings = [{ name: 'CVE-2099-X', severity: 'LOW' }];
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /mode is ambiguous/);
  });

  it('rejects a body with neither array', async () => {
    const body = await fixture('with-fix.json');
    delete body.imageScanFindings.enhancedFindings;
    delete body.imageScanFindings.findings;
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /neither findings nor enhancedFindings/);
  });

  it('rejects an unverified finding type', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.enhancedFindings[0].type = 'CODE_VULNERABILITY';
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /unsupported type/);
  });

  it('rejects an unobserved finding status rather than silently dropping it', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.enhancedFindings[0].status = 'SUPPRESSED';
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /unsupported status/);
  });

  it('rejects an unknown severity', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.enhancedFindings[0].severity = 'SEVERE';
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /unsupported enhanced severity/);
  });

  it('maps UNTRIAGED up to high, never down', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.enhancedFindings[0].severity = 'UNTRIAGED';
    body.imageScanFindings.findingSeverityCounts = { UNTRIAGED: 1 };
    assert.equal(normalizeEcrResponse(body, OPTIONS).findings[0].severity, 'high');
  });

  it('rejects a finding whose resource names a different image', async () => {
    const body = await fixture('with-fix.json');
    body.imageScanFindings.enhancedFindings[0].resources[0].details.awsEcrContainerImage.imageHash = 'sha256:other';
    assert.throws(() => normalizeEcrResponse(body, OPTIONS), /is for image sha256:other/);
  });

  it('rejects a response for a different digest than the one polled', async () => {
    const body = await fixture('with-fix.json');
    assert.throws(
      () => normalizeEcrResponse(body, { ...OPTIONS, image_digest: 'sha256:different' }),
      /does not match requested/
    );
  });
});

describe('both modes produce the same internal representation for the gate', () => {
  it('shares id/severity and differs only in fields basic scanning cannot supply', async () => {
    const enhanced = normalizeEcrResponse(await fixture('with-fix.json'), OPTIONS);
    const basic = normalizeEcrResponse(
      {
        imageScanStatus: { status: 'COMPLETE' },
        imageId: { imageDigest: DIGEST },
        imageScanFindings: {
          findingSeverityCounts: { CRITICAL: 1 },
          findings: [{ name: 'CVE-2026-63073', severity: 'CRITICAL' }]
        }
      },
      OPTIONS
    );
    for (const key of ['schemaVersion', 'scanStatus', 'image', 'severityCounts']) {
      assert.deepEqual(basic[key], enhanced[key], `mismatch on ${key}`);
    }
    assert.deepEqual(
      { id: basic.findings[0].id, severity: basic.findings[0].severity },
      { id: enhanced.findings[0].id, severity: enhanced.findings[0].severity }
    );
    assert.deepEqual(Object.keys(basic.findings[0]).sort(), ['id', 'severity']);
  });
});
