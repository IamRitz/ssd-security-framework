// The raw-response capture is how the real ECR response shape (basic vs
// enhanced) and any permission error are observed from CI, where the only AWS
// credentials exist. It must survive a failed poll — the failure case is the one
// where the evidence matters most.
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { pollEcrScan } from '../security/scripts/poll-ecr-scan.mjs';

let directory;
let originalPath;

// A stand-in `aws` executable on PATH, so the real spawn path is exercised.
async function fakeAws(script) {
  const bin = join(directory, 'aws');
  await writeFile(bin, `#!/bin/sh\n${script}\n`);
  await chmod(bin, 0o755);
  process.env.PATH = `${directory}:${originalPath}`;
}

function options(overrides = {}) {
  return {
    repository: 'secure-software-delivery',
    region: 'us-east-1',
    image_digest: 'sha256:abc',
    image_tag: 'test',
    raw_output: join(directory, 'raw.json'),
    maxAttempts: 2,
    delaySeconds: 0,
    ...overrides
  };
}

describe('poll-ecr-scan: raw response capture', () => {
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'ecr-raw-'));
    originalPath = process.env.PATH;
  });

  afterEach(async () => {
    process.env.PATH = originalPath;
    await rm(directory, { recursive: true, force: true });
  });

  it('records every failed attempt, stderr included, even though the poll throws', async () => {
    await fakeAws('echo "Could not connect to the endpoint URL" >&2\nexit 255');
    await assert.rejects(pollEcrScan(options()), /AWS CLI failed while polling ECR/);

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts.length, 2);
    assert.equal(raw.attempts[0].exitCode, 255);
    assert.match(raw.attempts[0].stderr, /Could not connect/);
    assert.equal(raw.attempts[0].response, null);
  });

  it('fails closed on the FIRST attempt for an authorization error instead of retrying', async () => {
    // The exact stderr observed live when enhanced scanning was enabled on a role
    // that only had ECR permissions.
    await fakeAws(
      'echo "aws: [ERROR]: An error occurred (AccessDeniedException) when calling the DescribeImageScanFindings operation: User: arn:aws:sts::123456789012:assumed-role/github-actions-ecr-push/ssd-ecr-push-scan is not authorized to perform: inspector2:ListCoverage on resource: arn:aws:inspector2:us-east-1:123456789012:/coverage/list" >&2\nexit 254'
    );
    await assert.rejects(pollEcrScan(options({ maxAttempts: 40 })), /authorization failure .*not retried/);

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts.length, 1);
    assert.match(raw.attempts[0].stderr, /inspector2:ListCoverage/);
  });

  it('records the raw body of a completed scan alongside the normalized result', async () => {
    const body = {
      imageScanStatus: { status: 'COMPLETE' },
      imageId: { imageDigest: 'sha256:abc' },
      imageScanFindings: { findingSeverityCounts: {}, findings: [] }
    };
    await fakeAws(`cat <<'JSON'\n${JSON.stringify(body)}\nJSON`);

    const report = await pollEcrScan(options());
    assert.equal(report.scanStatus, 'COMPLETE');

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts.length, 1);
    assert.deepEqual(raw.attempts[0].response, body);
  });

  it('preserves the unparseable stdout when the CLI returns malformed JSON', async () => {
    await fakeAws('echo "not json at all"');
    await assert.rejects(pollEcrScan(options()), /malformed JSON/);

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.match(raw.attempts[0].rawStdout, /not json at all/);
  });
});
