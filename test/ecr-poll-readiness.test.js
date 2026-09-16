// Polling readiness in enhanced mode, against responses captured live.
//
// Run 34745111774: ECR answered COMPLETE ~10s after the scan finished, but with
// `findings: []` and no severity counts — Inspector had not attached its results.
// The poller treated that as terminal and the gate blocked on an empty report.
// The block was correct (unknown is not clean); giving up at 16s was not.
//
// Run 34809100547: a CLEAN enhanced scan returns that same counts-less body
// permanently. Waiting for counts could never succeed, so a clean image always
// blocked. The poller now asks Inspector for positive confirmation of a clean
// scan, and anything short of that still waits and fails closed.
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { runImageGate } from '../security/scripts/image-gate.mjs';
import {
  confirmCleanEnhancedScan,
  findingsAttached,
  normalizeEcrResponse,
  pollEcrScan
} from '../security/scripts/poll-ecr-scan.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__/ecr-enhanced');
const DIGEST = 'sha256:7bb2656c990a9e3c82aa44a28bee2ee14fbcabbc9cf30c642f5c79f112b7b7d1';
const CLEAN_DIGEST = 'sha256:c8646f70f38c9c74bb0e917656df2c8d2eb31d356c8eef6732082c19b907a487';
const CLEAN_RESOURCE_ID = `arn:aws:ecr:us-east-1:123456789012:repository/secure-software-delivery/${CLEAN_DIGEST}`;

let directory;
let originalPath;

async function fixture(name) {
  return JSON.parse(await readFile(join(FIXTURES, name), 'utf8'));
}

// The live counts-less body, re-pointed at the digest of the populated capture so
// a before -> after sequence describes one image.
async function beforeFindings() {
  const body = await fixture('complete-before-findings.json');
  body.imageId.imageDigest = DIGEST;
  return body;
}

// A fake `aws` on PATH. `ecr` calls return response N on call N, repeating the
// last one. `inspector2 list-coverage` / `list-findings` return fixed bodies
// (default: nothing covered, no findings), or run `inspectorScript` if given.
// Every invocation's arguments are appended to calls.log.
async function fakeAws(bodies, { coverage = { coveredResources: [] }, findings = { findings: [] }, inspectorScript } = {}) {
  for (const [index, body] of bodies.entries()) {
    await writeFile(join(directory, `body-${index}.json`), JSON.stringify(body));
  }
  await writeFile(join(directory, 'coverage.json'), JSON.stringify(coverage));
  await writeFile(join(directory, 'inspector-findings.json'), JSON.stringify(findings));
  const bin = join(directory, 'aws');
  await writeFile(
    bin,
    [
      '#!/bin/sh',
      `echo "$@" >> "${join(directory, 'calls.log')}"`,
      'if [ "$1" = "inspector2" ]; then',
      inspectorScript ?? [
        `  [ "$2" = "list-coverage" ] && cat "${directory}/coverage.json"`,
        `  [ "$2" = "list-findings" ] && cat "${directory}/inspector-findings.json"`,
        '  exit 0'
      ].join('\n'),
      'fi',
      `count_file="${join(directory, 'count')}"`,
      'n=$(cat "$count_file" 2>/dev/null || echo 0)',
      `last=${bodies.length - 1}`,
      '[ "$n" -gt "$last" ] && n=$last',
      `cat "${directory}/body-$n.json"`,
      'echo $((n + 1)) > "$count_file"'
    ].join('\n')
  );
  await chmod(bin, 0o755);
  process.env.PATH = `${directory}:${originalPath}`;
}

function options(overrides = {}) {
  return {
    repository: 'secure-software-delivery',
    region: 'us-east-1',
    image_digest: DIGEST,
    image_tag: 'test',
    raw_output: join(directory, 'raw.json'),
    maxAttempts: 5,
    delaySeconds: 0,
    ...overrides
  };
}

async function cleanCoverage(mutate = () => {}) {
  const body = await fixture('inspector-coverage-clean.json');
  mutate(body.coveredResources[0]);
  return body;
}

describe('poll readiness: COMPLETE before findings are attached', () => {
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'ecr-ready-'));
    originalPath = process.env.PATH;
  });

  afterEach(async () => {
    process.env.PATH = originalPath;
    await rm(directory, { recursive: true, force: true });
  });

  it('recognizes the live counts-less COMPLETE body as not ready', async () => {
    const body = await fixture('complete-before-findings.json');
    assert.equal(body.imageScanStatus.status, 'COMPLETE');
    assert.equal(findingsAttached(body), false);
    assert.equal(findingsAttached(await fixture('complete-clean.json')), false);
    assert.equal(findingsAttached(await fixture('complete-mixed.json')), true);
    assert.equal(findingsAttached(await fixture('empty-complete.json')), true);
  });

  it('keeps waiting through it and returns the populated result', async () => {
    await fakeAws([await beforeFindings(), await beforeFindings(), await fixture('complete-mixed.json')]);
    const report = await pollEcrScan(options());
    assert.equal(report.source, 'aws-ecr-enhanced');
    assert.equal(report.findings.length, 6);

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts.length, 3);
  });

  it('fails closed at the limit if findings never attach — never reads it as clean', async () => {
    await fakeAws([await beforeFindings()]);
    await assert.rejects(
      pollEcrScan(options({ maxAttempts: 3 })),
      /did not complete before the polling limit \(last state: COMPLETE but findings not yet attached/
    );
  });

  it('the normalizer still rejects the counts-less body on its own (defence in depth)', async () => {
    const body = await beforeFindings();
    assert.throws(
      () => normalizeEcrResponse(body, { repository: 'r', image_digest: DIGEST }),
      /lacks findingSeverityCounts/
    );
  });
});

describe('poll readiness: clean enhanced scan confirmed with Inspector', () => {
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'ecr-clean-'));
    originalPath = process.env.PATH;
  });

  afterEach(async () => {
    process.env.PATH = originalPath;
    await rm(directory, { recursive: true, force: true });
  });

  it('emits an empty enhanced report when Inspector confirms the live clean scan', async () => {
    await fakeAws([await fixture('complete-clean.json')], { coverage: await cleanCoverage() });
    const report = await pollEcrScan(options({ image_digest: CLEAN_DIGEST }));
    assert.deepEqual(report, {
      schemaVersion: 1,
      source: 'aws-ecr-enhanced',
      scanStatus: 'COMPLETE',
      image: { repository: 'secure-software-delivery', imageTag: 'test', imageDigest: CLEAN_DIGEST },
      severityCounts: {},
      findings: []
    });

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts[0].cleanConfirmation.clean, true);
    assert.equal(raw.attempts[0].cleanConfirmation.resourceId, CLEAN_RESOURCE_ID);
    const calls = await readFile(join(directory, 'calls.log'), 'utf8');
    assert.match(calls, new RegExp(`list-coverage .*${CLEAN_RESOURCE_ID.replaceAll('/', '\\/')}`));
    assert.match(calls, new RegExp(`list-findings .*ecrImageHash.*${CLEAN_DIGEST}`));
  });

  it('the confirmed-clean report is a DEPLOY at the image gate', async () => {
    await fakeAws([await fixture('complete-clean.json')], { coverage: await cleanCoverage() });
    const report = await pollEcrScan(options({ image_digest: CLEAN_DIGEST }));
    const path = join(directory, 'report.json');
    await writeFile(path, JSON.stringify(report));
    const result = await runImageGate({
      policy: resolve('security/policy.yaml'),
      report: path,
      output: join(directory, 'gate.json')
    });
    assert.equal(result.verdict, 'DEPLOY');
  });

  it('never confirms the live PENDING body mislabelled COMPLETE (no imageScanCompletedAt)', async () => {
    const body = await fixture('pending.json');
    body.imageScanStatus.status = 'COMPLETE';
    const result = await confirmCleanEnhancedScan(body, options({ image_digest: body.imageId.imageDigest }));
    assert.equal(result.clean, false);
    assert.match(result.reason, /lacks imageScanCompletedAt/);
  });

  it('does not ask Inspector while the scan is still settling', async () => {
    const body = await fixture('complete-clean.json');
    const completedAt = Date.parse(body.imageScanFindings.imageScanCompletedAt);
    const result = await confirmCleanEnhancedScan(
      body,
      options({ image_digest: CLEAN_DIGEST }),
      completedAt + 10_000
    );
    assert.equal(result.clean, false);
    assert.match(result.reason, /settling/);
  });

  it('refuses clean when Inspector holds findings ECR has not attached (run 34745111774)', async () => {
    await fakeAws([await fixture('complete-clean.json')], {
      coverage: await cleanCoverage(),
      findings: { findings: [{ findingArn: 'arn:aws:inspector2:us-east-1:123456789012:finding/x' }] }
    });
    await assert.rejects(
      pollEcrScan(options({ image_digest: CLEAN_DIGEST, maxAttempts: 2 })),
      /Inspector holds 1 finding\(s\) .* that ECR has not attached/
    );
  });

  for (const [name, mutate, expected] of [
    ['a scan status that is not a confirmed scan', (r) => (r.scanStatus = { statusCode: 'INACTIVE', reason: 'UNSUPPORTED_OS' }), /INACTIVE\/UNSUPPORTED_OS is not a confirmed scan/],
    ['a last scan before ECR reported completion', (r) => (r.lastScannedAt = '2026-09-14T05:00:00.000000+00:00'), /has not scanned this image since/],
    ['a coverage entry for a different image', (r) => (r.resourceId = r.resourceId.replace('c8646f70', '00000000')), /not a package scan of this image/],
    ['a non-package scan type', (r) => (r.scanType = 'NETWORK'), /not a package scan of this image/]
  ]) {
    it(`refuses clean on ${name}`, async () => {
      await fakeAws([await fixture('complete-clean.json')], { coverage: await cleanCoverage(mutate) });
      await assert.rejects(pollEcrScan(options({ image_digest: CLEAN_DIGEST, maxAttempts: 2 })), expected);
    });
  }

  it('refuses clean when Inspector has no coverage entry for the image', async () => {
    await fakeAws([await fixture('complete-clean.json')]);
    await assert.rejects(
      pollEcrScan(options({ image_digest: CLEAN_DIGEST, maxAttempts: 2 })),
      /Inspector coverage lists 0 resource\(s\)/
    );
  });

  it('refuses clean when polled by tag only', async () => {
    const result = await confirmCleanEnhancedScan(await fixture('complete-clean.json'), options({ image_digest: undefined }));
    assert.equal(result.clean, false);
    assert.match(result.reason, /requires polling by digest/);
  });

  it('keeps waiting on a transient Inspector error, then fails closed', async () => {
    await fakeAws([await fixture('complete-clean.json')], {
      inspectorScript: '  echo "Could not connect to the endpoint URL" >&2\n  exit 255'
    });
    await assert.rejects(
      pollEcrScan(options({ image_digest: CLEAN_DIGEST, maxAttempts: 2 })),
      /Inspector coverage unavailable: Could not connect/
    );
  });

  it('fails closed immediately on an Inspector authorization error', async () => {
    await fakeAws([await fixture('complete-clean.json')], {
      inspectorScript:
        '  echo "An error occurred (AccessDeniedException) when calling the ListCoverage operation" >&2\n  exit 254'
    });
    await assert.rejects(
      pollEcrScan(options({ image_digest: CLEAN_DIGEST, maxAttempts: 5 })),
      /authorization failure while confirming a clean scan with Inspector/
    );
    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts.length, 1);
  });
});
