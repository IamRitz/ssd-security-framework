import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { normalizeEcrResponse } from '../security/scripts/poll-ecr-scan.mjs';

test('normalizes native ECR findings for the deploy gate without losing severity', async () => {
  const fixture = JSON.parse(
    await readFile(
      resolve('security/scripts/__fixtures__/image-gate/ecr-response.json'),
      'utf8'
    )
  );

  const report = normalizeEcrResponse(fixture, {
    repository: 'secure-software-delivery',
    image_tag: 'test-commit'
  });

  assert.equal(report.scanStatus, 'COMPLETE');
  assert.deepEqual(report.severityCounts, { critical: 1, medium: 1 });
  assert.deepEqual(
    report.findings.map(({ id, severity }) => ({ id, severity })),
    [
      { id: 'CVE-2099-CRITICAL', severity: 'critical' },
      { id: 'CVE-2099-MEDIUM', severity: 'medium' }
    ]
  );
});
