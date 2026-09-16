// The validator had no tests, which is exactly how a bare `JSON.parse` on a
// possibly-empty file reached a consumer repo and failed with
// `SyntaxError: Unexpected end of JSON input`.
//
// The distinction these tests protect is the one that matters for a security
// gate: a report the scanner WROTE saying "nothing found" is clean; a report the
// scanner never wrote is UNKNOWN and must fail closed. Both look like "no
// findings" to anything that is not paying attention.
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import { validateDependencyReport } from '../security/scripts/validate-dependency-report.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const SCRIPT = resolve('security/scripts/validate-dependency-report.mjs');

async function withTempFile(contents, run) {
  const directory = await mkdtemp(join(tmpdir(), 'validate-report-'));
  const path = join(directory, 'report.json');
  await writeFile(path, contents);
  try {
    return await run(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe('a report the scanner never wrote is UNKNOWN, not clean', () => {
  it('rejects an empty report rather than reading it as zero findings', async () => {
    // The exact failure seen in CI: OSV-Scanner exits 128 ("No package sources
    // found"), the shell redirect still creates the file, and the file is empty.
    await withTempFile('', async (path) => {
      await assert.rejects(
        () => validateDependencyReport('osv-scanner', path),
        /is empty \(0 bytes\)[\s\S]*UNKNOWN, not clean/
      );
    });
  });

  it('rejects a whitespace-only report', async () => {
    await withTempFile('   \n\t\n', async (path) => {
      await assert.rejects(() => validateDependencyReport('osv-scanner', path), /is empty/);
    });
  });

  it('rejects a missing report and says so in words', async () => {
    await assert.rejects(
      () => validateDependencyReport('osv-scanner', join(FIXTURES, 'does-not-exist.json')),
      /does not exist[\s\S]*UNKNOWN, not zero findings/
    );
  });

  it('reports malformed JSON with the scanner, the path, and a snippet', async () => {
    // The old behaviour was a raw SyntaxError naming neither the scanner nor the
    // file, which told a developer nothing about which step to look at.
    await withTempFile('{"results": [', async (path) => {
      await assert.rejects(() => validateDependencyReport('osv-scanner', path), (error) => {
        assert.match(error.message, /osv-scanner/);
        assert.match(error.message, /is not valid JSON/);
        assert.match(error.message, /First 120 bytes/);
        return true;
      });
    });
  });
});

describe('osv-scanner reports', () => {
  it('accepts a written empty result set — the no-dependencies case', async () => {
    // `{"results": []}` is what --allow-no-lockfiles emits for a repo with no
    // dependencies. It is trusted BECAUSE the scanner wrote it: the scanner is
    // asserting it looked and found nothing, which an empty file cannot assert.
    const summary = await validateDependencyReport(
      'osv-scanner',
      join(FIXTURES, 'clean/osv-scanner.json')
    );
    assert.match(summary, /advisories=0/);
    assert.match(summary, /no package sources/);
  });

  it('counts advisories in a real report', async () => {
    const summary = await validateDependencyReport(
      'osv-scanner',
      join(FIXTURES, 'osv-critical-with-fix/osv-scanner.json')
    );
    assert.match(summary, /advisories=[1-9]/);
  });

  it('counts malicious-package advisories separately', async () => {
    const summary = await validateDependencyReport(
      'osv-scanner',
      join(FIXTURES, 'malicious-package/osv-scanner.json')
    );
    assert.match(summary, /malicious=[1-9]/);
  });

  it('rejects a report with no results array', async () => {
    await withTempFile('{"notResults": []}', async (path) => {
      await assert.rejects(
        () => validateDependencyReport('osv-scanner', path),
        /missing its results array/
      );
    });
  });
});

describe('npm-audit and pip-audit reports', () => {
  it('accepts a clean npm audit report', async () => {
    const summary = await validateDependencyReport(
      'npm-audit',
      join(FIXTURES, 'clean/npm-audit.json')
    );
    assert.match(summary, /npm-audit vulnerabilities=/);
  });

  it('surfaces npm audit’s own error object', async () => {
    await withTempFile('{"error":{"summary":"registry unreachable"}}', async (path) => {
      await assert.rejects(
        () => validateDependencyReport('npm-audit', path),
        /npm audit failed: registry unreachable/
      );
    });
  });

  it('rejects an npm audit report with the wrong schema', async () => {
    await withTempFile('{"something":"else"}', async (path) => {
      await assert.rejects(
        () => validateDependencyReport('npm-audit', path),
        /does not have the expected schema/
      );
    });
  });

  it('accepts a clean pip-audit report', async () => {
    const summary = await validateDependencyReport(
      'pip-audit',
      join(FIXTURES, 'pip-audit/clean.json')
    );
    assert.match(summary, /pip-audit vulnerabilities=/);
  });

  it('rejects a pip-audit report with no dependencies array', async () => {
    await withTempFile('{"dependencies":"nope"}', async (path) => {
      await assert.rejects(
        () => validateDependencyReport('pip-audit', path),
        /does not have a dependencies array/
      );
    });
  });
});

describe('the CLI fails closed with a readable message', () => {
  it('exits non-zero on an empty report and names the problem', async () => {
    await withTempFile('', async (path) => {
      const result = spawnSync(process.execPath, [SCRIPT, 'osv-scanner', path], {
        encoding: 'utf8'
      });
      assert.notEqual(result.status, 0, 'an empty report must fail the step');
      assert.match(result.stderr, /DEPENDENCY REPORT INVALID/);
      assert.match(result.stderr, /is empty/);
      // A stack trace is not an error message.
      assert.ok(
        !/at \w+ \(/.test(result.stderr),
        'should print a message, not a stack trace'
      );
    });
  });

  it('exits zero and prints a summary on a valid report', () => {
    const result = spawnSync(
      process.execPath,
      [SCRIPT, 'osv-scanner', join(FIXTURES, 'clean/osv-scanner.json')],
      { encoding: 'utf8' }
    );
    assert.equal(result.status, 0);
    assert.match(result.stdout, /osv-scanner advisories=0/);
  });

  it('rejects an unsupported scanner name', async () => {
    await withTempFile('{}', async (path) => {
      await assert.rejects(
        () => validateDependencyReport('snyk', path),
        /unsupported scanner: snyk/
      );
    });
  });
});
