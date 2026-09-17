// Scanner execution evidence: acquisition, execution and report validity are
// recorded separately from report trust (integrity) and from findings (policy).
//
// Regression (live run IamRitz/ssd-scratch-consumer 35233605122, attempt 1): the
// SAST job could not pull the pinned Semgrep image from Docker Hub (connection
// reset talking to the registry auth endpoint). The scanner never ran, the gate
// correctly failed closed on the missing report, and the only visible cause was
// "Semgrep: missing report file reports/semgrep.json". Attempt 2 passed with no
// code change.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import {
  acquireImage,
  acquisitionRecord,
  classifyAcquisitionFailure,
  classifyExecutionFailure,
  completeExecution,
  configurationFailureRecord,
  DEFAULT_BACKOFF_MS,
  normalizeExecutionRecord,
  readExecutionRecords
} from '../security/scripts/scanner-execution.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const POLICY = resolve('security/policy.yaml');
const SEMGREP_IMAGE = 'semgrep/semgrep@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e';

// The live error text, shape-for-shape (token query string included).
const LIVE_REGISTRY_ERROR =
  'docker: Error response from daemon: Get "https://auth.docker.io/token?scope=repository%3Asemgrep%2Fsemgrep%3Apull&service=registry.docker.io": ' +
  'read tcp 10.1.0.94:48212->98.85.153.80:443: read: connection reset by peer.';

async function withTempDir(work) {
  const directory = await mkdtemp(join(tmpdir(), 'scanner-execution-'));
  try {
    return await work(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

// A scripted docker: `inspect` misses, then each `pull` takes the next result.
function scriptedDocker(pulls) {
  const calls = [];
  const docker = async (args) => {
    calls.push(args.join(' '));
    if (args[0] === 'image') return { status: 1, output: 'Error: No such image' };
    const next = pulls.shift();
    return next ?? { status: 0, output: '' };
  };
  return { docker, calls, pullCount: () => calls.filter((call) => call.startsWith('pull ')).length };
}

const RESET = { status: 1, output: LIVE_REGISTRY_ERROR };
const quiet = { log: () => {}, sleep: async () => {} };

describe('acquisition failures are classified from the registry error itself', () => {
  it('the live Docker Hub connection reset is registry-network and retryable', () => {
    const result = classifyAcquisitionFailure({ status: 125, output: LIVE_REGISTRY_ERROR });
    assert.equal(result.cause, 'registry-network');
    assert.equal(result.retryable, true);
    assert.doesNotMatch(result.detail, /scope=|service=/, 'token query strings are not copied into evidence');
  });

  it('an auth endpoint URL alone is not an auth failure', () => {
    assert.equal(classifyAcquisitionFailure({ status: 1, output: 'Get "https://auth.docker.io/token": i/o timeout' }).cause, 'registry-network');
  });

  for (const [output, cause, retryable] of [
    ['Error response from daemon: unauthorized: authentication required', 'registry-auth', false],
    ['Error response from daemon: pull access denied for semgrep/semgrep, repository does not exist or may require docker login', 'registry-auth', false],
    ['toomanyrequests: You have reached your pull rate limit.', 'registry-rate-limit', true],
    ['Error response from daemon: manifest unknown: manifest unknown', 'image-not-found', false],
    ['Error response from daemon: received unexpected HTTP status: 503 Service Unavailable', 'registry-network', true],
    ['Error response from daemon: dial tcp: lookup registry-1.docker.io: no such host', 'registry-network', true],
    ['net/http: TLS handshake timeout', 'registry-network', true],
    ['something nobody has seen before', 'unknown', false],
    ['', 'unknown', false]
  ]) {
    it(`${JSON.stringify(output.slice(0, 48))} -> ${cause}`, () => {
      const result = classifyAcquisitionFailure({ status: 1, output });
      assert.equal(result.cause, cause);
      assert.equal(result.retryable, retryable);
    });
  }

  it('a digest that happens to contain 502 is not read as an HTTP status', () => {
    assert.equal(classifyAcquisitionFailure({ status: 1, output: 'failed to verify sha256:502a0f' }).cause, 'unknown');
  });

  it('a timed-out pull is a network failure; docker missing entirely is unknown', () => {
    assert.deepEqual(
      [classifyAcquisitionFailure({ timedOut: true }).cause, classifyAcquisitionFailure({ spawnError: 'ENOENT' }).cause],
      ['registry-network', 'unknown']
    );
  });
});

describe('image acquisition retries only transient registry failures, and is bounded', () => {
  it('succeeds on attempt 2 after the live connection reset', async () => {
    const docker = scriptedDocker([RESET, { status: 0 }]);
    const waits = [];
    const logs = [];
    const result = await acquireImage({ image: SEMGREP_IMAGE, docker: docker.docker, sleep: async (ms) => waits.push(ms), log: (line) => logs.push(line) });
    assert.equal(result.acquired, true);
    assert.equal(docker.pullCount(), 2);
    assert.deepEqual(result.attempts.map((attempt) => attempt.outcome), ['failed', 'acquired']);
    assert.deepEqual(waits, [DEFAULT_BACKOFF_MS[0]]);
    assert.ok(logs.some((line) => /attempt 1\/3/.test(line)));
    assert.ok(logs.some((line) => /Acquired .* on attempt 2\/3/.test(line)));
  });

  it('succeeds on attempt 3', async () => {
    const docker = scriptedDocker([RESET, RESET, { status: 0 }]);
    const waits = [];
    const result = await acquireImage({ image: SEMGREP_IMAGE, docker: docker.docker, sleep: async (ms) => waits.push(ms), log: () => {} });
    assert.equal(result.acquired, true);
    assert.equal(docker.pullCount(), 3);
    assert.deepEqual(waits, DEFAULT_BACKOFF_MS, 'short bounded backoff between attempts, none after the last');
  });

  it('exhaustion after 3 attempts fails, records every attempt, and stays retryable', async () => {
    const docker = scriptedDocker([RESET, RESET, RESET, { status: 0 }]);
    const result = await acquireImage({ image: SEMGREP_IMAGE, docker: docker.docker, ...quiet });
    assert.equal(result.acquired, false);
    assert.equal(docker.pullCount(), 3, 'never a fourth pull');
    assert.equal(result.cause, 'registry-network');
    assert.equal(result.retryable, true);
    const record = acquisitionRecord({ scanner: 'semgrep', image: SEMGREP_IMAGE, acquisition: result });
    assert.equal(record.state, 'acquisition-failed');
    assert.equal(record.control, 'sast');
    assert.equal(record.acquisition.attempts.length, 3);
    assert.equal(record.execution, null, 'the scanner never ran');
  });

  it('a non-transient registry failure is not retried', async () => {
    const docker = scriptedDocker([{ status: 1, output: 'unauthorized: authentication required' }, { status: 0 }]);
    const result = await acquireImage({ image: SEMGREP_IMAGE, docker: docker.docker, ...quiet });
    assert.equal(result.acquired, false);
    assert.equal(docker.pullCount(), 1);
    assert.equal(result.cause, 'registry-auth');
    assert.equal(result.retryable, false);
  });

  it('an unrecognized failure is not retried on a guess', async () => {
    const docker = scriptedDocker([{ status: 1, output: 'mystery' }, { status: 0 }]);
    assert.equal((await acquireImage({ image: SEMGREP_IMAGE, docker: docker.docker, ...quiet })).cause, 'unknown');
    assert.equal(docker.pullCount(), 1);
  });

  it('refuses an image that is not pinned by digest, without pulling anything', async () => {
    for (const image of ['semgrep/semgrep:latest', 'semgrep/semgrep', '']) {
      const docker = scriptedDocker([]);
      const result = await acquireImage({ image, docker: docker.docker, ...quiet });
      assert.equal(result.acquired, false);
      assert.equal(result.cause, 'scanner-configuration');
      assert.equal(docker.calls.length, 0);
    }
  });

  it('an image already on the runner is used without a pull', async () => {
    const calls = [];
    const result = await acquireImage({ image: SEMGREP_IMAGE, docker: async (args) => (calls.push(args[0]), { status: 0 }), ...quiet });
    assert.equal(result.acquired, true);
    assert.equal(result.source, 'local');
    assert.deepEqual(calls, ['image']);
  });
});

const VALID_SEMGREP = join(CLEAN, 'semgrep.json');

describe('execution and report failures are never classified as acquisition failures', () => {
  const acquired = acquisitionRecord({
    scanner: 'semgrep',
    image: SEMGREP_IMAGE,
    acquisition: { acquired: true, source: 'registry', maxAttempts: 3, attempts: [{ attempt: 1, outcome: 'failed', cause: 'registry-network' }, { attempt: 2, outcome: 'acquired' }] }
  });

  it('exit 0 with a valid report is success, and keeps the acquisition history', async () => {
    const record = await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: '0', reportPath: VALID_SEMGREP });
    assert.equal(record.state, 'success');
    assert.equal(record.cause, null);
    assert.equal(record.acquisition.attempts.length, 2);
    assert.equal(record.report.valid, true);
  });

  for (const [exitCode, cause] of [
    [2, 'scanner-runtime'],
    [7, 'scanner-configuration'],
    [5, 'scanner-configuration'],
    [137, 'scanner-runtime'],
    [125, 'scanner-runtime'],
    [42, 'unknown']
  ]) {
    it(`scanner exit ${exitCode} is execution-failed (${cause}), not retryable, never a registry cause`, async () => {
      const record = await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: String(exitCode), reportPath: VALID_SEMGREP });
      assert.equal(record.state, 'execution-failed');
      assert.equal(record.cause, cause);
      assert.equal(record.retryable, false);
      assert.doesNotMatch(record.cause, /^registry|image-not-found/);
      assert.equal(record.execution.exitCode, exitCode);
    });
  }

  it('an OOM kill says so', () => {
    assert.match(classifyExecutionFailure('semgrep', 137).detail, /out of memory/);
  });

  it('a non-zero exit is a failure even when a valid-looking report exists', async () => {
    const record = await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: 1, reportPath: VALID_SEMGREP });
    assert.equal(record.state, 'execution-failed');
    assert.equal(record.report.valid, true);
  });

  it('exit 0 with no report is report-missing; with an invalid report, report-invalid', async () => {
    await withTempDir(async (directory) => {
      const missing = await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: 0, reportPath: join(directory, 'absent.json') });
      assert.deepEqual([missing.state, missing.cause], ['report-missing', 'report-validation']);

      const errored = join(directory, 'errored.json');
      await writeFile(errored, JSON.stringify({ version: '1', results: [], errors: [{ message: 'x' }], paths: { scanned: [] } }));
      const invalid = await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: 0, reportPath: errored });
      assert.deepEqual([invalid.state, invalid.cause], ['report-invalid', 'report-validation']);
      assert.match(invalid.detail, /1 scan error/);

      const empty = join(directory, 'empty.json');
      await writeFile(empty, '');
      assert.equal((await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: 0, reportPath: empty })).state, 'report-invalid');
    });
  });

  it('an uncaptured exit status is a failure with an unknown cause', async () => {
    const record = await completeExecution({ record: acquired, scanner: 'semgrep', exitCode: '', reportPath: VALID_SEMGREP });
    assert.deepEqual([record.state, record.cause], ['execution-failed', 'unknown']);
  });

  it('a configuration refusal before the run is scanner-configuration', () => {
    const record = configurationFailureRecord({ scanner: 'semgrep', detail: 'semgrep_configs resolved to no rulesets' });
    assert.deepEqual([record.state, record.cause, record.retryable], ['execution-failed', 'scanner-configuration', false]);
  });
});

describe('reading execution records never fails and never invents success', () => {
  it('absent records are simply absent; unreadable ones are state unknown', async () => {
    await withTempDir(async (directory) => {
      assert.deepEqual(await readExecutionRecords({ semgrep: join(directory, 'none.json') }), []);
      const bad = join(directory, 'bad.json');
      await writeFile(bad, '{ not json');
      const [record] = await readExecutionRecords({ semgrep: bad });
      assert.equal(record.state, 'unknown');
      assert.match(record.unavailable, /not valid JSON/);
    });
    assert.equal(normalizeExecutionRecord({ scanner: 'semgrep', state: 'fine' }, 'semgrep').state, 'unknown');
    assert.equal(normalizeExecutionRecord({ scanner: 'semgrep', state: 'success', cause: 'made-up' }, 'semgrep').cause, 'unknown');
  });
});

// ---- the gate --------------------------------------------------------------------

// A path that never exists, identical across runs so failure reasons compare.
const MISSING_SEMGREP = join(tmpdir(), 'ssd-scanner-execution-test-never-created', 'semgrep.json');

async function gateRun({ semgrep = VALID_SEMGREP, record = null } = {}) {
  return withTempDir(async (directory) => {
    let semgrepExecution = join(directory, 'no-record.json');
    if (record) {
      semgrepExecution = join(directory, 'scanner-execution-semgrep.json');
      await writeFile(semgrepExecution, JSON.stringify(record));
    }
    const output = join(directory, 'security-gate.json');
    const result = await runSecurityGate({
      policy: POLICY,
      repoDir: directory,
      gitleaks: join(CLEAN, 'gitleaks.json'),
      trufflehog: join(CLEAN, 'trufflehog.json'),
      npmAudit: join(directory, 'absent-npm.json'),
      pipAudit: join(directory, 'absent-pip.json'),
      osv: join(CLEAN, 'osv-scanner.json'),
      semgrep: semgrep ?? MISSING_SEMGREP,
      semgrepExecution,
      baseline: join(CLEAN, 'semgrep-baseline.json'),
      output,
      exceptions: join(directory, 'gate-exceptions.json')
    });
    return { result, written: JSON.parse(await readFile(output, 'utf8')) };
  });
}

async function acquisitionFailedRecord() {
  const docker = scriptedDocker([RESET, RESET, RESET]);
  const acquisition = await acquireImage({ image: SEMGREP_IMAGE, docker: docker.docker, ...quiet });
  return acquisitionRecord({ scanner: 'semgrep', image: SEMGREP_IMAGE, acquisition });
}

describe('the gate keeps execution evidence apart from integrity and policy', () => {
  it('acquisition failure: still a fail-closed missing-report integrity BLOCK, now with its cause recorded', async () => {
    const record = await acquisitionFailedRecord();
    const { result, written } = await gateRun({ semgrep: null, record });
    assert.equal(result.verdict, 'BLOCK');
    assert.equal(result.integrity.trusted, false);
    assert.equal(result.integrity.failures.length, 1);
    assert.equal(result.integrity.failures[0].control, 'sast');
    assert.match(result.integrity.failures[0].reason, /^Semgrep: missing report file /);
    assert.equal(result.breakGlass.eligible, false);
    assert.deepEqual(
      written.scannerExecution.records.map((entry) => [entry.scanner, entry.state, entry.cause, entry.retryable]),
      [['semgrep', 'acquisition-failed', 'registry-network', true]]
    );
  });

  it('the record changes nothing a decision reads: identical verdict, summary, integrity, findings, break-glass', async () => {
    const policyView = ({ result }) => ({
      verdict: result.verdict,
      summary: result.summary,
      integrity: result.integrity,
      findings: result.findings,
      breakGlass: result.breakGlass
    });
    const record = await acquisitionFailedRecord();
    assert.deepEqual(policyView(await gateRun({ semgrep: null, record })), policyView(await gateRun({ semgrep: null })));
    // A record claiming success cannot rescue a missing report...
    const lying = { ...record, state: 'success', cause: null };
    assert.deepEqual(policyView(await gateRun({ semgrep: null, record: lying })), policyView(await gateRun({ semgrep: null })));
    // ...and a record claiming failure cannot fail a valid one.
    assert.deepEqual(policyView(await gateRun({ record })), policyView(await gateRun()));
    assert.equal((await gateRun({ record })).result.verdict, 'PASS');
  });

  it('a run with no record keeps an empty, additive scannerExecution block', async () => {
    const { written } = await gateRun();
    assert.deepEqual(written.scannerExecution, { schemaVersion: 1, records: [] });
  });
});
