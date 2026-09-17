// Scanner EXECUTION evidence: did the scanner run, and why not.
//
// Three facts about a scanner are kept apart, and never merged:
//
//   execution   did the scanner start, run and write a report?  (this file)
//   trust       could the gate interpret that report?  (security-gate.mjs
//               `integrity`, fail-closed)
//   findings    what the report says  (raw `findings`, policy)
//
// A live run showed why. Docker Hub reset the connection while the SAST job
// pulled the pinned Semgrep image, the scanner never started, no report was
// written, and the gate correctly failed closed with
// "Semgrep: missing report file reports/semgrep.json". True, but it hid the
// operational cause: image acquisition failed, and a re-run fixed it.
//
// So the SAST step now runs in three separate phases, each with its own
// evidence:
//
//   acquire   pull the PINNED image by digest. Bounded retry, and ONLY here: a
//             pull is idempotent and its failure says nothing about the code.
//   run       `docker run --pull=never` the already-acquired image, exactly
//             once. A scanner crash, bad config or OOM is never retried.
//   complete  judge the exit status and the report, write the record.
//
// The record is written next to the report and uploaded with it, so the gate
// job can say WHY a report is missing. It is never read by a policy decision:
// a missing report stays a report-integrity BLOCK whatever the record says.
//
// Record (reports/scanner-execution-<scanner>.json), schemaVersion 1:
//
//   state      success | acquisition-failed | execution-failed |
//              report-missing | report-invalid | incomplete
//   cause      registry-network | registry-rate-limit | registry-auth |
//              image-not-found | scanner-runtime | scanner-configuration |
//              report-validation | unknown | null (success/incomplete)
//   retryable  true only when the evidence says re-running can help
//
// A cause is named only from direct evidence (the registry's own error text, a
// documented scanner exit status). Anything else is `unknown`.
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateSemgrepReport } from './validate-semgrep-report.mjs';

export const EXECUTION_SCHEMA_VERSION = 1;

export const EXECUTION_STATES = [
  'success',
  'acquisition-failed',
  'execution-failed',
  'report-missing',
  'report-invalid',
  // The image was acquired but the run was never recorded: the step stopped
  // (runner lost, step cancelled) between acquisition and completion.
  'incomplete'
];

export const EXECUTION_CAUSES = [
  'registry-network',
  'registry-rate-limit',
  'registry-auth',
  'image-not-found',
  'scanner-runtime',
  'scanner-configuration',
  'report-validation',
  'unknown'
];

// Scanners whose execution is recorded. `control` matches the gate's
// INTEGRITY_CONTROLS, so a record joins the integrity failure it explains.
export const RECORDED_SCANNERS = {
  semgrep: {
    label: 'Semgrep',
    control: 'sast',
    record: 'reports/scanner-execution-semgrep.json',
    validate: (report) => validateSemgrepReport(report)
  }
};

export const DEFAULT_MAX_ATTEMPTS = 3;
// Waits AFTER failed attempts 1 and 2. Short and bounded: at most 15s of
// waiting in total, on top of the pulls themselves.
export const DEFAULT_BACKOFF_MS = [5_000, 10_000];
// A pull that has not finished in 10 minutes is treated as a failed attempt,
// so a stalled connection cannot hold the job for GitHub's 6-hour limit.
export const DEFAULT_PULL_TIMEOUT_MS = 600_000;

const PINNED_IMAGE = /^[a-z0-9][a-z0-9._\-/:]*@sha256:[0-9a-f]{64}$/;

// ---- acquisition ----------------------------------------------------------------

// Registry error text -> cause. Order matters: a rate-limit response also says
// "denied" on some registries, and an auth endpoint URL contains "auth" without
// being an auth failure (the live error was a connection reset talking to
// auth.docker.io).
const ACQUISITION_PATTERNS = [
  ['registry-rate-limit', true, /toomanyrequests|too many requests|pull rate limit|rate limit exceeded/],
  ['registry-auth', false, /unauthorized|authentication required|pull access denied|no basic auth credentials|incorrect username or password|denied: |\b403 forbidden\b/],
  ['image-not-found', false, /manifest unknown|manifest for \S+ not found|not found: manifest unknown|name unknown/],
  [
    'registry-network',
    true,
    /connection reset|connection refused|i\/o timeout|tls handshake timeout|context deadline exceeded|client\.timeout exceeded|request canceled|no such host|temporary failure in name resolution|server misbehaving|network is unreachable|no route to host|unexpected eof|broken pipe|http status: 50[234]|status code 50[234]|bad gateway|service unavailable|gateway time-?out/
  ]
];

// Short, single-line excerpt of a registry error for the record and the log.
// Query strings are dropped (registry token URLs carry scopes, not secrets, but
// nothing here needs them).
export function errorExcerpt(output, limit = 400) {
  const text = String(output ?? '')
    .replace(/\?[^\s"']*/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length > limit ? `…${text.slice(-limit)}` : text;
}

export function classifyAcquisitionFailure({ status = null, output = '', timedOut = false, spawnError = null } = {}) {
  if (spawnError) {
    return { cause: 'unknown', retryable: false, detail: `docker could not be started (${spawnError})` };
  }
  if (timedOut) {
    return { cause: 'registry-network', retryable: true, detail: 'the image pull did not finish within the time limit' };
  }
  const text = String(output).toLowerCase();
  for (const [cause, retryable, pattern] of ACQUISITION_PATTERNS) {
    if (pattern.test(text)) {
      return { cause, retryable, detail: errorExcerpt(output) };
    }
  }
  return {
    cause: 'unknown',
    retryable: false,
    detail: errorExcerpt(output) || `docker pull exited ${status} with no error text`
  };
}

function runDocker(args, { timeoutMs } = {}) {
  return new Promise((resolvePromise) => {
    let child;
    try {
      child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      resolvePromise({ status: null, output: error.message, timedOut: false, spawnError: error.code ?? 'spawn-failed' });
      return;
    }
    let output = '';
    let timedOut = false;
    const collect = (chunk) => {
      output = `${output}${chunk}`.slice(-65_536);
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const timer = timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill('SIGKILL');
        }, timeoutMs)
      : null;
    child.on('error', (error) => {
      clearTimeout(timer);
      resolvePromise({ status: null, output: `${output}${error.message}`, timedOut, spawnError: error.code ?? 'spawn-failed' });
    });
    child.on('close', (status) => {
      clearTimeout(timer);
      resolvePromise({ status, output, timedOut });
    });
  });
}

const delay = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));

// Obtain a pinned image. Retries ONLY retryable acquisition failures, at most
// `maxAttempts` pulls, waiting `backoffMs[n]` after failed attempt n+1.
// `docker`, `sleep` and `log` are injectable for tests.
export async function acquireImage({
  image,
  maxAttempts = DEFAULT_MAX_ATTEMPTS,
  backoffMs = DEFAULT_BACKOFF_MS,
  timeoutMs = DEFAULT_PULL_TIMEOUT_MS,
  docker = runDocker,
  sleep = delay,
  log = console.log
} = {}) {
  // The image identity is fixed by digest. An unpinned reference would let a
  // retry silently fetch different bits, so it is refused, never "fixed up".
  if (typeof image !== 'string' || !PINNED_IMAGE.test(image)) {
    return {
      acquired: false,
      source: null,
      maxAttempts,
      attempts: [],
      cause: 'scanner-configuration',
      retryable: false,
      detail: `image '${image}' is not pinned by sha256 digest; refusing to pull it`
    };
  }

  const inspected = await docker(['image', 'inspect', '--format', '{{.Id}}', image], { timeoutMs: 60_000 });
  if (inspected.status === 0) {
    log(`Pinned image ${image} is already present on this runner; no pull needed.`);
    return { acquired: true, source: 'local', maxAttempts, attempts: [], cause: null, retryable: null, detail: null };
  }

  const attempts = [];
  const limit = Math.max(1, Math.trunc(maxAttempts));
  for (let attempt = 1; attempt <= limit; attempt += 1) {
    log(`Acquiring pinned image ${image} (attempt ${attempt}/${limit})`);
    const result = await docker(['pull', image], { timeoutMs });
    if (result.status === 0 && !result.timedOut) {
      attempts.push({ attempt, outcome: 'acquired' });
      log(`Acquired ${image} on attempt ${attempt}/${limit}.`);
      return { acquired: true, source: 'registry', maxAttempts: limit, attempts, cause: null, retryable: null, detail: null };
    }
    const failure = classifyAcquisitionFailure(result);
    attempts.push({
      attempt,
      outcome: 'failed',
      exitCode: Number.isInteger(result.status) ? result.status : null,
      cause: failure.cause,
      retryable: failure.retryable,
      detail: failure.detail
    });
    log(`Attempt ${attempt}/${limit} to acquire ${image} failed: ${failure.cause} (retryable: ${failure.retryable}). ${failure.detail}`);
    if (!failure.retryable) {
      log(`Not retrying: a ${failure.cause} failure is not transient.`);
      break;
    }
    if (attempt < limit) {
      const wait = backoffMs[Math.min(attempt - 1, backoffMs.length - 1)] ?? 0;
      log(`Retrying image acquisition in ${Math.round(wait / 1000)}s.`);
      await sleep(wait);
    }
  }
  const last = attempts.at(-1);
  return {
    acquired: false,
    source: null,
    maxAttempts: limit,
    attempts,
    cause: last.cause,
    retryable: last.retryable,
    detail: last.detail
  };
}

// ---- records ----------------------------------------------------------------------

function baseRecord(scanner, image = null) {
  const known = RECORDED_SCANNERS[scanner];
  if (!known) {
    throw new Error(`no execution record contract for scanner '${scanner}'`);
  }
  return {
    schemaVersion: EXECUTION_SCHEMA_VERSION,
    scanner,
    control: known.control,
    image,
    state: 'incomplete',
    cause: null,
    retryable: null,
    acquisition: null,
    execution: null,
    report: null,
    detail: null
  };
}

export function acquisitionRecord({ scanner, image, acquisition }) {
  const record = baseRecord(scanner, image);
  record.acquisition = {
    source: acquisition.source,
    maxAttempts: acquisition.maxAttempts,
    attempts: acquisition.attempts
  };
  if (!acquisition.acquired) {
    record.state = 'acquisition-failed';
    record.cause = acquisition.cause;
    record.retryable = acquisition.retryable;
    record.detail = acquisition.detail;
  }
  return record;
}

// Documented Semgrep CLI exit codes (semgrep.dev/docs/cli-reference, "Exit
// codes"), plus the container runtime's own. Semgrep is invoked WITHOUT
// `--error`, so a scan with findings exits 0; any non-zero status is a failure.
const SEMGREP_CONFIGURATION_EXITS = new Map([
  [4, 'invalid pattern in a rule'],
  [5, 'unparseable YAML in a rule configuration'],
  [6, 'a rule requires an unsupported language'],
  [7, 'missing or unreadable configuration'],
  [8, 'invalid language in a rule'],
  [13, 'invalid API token']
]);
const SEMGREP_RUNTIME_EXITS = new Map([
  [2, 'fatal scanner error'],
  [3, 'invalid code in a scanned target'],
  [9, 'rule match timeout'],
  [10, 'rule match exceeded memory'],
  [11, 'lexical error in a scanned target'],
  [12, 'too many matches'],
  [14, 'scan failure']
]);
const CONTAINER_EXITS = new Map([
  [125, 'the container runtime could not start the scanner container'],
  [126, 'the scanner command could not be invoked in the container'],
  [127, 'the scanner command was not found in the container'],
  [137, 'the scanner was killed (SIGKILL; commonly out of memory)'],
  [139, 'the scanner crashed (SIGSEGV)'],
  [143, 'the scanner was terminated (SIGTERM)']
]);

export function classifyExecutionFailure(scanner, exitCode) {
  if (scanner === 'semgrep' && SEMGREP_CONFIGURATION_EXITS.has(exitCode)) {
    return { cause: 'scanner-configuration', retryable: false, detail: `exit ${exitCode}: ${SEMGREP_CONFIGURATION_EXITS.get(exitCode)}` };
  }
  if (scanner === 'semgrep' && SEMGREP_RUNTIME_EXITS.has(exitCode)) {
    return { cause: 'scanner-runtime', retryable: false, detail: `exit ${exitCode}: ${SEMGREP_RUNTIME_EXITS.get(exitCode)}` };
  }
  if (CONTAINER_EXITS.has(exitCode)) {
    return { cause: 'scanner-runtime', retryable: false, detail: `exit ${exitCode}: ${CONTAINER_EXITS.get(exitCode)}` };
  }
  return { cause: 'unknown', retryable: false, detail: `exit ${exitCode}: not a documented exit status` };
}

async function assessReport(scanner, reportPath) {
  let source;
  try {
    source = await readFile(reportPath, 'utf8');
  } catch (error) {
    return error?.code === 'ENOENT'
      ? { path: reportPath, present: false, valid: false, error: 'no report was written' }
      : { path: reportPath, present: true, valid: false, error: `report could not be read: ${error.message}` };
  }
  if (source.trim() === '') {
    return { path: reportPath, present: true, valid: false, error: 'report is empty' };
  }
  try {
    const summary = RECORDED_SCANNERS[scanner].validate(JSON.parse(source));
    return { path: reportPath, present: true, valid: true, summary };
  } catch (error) {
    return { path: reportPath, present: true, valid: false, error: error.message };
  }
}

// The final record after the single scanner run. The exit status is judged
// first: a non-zero exit is an execution failure even if a report exists.
export async function completeExecution({ record, scanner, exitCode, reportPath }) {
  const next = record && record.scanner === scanner ? { ...record } : baseRecord(scanner);
  const code = typeof exitCode === 'string' && /^\d+$/.test(exitCode.trim()) ? Number(exitCode) : exitCode;
  next.report = await assessReport(scanner, reportPath);
  next.execution = { exitCode: Number.isInteger(code) ? code : null };

  if (next.state === 'acquisition-failed') {
    // The scanner cannot have run. Keep the acquisition verdict.
    return next;
  }
  if (!Number.isInteger(code)) {
    Object.assign(next, { state: 'execution-failed', cause: 'unknown', retryable: false, detail: `exit status '${exitCode}' was not captured` });
  } else if (code !== 0) {
    Object.assign(next, { state: 'execution-failed', ...classifyExecutionFailure(scanner, code) });
  } else if (!next.report.present) {
    Object.assign(next, { state: 'report-missing', cause: 'report-validation', retryable: false, detail: 'the scanner exited 0 but wrote no report' });
  } else if (!next.report.valid) {
    Object.assign(next, { state: 'report-invalid', cause: 'report-validation', retryable: false, detail: next.report.error });
  } else {
    Object.assign(next, { state: 'success', cause: null, retryable: false, detail: next.report.summary });
  }
  return next;
}

// A failure found before the scanner could be run at all (for example an empty
// ruleset input): the scanner is not executed, and the configuration is named.
export function configurationFailureRecord({ scanner, image = null, detail }) {
  return { ...baseRecord(scanner, image), state: 'execution-failed', cause: 'scanner-configuration', retryable: false, detail };
}

// ---- reading (gate side) -----------------------------------------------------------

// Never throws. Returns null when no record exists (older toolkit, or a job that
// never reached the scanner step), a normalized record otherwise. A record that
// cannot be interpreted is kept as `state: "unknown"` with the reason: it is
// evidence about evidence, and must not be mistaken for success.
export function normalizeExecutionRecord(raw, scanner) {
  const known = RECORDED_SCANNERS[scanner];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || raw.scanner !== scanner || !EXECUTION_STATES.includes(raw.state)) {
    return {
      schemaVersion: EXECUTION_SCHEMA_VERSION,
      scanner,
      control: known?.control ?? null,
      state: 'unknown',
      cause: 'unknown',
      retryable: false,
      unavailable: 'the execution record does not have the expected shape'
    };
  }
  return {
    ...raw,
    control: known?.control ?? raw.control ?? null,
    cause: EXECUTION_CAUSES.includes(raw.cause) ? raw.cause : raw.cause == null ? null : 'unknown',
    retryable: raw.retryable === true
  };
}

export async function readExecutionRecords(paths = {}) {
  const records = [];
  for (const [scanner, known] of Object.entries(RECORDED_SCANNERS)) {
    const path = paths[scanner] ?? known.record;
    let source;
    try {
      source = await readFile(path, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        records.push({ ...normalizeExecutionRecord(null, scanner), unavailable: `the execution record could not be read: ${error.message}` });
      }
      continue;
    }
    try {
      records.push(normalizeExecutionRecord(JSON.parse(source), scanner));
    } catch (error) {
      records.push({ ...normalizeExecutionRecord(null, scanner), unavailable: `the execution record is not valid JSON: ${error.message}` });
    }
  }
  return records;
}

// ---- CLI ---------------------------------------------------------------------------

async function writeRecord(path, record) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`);
}

async function readRecord(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!/^--[a-z-]+$/.test(key ?? '') || value === undefined) {
      throw new Error(`unknown or incomplete argument ${key}`);
    }
    options[key.slice(2)] = value;
  }
  return options;
}

function label(scanner) {
  return RECORDED_SCANNERS[scanner]?.label ?? scanner;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const options = parseOptions(rest);
  const scanner = options.scanner;
  if (!RECORDED_SCANNERS[scanner]) {
    throw new Error(`usage: scanner-execution.mjs <acquire|complete|configuration-failure> --scanner <${Object.keys(RECORDED_SCANNERS).join('|')}> ...`);
  }
  const recordPath = options.record ?? RECORDED_SCANNERS[scanner].record;

  if (command === 'acquire') {
    // Test hook only (workflow-step-execution.test.js sets 0). The workflow
    // never sets it, so production uses DEFAULT_BACKOFF_MS.
    const backoff = process.env.SSD_IMAGE_ACQUIRE_BACKOFF_MS;
    const acquisition = await acquireImage({
      image: options.image,
      ...(backoff !== undefined && /^\d+$/.test(backoff) ? { backoffMs: [Number(backoff)] } : {})
    });
    const record = acquisitionRecord({ scanner, image: options.image, acquisition });
    await writeRecord(recordPath, record);
    if (!acquisition.acquired) {
      console.log(
        `::error title=${label(scanner)} could not start — scanner image unavailable::` +
          `The pinned ${label(scanner)} image could not be obtained after ${acquisition.attempts.length} attempt(s) ` +
          `(cause: ${record.cause}, retryable: ${record.retryable}). The scanner never ran, so no report exists. ` +
          'This is not a vulnerability finding.'
      );
      process.exitCode = 1;
    }
    return;
  }

  if (command === 'complete') {
    const record = await completeExecution({
      record: await readRecord(recordPath),
      scanner,
      exitCode: options['exit-code'],
      reportPath: options.report
    });
    await writeRecord(recordPath, record);
    if (record.state === 'success') {
      console.log(`${label(scanner)} ran and produced a valid report (${record.detail}).`);
      return;
    }
    console.log(
      `::error title=${label(scanner)} ${record.state}::${label(scanner)} ${record.state} (cause: ${record.cause}): ${record.detail}`
    );
    process.exitCode = 1;
    return;
  }

  if (command === 'configuration-failure') {
    const record = configurationFailureRecord({ scanner, image: options.image ?? null, detail: options.detail ?? 'invalid scanner configuration' });
    await writeRecord(recordPath, record);
    console.log(`::error title=${label(scanner)} configuration invalid::${record.detail}`);
    process.exitCode = 1;
    return;
  }

  throw new Error(`unknown command '${command}'`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  try {
    await main();
  } catch (error) {
    console.error(`SCANNER EXECUTION: ${error.message}`);
    process.exitCode = 1;
  }
}
