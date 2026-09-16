// Generates a candidate Semgrep baseline: the set of findings a repo formally
// accepts as pre-existing, so the gate can block only what a change introduces.
//
// WHY THIS REFUSES TO RUN ON AN UNTRUSTED SCAN
//
// A baseline is generated during the TUNE phase, while the gate is usually in
// `log-only` mode. In `log-only` a BLOCK does not fail the job — including a
// report-integrity BLOCK, which means a scanner could not interpret its input
// (missing or malformed report, Trivy unable to identify the base image OS, an
// end-of-life OS with no advisories). Such a run reports zero findings because
// it understood nothing, not because the repo is clean.
//
// Baselining from that run writes "no findings" into the permanently accepted
// state, and every later scan then compares against a baseline built from a
// scan that never happened. That is the one place where log-only's
// deliberate non-blocking behaviour would cause silent, lasting damage, so this
// script fails closed: it requires at least one gate result and refuses unless
// every one of them reports `integrity.trusted === true`.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export class UntrustedScanError extends Error {
  constructor(failures) {
    super(
      'refusing to generate a baseline from a run whose scans could not be trusted:\n' +
        failures.map((failure) => `  - ${failure}`).join('\n')
    );
    this.name = 'UntrustedScanError';
    this.failures = failures;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function readJson(path, label) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`${label}: missing file ${path}`, { cause: error });
    }
    throw new Error(`${label}: cannot read ${path}: ${error.message}`, { cause: error });
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`${label}: malformed JSON in ${path}: ${error.message}`, { cause: error });
  }
}

// Every gate result must be present, parseable, and explicitly trusted. A gate
// result with no `integrity` field at all is treated as untrusted rather than
// assumed fine — it was produced by something this script does not recognise.
export function assertScansTrusted(gateResults) {
  assert(
    gateResults.length > 0,
    'refusing to generate a baseline with no gate result to check: pass --gate <path> ' +
      '(at minimum the source gate, e.g. reports/security-gate.json)'
  );

  const failures = [];
  for (const { path, result } of gateResults) {
    const integrity = result?.integrity;
    if (!integrity || typeof integrity.trusted !== 'boolean') {
      failures.push(`${path}: no integrity field — cannot confirm the scan was interpretable`);
      continue;
    }
    if (!integrity.trusted) {
      const reasons = (integrity.failures ?? []).map(
        (failure) => `${failure.source ?? 'gate'}: ${failure.reason ?? 'report-integrity failure'}`
      );
      failures.push(
        `${path}: ${reasons.length > 0 ? reasons.join('; ') : 'report-integrity failure'}`
      );
    }
  }

  if (failures.length > 0) {
    throw new UntrustedScanError(failures);
  }
}

export function buildBaseline(report, rulesets) {
  assert(
    Array.isArray(report.results) && Array.isArray(report.errors),
    'Semgrep report does not have the expected JSON schema'
  );
  assert(
    report.errors.length === 0,
    'refusing to baseline a Semgrep report that contains scan errors'
  );

  const findings = report.results
    .map((finding) => {
      const checkId = finding.check_id;
      const path = finding.path;
      const matchedCode = finding.extra?.lines?.trim();

      assert(
        checkId && path && matchedCode,
        'Semgrep finding lacks check_id, path, or matched source text'
      );

      return {
        fingerprint: createHash('sha256')
          .update(`${checkId}\0${path}\0${matchedCode}`)
          .digest('hex'),
        checkId,
        path
      };
    })
    .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));

  return {
    schemaVersion: 1,
    generatedBy: `semgrep ${report.version}`,
    // Recorded from what the caller actually scanned with. A baseline that
    // claims rulesets it was not generated with is a quieter version of the same
    // false-clean problem: a later scan with different rules compares against a
    // baseline that never saw those rules.
    rulesets,
    findings
  };
}

function parseArguments(argv) {
  const options = { report: null, gates: [], rulesets: null, output: null };

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--report') {
      assert(value, 'missing value for --report');
      options.report = value;
      index += 1;
    } else if (flag === '--gate') {
      assert(value, 'missing value for --gate');
      options.gates.push(value);
      index += 1;
    } else if (flag === '--rulesets') {
      assert(value, 'missing value for --rulesets');
      options.rulesets = value;
      index += 1;
    } else if (flag === '--output') {
      assert(value, 'missing value for --output');
      options.output = value;
      index += 1;
    } else {
      throw new Error(
        `unknown argument ${flag}\n` +
          'usage: generate-semgrep-baseline.mjs --report <semgrep.json> ' +
          '--gate <gate-result.json> [--gate ...] --rulesets "<config> <config>" [--output <path>]'
      );
    }
  }

  assert(options.report, 'missing --report <semgrep.json>');
  assert(
    options.rulesets,
    'missing --rulesets: the baseline records which configs produced it, so it must be stated'
  );
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));

  const gateResults = await Promise.all(
    options.gates.map(async (path) => ({
      path,
      result: await readJson(path, 'gate result')
    }))
  );
  assertScansTrusted(gateResults);

  const report = await readJson(options.report, 'Semgrep report');
  const baseline = buildBaseline(report, options.rulesets.split(/\s+/).filter(Boolean));
  const serialized = `${JSON.stringify(baseline, null, 2)}\n`;

  if (options.output) {
    await writeFile(options.output, serialized);
    console.error(`Wrote ${baseline.findings.length} baselined findings to ${options.output}`);
  } else {
    process.stdout.write(serialized);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  try {
    await main();
  } catch (error) {
    console.error(`BASELINE GENERATION REFUSED: ${error.message}`);
    process.exitCode = 1;
  }
}
