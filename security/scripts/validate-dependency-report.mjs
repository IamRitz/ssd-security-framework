// Validates that a dependency scanner actually produced an interpretable report.
//
// This runs BEFORE the gate, and its entire job is to distinguish three states
// that look alike from the outside:
//
//   a real report with zero findings   -> clean, proceed
//   a report the scanner never wrote   -> UNKNOWN, fail closed
//   a report we cannot parse           -> UNKNOWN, fail closed
//
// The second case is the dangerous one. A scanner that exits early writes
// nothing, the shell redirect still creates the file, and a naive reader sees an
// empty file. Parsing that with a bare JSON.parse throws
// `SyntaxError: Unexpected end of JSON input` — a stack trace that says nothing
// about which scanner failed or why. Worse, any handling that treated empty as
// "no vulnerabilities" would be a false clean: zero findings from a scan that
// never happened is not the same as zero findings from a scan that did.
//
// So every failure below names the scanner, names the file, and says what the
// state actually means. Each rethrow keeps the original error as `cause`, so the
// underlying errno or parser position survives alongside the explanation.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function readReport(scanner, reportPath) {
  let raw;
  try {
    raw = await readFile(reportPath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(
        `${scanner} report ${reportPath} does not exist. The scanner did not run, or it failed ` +
          'before writing anything. A missing report is UNKNOWN, not zero findings.',
        { cause: error }
      );
    }
    throw new Error(`${scanner} report ${reportPath} could not be read: ${error.message}`, {
      cause: error
    });
  }

  if (raw.trim() === '') {
    throw new Error(
      `${scanner} report ${reportPath} is empty (${raw.length} bytes). The scanner exited ` +
        'without writing a report, so the findings list is UNKNOWN, not clean. Check the ' +
        "scanner step's own exit code and stderr in the job log — an empty report is never " +
        'treated as a pass.'
    );
  }

  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `${scanner} report ${reportPath} is not valid JSON: ${error.message}. ` +
        `First 120 bytes: ${JSON.stringify(raw.slice(0, 120))}`,
      { cause: error }
    );
  }
}

// The parsed report, with the same fail-closed read errors as validation.
export async function readDependencyReport(scanner, reportPath) {
  return readReport(scanner, reportPath);
}

// Returns a short human-readable summary. Throws on anything that means the
// report cannot be trusted; the caller's non-zero exit is the fail-closed signal.
export async function validateDependencyReport(scanner, reportPath) {
  assert(scanner && reportPath, 'usage: validate-dependency-report.mjs <scanner> <report.json>');

  const report = await readReport(scanner, reportPath);

  if (scanner === 'npm-audit') {
    if (report.error) {
      throw new Error(`npm audit failed: ${report.error.summary ?? 'unknown error'}`);
    }
    assert(
      report.auditReportVersion && report.metadata?.vulnerabilities,
      'npm audit report does not have the expected schema'
    );
    return `npm-audit vulnerabilities=${report.metadata.vulnerabilities.total}`;
  }

  if (scanner === 'pip-audit') {
    assert(Array.isArray(report.dependencies), 'pip-audit report does not have a dependencies array');
    const vulnerabilityCount = report.dependencies
      .flatMap((dependency) => dependency.vulns ?? [])
      .filter((vulnerability) => typeof vulnerability.id === 'string').length;
    return `pip-audit vulnerabilities=${vulnerabilityCount}`;
  }

  if (scanner === 'osv-scanner') {
    // OSV-Scanner is written in Go, and Go marshals an empty slice as `null`
    // rather than `[]`. A successful scan that found no package sources emits
    // exactly `{"results": null, "experimental_config": {...}}` with exit 0 —
    // verified against this pinned version both locally and on a runner.
    //
    // That is the scanner asserting "I looked and found nothing", so it is a
    // clean empty result set, not a malformed report. It is trusted precisely
    // BECAUSE the scanner wrote it, which an empty file cannot do.
    //
    // The key must still be PRESENT. A payload with no `results` key at all is
    // not something this scanner produces, so it stays a fail-closed rejection
    // rather than being normalized away.
    assert(Object.hasOwn(report, 'results'), 'OSV-Scanner report has no results key');
    assert(
      report.results === null || Array.isArray(report.results),
      'OSV-Scanner report results must be an array, or null when no package sources were found'
    );

    const results = report.results ?? [];
    const advisoryIds = results
      .flatMap((result) => result.packages ?? [])
      .flatMap((dependency) => dependency.vulnerabilities ?? [])
      .map((advisory) => advisory.id)
      .filter(Boolean);
    const maliciousAdvisories = advisoryIds.filter((id) => id.startsWith('MAL-'));

    return (
      `osv-scanner advisories=${advisoryIds.length} malicious=${maliciousAdvisories.length}` +
      (results.length === 0 ? ' (no package sources — repository has no dependencies)' : '')
    );
  }

  throw new Error(`unsupported scanner: ${scanner}`);
}

async function main() {
  const [scanner, reportPath] = process.argv.slice(2);
  try {
    console.log(await validateDependencyReport(scanner, reportPath));
  } catch (error) {
    // The message is the product here, not the stack. A developer reading a
    // failed job needs to know which scanner produced nothing and why that
    // blocks, not which line of this file threw.
    console.error(`DEPENDENCY REPORT INVALID: ${error.message}`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
