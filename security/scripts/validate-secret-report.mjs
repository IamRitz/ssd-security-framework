// Validates that the secret scanners produced interpretable reports, inside the
// Secret scanning job, before upload.
//
// The dependency and SAST jobs already refuse to succeed on an unusable report.
// This gives the secret-scanning job the same meaning, so every scanning
// control's job result says the same thing: "the scanner executed and produced
// a trustworthy report" — never "no secrets were found". The checks mirror what
// the security gate requires of each report, so a report accepted here is one
// the gate can evaluate.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

export function validateSecretReport(scanner, report) {
  assert(Array.isArray(report), `${scanner} report must be a JSON array`);
  if (scanner === 'gitleaks') {
    for (const finding of report) {
      assert(typeof finding?.RuleID === 'string', 'Gitleaks finding is missing RuleID');
      assert(typeof finding?.File === 'string', 'Gitleaks finding is missing File');
    }
  } else if (scanner === 'trufflehog') {
    for (const finding of report) {
      assert(typeof finding?.DetectorName === 'string', 'TruffleHog finding is missing DetectorName');
      assert(typeof finding?.Verified === 'boolean', 'TruffleHog finding is missing Verified');
    }
  } else {
    throw new Error(`unsupported secret scanner: ${scanner}`);
  }
  return `${scanner} findings=${report.length}`;
}

export async function validateSecretReportFile(scanner, reportPath) {
  let raw;
  try {
    raw = await readFile(reportPath, 'utf8');
  } catch (error) {
    throw new Error(`${scanner} report ${reportPath} could not be read (${error.code ?? error.message}); findings are UNKNOWN, not clean`, {
      cause: error
    });
  }
  let report;
  try {
    report = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${scanner} report ${reportPath} is not valid JSON (${error.message}); findings are UNKNOWN, not clean`, {
      cause: error
    });
  }
  return validateSecretReport(scanner, report);
}

async function main() {
  const [scanner, reportPath] = process.argv.slice(2);
  try {
    assert(scanner && reportPath, 'usage: validate-secret-report.mjs <gitleaks|trufflehog> <report.json>');
    console.log(await validateSecretReportFile(scanner, reportPath));
  } catch (error) {
    console.error(`SECRET REPORT INVALID: ${error.message}`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
