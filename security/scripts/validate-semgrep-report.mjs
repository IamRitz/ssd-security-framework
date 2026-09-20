import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Throws unless `report` is a Semgrep JSON report the gate can interpret, and
// returns a one-line summary. Shared with scanner-execution.mjs, so the SAST
// step and its execution record apply exactly the same rule.
export function validateSemgrepReport(report) {
  if (
    !report ||
    typeof report !== 'object' ||
    typeof report.version !== 'string' ||
    !Array.isArray(report.results) ||
    !Array.isArray(report.errors) ||
    !Array.isArray(report.paths?.scanned)
  ) {
    throw new Error('Semgrep report does not have the expected JSON schema');
  }

  if (report.errors.length > 0) {
    throw new Error(`Semgrep report contains ${report.errors.length} scan error(s)`);
  }

  return `semgrep findings=${report.results.length} errors=${report.errors.length} scanned=${report.paths.scanned.length}`;
}

async function main() {
  const [reportPath] = process.argv.slice(2);

  if (!reportPath) {
    throw new Error('usage: validate-semgrep-report.mjs <semgrep-report.json>');
  }

  console.log(validateSemgrepReport(JSON.parse(await readFile(reportPath, 'utf8'))));
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
