import { readFile } from 'node:fs/promises';

const [reportPath] = process.argv.slice(2);

if (!reportPath) {
  throw new Error('usage: validate-semgrep-report.mjs <semgrep-report.json>');
}

const report = JSON.parse(await readFile(reportPath, 'utf8'));

if (
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

console.log(
  `semgrep findings=${report.results.length} errors=${report.errors.length} scanned=${report.paths.scanned.length}`
);
