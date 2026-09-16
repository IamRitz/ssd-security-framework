import { readFile } from 'node:fs/promises';

const [scanner, reportPath] = process.argv.slice(2);

if (!scanner || !reportPath) {
  throw new Error('usage: validate-dependency-report.mjs <scanner> <report.json>');
}

const report = JSON.parse(await readFile(reportPath, 'utf8'));

if (scanner === 'npm-audit') {
  if (report.error) {
    throw new Error(`npm audit failed: ${report.error.summary ?? 'unknown error'}`);
  }

  if (!report.auditReportVersion || !report.metadata?.vulnerabilities) {
    throw new Error('npm audit report does not have the expected schema');
  }

  console.log(`npm-audit vulnerabilities=${report.metadata.vulnerabilities.total}`);
} else if (scanner === 'pip-audit') {
  if (!Array.isArray(report.dependencies)) {
    throw new Error('pip-audit report does not have a dependencies array');
  }

  const vulnCount = report.dependencies
    .flatMap((dependency) => dependency.vulns ?? [])
    .filter((vulnerability) => typeof vulnerability.id === 'string').length;

  console.log(`pip-audit vulnerabilities=${vulnCount}`);
} else if (scanner === 'osv-scanner') {
  if (!Array.isArray(report.results)) {
    throw new Error('OSV-Scanner report does not have a results array');
  }

  const advisoryIds = report.results
    .flatMap((result) => result.packages ?? [])
    .flatMap((dependency) => dependency.vulnerabilities ?? [])
    .map((advisory) => advisory.id)
    .filter(Boolean);
  const maliciousAdvisories = advisoryIds.filter((id) => id.startsWith('MAL-'));

  console.log(
    `osv-scanner advisories=${advisoryIds.length} malicious=${maliciousAdvisories.length}`
  );
} else {
  throw new Error(`unsupported scanner: ${scanner}`);
}
