// Interprets a dependency scanner's exit status AS DATA, next to its report.
//
// pip-audit and OSV-Scanner exit 1 when they find vulnerabilities. That is the
// scanner doing its job — the policy gate judges the findings later — yet a
// workflow step that simply propagates it shows GitHub's red "Process completed
// with exit code 1" on a scan that worked. Masking it with `continue-on-error`
// (or `|| true`) hides a genuine crash the same way, so neither is used.
//
// Instead the workflow captures the exit status and hands it here with the
// report. The step passes only when the exit status and the report AGREE:
//
//   exit 0, valid report, no findings          clean scan
//   exit 1, valid report, at least one finding  findings found (expected)
//   exit 0, valid report, findings present     accepted: the findings are all in
//                                               the report and the gate evaluates
//                                               every one — nothing is hidden
//   exit 1, valid report, NO findings           FAIL: the scanner signalled
//                                               something the report does not show
//   any other exit status                       FAIL: unexpected (crash, docker
//                                               error, OSV 127/128, ...)
//   missing / empty / malformed report          FAIL: findings UNKNOWN, not clean
//
// SCANNER LIMITATION, stated rather than hidden: pip-audit (verified in 2.10.1's
// CLI) exits 1 BOTH for "vulnerabilities found" and for fatal errors. Its exit
// code alone cannot tell them apart. The disambiguation is the report: a fatal
// error exits before any report is written, so an empty or unparseable report
// with exit 1 fails here, and a well-formed report listing findings with exit 1
// is the findings case. A crash occurring AFTER a complete, well-formed report
// was written cannot be distinguished — no such path exists in the pinned
// version. OSV-Scanner reserves distinct codes (1 findings, 127 error, 128 no
// packages), so its error cases are caught by the exit status as well.
import { appendFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readDependencyReport, validateDependencyReport } from './validate-dependency-report.mjs';

export const EXIT_CONTRACTS = {
  'pip-audit': { clean: 0, findings: 1, ambiguousFindingsExit: true },
  'osv-scanner': { clean: 0, findings: 1, ambiguousFindingsExit: false }
};

// Findings as the scanner's own report lists them. Mirrors the gate's reading:
// a pip-audit vuln or OSV advisory with a string id.
export function countReportFindings(scanner, report) {
  if (scanner === 'pip-audit') {
    return report.dependencies
      .flatMap((dependency) => (Array.isArray(dependency?.vulns) ? dependency.vulns : []))
      .filter((vulnerability) => typeof vulnerability?.id === 'string').length;
  }
  if (scanner === 'osv-scanner') {
    return (report.results ?? [])
      .flatMap((result) => (Array.isArray(result?.packages) ? result.packages : []))
      .flatMap((dependency) => (Array.isArray(dependency?.vulnerabilities) ? dependency.vulnerabilities : []))
      .filter((advisory) => typeof advisory?.id === 'string').length;
  }
  throw new Error(`no exit-status contract for scanner '${scanner}'`);
}

// Pure decision over an already-validated report. Returns
// { ok, outcome, message }; `ok: false` fails the scanner step.
export function assessScannerExit({ scanner, exitCode, findingCount }) {
  const contract = EXIT_CONTRACTS[scanner];
  if (!contract) {
    return { ok: false, outcome: 'unsupported', message: `no exit-status contract for scanner '${scanner}'` };
  }
  const code = typeof exitCode === 'string' && /^\d+$/.test(exitCode.trim()) ? Number(exitCode) : exitCode;
  if (!Number.isInteger(code)) {
    return {
      ok: false,
      outcome: 'unknown-exit',
      message: `${scanner} exit status '${exitCode}' was not captured; the scan cannot be interpreted`
    };
  }

  if (code === contract.clean) {
    return findingCount === 0
      ? { ok: true, outcome: 'clean', message: `${scanner} exited ${code} with a valid report and no findings` }
      : {
          ok: true,
          outcome: 'findings-clean-exit',
          message:
            `${scanner} exited ${code} but its valid report lists ${findingCount} finding(s); ` +
            'every one is evaluated by the security gate'
        };
  }

  if (code === contract.findings) {
    if (findingCount > 0) {
      return {
        ok: true,
        outcome: 'findings',
        message:
          `${scanner} exited ${code} (vulnerabilities found) with a valid report listing ${findingCount} finding(s). ` +
          'This is a successful scan, not a scanner failure; the security gate decides what the findings mean'
      };
    }
    return {
      ok: false,
      outcome: 'exit-report-mismatch',
      message:
        `${scanner} exited ${code}, but its report lists no findings.` +
        (contract.ambiguousFindingsExit
          ? ` ${scanner} also uses exit ${code} for fatal errors, so this is treated as a scanner failure`
          : ' The exit status and the report disagree, so the scan cannot be trusted')
    };
  }

  return {
    ok: false,
    outcome: 'unexpected-exit',
    message: `${scanner} exited with unexpected status ${code}; this is a scanner or container failure, not a findings result`
  };
}

// Validate the report (fail closed on missing/empty/malformed), then judge the
// exit status against it.
export async function checkScannerRun({ scanner, exitCode, reportPath }) {
  // Validation throws on an unusable report whatever the exit status was: an
  // unreadable report is never rescued by a zero exit, nor excused by a 1.
  const summary = await validateDependencyReport(scanner, reportPath);
  const report = await readDependencyReport(scanner, reportPath);
  const findingCount = countReportFindings(scanner, report);
  return { ...assessScannerExit({ scanner, exitCode, findingCount }), findingCount, summary };
}

async function main() {
  const [scanner, exitCode, reportPath] = process.argv.slice(2);
  let assessment;
  try {
    if (!scanner || exitCode === undefined || !reportPath) {
      throw new Error('usage: check-scanner-exit.mjs <pip-audit|osv-scanner> <exit-status> <report.json>');
    }
    assessment = await checkScannerRun({ scanner, exitCode, reportPath });
  } catch (error) {
    console.error(`SCANNER RUN INVALID: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  if (process.env.GITHUB_OUTPUT) {
    await appendFile(
      process.env.GITHUB_OUTPUT,
      `exit_code=${exitCode}\noutcome=${assessment.outcome}\nfindings=${assessment.findingCount}\n`
    );
  }
  if (assessment.ok) {
    console.log(`${assessment.message}. (${assessment.summary})`);
    if (assessment.outcome === 'findings') {
      console.log(`::notice title=${scanner} found vulnerabilities::${assessment.message}.`);
    }
  } else {
    console.error(`SCANNER RUN INVALID: ${assessment.message}. (${assessment.summary})`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
