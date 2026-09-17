// Per-control evidence for the source-security reusable workflow.
//
// WHY THIS EXISTS: a caller of a reusable workflow sees one aggregate
// `needs.<job>.result`. When the policy gate BLOCKs, that aggregate is `failure`,
// and a caller that fed it to every source control reported secret scanning,
// dependency scanning and SAST as failed although all three scanners ran and
// produced usable reports. A finding is not a scanner failure.
//
// So each SCANNING control is answered from its own evidence:
//
//   did the scanner job execute and produce a trustworthy report?
//
// and nothing about whether the findings in that report satisfy policy — that is
// the source-gate control's question, answered by the gate job's own result.
//
// Result vocabulary (one per control):
//
//   success    the scanner job succeeded (it validates its own report before
//              upload) and the gate did not reject that report
//   failure    the scanner job failed: no trustworthy report was produced
//   cancelled  the scanner job was cancelled
//   skipped    the scanner job did not run
//   untrusted  the scanner job succeeded, but the gate attributed a
//              report-integrity failure to THIS control's report — findings are
//              UNKNOWN, not clean
//
// Anything unrecognized or missing becomes `failure`: absent evidence never
// reads as success.
import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCAN_CONTROLS = [
  { id: 'secret-scan', output: 'secret_scan_result', env: 'SECRET_SCAN_JOB_RESULT', job: 'Secret scanning' },
  {
    id: 'dependency-scan',
    output: 'dependency_scan_result',
    env: 'DEPENDENCY_SCAN_JOB_RESULT',
    job: 'Dependency scanning'
  },
  { id: 'sast', output: 'sast_result', env: 'SAST_JOB_RESULT', job: 'SAST' }
];

const JOB_RESULTS = new Set(['success', 'failure', 'cancelled', 'skipped']);

// `gate` is the parsed security-gate.json, or null when it could not be read.
// An unreadable gate result is the SOURCE GATE's failure (reported by that job's
// own result); it is not evidence against a scanner whose job validated and
// uploaded its report, so it downgrades no scanning control.
export function deriveScanControlResults({ jobResults = {}, gate = null } = {}) {
  const failures = Array.isArray(gate?.integrity?.failures) ? gate.integrity.failures : [];
  const results = {};

  for (const control of SCAN_CONTROLS) {
    const raw = typeof jobResults[control.id] === 'string' ? jobResults[control.id].trim() : '';
    if (!JOB_RESULTS.has(raw)) {
      results[control.id] = {
        result: 'failure',
        reason:
          raw === ''
            ? `no result was available for the ${control.job} job; missing evidence is treated as failure`
            : `unrecognized ${control.job} job result '${raw}'; treated as failure`
      };
      continue;
    }
    if (raw !== 'success') {
      results[control.id] = {
        result: raw,
        reason: `the ${control.job} job ended '${raw}', so it produced no trustworthy report`
      };
      continue;
    }
    const rejected = failures.find((failure) => failure?.control === control.id);
    results[control.id] = rejected
      ? {
          result: 'untrusted',
          reason: `the ${control.job} job completed, but the gate could not interpret its report: ${rejected.reason}`
        }
      : {
          result: 'success',
          reason: `the ${control.job} job executed and produced a report the gate accepted as trustworthy`
        };
  }

  return results;
}

async function readGate(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const gatePath = argv[argv.indexOf('--gate') + 1] || 'reports/security-gate.json';
  const env = process.env;
  const jobResults = Object.fromEntries(SCAN_CONTROLS.map((control) => [control.id, env[control.env]]));
  const results = deriveScanControlResults({ jobResults, gate: await readGate(gatePath) });

  const lines = [];
  for (const control of SCAN_CONTROLS) {
    const { result, reason } = results[control.id];
    lines.push(`${control.output}=${result}`);
    console.log(`${control.id}: ${result} — ${reason}`);
  }
  if (env.GITHUB_OUTPUT) {
    await appendFile(env.GITHUB_OUTPUT, `${lines.join('\n')}\n`);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
