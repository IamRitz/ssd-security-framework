// The baseline is the one artifact where log-only's deliberate non-blocking
// behaviour could cause silent, permanent damage: a baseline generated from a
// run whose scanners could not interpret their input records "no findings" as
// the accepted state forever. These tests pin that refusal.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { summarizeIntegrity } from '../security/scripts/security-gate.mjs';
import {
  assertScansTrusted,
  buildBaseline,
  UntrustedScanError
} from '../security/scripts/generate-semgrep-baseline.mjs';

const CLEAN_SEMGREP = {
  version: '1.176.0',
  errors: [],
  results: [
    {
      check_id: 'rules.command-injection',
      path: 'src/app.js',
      extra: { lines: '  exec(req.query.cmd)' }
    }
  ]
};

describe('summarizeIntegrity: what makes a scan untrustworthy', () => {
  it('treats a clean findings list as trusted', () => {
    assert.deepEqual(summarizeIntegrity([{ source: 'semgrep', policyRule: 'sast.high_new' }]), {
      trusted: true,
      failures: []
    });
  });

  it('catches the source gate report-integrity rule', () => {
    const integrity = summarizeIntegrity([
      { source: 'security-gate', id: 'report-integrity', policyRule: 'gate.report_integrity', reason: 'malformed JSON' }
    ]);
    assert.equal(integrity.trusted, false);
    assert.deepEqual(integrity.failures, [{ source: 'security-gate', reason: 'malformed JSON' }]);
  });

  it('catches the image gate report-integrity rule (Trivy false clean, EOSL)', () => {
    const integrity = summarizeIntegrity([
      {
        source: 'image-gate',
        id: 'report-integrity',
        policyRule: 'image.report_integrity',
        reason: 'Trivy did not detect an OS family — a zero-finding result would be a false clean'
      }
    ]);
    assert.equal(integrity.trusted, false);
    assert.match(integrity.failures[0].reason, /false clean/);
  });
});

describe('generate-semgrep-baseline: refuses an untrusted run', () => {
  it('generates from a trusted gate result', () => {
    assertScansTrusted([
      { path: 'reports/security-gate.json', result: { integrity: { trusted: true, failures: [] } } }
    ]);
    const baseline = buildBaseline(CLEAN_SEMGREP, ['p/owasp-top-ten']);
    assert.equal(baseline.schemaVersion, 1);
    assert.equal(baseline.findings.length, 1);
    assert.deepEqual(baseline.rulesets, ['p/owasp-top-ten']);
  });

  it('refuses when any gate result reports an integrity failure', () => {
    assert.throws(
      () =>
        assertScansTrusted([
          { path: 'reports/security-gate.json', result: { integrity: { trusted: true, failures: [] } } },
          {
            path: 'reports/image-gate-prepush.json',
            result: {
              integrity: {
                trusted: false,
                failures: [{ source: 'image-gate', reason: 'OS alpine is end-of-life (EOSL)' }]
              }
            }
          }
        ]),
      (error) => {
        assert.ok(error instanceof UntrustedScanError);
        assert.match(error.message, /image-gate-prepush\.json/);
        assert.match(error.message, /end-of-life/);
        return true;
      }
    );
  });

  it('refuses when no gate result is supplied at all', () => {
    // Fail closed: "nothing checked" must not read as "nothing wrong".
    assert.throws(() => assertScansTrusted([]), /no gate result to check/);
  });

  it('refuses a gate result with no integrity field, rather than assuming it is fine', () => {
    assert.throws(
      () => assertScansTrusted([{ path: 'old-gate.json', result: { verdict: 'PASS' } }]),
      /no integrity field/
    );
  });

  it('a log-only PASS verdict does not make an untrusted scan baselineable', () => {
    // The exact bypass this guards: in log-only the job is green and the verdict
    // may even read BLOCK without failing anything. Only `integrity` decides.
    assert.throws(
      () =>
        assertScansTrusted([
          {
            path: 'reports/security-gate.json',
            result: {
              verdict: 'BLOCK',
              integrity: { trusted: false, failures: [{ source: 'security-gate', reason: 'missing report file' }] }
            }
          }
        ]),
      UntrustedScanError
    );
  });

  it('still refuses a Semgrep report carrying scan errors', () => {
    assert.throws(
      () => buildBaseline({ ...CLEAN_SEMGREP, errors: [{ message: 'rule timeout' }] }, ['p/owasp-top-ten']),
      /scan errors/
    );
  });
});
