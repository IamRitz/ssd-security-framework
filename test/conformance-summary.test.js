// The conformance job summary answers "did the required controls operate?".
// A clean run is a confirmation and renders compactly; anything abnormal keeps
// the full diagnostic report. Presentation only: conformance.json, every
// control status and the exit code are asserted unchanged.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';

import {
  CONTROLS,
  buildConformance,
  isCleanConformance,
  renderDetailedMarkdown,
  renderMarkdown,
  resolveCapabilities
} from '../security/scripts/conformance.mjs';

const D = 'c'.repeat(64);
const LIBRARY = resolveCapabilities({ artifact_type: 'library', registry: 'none', deploy_target: 'none' });
const SCANS = {
  'secret-scan': { status: 'success' },
  'dependency-scan': { status: 'success' },
  sast: { status: 'success' }
};
const SG_BLOCK_APPROVED = { status: 'failure', verdict: 'BLOCK', gate_mode: 'enforce', integrity_trusted: 'true', break_glass_eligible: 'true', gate_digest: D, override: 'approved' };
const BG_APPROVED = { status: 'success', decision: 'approved', request_delivered: 'true', gate_digest: D, delegated: 'true' };
const SG_PASS = { status: 'success', verdict: 'PASS', gate_mode: 'enforce', integrity_trusted: 'true', break_glass_eligible: 'false', gate_digest: D };
const CONTAINER = resolveCapabilities({ artifact_type: 'container', registry: 'ecr', deploy_target: 'framework-gated' });
const BG_NOT_EXERCISED = { status: 'skipped', decision: '', request_delivered: '', gate_digest: '', delegated: 'false' };

// Short names, as the compact renderer prints them.
const SHORT_NAMES = {
  'secret-scan': 'secret scanning',
  'dependency-scan': 'dependency scanning',
  sast: 'SAST',
  'source-gate': 'source gate',
  'image-scan-prepush': 'image scan',
  'registry-scan-collect': 'registry collection',
  'artifact-gate': 'artifact gate',
  'gated-deploy': 'deploy',
  'break-glass': 'break-glass'
};
const naLines = (markdown) => markdown.split('\n').filter((line) => line.startsWith('Not applicable: '));

// A container repo on a PR: every pr-phase control observed, the three delivery
// controls deferred by the phase logic. Break-glass is off, so it is not observed.
const containerPr = ({ observed: extraObserved = {}, ...extra } = {}) => {
  const observed = Object.fromEntries(
    CONTROLS.filter((control) => control.phases.includes('pr') && control.id !== 'break-glass').map((control) => [control.id, { status: 'pass' }])
  );
  return buildConformance({ capabilities: CONTAINER, ...extra, observed: { ...observed, 'source-gate': SG_PASS, ...extraObserved } });
};

// The live scratch consumer: library, break-glass on, strict, approved override.
const approvedLibrary = (extra = {}) =>
  buildConformance({
    capabilities: LIBRARY,
    observed: { ...SCANS, 'source-gate': SG_BLOCK_APPROVED, 'break-glass': BG_APPROVED },
    breakGlassEnabled: true,
    strictBreakGlassEvidence: true,
    now: Date.parse('2026-09-19T00:00:00Z'),
    ...extra
  });

// Long N/A reasons and the educational paragraph that a clean run must not repeat.
const VERBOSE = [/Scanning controls/, /\| Why \|/, /➖ N\/A/, /ships no container image/, /deploys nothing/, /This repository requires/];

describe('clean successful run: compact summary', () => {
  const report = approvedLibrary();
  const md = renderMarkdown(report);

  it('is clean by every measure', () => {
    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.exempt, 0);
    assert.equal(report.summary.deferred, 0);
    assert.deepEqual(report.warnings, []);
    assert.equal(isCleanConformance(report), true);
  });

  it('headlines the result, the phase, the applied count and the evidence mode', () => {
    assert.match(md, /^## ✅ Conformance$/m);
    assert.match(md, /^Phase: `pr` · Required controls: \*\*5\/5\*\* applied · Break-glass evidence: \*\*strict\*\*$/m);
  });

  it('lists only the controls that apply to this repository', () => {
    const rows = md.split('\n').filter((line) => line.startsWith('| ') && !line.startsWith('| Control') && !line.startsWith('| ---'));
    assert.deepEqual(rows, [
      '| Secret scanning (Gitleaks + TruffleHog) | ✅ applied |',
      '| Dependency scanning (npm audit / pip-audit / OSV-Scanner) | ✅ applied |',
      '| SAST (Semgrep) | ✅ applied |',
      '| Source security gate | ✅ applied — BLOCK overridden by verified approval |',
      '| Break-glass approval for an eligible BLOCK | ✅ applied — approved |'
    ]);
  });

  it('summarizes capability-driven N/A controls on one line, without their long reasons', () => {
    assert.deepEqual(naLines(md), [
      'Not applicable: image scan, registry collection, artifact gate, deploy (`artifact_type=library` `registry=none` `deploy_target=none`)'
    ]);
    for (const pattern of VERBOSE) assert.doesNotMatch(md, pattern);
  });

  it('without break-glass: no evidence-mode line, and break-glass carries its OWN reason', () => {
    const plain = renderMarkdown(
      buildConformance({ capabilities: LIBRARY, observed: { ...SCANS, 'source-gate': SG_PASS } })
    );
    assert.match(plain, /^Phase: `pr` · Required controls: \*\*4\/4\*\* applied$/m);
    assert.match(plain, /\| Source security gate \| ✅ applied — verdict PASS \|/);
    assert.doesNotMatch(plain, /Break-glass evidence/);
    // Two kinds of N/A, two lines: neither reason is attached to the other's controls.
    assert.deepEqual(naLines(plain), [
      'Not applicable: image scan, registry collection, artifact gate, deploy (`artifact_type=library` `registry=none` `deploy_target=none`)',
      'Not applicable: break-glass (`break_glass_enabled=false`)'
    ]);
  });

  it('break-glass disabled alone: only its own reason, never the capability triple', () => {
    // A container repo whose capabilities make every other control applicable.
    const md2 = renderMarkdown(containerPr());
    assert.deepEqual(naLines(md2), ['Not applicable: break-glass (`break_glass_enabled=false`)']);
    assert.doesNotMatch(md2, /Not applicable:.*artifact_type=/);
  });

  it('no N/A controls: no N/A line at all', () => {
    // Container + break-glass enabled: every control applies to this repository.
    const report = containerPr({ breakGlassEnabled: true, strictBreakGlassEvidence: true, observed: { 'break-glass': BG_NOT_EXERCISED } });
    assert.equal(report.summary.notApplicable, 0);
    const md2 = renderMarkdown(report);
    assert.deepEqual(naLines(md2), []);
    assert.doesNotMatch(md2, /Not applicable/);
  });

  it('every N/A line states a reason that belongs to the controls on it', () => {
    for (const report of [
      approvedLibrary(),
      buildConformance({ capabilities: LIBRARY, observed: { ...SCANS, 'source-gate': SG_PASS } }),
      containerPr(),
      buildConformance({ capabilities: resolveCapabilities({ artifact_type: 'container', registry: 'ecr', deploy_target: 'self-managed' }), observed: { ...SCANS, 'source-gate': SG_PASS, 'image-scan-prepush': { status: 'pass' } } })
    ]) {
      const byName = new Map(report.controls.map((control) => [SHORT_NAMES[control.id], control]));
      for (const line of naLines(renderMarkdown(report))) {
        const [, names, why = ''] = /^Not applicable: ([^(]+?)(?: \((.+)\))?$/.exec(line);
        const tokens = why.split(' ').map((entry) => entry.replaceAll('`', '')).filter(Boolean);
        // A capability line carries the whole declared triple; any other line
        // carries exactly one `key=value`.
        const isCapabilityLine = tokens.length > 1;
        if (isCapabilityLine) {
          assert.deepEqual(tokens, Object.entries(report.capabilities).map(([key, value]) => `${key}=${value}`));
        }
        for (const name of names.split(', ')) {
          const control = byName.get(name);
          assert.ok(control, `${name} is a known control`);
          assert.equal(control.status, 'not-applicable');
          const [key, value] = /^([a-z_]+)=([^:]*):/.exec(control.reason).slice(1);
          if (isCapabilityLine) {
            // Grouped here only because its OWN reason names a declared capability.
            assert.ok(Object.hasOwn(report.capabilities, key), `${name}: '${control.reason}' is not capability-driven`);
            assert.equal(report.capabilities[key], value, `${name}: stale capability value`);
          } else {
            // Its own reason, verbatim — never another control's.
            assert.deepEqual(tokens, [`${key}=${value}`], `${name}: '${control.reason}'`);
          }
        }
      }
    }
  });

  it('never presents an overridden BLOCK as PASS', () => {
    assert.doesNotMatch(md, /PASS/);
  });
});

describe('expected lifecycle deferral stays compact (container repo on a PR)', () => {
  const report = containerPr();
  const md = renderMarkdown(report);

  it('deferral is the only non-applied state, and it is not degraded', () => {
    assert.equal(report.summary.deferred, 3);
    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.exempt, 0);
    assert.deepEqual(report.warnings, []);
    assert.equal(isCleanConformance(report), true);
  });

  it('renders compactly, counting the deferred controls in the headline', () => {
    assert.match(md, /^## ✅ Conformance$/m);
    assert.match(md, /^Phase: `pr` · Required controls: \*\*5\/8\*\* applied, \*\*3\*\* deferred to another phase$/m);
    for (const pattern of VERBOSE) assert.doesNotMatch(md, pattern);
  });

  it('names the deferred controls once, on one line, with the phase they run in', () => {
    const line = md.split('\n').filter((entry) => entry.startsWith('Deferred to '));
    assert.deepEqual(line, ['Deferred to delivery: registry collection, artifact gate, deploy']);
    // Named once: not also as table rows.
    const rows = md.split('\n').filter((entry) => entry.startsWith('| ') && !entry.startsWith('| Control') && !entry.startsWith('| ---'));
    assert.equal(rows.length, 5);
    assert.ok(rows.every((row) => row.includes('✅ applied')), rows.join('\n'));
    assert.doesNotMatch(md, /⏳|deferred \|/);
  });

  it('a phase where nothing is deferred carries no deferred line', () => {
    const md2 = renderMarkdown(approvedLibrary());
    assert.doesNotMatch(md2, /Deferred to/);
    assert.doesNotMatch(md2, /deferred to another phase/);
  });
});

describe('abnormal or degraded run: the full diagnostic report', () => {
  const assertDetailed = (report, ...expected) => {
    assert.equal(isCleanConformance(report), false);
    const md = renderMarkdown(report);
    assert.equal(md, renderDetailedMarkdown(report), 'the detailed renderer, unchanged');
    assert.match(md, /^## Conformance$/m);
    assert.doesNotMatch(md, /✅ Conformance/);
    assert.match(md, /Scanning controls/);
    assert.match(md, /\| Control \| Status \| Why \|/);
    for (const pattern of expected) assert.match(md, pattern);
    return md;
  };

  it('a failed control', () => {
    const report = buildConformance({ capabilities: LIBRARY, observed: { ...SCANS, sast: { status: 'failure' }, 'source-gate': SG_PASS } });
    assert.equal(report.summary.failed, 1);
    assertDetailed(report, /\| SAST \(Semgrep\) \| ❌ failed \| .+ \|/, /➖ N\/A \| artifact_type=library/);
  });

  it('a claimed override that is not proven fails, with its reason', () => {
    const report = approvedLibrary({ observed: { ...SCANS, 'source-gate': SG_BLOCK_APPROVED, 'break-glass': { ...BG_APPROVED, gate_digest: 'e'.repeat(64) } } });
    assertDetailed(report, /❌ failed/, /different gate digest|not an override|verified approval/);
  });

  it('an exemption', () => {
    const future = '2999-01-01';
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: { ...SCANS, 'source-gate': SG_PASS },
      exemptions: [{ control: 'sast', reason: 'migrating rules', owner: 'security-eng', expires: future, expiresAt: Date.parse(future) }]
    });
    assert.equal(report.summary.exempt, 1);
    assertDetailed(report, /⚠️ exempt \| migrating rules — owner security-eng, expires 2999-01-01/);
  });

  for (const [name, extra, expected] of [
    ['a failed control', { observed: { sast: { status: 'failure' } } }, /❌ failed/],
    ['an exemption', { exemptions: [{ control: 'sast', reason: 'migrating rules', owner: 'security-eng', expires: '2999-01-01', expiresAt: Date.parse('2999-01-01') }] }, /⚠️ exempt/],
    ['a warning', { observed: { 'gated-deploy': { status: 'pass' } } }, /\*\*Warnings\*\*/],
    ['legacy break-glass evidence', { observed: { 'break-glass': { status: 'pass' } }, breakGlassEnabled: true, strictBreakGlassEvidence: false }, /legacy \(deprecated\)/]
  ]) {
    it(`${name} alongside expected deferral still renders detailed`, () => {
      const report = containerPr(extra);
      assert.ok(report.summary.deferred > 0, 'the deferred controls are still there');
      const md = assertDetailed(report, expected);
      assert.match(md, /⏳ deferred/, 'deferred controls keep their own rows in the detailed report');
    });
  }

  it('a warning', () => {
    const report = buildConformance({ capabilities: LIBRARY, observed: { ...SCANS, 'source-gate': SG_PASS, 'image-scan-prepush': { status: 'pass' } } });
    assert.equal(report.summary.failed, 0);
    assert.ok(report.warnings.length > 0);
    assertDetailed(report, /\*\*Warnings\*\*/, /disagree/);
  });

  it('legacy break-glass evidence stays visibly warned, even when every control applied', () => {
    const report = buildConformance({
      capabilities: LIBRARY,
      observed: { ...SCANS, 'source-gate': SG_PASS, 'break-glass': { status: 'pass' } },
      breakGlassEnabled: true,
      strictBreakGlassEvidence: false
    });
    assert.equal(report.summary.failed, 0);
    assertDetailed(report, /Break-glass evidence: \*\*legacy \(deprecated\)\*\*/, /DEPRECATED \(v1 legacy break-glass evidence\)/);
  });

  it('legacy mode without any warning still renders detailed', () => {
    const report = { ...approvedLibrary(), breakGlassEvidence: 'legacy', warnings: [] };
    assert.equal(isCleanConformance(report), false);
    assert.match(renderMarkdown(report), /legacy \(deprecated\)/);
  });
});

describe('machine-readable conformance is unchanged', () => {
  it('rendering never mutates the report object', () => {
    for (const report of [approvedLibrary(), buildConformance({ capabilities: LIBRARY, observed: { ...SCANS, sast: { status: 'failure' } } })]) {
      const before = structuredClone(report);
      renderMarkdown(report);
      assert.deepEqual(report, before);
    }
  });

  const runCli = async (observed) => {
    const directory = await mkdtemp(join(tmpdir(), 'conformance-summary-'));
    try {
      const output = join(directory, 'conformance.json');
      const r = spawnSync(
        process.execPath,
        [
          resolve('security/scripts/conformance.mjs'),
          '--artifact-type', 'library', '--registry', 'none', '--deploy-target', 'none',
          '--break-glass', 'true', '--strict-break-glass-evidence', 'true',
          '--phase', 'pr', '--observed', JSON.stringify(observed), '--output', output
        ],
        { encoding: 'utf8' }
      );
      return { ...r, json: JSON.parse(await readFile(output, 'utf8')) };
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  };
  const withoutTime = ({ generatedAt, ...rest }) => rest;

  it('clean run: exit 0, compact stdout, conformance.json equals buildConformance()', async () => {
    const observed = { ...SCANS, 'source-gate': SG_BLOCK_APPROVED, 'break-glass': BG_APPROVED };
    const r = await runCli(observed);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^## ✅ Conformance$/m);
    const expected = buildConformance({ capabilities: LIBRARY, observed, breakGlassEnabled: true, strictBreakGlassEvidence: true });
    assert.deepEqual(withoutTime(r.json), withoutTime(JSON.parse(JSON.stringify(expected))));
  });

  it('failed run: exit 1, detailed stdout, the failure count on stderr', async () => {
    const r = await runCli({ ...SCANS, sast: { status: 'failure' }, 'source-gate': SG_PASS, 'break-glass': { status: 'skipped', decision: '', request_delivered: '', gate_digest: '', delegated: 'false' } });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /^## Conformance$/m);
    assert.match(r.stderr, /applicable control\(s\) did not pass/);
    assert.ok(r.json.summary.failed >= 1);
  });
});
