// The synthetic break-glass caller template (Phase 3E,
// docs/break-glass-validation.md § The synthetic live contract):
// examples/synthetic-break-glass/security.yml. Structural assertions, as for the
// other example callers (no YAML dependency in the toolkit), plus a parse with
// the onboarding YAML subset.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { parseYaml } from '../onboarding/lib/yaml.mjs';

const PATH = 'examples/synthetic-break-glass/security.yml';
const raw = readFileSync(PATH, 'utf8');
const source = raw.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
const doc = parseYaml(raw);

function jobBlock(text, jobId) {
  const start = text.indexOf(`\n  ${jobId}:\n`);
  assert.notEqual(start, -1, `${PATH} must define a '${jobId}' job`);
  const lines = text.slice(start + 1).split('\n');
  const block = [lines[0]];
  for (const line of lines.slice(1)) {
    if (/^ {2}[A-Za-z0-9_-]+:/.test(line)) break;
    block.push(line);
  }
  return block.join('\n');
}
const withValue = (block, key) => {
  const match = new RegExp(`^ {6}${key}: (.+)$`, 'm').exec(block);
  return match ? match[1].trim() : null;
};

// A caller with one of these defects must fail the structural checks below.
export function assertSyntheticCaller(text) {
  const parsed = parseYaml(text);
  const executable = text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
  // pull_request only.
  assert.deepEqual(Object.keys(parsed.on ?? {}), ['pull_request'], 'the synthetic caller is triggered by pull_request only');
  assert.ok(!/pull_request_target|workflow_dispatch|schedule:|push:/.test(executable), 'no other trigger, never pull_request_target');

  // The fixture is a literal eligible fixture, and the gate enforces.
  const scan = jobBlock(executable, 'source-security');
  assert.match(withValue(scan, 'synthetic_block_fixture') ?? '', /^(sast|dependency)$/, 'synthetic_block_fixture is a literal sast or dependency, never an expression');
  assert.equal(withValue(scan, 'gate_mode'), 'enforce', 'only an enforced BLOCK is delegated');
  assert.equal(withValue(scan, 'break_glass_transport'), 'lambda');
  assert.ok(!/lambda_function|lambda_role_arn|id-token/.test(scan), 'no broker identifier and no OIDC reach the scanner workflow');

  // Exactly one job holds id-token, and it is the break-glass job.
  const holders = Object.entries(parsed.jobs).filter(([, job]) => job.permissions?.['id-token'] !== undefined).map(([id]) => id);
  assert.deepEqual(holders, ['break-glass'], 'only the break-glass job is granted id-token');
  assert.equal(parsed.jobs['break-glass'].permissions['id-token'], 'write');
  assert.ok(!/secrets\s*:\s*inherit/.test(executable), 'never secrets: inherit');

  // Production and synthetic identifiers: explicit, separate variables.
  const bg = jobBlock(executable, 'break-glass');
  const synthetic = ['synthetic_lambda_function', 'synthetic_lambda_role_arn'].map((key) => withValue(bg, key));
  const production = ['lambda_function', 'lambda_role_arn'].map((key) => withValue(bg, key));
  for (const value of synthetic) assert.match(value ?? '', /^\$\{\{ vars\.SYNTHETIC_[A-Z_]+ \}\}$/, 'a synthetic identifier comes from a SYNTHETIC_ variable');
  for (const value of production) {
    assert.match(value ?? '', /^\$\{\{ vars\.[A-Z_]+ \}\}$/, 'a production identifier comes from a variable');
    assert.ok(!/SYNTHETIC/.test(value), 'a production identifier never comes from a synthetic variable');
  }
  assert.equal(new Set([...synthetic, ...production]).size, 4, 'four different variables: no identifier is shared between environments');
  assert.ok(!/^ {6}[a-z_]*environment[a-z_]*:/m.test(bg), 'the caller passes no environment: the framework derives it from the evidence');
  assert.match(bg, /if: \$\{\{ always\(\) && needs\.source-security\.outputs\.break_glass_delegated == 'true' \}\}/);
  assert.match(bg, /expected_gate_digest: \$\{\{ needs\.source-security\.outputs\.gate_digest \}\}/);

  // The overridden BLOCK is decided by final-gate.mjs with every fact.
  const gate = jobBlock(executable, 'security-gate');
  assert.match(gate, /if ! node "\$SSD_TOOLKIT\/scripts\/final-gate\.mjs"; then\s*\n\s*failed=1/);
  for (const fact of ['BREAK_GLASS_RESULT', 'BREAK_GLASS_DECISION', 'BREAK_GLASS_REQUEST_DELIVERED', 'BREAK_GLASS_GATE_DIGEST', 'SOURCE_GATE_DIGEST', 'SOURCE_BREAK_GLASS_DELEGATED']) {
    assert.match(gate, new RegExp(`${fact}: \\$\\{\\{ needs\\.`), `security-gate passes ${fact}`);
  }
  const conformance = jobBlock(executable, 'conformance');
  assert.match(conformance, /strict_break_glass_evidence: true/);
  assert.match(conformance, /break_glass_enabled: true/);
}

describe('the synthetic break-glass caller template', () => {
  it('parses, and calls the framework workflows the contract names', () => {
    assert.ok(doc.jobs['source-security'].uses.includes('/_source-scan.yml@'));
    assert.ok(doc.jobs['break-glass'].uses.includes('/_break-glass-lambda.yml@'));
    assert.ok(doc.jobs.conformance.uses.includes('/_conformance.yml@'));
    assert.ok(!source.includes('_source-security.yml'), 'never the legacy in-job path the hardened broker refuses');
  });

  it('meets the synthetic caller contract', () => {
    assertSyntheticCaller(raw);
  });

  describe('defects the contract check must reject', () => {
    const mutate = (from, to) => {
      assert.ok(raw.includes(from), `fixture drift: ${JSON.stringify(from)}`);
      return raw.replace(from, to);
    };
    for (const [name, broken] of [
      ['a workflow_dispatch trigger', () => mutate('on:\n  pull_request:\n', 'on:\n  workflow_dispatch:\n  pull_request:\n')],
      ['pull_request_target', () => mutate('on:\n  pull_request:\n', 'on:\n  pull_request_target:\n')],
      ['a fixture from a variable', () => mutate('synthetic_block_fixture: sast', "synthetic_block_fixture: ${{ vars.FIXTURE || 'none' }}")],
      ['no fixture', () => mutate('      synthetic_block_fixture: sast\n', '')],
      ['log-only', () => mutate('      gate_mode: enforce\n', "      gate_mode: log-only\n")],
      ['the synthetic function from the production variable', () => mutate('synthetic_lambda_function: ${{ vars.SYNTHETIC_BREAK_GLASS_LAMBDA_FUNCTION }}', 'synthetic_lambda_function: ${{ vars.BREAK_GLASS_LAMBDA_FUNCTION }}')],
      ['the production role from the synthetic variable', () => mutate('lambda_role_arn: ${{ vars.BREAK_GLASS_LAMBDA_ROLE_ARN }}', 'lambda_role_arn: ${{ vars.SYNTHETIC_BREAK_GLASS_LAMBDA_ROLE_ARN }}')],
      ['a literal production function', () => mutate('lambda_function: ${{ vars.BREAK_GLASS_LAMBDA_FUNCTION }}', 'lambda_function: ssd-break-glass-production-ci')],
      ['a caller-chosen environment', () => mutate('      timeout_seconds:', '      broker_environment: production\n      timeout_seconds:')],
      ['id-token on the scanner job', () => mutate('      pull-requests: write\n    with:\n      toolkit_ref: v1\n      # A synthetic', '      pull-requests: write\n      id-token: write\n    with:\n      toolkit_ref: v1\n      # A synthetic')],
      ['secrets: inherit', () => mutate('    permissions:\n      contents: read\n      id-token: write\n', '    permissions:\n      contents: read\n      id-token: write\n    secrets: inherit\n')],
      ['an aggregate without final-gate.mjs', () => mutate('if ! node "$SSD_TOOLKIT/scripts/final-gate.mjs"; then', 'if ! true; then')]
    ]) {
      it(`rejects ${name}`, () => {
        assert.throws(() => assertSyntheticCaller(broken()), assert.AssertionError);
      });
    }
  });
});
