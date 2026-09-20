// The break-glass OIDC boundary.
//
// A repository with no Lambda break-glass must grant no GitHub OIDC permission,
// and a repository with Lambda break-glass grants it ONLY to the dedicated
// break-glass job — which must validate this run's gate evidence, with
// framework code, before it can obtain an AWS credential. Nothing here fails at
// runtime if it regresses (an extra `id-token`, a reordered step, a looser final
// gate all still "work"), so it is asserted structurally, by executing the real
// step scripts, and with mutation-style cases that must be rejected.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, describe, it } from 'node:test';

import { renderSourceScan } from '../tools/render-source-scan.mjs';
import { runSecurityGate } from '../security/scripts/security-gate.mjs';
import {
  gateDigest,
  resolveBrokerRoute,
  revalidateGateForBreakGlass
} from '../security/scripts/break-glass-evidence.mjs';
import { deriveBreakGlassResult } from '../security/scripts/break-glass-result.mjs';
import { decideSourceGate, factsFromEnv } from '../security/scripts/final-gate.mjs';
import { CONTROLS, buildConformance, explainObserved, resolveCapabilities } from '../security/scripts/conformance.mjs';
import { deriveBreakGlassState, route } from '../security/scripts/format-findings.mjs';
import { breakGlassStateFromEnv, dispatch } from '../security/scripts/notify.mjs';
import { createLambdaInvoker } from '../security/scripts/break-glass-lambda-invoke.mjs';
import { notifyBreakGlass } from '../security/scripts/break-glass-notify.mjs';
import { pollBreakGlass } from '../security/scripts/break-glass-poll.mjs';

const FRAMEWORK = resolve('.');
const FIXTURES = join(FRAMEWORK, 'security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const WORK = mkdtempSync(join(tmpdir(), 'bg-oidc-boundary-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

const read = (path) => readFileSync(join(FRAMEWORK, path), 'utf8');
const executable = (text) => text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');

// One job's block from a workflow or example (no YAML parser: the toolkit is
// dependency-free by design).
function jobBlock(source, jobId) {
  const start = source.indexOf(`\n  ${jobId}:\n`);
  if (start === -1) return null;
  const lines = source.slice(start + 1).split('\n');
  const block = [lines[0]];
  for (const line of lines.slice(1)) {
    if (/^ {2}[A-Za-z0-9_-]+:/.test(line)) break;
    block.push(line);
  }
  return block.join('\n');
}

function jobIds(source) {
  const jobs = source.slice(source.indexOf('\njobs:\n'));
  return [...jobs.matchAll(/^ {2}([A-Za-z0-9_-]+):\s*$/gm)].map((match) => match[1]);
}

// The `run:` body of a named step, dedented (same extraction the other
// step-execution tests use).
function stepScript(text, name) {
  const start = text.indexOf(`- name: ${name}\n`);
  assert.ok(start >= 0, `step "${name}" not found`);
  const indent = start - (text.lastIndexOf('\n', start) + 1);
  const body = [];
  let runIndent = null;
  for (const line of text.slice(start).split('\n').slice(1)) {
    if (runIndent === null) {
      if (line.trim() !== '' && line.length - line.trimStart().length <= indent) break;
      const match = /^(\s*)run: \|\s*$/.exec(line);
      if (match) runIndent = match[1].length;
      continue;
    }
    if (line.trim() !== '' && line.length - line.trimStart().length <= runIndent) break;
    body.push(line);
  }
  assert.ok(body.length > 0, `step "${name}" has no multi-line run script`);
  const dedent = Math.min(...body.filter((l) => l.trim() !== '').map((l) => l.length - l.trimStart().length));
  return body.map((line) => line.slice(dedent)).join('\n');
}

function runScript(script, env = {}) {
  const outputs = join(mkdtempSync(join(WORK, 'out-')), 'github-output');
  writeFileSync(outputs, '');
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
    cwd: WORK,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_OUTPUT: outputs, ...env },
    encoding: 'utf8'
  });
  const parsed = Object.fromEntries(
    readFileSync(outputs, 'utf8').split('\n').filter(Boolean).map((line) => {
      const at = line.indexOf('=');
      return [line.slice(0, at), line.slice(at + 1)];
    })
  );
  return { code: result.status, out: `${result.stdout}${result.stderr}`, outputs: parsed };
}

// ---- real gate results ----------------------------------------------------------

const RUN = { repository: 'acme/app', commitSha: 'a'.repeat(40), runId: '4242' };

async function gate(overrides = {}, { provenance = RUN, syntheticFixture = null } = {}) {
  const dir = mkdtempSync(join(WORK, 'gate-'));
  return runSecurityGate({
    policy: join(FRAMEWORK, 'security/policy.yaml'),
    gitleaks: join(CLEAN, 'gitleaks.json'),
    trufflehog: join(CLEAN, 'trufflehog.json'),
    npmAudit: join(CLEAN, 'npm-audit.json'),
    osv: join(CLEAN, 'osv-scanner.json'),
    semgrep: join(CLEAN, 'semgrep.json'),
    baseline: join(CLEAN, 'semgrep-baseline.json'),
    output: join(dir, 'security-gate.json'),
    exceptions: join(dir, 'gate-exceptions.json'),
    provenance,
    syntheticFixture,
    ...overrides
  });
}

const G = {
  pass: () => gate(),
  passWithExceptions: () => gate({ npmAudit: join(FIXTURES, 'critical-no-fix/npm-audit.json') }),
  sast: () => gate({ semgrep: join(FIXTURES, 'new-high-sast/semgrep.json') }),
  dependency: () => gate({ npmAudit: join(FIXTURES, 'critical-with-fix/npm-audit.json') }),
  verifiedSecret: () => gate({ trufflehog: join(FIXTURES, 'verified-secret/trufflehog.json') }),
  malicious: () => gate({ osv: join(FIXTURES, 'malicious-package/osv-scanner.json') }),
  integrity: () => gate({ npmAudit: join(FIXTURES, 'malformed/npm-audit.json') }),
  mixed: () =>
    gate({
      semgrep: join(FIXTURES, 'new-high-sast/semgrep.json'),
      trufflehog: join(FIXTURES, 'verified-secret/trufflehog.json')
    })
};

const revalidate = (g, extra = {}) =>
  revalidateGateForBreakGlass(g, { expectedDigest: gateDigest(g), expectedProvenance: RUN, ...extra });

const PROD = {
  functionName: 'break-glass-broker',
  roleArn: 'arn:aws:iam::111122223333:role/break-glass-invoker',
  region: 'us-east-1'
};
const SYNTH = {
  syntheticFunctionName: 'break-glass-broker-synthetic',
  syntheticRoleArn: 'arn:aws:iam::111122223333:role/break-glass-invoker-synthetic'
};

// =================================================================================
describe('the OIDC-free twin is generated, not hand-maintained', () => {
  const legacy = read('.github/workflows/_source-security.yml');
  const twin = read('.github/workflows/_source-scan.yml');

  it('the committed _source-scan.yml is exactly the render of _source-security.yml', () => {
    assert.equal(twin, renderSourceScan(legacy), 'stale twin: run node tools/render-source-scan.mjs');
  });

  it('the twin can request no OIDC token and assume no role', () => {
    const body = executable(twin);
    assert.ok(!/id-token\s*:/.test(body), 'no job may declare id-token');
    assert.ok(!/aws-actions\//.test(body), 'no AWS credential action');
    assert.ok(!/role-to-assume/.test(body), 'no role assumption');
  });

  it('the v1 workflow keeps its in-job Lambda path for existing callers', () => {
    const gateJob = executable(legacy).slice(executable(legacy).indexOf('  source-gate:'));
    assert.match(gateJob, /id-token: write/, 'v1 Lambda callers depend on this permission');
    assert.match(gateJob, /- name: Assume the break-glass invoker role \(OIDC\)/);
    assert.match(legacy, /^ {2}SSD_WORKFLOW_VARIANT: legacy$/m);
    assert.match(twin, /^ {2}SSD_WORKFLOW_VARIANT: scan$/m);
  });

  it('the only differences are inside marked regions', () => {
    // Removing every marked region from the source, and every line the twin
    // gained from a scan-only region, leaves identical text.
    const strip = (text, keep) => renderSourceScan(text).split('\n').filter(keep).join('\n');
    const legacyShared = legacy
      .replace(/^\s*# >>> legacy-only[\s\S]*?# <<< legacy-only\n/gm, '')
      .replace(/^\s*# >>> scan-only[\s\S]*?# <<< scan-only\n/gm, '');
    const scanOnly = new Set(
      [...legacy.matchAll(/# >>> scan-only\n([\s\S]*?)\s*# <<< scan-only/g)]
        .flatMap((m) => m[1].split('\n'))
        .map((line) => line.replace(/^(\s*)# \| ?/, '$1'))
    );
    assert.equal(strip(legacy, (line) => !scanOnly.has(line)), legacyShared.split('\n').filter((line) => !scanOnly.has(line)).join('\n'));
  });

  it('the renderer refuses malformed regions instead of guessing', () => {
    assert.throws(() => renderSourceScan('a\n# >>> legacy-only\nb\n'), /unterminated/);
    assert.throws(() => renderSourceScan('# >>> scan-only\nnot-commented\n# <<< scan-only\n'), /# \| text/);
    assert.throws(() => renderSourceScan('# <<< legacy-only\n'), /closed/);
  });
});

// =================================================================================
describe('route: where break-glass runs (executes the real step)', () => {
  const script = stepScript(read('.github/workflows/_source-security.yml'), 'Resolve where break-glass runs for this workflow');
  const cases = [];
  for (const variant of ['legacy', 'scan'])
    for (const ENABLED of ['true', 'false'])
      for (const GATE_MODE of ['enforce', 'log-only'])
        for (const TRANSPORT of ['http', 'lambda']) cases.push({ variant, ENABLED, GATE_MODE, TRANSPORT });

  for (const c of cases) {
    it(`${c.variant} enabled=${c.ENABLED} ${c.GATE_MODE} ${c.TRANSPORT}`, () => {
      const { code, outputs } = runScript(script, { SSD_WORKFLOW_VARIANT: c.variant, ...c });
      assert.equal(code, 0);
      const active = c.ENABLED === 'true' && c.GATE_MODE !== 'log-only';
      if (c.variant === 'legacy') {
        // v1 behaviour, unchanged: in-job for every transport, never delegated.
        assert.equal(outputs.in_job, String(active));
        assert.equal(outputs.delegate_lambda, 'false');
      } else {
        assert.equal(outputs.in_job, String(active && c.TRANSPORT === 'http'));
        assert.equal(outputs.delegate_lambda, String(active && c.TRANSPORT === 'lambda'));
      }
    });
  }
});

describe('delegation requires an eligible, trusted, enforced BLOCK on the Lambda route', () => {
  const script = stepScript(read('.github/workflows/_source-scan.yml'), 'Decide whether this BLOCK is delegated to Lambda break-glass');
  const yes = { DELEGATE_LAMBDA: 'true', VERDICT: 'BLOCK', ELIGIBLE: 'true', TRUSTED: 'true', DIGEST: 'f'.repeat(64) };

  it('delegates exactly that case', () => {
    assert.equal(runScript(script, yes).outputs.break_glass_delegated, 'true');
  });
  for (const [key, bad] of [
    ['DELEGATE_LAMBDA', 'false'],
    ['VERDICT', 'PASS'],
    ['VERDICT', 'PASS-WITH-EXCEPTIONS'],
    ['ELIGIBLE', 'false'],
    ['TRUSTED', 'false'],
    ['DIGEST', '']
  ]) {
    it(`does not delegate when ${key}=${bad || '<empty>'}`, () => {
      assert.equal(runScript(script, { ...yes, [key]: bad }).outputs.break_glass_delegated, 'false');
    });
  }
});

describe('the source gate still fails on a delegated BLOCK (never green so break-glass can run)', () => {
  const script = stepScript(read('.github/workflows/_source-scan.yml'), 'Enforce the gate verdict');
  it('enforce + BLOCK + in-job break-glass skipped fails', () => {
    assert.equal(runScript(script, { GATE_MODE: 'enforce', VERDICT: 'BLOCK', BREAK_GLASS_OUTCOME: 'skipped' }).code, 1);
  });
  it('enforce + PASS passes', () => {
    assert.equal(runScript(script, { GATE_MODE: 'enforce', VERDICT: 'PASS', BREAK_GLASS_OUTCOME: 'skipped' }).code, 0);
  });
});

// =================================================================================
describe('no break-glass: callers grant no OIDC permission', () => {
  const twin = read('.github/workflows/_source-scan.yml');

  for (const path of ['examples/source-only/security.yml', 'examples/python-self-managed/security.yml']) {
    it(`${path} calls the OIDC-free workflow and grants id-token nowhere`, () => {
      const source = read(path);
      assert.match(source, /_source-scan\.yml@/);
      assert.ok(!/_source-security\.yml@/.test(source), 'must not call the OIDC-capable v1 workflow');
      assert.ok(!/id-token/.test(executable(source)), 'no job may be granted id-token');
      assert.ok(!/_break-glass-lambda\.yml/.test(source));
    });
  }

  it('the OIDC-free workflow still publishes every documented source output', () => {
    const outputs = twin.slice(twin.indexOf('    outputs:\n'), twin.indexOf('\npermissions:'));
    for (const name of [
      'verdict', 'break_glass_eligible', 'gate_mode', 'integrity_trusted', 'secret_scan_result',
      'dependency_scan_result', 'sast_result', 'source_gate_result', 'gate_digest', 'break_glass_delegated'
    ]) {
      assert.match(outputs, new RegExp(`^ {6}${name}:\\n[\\s\\S]*?value: \\$\\{\\{ jobs\\.source-gate\\.outputs\\.${name} \\}\\}`, 'm'), name);
    }
  });

  it('those outputs are published by always() steps, so a failed BLOCK still has them', () => {
    const job = twin.slice(twin.indexOf('  source-gate:'));
    for (const step of ['Publish gate verdict', 'Decide whether this BLOCK is delegated to Lambda break-glass', 'Publish per-control scan evidence', 'Publish the source gate control result']) {
      const at = job.indexOf(`- name: ${step}`);
      const next = job.indexOf('\n      - name:', at + 1);
      assert.match(job.slice(at, next), /\n\s+if: always\(\)\n/, step);
    }
  });
});

// =================================================================================
// The ordering control, as a reusable check, so the mutation cases below can
// prove the check itself catches each regression.
function assertOidcBoundary(source) {
  const body = executable(source);
  const steps = [...body.matchAll(/\n {6}- name: ([^\n]+)/g)].map((m) => ({ name: m[1], at: m.index }));
  const stepText = (i) => body.slice(steps[i].at, steps[i + 1]?.at ?? body.length);
  const index = (pattern) => steps.findIndex((_, i) => pattern.test(stepText(i)));

  const oidc = index(/aws-actions\/configure-aws-credentials@/);
  const preflight = index(/scripts\/break-glass-evidence\.mjs/);
  const download = index(/actions\/download-artifact@/);
  const request = index(/scripts\/break-glass-notify\.mjs/);
  const poll = index(/scripts\/break-glass-poll\.mjs/);
  assert.ok(oidc >= 0 && preflight >= 0 && download >= 0 && request >= 0 && poll >= 0, 'a boundary step is missing');
  assert.ok(download < preflight, 'evidence must be downloaded before validation');
  assert.ok(preflight < oidc, 'the evidence must be validated BEFORE any AWS credential is configured');
  assert.ok(oidc < request && request < poll, 'the broker is only called with credentials, after validation');
  assert.match(stepText(oidc), /if: \$\{\{ steps\.preflight\.outcome == 'success' \}\}/, 'OIDC must be gated on a successful preflight');
  assert.match(stepText(preflight), /\n\s+id: preflight\n/);
  assert.ok(!/continue-on-error/.test(stepText(preflight)), 'a refused preflight must not be masked');
  assert.match(stepText(oidc), /role-to-assume: \$\{\{ steps\.preflight\.outputs\.role_arn \}\}/, 'the role must be the one the preflight resolved');

  for (let i = 0; i < oidc; i += 1) {
    const text = stepText(i);
    // Only pinned, trusted actions before the credential.
    for (const [, action, ref] of text.matchAll(/uses: ([^@\s]+)@(\S+)/g)) {
      assert.ok(['actions/checkout', 'actions/setup-node', 'actions/download-artifact'].includes(action), `untrusted action before OIDC: ${action}`);
      assert.match(ref, /^[0-9a-f]{40}$/, `${action} must be pinned by commit SHA`);
    }
    if (/actions\/checkout@/.test(text)) {
      assert.match(text, /repository: IamRitz\/ssd-security-framework\n/, 'the only checkout is the fixed framework repository');
    }
    // No consumer code: every executed script is the toolkit's.
    for (const [, command] of text.matchAll(/\bnode\s+(\S+)/g)) {
      assert.match(command, /^"\$SSD_TOOLKIT\/scripts\/[a-z-]+\.mjs"$/, `non-toolkit script before OIDC: ${command}`);
    }
    assert.ok(!/\bnpm |\bnpx |\bmake |\.\/|bash [^-]|sh -c|\$GITHUB_WORKSPACE|github\.workspace/.test(text), `step "${steps[i].name}" may execute consumer code`);
  }
}

describe('Lambda break-glass: the credential boundary', () => {
  const bg = read('.github/workflows/_break-glass-lambda.yml');

  it('orders download -> framework validation -> OIDC -> request -> poll, running no consumer code', () => {
    assertOidcBoundary(bg);
  });

  it('grants exactly contents:read + id-token:write, and nothing else', () => {
    const job = jobBlock(executable(bg), 'break-glass');
    const perms = /\n {4}permissions:\n((?: {6}[a-z-]+: [a-z]+\n)+)/.exec(job)[1].trim().split('\n').map((l) => l.trim()).sort();
    assert.deepEqual(perms, ['contents: read', 'id-token: write']);
    assert.ok(!/write-all|secrets:\s*inherit/.test(bg));
  });

  it('never checks out the consumer and offers no vendored-toolkit or repository override', () => {
    const body = executable(bg);
    assert.equal((body.match(/actions\/checkout@/g) ?? []).length, 1);
    assert.ok(!/toolkit_path|toolkit_repository/.test(body));
  });

  it('reads only this run\'s artifact (no run-id / repository / token override)', () => {
    const body = executable(bg);
    const download = body.slice(body.indexOf('actions/download-artifact@'), body.indexOf('- name: Validate the gate evidence'));
    assert.match(download, /name: security-gate-results/);
    assert.ok(!/run-id|github-token|repository:/.test(download));
  });

  it('derives synthetic routing from evidence: it has no synthetic on/off input', () => {
    const inputs = bg.slice(bg.indexOf('    inputs:\n'), bg.indexOf('    outputs:\n'));
    const names = [...inputs.matchAll(/^ {6}([a-z_]+):\s*$/gm)].map((m) => m[1]);
    // Only broker IDENTIFIERS for the isolated route may be supplied; whether
    // the route is used is never an input.
    assert.deepEqual(names.filter((n) => /synthetic/.test(n)).sort(), ['synthetic_aws_region', 'synthetic_lambda_function', 'synthetic_lambda_role_arn']);
    assert.ok(!/inputs\.synthetic\b|synthetic_block_fixture/.test(bg));
  });

  it('keeps the Slack URL scoped to the notifier step only', () => {
    const body = executable(bg);
    assert.equal((body.match(/inputs\.slack_notify_url/g) ?? []).length, 1);
    const at = body.indexOf('inputs.slack_notify_url');
    assert.ok(body.lastIndexOf('- name: Post developer-readable findings', at) > body.lastIndexOf('- name: Record the break-glass result', at));
  });

  describe('mutations of the workflow that the boundary check must reject', () => {
    const swap = (text, a, b) => {
      const body = text;
      const start = (name) => body.indexOf(`      - name: ${name}\n`);
      const end = (name) => {
        const s = start(name);
        const n = body.indexOf('\n      - name:', s + 1);
        return n === -1 ? body.length : n + 1;
      };
      const [first, second] = start(a) < start(b) ? [a, b] : [b, a];
      const A = body.slice(start(first), end(first));
      const B = body.slice(start(second), end(second));
      return body.slice(0, start(first)) + B + body.slice(end(first), start(second)) + A + body.slice(end(second));
    };
    const cases = {
      'OIDC moved before validation': swap(bg, 'Validate the gate evidence and resolve the broker before any credential', 'Assume the break-glass invoker role (OIDC)'),
      'download moved after validation': swap(bg, 'Download this run\'s security gate evidence', 'Validate the gate evidence and resolve the broker before any credential'),
      'OIDC no longer gated on the preflight': bg.replace("if: ${{ steps.preflight.outcome == 'success' }}\n        uses: aws-actions", 'uses: aws-actions'),
      'preflight masked with continue-on-error': bg.replace('        id: preflight\n', '        id: preflight\n        continue-on-error: true\n'),
      'raw role input handed to OIDC': bg.replace('role-to-assume: ${{ steps.preflight.outputs.role_arn }}', 'role-to-assume: ${{ inputs.lambda_role_arn }}'),
      'consumer checkout before OIDC': bg.replace('      - name: Set up Node.js\n', '      - name: Check out consumer\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n\n      - name: Set up Node.js\n'),
      'consumer script before OIDC': bg.replace('        run: node "$SSD_TOOLKIT/scripts/break-glass-evidence.mjs"', '        run: |\n          ./scripts/prepare.sh\n          node "$SSD_TOOLKIT/scripts/break-glass-evidence.mjs"'),
      'unpinned action before OIDC': bg.replace('actions/setup-node@820762786026740c76f36085b0efc47a31fe5020', 'actions/setup-node@v4'),
      'third-party action before OIDC': bg.replace('      - name: Set up Node.js\n', '      - name: Helper\n        uses: someone/helper@0123456789012345678901234567890123456789\n\n      - name: Set up Node.js\n')
    };
    for (const [name, mutated] of Object.entries(cases)) {
      it(`rejects: ${name}`, () => {
        assert.notEqual(mutated, bg, 'the mutation must change the workflow');
        assert.throws(() => assertOidcBoundary(mutated));
      });
    }
  });
});

describe('Lambda break-glass callers: only the break-glass job holds OIDC', () => {
  const source = read('examples/container-ecr/security.yml');
  it('exactly one job is granted id-token, and it is the break-glass job', () => {
    const granted = jobIds(source).filter((id) => /id-token:\s*write/.test(executable(jobBlock(source, id))));
    assert.deepEqual(granted, ['break-glass']);
  });
  it('the source job calls the OIDC-free workflow and delegates Lambda', () => {
    const job = jobBlock(source, 'source-security');
    assert.match(job, /_source-scan\.yml@v1/);
    assert.match(job, /break_glass_transport: lambda/);
    assert.ok(!/lambda_role_arn|lambda_function/.test(job), 'no Lambda configuration reaches the scanner workflow');
  });
  it('the break-glass job runs only for a delegated BLOCK and binds to the evaluated digest', () => {
    const job = jobBlock(source, 'break-glass');
    assert.match(job, /if: \$\{\{ always\(\) && needs\.source-security\.outputs\.break_glass_delegated == 'true' \}\}/);
    assert.match(job, /expected_gate_digest: \$\{\{ needs\.source-security\.outputs\.gate_digest \}\}/);
    assert.match(job, /_break-glass-lambda\.yml@v1/);
    assert.ok(!/secrets:/.test(job));
  });
});

// =================================================================================
describe('independent revalidation of the gate evidence', () => {
  it('accepts an eligible new High/Critical SAST BLOCK', async () => {
    const g = await G.sast();
    const v = revalidate(g);
    assert.equal(v.synthetic, false);
    assert.ok(v.eligibleFindings.length > 0);
  });
  it('accepts an eligible fixable High/Critical dependency BLOCK', async () => {
    assert.ok(revalidate(await G.dependency()).eligibleFindings.length > 0);
  });

  for (const [name, make, code] of [
    ['PASS', G.pass, 'not-a-block'],
    ['PASS-WITH-EXCEPTIONS', G.passWithExceptions, 'not-a-block'],
    ['integrity BLOCK', G.integrity, 'integrity'],
    ['verified-secret BLOCK', G.verifiedSecret, 'hard-block'],
    ['malicious-package BLOCK', G.malicious, 'hard-block'],
    ['mixed eligible + hard BLOCK', G.mixed, 'hard-block']
  ]) {
    it(`refuses ${name}`, async () => {
      const g = await make();
      assert.throws(() => revalidate(g), (error) => error.code === code);
    });
  }

  it('does not trust the gate\'s own summary: a hard block marked eligible is refused', async () => {
    const g = await G.mixed();
    g.breakGlass = { eligible: true, eligibleFindings: g.findings.filter((f) => f.action === 'BLOCK'), ineligibleFindings: [] };
    for (const f of g.findings) f.breakGlassEligible = true;
    assert.throws(() => revalidate(g), (error) => error.code === 'hard-block');
  });

  it('refuses an eligible summary that omits a raw BLOCK', async () => {
    const g = await G.sast();
    g.findings.push({ ...g.findings.find((f) => f.action === 'BLOCK'), id: 'extra' });
    assert.throws(() => revalidate(g), (error) => error.code === 'ineligible');
  });

  it('refuses a raw BLOCK whose rule is not eligible even when the summary looks valid', async () => {
    const g = await G.sast();
    const raw = g.findings.find((f) => f.action === 'BLOCK');
    raw.policyRule = 'secrets.unverified';
    assert.throws(() => revalidate(g), /secrets\.unverified, which break-glass may not override/);
  });

  it('refuses a raw BLOCK that policy marked not eligible even when the summary looks valid', async () => {
    const g = await G.sast();
    g.findings.find((f) => f.action === 'BLOCK').breakGlassEligible = false;
    assert.throws(() => revalidate(g), /policy marked a sast\.\w+ finding as not break-glass eligible/);
  });

  it('refuses a summary that shows approvers a different finding than the raw BLOCK', async () => {
    const g = await G.sast();
    g.breakGlass.eligibleFindings = g.breakGlass.eligibleFindings.map((f) => ({ ...f, reason: 'something harmless' }));
    assert.throws(() => revalidate(g), /not the raw BLOCK findings/);
  });

  it('refuses an integrity flag that was flipped to untrusted on an eligible BLOCK', async () => {
    const g = await G.sast();
    g.integrity.trusted = false;
    assert.throws(() => revalidate(g), (error) => error.code === 'integrity');
  });

  it('refuses a bootstrap evaluation', async () => {
    const g = await G.sast();
    g.bootstrap = { active: true };
    assert.throws(() => revalidate(g), (error) => error.code === 'bootstrap');
  });

  describe('run binding', () => {
    it('refuses evidence with no provenance', async () => {
      const g = await gate({ semgrep: join(FIXTURES, 'new-high-sast/semgrep.json') }, { provenance: null });
      assert.throws(() => revalidate(g), (error) => error.code === 'provenance');
    });
    for (const field of ['repository', 'commitSha', 'runId']) {
      it(`refuses evidence from another ${field}`, async () => {
        const g = await gate({ semgrep: join(FIXTURES, 'new-high-sast/semgrep.json') }, { provenance: { ...RUN, [field]: `${RUN[field]}x` } });
        assert.throws(() => revalidate(g), (error) => error.code === 'provenance');
      });
    }
    it('refuses when the expected run identity is unknown', async () => {
      const g = await G.sast();
      assert.throws(() => revalidate(g, { expectedProvenance: { ...RUN, runId: '' } }), (error) => error.code === 'configuration');
    });
  });

  describe('gate digest binding', () => {
    it('refuses evidence that is not the gate the source workflow evaluated', async () => {
      const a = await G.sast();
      const b = await G.dependency();
      assert.throws(() => revalidate(b, { expectedDigest: gateDigest(a) }), (error) => error.code === 'digest-mismatch');
    });
    it('refuses a missing or malformed expected digest', async () => {
      const g = await G.sast();
      for (const expectedDigest of ['', undefined, 'abc', 'G'.repeat(64)]) {
        assert.throws(() => revalidate(g, { expectedDigest }), (error) => error.code === 'configuration');
      }
    });
    it('the source workflow publishes the same digest the broker binds to', () => {
      // Publish gate verdict computes the digest inline; it must equal gateDigest().
      const script = stepScript(read('.github/workflows/_source-scan.yml'), 'Publish gate verdict');
      const dir = mkdtempSync(join(WORK, 'digest-'));
      mkdirSync(join(dir, 'reports'));
      const g = { verdict: 'BLOCK', integrity: { trusted: true }, breakGlass: { eligible: true }, n: 1 };
      writeFileSync(join(dir, 'reports/security-gate.json'), JSON.stringify(g, null, 2));
      const outputs = join(dir, 'out');
      writeFileSync(outputs, '');
      const r = spawnSync('bash', ['-eo', 'pipefail', '-c', script], { cwd: dir, env: { ...process.env, GITHUB_OUTPUT: outputs }, encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
      assert.match(readFileSync(outputs, 'utf8'), new RegExp(`gate_digest=${gateDigest(g)}\\n`));
      assert.equal(gateDigest(g), createHash('sha256').update(JSON.stringify(g)).digest('hex'));
    });
  });

  it('refuses evidence that does not say whether it is synthetic', async () => {
    const g = await G.sast();
    delete g.synthetic;
    assert.throws(() => revalidate(g), (error) => error.code === 'synthetic-unknown');
  });

  it('refuses non-object evidence', () => {
    for (const bad of [null, [], 'BLOCK', 7]) {
      assert.throws(() => revalidateGateForBreakGlass(bad, { expectedDigest: 'f'.repeat(64), expectedProvenance: RUN }), (error) => error.code === 'malformed-evidence');
    }
  });
});

// =================================================================================
describe('synthetic isolation is evidence-derived', () => {
  it('the gate records an injected fixture, and records its absence', async () => {
    assert.deepEqual((await G.sast()).synthetic, { active: false, fixture: null });
    const s = await gate({ semgrep: join(FIXTURES, 'new-high-sast/semgrep.json') }, { syntheticFixture: 'sast' });
    assert.deepEqual(s.synthetic, { active: true, fixture: 'sast' });
    assert.equal(revalidate(s).synthetic, true);
  });

  it('an unsupported fixture name fails the gate run instead of reading as "not synthetic"', async () => {
    await assert.rejects(() => gate({}, { syntheticFixture: 'secrets' }), /unsupported synthetic fixture/);
  });

  it('production evidence routes to production identifiers', () => {
    assert.deepEqual(resolveBrokerRoute({ synthetic: false, config: { ...PROD, ...SYNTH } }), { route: 'production', ...PROD });
  });

  it('synthetic evidence routes to the dedicated test broker and role', () => {
    const r = resolveBrokerRoute({ synthetic: true, config: { ...PROD, ...SYNTH } });
    assert.equal(r.route, 'synthetic');
    assert.equal(r.functionName, SYNTH.syntheticFunctionName);
    assert.equal(r.roleArn, SYNTH.syntheticRoleArn);
    assert.equal(r.region, PROD.region, 'region alone may default; identity never does');
  });

  it('missing synthetic configuration never falls back to production', () => {
    for (const missing of [{}, { syntheticFunctionName: SYNTH.syntheticFunctionName }, { syntheticRoleArn: SYNTH.syntheticRoleArn }]) {
      assert.throws(() => resolveBrokerRoute({ synthetic: true, config: { ...PROD, ...missing } }), (error) => error.code === 'synthetic-isolation');
    }
  });

  it('the production function or role cannot be reused for a synthetic request', () => {
    assert.throws(() => resolveBrokerRoute({ synthetic: true, config: { ...PROD, ...SYNTH, syntheticFunctionName: PROD.functionName } }), /SEPARATE broker/);
    assert.throws(
      () => resolveBrokerRoute({ synthetic: true, config: { ...PROD, ...SYNTH, syntheticFunctionName: `arn:aws:lambda:us-east-1:111122223333:function:${PROD.functionName}` } }),
      /SEPARATE broker/,
      'an ARN of the production function is still the production function'
    );
    assert.throws(() => resolveBrokerRoute({ synthetic: true, config: { ...PROD, ...SYNTH, syntheticRoleArn: PROD.roleArn } }), /production role/);
  });

  it('isolation must be proven by comparison: synthetic without production identifiers is refused', () => {
    assert.throws(() => resolveBrokerRoute({ synthetic: true, config: SYNTH }), (error) => error.code === 'synthetic-isolation');
  });

  it('production requires complete, well-formed configuration', () => {
    for (const bad of [{}, { ...PROD, roleArn: '' }, { ...PROD, region: '' }, { ...PROD, roleArn: 'role/x' }, { ...PROD, functionName: 'bad name' }]) {
      assert.throws(() => resolveBrokerRoute({ synthetic: false, config: bad }), (error) => error.code === 'configuration');
    }
  });

  it('the route cannot be chosen without evidence', () => {
    assert.throws(() => resolveBrokerRoute({ synthetic: undefined, config: { ...PROD, ...SYNTH } }), (error) => error.code === 'synthetic-unknown');
  });
});

// =================================================================================
describe('preflight CLI (the exact command the workflow runs, before OIDC)', () => {
  const SCRIPT = join(FRAMEWORK, 'security/scripts/break-glass-evidence.mjs');

  function preflight(g, env = {}) {
    const dir = mkdtempSync(join(WORK, 'preflight-'));
    const gatePath = join(dir, 'security-gate.json');
    if (g !== undefined) writeFileSync(gatePath, typeof g === 'string' ? g : JSON.stringify(g, null, 2));
    const output = join(dir, 'out');
    writeFileSync(output, '');
    const result = spawnSync(process.execPath, [SCRIPT], {
      env: {
        PATH: process.env.PATH,
        GITHUB_OUTPUT: output,
        GITHUB_REPOSITORY: RUN.repository,
        GITHUB_SHA: RUN.commitSha,
        GITHUB_RUN_ID: RUN.runId,
        SSD_GATE_PATH: gatePath,
        SSD_PREFLIGHT_PATH: join(dir, 'preflight.json'),
        GATE_MODE: 'enforce',
        EXPECTED_GATE_DIGEST: g && typeof g === 'object' ? gateDigest(g) : 'f'.repeat(64),
        PROD_FUNCTION: PROD.functionName,
        PROD_ROLE: PROD.roleArn,
        PROD_REGION: PROD.region,
        ...env
      },
      encoding: 'utf8'
    });
    const record = existsSync(join(dir, 'preflight.json')) ? JSON.parse(readFileSync(join(dir, 'preflight.json'), 'utf8')) : null;
    return { code: result.status, out: `${result.stdout}${result.stderr}`, outputs: readFileSync(output, 'utf8'), record };
  }

  it('accepts an eligible BLOCK and hands the resolved role to the OIDC step', async () => {
    const r = preflight(await G.dependency());
    assert.equal(r.code, 0, r.out);
    assert.match(r.outputs, new RegExp(`role_arn=${PROD.roleArn}\\n`));
    assert.match(r.outputs, /route=production\n/);
    assert.equal(r.record.accepted, true);
  });

  for (const [name, make] of [['hard BLOCK', G.verifiedSecret], ['integrity BLOCK', G.integrity], ['PASS', G.pass]]) {
    it(`refuses a ${name} and emits no role for the OIDC step`, async () => {
      const r = preflight(await make());
      assert.equal(r.code, 1);
      assert.ok(!/role_arn=/.test(r.outputs), 'no role may reach the OIDC step');
      assert.equal(r.record.accepted, false);
    });
  }

  it('missing gate artifact fails closed', () => {
    const r = preflight(undefined);
    assert.equal(r.code, 1);
    assert.equal(r.record.refusal.code, 'malformed-evidence');
  });

  it('malformed gate artifact fails closed', () => {
    const r = preflight('{"verdict": "BLOCK",');
    assert.equal(r.code, 1);
    assert.equal(r.record.refusal.code, 'malformed-evidence');
  });

  it('missing broker configuration fails before any credential', async () => {
    const r = preflight(await G.sast(), { PROD_ROLE: '' });
    assert.equal(r.code, 1);
    assert.equal(r.record.refusal.code, 'configuration');
  });

  it('refuses a log-only gate', async () => {
    const r = preflight(await G.sast(), { GATE_MODE: 'log-only' });
    assert.equal(r.code, 1);
  });

  it('synthetic evidence with only production configuration is refused, not routed to production', async () => {
    const g = await gate({ npmAudit: join(FIXTURES, 'critical-with-fix/npm-audit.json') }, { syntheticFixture: 'dependency' });
    const r = preflight(g);
    assert.equal(r.code, 1);
    assert.equal(r.record.refusal.code, 'synthetic-isolation');
    assert.ok(!/role_arn=/.test(r.outputs));
  });

  it('synthetic evidence with isolated configuration assumes only the synthetic role', async () => {
    const g = await gate({ npmAudit: join(FIXTURES, 'critical-with-fix/npm-audit.json') }, { syntheticFixture: 'dependency' });
    const r = preflight(g, { SYNTH_FUNCTION: SYNTH.syntheticFunctionName, SYNTH_ROLE: SYNTH.syntheticRoleArn });
    assert.equal(r.code, 0, r.out);
    assert.match(r.outputs, new RegExp(`role_arn=${SYNTH.syntheticRoleArn}\\n`));
    assert.match(r.outputs, /synthetic=true\n/);
  });
});

// =================================================================================
describe('broker exchange: request, poll, and the recorded decision', () => {
  const DIGEST = 'd'.repeat(64);
  const request = { requestId: 'req-1', gateDigest: DIGEST };
  const invokeReturning = (...bodies) => {
    let i = 0;
    return async () => bodies[Math.min(i++, bodies.length - 1)];
  };
  const poll = (invoke, extra = {}) =>
    pollBreakGlass({ request, invoke, sleep: async () => {}, intervalMilliseconds: 0, ...extra });

  it('approved with the exact requestId and gate digest succeeds', async () => {
    const status = await poll(invokeReturning({ ok: true, body: { requestId: 'req-1', gateDigest: DIGEST, status: 'approved', approver: { username: 'u' } } }));
    assert.equal(status.status, 'approved');
  });
  it('a decision for another gate digest fails', async () => {
    await assert.rejects(() => poll(invokeReturning({ ok: true, body: { requestId: 'req-1', gateDigest: 'e'.repeat(64), status: 'approved' } })), /gateDigest mismatch/);
  });
  it('a decision for another request fails', async () => {
    await assert.rejects(() => poll(invokeReturning({ ok: true, body: { requestId: 'req-2', gateDigest: DIGEST, status: 'approved' } })), /requestId mismatch/);
  });
  for (const status of ['denied', 'expired']) {
    it(`${status} is terminal and not approved`, async () => {
      assert.equal((await poll(invokeReturning({ ok: true, body: { requestId: 'req-1', gateDigest: DIGEST, status } }))).status, status);
    });
  }
  it('no decision before the deadline is a timeout', async () => {
    let t = 0;
    const r = await poll(invokeReturning({ ok: true, body: { requestId: 'req-1', gateDigest: DIGEST, status: 'pending' } }), { timeoutSeconds: 1, now: () => (t += 600) });
    assert.equal(r.status, 'timeout');
  });
  it('an unknown status fails', async () => {
    await assert.rejects(() => poll(invokeReturning({ ok: true, body: { requestId: 'req-1', gateDigest: DIGEST, status: 'maybe' } })), /unsupported/);
  });
  it('a broker rejection fails', async () => {
    await assert.rejects(() => poll(invokeReturning({ ok: false, error: 'nope' })), /rejected status/);
    const g = await G.sast();
    await assert.rejects(
      () => notifyBreakGlass({ gate: g, context: { repository: 'a/b', commitSha: 'x' }, invoke: async () => ({ ok: false, error: 'denied' }) }),
      /rejected notify/
    );
  });
  it('an unreachable broker fails', async () => {
    const invoke = createLambdaInvoker({ functionName: 'fn', region: 'us-east-1', execFileImpl: async () => { throw new Error('connect ETIMEDOUT'); } });
    await assert.rejects(() => poll(invoke), /ETIMEDOUT/);
  });

  describe('deriveBreakGlassResult: bounded, fail-closed status', () => {
    const preflight = { accepted: true, gateDigest: DIGEST, synthetic: false, route: 'production' };
    const ok = { preflightOutcome: 'success', requestOutcome: 'success', pollOutcome: 'success', preflight, request };
    const decision = (status, extra = {}) => ({ requestId: 'req-1', gateDigest: DIGEST, status, ...extra });

    it('approved only with every link intact', () => {
      const r = deriveBreakGlassResult({ ...ok, decision: decision('approved', { approver: { username: 'u' } }) });
      assert.equal(r.decisionStatus, 'approved');
      assert.equal(r.controlResult, 'success');
      assert.equal(r.requestDelivered, true);
      assert.equal(r.gateDigest, DIGEST);
    });
    for (const [name, input, expected] of [
      ['denied', { ...ok, pollOutcome: 'failure', decision: decision('denied') }, 'denied'],
      ['expired', { ...ok, pollOutcome: 'failure', decision: decision('expired') }, 'expired'],
      ['timeout', { ...ok, pollOutcome: 'failure', decision: decision('timeout') }, 'timeout'],
      ['unknown status', { ...ok, decision: decision('maybe') }, 'error'],
      ['decision for another digest', { ...ok, decision: decision('approved', { gateDigest: 'e'.repeat(64) }) }, 'error'],
      ['decision for another request', { ...ok, decision: decision('approved', { requestId: 'req-2' }) }, 'error'],
      ['approved file but poll step failed', { ...ok, pollOutcome: 'failure', decision: decision('approved') }, 'error'],
      ['no decision (unreachable / malformed)', { ...ok, pollOutcome: 'failure', decision: null }, 'error'],
      ['request not delivered', { ...ok, requestOutcome: 'failure', pollOutcome: 'skipped' }, 'error'],
      // Request and decision agree with each other, but not with the validated gate.
      ['request bound to another digest', { ...ok, request: { requestId: 'req-1', gateDigest: 'e'.repeat(64) }, decision: decision('approved', { gateDigest: 'e'.repeat(64) }) }, 'error'],
      ['requestId that could forge an output line', { ...ok, request: { requestId: 'r\ncontrol_result=success', gateDigest: DIGEST }, decision: decision('approved', { requestId: 'r\ncontrol_result=success' }) }, 'error'],
      ['preflight refused a hard block', { preflightOutcome: 'failure', preflight: { accepted: false, refusal: { code: 'hard-block', reason: 'x' } } }, 'refused'],
      ['preflight configuration error', { preflightOutcome: 'failure', preflight: { accepted: false, refusal: { code: 'configuration', reason: 'x' } } }, 'error'],
      ['preflight never ran', {}, 'error'],
      ['preflight success without a record', { preflightOutcome: 'success' }, 'error']
    ]) {
      it(`${name} -> ${expected}`, () => {
        const r = deriveBreakGlassResult(input);
        assert.equal(r.decisionStatus, expected);
        assert.equal(r.controlResult, expected === 'approved' ? 'success' : 'failure');
        if (!['denied', 'expired', 'timeout', 'approved'].includes(expected) && input.requestOutcome !== 'success') {
          assert.equal(r.requestDelivered, false);
        }
      });
    }
  });

  it('the workflow enforce step passes only on approved', () => {
    const script = stepScript(read('.github/workflows/_break-glass-lambda.yml'), 'Enforce the break-glass decision');
    assert.equal(runScript(script, { DECISION: 'approved' }).code, 0);
    for (const d of ['denied', 'expired', 'timeout', 'refused', 'error', '', 'APPROVED']) {
      assert.equal(runScript(script, { DECISION: d }).code, 1, d);
    }
  });
});

// =================================================================================
const D = 'c'.repeat(64);
const OVERRIDE = {
  sourceResult: 'failure',
  verdict: 'BLOCK',
  gateMode: 'enforce',
  integrityTrusted: 'true',
  breakGlassEligible: 'true',
  breakGlassDelegated: 'true',
  secretScanResult: 'success',
  dependencyScanResult: 'success',
  sastResult: 'success',
  sourceGateDigest: D,
  breakGlassResult: 'success',
  breakGlassDecision: 'approved',
  breakGlassDelivered: 'true',
  breakGlassGateDigest: D
};

describe('final security-gate decision (source leg)', () => {
  it('source PASS + no break-glass -> pass', () => {
    assert.equal(decideSourceGate({ sourceResult: 'success', verdict: 'PASS', gateMode: 'enforce', breakGlassResult: 'skipped' }).outcome, 'pass');
  });
  it('eligible BLOCK + approved exact decision -> overridden-block (not "pass")', () => {
    const d = decideSourceGate(OVERRIDE);
    assert.equal(d.outcome, 'overridden-block');
    assert.equal(d.override, 'approved');
  });
  for (const [name, patch] of [
    ['eligible BLOCK + denied', { breakGlassResult: 'failure', breakGlassDecision: 'denied' }],
    ['eligible BLOCK + timeout', { breakGlassResult: 'failure', breakGlassDecision: 'timeout' }],
    ['eligible BLOCK + expired', { breakGlassResult: 'failure', breakGlassDecision: 'expired' }],
    ['eligible BLOCK + break-glass skipped', { breakGlassResult: 'skipped', breakGlassDecision: '', breakGlassDelivered: '', breakGlassGateDigest: '' }],
    ['hard BLOCK + fake approval', { breakGlassEligible: 'false', breakGlassDelegated: 'false' }],
    ['integrity BLOCK + fake approval', { integrityTrusted: 'false', breakGlassEligible: 'false' }],
    ['arbitrary source failure + break-glass success', { verdict: 'PASS' }],
    ['scanner crash + BLOCK + approval', { sastResult: 'failure' }],
    ['approval for a different gate', { breakGlassGateDigest: 'b'.repeat(64) }],
    ['log-only source failure + approval', { gateMode: 'log-only' }],
    ['source cancelled + approval', { sourceResult: 'cancelled' }]
  ]) {
    it(`${name} -> block`, () => {
      assert.equal(decideSourceGate({ ...OVERRIDE, ...patch }).outcome, 'block');
    });
  }

  // Mutation-style: every single required fact, removed or altered, must block.
  describe('every override fact is load-bearing', () => {
    const wrong = { sourceGateDigest: 'x', breakGlassGateDigest: 'x' };
    for (const key of Object.keys(OVERRIDE)) {
      for (const value of ['', undefined, 'TRUE', ' ', wrong[key] ?? 'unexpected']) {
        it(`${key}=${JSON.stringify(value)} blocks`, () => {
          const facts = { ...OVERRIDE, [key]: value };
          if (key === 'sourceResult' && value === undefined) delete facts.sourceResult;
          assert.equal(decideSourceGate(facts).outcome, 'block');
        });
      }
    }
    it('both digests empty never match each other into an override', () => {
      assert.equal(decideSourceGate({ ...OVERRIDE, sourceGateDigest: '', breakGlassGateDigest: '' }).outcome, 'block');
    });
  });

  describe('executed through the example caller\'s real security-gate step', () => {
    const script = stepScript(read('examples/container-ecr/security.yml'), 'Require every security control that gates this pull request');
    const env = (source, image) => ({
      SSD_TOOLKIT: join(FRAMEWORK, 'security'),
      EVENT: 'pull_request',
      SOURCE_RESULT: source.sourceResult,
      SOURCE_VERDICT: source.verdict,
      MODE: source.gateMode,
      SOURCE_GATE_MODE: source.gateMode,
      SOURCE_INTEGRITY_TRUSTED: source.integrityTrusted,
      SOURCE_BREAK_GLASS_ELIGIBLE: source.breakGlassEligible,
      SOURCE_BREAK_GLASS_DELEGATED: source.breakGlassDelegated,
      SOURCE_SECRET_SCAN_RESULT: source.secretScanResult,
      SOURCE_DEPENDENCY_SCAN_RESULT: source.dependencyScanResult,
      SOURCE_SAST_RESULT: source.sastResult,
      SOURCE_GATE_DIGEST: source.sourceGateDigest,
      BREAK_GLASS_RESULT: source.breakGlassResult,
      BREAK_GLASS_DECISION: source.breakGlassDecision,
      BREAK_GLASS_REQUEST_DELIVERED: source.breakGlassDelivered,
      BREAK_GLASS_GATE_DIGEST: source.breakGlassGateDigest,
      IMAGE_MODE: 'enforce',
      ...image
    });

    it('an approved eligible source BLOCK with a passing image -> green, reported as an overridden BLOCK', () => {
      const r = runScript(script, env(OVERRIDE, { IMAGE_RESULT: 'success', IMAGE_VERDICT: 'DEPLOY' }));
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /OVERRIDDEN BLOCK/);
      assert.match(r.out, /policy verdict remains BLOCK/);
      assert.equal(r.outputs.source_override, 'approved');
    });
    it('image BLOCK_DEPLOY cannot be overridden by a source break-glass approval', () => {
      const r = runScript(script, env(OVERRIDE, { IMAGE_RESULT: 'failure', IMAGE_VERDICT: 'BLOCK_DEPLOY' }));
      assert.equal(r.code, 1);
      assert.match(r.out, /image security did not pass/);
    });
    it('a denied source BLOCK -> red', () => {
      const r = runScript(script, env({ ...OVERRIDE, breakGlassResult: 'failure', breakGlassDecision: 'denied' }, { IMAGE_RESULT: 'success', IMAGE_VERDICT: 'DEPLOY' }));
      assert.equal(r.code, 1);
    });
    it('delegated but break-glass never ran -> red, and says no approval request was sent', () => {
      const r = runScript(script, env({ ...OVERRIDE, breakGlassResult: 'skipped', breakGlassDecision: '' }, { IMAGE_RESULT: 'success', IMAGE_VERDICT: 'DEPLOY' }));
      assert.equal(r.code, 1);
      assert.match(r.out, /No approval request was sent/);
      assert.match(r.out, /normal BLOCK alert was sent by the source workflow/);
    });
  });
});

// =================================================================================
describe('conformance: break-glass is observed, and an override must be proven', () => {
  const capabilities = resolveCapabilities({ artifact_type: 'library' });
  const scans = {
    'secret-scan': { status: 'success' },
    'dependency-scan': { status: 'success' },
    sast: { status: 'success' }
  };
  const sgBlock = { status: 'failure', verdict: 'BLOCK', gate_mode: 'enforce', integrity_trusted: 'true', break_glass_eligible: 'true', gate_digest: D };
  const sgPass = { status: 'success', verdict: 'PASS', gate_mode: 'enforce', integrity_trusted: 'true', break_glass_eligible: 'false', gate_digest: D };
  const bgApproved = { status: 'success', decision: 'approved', request_delivered: 'true', gate_digest: D, delegated: 'true' };
  const bgNotRun = { status: 'skipped', decision: '', request_delivered: '', gate_digest: '', delegated: 'false' };
  // Strict mode is passed EXPLICITLY, as _conformance.yml does for new callers.
  const build = (observed, breakGlassEnabled = true, strictBreakGlassEvidence = true) =>
    buildConformance({ capabilities, observed: { ...scans, ...observed }, breakGlassEnabled, strictBreakGlassEvidence });
  const legacy = (observed, breakGlassEnabled = true) => build(observed, breakGlassEnabled, false);
  const control = (report, id) => report.controls.find((c) => c.id === id);

  it('disabled break-glass is N/A with the existing reason', () => {
    const c = control(build({ 'source-gate': { status: 'success', verdict: 'PASS' } }, false), 'break-glass');
    assert.equal(c.status, 'not-applicable');
    assert.match(c.reason, /break_glass_enabled=false/);
  });

  it('enabled but unobserved fails', () => {
    assert.equal(control(build({ 'source-gate': { status: 'success', verdict: 'PASS' } }), 'break-glass').status, 'failed');
  });

  it('an approved override is represented explicitly on both controls', () => {
    const report = build({ 'source-gate': { ...sgBlock, override: 'approved' }, 'break-glass': bgApproved });
    const sg = control(report, 'source-gate');
    assert.equal(sg.status, 'applied');
    assert.equal(sg.observedStatus, 'failure', 'the raw job result is preserved, not rewritten');
    assert.equal(sg.verdict, 'BLOCK');
    assert.equal(sg.override, 'approved');
    assert.match(sg.detail, /policy verdict BLOCK; override: verified approved break-glass for gate sha256 c{64}/);
    const bg = control(report, 'break-glass');
    assert.equal(bg.status, 'applied');
    assert.equal(bg.exercised, true);
    assert.equal(bg.decision, 'approved');
  });

  for (const decision of ['denied', 'timeout', 'expired']) {
    it(`${decision} does not become applied, and the source BLOCK stays failed`, () => {
      const report = build({ 'source-gate': sgBlock, 'break-glass': { ...bgApproved, status: 'failure', decision } });
      assert.equal(control(report, 'break-glass').status, 'failed');
      assert.match(control(report, 'break-glass').reason, new RegExp(`decision was ${decision}`));
      assert.equal(control(report, 'source-gate').status, 'failed');
    });
  }

  it('a fabricated source override without break-glass evidence fails', () => {
    const report = build({ 'source-gate': { ...sgBlock, override: 'approved' } });
    assert.equal(control(report, 'source-gate').status, 'failed');
    assert.match(control(report, 'source-gate').reason, /no break-glass observation/);
  });

  for (const [name, bg, sg] of [
    ['a denied break-glass', { ...bgApproved, status: 'failure', decision: 'denied' }, {}],
    ['a successful job whose decision is not approved', { ...bgApproved, decision: 'timeout' }, {}],
    ['a different gate digest', { ...bgApproved, gate_digest: 'b'.repeat(64) }, {}],
    ['an undelivered request', { ...bgApproved, request_delivered: 'false' }, {}],
    ['an integrity BLOCK', bgApproved, { integrity_trusted: 'false' }],
    ['a hard (ineligible) BLOCK', bgApproved, { break_glass_eligible: 'false' }]
  ]) {
    it(`a claimed override with ${name} fails`, () => {
      const report = build({ 'source-gate': { ...sgBlock, ...sg, override: 'approved' }, 'break-glass': bg });
      assert.equal(control(report, 'source-gate').status, 'failed');
    });
  }

  it('a claimed override when break-glass is disabled fails', () => {
    const report = build({ 'source-gate': { ...sgBlock, override: 'approved' }, 'break-glass': bgApproved }, false);
    assert.equal(control(report, 'source-gate').status, 'failed');
  });

  it('no eligible BLOCK -> applied but NOT exercised, stated as such', () => {
    const report = build({ 'source-gate': sgPass, 'break-glass': bgNotRun });
    const bg = control(report, 'break-glass');
    assert.equal(bg.status, 'applied');
    assert.equal(bg.exercised, false);
    assert.match(bg.detail, /not exercised/);
  });

  it('an eligible enforced BLOCK that was not delegated fails', () => {
    const report = build({ 'source-gate': sgBlock, 'break-glass': bgNotRun });
    assert.equal(control(report, 'break-glass').status, 'failed');
  });

  it('delegated but the break-glass job never ran fails', () => {
    const report = build({ 'source-gate': sgBlock, 'break-glass': { ...bgNotRun, delegated: 'true' } });
    assert.equal(control(report, 'break-glass').status, 'failed');
  });

  it('a success result with inconsistent evidence fails closed', () => {
    const report = build({ 'source-gate': sgBlock, 'break-glass': { ...bgApproved, decision: 'denied' } });
    assert.equal(control(report, 'break-glass').status, 'failed');
  });

  // ---- v1 compatibility: the legacy (default) mode ------------------------------
  describe('legacy mode (strict_break_glass_evidence=false, the v1 default)', () => {
    it('v1-style {"status":"pass"} keeps its previous result, with a loud deprecation warning', () => {
      const report = legacy({ 'source-gate': { status: 'success', verdict: 'PASS' }, 'break-glass': { status: 'pass' } });
      const c = control(report, 'break-glass');
      assert.equal(c.status, 'applied');
      assert.equal(report.breakGlassEvidence, 'legacy');
      assert.ok(report.warnings.some((w) => /DEPRECATED \(v1 legacy break-glass evidence\)/.test(w) && /proves NOTHING about request delivery/.test(w)));
      assert.ok(!/verified|approved/.test(c.detail ?? ''), 'status-only evidence is never described as verified');
      assert.equal(c.exercised, undefined);
      assert.equal(c.decision, undefined);
    });

    it('matches the pre-refactor engine exactly for status-only break-glass entries', () => {
      // Pre-refactor, break-glass was judged by explainObserved on status alone.
      for (const status of ['pass', 'success', 'failure', 'skipped', 'cancelled', '', 'weird']) {
        const c = control(legacy({ 'source-gate': { status: 'success', verdict: 'PASS' }, 'break-glass': { status } }), 'break-glass');
        const expected = explainObserved(CONTROLS.find((x) => x.id === 'break-glass'), { status });
        assert.equal(c.status, expected.passed ? 'applied' : 'failed', status);
        assert.equal(c.reason, expected.passed ? undefined : expected.reason, status);
      }
    });

    it('legacy mode is chosen by the caller, not inferred: structured fields do not switch it on', () => {
      // A structured-looking entry under legacy mode is still judged by status only.
      const report = legacy({ 'source-gate': sgBlock, 'break-glass': { ...bgApproved, status: 'pass', decision: 'denied' } });
      assert.equal(control(report, 'break-glass').status, 'applied');
      assert.equal(report.breakGlassEvidence, 'legacy');
    });

    it('does NOT gain override semantics: a failed source gate stays failed whatever it claims', () => {
      const report = legacy({ 'source-gate': { ...sgBlock, override: 'approved' }, 'break-glass': bgApproved });
      const sg = control(report, 'source-gate');
      assert.equal(sg.status, 'failed');
      assert.equal(sg.override, undefined);
      assert.ok(report.warnings.some((w) => /override 'approved', which is IGNORED in legacy/.test(w)));
    });

    it('omitting the mode entirely is legacy (callers that do not pass the new input stay compatible)', () => {
      const report = buildConformance({
        capabilities,
        observed: { ...scans, 'source-gate': { status: 'success', verdict: 'PASS' }, 'break-glass': { status: 'pass' } },
        breakGlassEnabled: true
      });
      assert.equal(report.breakGlassEvidence, 'legacy');
      assert.equal(control(report, 'break-glass').status, 'applied');
    });

    it('disabled break-glass is N/A in both modes', () => {
      for (const mode of [true, false]) {
        assert.equal(control(build({ 'source-gate': sgPass }, false, mode), 'break-glass').status, 'not-applicable');
      }
    });
  });

  describe('the mode is explicit at the reusable-workflow boundary', () => {
    const wf = read('.github/workflows/_conformance.yml');
    it('_conformance.yml declares strict_break_glass_evidence: boolean, default false', () => {
      assert.match(wf, /\n {6}strict_break_glass_evidence:\n[\s\S]*?type: boolean\n {8}default: false\n/);
    });

    it('the input reaches the engine: env wired from the input, flag passed on the command line', () => {
      const at = wf.indexOf('- name: Build the conformance report');
      const step = wf.slice(at, wf.indexOf('\n      - name:', at + 1));
      assert.match(step, /\n {10}STRICT_BREAK_GLASS_EVIDENCE: \$\{\{ inputs\.strict_break_glass_evidence \}\}\n/);
      assert.match(step, /--strict-break-glass-evidence "\$\{STRICT_BREAK_GLASS_EVIDENCE:-false\}"/);
    });

    const script = stepScript(wf, 'Build the conformance report');
    const runReport = (strict) => {
      const dir = mkdtempSync(join(WORK, 'conf-'));
      writeFileSync(join(dir, 'summary'), '');
      const env = {
        SSD_TOOLKIT: join(FRAMEWORK, 'security'),
        GITHUB_STEP_SUMMARY: join(dir, 'summary'),
        GITHUB_REPOSITORY: 'acme/app',
        ARTIFACT_TYPE: 'library', REGISTRY: 'none', DEPLOY_TARGET: 'none', PHASE: 'pr',
        BREAK_GLASS_ENABLED: 'true',
        EXEMPTIONS_PATH: join(dir, 'none.json'),
        OBSERVED: JSON.stringify({ ...scans, 'source-gate': { status: 'success', verdict: 'PASS' }, 'break-glass': { status: 'pass' } }),
        ...(strict === undefined ? {} : { STRICT_BREAK_GLASS_EVIDENCE: strict })
      };
      const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
        cwd: dir, env: { PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_OUTPUT: join(dir, 'out'), ...env }, encoding: 'utf8'
      });
      return { code: r.status, out: readFileSync(join(dir, 'out'), 'utf8'), report: JSON.parse(readFileSync(join(dir, 'reports/conformance.json'), 'utf8')) };
    };

    it('strict=true through the real workflow step: status-only break-glass is a failed control', () => {
      const r = runReport('true');
      assert.equal(r.code, 0, 'a failed control is data, not a step crash');
      assert.match(r.out, /failed=1\n/);
      assert.equal(r.report.breakGlassEvidence, 'strict');
    });
    it('strict=false through the real workflow step: v1 behaviour, zero failures', () => {
      const r = runReport('false');
      assert.match(r.out, /failed=0\n/);
      assert.equal(r.report.breakGlassEvidence, 'legacy');
    });
    it('an unset input behaves as the v1 default', () => {
      assert.match(runReport(undefined).out, /failed=0\n/);
    });
    it('an unrecognized mode value fails closed instead of choosing one', () => {
      const r = spawnSync(process.execPath, [join(FRAMEWORK, 'security/scripts/conformance.mjs'), '--strict-break-glass-evidence', 'yes', '--observed', '{}', '--output', join(WORK, 'x.json')], { encoding: 'utf8' });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /must be true or false/);
    });
  });

  describe('every new caller selects strict mode explicitly', () => {
    for (const path of ['examples/source-only/security.yml', 'examples/python-self-managed/security.yml', 'examples/container-ecr/security.yml', 'examples/container-ecr/deploy.yml']) {
      it(`${path}`, () => {
        const job = jobBlock(read(path), 'conformance');
        assert.match(job, /_conformance\.yml@/);
        assert.match(job, /\n {6}strict_break_glass_evidence: true\n/);
      });
    }
    it('every example that calls _source-scan.yml is a strict caller', () => {
      for (const path of ['examples/source-only/security.yml', 'examples/python-self-managed/security.yml', 'examples/container-ecr/security.yml', 'examples/container-ecr/deploy.yml']) {
        const text = read(path);
        if (/_source-scan\.yml@/.test(text)) assert.match(text, /strict_break_glass_evidence: true/, path);
      }
    });
    it('no example is left on the deprecated legacy break-glass evidence path', () => {
      for (const path of ['examples/source-only/security.yml', 'examples/python-self-managed/security.yml', 'examples/container-ecr/security.yml', 'examples/container-ecr/deploy.yml']) {
        const text = read(path);
        assert.ok(!/COMPATIBILITY path/.test(text), `${path} must not advertise the legacy path`);
        assert.match(text, /\n {6}strict_break_glass_evidence: true\n/, path);
      }
    });
  });

  describe('strict mode: enabled break-glass accepts ONLY structured evidence', () => {
    for (const [name, entry] of [
      ['fabricated {"status":"pass"}', { status: 'pass' }],
      ['fabricated {"status":"success"}', { status: 'success' }],
      ['status + decision only', { status: 'success', decision: 'approved' }],
      ['empty object', {}]
    ]) {
      it(`${name} fails`, () => {
        for (const sg of [sgPass, sgBlock]) {
          const c = control(build({ 'source-gate': sg, 'break-glass': entry }), 'break-glass');
          assert.equal(c.status, 'failed');
          assert.match(c.reason, /structured observed evidence is required/);
        }
      });
    }

    it('a status-only entry cannot prove an override either', () => {
      const report = build({ 'source-gate': { ...sgBlock, override: 'approved' }, 'break-glass': { status: 'pass' } });
      assert.equal(control(report, 'source-gate').status, 'failed');
      assert.equal(control(report, 'break-glass').status, 'failed');
    });

    it('evidence without an observed source-gate result fails', () => {
      const scansOnly = buildConformance({ capabilities, observed: { ...scans, 'break-glass': bgNotRun }, breakGlassEnabled: true, strictBreakGlassEvidence: true });
      assert.match(control(scansOnly, 'break-glass').reason, /no source-gate result was observed/);
      const empty = build({ 'source-gate': { ...sgPass, status: '' }, 'break-glass': bgNotRun });
      assert.equal(control(empty, 'break-glass').status, 'failed');
    });

    it('other controls keep their v1 status-based handling', () => {
      const report = build({ 'source-gate': { status: 'success', verdict: 'PASS' }, 'break-glass': bgNotRun });
      assert.equal(control(report, 'secret-scan').status, 'applied');
      assert.equal(control(report, 'source-gate').status, 'applied');
    });

    // Mutation-style: removing any one required field from a passing record fails.
    describe('each required field is load-bearing', () => {
      const passing = [
        ['approved', sgBlock, bgApproved],
        ['not exercised', sgPass, bgNotRun]
      ];
      for (const [shape, sg, bg] of passing) {
        it(`${shape}: the complete record passes`, () => {
          assert.equal(control(build({ 'source-gate': sg, 'break-glass': bg }), 'break-glass').status, 'applied');
        });
        for (const field of Object.keys(bg)) {
          it(`${shape}: removing break-glass.${field} fails`, () => {
            const { [field]: _removed, ...rest } = bg;
            assert.equal(control(build({ 'source-gate': sg, 'break-glass': rest }), 'break-glass').status, 'failed');
          });
        }
      }
      // For the approved shape, every value must also be exact.
      for (const [field, value] of [
        ['status', 'failure'], ['decision', 'denied'], ['decision', ''], ['request_delivered', 'false'],
        ['request_delivered', ''], ['gate_digest', ''], ['gate_digest', 'b'.repeat(64)], ['gate_digest', 'xyz'],
        ['delegated', 'false'], ['delegated', '']
      ]) {
        it(`approved: break-glass.${field}=${JSON.stringify(value)} fails`, () => {
          assert.equal(control(build({ 'source-gate': sgBlock, 'break-glass': { ...bgApproved, [field]: value } }), 'break-glass').status, 'failed');
        });
      }
      it('approved: a digest that differs only in case fails (exact comparison, like final-gate.mjs)', () => {
        const report = build({ 'source-gate': sgBlock, 'break-glass': { ...bgApproved, gate_digest: D.toUpperCase() } });
        assert.equal(control(report, 'break-glass').status, 'failed');
      });
      for (const bad of ['', 'xyz', 'C'.repeat(64)]) {
        it(`approved: equal but invalid digests (${JSON.stringify(bad)}) on both sides fail`, () => {
          const report = build({ 'source-gate': { ...sgBlock, gate_digest: bad }, 'break-glass': { ...bgApproved, gate_digest: bad } });
          assert.equal(control(report, 'break-glass').status, 'failed');
        });
      }
      for (const field of ['verdict', 'integrity_trusted', 'break_glass_eligible', 'gate_digest', 'gate_mode']) {
        it(`approved: removing source-gate.${field} fails`, () => {
          const { [field]: _removed, ...rest } = sgBlock;
          assert.equal(control(build({ 'source-gate': rest, 'break-glass': bgApproved }), 'break-glass').status, 'failed');
        });
      }
      for (const [field, value] of [['verdict', 'PASS'], ['integrity_trusted', 'false'], ['break_glass_eligible', 'false'], ['gate_mode', 'log-only']]) {
        it(`approved: source-gate.${field}=${value} fails`, () => {
          assert.equal(control(build({ 'source-gate': { ...sgBlock, [field]: value }, 'break-glass': bgApproved }), 'break-glass').status, 'failed');
        });
      }
      // For the not-exercised shape, any sign of activity is inconsistent.
      for (const [field, value] of [
        ['status', 'success'], ['status', 'pass'], ['decision', 'approved'], ['request_delivered', 'true'], ['gate_digest', D]
      ]) {
        it(`not exercised: break-glass.${field}=${JSON.stringify(value)} fails`, () => {
          assert.equal(control(build({ 'source-gate': sgPass, 'break-glass': { ...bgNotRun, [field]: value } }), 'break-glass').status, 'failed');
        });
      }
      it('not exercised: an override claimed on the source gate fails', () => {
        for (const override of ['approved', 'in-job']) {
          const c = control(build({ 'source-gate': { ...sgPass, override }, 'break-glass': bgNotRun }), 'break-glass');
          assert.equal(c.status, 'failed', override);
        }
      });
    });

    for (const decision of ['denied', 'expired', 'timeout', 'error', 'refused']) {
      it(`delegated + ${decision} fails`, () => {
        const bg = { ...bgApproved, status: 'failure', decision, request_delivered: ['error', 'refused'].includes(decision) ? 'false' : 'true' };
        assert.equal(control(build({ 'source-gate': sgBlock, 'break-glass': bg }), 'break-glass').status, 'failed');
      });
    }
  });

  it('the example callers never hard-code the break-glass control as pass', () => {
    for (const path of ['examples/container-ecr/security.yml', 'examples/container-ecr/deploy.yml']) {
      assert.ok(!/"break-glass":\{"status":"pass"/.test(read(path)), path);
    }
  });

  // RELEASE BLOCKER RB-1 (docs/release-blockers.md), now RESOLVED: this guards
  // the fix. The delivery example must stay on the split architecture —
  // _source-scan.yml + _break-glass-lambda.yml + final-gate.mjs — with the
  // aggregate `security-gate` job as the authorization boundary.
  describe('RB-1: the delivery example is on the split break-glass architecture', () => {
    const raw = read('examples/container-ecr/deploy.yml');
    // Assertions are made against the EXECUTABLE file: a comment that merely
    // mentions `id-token`, `synthetic` or `AWS` must not satisfy — or defeat —
    // a boundary check.
    const source = executable(raw);
    const job = (id) => {
      const block = jobBlock(source, id);
      assert.ok(block, `examples/container-ecr/deploy.yml must define a '${id}' job`);
      return block;
    };
    // An observed-evidence entry, whose values contain `${{ ... }}` and so
    // cannot be matched with a naive [^}]* run.
    const entryOf = (text, control) =>
      new RegExp(`"${control}":(\\{(?:[^{}]|\\$\\{\\{[^}]*\\}\\})*\\})`).exec(text);

    it('source security is the OIDC-free _source-scan.yml, and holds no id-token', () => {
      const sourceJob = job('source-security');
      assert.match(sourceJob, /uses: IamRitz\/ssd-security-framework\/\.github\/workflows\/_source-scan\.yml@v1/);
      assert.ok(!/_source-security\.yml/.test(raw), 'the delivery example must not call the in-job OIDC path');
      assert.ok(!/id-token/.test(sourceJob), 'source-security must not be granted id-token');
      assert.match(sourceJob, /\n {6}break_glass_transport: lambda\n/);
      // Lambda configuration belongs to the break-glass job, never to the
      // credential-free scan workflow.
      assert.ok(!/break_glass_lambda_/.test(sourceJob), 'Lambda inputs must not be passed to _source-scan.yml');
    });

    it('a dedicated break-glass job exists, and it alone holds id-token in the source path', () => {
      const bg = job('break-glass');
      assert.match(bg, /uses: IamRitz\/ssd-security-framework\/\.github\/workflows\/_break-glass-lambda\.yml@v1/);
      assert.match(bg, /\n {6}id-token: write\n/);
      assert.match(bg, /if: \$\{\{ always\(\) && needs\.source-security\.outputs\.break_glass_delegated == 'true' \}\}/);
      // Same gate digest as the source gate that was evaluated.
      assert.match(bg, /expected_gate_digest: \$\{\{ needs\.source-security\.outputs\.gate_digest \}\}/);
      assert.match(bg, /gate_mode: \$\{\{ needs\.source-security\.outputs\.gate_mode \}\}/);
      // Production brokers only: a real deploy must never be routable to a test
      // broker.
      assert.match(bg, /lambda_function: \$\{\{ vars\.BREAK_GLASS_LAMBDA_FUNCTION \}\}/);
      assert.match(bg, /lambda_role_arn: \$\{\{ vars\.BREAK_GLASS_LAMBDA_ROLE_ARN \}\}/);
      assert.ok(!/synthetic/i.test(source), 'no synthetic broker may be wired into the production delivery example');
    });

    it('only break-glass, ecr-collect and deploy hold id-token at all', () => {
      const allowed = new Set(['break-glass', 'ecr-collect', 'deploy']);
      for (const id of jobIds(source)) {
        const holds = /\n {6}id-token: write\n/.test(job(id));
        assert.equal(holds, allowed.has(id), `${id} id-token: write should be ${allowed.has(id)}`);
      }
    });

    it('an aggregate security-gate job runs final-gate.mjs with every required fact', () => {
      const gate = job('security-gate');
      assert.match(gate, /\n {4}needs:\n {6}- source-security\n {6}- break-glass\n/);
      assert.match(gate, /if: \$\{\{ always\(\) \}\}/);
      assert.match(gate, /final-gate\.mjs/);
      assert.ok(!/id-token/.test(gate), 'the authorization boundary holds no cloud credential');
      assert.ok(!/aws-actions\/configure-aws-credentials/.test(gate));
      for (const [env, expression] of [
        ['SOURCE_RESULT', 'needs.source-security.result'],
        ['SOURCE_VERDICT', 'needs.source-security.outputs.verdict'],
        ['SOURCE_GATE_MODE', 'needs.source-security.outputs.gate_mode'],
        ['SOURCE_INTEGRITY_TRUSTED', 'needs.source-security.outputs.integrity_trusted'],
        ['SOURCE_BREAK_GLASS_ELIGIBLE', 'needs.source-security.outputs.break_glass_eligible'],
        ['SOURCE_BREAK_GLASS_DELEGATED', 'needs.source-security.outputs.break_glass_delegated'],
        ['SOURCE_SECRET_SCAN_RESULT', 'needs.source-security.outputs.secret_scan_result'],
        ['SOURCE_DEPENDENCY_SCAN_RESULT', 'needs.source-security.outputs.dependency_scan_result'],
        ['SOURCE_SAST_RESULT', 'needs.source-security.outputs.sast_result'],
        ['SOURCE_GATE_DIGEST', 'needs.source-security.outputs.gate_digest'],
        ['BREAK_GLASS_RESULT', 'needs.break-glass.result'],
        ['BREAK_GLASS_DECISION', 'needs.break-glass.outputs.decision_status'],
        ['BREAK_GLASS_REQUEST_DELIVERED', 'needs.break-glass.outputs.request_delivered'],
        ['BREAK_GLASS_GATE_DIGEST', 'needs.break-glass.outputs.gate_digest']
      ]) {
        assert.match(
          gate,
          new RegExp(`\\n {10}${env}: \\$\\{\\{ ${expression.replace(/[.]/g, '\\.')} \\}\\}\\n`),
          `security-gate must feed ${env} from ${expression}`
        );
      }
      // Every env name final-gate.mjs reads is actually supplied.
      for (const key of Object.keys(factsFromEnv({}))) void key;
      const supplied = Object.fromEntries([...gate.matchAll(/\n {10}([A-Z_]+): /g)].map((m) => [m[1], 'x']));
      for (const [fact, value] of Object.entries(factsFromEnv(supplied))) {
        assert.equal(value, 'x', `final-gate.mjs reads a fact ('${fact}') the security-gate job does not supply`);
      }
      // The outcome is exported for conformance.
      assert.match(gate, /source_outcome: \$\{\{ steps\.gate\.outputs\.source_outcome \}\}/);
      assert.match(gate, /source_override: \$\{\{ steps\.gate\.outputs\.source_override \}\}/);
    });

    it('the source gate is never bypassed with continue-on-error', () => {
      assert.ok(!/continue-on-error/.test(source));
    });

    it('every delivery job is authorized by security-gate, not by the raw source result', () => {
      for (const id of ['aws-configuration', 'ecr-collect']) {
        const block = job(id);
        assert.match(block, /needs\.security-gate\.result == 'success'/, `${id} must depend on the aggregate gate`);
        assert.match(block, /needs\.image-security\.result == 'success'/, `${id} must keep the independent image gate`);
        assert.ok(
          !/needs\.source-security\.result/.test(block),
          `${id} must not consume the raw source-security result: an approved eligible BLOCK is a failure there`
        );
        assert.ok(!/\n {6}- source-security\n/.test(block), `${id} must not need source-security directly`);
      }
      // ...and the rest of the chain hangs off those, unchanged.
      assert.match(job('artifact-gate'), /\n {4}needs: ecr-collect\n/);
      assert.match(job('deploy'), /\n {4}needs:\n {6}- artifact-gate\n {6}- ecr-collect\n/);
    });

    it('the delivery security chain is not weakened', () => {
      assert.match(job('container-build'), /no-cache: true/);
      assert.ok(!/aws|AWS/.test(job('container-build')), 'the build job stays credential-free');
      assert.match(job('ecr-collect'), /expected_image_id: \$\{\{ needs\.image-security\.outputs\.image_id \}\}/);
      assert.match(job('artifact-gate'), /expected_digest: \$\{\{ needs\.ecr-collect\.outputs\.image_digest \}\}/);
      assert.ok(!/id-token/.test(job('artifact-gate')));
      const deploy = job('deploy');
      assert.match(deploy, /role-to-assume: \$\{\{ vars\.AWS_DEPLOY_ROLE_ARN \}\}/);
      assert.match(deploy, /IMAGE_DIGEST: \$\{\{ needs\.ecr-collect\.outputs\.image_digest \}\}/);
      assert.ok(!/AWS_PUSH_SCAN_ROLE_ARN/.test(deploy), 'the deploy job must hold no registry credential');
    });

    it('conformance is strict and fed structured, observed break-glass evidence', () => {
      const conformance = job('conformance');
      assert.match(conformance, /\n {6}strict_break_glass_evidence: true\n/);
      assert.ok(!/"break-glass":\{"status":"pass"/.test(raw), 'deploy.yml hard-codes break-glass as passed');
      assert.ok(!/lambda transport configured for this repo/.test(raw), 'the fabricated break-glass evidence string must be gone');

      const entry = entryOf(conformance, 'break-glass');
      assert.ok(entry, 'deploy.yml must observe the break-glass control');
      for (const [field, expression] of [
        ['status', 'needs.break-glass.result'],
        ['decision', 'needs.break-glass.outputs.decision_status'],
        ['request_delivered', 'needs.break-glass.outputs.request_delivered'],
        ['gate_digest', 'needs.break-glass.outputs.gate_digest'],
        ['delegated', 'needs.source-security.outputs.break_glass_delegated']
      ]) {
        assert.match(
          entry[1],
          new RegExp(`"${field}":"\\$\\{\\{ ${expression.replace(/[.]/g, '\\.')} \\}\\}"`),
          `break-glass.${field} must be observed from ${expression}`
        );
      }

      const sg = entryOf(conformance, 'source-gate');
      assert.ok(sg, 'deploy.yml must observe the source-gate control');
      for (const field of ['status', 'verdict', 'gate_mode', 'integrity_trusted', 'break_glass_eligible', 'gate_digest', 'override']) {
        assert.match(sg[1], new RegExp(`"${field}":`), `source-gate is missing ${field}`);
      }
      // The override CLAIM comes from the aggregate gate's decision, never from
      // the source workflow and never inferred.
      assert.match(sg[1], /"override":"\$\{\{ needs\.security-gate\.outputs\.source_override \}\}"/);
      assert.match(conformance, /\n {6}- break-glass\n/);
      assert.match(conformance, /\n {6}- security-gate\n/);
      assert.match(conformance, /if: \$\{\{ always\(\) && github\.ref == 'refs\/heads\/main' \}\}/);
    });

    it('the observed JSON still parses once the expressions are substituted', () => {
      const observed = job('conformance').match(/observed: >-\n([\s\S]*?)\n(?:\S|$)/)[1];
      const report = JSON.parse(observed.replace(/\$\{\{[^}]+\}\}/g, 'success').replace(/\n\s*/g, ''));
      assert.deepEqual(Object.keys(report).sort(), [
        'artifact-gate', 'break-glass', 'dependency-scan', 'gated-deploy', 'image-scan-prepush',
        'registry-scan-collect', 'sast', 'secret-scan', 'source-gate'
      ]);
    });
  });

  it('RB-1 is recorded as resolved, not silently dropped', () => {
    assert.match(
      read('docs/release-blockers.md'),
      /## RB-1 — `examples\/container-ecr\/deploy\.yml` hard-codes break-glass as passed\n\n\*\*Status:\*\* resolved/
    );
  });

});

// =================================================================================
describe('developer notification handoff', () => {
  const base = { verdict: 'BLOCK', eligible: true, mode: 'enforce', enabled: true };

  it('eligible + delegated still emits the ordinary BLOCK notification (delegation is not delivery)', () => {
    const state = deriveBreakGlassState({ ...base, delegated: true });
    assert.equal(state.decision, 'delegated');
    assert.deepEqual(route({ verdict: 'BLOCK', breakGlass: state }), { slack: true, slackReason: 'blocking-verdict', prComment: true, summary: true });
  });

  describe('end to end through the source notifier (notify.mjs dispatch)', () => {
    const slackPosts = async (env, g) => {
      const posts = [];
      const fetchImpl = async (url) => {
        posts.push(String(url));
        return { ok: true, status: 200, json: async () => ({}) };
      };
      const state = await breakGlassStateFromEnv(env, { gate: g, mode: 'enforce' });
      const performed = await dispatch({
        gate: g,
        mode: 'enforce',
        breakGlass: state,
        slackUrl: 'https://hooks.slack.test/T/B/X',
        fetchImpl,
        appendImpl: async () => {},
        writeImpl: async () => {},
        summaryPath: join(WORK, 'summary.md'),
        logger: { log() {}, error() {} }
      });
      return { performed, posts: posts.filter((u) => u.startsWith('https://hooks.slack.test')) };
    };

    it('delegated eligible BLOCK: Slack is posted by the source workflow', async () => {
      const g = await G.sast();
      const { performed, posts } = await slackPosts({ BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_DELEGATED: 'true' }, g);
      assert.equal(performed.slack, true);
      assert.equal(posts.length, 1);
      assert.equal(performed.breakGlass.decision, 'delegated');
    });

    it('a caller that skips the break-glass job cannot remove it: the source alert is independent of that job', async () => {
      // The source notifier runs before, and without any input from, the
      // caller's break-glass job; only an in-job DELIVERED request suppresses.
      const g = await G.sast();
      for (const env of [
        { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_DELEGATED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'skipped', BREAK_GLASS_REQUEST_OUTCOME: 'skipped', BREAK_GLASS_POLL_OUTCOME: 'skipped' },
        { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_DELEGATED: 'true', BREAK_GLASS_REQUEST_PATH: join(WORK, 'none.json') }
      ]) {
        assert.equal((await slackPosts(env, g)).posts.length, 1);
      }
      const twin = read('.github/workflows/_source-scan.yml');
      const notifyStep = twin.slice(twin.indexOf('- name: Post developer-readable findings'));
      assert.ok(!/needs\.break-glass|break-glass-lambda|decision_status|request_delivered/.test(notifyStep.slice(0, notifyStep.indexOf('\n      - name:'))), 'the source notifier reads no state from the caller\'s break-glass job');
    });

    it('eligibility alone cannot suppress Slack', async () => {
      const g = await G.sast();
      for (const env of [{}, { BREAK_GLASS_ENABLED: 'true' }, { BREAK_GLASS_ENABLED: 'false' }, { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_DELEGATED: 'false' }]) {
        assert.equal((await slackPosts(env, g)).posts.length, 1, JSON.stringify(env));
      }
    });

    it('a break-glass request failure cannot cause notification loss', async () => {
      const g = await G.sast();
      for (const env of [
        { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'failure' },
        { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'cancelled' },
        { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'failure', BREAK_GLASS_REQUEST_OUTCOME: 'skipped' }
      ]) {
        assert.equal((await slackPosts(env, g)).posts.length, 1, JSON.stringify(env));
      }
    });

    it('only an actually delivered request suppresses the plain alert', async () => {
      const g = await G.sast();
      const { posts } = await slackPosts(
        { BREAK_GLASS_ENABLED: 'true', BREAK_GLASS_CHECK_OUTCOME: 'success', BREAK_GLASS_REQUEST_OUTCOME: 'success', BREAK_GLASS_POLL_OUTCOME: 'failure' },
        g
      );
      assert.equal(posts.length, 0);
    });
  });

  it('eligibility and enabled alone never suppress Slack', () => {
    const state = deriveBreakGlassState({ ...base, checkOutcome: 'skipped', requestOutcome: 'skipped' });
    assert.equal(route({ verdict: 'BLOCK', breakGlass: state }).slack, true);
  });

  it('an ineligible BLOCK is never delegated, even if told so', () => {
    const state = deriveBreakGlassState({ ...base, eligible: false, delegated: true });
    assert.equal(state.decision, 'not-eligible');
    assert.equal(route({ verdict: 'BLOCK', breakGlass: state }).slack, true);
  });

  it('log-only is unaffected by delegation', () => {
    const state = deriveBreakGlassState({ ...base, mode: 'log-only', delegated: true });
    assert.equal(route({ verdict: 'BLOCK', mode: 'log-only', breakGlass: state }).slackReason, 'log-only');
  });

  describe('inside the break-glass workflow (preflight = the eligibility step)', () => {
    for (const [name, outcomes, slack] of [
      ['preflight refused', { checkOutcome: 'failure', requestOutcome: 'skipped' }, true],
      ['request failed before delivery', { checkOutcome: 'success', requestOutcome: 'failure' }, true],
      ['delivered, then denied', { checkOutcome: 'success', requestOutcome: 'success', pollOutcome: 'failure', decision: { status: 'denied' } }, false],
      ['delivered, then approved', { checkOutcome: 'success', requestOutcome: 'success', pollOutcome: 'success' }, false]
    ]) {
      it(`${name}: plain BLOCK alert ${slack ? 'sent' : 'suppressed (request reached approvers)'}`, () => {
        const state = deriveBreakGlassState({ ...base, ...outcomes });
        assert.equal(route({ verdict: 'BLOCK', breakGlass: state }).slack, slack);
      });
    }
  });

  it('the source notifier always receives the Slack URL, unconditioned on delegation', () => {
    for (const file of ['.github/workflows/_source-scan.yml', '.github/workflows/_source-security.yml']) {
      const text = read(file);
      const at = text.indexOf('- name: Post developer-readable findings (Slack + PR comment + job summary)');
      const step = text.slice(at, text.indexOf('\n      - name:', at + 1));
      assert.match(step, /\n {10}SECURITY_NOTIFY_SLACK_URL: \$\{\{ inputs\.slack_notify_url \}\}\n/, file);
      assert.match(step, /\n\s+if: always\(\)\n/, `${file}: the notifier must run on every outcome`);
    }
  });

  it('the source workflow passes the explicit delegation output to its notifier', () => {
    const twin = read('.github/workflows/_source-scan.yml');
    assert.match(twin, /BREAK_GLASS_DELEGATED: \$\{\{ steps\.delegate\.outputs\.break_glass_delegated \}\}/);
    assert.ok(
      twin.indexOf('- name: Decide whether this BLOCK is delegated') < twin.indexOf('- name: Post developer-readable findings'),
      'delegation is decided before the notifier runs'
    );
  });
});
