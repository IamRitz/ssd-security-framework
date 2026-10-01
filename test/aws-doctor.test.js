// `ssd-onboard aws doctor` end to end through the CLI: human and JSON output,
// exit codes, terminal-control safety for AWS-controlled text, and the trust
// boundary between the repository commands and AWS.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { awsDoctor, exitCodeOf, outcomeOf } from '../onboarding/aws/doctor.mjs';
import { awsDoctorBlocks } from '../onboarding/aws/report.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { format, outputStyle } from '../onboarding/lib/output.mjs';
import { FRAMEWORK, capture, commitAll, config, makeRepo, write } from './support/onboarding-fixtures.mjs';
import { ACCOUNT, PROVIDER, accessDenied, fakeAws, ok, readyWorld } from './support/aws-fake.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ECR = 'container-ecr-framework-gated';
const ESC = '\x1b';
const RLO = String.fromCodePoint(0x202e);
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]/;
const SGR = /\x1b\[\d+m/g;

function consumer(t, profile = ECR, overrides = { delivery: { environment: 'production' } }) {
  const root = makeRepo(t, { 'src/app.py': 'x = 1\n', Dockerfile: 'FROM scratch\n' });
  write(root, '.ssd/onboarding.yml', serializeConfig(config(profile, overrides)));
  commitAll(root, 'config');
  return root;
}

async function cli(root, args, { world = readyWorld(), io = {} } = {}) {
  const c = capture();
  const f = fakeAws(world);
  const code = await main([...args, '--repo', root], { framework: FRAMEWORK, awsExec: f.exec, env: {}, ...c.io, ...io });
  return { code, out: c.text(), err: c.errors(), f };
}

describe('aws doctor: human output', () => {
  it('plain (non-TTY) output: target, sections, status words, result', async (t) => {
    const { code, out, err } = await cli(consumer(t), ['aws', 'doctor']);
    assert.equal(code, 0);
    assert.equal(err, '');
    assert.ok(!out.includes(ESC), 'no ANSI for an injected (non-TTY) writer');
    for (const expected of ['SSD AWS Doctor', 'Target', `Account     ${ACCOUNT}`, 'Identity', 'GitHub OIDC', 'ECR', 'IAM', 'SSM', 'Ownership', '✓ PASS          Caller account', '? NOT VERIFIED  Subject format', 'exists, not owned', 'READY WITH WARNINGS']) {
      assert.ok(out.includes(expected), expected);
    }
  });

  it('TTY output is colored through the Phase 1 formatter; words survive without color', async (t) => {
    const root = consumer(t);
    const colored = await cli(root, ['aws', 'doctor'], { io: { color: true } });
    const plain = await cli(root, ['aws', 'doctor']);
    assert.match(colored.out, SGR);
    assert.equal(colored.out.replace(SGR, ''), plain.out, 'color adds nothing but SGR');
  });

  it('NO_COLOR disables color on a terminal', async () => {
    const f = fakeAws(readyWorld());
    const report = await awsDoctor({ config: config(ECR, { delivery: { environment: 'production' } }), exec: f.exec, env: {} });
    assert.match(format(awsDoctorBlocks(report), outputStyle({ isTTY: true, columns: 100 }, {})), SGR);
    assert.doesNotMatch(format(awsDoctorBlocks(report), outputStyle({ isTTY: true, columns: 100 }, { NO_COLOR: '1' })), SGR);
  });

  it('AWS-controlled ANSI, CR and bidi text cannot control the terminal', async (t) => {
    const world = readyWorld();
    const hostile = `evil${ESC}[2J${ESC}]8;;https://evil.example\x07link\rOVERWRITE${RLO}txt`;
    world[`iam get-open-id-connect-provider --open-id-connect-provider-arn ${PROVIDER}`] = ok({ Url: 'token.actions.githubusercontent.com', ClientIDList: [hostile], ThumbprintList: [hostile] });
    world['iam get-role --role-name app-deploy'] = accessDenied('GetRole', `iam:GetRole ${ESC}[31mFAKE PASS${ESC}[0m\r`);
    world['cloudformation describe-stack-resources --physical-resource-id app-ecr-push-scan'] = ok({
      StackResources: [{ StackName: `stack${RLO}kcats`, StackId: 'sid', LogicalResourceId: `L${ESC}[1m`, PhysicalResourceId: 'app-ecr-push-scan', ResourceType: 'AWS::IAM::Role' }]
    });
    world['cloudformation describe-stacks --stack-name sid'] = ok({ Stacks: [{ StackName: `stack${RLO}kcats`, StackStatus: 'CREATE_COMPLETE', Tags: [{ Key: 'ssd:framework', Value: `x${ESC}[5m` }] }] });
    for (const io of [{}, { color: true }]) {
      const { out, err } = await cli(consumer(t), ['aws', 'doctor'], { world, io });
      const text = (out + err).replace(SGR, '');
      assert.doesNotMatch(text, CONTROL);
      assert.ok(text.includes('\\x1b[2J'), 'shown, not executed');
      assert.ok(text.includes('\\u202e'));
    }
    const json = await cli(consumer(t), ['aws', 'doctor', '--json'], { world });
    const doc = JSON.parse(json.out);
    assert.ok(doc.checks.find((c) => c.id === 'oidc.provider').findings.some((f) => f.message.includes(hostile)), 'JSON keeps AWS data as data');
  });

  it('credential values in AWS error text never reach the output', async (t) => {
    const world = readyWorld();
    world['iam get-role --role-name app-deploy'] = accessDenied('GetRole', 'iam:GetRole token=SESSIONTOKENVALUE-abcdef key AKIAIOSFODNN7EXAMPLE');
    const { out } = await cli(consumer(t), ['aws', 'doctor'], { world, io: { env: { AWS_SESSION_TOKEN: 'SESSIONTOKENVALUE-abcdef' } } });
    assert.ok(!out.includes('SESSIONTOKENVALUE-abcdef'));
    assert.ok(!out.includes('AKIAIOSFODNN7EXAMPLE'));
    assert.ok(out.includes('[REDACTED]'));
  });
});

describe('aws doctor --json', () => {
  it('one JSON document, versioned, independent of human text', async (t) => {
    const { code, out, err } = await cli(consumer(t), ['aws', 'doctor', '--json']);
    assert.equal(code, 0);
    assert.equal(err, '');
    const doc = JSON.parse(out);
    assert.equal(doc.schemaVersion, 1);
    assert.equal(doc.command, 'aws doctor');
    assert.equal(doc.outcome, 'READY_WITH_WARNINGS');
    assert.deepEqual(Object.keys(doc).sort(), ['awsCalls', 'checks', 'command', 'counts', 'outcome', 'schemaVersion', 'skipped', 'target']);
    assert.deepEqual(doc.target, { repository: 'acme/app', account: ACCOUNT, region: 'us-east-1', regionSource: 'config', caller: doc.target.caller });
    assert.equal(doc.awsCalls[0], 'sts get-caller-identity');
    for (const c of doc.checks) {
      assert.deepEqual(Object.keys(c).filter((k) => ['id', 'section', 'title', 'status', 'required', 'basis', 'observed', 'expected', 'findings', 'remediation'].includes(k)).length, 10, c.id);
      assert.ok(['PASS', 'WARN', 'FAIL', 'NOT VERIFIED'].includes(c.status));
    }
    assert.ok(!out.includes('✓'), 'no human formatting in the machine contract');
  });

  it('a run that cannot start is still one JSON document with a typed error', async (t) => {
    const world = { 'sts get-caller-identity': { stdout: '', stderr: 'Unable to locate credentials.', exitCode: 253 } };
    const { code, out } = await cli(consumer(t), ['aws', 'doctor', '--json'], { world });
    assert.equal(code, 1);
    const doc = JSON.parse(out);
    assert.equal(doc.outcome, 'ERROR');
    assert.equal(doc.error.kind, 'authentication');
  });

  it('a missing configuration is a typed configuration error, and AWS is not contacted', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    const { code, out, f } = await cli(root, ['aws', 'doctor', '--json']);
    assert.equal(code, 1);
    assert.equal(JSON.parse(out).error.kind, 'configuration');
    assert.deepEqual(f.calls, []);
  });
});

describe('aws doctor: exit codes', () => {
  it('0 ready (warnings allowed), 1 blocked, 1 not verified', async (t) => {
    const root = consumer(t);
    assert.equal((await cli(root, ['aws', 'doctor'])).code, 0);
    const blocked = readyWorld();
    blocked['sts get-caller-identity'] = ok({ Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:root`, UserId: ACCOUNT });
    const b = await cli(root, ['aws', 'doctor'], { world: blocked });
    assert.equal(b.code, 1);
    assert.match(b.out, /BLOCKED/);
    const unverified = readyWorld();
    unverified['ec2 describe-instances --instance-ids i-0123456789abcdef0'] = accessDenied('DescribeInstances', 'ec2:DescribeInstances');
    const u = await cli(root, ['aws', 'doctor'], { world: unverified });
    assert.equal(u.code, 1);
    assert.match(u.out, /NOT VERIFIED  /);
  });

  it('2 for usage errors — and no access-key option exists', async (t) => {
    const root = consumer(t);
    for (const args of [['aws'], ['aws', 'bogus'], ['aws', 'doctor', 'extra'], ['aws', 'doctor', '--region', 'Mars-1'], ['aws', 'doctor', '--access-key-id', 'AKIAIOSFODNN7EXAMPLE'], ['aws', 'doctor', '--profile', 'x'], ['aws', 'doctor', '--bogus']]) {
      const result = await cli(root, args);
      assert.equal(result.code, 2, args.join(' '));
      assert.deepEqual(result.f.calls, [], `${args.join(' ')} contacts nothing`);
    }
    assert.equal((await cli(root, ['aws', '--help'])).code, 0);
  });

  it('1 for a configuration aws doctor cannot check (source-only), with no AWS call', async (t) => {
    const { code, err, f } = await cli(consumer(t, 'source-only', {}), ['aws', 'doctor']);
    assert.equal(code, 1);
    assert.match(err, /container-ecr-framework-gated/);
    assert.deepEqual(f.calls, []);
  });

  it('apply and verify are not implemented: exit 2, nothing contacted', async (t) => {
    const root = consumer(t);
    for (const sub of ['apply', 'verify']) {
      const result = await cli(root, ['aws', sub]);
      assert.equal(result.code, 2);
      assert.match(result.err, /not implemented/);
      assert.deepEqual(result.f.calls, []);
    }
  });
});

describe('aws doctor: required vs advisory NOT VERIFIED', () => {
  const c = (status, required) => ({ status, required });
  // The only checks that may be advisory; every other check is a required prerequisite.
  const ADVISORY = new Set(['oidc.subject-format', 'ecr.tag-immutability']);
  const assertNoWeakening = (report, managed = new Set()) => {
    for (const check of report.checks) {
      if (check.id.startsWith('ownership.')) {
        assert.equal(check.required, managed.has(check.id), `${check.id}: required only in managed mode`);
      } else {
        assert.equal(check.required, !ADVISORY.has(check.id), `${check.id} must be ${ADVISORY.has(check.id) ? 'advisory' : 'required'}`);
      }
    }
  };

  it('the outcome contract, decided by `required` alone', () => {
    assert.equal(outcomeOf([c('PASS', true), c('NOT VERIFIED', true)]), 'NOT_VERIFIED');
    assert.equal(outcomeOf([c('PASS', true), c('NOT VERIFIED', false)]), 'READY_WITH_WARNINGS');
    assert.equal(outcomeOf([c('NOT VERIFIED', false), c('NOT VERIFIED', true)]), 'NOT_VERIFIED');
    assert.equal(outcomeOf([c('NOT VERIFIED', true), c('FAIL', false)]), 'BLOCKED');
    assert.equal(outcomeOf([c('WARN', true), c('PASS', true)]), 'READY_WITH_WARNINGS');
    assert.equal(outcomeOf([c('PASS', true), c('PASS', false)]), 'READY');
    assert.equal(exitCodeOf({ outcome: 'NOT_VERIFIED' }), 1);
    assert.equal(exitCodeOf({ outcome: 'READY_WITH_WARNINGS' }), 0);
  });

  it('an ADVISORY NOT VERIFIED only: READY WITH WARNINGS, exit 0, labelled (advisory)', async (t) => {
    const root = consumer(t);
    const json = await cli(root, ['aws', 'doctor', '--json']);
    const doc = JSON.parse(json.out);
    assert.equal(json.code, 0);
    assert.equal(doc.outcome, 'READY_WITH_WARNINGS');
    assert.deepEqual(doc.checks.filter((x) => x.status === 'NOT VERIFIED').map((x) => [x.id, x.required]), [['oidc.subject-format', false]]);
    assertNoWeakening(doc);
    const human = await cli(root, ['aws', 'doctor']);
    assert.ok(human.out.includes('? NOT VERIFIED  Subject format (advisory)'));
    assert.ok(human.out.includes('1 NOT VERIFIED (0 required, 1 advisory)'));
    assert.match(human.out, /READY WITH WARNINGS/);
  });

  it('a REQUIRED NOT VERIFIED: overall NOT VERIFIED, exit 1, never labelled advisory', async (t) => {
    const world = readyWorld();
    world['ec2 describe-instances --instance-ids i-0123456789abcdef0'] = accessDenied('DescribeInstances', 'ec2:DescribeInstances');
    const root = consumer(t);
    const json = await cli(root, ['aws', 'doctor', '--json'], { world });
    const doc = JSON.parse(json.out);
    assert.equal(json.code, 1);
    assert.equal(doc.outcome, 'NOT_VERIFIED');
    const instance = doc.checks.find((x) => x.id === 'ssm.instance');
    assert.deepEqual([instance.status, instance.required], ['NOT VERIFIED', true]);
    assertNoWeakening(doc);
    const human = await cli(root, ['aws', 'doctor'], { world });
    assert.equal(human.code, 1);
    assert.ok(human.out.includes('? NOT VERIFIED  Instance\n'), 'a required check carries no advisory label');
    assert.ok(!/Instance \(advisory\)/.test(human.out));
    assert.match(human.out, /\? NOT VERIFIED {2}0 FAIL/, 'the overall outcome word is NOT VERIFIED');
  });

  it('ownership NOT VERIFIED is advisory for `existing`, required for `managed`', async (t) => {
    const world = readyWorld();
    world['cloudformation describe-stack-resources --physical-resource-id app-deploy'] = accessDenied('DescribeStackResources', 'cloudformation:DescribeStackResources');
    const existing = await cli(consumer(t), ['aws', 'doctor', '--json'], { world });
    assert.equal(existing.code, 0);
    assert.equal(JSON.parse(existing.out).outcome, 'READY_WITH_WARNINGS');
    assertNoWeakening(JSON.parse(existing.out));
    const managed = await cli(consumer(t, ECR, { delivery: { environment: 'production', roles: { deployOwnership: 'managed' } } }), ['aws', 'doctor', '--json'], { world });
    assert.equal(managed.code, 1);
    assert.equal(JSON.parse(managed.out).outcome, 'NOT_VERIFIED');
    assertNoWeakening(JSON.parse(managed.out), new Set(['ownership.deploy-role']));
  });
});

describe('trust boundary', () => {
  const read = (path) => readFileSync(join(ROOT, path), 'utf8');
  const importsOf = (path) => [...read(path).matchAll(/^\s*(?:import|export)\s[^;]*?from\s+'([^']+)';/gms)].map((m) => m[1]);
  const walk = (dir) => readdirSync(join(ROOT, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : e.name.endsWith('.mjs') ? [join(dir, e.name)] : []));

  it('no repository command can reach the AWS executor: the static module graph of cli.mjs excludes onboarding/aws', () => {
    const seen = new Set();
    const visit = (path) => {
      if (seen.has(path)) {
        return;
      }
      seen.add(path);
      for (const specifier of importsOf(path)) {
        if (specifier.startsWith('.')) {
          visit(join(dirname(path), specifier));
        }
      }
    };
    visit('onboarding/cli.mjs');
    assert.ok(seen.size > 10);
    assert.deepEqual([...seen].filter((p) => p.startsWith(join('onboarding', 'aws'))), []);
    assert.equal((read('onboarding/cli.mjs').match(/import\('\.\/aws\/cli\.mjs'\)/g) ?? []).length, 1, 'one dynamic import, in the aws branch');
  });

  it('only aws-cli.mjs runs a process; only plan/record.mjs writes files (the plan directory); nothing calls gh', () => {
    // The ONE writer under onboarding/aws: the `aws plan` record, confined to
    // .ssd/aws-plans/ through safe-path (test/aws-plan.test.js).
    const WRITER = join('onboarding', 'aws', 'plan', 'record.mjs');
    for (const file of walk('onboarding/aws')) {
      const imports = importsOf(file);
      if (!file.endsWith('aws-cli.mjs')) {
        assert.ok(!imports.includes('node:child_process'), `${file} runs a process`);
      }
      const forbidden = file === WRITER
        ? ['../../lib/files.mjs', '../../lib/baseline.mjs', '../../lib/render.mjs']
        : ['node:fs', 'node:fs/promises', '../lib/files.mjs', '../lib/safe-path.mjs', '../../lib/safe-path.mjs', '../lib/baseline.mjs', '../lib/render.mjs'];
      for (const specifier of forbidden) {
        assert.ok(!imports.includes(specifier), `${file} imports ${specifier}`);
      }
      assert.doesNotMatch(read(file), /['"]gh['"]/, `${file} mentions the gh executable`);
    }
    assert.doesNotMatch(read(WRITER), /\b(?:rm|unlink|rename|safeRemove|writeFile)\s*\(/, 'the plan record never removes, renames or truncating-writes');
    // doctor's module graph never reaches the planner or its writer.
    const seen = new Set();
    const visit = (path) => {
      if (seen.has(path)) return;
      seen.add(path);
      importsOf(path).filter((s) => s.startsWith('.')).forEach((s) => visit(join(dirname(path), s)));
    };
    visit(join('onboarding', 'aws', 'doctor.mjs'));
    for (const path of seen) {
      assert.ok(!path.startsWith(join('onboarding', 'aws', 'plan')), `doctor reaches ${path}`);
      assert.ok(!path.includes('safe-path'), `doctor reaches ${path}`);
    }
    assert.match(read('onboarding/aws/aws-cli.mjs'), /execFile\(\s*'aws',/);
    assert.match(read('onboarding/aws/aws-cli.mjs'), /shell: false/);
  });

  it('repository commands never invoke an injected AWS executor', async (t) => {
    const root = consumer(t);
    const exec = () => assert.fail('a repository command reached the AWS executor');
    for (const args of [['inspect'], ['validate'], ['doctor'], ['doctor', '--json'], ['render', '--check'], ['baseline', 'status']]) {
      const c = capture();
      await main([...args, '--repo', root], { framework: FRAMEWORK, awsExec: exec, ...c.io });
    }
  });

  it('aws doctor writes nothing to the repository', async (t) => {
    const root = consumer(t);
    await cli(root, ['aws', 'doctor']);
    await cli(root, ['aws', 'doctor', '--json']);
    assert.equal(execFileSync('git', ['-C', root, 'status', '--porcelain'], { encoding: 'utf8' }), '');
  });

  it('the github command is still Phase 2E: exit 2, nothing contacted', async (t) => {
    const result = await cli(consumer(t), ['github', 'apply']);
    assert.equal(result.code, 2);
    assert.match(result.err, /not implemented/);
    assert.deepEqual(result.f.calls, []);
  });
});
