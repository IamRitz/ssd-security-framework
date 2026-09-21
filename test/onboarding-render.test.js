// ssd-onboard rendering: config -> workflows and scanner configs. Assertions are
// made on the PARSED structure (the strict YAML subset parser is equivalent to
// PyYAML on these files; tools/verify-generated-workflows.sh also runs
// actionlint over them).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseConfig, serializeConfig } from '../onboarding/lib/config.mjs';
import { contractProblems, requiredCallerPermissions } from '../onboarding/lib/contract.mjs';
import { readMarker } from '../onboarding/lib/files.mjs';
import { ACTIONS } from '../onboarding/lib/pins.mjs';
import { renderAll, renderDeliveryWorkflow, renderSecurityWorkflow } from '../onboarding/lib/render.mjs';
import { parseYaml } from '../onboarding/lib/yaml.mjs';
import { DEPLOY_ROLE, PUSH_ROLE, REF, config, readWorkingTreeWorkflow } from './support/onboarding-fixtures.mjs';

const PROFILES = ['source-only', 'container-self-managed', 'container-ecr-framework-gated'];
const ENFORCING = { rollout: { gateMode: 'enforce' }, semgrep: { baseline: { state: 'accepted' } } };
const SLACK = { slack: { enabled: true, githubSecretName: 'SECURITY_NOTIFY_SLACK_URL' } };

const security = (profile, overrides) => parseYaml(renderSecurityWorkflow(config(profile, overrides)));
const delivery = (overrides) => parseYaml(renderDeliveryWorkflow(config('container-ecr-framework-gated', { ...ENFORCING, ...overrides })));
const everyWorkflow = () =>
  PROFILES.flatMap((profile) =>
    [{}, ENFORCING, { ...ENFORCING, notifications: SLACK }].flatMap((overrides) =>
      renderAll(config(profile, overrides))
        .filter((file) => file.kind === 'workflow')
        .map((file) => ({ label: `${profile}${JSON.stringify(overrides)} ${file.path}`, text: file.content, doc: parseYaml(file.content) }))
    )
  );

describe('rendering is deterministic', () => {
  for (const profile of PROFILES) {
    it(`${profile}: identical config renders byte-identical output, including after a config round-trip`, () => {
      const c = config(profile, ENFORCING);
      const first = renderAll(c);
      const second = renderAll(c);
      assert.deepEqual(second, first);
      const reparsed = parseConfig(serializeConfig(c)).config;
      assert.deepEqual(renderAll(reparsed), first);
    });
  }

  it('embeds no timestamp or run-specific value', () => {
    for (const { label, text } of everyWorkflow()) {
      assert.ok(!/\b20\d\d-\d\d-\d\d(T|\s)\d\d:/.test(text), `${label} contains a timestamp`);
    }
  });

  it('every generated file carries an intact ssd-onboard marker', () => {
    for (const profile of PROFILES) {
      for (const file of renderAll(config(profile, { gitleaks: { mode: 'managed', path: '.gitleaks.toml', customRules: [] } }))) {
        assert.deepEqual(readMarker(file.content), { marked: true, intact: true, schema: '1' }, file.path);
      }
    }
  });
});

describe('the exact framework ref, everywhere', () => {
  it('every uses:, toolkit_ref, toolkit_repository and framework checkout names the configured ref', async () => {
    for (const profile of PROFILES) {
      const rendered = renderAll(config(profile, { ...ENFORCING, notifications: SLACK }));
      const { problems } = await contractProblems(rendered, config(profile), async () => '{}');
      assert.deepEqual(problems.filter((p) => !/does not declare|required input| grants /.test(p)), [], profile);
      for (const file of rendered.filter((f) => f.kind === 'workflow')) {
        for (const match of file.content.matchAll(/ssd-security-framework\/\.github\/workflows\/[^@\s]+@(\S+)/g)) {
          assert.equal(match[1], REF);
        }
      }
    }
  });

  it('passes only inputs and secrets the reusable workflows (at this framework revision) declare', async () => {
    for (const profile of PROFILES) {
      for (const overrides of [{}, ENFORCING, { ...ENFORCING, notifications: SLACK }]) {
        const { problems, unverified } = await contractProblems(renderAll(config(profile, overrides)), config(profile, overrides), readWorkingTreeWorkflow);
        assert.deepEqual(unverified, []);
        assert.deepEqual(problems, [], `${profile} ${JSON.stringify(overrides)}`);
      }
    }
  });

  it('detects a pinned ref that lacks a secret the render passes (e.g. a pre-webhook-secret framework)', async () => {
    const rendered = renderAll(config('source-only', { notifications: SLACK }));
    const legacy = async (file) => (await readWorkingTreeWorkflow(file)).replace(/\n      slack_notify_webhook:\n(?: {8}.*\n)+/, '\n');
    const { problems } = await contractProblems(rendered, config('source-only'), legacy);
    assert.ok(problems.some((p) => /secret 'slack_notify_webhook'.*would fail to start/.test(p)), problems.join('\n'));
  });

  // Future-proofing, symmetric with required inputs: GitHub refuses to start a
  // callee whose required secret the caller does not pass. No secret the
  // framework declares today is required — this pins the check down against the
  // day one becomes required, by making `slack_notify_webhook` required only in
  // the pinned text this test reads.
  it('detects a pinned ref that REQUIRES a secret the render does not pass', async () => {
    const requiringWebhook = async (file) =>
      (await readWorkingTreeWorkflow(file))?.replace(
        /(\n      slack_notify_webhook:\n(?: {8}.*\n)*? {8}required: )false\n/,
        '$1true\n'
      ) ?? null;
    // Sanity: the substitution really did make it required at the pinned ref.
    assert.match(await requiringWebhook('_source-scan.yml'), /slack_notify_webhook:[\s\S]*?required: true/);

    const silent = config('source-only'); // notifications off: no secrets are passed
    const { problems } = await contractProblems(renderAll(silent), silent, requiringWebhook);
    assert.ok(
      problems.some((p) => /does not pass required secret 'slack_notify_webhook' of _source-scan\.yml/.test(p)),
      problems.join('\n')
    );

    // A caller that does pass it has no problem — the check is about the
    // contract, not about Slack being enabled.
    const notifying = config('source-only', { notifications: SLACK });
    const passing = await contractProblems(renderAll(notifying), notifying, requiringWebhook);
    assert.deepEqual(passing.problems.filter((p) => /required secret/.test(p)), []);
  });

  it('uses the same third-party action pins as the framework examples', async () => {
    const { readFileSync } = await import('node:fs');
    const examples = readFileSync('examples/container-ecr/deploy.yml', 'utf8') + readFileSync('examples/container-ecr/security.yml', 'utf8');
    for (const [name, pin] of Object.entries(ACTIONS)) {
      assert.ok(examples.includes(pin.split(' #')[0]), `${name} pin ${pin} differs from the examples`);
    }
  });
});

describe('security invariants hold for every generated workflow', () => {
  const all = everyWorkflow();

  it('no pull_request_target, anywhere', () => {
    for (const { label, doc, text } of all) {
      assert.ok(!('pull_request_target' in doc.on), label);
      assert.ok(!/pull_request_target:/.test(text), label);
    }
  });

  it('no secrets: inherit, anywhere', () => {
    for (const { label, doc, text } of all) {
      for (const job of Object.values(doc.jobs)) {
        assert.notEqual(job.secrets, 'inherit', label);
      }
      const executable = text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
      assert.ok(!/secrets:\s*inherit/.test(executable), label);
    }
  });

  it('top-level permissions are read-only contents', () => {
    for (const { label, doc } of all) {
      assert.deepEqual(doc.permissions, { contents: 'read' }, label);
    }
  });

  it('build and scanner jobs can assume no cloud role and read no secret', () => {
    for (const { label, doc } of all) {
      const build = doc.jobs['container-build'];
      if (build) {
        assert.deepEqual(build.permissions, { contents: 'read' }, `${label}: container-build`);
        assert.ok(!/aws-actions|role-to-assume|secrets\.|build-args|secrets:/.test(JSON.stringify(build)), `${label}: container-build`);
      }
      const image = doc.jobs['image-security'];
      if (image) {
        assert.ok(!('id-token' in image.permissions), `${label}: image-security must not hold id-token`);
      }
      for (const jobId of ['security-gate', 'gate-mode']) {
        assert.deepEqual(doc.jobs[jobId]?.permissions ?? {}, {}, `${label}: ${jobId}`);
      }
      const conformance = doc.jobs.conformance;
      assert.ok(!('id-token' in conformance.permissions) && !conformance.secrets, `${label}: conformance`);
    }
  });

  it('only break-glass (OIDC approval), ecr-collect (push) and deploy (SSM) may request id-token', () => {
    // Since the v1.2.0 source/break-glass split, the source-path OIDC boundary is
    // the dedicated `break-glass` job calling `_break-glass-lambda.yml`. The
    // scanning caller uses the OIDC-free `_source-scan.yml`, so it never holds a
    // token — and with break-glass disabled (all Phase 1 renders) NO source-path
    // job does. `ecr-collect` and `deploy` are delivery-side and unaffected.
    for (const { label, doc } of all) {
      const holders = Object.entries(doc.jobs)
        .filter(([, job]) => job.permissions?.['id-token'] === 'write')
        .map(([id]) => id)
        .sort();
      const allowed = ['break-glass', 'deploy', 'ecr-collect'];
      assert.ok(holders.every((id) => allowed.includes(id)), `${label}: ${holders}`);
      assert.ok(!holders.includes('source-security'), `${label}: the source scan caller must never hold id-token`);
    }
  });

  it('with break-glass disabled, no source-path job requests id-token at all', () => {
    for (const { label, doc } of all) {
      for (const [jobId, job] of Object.entries(doc.jobs)) {
        if (jobId === 'ecr-collect' || jobId === 'deploy') continue;
        assert.ok(!('id-token' in (job.permissions ?? {})), `${label}: ${jobId} holds id-token although break-glass is disabled`);
      }
    }
  });

  it('every generated source caller uses the OIDC-free _source-scan.yml', () => {
    for (const { label, doc } of all) {
      const job = doc.jobs['source-security'];
      assert.ok(job, `${label}: no source-security job`);
      assert.match(job.uses, /\/\.github\/workflows\/_source-scan\.yml@/, `${label}: new callers must not use _source-security.yml`);
    }
  });

  it('the Slack webhook is a declared secret on notifying jobs only, never an input', () => {
    for (const { label, doc } of all) {
      for (const [jobId, job] of Object.entries(doc.jobs)) {
        assert.ok(!('slack_notify_url' in (job.with ?? {})), `${label}: ${jobId} passes the webhook as an input`);
        if (job.secrets) {
          assert.deepEqual(Object.keys(job.secrets), ['slack_notify_webhook'], `${label}: ${jobId}`);
          assert.ok(['source-security', 'image-security', 'artifact-gate', 'break-glass'].includes(jobId), `${label}: ${jobId} must not receive the webhook`);
        }
      }
    }
  });
});

describe('the stable required check', () => {
  for (const profile of PROFILES) {
    const doc = security(profile);
    const gate = doc.jobs['security-gate'];

    it(`${profile}: security-gate is a literal, mode-independent name that always reports`, () => {
      assert.equal(gate.name, 'security-gate');
      assert.equal(gate.if, '${{ always() }}');
      const log = security(profile).jobs['security-gate'].name;
      const enforce = security(profile, ENFORCING).jobs['security-gate'].name;
      assert.equal(log, enforce);
    });

    const container = profile !== 'source-only';
    it(`${profile}: aggregates ${container ? 'source AND image' : 'source only'}`, () => {
      const needs = [gate.needs].flat();
      assert.deepEqual(needs, container ? ['source-security', 'image-security'] : ['source-security']);
      const script = gate.steps[0].run;
      assert.match(script, /"\$SOURCE_RESULT" != "success"/);
      if (container) {
        assert.match(script, /"\$IMAGE_RESULT" != "success"/);
        const scheduleBranch = script.slice(script.indexOf('if [ "$EVENT" = "schedule" ]'));
        assert.ok(!/success\|skipped/.test(script.slice(0, script.indexOf('if [ "$EVENT" = "schedule" ]'))), 'skipped only tolerated on schedule');
        assert.match(scheduleBranch, /success\|skipped/);
      } else {
        assert.ok(!/image-security/.test(JSON.stringify(gate)));
      }
    });
  }

  it('the gate-mode visibility check reads the mode the reusable workflow echoed back', () => {
    const job = security('container-self-managed').jobs['gate-mode'];
    assert.match(job.name, /needs\.source-security\.outputs\.gate_mode == 'log-only'/);
    assert.equal(job.steps[0].env.MODE, '${{ needs.source-security.outputs.gate_mode }}');
  });
});

describe('profiles', () => {
  it('source-only: one reusable call chain, no build, no cloud, library capabilities', () => {
    const doc = security('source-only');
    assert.deepEqual(Object.keys(doc.jobs), ['source-security', 'security-gate', 'gate-mode', 'conformance']);
    const c = doc.jobs.conformance.with;
    assert.deepEqual([c.artifact_type, c.registry, c.deploy_target, c.phase], ['library', 'none', 'none', 'pr']);
    assert.ok(!/aws-actions|role_arn|role-to-assume/.test(renderSecurityWorkflow(config('source-only'))));
  });

  it('container-self-managed: credential-free build + pre-push Trivy, no registry, no deploy', () => {
    const doc = security('container-self-managed');
    assert.deepEqual(Object.keys(doc.jobs), ['source-security', 'container-build', 'image-security', 'security-gate', 'gate-mode', 'conformance']);
    const c = doc.jobs.conformance.with;
    assert.deepEqual([c.artifact_type, c.registry, c.deploy_target], ['container', 'none', 'self-managed']);
    assert.match(c.observed, /"image-scan-prepush":\{"status":"\$\{\{ needs\.image-security\.result \}\}"/);
    const build = doc.jobs['container-build'].steps.find((s) => s.uses?.startsWith('docker/build-push-action'));
    assert.deepEqual(Object.keys(build.with).sort(), ['cache-from', 'cache-to', 'context', 'file', 'load', 'tags']);
  });

  it('container-ecr: the PR phase defers delivery; there is NO delivery workflow while log-only', () => {
    const files = renderAll(config('container-ecr-framework-gated'));
    assert.deepEqual(files.map((f) => f.path), ['.github/workflows/security.yml', '.semgrepignore']);
    const c = parseYaml(files[0].content).jobs.conformance.with;
    assert.deepEqual([c.artifact_type, c.registry, c.deploy_target, c.phase], ['container', 'ecr', 'framework-gated', 'pr']);
    assert.ok(!/"gated-deploy"|"registry-scan-collect"|"artifact-gate"/.test(c.observed), 'a PR must not claim delivery controls');
  });

  it('container-ecr enforcing: the delivery workflow keeps every trust boundary and the digest chain', () => {
    const doc = delivery();
    assert.deepEqual(Object.keys(doc.jobs), ['source-security', 'container-build', 'image-security', 'ecr-collect', 'artifact-gate', 'deploy', 'conformance']);
    assert.deepEqual(Object.keys(doc.on).sort(), ['push', 'workflow_dispatch']);
    for (const jobId of ['source-security', 'image-security', 'artifact-gate']) {
      assert.equal(doc.jobs[jobId].with.gate_mode, 'enforce', `${jobId}: delivery never runs log-only`);
    }
    const build = doc.jobs['container-build'].steps.find((s) => s.uses?.startsWith('docker/build-push-action'));
    assert.equal(build.with['no-cache'], true, 'release builds never use the Actions cache');

    const ecr = doc.jobs['ecr-collect'];
    assert.equal(ecr.with.role_arn, PUSH_ROLE);
    assert.equal(ecr.with.expected_image_id, '${{ needs.image-security.outputs.image_id }}', 'scan -> push link');
    assert.match(ecr.if, /github\.ref == 'refs\/heads\/main'/);
    assert.match(ecr.if, /needs\.source-security\.result == 'success'/);
    assert.match(ecr.if, /needs\.image-security\.result == 'success'/);

    const gate = doc.jobs['artifact-gate'];
    assert.equal(gate.with.expected_digest, '${{ needs.ecr-collect.outputs.image_digest }}', 'push -> gate link');
    assert.ok(!('id-token' in gate.permissions));

    const deploy = doc.jobs.deploy;
    assert.deepEqual(deploy.needs, ['artifact-gate', 'ecr-collect'], 'deploy never starts unless the artifact gate succeeded');
    const creds = deploy.steps.find((s) => s.uses?.startsWith('aws-actions/configure-aws-credentials'));
    assert.equal(creds.with['role-to-assume'], DEPLOY_ROLE);
    const run = deploy.steps.at(-1);
    assert.equal(run.env.IMAGE_DIGEST, '${{ needs.ecr-collect.outputs.image_digest }}', 'gate -> deploy link');
    assert.match(run.run, /--image-digest "\$IMAGE_DIGEST"/);
    assert.ok(!/--image-tag/.test(run.run), 'never a mutable tag');
    assert.match(run.run, /--container-name app/);
  });

  it('container-ecr: the delivery template enforces even if handed a log-only config (defence in depth)', () => {
    const doc = parseYaml(renderDeliveryWorkflow(config('container-ecr-framework-gated', { semgrep: { baseline: { state: 'accepted' } } })));
    for (const jobId of ['source-security', 'image-security', 'artifact-gate']) {
      assert.equal(doc.jobs[jobId].with.gate_mode, 'enforce', jobId);
    }
  });

  it('container-ecr: push and deploy credentials never share a job', () => {
    const text = renderDeliveryWorkflow(config('container-ecr-framework-gated', ENFORCING));
    const doc = parseYaml(text);
    for (const [jobId, job] of Object.entries(doc.jobs)) {
      const body = JSON.stringify(job);
      if (jobId !== 'ecr-collect') {
        assert.ok(!body.includes(PUSH_ROLE), `${jobId} must not hold the push role`);
      }
      if (jobId !== 'deploy') {
        assert.ok(!body.includes(DEPLOY_ROLE), `${jobId} must not hold the deploy role`);
      }
    }
  });

  it('container-ecr: delivery conformance proves delivery controls with real job results', () => {
    const observed = delivery().jobs.conformance.with.observed;
    for (const [control, job] of [['registry-scan-collect', 'ecr-collect'], ['artifact-gate', 'artifact-gate'], ['gated-deploy', 'deploy']]) {
      assert.ok(observed.includes(`"${control}":{"status":"\${{ needs.${job}.result }}"`), control);
    }
    const parsed = JSON.parse(observed.replace(/\$\{\{[^}]+\}\}/g, 'x'));
    assert.equal(Object.keys(parsed).length, 8);
  });

  it('an optional GitHub environment gates the deploy job', () => {
    assert.equal(delivery({ delivery: { environment: 'production' } }).jobs.deploy.environment, 'production');
    assert.ok(!('environment' in delivery().jobs.deploy));
  });

  it('break-glass is never generated, and conformance is never fed a break-glass claim', () => {
    for (const { label, doc } of everyWorkflow()) {
      for (const [jobId, job] of Object.entries(doc.jobs)) {
        if (job.with && 'break_glass_enabled' in job.with) {
          assert.equal(job.with.break_glass_enabled, false, `${label}: ${jobId}`);
        }
        assert.ok(!Object.keys(job.with ?? {}).some((key) => /^break_glass_(transport|lambda|aws_region|notify|status)/.test(key)), `${label}: ${jobId}`);
      }
      assert.ok(!/"break-glass"/.test(doc.jobs.conformance.with.observed), `${label}: no fabricated break-glass evidence`);
    }
  });
});

// Item: OIDC least privilege. GitHub validates a reusable workflow's job
// permissions STATICALLY (even for jobs or steps that would not run), so a
// caller must grant exactly the union its callee declares. Since the v1.2.0
// source/break-glass split, the source scan callee (`_source-scan.yml`) declares
// no `id-token` on any job, so a generated source caller grants none. OIDC lives
// only in the dedicated `_break-glass-lambda.yml` caller. These tests pin what
// the generator grants, and why.
describe('caller permissions are exactly what the callee statically requires', () => {
  const callee = async (file) => parseYaml(await readWorkingTreeWorkflow(file));
  const grants = (profile, overrides) =>
    Object.fromEntries(Object.entries(security(profile, overrides).jobs).map(([id, job]) => [id, job.permissions ?? null]));

  it('source-only, break-glass disabled: contents + pull-requests, and no OIDC', () => {
    const g = grants('source-only');
    assert.deepEqual(g['source-security'], { contents: 'read', 'pull-requests': 'write' });
    assert.deepEqual(g.conformance, { contents: 'read' });
    assert.deepEqual(g['security-gate'], {});
    assert.deepEqual(g['gate-mode'], {});
  });

  it('container-self-managed, break-glass disabled: neither the source nor the image path holds id-token', () => {
    const g = grants('container-self-managed');
    assert.deepEqual(g['container-build'], { contents: 'read' });
    assert.deepEqual(g['image-security'], { contents: 'read', 'pull-requests': 'write' });
    assert.deepEqual(g['source-security'], { contents: 'read', 'pull-requests': 'write' });
  });

  it('break-glass (Lambda) enabled: not generated by Phase 1 — the schema refuses it (see onboarding-config tests)', () => {
    assert.throws(() => config('source-only', { breakGlass: { mode: 'existing' } }), /not supported by ssd-onboard Phase 1/);
  });

  it('the source scan callee declares no id-token on any job, so no caller needs one', async () => {
    const workflow = await callee('_source-scan.yml');
    const holders = Object.entries(workflow.jobs).filter(([, job]) => job.permissions?.['id-token'] === 'write').map(([id]) => id);
    assert.deepEqual(holders, [], '_source-scan.yml must stay OIDC-free; if this changes, the generator grant must change with it');
    assert.ok(
      !workflow.jobs['source-gate'].steps.some((step) => step.uses?.startsWith('aws-actions/configure-aws-credentials')),
      'the OIDC-free twin must assume no role'
    );
    assert.deepEqual(requiredCallerPermissions(workflow.jobs), { contents: 'read', 'pull-requests': 'write' });
  });

  it('OIDC belongs to the dedicated break-glass callee, which is where a caller must grant it', async () => {
    const workflow = await callee('_break-glass-lambda.yml');
    const holders = Object.entries(workflow.jobs).filter(([, job]) => job.permissions?.['id-token'] === 'write').map(([id]) => id);
    assert.deepEqual(holders, ['break-glass'], 'the credential-bearing job is the only OIDC holder');
    assert.deepEqual(requiredCallerPermissions(workflow.jobs), { contents: 'read', 'id-token': 'write' });
  });

  it('the contract check reports over- and under-grants', async () => {
    const c = config('source-only');
    const rendered = renderAll(c);
    const ok = await contractProblems(rendered, c, readWorkingTreeWorkflow);
    assert.deepEqual(ok.problems, []);
    // The static-grant note existed only because `_source-security.yml` declared
    // id-token on a job GitHub validates statically. New callers use the
    // OIDC-free twin, so there is nothing left to flag.
    assert.deepEqual(ok.staticGrants, [], 'no caller grants a token its callee does not require');

    // Dropping id-token from the source caller is NOT an under-grant: the callee
    // never required it.
    const withoutSourceToken = rendered.map((f) => ({ ...f, content: f.content.replace('      id-token: write\n', '') }));
    assert.deepEqual((await contractProblems(withoutSourceToken, c, readWorkingTreeWorkflow)).problems, []);

    // Adding it back IS an over-grant.
    const overGrantedToken = rendered.map((f) => ({
      ...f,
      content: f.content.replace('      contents: read\n      pull-requests: write\n', '      contents: read\n      pull-requests: write\n      id-token: write\n')
    }));
    assert.ok(
      (await contractProblems(overGrantedToken, c, readWorkingTreeWorkflow)).problems.some((p) => /id-token: write.*unnecessary grant/.test(p)),
      'id-token on a _source-scan.yml caller is an unnecessary grant'
    );

    const overGranted = rendered.map((f) => ({ ...f, content: f.content.replace('    permissions:\n      contents: read\n    with:', '    permissions:\n      contents: read\n      actions: write\n    with:') }));
    assert.ok((await contractProblems(overGranted, c, readWorkingTreeWorkflow)).problems.some((p) => /actions: write.*unnecessary grant/.test(p)));
  });

  it('a dedicated break-glass caller that omits id-token IS an under-grant', async () => {
    // Phase 1 never generates this job (break-glass is refused by the schema), so
    // the contract is pinned against a hand-built caller: the check is generic
    // over whatever callee a job names.
    const c = config('source-only');
    const caller = (permissions) => [
      {
        kind: 'workflow',
        path: '.github/workflows/security.yml',
        content: [
          'on:',
          '  pull_request:',
          'permissions:',
          '  contents: read',
          'jobs:',
          '  break-glass:',
          `    uses: ${c.framework.repository}/.github/workflows/_break-glass-lambda.yml@${c.framework.ref}`,
          '    permissions:',
          ...permissions.map((line) => `      ${line}`),
          '    with:',
          `      toolkit_ref: ${c.framework.ref}`,
          '      gate_mode: enforce',
          "      expected_gate_digest: ${{ needs.source-security.outputs.gate_digest }}",
          ''
        ].join('\n')
      }
    ];
    const granted = await contractProblems(caller(['contents: read', 'id-token: write']), c, readWorkingTreeWorkflow);
    assert.deepEqual(granted.problems.filter((p) => /id-token/.test(p)), [], 'a correct grant raises no id-token problem');

    const omitted = await contractProblems(caller(['contents: read']), c, readWorkingTreeWorkflow);
    assert.ok(
      omitted.problems.some((p) => /id-token: none.*would fail to start/.test(p)),
      `omitting id-token must be an under-grant: ${omitted.problems.join('\n')}`
    );
  });
});

describe('custom workflow file names', () => {
  it('writes to the configured names; the job name security-gate never changes', () => {
    const c = config('container-ecr-framework-gated', { ...ENFORCING, workflows: { security: '.github/workflows/ci-security.yaml', delivery: '.github/workflows/release.yml' } });
    const files = renderAll(c);
    assert.deepEqual(files.filter((f) => f.kind === 'workflow').map((f) => f.path), ['.github/workflows/ci-security.yaml', '.github/workflows/release.yml']);
    assert.equal(parseYaml(files[0].content).jobs['security-gate'].name, 'security-gate');
    assert.match(files[0].content, /delivery phase .* is \.github\/workflows\/release\.yml/i);
  });
});

describe('scanner scope in the generated call', () => {
  it('Semgrep scans `.` by default and exactly the configured roots otherwise', () => {
    assert.equal(security('source-only').jobs['source-security'].with.semgrep_paths, '.');
    assert.equal(security('source-only', { semgrep: { roots: ['src', 'lib'] } }).jobs['source-security'].with.semgrep_paths, 'src lib');
  });

  it('rulesets and the baseline path come from the config', () => {
    const w = security('source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/golang'], baseline: { path: 'sec/base.json' } } }).jobs['source-security'].with;
    assert.equal(w.semgrep_configs, 'p/owasp-top-ten\np/golang\n');
    assert.equal(w.semgrep_baseline_path, 'sec/base.json');
  });

  it("Gitleaks and TruffleHog default to an EXPLICIT '' (no stray file can change the scan)", () => {
    const w = security('source-only').jobs['source-security'].with;
    assert.equal(w.gitleaks_config, '');
    assert.equal(w.trufflehog_exclude_paths, '');
  });

  it('a custom TruffleHog exclude file and a managed Gitleaks config are wired by path', () => {
    const w = security('source-only', {
      trufflehog: { excludePathsFile: 'security/trufflehog-exclude.txt' },
      gitleaks: { mode: 'managed', path: 'security/gitleaks.toml', customRules: [] }
    }).jobs['source-security'].with;
    assert.equal(w.trufflehog_exclude_paths, 'security/trufflehog-exclude.txt');
    assert.equal(w.gitleaks_config, 'security/gitleaks.toml');
  });
});

describe('generated scanner configs', () => {
  it('.semgrepignore is always explicit and carries exactly the configured patterns', () => {
    const files = renderAll(config('source-only', { semgrep: { ignore: { managed: true, patterns: ['dist/', '*.min.js'] } } }));
    const ignore = files.find((f) => f.path === '.semgrepignore').content;
    const patterns = ignore.split('\n').filter((line) => line && !line.startsWith('#'));
    assert.deepEqual(patterns, ['dist/', '*.min.js']);
    const empty = renderAll(config('source-only')).find((f) => f.path === '.semgrepignore').content;
    assert.deepEqual(empty.split('\n').filter((line) => line && !line.startsWith('#')), []);
  });

  it('no .semgrepignore is generated when the owner manages it', () => {
    assert.ok(!renderAll(config('source-only', { semgrep: { ignore: { managed: false, patterns: [] } } })).some((f) => f.path === '.semgrepignore'));
  });

  it('the generated .gitleaks.toml extends the default ruleset BEFORE any consumer rule', () => {
    const c = config('source-only', {
      gitleaks: {
        mode: 'managed',
        path: '.gitleaks.toml',
        customRules: [{ id: 'acme-token', description: 'ACME "internal" token', regex: 'ACME_[A-Z0-9]{32}', keywords: ['ACME_'] }],
        allowlists: [{ description: 'documented test vector', paths: ['^docs/vectors\\.md$'] }]
      }
    });
    const toml = renderAll(c).find((f) => f.path === '.gitleaks.toml').content;
    const extend = toml.indexOf('[extend]\n');
    const useDefault = toml.indexOf('useDefault = true');
    assert.ok(extend > 0 && useDefault > extend && useDefault < toml.indexOf('[[rules]]'));
    assert.match(toml, /description = "ACME \\"internal\\" token"/);
    assert.match(toml, /regex = '''ACME_\[A-Z0-9\]\{32\}'''/);
    assert.match(toml, /\[\[allowlists\]\]\ndescription = "documented test vector"\npaths = \['''\^docs\/vectors\\\.md\$'''\]/);
  });

  it('no .gitleaks.toml is generated in default mode', () => {
    assert.ok(!renderAll(config('source-only')).some((f) => f.path.endsWith('.toml')));
  });
});

describe('baseline bootstrap in the generated workflow', () => {
  it('while the baseline is absent: a workflow_dispatch checkbox, true only on a dispatched run', () => {
    const doc = security('source-only');
    assert.equal(doc.on.workflow_dispatch.inputs.bootstrap_baseline.type, 'boolean');
    assert.equal(doc.on.workflow_dispatch.inputs.bootstrap_baseline.default, false);
    assert.equal(
      doc.jobs['source-security'].with.bootstrap_baseline,
      "${{ github.event_name == 'workflow_dispatch' && inputs.bootstrap_baseline == true }}"
    );
    assert.equal(doc.jobs['source-security'].with.gate_mode, 'log-only');
  });

  it('once the baseline is accepted: no bootstrap input and no dispatch trigger remain', () => {
    for (const overrides of [{ semgrep: { baseline: { state: 'accepted' } } }, ENFORCING]) {
      const doc = security('container-self-managed', overrides);
      assert.ok(!('workflow_dispatch' in doc.on));
      assert.ok(!('bootstrap_baseline' in doc.jobs['source-security'].with));
    }
  });

  it('the gate mode is a literal from the config, never a repository variable', () => {
    for (const { label, text } of everyWorkflow()) {
      assert.ok(!/gate_mode: \$\{\{/.test(text), label);
      assert.ok(!/vars\./.test(text), `${label} must not read repository variables`);
    }
  });
});

// The generated aggregate scripts are EXECUTED, not only pattern-matched: the
// required check's behaviour is the contract branch protection relies on.
describe('the generated gate scripts behave as the required check promises', async () => {
  const { spawnSync } = await import('node:child_process');
  const run = (profile, jobId, env) => {
    const script = security(profile).jobs[jobId].steps[0].run;
    const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
      env: { PATH: process.env.PATH, GITHUB_STEP_SUMMARY: '/dev/null', ...env },
      encoding: 'utf8'
    });
    return { code: result.status, out: `${result.stdout}${result.stderr}` };
  };
  const pr = { EVENT: 'pull_request', SOURCE_RESULT: 'success', SOURCE_VERDICT: 'PASS', SOURCE_MODE: 'enforce', IMAGE_RESULT: 'success', IMAGE_VERDICT: 'DEPLOY', IMAGE_MODE: 'enforce' };

  it('container: passes only when source AND image passed', () => {
    assert.equal(run('container-self-managed', 'security-gate', pr).code, 0);
    assert.equal(run('container-self-managed', 'security-gate', { ...pr, IMAGE_RESULT: 'failure' }).code, 1);
    assert.equal(run('container-self-managed', 'security-gate', { ...pr, SOURCE_RESULT: 'failure' }).code, 1);
  });

  it('container: a skipped image gate fails a PR and passes only the scheduled sweep', () => {
    assert.equal(run('container-self-managed', 'security-gate', { ...pr, IMAGE_RESULT: 'skipped' }).code, 1);
    assert.equal(run('container-self-managed', 'security-gate', { ...pr, EVENT: 'schedule', IMAGE_RESULT: 'skipped' }).code, 0);
  });

  it('log-only: a BLOCK is announced as GREEN BY CONFIGURATION, a PASS is not', () => {
    const block = run('source-only', 'security-gate', { ...pr, SOURCE_VERDICT: 'BLOCK', SOURCE_MODE: 'log-only' });
    assert.equal(block.code, 0);
    assert.match(block.out, /GREEN BY CONFIGURATION, not by verdict — source verdict BLOCK/);
    const pass = run('source-only', 'security-gate', { ...pr, SOURCE_MODE: 'log-only' });
    assert.doesNotMatch(pass.out, /GREEN BY CONFIGURATION/);
  });

  it('gate-mode goes red when log-only suppresses a BLOCK or a scan is untrusted, and green otherwise', () => {
    const base = { MODE: 'enforce', SOURCE_VERDICT: 'PASS', SOURCE_TRUSTED: 'true', IMAGE_RESULT: 'success', IMAGE_VERDICT: 'DEPLOY', IMAGE_TRUSTED: 'true' };
    assert.equal(run('container-self-managed', 'gate-mode', base).code, 0);
    assert.equal(run('container-self-managed', 'gate-mode', { ...base, MODE: 'log-only', IMAGE_VERDICT: 'BLOCK_DEPLOY' }).code, 1);
    assert.equal(run('container-self-managed', 'gate-mode', { ...base, SOURCE_TRUSTED: 'false' }).code, 1);
    assert.equal(run('source-only', 'gate-mode', { ...base, MODE: 'log-only', SOURCE_VERDICT: 'BLOCK' }).code, 1);
  });
});
