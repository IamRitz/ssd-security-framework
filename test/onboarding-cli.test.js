// ssd-onboard end to end, against throwaway git repositories: init, render,
// drift, file ownership, the baseline state machine, promotion — and proof that
// none of it contacts AWS or mutates GitHub.
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';

import { ghReadOnly, main } from '../onboarding/cli.mjs';
import { analyze } from '../onboarding/lib/analyze.mjs';
import { CANDIDATE_FILE, CANDIDATE_PROVENANCE, installCandidate, loadCandidateForAcceptance, rolloutState, validateBaselineDocument } from '../onboarding/lib/baseline.mjs';
import { detectFramework } from '../onboarding/lib/framework.mjs';
import { parseConfig, serializeConfig } from '../onboarding/lib/config.mjs';
import { planWrites, readMarker, withMarker } from '../onboarding/lib/files.mjs';
import { scriptedPrompter } from '../onboarding/lib/prompt.mjs';
import { renderSecurityWorkflow } from '../onboarding/lib/render.mjs';
import { parseYaml } from '../onboarding/lib/yaml.mjs';
import { inspectRepository } from '../onboarding/lib/inspect.mjs';
import { FRAMEWORK, REF, SAMPLE_BASELINE, bootstrapArtifact, capture, commitAll, config, head, makeRepo, read, readWorkingTreeWorkflow, tempDir, write } from './support/onboarding-fixtures.mjs';

// Partial configs live outside the repository, so they are not scanned files.
const PARTIALS = mkdtempSync(join(tmpdir(), 'ssd-partials-'));
const partial = (name, text) => {
  writeFileSync(join(PARTIALS, name), text);
  return join(PARTIALS, name);
};

const PY_REPO = {
  'src/app.py': 'print("hi")\n',
  'tests/test_app.py': 'def test(): pass\n',
  'requirements.txt': 'requests==2.32.5\n',
  '.github/workflows/lint.yml': 'name: lint\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n'
};

// PATH shims that record any aws / gh invocation. Tests assert they stay empty.
const SHIM_DIR = mkdtempSync(join(tmpdir(), 'ssd-shims-'));
const SHIM_LOG = join(SHIM_DIR, 'calls.log');
for (const tool of ['aws', 'gh']) {
  writeFileSync(join(SHIM_DIR, tool), `#!/bin/sh\necho "${tool} $*" >> "${SHIM_LOG}"\nexit 97\n`);
  chmodSync(join(SHIM_DIR, tool), 0o755);
}
const ORIGINAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${ORIGINAL_PATH}`;
after(() => {
  process.env.PATH = ORIGINAL_PATH;
  // These two are this file's own roots, created at module load; every
  // per-test root is owned by its test (see makeRepo/tempDir).
  for (const dir of [PARTIALS, SHIM_DIR]) {
    rmSync(dir, { recursive: true, force: true });
  }
});
const shimCalls = () => (existsSync(SHIM_LOG) ? readFileSync(SHIM_LOG, 'utf8').trim().split('\n').filter(Boolean) : []);

async function cli(root, args, io = {}) {
  const c = capture();
  // The CLI is bound to REF unless a test says otherwise (see framework.mjs).
  const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io, ...io });
  return { code, out: c.text(), err: c.errors() };
}

function writeConfig(root, profile, overrides) {
  write(root, '.ssd/onboarding.yml', serializeConfig(config(profile, overrides)));
}

describe('init', () => {
  it('non-interactive: a partial config + repository facts -> a canonical config', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const from = partial('source-only.yml', `profile: source-only\nframework:\n  ref: ${REF}\n`);
    const { code, out } = await cli(root, ['init', '--non-interactive', '--from', from]);
    assert.equal(code, 0, out);
    const { config: written, errors } = parseConfig(read(root, '.ssd/onboarding.yml'));
    assert.deepEqual(errors, []);
    assert.equal(written.repository.slug, 'acme/app');
    assert.equal(written.repository.defaultBranch, 'main');
    assert.deepEqual(written.semgrep.roots, ['.']);
    assert.deepEqual(written.semgrep.rulesets, ['p/owasp-top-ten', 'p/python']);
    assert.deepEqual(written.semgrep.ignore, { managed: true, patterns: [] });
    assert.equal(written.rollout.gateMode, 'log-only');
    // src/app.py, tests/test_app.py and the lint workflow: tests are IN scope.
    assert.match(out, /Semgrep scope:\s+3 source file\(s\) scanned, 0 ignored/);
  });

  it('interactive: scripted answers -> the expected config, and the effective scope is shown before writing', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, Dockerfile: 'FROM python:3.13-slim\n', 'dist/bundle.js': 'x\n' });
    const prompter = scriptedPrompter({
      frameworkRef: REF,
      profile: 'container-self-managed',
      acceptIgnoreSuggestions: true,
      slack: true,
      slackSecretName: 'TEAM_SLACK_WEBHOOK',
      writeConfig: true
    });
    const { code, out } = await cli(root, ['init'], { prompter });
    assert.equal(code, 0, out);
    const { config: written } = parseConfig(read(root, '.ssd/onboarding.yml'));
    assert.equal(written.profile, 'container-self-managed');
    assert.deepEqual(written.container, { dockerfile: 'Dockerfile', context: '.', imageName: 'app' });
    assert.deepEqual(written.semgrep.ignore.patterns, ['dist/']);
    assert.deepEqual(written.notifications.slack, { enabled: true, githubSecretName: 'TEAM_SLACK_WEBHOOK' });
    assert.equal(written.breakGlass.mode, 'disabled');
    assert.ok(prompter.said.some((line) => /silently skips tests\//.test(line)), 'the implicit Semgrep ignore list is explained');
    assert.ok(out.indexOf('Semgrep scope:') < out.indexOf('Wrote .ssd/onboarding.yml'), 'scope is shown before the file is written');
    assert.ok(!prompter.asked.includes('awsAccountId'), 'no AWS questions for a self-managed profile');
  });

  it('refuses to guess owner decisions: an existing Gitleaks config, TruffleHog excludes, or baseline', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, '.gitleaks.toml': 'title = "x"\n', '.trufflehog-exclude-paths.txt': 'x\n', 'security/baseline/semgrep-baseline.json': '{}' });
    const from = partial('decisions.yml', `profile: source-only\nframework:\n  ref: ${REF}\n`);
    const { code, err } = await cli(root, ['init', '--non-interactive', '--from', from]);
    assert.equal(code, 1);
    assert.match(err, /gitleaks\.mode/);
    assert.match(err, /trufflehog\.excludePathsFile/);
    assert.match(err, /semgrep\.baseline\.state/);
    assert.ok(!existsSync(join(root, '.ssd/onboarding.yml')));
  });

  it('refuses to write a config containing a credential value', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const from = partial('secret.json', JSON.stringify({ profile: 'source-only', framework: { ref: REF }, notifications: { slack: { enabled: true, githubSecretName: 'https://hooks.slack.com/services/T0/B0/xyz' } } }));
    const { code, err } = await cli(root, ['init', '--non-interactive', '--from', from]);
    assert.equal(code, 1);
    assert.match(err, /non-secret/);
    assert.ok(!existsSync(join(root, '.ssd/onboarding.yml')));
  });

  it('will not overwrite an existing config without --overwrite', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only');
    const { code, err } = await cli(root, ['init', '--non-interactive', '--from', 'x.yml']);
    assert.equal(code, 2);
    assert.match(err, /already exists/);
  });
});

describe('render, update and drift', () => {
  it('writes the profile files, and a second render changes nothing (byte-identical)', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only');
    assert.equal((await cli(root, ['render'])).code, 0);
    const first = read(root, '.github/workflows/security.yml');
    const update = await cli(root, ['update']);
    assert.equal(update.code, 0);
    assert.match(update.out, /Wrote 0 file\(s\)/);
    assert.equal(read(root, '.github/workflows/security.yml'), first);
    assert.equal((await cli(root, ['render', '--check'])).code, 0);
  });

  it('render --check fails when the config changed but render was not run', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only');
    await cli(root, ['render']);
    writeConfig(root, 'source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/python', 'p/secrets'] } });
    const check = await cli(root, ['render', '--check']);
    assert.equal(check.code, 1);
    assert.match(check.out, /DRIFTED/);
    assert.match(check.out, /\+\s+p\/secrets/);
  });

  it('protects a hand-edited generated file: --check fails, render refuses, --force overwrites', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only');
    await cli(root, ['render']);
    const path = '.github/workflows/security.yml';
    write(root, path, read(root, path).replace('gate_mode: log-only', 'gate_mode: enforce'));
    assert.equal(readMarker(read(root, path)).intact, false);
    assert.equal((await cli(root, ['render', '--check'])).code, 1);
    const refused = await cli(root, ['render']);
    assert.equal(refused.code, 1);
    assert.match(refused.out, /edited by hand/);
    assert.match(read(root, path), /gate_mode: enforce/, 'the hand edit is not silently clobbered');
    assert.equal((await cli(root, ['render', '--force', path])).code, 0);
    assert.match(read(root, path), /gate_mode: log-only/);
  });

  it('never overwrites a human-owned workflow without --adopt, and never touches unrelated workflows', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, '.github/workflows/security.yml': 'name: mine\non: push\njobs: {}\n' });
    writeConfig(root, 'source-only');
    const refused = await cli(root, ['render']);
    assert.equal(refused.code, 1);
    assert.match(refused.out, /not generated by ssd-onboard/);
    assert.equal(read(root, '.github/workflows/security.yml'), 'name: mine\non: push\njobs: {}\n');
    const dry = await cli(root, ['render', '--dry-run', '--adopt', '.github/workflows/security.yml']);
    assert.equal(dry.code, 0);
    assert.match(dry.out, /-name: mine/, 'the diff is shown before adoption');
    assert.equal(read(root, '.github/workflows/security.yml'), 'name: mine\non: push\njobs: {}\n', 'dry-run writes nothing');
    assert.equal((await cli(root, ['render', '--adopt', '.github/workflows/security.yml'])).code, 0);
    assert.ok(readMarker(read(root, '.github/workflows/security.yml')).marked);
    assert.equal(read(root, '.github/workflows/lint.yml'), PY_REPO['.github/workflows/lint.yml']);
  });

  it('custom workflow file names are honoured', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { workflows: { security: '.github/workflows/sec-checks.yaml' } });
    assert.equal((await cli(root, ['render'])).code, 0);
    assert.ok(existsSync(join(root, '.github/workflows/sec-checks.yaml')));
    assert.ok(!existsSync(join(root, '.github/workflows/security.yml')));
  });

  it('a generated file the config no longer produces is reported stale and only removed with --prune', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, Dockerfile: 'FROM scratch\n' });
    write(root, 'security/baseline/semgrep-baseline.json', JSON.stringify(SAMPLE_BASELINE));
    const enforcing = { rollout: { gateMode: 'enforce' }, semgrep: { baseline: { state: 'accepted' } } };
    writeConfig(root, 'container-ecr-framework-gated', enforcing);
    assert.equal((await cli(root, ['render'])).code, 0);
    assert.ok(existsSync(join(root, '.github/workflows/deploy.yml')));
    writeConfig(root, 'container-ecr-framework-gated', { semgrep: { baseline: { state: 'accepted' } } });
    assert.equal((await cli(root, ['render', '--check'])).code, 1);
    await cli(root, ['render']);
    assert.ok(existsSync(join(root, '.github/workflows/deploy.yml')), 'not deleted without --prune');
    await cli(root, ['render', '--prune']);
    assert.ok(!existsSync(join(root, '.github/workflows/deploy.yml')));
  });

  it('planWrites classifies every case', async (t) => {
    const root = makeRepo(t, { 'a.yml': 'x\n', 'b.yml': withMarker('old\n'), 'c.yml': withMarker('old\n').replace('old', 'edited'), 'd.yml': withMarker('same\n') });
    const plan = await planWrites(root, [
      { path: 'a.yml', content: withMarker('new\n') },
      { path: 'b.yml', content: withMarker('new\n') },
      { path: 'c.yml', content: withMarker('new\n') },
      { path: 'd.yml', content: withMarker('same\n') },
      { path: 'e.yml', content: withMarker('new\n') }
    ]);
    assert.deepEqual(plan.map((e) => e.action), ['conflict', 'update', 'conflict', 'unchanged', 'create']);
  });
});

describe('validation blocks generation on real coverage gaps', () => {
  it('a nested lockfile the native scanner never reads blocks render, and says exactly why', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, 'services/api/package-lock.json': '{"lockfileVersion":3,"packages":{}}' });
    writeConfig(root, 'source-only');
    const result = await cli(root, ['render']);
    assert.equal(result.code, 1);
    assert.match(result.out, /services\/api\/package-lock\.json: OSV-Scanner only/);
    assert.match(result.out, /npm audit runs only on the repository-root package-lock\.json/);
    assert.match(result.out, /UNSUPPORTED by the current framework/);
    assert.match(result.out, /There is deliberately no local override/);
    assert.match(result.out, /Not fully covered: services\/api\/package-lock\.json \(osv-only, UNSUPPORTED/);
    assert.ok(!existsSync(join(root, '.github/workflows/security.yml')), 'nothing generated');
  });

  it('no config content can turn an unsupported layout into a passing validation', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, 'setup.py': 'from setuptools import setup\nsetup(install_requires=["requests"])\n' });
    const text = serializeConfig(config('source-only')) +
      '\ndependencies:\n  acknowledgedGaps:\n    - path: setup.py\n      gap: uncovered\n      reason: accepted by the team for now\n      owner: acme\n      expires: \'2999-01-01\'\n';
    write(root, '.ssd/onboarding.yml', text);
    const validate = await cli(root, ['validate']);
    assert.equal(validate.code, 1);
    assert.match(validate.out, /config\.dependencies: unknown key/);
    assert.equal((await cli(root, ['render'])).code, 1);
  });

  it('an existing Gitleaks config that replaces the default ruleset blocks render', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, '.gitleaks.toml': '[[rules]]\nid = "x"\nregex = \'\'\'X\'\'\'\n' });
    writeConfig(root, 'source-only', { gitleaks: { mode: 'existing', path: '.gitleaks.toml' } });
    const result = await cli(root, ['render']);
    assert.equal(result.code, 1);
    assert.match(result.out, /REPLACES Gitleaks' built-in ruleset/);
  });

  it('a narrowed Semgrep scope warns about what falls outside SAST', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { semgrep: { roots: ['src'] } });
    const result = await cli(root, ['validate']);
    assert.match(result.out, /SAST is NARROWED to src\. \d+ source-like file\(s\) are OUTSIDE SAST coverage \([^)]*tests\/[^)]*\)/);
  });

  it("an owner-managed Semgrep scope with no .semgrepignore is an error (Semgrep's implicit list would skip tests/)", async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { semgrep: { ignore: { managed: false, patterns: [] } } });
    const result = await cli(root, ['validate']);
    assert.equal(result.code, 1);
    assert.match(result.out, /✗ \[semgrep\] semgrep\.ignore\.managed is false and there is no \.semgrepignore/);
  });

  it('blocks generation when the pinned framework commit does not declare an input or secret the render passes', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const c = config('source-only', { notifications: { slack: { enabled: true, githubSecretName: 'SECURITY_NOTIFY_SLACK_URL' } } });
    const facts = await inspectRepository(root);
    const legacy = async (file) => (await readWorkingTreeWorkflow(file)).replace(/\n      slack_notify_webhook:\n(?: {8}.*\n)+/, '\n');
    const result = await analyze({ root, config: c, facts, framework: { ...FRAMEWORK, readWorkflow: legacy } });
    assert.ok(result.errors.some((e) => e.area === 'framework' && /slack_notify_webhook/.test(e.message)));
    const unreadable = await analyze({ root, config: c, facts, framework: { ...FRAMEWORK, readWorkflow: async () => null } });
    assert.ok(unreadable.errors.some((e) => /could not be read/.test(e.message)), 'an unverifiable contract is an error, never a pass');
  });

  it('a Semgrep root that does not exist is an error, not a scan of nothing', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { semgrep: { roots: ['app'] } });
    assert.match((await cli(root, ['validate'])).out, /semgrep\.roots entry 'app' does not exist/);
  });

  // Repository identity is fail-closed: what the config claims must match what
  // git says, because render turns those two values into the branch filter and
  // the delivery condition. The fixture repository is github.com/acme/app with
  // origin/HEAD -> main.
  it('a configured default branch that is not the real one BLOCKS generation, so the branch that ships is never left ungated', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { repository: { defaultBranch: 'develop' } });

    const validate = await cli(root, ['validate']);
    assert.equal(validate.code, 1);
    assert.match(validate.out, /✗ \[repository\] repository\.defaultBranch is develop but origin\/HEAD is main/);
    assert.match(validate.out, /pull requests into the real default branch would not be scanned/);

    const render = await cli(root, ['render']);
    assert.equal(render.code, 1);
    assert.ok(!existsSync(join(root, '.github/workflows/security.yml')), 'no workflow is written');

    // The danger this blocks, stated exactly: the workflow this config WOULD
    // produce gates `develop` only, so every pull request into the real default
    // branch `main` would run no security checks at all.
    const wouldBe = parseYaml(renderSecurityWorkflow(config('source-only', { repository: { defaultBranch: 'develop' } })));
    assert.deepEqual(wouldBe.on.pull_request.branches, ['develop']);
    assert.ok(!wouldBe.on.pull_request.branches.includes('main'));
  });

  it('a configured slug that is not the origin BLOCKS generation', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { repository: { slug: 'acme/other' } });
    const validate = await cli(root, ['validate']);
    assert.equal(validate.code, 1);
    assert.match(validate.out, /✗ \[repository\] repository\.slug is acme\/other but origin points at acme\/app/);
    assert.equal((await cli(root, ['render'])).code, 1);
    assert.ok(!existsSync(join(root, '.github/workflows/security.yml')));
  });

  // Fail-closed, not fact-inventing: with no GitHub origin git knows nothing
  // about identity, and an unknown fact must not block or overrule the config.
  it('an unknown git fact does not block: identity is never invented', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', { repository: { slug: 'acme/other', defaultBranch: 'develop' } });
    const facts = await inspectRepository(root);
    const blind = { ...facts, git: { ...facts.git, slug: null, defaultBranch: null } };
    const result = await analyze({ root, config: config('source-only', { repository: { slug: 'acme/other', defaultBranch: 'develop' } }), facts: blind, framework: FRAMEWORK });
    assert.deepEqual(result.errors.filter((e) => e.area === 'repository'), []);
  });
});

describe('the baseline state machine', () => {
  // A repository at the start of onboarding, rendered and committed — the
  // state a real bootstrap run would scan.
  async function onboardingRepo(t, overrides = {}) {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only', overrides);
    assert.equal((await cli(root, ['render'])).code, 0);
    commitAll(root, 'onboard');
    return root;
  }

  function fakeGh(root, { runOverrides = {}, artifact = {}, artifactFor = null } = {}) {
    const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    const files = { ...bootstrapArtifact(root, cfg, artifactFor ?? {}), ...artifact };
    delete files.provenance;
    const run = {
      id: 4242, html_url: 'https://github.com/acme/app/actions/runs/4242', event: 'workflow_dispatch', status: 'completed',
      conclusion: 'success',
      head_branch: 'main', head_sha: head(root), path: '.github/workflows/security.yml', ...runOverrides
    };
    const calls = [];
    const gh = async (args) => {
      calls.push(args);
      if (args[0] === 'api') {
        return JSON.stringify(run);
      }
      const dir = args[args.indexOf('--dir') + 1];
      for (const [name, content] of Object.entries(files)) {
        if (content !== null) {
          write(dir, name, content);
        }
      }
      return '';
    };
    return { gh, calls };
  }

  async function candidateRepo(t, overrides) {
    const root = await onboardingRepo(t, overrides);
    const prepared = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh: fakeGh(root).gh });
    assert.equal(prepared.code, 0, prepared.err);
    return root;
  }

  const accept = (root, io = {}) => cli(root, ['baseline', 'accept', '--yes', '--expect-findings', '2'], io);

  it('walks onboarding -> candidate -> accepted -> enforcing, explicitly at each step', async (t) => {
    const root = await onboardingRepo(t);
    assert.match((await cli(root, ['baseline', 'status'])).out, /Rollout state: onboarding/);
    assert.match((await cli(root, ['baseline', 'prepare'])).out, /gh workflow run security\.yml --repo acme\/app --ref main -f bootstrap_baseline=true/);

    const { gh, calls } = fakeGh(root);
    const prepared = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh });
    assert.equal(prepared.code, 0, prepared.err);
    assert.deepEqual(calls.map((c) => c.slice(0, 2)), [['api', 'repos/acme/app/actions/runs/4242'], ['run', 'download']]);
    assert.ok(existsSync(join(root, CANDIDATE_FILE)) && existsSync(join(root, CANDIDATE_PROVENANCE)));
    assert.ok(!existsSync(join(root, 'security/baseline/semgrep-baseline.json')), 'prepare never writes the baseline');
    assert.match((await cli(root, ['baseline', 'status'])).out, /candidate-downloaded/);

    const wrongCount = await cli(root, ['baseline', 'accept'], { prompter: scriptedPrompter({ confirmFindings: '3' }) });
    assert.equal(wrongCount.code, 1, 'a mistyped count accepts nothing');
    assert.ok(!existsSync(join(root, 'security/baseline/semgrep-baseline.json')));

    const accepted = await cli(root, ['baseline', 'accept'], { prompter: scriptedPrompter({ confirmFindings: '2' }) });
    assert.equal(accepted.code, 0, accepted.err + accepted.out);
    assert.match(accepted.out, /bound to this checkout/);
    assert.match(accepted.out, /tests\/test_app\.py/, 'every finding is shown');
    assert.equal(read(root, 'security/baseline/semgrep-baseline.json'), JSON.stringify(SAMPLE_BASELINE, null, 2));
    assert.ok(!existsSync(join(root, CANDIDATE_FILE)));
    const afterAccept = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    assert.equal(afterAccept.semgrep.baseline.state, 'accepted');
    assert.match(afterAccept.semgrep.baseline.acceptedScope, /^[0-9a-f]{64}$/);
    assert.equal(afterAccept.rollout.gateMode, 'log-only', 'accepting a baseline does not silently enforce');
    assert.ok(!('workflow_dispatch' in parseYaml(read(root, '.github/workflows/security.yml')).on), 'the bootstrap input is removed once accepted');
    assert.equal((await cli(root, ['render', '--check'])).code, 0);

    // No answer at all must mean "no": there is no yes-default.
    const declined = await cli(root, ['promote', '--enforce'], { prompter: scriptedPrompter({}) });
    assert.equal(declined.code, 1);
    assert.equal(parseConfig(read(root, '.ssd/onboarding.yml')).config.rollout.gateMode, 'log-only');
    const promoted = await cli(root, ['promote', '--enforce', '--yes']);
    assert.equal(promoted.code, 0, promoted.err);
    assert.match(promoted.out, /-\s+gate_mode: log-only\n\+\s+gate_mode: enforce/);
    assert.match((await cli(root, ['baseline', 'status'])).out, /Rollout state: enforcing/);
  });

  it('non-interactive accept needs --yes AND the exact finding count', async (t) => {
    const root = await candidateRepo(t);
    assert.equal((await cli(root, ['baseline', 'accept', '--yes'])).code, 1);
    assert.equal((await cli(root, ['baseline', 'accept', '--yes', '--expect-findings', '5'])).code, 1);
    assert.equal((await accept(root)).code, 0);
  });

  // Mutation tests: change exactly one input the candidate is bound to, after
  // the candidate was produced. Every one must make acceptance fail.
  const bindingMutations = [
    ['the HEAD commit', async (root) => { write(root, 'src/new.py', 'eval(x)\n'); commitAll(root, 'new commit'); }, /HEAD is .* but the candidate was scanned at/],
    ['uncommitted changes to tracked files', async (root) => { write(root, 'src/app.py', 'eval(y)\n'); }, /uncommitted changes to tracked files/],
    ['the Semgrep configs', async (root) => { writeConfig(root, 'source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/python', 'p/secrets'] } }); commitAll(root); }, /Semgrep configs/],
    ['the Semgrep scan paths', async (root) => { writeConfig(root, 'source-only', { semgrep: { roots: ['src'] } }); commitAll(root); }, /Semgrep paths/],
    [
      '.semgrepignore (changed through the config, re-rendered and committed)',
      async (root) => {
        writeConfig(root, 'source-only', { semgrep: { ignore: { managed: true, patterns: ['dist/'] } } });
        assert.equal((await cli(root, ['render'])).code, 0);
        commitAll(root);
      },
      /\.semgrepignore differs from the scan/
    ],
    [
      'the framework ref',
      async (root) => { writeConfig(root, 'source-only', { framework: { ref: 'f'.repeat(40) } }); commitAll(root); },
      /the scan ran framework .*@068303774554/,
      { framework: { ...FRAMEWORK, sha: 'f'.repeat(40) } }
    ]
  ];
  for (const [label, mutate, pattern, io] of bindingMutations) {
    it(`accept refuses when ${label} changed after the scan`, async (t) => {
      const root = await candidateRepo(t);
      await mutate(root);
      const result = await accept(root, io);
      assert.equal(result.code, 1, `${label}: ${result.out}`);
      assert.match(result.err + result.out, pattern);
      assert.ok(!existsSync(join(root, 'security/baseline/semgrep-baseline.json')));
    });
  }

  it('a candidate can never overwrite an accepted or existing baseline', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, 'security/baseline/semgrep-baseline.json': JSON.stringify(SAMPLE_BASELINE) });
    writeConfig(root, 'source-only', { semgrep: { baseline: { state: 'accepted' } } });
    const prepared = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh: fakeGh(root).gh });
    assert.equal(prepared.code, 1);
    assert.match(prepared.err, /candidate can never replace it/);

    const root2 = await candidateRepo(t);
    write(root2, 'security/baseline/semgrep-baseline.json', '{"schemaVersion":1,"findings":[]}');
    const result = await accept(root2);
    assert.equal(result.code, 1);
    assert.equal(read(root2, 'security/baseline/semgrep-baseline.json'), '{"schemaVersion":1,"findings":[]}');
  });

  // The repository identity binding, in both places it now holds. A configured
  // slug that disagrees with origin is a blocking analysis error since identity
  // is fail-closed, so the CLI never reaches acceptance with one — which is why
  // the binding itself is asserted directly, on the code path `accept` uses.
  it('accept refuses when the repository identity changed after the scan', async (t) => {
    const root = await candidateRepo(t);
    const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    const elsewhere = { ...cfg, repository: { ...cfg.repository, slug: 'acme/other' } };
    await assert.rejects(
      loadCandidateForAcceptance({ root, config: elsewhere, consumer: { head: head(root), clean: true, slug: 'acme/other', semgrepignoreSha256: null } }),
      /scanned in acme\/app, not acme\/other/
    );

    writeConfig(root, 'source-only', { repository: { slug: 'acme/other' } });
    commitAll(root);
    const result = await accept(root);
    assert.equal(result.code, 1, result.out);
    assert.match(result.out, /repository\.slug is acme\/other but origin points at acme\/app/);
    assert.ok(!existsSync(join(root, 'security/baseline/semgrep-baseline.json')));
  });

  it('loadCandidateForAcceptance itself refuses when the baseline path exists (independently of other checks)', async (t) => {
    const root = await candidateRepo(t);
    write(root, 'security/baseline/semgrep-baseline.json', '{}');
    const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    await assert.rejects(
      loadCandidateForAcceptance({ root, config: cfg, consumer: { head: head(root), clean: true, slug: 'acme/app', semgrepignoreSha256: null } }),
      /refusing to overwrite a baseline/
    );
  });

  const tamper = (root, provenance) => ({ 'semgrep-baseline.candidate.provenance.json': JSON.stringify(provenance) });
  for (const [label, options, pattern] of [
    ['a pull_request (diff-aware) run', { runOverrides: { event: 'pull_request' } }, /diff-aware/],
    ['a push run', { runOverrides: { event: 'push' } }, /diff-aware/],
    ['a scheduled run', { runOverrides: { event: 'schedule' } }, /Only a full-tree workflow_dispatch/],
    ['a run of another workflow', { runOverrides: { path: '.github/workflows/other.yml' } }, /not \.github\/workflows\/security\.yml/],
    ['a run on another branch', { runOverrides: { head_branch: 'feature' } }, /not the default branch/],
    ['an unfinished run', { runOverrides: { status: 'in_progress' } }, /has not completed/],
    ['a completed run that failed', { runOverrides: { conclusion: 'failure' } }, /completed with conclusion 'failure', not 'success'/],
    ['a cancelled run', { runOverrides: { conclusion: 'cancelled' } }, /completed with conclusion 'cancelled', not 'success'/],
    ['a timed-out run', { runOverrides: { conclusion: 'timed_out' } }, /completed with conclusion 'timed_out', not 'success'/],
    ['a run whose conclusion GitHub does not report', { runOverrides: { conclusion: undefined } }, /completed with conclusion 'undefined', not 'success'/],
    ['a run whose commit differs from the provenance', { runOverrides: { head_sha: 'd'.repeat(40) } }, /but the provenance records/],
    ['a run flagged DO-NOT-BASELINE', { artifact: { 'DO-NOT-BASELINE.txt': 'untrusted' } }, /DO-NOT-BASELINE/],
    ['an untrusted scan', { artifact: { 'security-gate.json': JSON.stringify({ integrity: { trusted: false }, bootstrap: { active: true } }) } }, /integrity\.trusted/],
    ['a candidate with no provenance (a framework without it)', { artifact: { 'semgrep-baseline.candidate.provenance.json': null } }, /no provenance record/],
    ['a candidate whose bytes differ from its provenance', { artifact: { 'semgrep-baseline.candidate.json': JSON.stringify({ ...SAMPLE_BASELINE, findings: SAMPLE_BASELINE.findings.slice(0, 1) }) } }, /sha256 mismatch/],
    ['provenance edited after the fact', { artifactFor: {} , tamperWith: (p) => ({ ...p, scan: { ...p.scan, event: 'workflow_dispatch', commit: 'a'.repeat(40) } }) }, /digest does not match/],
    ['provenance from a pull_request scan (even if re-digested)', { artifactFor: { env: { CI_EVENT: 'pull_request' } } }, /came from a 'pull_request' run/],
    ['provenance from another branch', { artifactFor: { env: { CI_REF: 'refs/heads/feature' } } }, /only the default branch/],
    ['a candidate generated with other rulesets', { artifactFor: { candidate: { ...SAMPLE_BASELINE, rulesets: ['p/owasp-top-ten'] } } }, /never saw the configured rules/]
  ]) {
    it(`prepare refuses ${label}`, async (t) => {
      const root = await onboardingRepo(t);
      let fake = fakeGh(root, options);
      if (options.tamperWith) {
        const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
        const { provenance } = bootstrapArtifact(root, cfg);
        fake = fakeGh(root, { artifact: tamper(root, options.tamperWith(provenance)) });
      }
      const result = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh: fake.gh });
      assert.equal(result.code, 1, result.out);
      assert.match(result.err, pattern);
      assert.ok(!existsSync(join(root, CANDIDATE_FILE)));
    });
  }

  // The conclusion is a run fact, so it is judged before anything is fetched:
  // an artifact from a failed scan is never downloaded, let alone installed.
  for (const conclusion of ['failure', 'cancelled']) {
    it(`prepare refuses a completed/${conclusion} run BEFORE \`gh run download\``, async (t) => {
      const root = await onboardingRepo(t);
      const fake = fakeGh(root, { runOverrides: { conclusion } });
      const result = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh: fake.gh });
      assert.equal(result.code, 1, result.out);
      assert.match(result.err, new RegExp(`completed with conclusion '${conclusion}', not 'success'`));
      assert.deepEqual(fake.calls.map((c) => c.slice(0, 2)), [['api', 'repos/acme/app/actions/runs/4242']], 'the run was never downloaded');
      assert.ok(!existsSync(join(root, CANDIDATE_FILE)));
    });
  }

  it('prepare accepts completed/success and goes on to validate the artifact', async (t) => {
    const root = await onboardingRepo(t);
    const fake = fakeGh(root, { runOverrides: { conclusion: 'success' } });
    const result = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh: fake.gh });
    assert.equal(result.code, 0, result.err);
    assert.deepEqual(fake.calls.map((c) => c.slice(0, 2)), [['api', 'repos/acme/app/actions/runs/4242'], ['run', 'download']]);
    assert.ok(existsSync(join(root, CANDIDATE_FILE)));
  });

  it('accept refuses a candidate placed by hand, without verified provenance', async (t) => {
    const root = await onboardingRepo(t);
    write(root, CANDIDATE_FILE, JSON.stringify(SAMPLE_BASELINE));
    const result = await accept(root);
    assert.equal(result.code, 1);
    assert.match(result.err, /no provenance record/);
  });

  it('accept refuses a candidate whose file was swapped after prepare', async (t) => {
    const root = await candidateRepo(t);
    write(root, CANDIDATE_FILE, JSON.stringify({ ...SAMPLE_BASELINE, findings: [SAMPLE_BASELINE.findings[0]] }, null, 2));
    const result = await cli(root, ['baseline', 'accept', '--yes', '--expect-findings', '1']);
    assert.equal(result.code, 1);
    assert.match(result.err, /sha256 mismatch/);
  });

  it('a baseline can hold Semgrep fingerprints only — no secret, dependency or image finding', (t) => {
    const smuggled = { ...SAMPLE_BASELINE, findings: [{ ...SAMPLE_BASELINE.findings[0], source: 'gitleaks', secret: 'x' }] };
    assert.ok(validateBaselineDocument(smuggled).some((e) => /unexpected fields/.test(e)));
    assert.ok(validateBaselineDocument({ ...SAMPLE_BASELINE, findings: [{ id: 'CVE-1', package: 'x' }] }).length > 0);
  });

  it('promote refuses a missing or invalid baseline', async (t) => {
    const missing = makeRepo(t, PY_REPO);
    writeConfig(missing, 'source-only');
    const r1 = await cli(missing, ['promote', '--enforce', '--yes']);
    assert.equal(r1.code, 1);
    assert.match(r1.err, /rollout state is 'onboarding'/);

    const invalid = makeRepo(t, { ...PY_REPO, 'security/baseline/semgrep-baseline.json': '{"schemaVersion":2}' });
    writeConfig(invalid, 'source-only', { semgrep: { baseline: { state: 'accepted' } } });
    const r2 = await cli(invalid, ['promote', '--enforce', '--yes']);
    assert.equal(r2.code, 1);
    assert.match(r2.err, /schemaVersion/);

    const gone = makeRepo(t, PY_REPO);
    writeConfig(gone, 'source-only', { semgrep: { baseline: { state: 'accepted' } } });
    const r3 = await cli(gone, ['promote', '--enforce', '--yes']);
    assert.equal(r3.code, 1);
    assert.match(r3.err, /is required and missing/);
    assert.equal(parseConfig(read(gone, '.ssd/onboarding.yml')).config.rollout.gateMode, 'log-only');
  });

  it('an inconsistent state (baseline on disk, config says absent) fails validation', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, 'security/baseline/semgrep-baseline.json': JSON.stringify(SAMPLE_BASELINE) });
    const state = await rolloutState(root, config('source-only'));
    assert.equal(state.name, 'inconsistent');
    writeConfig(root, 'source-only');
    assert.equal((await cli(root, ['validate'])).code, 1);
  });

  it('installCandidate never writes the baseline path', async (t) => {
    const root = await onboardingRepo(t);
    const dir = tempDir(t, 'ssd-artifact-');
    const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    const files = bootstrapArtifact(root, cfg);
    for (const name of ['security-gate.json', 'semgrep-baseline.candidate.json', 'semgrep-baseline.candidate.provenance.json']) {
      write(dir, name, files[name]);
    }
    await installCandidate({ root, config: cfg, artifactDir: dir, run: { id: 4242, head_sha: head(root), event: 'workflow_dispatch' } });
    assert.ok(!existsSync(join(root, 'security/baseline/semgrep-baseline.json')));
    assert.equal(read(root, '.ssd/candidates/.gitignore'), '*\n');
  });
});

describe('the generator is bound to the framework commit it generates for', () => {
  const bound = async (t, framework) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only');
    return cli(root, ['render'], { framework });
  };

  it('renders when the CLI checkout is clean and at framework.ref', async (t) => {
    assert.equal((await bound(t, FRAMEWORK)).code, 0);
  });

  for (const [label, framework, pattern] of [
    ['a different commit', { ...FRAMEWORK, sha: 'b'.repeat(40) }, /is not the commit this ssd-onboard runs from/],
    ['a dirty checkout', { ...FRAMEWORK, clean: false, dirtyPaths: ['onboarding/lib/render.mjs'] }, /uncommitted changes/],
    ['another framework repository', { ...FRAMEWORK, slug: 'someone/fork' }, /origin is someone\/fork/],
    ['an unknown commit (not a git checkout)', null, /cannot determine the framework commit/]
  ]) {
    it(`refuses to generate from ${label}`, async (t) => {
      const result = await bound(t, framework);
      assert.equal(result.code, 1);
      assert.match(result.out, pattern);
    });
  }

  it('detectFramework reports the commit, cleanliness and origin of a real checkout', async (t) => {
    const repo = makeRepo(t, { 'onboarding/cli.mjs': '// x\n', '.github/workflows/_source-security.yml': 'on:\n  workflow_call: {}\n' });
    const clean = await detectFramework(repo);
    assert.equal(clean.sha, head(repo));
    assert.equal(clean.clean, true);
    assert.equal(clean.slug, 'acme/app');
    assert.match(await clean.readWorkflow('_source-security.yml'), /workflow_call/);
    assert.equal(await clean.readWorkflow('../../etc/passwd'), null, 'only workflow file names are read');
    write(repo, 'onboarding/cli.mjs', '// edited\n');
    const dirty = await detectFramework(repo);
    assert.equal(dirty.clean, false);
    assert.deepEqual(dirty.dirtyPaths, ['onboarding/cli.mjs']);
    // The contract is the COMMITTED object, never the edited working tree.
    write(repo, '.github/workflows/_source-security.yml', 'edited: true\n');
    assert.match(await dirty.readWorkflow('_source-security.yml'), /workflow_call/);
    assert.equal(await detectFramework(tempDir(t, 'ssd-not-git-')), null);
  });
});

describe('Phase 1 makes no AWS calls and no GitHub mutations', () => {
  it('init, inspect, validate, render and baseline status never run aws or gh', async (t) => {
    const before = shimCalls().length;
    const root = makeRepo(t, { ...PY_REPO, Dockerfile: 'FROM scratch\n' });
    await cli(root, ['init', '--non-interactive', '--from', partial('container.yml', `profile: container-self-managed\nframework:\n  ref: ${REF}\n`)]);
    for (const args of [['inspect'], ['inspect', '--json'], ['validate'], ['render'], ['render', '--check'], ['baseline', 'status'], ['baseline', 'prepare']]) {
      await cli(root, args);
    }
    assert.deepEqual(shimCalls().slice(before), []);
  });

  it('the aws and github commands are not implemented and contact nothing', async (t) => {
    const before = shimCalls().length;
    const root = makeRepo(t, PY_REPO);
    for (const args of [['aws', 'doctor'], ['aws', 'apply'], ['github', 'apply']]) {
      const result = await cli(root, args);
      assert.equal(result.code, 2);
      assert.match(result.err, /not implemented/);
    }
    assert.deepEqual(shimCalls().slice(before), []);
  });

  it('the gh wrapper refuses every mutating command', async (t) => {
    const executed = [];
    const gh = ghReadOnly(async (args) => executed.push(args));
    for (const args of [
      ['secret', 'set', 'X'],
      ['variable', 'set', 'X'],
      ['workflow', 'run', 'security.yml'],
      ['api', '-X', 'PUT', 'repos/a/b'],
      ['api', '--method=POST', 'repos/a/b'],
      ['api', 'repos/a/b', '-f', 'x=y'],
      ['run', 'rerun', '1']
    ]) {
      await assert.rejects(gh(args), /no GitHub mutations/, args.join(' '));
    }
    await gh(['api', 'repos/a/b/actions/runs/1']);
    await gh(['run', 'download', '1', '--name', 'x']);
    assert.equal(executed.length, 2);
  });
});
