// `ssd-onboard onboard`: the one-command first-time path. It composes init,
// render, validate and doctor in process, and must keep every trust boundary
// those commands have: nothing is written unless the whole result validates and
// the operator said yes; the baseline stays absent and the gate log-only; no
// path is adopted or forced unless named; the framework binding and repository
// identity still refuse; AWS and GitHub are never contacted.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { after, describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { parseConfig } from '../onboarding/lib/config.mjs';
import { applyWrites, readMarker, withMarker } from '../onboarding/lib/files.mjs';
import { scriptedPrompter, terminalPrompter } from '../onboarding/lib/prompt.mjs';
import { parseYaml } from '../onboarding/lib/yaml.mjs';
import { ACCOUNT, DEPLOY_ROLE, FRAMEWORK, PUSH_ROLE, REF, capture, makeRepo, read, tempDir } from './support/onboarding-fixtures.mjs';

const PARTIALS = mkdtempSync(join(tmpdir(), 'ssd-onboard-partials-'));
const partial = (name, value) => {
  const path = join(PARTIALS, name);
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
};

// PATH shims that record any aws / gh invocation.
const SHIM_DIR = mkdtempSync(join(tmpdir(), 'ssd-onboard-shims-'));
const SHIM_LOG = join(SHIM_DIR, 'calls.log');
for (const tool of ['aws', 'gh']) {
  writeFileSync(join(SHIM_DIR, tool), `#!/bin/sh\necho "${tool} $*" >> "${SHIM_LOG}"\nexit 97\n`);
  chmodSync(join(SHIM_DIR, tool), 0o755);
}
const ORIGINAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${ORIGINAL_PATH}`;
after(() => {
  process.env.PATH = ORIGINAL_PATH;
  for (const dir of [PARTIALS, SHIM_DIR]) {
    rmSync(dir, { recursive: true, force: true });
  }
});
const shimCalls = () => (existsSync(SHIM_LOG) ? readFileSync(SHIM_LOG, 'utf8').trim().split('\n').filter(Boolean) : []);

const PY_REPO = {
  'src/app.py': 'print("hi")\n',
  'tests/test_app.py': 'def test(): pass\n',
  'requirements.txt': 'requests==2.32.5\n'
};
const SECURITY = '.github/workflows/security.yml';
const CONFIG = '.ssd/onboarding.yml';
const SOURCE_ONLY = { profile: 'source-only', framework: { ref: REF } };
const ANSWERS = { frameworkRef: REF, profile: 'source-only', writeOnboarding: true };

async function cli(root, args, io = {}) {
  const c = capture();
  const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io, ...io });
  return { code, out: c.text(), err: c.errors() };
}

const onboard = (root, answers = ANSWERS, io = {}, extra = []) => cli(root, ['onboard', ...extra], { prompter: scriptedPrompter(answers), ...io });
const onboardFrom = (root, value, extra = [], io = {}) => cli(root, ['onboard', '--non-interactive', '--from', partial(`p-${Math.random()}.json`, value), ...extra], io);

// Every file under root except .git, with its bytes: "nothing was written" is
// checked against this, not against a guess about which files might appear.
function snapshot(root) {
  const out = {};
  const walk = (dir, prefix) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === '.git') {
        continue;
      }
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(join(dir, entry.name), rel);
      } else {
        out[rel] = entry.isSymbolicLink() ? '<symlink>' : readFileSync(join(dir, entry.name), 'utf8');
      }
    }
  };
  walk(root, '');
  return out;
}

const gitStatus = (root) => execFileSync('git', ['-C', root, 'status', '--porcelain', '--untracked-files=all']).toString();
const doctorJson = async (root) => JSON.parse((await cli(root, ['doctor', '--json'])).out);
const status = (report, id) => report.checks.find((c) => c.id === id)?.status;

describe('onboard: a fresh source-only repository', () => {
  it('writes the config, the security workflow and an explicit .semgrepignore, in the onboarding state', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const calls = shimCalls().length;
    const { code, out, err } = await onboard(root);
    assert.equal(code, 0, `${out}\n${err}`);

    const { config, errors } = parseConfig(read(root, CONFIG));
    assert.deepEqual(errors, []);
    assert.equal(config.profile, 'source-only');
    assert.equal(config.semgrep.baseline.state, 'absent');
    assert.equal(config.rollout.gateMode, 'log-only');
    assert.equal(config.breakGlass.mode, 'disabled');
    assert.equal(config.framework.ref, REF);
    assert.ok(!existsSync(join(root, config.semgrep.baseline.path)), 'no baseline is created');
    assert.ok(!existsSync(join(root, '.ssd/candidates')), 'no candidate is created');
    assert.ok(!existsSync(join(root, '.github/workflows/deploy.yml')));

    const ignore = read(root, '.semgrepignore');
    assert.ok(readMarker(ignore).intact, '.semgrepignore is an explicit generated file');

    const text = read(root, SECURITY);
    assert.ok(readMarker(text).intact);
    const doc = parseYaml(text);
    assert.ok(!Object.hasOwn(doc.on, 'pull_request_target'), 'never pull_request_target');
    const source = doc.jobs['source-security'];
    assert.equal(source.uses, `IamRitz/ssd-security-framework/.github/workflows/_source-scan.yml@${REF}`);
    assert.equal(source.with.gate_mode, 'log-only');
    assert.equal(source.with.semgrep_baseline_state, 'absent');
    assert.equal(source.with.break_glass_enabled, false);
    for (const [id, job] of Object.entries(doc.jobs)) {
      assert.notEqual(job.secrets, 'inherit', `${id} must not pass secrets: inherit`);
      assert.ok(!(job.permissions && job.permissions['id-token']), `${id} must not hold id-token`);
    }
    assert.ok(!(doc.permissions && doc.permissions['id-token']), 'no workflow-level id-token');

    assert.deepEqual(shimCalls().slice(calls), [], 'onboard runs neither aws nor gh');
    assert.equal((await cli(root, ['validate'])).code, 0, 'validate passes immediately');
    assert.equal((await cli(root, ['render', '--check'])).code, 0, 'render --check passes immediately');
  });

  it('doctor: no FAIL; baseline and gate mode WARN; governance NOT VERIFIED — and the output says so', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const { code, out } = await onboard(root);
    assert.equal(code, 0, out);
    const report = await doctorJson(root);
    assert.equal(report.counts.FAIL, 0);
    assert.equal(status(report, 'baseline'), 'WARN');
    assert.equal(status(report, 'gate-mode'), 'WARN');
    assert.equal(status(report, 'github-governance'), 'NOT VERIFIED');
    // No CODEOWNERS file: analyze warns, so at least WARN; never PASS.
    assert.equal(status(report, 'codeowners'), 'WARN');
    assert.equal(status(report, 'generated-files'), 'PASS');
    assert.equal(status(report, 'source-boundary'), 'PASS');
    assert.equal(status(report, 'framework-pin'), 'PASS');
    // The same projection is shown by onboard itself.
    assert.match(out, /Readiness:\nSSD Doctor — source-only/);
    assert.match(out, /Result: READY WITH WARNINGS \(0 FAIL/);
  });

  it('closes with the rollout state, NOT production-ready, and the existing lifecycle guidance', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const { code, out } = await onboard(root);
    assert.equal(code, 0, out);
    assert.match(out, /Onboarding generated successfully\.\nLocal validation passed/);
    assert.match(out, /Rollout state: onboarding\nThis repository is NOT production-ready yet/);
    assert.doesNotMatch(out, /production[- ]ready\.|is production-ready/i);
    // dispatchInstructions, not a second copy of the bootstrap procedure.
    assert.match(out, /gh workflow run security\.yml --repo acme\/app --ref main -f bootstrap_baseline=true/);
    assert.match(out, /ssd-onboard baseline prepare --run <run-id>/);
    assert.match(out, /Do not copy a candidate baseline into place by hand/);
    assert.match(out, /does not accept a baseline, enable enforcement, or configure GitHub/);
    assert.match(out, /Planned files:\n {2}CREATE {4}\.ssd\/onboarding\.yml\n {2}CREATE {4}\.github\/workflows\/security\.yml\n {2}CREATE {4}\.semgrepignore/);
  });

  it('non-interactive: the same result from a partial config, through init\'s path', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const { code, out } = await onboardFrom(root, SOURCE_ONLY);
    assert.equal(code, 0, out);
    const interactive = makeRepo(t, PY_REPO);
    assert.equal((await onboard(interactive)).code, 0);
    assert.equal(read(root, CONFIG), read(interactive, CONFIG), 'both modes produce the same config');
    assert.equal(read(root, SECURITY), read(interactive, SECURITY));
  });

  it('non-interactive refuses missing owner decisions and writes nothing', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, '.trufflehog-exclude-paths.txt': 'x\n' });
    const before = snapshot(root);
    const { code, err } = await onboardFrom(root, SOURCE_ONLY);
    assert.equal(code, 1);
    assert.match(err, /trufflehog\.excludePathsFile/);
    assert.match(err, /Nothing written/);
    assert.deepEqual(snapshot(root), before);
  });
});

describe('onboard: validity has one definition', () => {
  it('validate fails on drift alone — the generated state onboard relies on is the one validate checks', async (t) => {
    const root = makeRepo(t, PY_REPO);
    assert.equal((await onboard(root)).code, 0);
    rmSync(join(root, '.semgrepignore'));
    const { code, out } = await cli(root, ['validate', '--json']);
    const report = JSON.parse(out);
    assert.deepEqual(report.errors, [], 'no blocking error: only drift');
    assert.equal(report.drift, true);
    assert.equal(code, 1, 'drift alone fails validate');
    assert.equal((await cli(root, ['render', '--check'])).code, 1);
  });
});

describe('onboard: confirmation', () => {
  it('declining, or giving no answer at all, writes nothing (the default is no)', async (t) => {
    for (const answers of [{ ...ANSWERS, writeOnboarding: false }, { frameworkRef: REF, profile: 'source-only' }]) {
      const root = makeRepo(t, PY_REPO);
      const before = snapshot(root);
      const prompter = scriptedPrompter(answers);
      const { code, err } = await cli(root, ['onboard'], { prompter });
      assert.equal(code, 1);
      assert.match(err, /Nothing written\./);
      assert.ok(prompter.asked.includes('writeOnboarding'));
      assert.deepEqual(snapshot(root), before);
      assert.equal(gitStatus(root), '');
    }
  });

  it('the terminal prompt shows [y/N] and treats Enter as no', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let shown = '';
    output.on('data', (chunk) => (shown += chunk));
    const prompter = terminalPrompter({ input, output });
    const answer = prompter.confirm({ question: 'Write these onboarding files?', default: false });
    input.write('\n');
    assert.equal(await answer, false);
    prompter.close();
    assert.match(shown, /Write these onboarding files\? \[y\/N\]/);
  });
});

describe('onboard: the profile is an explicit owner decision', () => {
  it('Dockerfile present and no profile answer: no profile is inferred and nothing is written (onboard and init)', async (t) => {
    for (const command of ['onboard', 'init']) {
      const root = makeRepo(t, { ...PY_REPO, Dockerfile: 'FROM python:3.13-slim\n' });
      const before = snapshot(root);
      const prompter = scriptedPrompter({ frameworkRef: REF, writeOnboarding: true, writeConfig: true });
      const { code } = await cli(root, [command], { prompter });
      assert.equal(code, 1, command);
      assert.ok(prompter.asked.includes('profile'));
      assert.deepEqual(snapshot(root), before, `${command} wrote nothing`);
      assert.ok(prompter.said.some((line) => /does not mean this repository ships an image/.test(line)));
    }
  });

  it('the interview offers the profile with NO default, and an empty terminal answer re-asks', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, Dockerfile: 'FROM python:3.13-slim\n' });
    const seen = [];
    const spy = scriptedPrompter(ANSWERS);
    const choose = spy.choose;
    spy.choose = (question) => {
      seen.push(question);
      return choose(question);
    };
    assert.equal((await onboard(root, undefined, { prompter: spy })).code, 0);
    const profile = seen.find((q) => q.id === 'profile');
    assert.ok(profile && !Object.hasOwn(profile, 'default'), 'the profile question carries no default');

    // Each line is typed only once the prompt for it is shown, as a person would.
    const input = new PassThrough();
    const output = new PassThrough();
    const typed = ['', '', '1'];
    let prompts = 0;
    output.on('data', (chunk) => {
      if (String(chunk).startsWith('Choice')) {
        prompts += 1;
        input.write(`${typed.shift()}\n`);
      }
    });
    const prompter = terminalPrompter({ input, output });
    const answer = await prompter.choose({ question: 'Profile', choices: profile.choices });
    prompter.close();
    assert.equal(answer, 'source-only', 'empty input selected nothing; the explicit choice did');
    assert.equal(prompts, 3, 'asked again after each empty answer');
  });

  it('Dockerfile present with an explicit source-only choice: source-only stays selected', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, Dockerfile: 'FROM python:3.13-slim\n' });
    const { code, out } = await onboard(root);
    assert.equal(code, 0, out);
    const { config } = parseConfig(read(root, CONFIG));
    assert.equal(config.profile, 'source-only');
    assert.equal(config.container, undefined);
    const report = await doctorJson(root);
    assert.equal(status(report, 'container'), 'WARN', 'the Dockerfile is reported, not acted on');
    assert.equal(report.counts.FAIL, 0);
  });
});

describe('onboard: existing files are never silently overwritten', () => {
  const HUMAN_WORKFLOW = 'name: security\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hand-written\n';

  it('a human-owned security workflow: CONFLICT, zero files written, remediation names --adopt', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, [SECURITY]: HUMAN_WORKFLOW });
    const before = snapshot(root);
    const { code, out, err } = await onboard(root);
    assert.equal(code, 1);
    assert.match(out, /CONFLICT {2}\.github\/workflows\/security\.yml/);
    assert.match(err, /--adopt <path>/);
    assert.deepEqual(snapshot(root), before, 'not even the config is written');
  });

  it('--adopt <path>: the diff is shown and the write still needs a yes', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, [SECURITY]: HUMAN_WORKFLOW });
    const before = snapshot(root);
    const declined = await onboard(root, { frameworkRef: REF, profile: 'source-only' }, {}, ['--adopt', SECURITY]);
    assert.equal(declined.code, 1);
    assert.match(declined.out, /ADOPT {5}\.github\/workflows\/security\.yml/);
    assert.match(declined.out, /--- a\/\.github\/workflows\/security\.yml\n\+\+\+ b\/\.github\/workflows\/security\.yml/);
    assert.match(declined.out, /-      - run: echo hand-written/);
    assert.deepEqual(snapshot(root), before);

    const accepted = await onboard(root, ANSWERS, {}, ['--adopt', SECURITY]);
    assert.equal(accepted.code, 0, accepted.err);
    assert.ok(readMarker(read(root, SECURITY)).intact, 'adopted: now generated');
  });

  it('non-interactive --adopt is honoured for exactly the named path', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, [SECURITY]: HUMAN_WORKFLOW, '.semgrepignore': 'dist/\n' });
    const onlyOne = await onboardFrom(root, SOURCE_ONLY, ['--adopt', SECURITY]);
    assert.equal(onlyOne.code, 1, 'the unnamed .semgrepignore is still a conflict');
    assert.match(onlyOne.out, /CONFLICT {2}\.semgrepignore/);
    assert.ok(!existsSync(join(root, CONFIG)));
    assert.equal(read(root, SECURITY), HUMAN_WORKFLOW);
  });

  it('a hand-edited generated file needs --force <path>; --adopt does not stand in for it', async (t) => {
    const edited = `${withMarker('# old generated body\n')}# edited by hand\n`;
    const root = makeRepo(t, { ...PY_REPO, '.semgrepignore': edited });
    const before = snapshot(root);
    for (const extra of [[], ['--adopt', '.semgrepignore'], ['--force', SECURITY]]) {
      const { code, out } = await onboardFrom(root, { ...SOURCE_ONLY, semgrep: { ignore: { managed: true } } }, extra);
      assert.equal(code, 1, extra.join(' '));
      assert.match(out, /CONFLICT {2}\.semgrepignore/);
      assert.deepEqual(snapshot(root), before);
    }
    const forced = await onboard(root, { ...ANSWERS, manageSemgrepignore: true }, {}, ['--force', '.semgrepignore']);
    assert.equal(forced.code, 0, forced.err);
    assert.match(forced.out, /OVERWRITE \.semgrepignore/);
    assert.ok(readMarker(read(root, '.semgrepignore')).intact);
  });

  it('an existing .ssd/onboarding.yml: exit 1, nothing written, points to validate / doctor / render', async (t) => {
    const root = makeRepo(t, { ...PY_REPO, [CONFIG]: 'anything: at all\n' });
    const before = snapshot(root);
    const { code, err } = await onboard(root);
    assert.equal(code, 1);
    assert.match(err, /This repository already has \.ssd\/onboarding\.yml\. Nothing was written\./);
    assert.match(err, /ssd-onboard validate/);
    assert.match(err, /ssd-onboard doctor/);
    assert.match(err, /ssd-onboard render/);
    assert.match(err, /init --overwrite/);
    assert.deepEqual(snapshot(root), before);
  });

  it('a second onboard is deterministic: exit 1 and byte-for-byte nothing changes', async (t) => {
    const root = makeRepo(t, PY_REPO);
    assert.equal((await onboard(root)).code, 0);
    const before = snapshot(root);
    for (let i = 0; i < 2; i += 1) {
      const again = await onboard(root);
      assert.equal(again.code, 1);
      assert.match(again.err, /already has \.ssd\/onboarding\.yml/);
      assert.deepEqual(snapshot(root), before);
    }
  });
});

describe('onboard: refusals before any write', () => {
  it('a framework checkout at another commit, or dirty, is refused with zero writes', async (t) => {
    const other = { ...FRAMEWORK, sha: 'f'.repeat(40) };
    const dirty = { ...FRAMEWORK, clean: false, dirtyPaths: ['onboarding/lib/render.mjs'] };
    for (const [framework, pattern] of [[other, /is not the commit this ssd-onboard runs from/], [dirty, /has uncommitted changes/]]) {
      const root = makeRepo(t, PY_REPO);
      const before = snapshot(root);
      const { code, out, err } = await onboardFrom(root, SOURCE_ONLY, [], { framework });
      assert.equal(code, 1);
      assert.match(out, pattern);
      assert.match(err, /Nothing written/);
      assert.deepEqual(snapshot(root), before);
    }
  });

  it('a framework checkout that cannot be identified is refused', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const before = snapshot(root);
    const { code, out } = await onboardFrom(root, SOURCE_ONLY, [], { framework: null });
    assert.equal(code, 1);
    assert.match(out, /cannot determine the framework commit/);
    assert.deepEqual(snapshot(root), before);
  });

  it('a repository identity that is not the origin is refused (slug and default branch)', async (t) => {
    for (const [answers, pattern] of [
      [{ ...ANSWERS, slug: 'acme/other' }, /repository\.slug is acme\/other but origin points at acme\/app/],
      [{ ...ANSWERS, defaultBranch: 'develop' }, /repository\.defaultBranch is develop but origin\/HEAD is main/]
    ]) {
      const root = makeRepo(t, PY_REPO);
      const before = snapshot(root);
      const { code, out } = await onboard(root, answers);
      assert.equal(code, 1);
      assert.match(out, pattern);
      assert.deepEqual(snapshot(root), before);
    }
  });

  it('a coverage gap that blocks render blocks onboard, instead of writing a config that cannot render', async (t) => {
    // A nested package.json with dependencies and NO lockfile: scanned by nothing.
    const root = makeRepo(t, { ...PY_REPO, 'packages/web/package.json': '{"dependencies":{"x":"1"}}\n' });
    const before = snapshot(root);
    const { code, out } = await onboardFrom(root, SOURCE_ONLY);
    assert.equal(code, 1);
    assert.match(out, /UNSUPPORTED by the current framework/);
    assert.deepEqual(snapshot(root), before);
  });

  it('usage errors are exit 2', async (t) => {
    const root = makeRepo(t, PY_REPO);
    assert.equal((await cli(root, ['onboard', '--non-interactive'])).code, 2);
    assert.equal((await cli(root, ['onboard', '--from', 'x.yml'])).code, 2);
    assert.equal((await cli(root, ['onboard', '--overwrite'])).code, 2);
    assert.equal((await cli(root, ['onboard', '--bogus'])).code, 2);
    assert.ok(!existsSync(join(root, CONFIG)));
  });
});

describe('onboard: path confinement is proven before the first write', () => {
  it('a symlinked .github refuses the whole onboarding: no config, nothing outside the repository', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = tempDir(t);
    symlinkSync(outside, join(root, '.github'));
    const { code, err } = await onboardFrom(root, SOURCE_ONLY);
    assert.equal(code, 1);
    assert.match(err, /symbolic link/);
    assert.ok(!existsSync(join(root, CONFIG)), 'the config was not written first');
    assert.deepEqual(readdirSync(outside), []);
  });

  it('a symlinked .ssd refuses before anything is written', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = tempDir(t);
    symlinkSync(outside, join(root, '.ssd'));
    const { code, err } = await onboardFrom(root, SOURCE_ONLY);
    assert.equal(code, 1);
    assert.match(err, /symbolic link/);
    assert.deepEqual(readdirSync(outside), []);
    assert.ok(!existsSync(join(root, SECURITY)));
  });

  it('a workflow path escaping the repository is refused, and nothing is written', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const before = snapshot(root);
    const { code } = await onboardFrom(root, { ...SOURCE_ONLY, workflows: { security: '../../escape.yml' } });
    assert.equal(code, 1);
    assert.deepEqual(snapshot(root), before);
  });
});

describe('onboard: after writing, success is only what validate says', () => {
  it('a written state that no longer validates: exit 1, the validation report, the written files, no success', async (t) => {
    const root = makeRepo(t, PY_REPO);
    // The framework checkout becomes dirty between planning and the post-write
    // check: onboard must re-derive the truth, not reuse the plan's.
    let reads = 0;
    const framework = { ...FRAMEWORK, dirtyPaths: ['onboarding/lib/render.mjs'], get clean() { reads += 1; return reads <= 1; } };
    const { code, out, err } = await onboardFrom(root, SOURCE_ONLY, [], { framework });
    assert.equal(code, 1);
    assert.match(out, /ssd-onboard validate\n=+/);
    assert.match(out, /has uncommitted changes/);
    assert.match(err, /Onboarding did NOT complete: the written state does not validate/);
    assert.match(err, /\.ssd\/onboarding\.yml\n {2}\.github\/workflows\/security\.yml\n {2}\.semgrepignore/);
    assert.doesNotMatch(out, /successfully/);
  });

  it('an I/O failure part-way: exit 1, exactly what was written and what failed, and render finishes it', async (t) => {
    const root = makeRepo(t, PY_REPO);
    // A directory appears at the workflow path while the confirmation is open
    // (after planning, before writing). Opening a directory for writing fails
    // with EISDIR for every user, root included — a real OS error, no hook.
    const prompter = scriptedPrompter(ANSWERS);
    const confirm = prompter.confirm;
    prompter.confirm = async (question) => {
      const answer = await confirm(question);
      if (question.id === 'writeOnboarding') {
        mkdirSync(join(root, SECURITY), { recursive: true });
      }
      return answer;
    };
    const { code, out, err } = await cli(root, ['onboard'], { prompter });
    assert.equal(code, 1);
    assert.match(err, /writing \.github\/workflows\/security\.yml failed: EISDIR/);
    assert.match(err, /Onboarding did NOT complete\. Written \(nothing was rolled back\):\n {2}\.ssd\/onboarding\.yml\nOnce the cause is fixed, `ssd-onboard render` completes the generated files/);
    assert.doesNotMatch(`${out}\n${err}`, /successfully|Local validation passed/);
    assert.ok(existsSync(join(root, CONFIG)), 'the config is kept, not rolled back');
    assert.ok(!existsSync(join(root, '.semgrepignore')), 'the file after the failure was never attempted');

    // The guidance holds: once the cause is gone, render completes the state.
    rmSync(join(root, SECURITY), { recursive: true });
    assert.equal((await cli(root, ['render'])).code, 0);
    assert.equal((await cli(root, ['validate'])).code, 0);
  });
});

describe('applyWrites: a failed write reports exactly what landed', () => {
  it('A succeeds, B fails, C is not attempted: error.written = [A], error.failedPath = B', async (t) => {
    const root = tempDir(t);
    mkdirSync(join(root, 'b')); // opening a directory for writing: EISDIR, for root too
    const plan = [
      { path: 'a.txt', action: 'create', content: 'A\n' },
      { path: 'unchanged.txt', action: 'unchanged', content: 'U\n' },
      { path: 'b', action: 'create', content: 'B\n' },
      { path: 'c.txt', action: 'create', content: 'C\n' }
    ];
    const error = await applyWrites(root, plan).then(
      () => assert.fail('applyWrites must fail'),
      (e) => e
    );
    assert.equal(error.code, 'EISDIR');
    assert.deepEqual(error.written, ['a.txt'], 'only what was actually written; an unchanged entry is not a write');
    assert.equal(error.failedPath, 'b');
    assert.equal(readFileSync(join(root, 'a.txt'), 'utf8'), 'A\n');
    assert.ok(!existsSync(join(root, 'c.txt')), 'C was not attempted');
  });

  it('a confinement refusal carries the same metadata', async (t) => {
    const root = tempDir(t);
    const outside = tempDir(t);
    symlinkSync(outside, join(root, 'link'));
    const error = await applyWrites(root, [
      { path: 'a.txt', action: 'create', content: 'A\n' },
      { path: 'link/b.txt', action: 'create', content: 'B\n' }
    ]).then(() => assert.fail('applyWrites must fail'), (e) => e);
    assert.equal(error.code, 'ERR_PATH_NOT_CONFINED');
    assert.deepEqual(error.written, ['a.txt']);
    assert.equal(error.failedPath, 'link/b.txt');
    assert.deepEqual(readdirSync(outside), []);
  });
});

describe('the shared interview names the command it runs under', () => {
  it('init says init, onboard says onboard, and both ask exactly the same questions', async (t) => {
    const transcripts = {};
    for (const command of ['init', 'onboard']) {
      const root = makeRepo(t, PY_REPO);
      const prompter = scriptedPrompter({ ...ANSWERS, writeConfig: true });
      assert.equal((await cli(root, [command], { prompter })).code, 0, command);
      transcripts[command] = prompter;
    }
    assert.equal(transcripts.init.said[0], 'ssd-onboard init — answers are recorded in .ssd/onboarding.yml (non-secret).');
    assert.equal(transcripts.onboard.said[0], 'ssd-onboard onboard — answers are recorded in .ssd/onboarding.yml (non-secret).');
    assert.ok(!transcripts.onboard.said.some((line) => /ssd-onboard init\b/.test(line)), 'onboard never presents itself as init');
    const questions = (p) => p.asked.filter((id) => !['writeConfig', 'writeOnboarding'].includes(id));
    assert.deepEqual(questions(transcripts.onboard), questions(transcripts.init));
    assert.deepEqual(transcripts.onboard.said.slice(1), transcripts.init.said.slice(1), 'only the header differs');
  });
});

describe('onboard: container profiles', () => {
  const DOCKER = { ...PY_REPO, Dockerfile: 'FROM python:3.13-slim\n' };

  it('container-self-managed: container scanning, no AWS question, field, workflow or call', async (t) => {
    const root = makeRepo(t, DOCKER);
    const calls = shimCalls().length;
    const prompter = scriptedPrompter({ ...ANSWERS, profile: 'container-self-managed' });
    const { code, out } = await cli(root, ['onboard'], { prompter });
    assert.equal(code, 0, out);
    assert.ok(!prompter.asked.some((id) => /^aws|Role|instanceId|ecr/.test(id)), 'no AWS questions');
    const { config } = parseConfig(read(root, CONFIG));
    assert.equal(config.profile, 'container-self-managed');
    assert.equal(config.delivery, undefined);
    assert.equal(config.rollout.gateMode, 'log-only');
    assert.ok(!existsSync(join(root, '.github/workflows/deploy.yml')));
    assert.doesNotMatch(read(root, SECURITY), /aws-actions|role-to-assume/);
    assert.match(out, /AWS\/OIDC: {10}not used/);
    assert.deepEqual(shimCalls().slice(calls), []);
    assert.equal((await doctorJson(root)).counts.FAIL, 0);
  });

  it('container-ecr-framework-gated: identifiers recorded, nothing probed, AWS readiness NOT VERIFIED', async (t) => {
    const root = makeRepo(t, DOCKER);
    const calls = shimCalls().length;
    const { code, out } = await onboardFrom(root, {
      profile: 'container-ecr-framework-gated',
      framework: { ref: REF },
      delivery: {
        aws: { accountId: ACCOUNT, region: 'us-east-1' },
        roles: { pushScanRoleArn: PUSH_ROLE, deployRoleArn: DEPLOY_ROLE },
        ssm: { instanceId: 'i-0123456789abcdef0' }
      }
    });
    assert.equal(code, 0, out);
    assert.deepEqual(shimCalls().slice(calls), [], 'no aws or gh call');
    assert.match(out, /NOT contacted or verified/);
    const { config } = parseConfig(read(root, CONFIG));
    assert.equal(config.rollout.gateMode, 'log-only');
    assert.equal(config.semgrep.baseline.state, 'absent');
    assert.ok(!existsSync(join(root, '.github/workflows/deploy.yml')), 'no delivery workflow while log-only');
    const report = await doctorJson(root);
    assert.equal(status(report, 'aws-delivery'), 'NOT VERIFIED');
    assert.equal(report.counts.FAIL, 0);
  });
});
