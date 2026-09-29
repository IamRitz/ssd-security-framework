// The developer-facing guidance after a baseline bootstrap run. Executes the REAL
// `run:` scripts of both source workflows and pins the YAML wiring they depend on.
//
// The guidance is wording only — no trust decision rests on it — but it is the
// onboarding funnel: it must link the run (and, when upload-artifact reports it,
// the artifact), and send the developer through `ssd-onboard baseline prepare`
// / `baseline accept`, which verify provenance. It must never suggest copying
// the candidate into place by hand, and a non-bootstrap run must not show it.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, describe, it } from 'node:test';

import { parseYaml } from '../onboarding/lib/yaml.mjs';
import { renderSourceScan } from '../tools/render-source-scan.mjs';
import { stepScript } from './support/workflow-steps.mjs';

const FRAMEWORK = resolve('.');
const WORKFLOWS = join(FRAMEWORK, '.github/workflows');
const GUIDANCE = 'Explain the next baseline step (bootstrap only)';
const GENERATE = 'Generate the first Semgrep baseline (bootstrap only)';
const UPLOAD = 'Upload security gate decision';
const REFUSE = 'Refuse baseline bootstrap from a diff-aware scan';

const RUN_ID = '36315186238';
const RUN_URL = `https://github.com/acme/app/actions/runs/${RUN_ID}`;
const ARTIFACT_URL = `${RUN_URL}/artifacts/10930626377`;
const TOOLKIT_REF = 'b'.repeat(40);
const SENTINEL = 'ghs_SENTINELtokenMUSTnotLEAK';

const WORK = mkdtempSync(join(tmpdir(), 'bootstrap-guidance-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

function runGuidance(file, env = {}) {
  const summary = join(WORK, `summary-${Math.random().toString(36).slice(2)}`);
  writeFileSync(summary, '');
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript(join(WORKFLOWS, file), GUIDANCE)], {
    cwd: WORK,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'acme/app',
      GITHUB_RUN_ID: RUN_ID,
      // Present in a real job's environment; must never reach the summary.
      GITHUB_TOKEN: SENTINEL,
      ACTIONS_RUNTIME_TOKEN: SENTINEL,
      ARTIFACT_URL,
      BASELINE_PATH: 'security/baseline/semgrep-baseline.json',
      BASELINE_STATE: 'absent',
      TOOLKIT_REPOSITORY: 'IamRitz/ssd-security-framework',
      TOOLKIT_REF,
      ...env
    }
  });
  return { code: result.status, out: `${result.stdout}${result.stderr}`, summary: readFileSync(summary, 'utf8') };
}

const lines = (text) => text.split('\n');

for (const file of ['_source-security.yml', '_source-scan.yml']) {
  describe(`${file}: bootstrap guidance`, () => {
    it('links the run and the artifact, names security-gate-results, and gives the prepare command', () => {
      const { code, out, summary } = runGuidance(file);
      assert.equal(code, 0, out);
      assert.match(summary, /^## Semgrep baseline candidate generated$/m);
      assert.ok(lines(summary).includes(RUN_URL), summary);
      assert.ok(lines(summary).includes(ARTIFACT_URL), summary);
      assert.match(summary, /`security-gate-results`/);
      assert.ok(lines(summary).includes(`ssd-onboard baseline prepare --run ${RUN_ID}`), summary);
      assert.match(summary, /downloads and verifies the candidate and its provenance/);
      assert.match(summary, /review the candidate before running `ssd-onboard baseline accept`/);
      assert.doesNotMatch(summary, /not managed by ssd-onboard/, 'an ssd-onboard caller gets no adoption detour');
    });

    it('never offers a manual copy/commit of the candidate as the path', () => {
      const { summary } = runGuidance(file);
      assert.doesNotMatch(summary, /commit/i);
      assert.doesNotMatch(summary, /download the/i);
      // The only mention of copying is the warning against it.
      const copying = lines(summary).filter((line) => /\bcop(y|ied|ying)\b/i.test(line));
      assert.deepEqual(copying, ['Do not copy the candidate into place by hand — that skips the provenance checks.']);
    });

    it('never renders a token from the job environment', () => {
      const { summary } = runGuidance(file);
      assert.ok(!summary.includes(SENTINEL));
      for (const url of summary.match(/https?:\/\/\S+/g)) {
        assert.doesNotMatch(url, /token|[?&]|@/i, `${url} carries no credential or query`);
      }
    });

    it('without an artifact-url output: links the run and says the upload did not report an artifact', () => {
      const { code, summary } = runGuidance(file, { ARTIFACT_URL: '' });
      assert.equal(code, 0);
      assert.ok(lines(summary).includes(RUN_URL));
      assert.doesNotMatch(summary, /\/artifacts\//);
      assert.match(summary, /The artifact upload did not report an artifact/);
      assert.ok(lines(summary).includes(`ssd-onboard baseline prepare --run ${RUN_ID}`));
    });

    for (const [label, value] of [
      ['a non-https value', 'javascript:alert(1)'],
      ['a value with an embedded newline', `${ARTIFACT_URL}\nrun: curl evil`],
      ['a value with a space', `${ARTIFACT_URL} extra`]
    ]) {
      it(`an unexpected artifact-url (${label}) is not rendered; the run link stands`, () => {
        const { summary } = runGuidance(file, { ARTIFACT_URL: value });
        assert.ok(!summary.includes(value));
        assert.doesNotMatch(summary, /javascript:|curl evil|extra/);
        assert.ok(lines(summary).includes(RUN_URL));
        assert.match(summary, /did not report an artifact/);
      });
    }

    it('a legacy caller (no semgrep_baseline_state) is pointed at adoption, at the pinned framework ref', () => {
      const { summary } = runGuidance(file, { BASELINE_STATE: '' });
      assert.match(summary, /not managed by ssd-onboard yet/);
      assert.ok(
        lines(summary).includes(`https://github.com/IamRitz/ssd-security-framework/blob/${TOOLKIT_REF}/docs/onboarding-cli.md#from-a-hand-copied-example`),
        summary
      );
      assert.ok(lines(summary).includes(`ssd-onboard baseline prepare --run ${RUN_ID}`));
      assert.doesNotMatch(summary, /commit/i);
    });

    it('the diff-aware bootstrap refusal links the bootstrap docs at the pinned framework ref', () => {
      const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', stepScript(join(WORKFLOWS, file), REFUSE)], {
        cwd: WORK,
        encoding: 'utf8',
        env: {
          PATH: process.env.PATH,
          EVENT_NAME: 'pull_request',
          GITHUB_SERVER_URL: 'https://github.com',
          TOOLKIT_REPOSITORY: 'IamRitz/ssd-security-framework',
          TOOLKIT_REF
        }
      });
      assert.equal(result.status, 1, 'still refuses');
      assert.ok(
        result.stderr.includes(`https://github.com/IamRitz/ssd-security-framework/blob/${TOOLKIT_REF}/docs/onboarding.md#11-bootstrap-the-first-semgrep-baseline`),
        result.stderr
      );
    });

    // ---- the wiring the script relies on ----------------------------------------

    const steps = parseYaml(readFileSync(join(WORKFLOWS, file), 'utf8')).jobs['source-gate'].steps;
    const index = (name) => steps.findIndex((s) => s.name === name);

    it('reads the artifact URL from the upload step\'s documented output, after the upload', () => {
      const upload = steps[index(UPLOAD)];
      const guidance = steps[index(GUIDANCE)];
      assert.equal(upload.id, 'gate-artifact');
      assert.match(upload.uses, /^actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\b/, 'the pin whose action.yml declares artifact-url');
      assert.equal(upload.with.name, 'security-gate-results');
      assert.equal(guidance.env.ARTIFACT_URL, '${{ steps.gate-artifact.outputs.artifact-url }}');
      assert.ok(index(GENERATE) < index(UPLOAD) && index(UPLOAD) < index(GUIDANCE), 'generate -> upload -> guidance');
      assert.ok(index(GUIDANCE) < index('Enforce the gate verdict'), 'written before the job can fail on the verdict');
    });

    it('is shown only when THIS run generated a candidate (never on a normal run)', () => {
      const generate = steps[index(GENERATE)];
      const guidance = steps[index(GUIDANCE)];
      assert.equal(generate.id, 'bootstrap-candidate');
      assert.match(generate.if, /inputs\.bootstrap_baseline && steps\.verdict\.outputs\.integrity_trusted == 'true'/, 'generation guard unchanged');
      assert.equal(guidance.if, "${{ always() && inputs.bootstrap_baseline && steps.bootstrap-candidate.outcome == 'success' }}");
      // The generation step writes files only; no other step carries acceptance guidance.
      assert.doesNotMatch(generate.run, /GITHUB_STEP_SUMMARY/);
      const guiding = steps.filter((s) => /ssd-onboard baseline (prepare|accept)\b/.test(s.run ?? '')).map((s) => s.name);
      assert.deepEqual(guiding, [GUIDANCE]);
    });

    it('uses no secret and no token', () => {
      const guidance = steps[index(GUIDANCE)];
      const text = JSON.stringify(guidance);
      assert.doesNotMatch(text, /secrets\.|github\.token|GITHUB_TOKEN/);
      assert.equal(guidance.permissions, undefined);
    });
  });
}

describe('_source-scan.yml', () => {
  it('is exactly the render of _source-security.yml', () => {
    assert.equal(readFileSync(join(WORKFLOWS, '_source-scan.yml'), 'utf8'), renderSourceScan(readFileSync(join(WORKFLOWS, '_source-security.yml'), 'utf8')));
  });
});
