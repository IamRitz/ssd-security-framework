#!/usr/bin/env node
// Mutation check for the onboarding security invariants.
//
// A test suite that stays green when an invariant is deliberately broken is not
// testing that invariant. Each mutation below breaks exactly one security
// property in a scratch copy of the repository; the onboarding and contract
// tests must FAIL for every one. A surviving mutation fails this script.
//
//   node tools/mutation-check-onboarding.mjs
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TESTS = [
  'test/onboarding-config.test.js',
  'test/onboarding-coverage.test.js',
  'test/onboarding-render.test.js',
  'test/onboarding-cli.test.js',
  'test/baseline-provenance.test.js',
  'test/framework-contracts.test.js'
];

// [invariant, file, search, replace]
const MUTATIONS = [
  ['generated Gitleaks config keeps the default ruleset', 'onboarding/lib/render.mjs', "'useDefault = true'", "'useDefault = false'"],
  ['delivery never runs log-only', 'onboarding/lib/render.mjs', "const gateMode = phase === 'delivery' ? 'enforce' : config.rollout.gateMode;", 'const gateMode = config.rollout.gateMode;'],
  ['no delivery workflow exists while log-only', 'onboarding/lib/render.mjs', "if (isEcrProfile(config.profile) && config.rollout.gateMode === 'enforce') {", 'if (isEcrProfile(config.profile)) {'],
  ["Gitleaks default mode renders gitleaks_config: ''", 'onboarding/lib/render.mjs', "config.gitleaks.mode === 'default' ? '' :", "config.gitleaks.mode === 'default' ? '.gitleaks.toml' :"],
  ["TruffleHog default renders no exclusions", 'onboarding/lib/render.mjs', 'q(config.trufflehog.excludePathsFile)', "q(config.trufflehog.excludePathsFile || '.trufflehog-exclude-paths.txt')"],
  ['a skipped image gate fails a PR', 'onboarding/lib/render.mjs', `'elif [ "$IMAGE_RESULT" != "success" ]; then'`, `'elif [ "$IMAGE_RESULT" != "success" ] && [ "$IMAGE_RESULT" != "skipped" ]; then'`],
  ['the container build holds no id-token', 'onboarding/lib/render.mjs', "      'permissions:',\n      '  contents: read',\n      'steps:',\n      '  - name: Check out the repository',", "      'permissions:',\n      '  contents: read',\n      '  id-token: write',\n      'steps:',\n      '  - name: Check out the repository',"],
  ['the webhook is a declared secret, never an input', 'onboarding/lib/render.mjs', '`  slack_notify_webhook: \\${{ secrets.', '`  slack_notify_url: \\${{ secrets.'],
  ['bootstrap exists only while the baseline is absent', 'onboarding/lib/render.mjs', "config.semgrep.baseline.state === 'absent' && config.rollout.gateMode === 'log-only'", "config.rollout.gateMode === 'log-only'"],
  ['the deploy job holds the deploy role, not the push role', 'onboarding/lib/render.mjs', 'role-to-assume: ${q(d.roles.deployRoleArn)}', 'role-to-assume: ${q(d.roles.pushScanRoleArn)}'],
  ['the deploy pulls by digest', 'onboarding/lib/render.mjs', `'        --image-digest "$IMAGE_DIGEST" \\\\',`, `'        --image-tag "$IMAGE_DIGEST" \\\\',`],
  ['one role cannot both push and deploy', 'onboarding/lib/config.mjs', 'delivery.roles.pushScanRoleArn && delivery.roles.pushScanRoleArn === delivery.roles.deployRoleArn', 'false'],
  ['enforce requires an accepted baseline', 'onboarding/lib/config.mjs', "rollout.gateMode === 'enforce' && baseline.state !== 'accepted'", 'false'],
  ['credential values are refused', 'onboarding/lib/config.mjs', 'if (shape.pattern.test(value)) {', 'if (false) {'],
  ['native scanners are root-only', 'onboarding/lib/coverage.mjs', 'const native = atRoot && spec.nativeAtRoot ?', 'const native = spec.nativeAtRoot ?'],
  ['partial dependency coverage blocks generation', 'onboarding/lib/coverage.mjs', "new Set(['osv-only', 'uncovered'])", 'new Set([])'],
  ['a Gitleaks config that replaces defaults is flagged', 'onboarding/lib/coverage.mjs', '  if (!extendsDefault) {\n    problems.push(', '  if (false) {\n    problems.push('],
  ['a hand-edited generated file is not overwritten', 'onboarding/lib/files.mjs', "entry.action = force.includes(file.path) ? 'forced' : 'conflict';", "entry.action = 'forced';"],
  ['a human-owned file is not overwritten', 'onboarding/lib/files.mjs', "entry.action = adopt.includes(file.path) ? 'adopted' : 'conflict';", "entry.action = 'adopted';"],
  ['an untrusted scan cannot become a candidate', 'onboarding/lib/baseline.mjs', 'if (gate.integrity?.trusted !== true) {', 'if (false) {'],
  ['DO-NOT-BASELINE is honoured', 'onboarding/lib/baseline.mjs', "if (await resolveFile('DO-NOT-BASELINE.txt')) {", 'if (false) {'],
  ['a baseline holds Semgrep fingerprints only', 'onboarding/lib/baseline.mjs', 'if (extra.length > 0) {', 'if (false) {'],
  ['accept refuses an existing baseline', 'onboarding/lib/baseline.mjs', "  if (await exists(join(root, config.semgrep.baseline.path))) {\n    throw new Error(\n      `${config.semgrep.baseline.path} already exists; refusing", "  if (false) {\n    throw new Error(\n      `${config.semgrep.baseline.path} already exists; refusing"],
  ['only a workflow_dispatch run can supply a baseline', 'onboarding/lib/baseline.mjs', "const ONBOARDING_EVENT = 'workflow_dispatch';", "const ONBOARDING_EVENT = 'pull_request';"],
  ['the run event is checked at prepare', 'onboarding/lib/baseline.mjs', '  if (run.event !== ONBOARDING_EVENT) {', '  if (false) {'],
  ['accept binds to HEAD', 'onboarding/lib/baseline.mjs', '    if (consumer.head !== p.scan?.commit) {', '    if (false) {'],
  ['accept requires a clean tree', 'onboarding/lib/baseline.mjs', '    if (!consumer.clean) {', '    if (false) {'],
  ['accept binds to the Semgrep configs', 'onboarding/lib/baseline.mjs', '  if (!sameList(p.semgrep?.configs, config.semgrep.rulesets)) {', '  if (false) {'],
  ['accept binds to the Semgrep paths', 'onboarding/lib/baseline.mjs', '  if (!sameList(p.semgrep?.paths, config.semgrep.roots)) {', '  if (false) {'],
  ['accept binds to .semgrepignore', 'onboarding/lib/baseline.mjs', '    if ((p.semgrep?.semgrepignoreSha256 ?? null) !== current) {', '    if (false) {'],
  ['accept binds to the repository', 'onboarding/lib/baseline.mjs', '  if (p.repository?.slug?.toLowerCase() !== config.repository.slug?.toLowerCase()) {', '  if (false) {'],
  ['accept binds to the framework ref', 'onboarding/lib/baseline.mjs', '  if (p.framework?.repository !== config.framework.repository || p.framework?.ref !== config.framework.ref) {', '  if (false) {'],
  ['only the default branch may supply a baseline', 'onboarding/lib/baseline.mjs', '  if (p.scan?.ref !== expectedRef) {', '  if (false) {'],
  ['the provenance digest is verified', 'onboarding/lib/baseline.mjs', '  if (provenance.digest !== provenanceDigest(provenance)) {', '  if (false) {'],
  ['the candidate bytes are bound to the provenance', 'onboarding/lib/baseline.mjs', '  if (provenance.candidate?.sha256 !== sha256(candidateText)) {', '  if (false) {'],
  ['a candidate without provenance is refused', 'onboarding/lib/baseline.mjs', "    return ['there is no provenance record: a candidate that is not bound to the scan that produced it cannot be accepted'];", '    return [];'],
  ['provenance refuses an untrusted scan', 'security/scripts/baseline-provenance.mjs', '  if (gate?.integrity?.trusted !== true) {', '  if (false) {'],
  ['the framework ref is an exact SHA', 'onboarding/lib/config.mjs', "{ re: RE.sha, hint: 'a full 40-character", "{ re: /^\\S+$/, hint: 'a full 40-character"],
  ['generation is bound to the CLI commit', 'onboarding/lib/framework.mjs', '  if (config.framework.ref && config.framework.ref !== framework.sha) {', '  if (false) {'],
  ['a dirty CLI checkout cannot generate', 'onboarding/lib/framework.mjs', '  if (!framework.clean) {', '  if (false) {'],
  ['an unknown CLI commit cannot generate', 'onboarding/lib/analyze.mjs', '  const bindingProblems = frameworkProblems(framework, config);', '  const bindingProblems = framework ? frameworkProblems(framework, config) : [];'],
  ['caller permissions equal the callee requirement', 'onboarding/lib/contract.mjs', '          if (want !== have) {', '          if (false) {'],
  ['break-glass stays unsupported', 'onboarding/lib/config.mjs', "  if (breakGlass.mode !== 'disabled') {", '  if (false) {'],
  ['an unreadable contract is an error', 'onboarding/lib/analyze.mjs', "      errors.push({ area: 'framework', message: `${file} could not be read", "      warnings.push({ area: 'framework', message: `${file} could not be read"],
  ['the gh wrapper is read-only', 'onboarding/cli.mjs', 'if (!isGetApi && !isDownload) {', 'if (false) {'],
  ['non-interactive accept needs the exact count', 'onboarding/cli.mjs', "if (options['expect-findings'] === undefined || Number(options['expect-findings']) !== count) {", 'if (false) {'],
  ['promotion has no yes-default', 'onboarding/cli.mjs', "question: 'Write these changes?', default: false", "question: 'Write these changes?', default: true"],
  ['contract problems block generation', 'onboarding/lib/analyze.mjs', "contract.problems.forEach((message) => errors.push({ area: 'framework', message }));", ''],
  ["an absent owner-managed .semgrepignore is an error", 'onboarding/lib/analyze.mjs', "    ignorePatterns = null;\n    errors.push({", "    ignorePatterns = null;\n    warnings.push({"],
  ['bootstrap is refused on a diff-aware scan', '.github/workflows/_source-security.yml', "(github.event_name == 'pull_request' || github.event_name == 'push')", "(github.event_name == 'never')"],
  ['the image notifier reads the webhook secret', '.github/workflows/_image-scan-prepush.yml', 'secrets.slack_notify_webhook || inputs.slack_notify_url', 'inputs.slack_notify_url']
];

function copyRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'ssd-mutant-'));
  cpSync(ROOT, dir, { recursive: true, filter: (src) => !/[\\/](\.git|node_modules|reports)([\\/]|$)/.test(src.slice(ROOT.length)) });
  return dir;
}

const pristine = copyRepo();
const baseline = spawnSync(process.execPath, ['--test', ...TESTS], { cwd: pristine, encoding: 'utf8' });
if (baseline.status !== 0) {
  console.error('The unmutated suite fails; fix it before checking mutations.\n' + baseline.stdout.slice(-2000));
  process.exit(1);
}
rmSync(pristine, { recursive: true, force: true });

let survivors = 0;
for (const [invariant, file, search, replace] of MUTATIONS) {
  const dir = copyRepo();
  try {
    const path = join(dir, file);
    const source = readFileSync(path, 'utf8');
    const count = source.split(search).length - 1;
    if (count !== 1) {
      console.log(`STALE   ${invariant}: the mutation target occurs ${count} time(s) in ${file}; update this script`);
      survivors += 1;
      continue;
    }
    writeFileSync(path, source.replace(search, replace));
    const result = spawnSync(process.execPath, ['--test', ...TESTS], { cwd: dir, encoding: 'utf8' });
    if (result.status === 0) {
      console.log(`SURVIVED ${invariant} (${file})`);
      survivors += 1;
    } else {
      const failed = (/# fail (\d+)/.exec(result.stdout) ?? [])[1];
      console.log(`killed   ${invariant} — ${failed} test(s) failed`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
console.log(`\n${MUTATIONS.length - survivors}/${MUTATIONS.length} mutations killed.`);
process.exitCode = survivors === 0 ? 0 : 1;
