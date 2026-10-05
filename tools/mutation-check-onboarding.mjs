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
  'test/onboarding-path-confinement.test.js',
  'test/baseline-provenance.test.js',
  'test/framework-contracts.test.js',
  'test/baseline-lifecycle.test.js',
  'test/doctor.test.js',
  'test/onboard.test.js',
  'test/onboarding-codeowners.test.js',
  'test/dependency-roots.test.js',
  'test/cli-output.test.js',
  'test/aws-cli.test.js',
  'test/aws-identity.test.js',
  'test/aws-trust.test.js',
  'test/aws-discovery.test.js',
  'test/aws-doctor.test.js',
  'test/aws-plan-wrapper.test.js',
  'test/aws-plan-templates.test.js',
  'test/aws-plan.test.js',
  'test/aws-apply-wrapper.test.js',
  'test/aws-apply.test.js',
  'test/aws-verify.test.js',
  'test/aws-break-glass-template.test.js',
  'test/aws-break-glass-policy.test.js',
  'test/aws-break-glass-plan.test.js',
  'test/aws-break-glass-verify.test.js',
  'test/github-cli.test.js',
  'test/github-protection.test.js',
  'test/github-plan.test.js',
  'test/github-apply.test.js'
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
  ['pip-audit stays root-only', 'onboarding/lib/coverage.mjs', 'npmRoot !== undefined ? spec.nativeRoots : atRoot && spec.nativeAtRoot ?', 'npmRoot !== undefined ? spec.nativeRoots : spec.nativeAtRoot ?'],
  ['an npm lockfile is native+osv only when npm audit runs for its root', 'onboarding/lib/coverage.mjs', 'const native = npmRoot !== undefined ? spec.nativeRoots :', 'const native = spec.nativeRoots ? spec.nativeRoots :'],
  ['an untracked lockfile covers nothing (classification)', 'onboarding/lib/coverage.mjs', 'const isTracked = (file) => trackedSet === null || trackedSet.has(file);', 'const isTracked = () => true;'],
  ['an untracked lockfile is not a dependency root (discovery)', 'security/scripts/dependency-roots.mjs', "['-C', repoDir, 'ls-files', '-z', '--cached']", "['-C', repoDir, 'ls-files', '-z', '--cached', '--others']"],
  ['a nested npm root is not silently skipped (discovery)', 'security/scripts/dependency-roots.mjs', '    roots.push({ root, lockfile });', "    if (root === '.') roots.push({ root, lockfile });"],
  ['root-only scanning cannot pass (runner)', 'security/scripts/npm-audit-roots.mjs', '  for (const entry of roots) {', "  for (const entry of roots.filter((r) => r.root === '.')) {"],
  ['npm audit is pinned to its root with --prefix', 'security/scripts/npm-audit-roots.mjs', "return ['audit', '--json', '--package-lock-only', '--prefix', prefix];", "return ['audit', '--json', '--package-lock-only'];"],
  ['one failed root fails the npm audit run', 'security/scripts/npm-audit-roots.mjs', 'ok: failed.length === 0 && rejected.length === 0', 'ok: rejected.length === 0'],
  ['a dependency root path cannot contain ..', 'security/scripts/dependency-roots.mjs', "  if (segments.includes('..')) {", '  if (false) {'],
  ['a dependency root is never reached through a symbolic link', 'security/scripts/dependency-roots.mjs', '    if (info.isSymbolicLink()) {', '    if (false) {'],
  ['a linked lockfile is never read', 'security/scripts/dependency-roots.mjs', '  if (lockInfo.isSymbolicLink()) {', '  if (false) {'],
  ['the gate requires the nested npm audit report', 'security/scripts/security-gate.mjs', "        nestedNpmRoots.length > 0\n          ? readJson(paths.npmAuditNested", "        false\n          ? readJson(paths.npmAuditNested"],
  ['the gate requires a report for every nested root', 'security/scripts/security-gate.mjs', "    assert(entry, `npm audit report for dependency root", "    if (!entry) continue;\n    assert(entry, `npm audit report for dependency root"],
  ['the gate rejects a failed nested root', 'security/scripts/security-gate.mjs', "      entry.status === 'valid',", '      true,'],
  ['the gate rejects a root the checkout does not have', 'security/scripts/security-gate.mjs', '    byRoot.size === 0,', '    true,'],
  ['the recursive OSV backstop never disables .gitignore filtering', '.github/workflows/_source-security.yml', '--allow-no-lockfiles /repo --format=json', '--allow-no-lockfiles --no-ignore /repo --format=json'],
  ['the workflow runs OSV-Scanner over the npm root lockfiles', '.github/workflows/_source-security.yml', '          node "$SSD_TOOLKIT/scripts/osv-npm-roots.mjs"', '          : node "$SSD_TOOLKIT/scripts/osv-npm-roots.mjs"'],
  ['every npm root lockfile is named to OSV-Scanner', 'security/scripts/osv-npm-roots.mjs', "...lockfiles.flatMap((lockfile) => ['-L', `package-lock.json:${MOUNT}/${lockfile}`])", "...lockfiles.slice(0, 1).flatMap((lockfile) => ['-L', `package-lock.json:${MOUNT}/${lockfile}`])"],
  ['the gate requires the explicit OSV run when npm roots exist', 'security/scripts/security-gate.mjs', "        npmRoots.length > 0\n          ? await readJson(paths.osvNpmRoots", "        false\n          ? await readJson(paths.osvNpmRoots"],
  ['the explicit OSV run must cover every root lockfile', 'security/scripts/security-gate.mjs', '  assert(missing.length === 0,', '  assert(true,'],
  ['the explicit OSV run cannot declare an undiscovered lockfile', 'security/scripts/security-gate.mjs', '  assert(extra.length === 0,', '  assert(true,'],
  ['the explicit OSV run cannot report an undeclared file', 'security/scripts/security-gate.mjs', '      allowed.has(result?.source?.path),', '      true,'],
  ['a lockfile both OSV runs report counts once', 'security/scripts/security-gate.mjs', '!seen.has(result.source.path)', 'true'],
  ['a nested npm finding reproduces with --prefix', 'security/scripts/format-findings.mjs', "return root ? `${DEFAULT_REPRODUCE_COMMANDS['npm-audit']} --prefix ${shellArg(root)}` :", "return root ? DEFAULT_REPRODUCE_COMMANDS['npm-audit'] :"],
  ['a repository-root npm finding renders as before', 'security/scripts/format-findings.mjs', '        : null\n      : locationParts(finding.location);', '        : { path: finding.location, line: null }\n      : locationParts(finding.location);'],
  ['a refused dependency root fails the gate closed', 'security/scripts/dependency-roots.mjs', '  if (result.rejected.length > 0) {', '  if (false) {'],
  ['partial dependency coverage blocks generation', 'onboarding/lib/coverage.mjs', "new Set(['osv-only', 'osv-skipped', 'uncovered'])", 'new Set([])'],
  ['a tracked-but-gitignored lockfile the recursive OSV walk skips is not covered', 'onboarding/lib/coverage.mjs', '      if (npmRoot === undefined && ignoredSet.has(file)) {', '      if (false) {'],
  ['a tracked-but-gitignored lockfile blocks generation', 'onboarding/lib/coverage.mjs', "new Set(['osv-only', 'osv-skipped', 'uncovered'])", "new Set(['osv-only', 'uncovered'])"],
  ['inspect asks git which tracked files .gitignore matches', 'onboarding/lib/inspect.mjs', "'--cached', '--ignored', '--exclude-per-directory=.gitignore'", "'--cached', '--ignored', '--exclude-per-directory=.nothing'"],
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
  ['an unreadable contract is an error', 'onboarding/lib/analyze.mjs', "    for (const message of unverified) {\n      errors.push({ area: 'framework', message });", "    for (const message of unverified) {\n      warnings.push({ area: 'framework', message });"],
  ['consumer writes never traverse a symbolic link', 'onboarding/lib/safe-path.mjs', '    if (info.isSymbolicLink()) {', '    if (false) {'],
  ['a repository-relative path cannot escape with ..', 'onboarding/lib/safe-path.mjs', "  if (parts.includes('..')) {", '  if (false) {'],
  ['an absolute path is not a repository-relative path', 'onboarding/lib/safe-path.mjs', "  if (isAbsolute(relativePath) || /^[a-zA-Z]:/.test(relativePath) || relativePath.startsWith('\\\\')) {", '  if (false) {'],
  ['the gh wrapper is read-only', 'onboarding/cli.mjs', 'if (!isGetApi && !isDownload) {', 'if (false) {'],
  ['non-interactive accept needs the exact count', 'onboarding/cli.mjs', "if (options['expect-findings'] === undefined || Number(options['expect-findings']) !== count) {", 'if (false) {'],
  ['promotion has no yes-default', 'onboarding/cli.mjs', "question: 'Write these changes?', default: false", "question: 'Write these changes?', default: true"],
  ['onboard: the final confirmation defaults to no', 'onboarding/cli.mjs', "question: 'Write these onboarding files?', default: false", "question: 'Write these onboarding files?', default: true"],
  ['onboard writes nothing while the plan blocks', 'onboarding/cli.mjs', '    const blocking = isBlocking(planned);', '    const blocking = false;'],
  ['onboard succeeds only when the written state validates', 'onboarding/cli.mjs', '  if (validationFails(fresh.result)) {', '  if (false) {'],
  ['onboard adopts only the paths the operator named', 'onboarding/cli.mjs', 'const explicit = { adopt: options.adopt ?? [], force: options.force ?? [] };', "const explicit = { adopt: options.adopt ?? ['.github/workflows/security.yml', '.semgrepignore'], force: options.force ?? [] };"],
  ['onboard proves every path confined before the first write', 'onboarding/cli.mjs', '    await assertSafeRepoPath(root, path);', '    void path;'],
  ['validate fails on drift as well as on errors', 'onboarding/lib/analyze.mjs', 'export const validationFails = (result) => isBlocking(result) || hasDrift(result);', 'export const validationFails = (result) => isBlocking(result);'],
  ['a failed write reports what was written before it', 'onboarding/lib/files.mjs', '        error.written = [...written];', '        error.written = [];'],
  ['a failed write names the path that failed', 'onboarding/lib/files.mjs', '        error.failedPath = entry.path;', '        error.failedPath = undefined;'],
  ['onboard presents itself as onboard', 'onboarding/cli.mjs', "obtainPartial(options, facts, io, prompter, 'onboard')", "obtainPartial(options, facts, io, prompter, 'init')"],
  ['a new config starts with the baseline absent', 'onboarding/lib/init.mjs', "baseline: { path: DEFAULT_BASELINE, state: 'absent' }", "baseline: { path: DEFAULT_BASELINE, state: 'accepted' }"],
  ['a new config starts log-only', 'onboarding/lib/init.mjs', "    rollout: { gateMode: 'log-only' },", "    rollout: { gateMode: 'enforce' },"],
  ['the interview never defaults the profile', 'onboarding/lib/init.mjs', "    question: 'Profile (required: choose one explicitly)',", "    question: 'Profile (required: choose one explicitly)',\n    default: facts.dockerfiles.length > 0 ? 'container-self-managed' : 'source-only',"],
  ['the source caller holds no id-token', 'onboarding/lib/render.mjs', "    [\n      'permissions:',\n      '  contents: read',\n      '  pull-requests: write'\n    ].join('\\n')", "    [\n      'permissions:',\n      '  contents: read',\n      '  pull-requests: write',\n      '  id-token: write'\n    ].join('\\n')"],
  ['doctor: an analyze error always makes its check FAIL', 'onboarding/lib/doctor.mjs', "target.status = atLeast(target.status, severity === 'error' ? FAIL : WARN);", "target.status = atLeast(target.status, WARN);"],
  ['doctor: an unknown area routes to the catch-all', 'onboarding/lib/doctor.mjs', "  return AREA_CHECK[entry.area] ?? 'other';", "  return AREA_CHECK[entry.area] ?? 'configuration';"],
  ['doctor: generated-file drift is a FAIL', 'onboarding/lib/doctor.mjs', '  if (hasDrift(result)) {', '  if (false) {'],
  ['doctor: an absent baseline is a valid onboarding state, not corruption', 'onboarding/lib/doctor.mjs', "    // treats every Semgrep finding as new. Only production readiness is missing.\n    c.status = WARN;", "    // treats every Semgrep finding as new. Only production readiness is missing.\n    c.status = FAIL;"],
  ['doctor: an unbound contract is NOT VERIFIED, never PASS', 'onboarding/lib/doctor.mjs', "    c.status = NOT_VERIFIED;\n    c.observed.push('not checked: the generator", "    c.observed.push('not checked: the generator"],
  ['doctor: an unestablished identity is not a PASS', 'onboarding/lib/doctor.mjs', "    c.status = WARN;\n    c.observed.push(`identity not established", "    c.observed.push(`identity not established"],
  ['doctor: GitHub merge governance is never PASS', 'onboarding/lib/doctor.mjs', "  return check('github-governance', 'GitHub merge governance', {\n    status: NOT_VERIFIED,", "  return check('github-governance', 'GitHub merge governance', {\n    status: PASS,"],
  ['doctor: CODEOWNERS coverage is never claimed', 'onboarding/lib/doctor.mjs', "  return check('codeowners', 'CODEOWNERS coverage', {\n    status: NOT_VERIFIED,", "  return check('codeowners', 'CODEOWNERS coverage', {\n    status: PASS,"],
  ['doctor: a settings link only for an exact github.com origin', 'onboarding/lib/doctor.mjs', "  if (git.host !== 'github.com' || !git.slug", "  if (!git.slug"],
  ['doctor writes nothing', 'onboarding/cli.mjs', '  const report = diagnose({ result, facts });', "  await applyWrites(root, result.plan.filter((entry) => entry.action !== 'conflict'));\n  const report = diagnose({ result, facts });"],
  ['CODEOWNERS: `/*` is not a recursive wildcard', 'onboarding/lib/analyze.mjs', '  if (literalLast && prefixes(t).slice(', '  if (prefixes(t).slice('],
  ['CODEOWNERS: the last matching rule wins', 'onboarding/lib/analyze.mjs', '  for (let i = rules.length - 1; i >= 0; i -= 1) {', '  for (let i = 0; i < rules.length; i += 1) {'],
  ['CODEOWNERS: a later ownerless rule removes ownership', 'onboarding/lib/analyze.mjs', '    if (!rule.owned && ruleMayMatch(rule, path)) {', '    if (false) {'],
  ['CODEOWNERS: a rule without owners owns nothing', 'onboarding/lib/analyze.mjs', 'owned: owners.length > 0 && owners.every(', 'owned: owners.every('],
  ['CODEOWNERS: an unsupported pattern proves nothing', 'onboarding/lib/analyze.mjs', '    if (rule.owned && rule.supported && ruleCovers(rule, path)) {', '    if (rule.owned && ruleCovers({ segments: [\'**\'], ...rule }, path)) {'],
  ['GitHub remote: the exact github.com host is required', 'onboarding/lib/inspect.mjs', "remote.host !== 'github.com' || ", ''],
  ['GitHub remote: github.com.evil.example is not github.com', 'onboarding/lib/inspect.mjs', "remote.host !== 'github.com'", "!remote.host.startsWith('github.com')"],
  ['GitHub remote: notgithub.com is not github.com', 'onboarding/lib/inspect.mjs', "remote.host !== 'github.com'", "!remote.host.endsWith('github.com')"],
  ['GitHub remote: the slug is read from the path, not searched for', 'onboarding/lib/inspect.mjs', '.exec(remote.path);', '.exec(url.trim().replace(/^.*github\\.com[:/]+/i, \'\'));'],
  ['contract problems block generation', 'onboarding/lib/analyze.mjs', "contract.problems.forEach((message) => errors.push({ area: 'framework', message }));", ''],
  ["an absent owner-managed .semgrepignore is an error", 'onboarding/lib/analyze.mjs', "    ignorePatterns = null;\n    errors.push({", "    ignorePatterns = null;\n    warnings.push({"],
  ['bootstrap is refused on a diff-aware scan', '.github/workflows/_source-security.yml', "(github.event_name == 'pull_request' || github.event_name == 'push')", "(github.event_name == 'never')"],
  ['baseline state absent is not treated as accepted', 'security/scripts/security-gate.mjs', "  if (lifecycle === 'absent') {", '  if (false) {'],
  ['an accepted baseline that is missing still fails closed', 'security/scripts/security-gate.mjs', "  if (lifecycle === 'absent') {", "  if (lifecycle === 'absent' || lifecycle === 'accepted') {"],
  ['a caller that declares no baseline state stays fail-closed', 'security/scripts/security-gate.mjs', "    return 'unspecified';", "    return 'absent';"],
  ['state absent refuses a baseline that exists anyway', 'security/scripts/security-gate.mjs', '    throw new Error(\n      `Semgrep baseline: inconsistent lifecycle', "    return readJson(path, 'Semgrep baseline');\n    throw new Error(\n      `Semgrep baseline: inconsistent lifecycle"],
  ['an unsupported baseline state is a written report-integrity BLOCK', 'security/scripts/security-gate.mjs', "  } catch (error) {\n    const finding = {\n      source: 'security-gate',", "  } catch (error) {\n    if (lifecycle === undefined) throw error;\n    const finding = {\n      source: 'security-gate',"],
  ['the workflow hands the declared baseline state to the gate', '.github/workflows/_source-security.yml', 'args+=(--baseline-state "$BASELINE_STATE")', ':'],
  ['the generated caller declares the configured baseline state', 'onboarding/lib/render.mjs', 'semgrep_baseline_state: ${config.semgrep.baseline.state}', 'semgrep_baseline_state: absent'],
  ['the image notifier reads the webhook secret', '.github/workflows/_image-scan-prepush.yml', 'secrets.slack_notify_webhook || inputs.slack_notify_url', 'inputs.slack_notify_url'],
  // Human output (onboarding/lib/output.mjs): terminal safety and status semantics.
  ['output: repository text is sanitized before it reaches a terminal', 'onboarding/lib/output.mjs', "const text = String(value ?? '').replace(UNSAFE, escapeChar);", "const text = String(value ?? '');"],
  ['output: a newline in a label cannot fake a row', 'onboarding/lib/output.mjs', "return singleLine ? text.replace(/\\n/g, '\\\\n') : text;", 'return text;'],
  ['output: NO_COLOR disables color', 'onboarding/lib/output.mjs', "const color = tty && !env.NO_COLOR && env.TERM !== 'dumb';", "const color = tty && env.TERM !== 'dumb';"],
  ['output: redirected output is plain', 'onboarding/lib/output.mjs', 'const tty = Boolean(stream?.isTTY);', 'const tty = true;'],
  ['output: FAIL is never rendered as PASS', 'onboarding/lib/output.mjs', "  FAIL: { symbol: '✗', tone: 'red' },", "  FAIL: { symbol: '✓', tone: 'green' },"],
  ['output: an unknown status never looks like a pass', 'onboarding/lib/output.mjs', "const statusOf = (word) => STATUS[word] ?? { symbol: '?', tone: 'red' };", 'const statusOf = (word) => STATUS[word] ?? STATUS.PASS;'],
  ['output: a blocking issue is never rendered as a warning', 'onboarding/lib/report.mjs', "`Blocking issues (${result.errors.length})`, problemRows(result.errors, 'FAIL')", "`Blocking issues (${result.errors.length})`, problemRows(result.errors, 'WARN')"],
  ['output: --json never passes through the human renderer', 'onboarding/cli.mjs', "    json: (value) => rawOut(`${JSON.stringify(value, null, 2)}\\n`)", '    json: (value) => rawOut(format(dim(JSON.stringify(value, null, 2)), outStyle))'],
  ['output: the prompter sanitizes what it echoes', 'onboarding/lib/prompt.mjs', '      output.write(`${sanitize(text)}\\n`);', '      output.write(`${text}\\n`);'],
  // Phase 2A: aws doctor (read-only AWS readiness).
  ['an AWS root principal is never accepted', 'onboarding/aws/identity.mjs', "const root = caller.kind === 'root';", 'const root = false;'],
  ['an account mismatch cannot PASS', 'onboarding/aws/identity.mjs', 'const ok = caller.account === expectedAccount;', 'const ok = true;'],
  ['a region mismatch cannot PASS', 'onboarding/aws/identity.mjs', 'const mismatch = resolved.source === \'flag\' && resolved.configured && resolved.configured !== resolved.region;', 'const mismatch = false;'],
  ['a region mismatch contacts no AWS', 'onboarding/aws/doctor.mjs', '  if (regionC.status === FAIL) {', '  if (false) {'],
  ['an identity failure stops the run before discovery', 'onboarding/aws/doctor.mjs', '  if (identity.some((c) => c.status === FAIL)) {', '  if (false) {'],
  ['a mutating AWS call cannot pass the read-only allowlist', 'onboarding/aws/aws-cli.mjs', '  assertAllowed(argv, READ_ONLY_OPERATIONS, READ_ONLY_WORDS);\n', ''],
  ['a file:// / fileb:// / http(s):// value never reaches the AWS CLI', 'onboarding/aws/aws-cli.mjs', '      if (INDIRECT_VALUE.test(value)) {', '      if (false) {'],
  ['a caller cannot add unlisted AWS CLI parameters (endpoint, profile, debug)', 'onboarding/aws/aws-cli.mjs', '    if (!Object.hasOwn(flags, flag) || WRAPPER_FLAGS.includes(flag)) {', '    if (WRAPPER_FLAGS.includes(flag)) {'],
  ['a wildcard OIDC subject is never accepted', 'onboarding/aws/policy/trust.mjs', "  return { severity: 'FAIL', kind, message: `subject pattern", "  return { severity: 'WARN', kind, message: `subject pattern"],
  ['a wrong trust audience is never accepted', 'onboarding/aws/policy/trust.mjs', "(value) => (value === STS_AUDIENCE ? [] :", '(value) => (true ? [] :'],
  ['an OIDC provider without the sts audience cannot PASS', 'onboarding/aws/doctor.mjs', '  if (!p.clientIds.includes(STS_AUDIENCE)) {', '  if (false) {'],
  ['a name-only resource is never managed', 'onboarding/aws/discover/stacks.mjs', "    return { ownership: 'exists-not-owned', reasons, stack: null };", "    return { ownership: 'managed', reasons, stack: null };"],
  ['a stack for another consumer is never managed', 'onboarding/aws/discover/stacks.mjs', '    if (consumer !== canonical) {', '    if (false) {'],
  ['access denied is never resource-absent', 'onboarding/aws/discover/result.mjs', "    if (error.kind === 'not-found' && notFound.includes(error.code)) {", "    if (error.kind === 'not-found' || error.kind === 'authorization') {"],
  ['an Offline SSM node cannot PASS', 'onboarding/aws/doctor.mjs', "  const online = result.value.pingStatus === 'Online';", '  const online = true;'],
  ['a required NOT VERIFIED check blocks readiness', 'onboarding/aws/doctor.mjs', '  if (checks.some((c) => c.status === NOT_VERIFIED && c.required)) {', '  if (false) {'],
  ['an AWS prerequisite is required unless explicitly advisory', 'onboarding/aws/doctor.mjs', "  return { id, section, title, status: PASS, required: true,", "  return { id, section, title, status: PASS, required: false,"],
  // Follow-up review fixes: readiness conclusions fail closed.
  ['an unknown registry scan type is not evaluated as coverage', 'onboarding/aws/doctor.mjs', '  if (!SCAN_TYPES.includes(s.scanType)) {', '  if (false) {'],
  ['an unknown scan type still asks the push role for Inspector access', 'onboarding/aws/policy/permissions.mjs', '        ...(enhanced === false', '        ...(enhanced !== true'],
  ['a possibly-needed permission that is missing is NOT VERIFIED, not a warning', 'onboarding/aws/policy/permissions.mjs', "r.possible ? 'NOT VERIFIED' :", "r.possible ? 'WARN' :"],
  ['managed + exists-not-owned blocks', 'onboarding/aws/doctor.mjs', "    findings.push({ severity: FAIL, kind: 'present-unowned',", "    findings.push({ severity: WARN, kind: 'present-unowned',"],
  ['a possibly-granted forbidden permission is never downgraded to WARN', 'onboarding/aws/policy/permissions.mjs', "      findings.push({ severity: f.severity, kind: 'permission-too-broad',", "      findings.push({ severity: g.decision === 'allowed' ? f.severity : 'WARN', kind: 'permission-too-broad',"],
  ['Allow + NotAction on every resource is possible administrator', 'onboarding/aws/policy/permissions.mjs', '  if (possibleAdmin.length > 0) {', '  if (false) {'],
  ['a conditional Deny hides no forbidden grant', 'onboarding/aws/policy/evaluate.mjs', '  const hardDenies = denies.filter((s) => !conditional(s));', '  const hardDenies = denies;'],
  ['a required permission granted only conditionally is NOT VERIFIED', 'onboarding/aws/policy/permissions.mjs', "        severity: r.soft ? 'WARN' : 'NOT VERIFIED',", "        severity: 'WARN',"],
  ['a grant through NotAction/NotResource is never proof', 'onboarding/aws/policy/evaluate.mjs', '  const direct = (s) => s.actions.length > 0 && s.resources.length > 0;', '  const direct = () => true;'],
  ['ownership requires the exact expected stack name', 'onboarding/aws/discover/stacks.mjs', '  if (sr.stackName !== expectedStackName || st.name !== expectedStackName) {', '  if (false) {'],
  ['ownership requires the expected ssd:environment (production; a break-glass stack its own)', 'onboarding/aws/discover/stacks.mjs', '  } else if (tagged !== expected) {', '  } else if (false) {'],
  ['the consumer tag is the canonical slug', 'onboarding/aws/discover/stacks.mjs', '  const canonical = canonicalSlug(slug);', '  const canonical = slug;'],
  ['the stack-name hash covers the canonical repository identity', 'onboarding/aws/stack-names.mjs', '.update(canonicalRepository(slug))', '.update(slug)'],
  // L2-L5 follow-up.
  ['a spent run deadline refuses further AWS calls', 'onboarding/aws/aws-cli.mjs', '    if (remaining <= 0) {', '    if (false) {'],
  ['each call is capped by the remaining run budget', 'onboarding/aws/aws-cli.mjs', '    const callTimeout = Math.min(timeoutMs, remaining);', '    const callTimeout = timeoutMs;'],
  ['a spent deadline ends the doctor run', 'onboarding/aws/discover/result.mjs', "|| error.kind === 'deadline') {", ') {'],
  ['an SSO credential operation failure is authentication', 'onboarding/aws/aws-cli.mjs', '    if (SSO_OPERATIONS.has(operation)) {', '    if (false) {'],
  ['an SSO session failure is authentication', 'onboarding/aws/aws-cli.mjs', '  if (SSO_SESSION.some((pattern) => pattern.test(text))) {', '  if (false) {'],
  ['the container credential token is redacted', 'onboarding/aws/aws-cli.mjs', ", 'AWS_CONTAINER_AUTHORIZATION_TOKEN'];", '];'],
  ['JWT-shaped tokens are redacted', 'onboarding/aws/aws-cli.mjs', '  /\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}/g\n', ''],
  ['ownership conclusions name the searched region', 'onboarding/aws/discover/stacks.mjs', "  const where = region ? ` in ${region}` : '';", "  const where = '';"],
  ['only a settled, successful stack proves ownership', 'onboarding/aws/discover/stacks.mjs', '  if (!LIVE.has(st.status)) {', '  if (false) {'],
  ['the fake AWS harness fails on an unrecorded call', 'test/support/aws-fake.mjs', '      throw new FakeAwsError(`UNRECORDED AWS CALL: ${key}`);', "      return { stdout: '', stderr: 'UNRECORDED', exitCode: 99 };"],
  ['the fake AWS harness enforces the read-only allowlist itself', 'test/support/aws-fake.mjs', '      check(call);\n', ''],
  ['a registry rule for another repository does not cover it', 'onboarding/aws/discover/ecr.mjs', '      if (!wildcardFilterMatches(f.filter, repository)) {', '      if (false) {'],
  // Phase 2B: aws plan (unexecuted change sets + local plan record).
  ['the planner cannot execute a change set', 'onboarding/aws/aws-cli.mjs', "    'describe-change-set': { '--stack-name': matches(STACK_NAMES), '--change-set-name': matches(CHANGE_SET_NAME) }\n", "    'describe-change-set': { '--stack-name': matches(STACK_NAMES), '--change-set-name': matches(CHANGE_SET_NAME) },\n    'execute-change-set': { '--stack-name': true, '--change-set-name': true }\n"],
  ['doctor cannot create a change set', 'onboarding/aws/aws-cli.mjs', "export function assertReadOnly(argv) {\n  assertAllowed(argv, READ_ONLY_OPERATIONS, READ_ONLY_WORDS);", "export function assertReadOnly(argv) {\n  assertAllowed(argv, PLANNING_OPERATIONS, READ_ONLY_WORDS);"],
  ['the planner never sends an IMPORT change set', 'onboarding/aws/aws-cli.mjs', "      '--change-set-name': matches(CHANGE_SET_NAME),\n      '--change-set-type': matches(/^(?:CREATE|UPDATE)$/),\n      '--template-body': templateBody,\n      '--tags': ssdTags,\n      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n    },\n    'describe-change-set': { '--stack-name': matches(STACK_NAMES)", "      '--change-set-name': matches(CHANGE_SET_NAME),\n      '--change-set-type': matches(/^(?:CREATE|UPDATE|IMPORT)$/),\n      '--template-body': templateBody,\n      '--tags': ssdTags,\n      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n    },\n    'describe-change-set': { '--stack-name': matches(STACK_NAMES)"],
  ['the planner never sends --import-existing-resources', 'onboarding/aws/aws-cli.mjs', "      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n    },\n    'describe-change-set': { '--stack-name': matches(STACK_NAMES)", "      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/),\n      '--import-existing-resources': false\n    },\n    'describe-change-set': { '--stack-name': matches(STACK_NAMES)"],
  ['planning values are checked, not only planning flags', 'onboarding/aws/aws-cli.mjs', "      if (typeof flags[flag] === 'function' && !flags[flag](value)) {", '      if (false) {'],
  ['the rendered template is scope-asserted (repo/shared boundary)', 'onboarding/aws/plan/scope.mjs', "    assertType(kind, stackKind, logicalId, resource?.Type, 'template');\n", ''],
  ['the described change set is scope-asserted (repo/shared boundary)', 'onboarding/aws/plan/change-set.mjs', '  assertChangeScope(stackKind, changes);\n', ''],
  ['every managed resource is retained', 'onboarding/aws/templates/common.mjs', "({ Type: type, DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain', Properties: properties })", "({ Type: type, DeletionPolicy: 'Delete', UpdateReplacePolicy: 'Retain', Properties: properties })"],
  ['an exists-not-owned resource is never planned as managed', 'onboarding/aws/plan.mjs', "  // exists-not-owned\n  if (mode === 'managed') {", "  // exists-not-owned\n  if (false) {"],
  ['an unowned (untagged) stack is never updated', 'onboarding/aws/discover/stacks.mjs', '  if (tagReasons.length > 0) {', '  if (false) {'],
  ['an unsettled or failed stack is never planned', 'onboarding/aws/discover/stacks.mjs', "  if (st.status !== 'REVIEW_IN_PROGRESS' && !LIVE.has(st.status)) {", '  if (false) {'],
  ['push and deploy never resolve to one role (case-insensitive)', 'onboarding/aws/plan.mjs', '  if (pushName.toLowerCase() === deployName.toLowerCase()) {', '  if (pushName === deployName) {'],
  ['a case-insensitive live role collision blocks', 'onboarding/aws/plan.mjs', '    if (role.state === \'present\' && role.value.arn !== arn) {', '    if (false) {'],
  ['the framework checkout binding blocks before AWS', 'onboarding/aws/plan.mjs', '  if (bindingProblems.length > 0) {', '  if (false) {'],
  ['a plan identity failure creates no change set', 'onboarding/aws/plan.mjs', '  if (identity.length > 0) {', '  if (false) {'],
  ['a plan region mismatch contacts no AWS', 'onboarding/aws/plan.mjs', '  if (regionC.status === FAIL) {', '  if (false) {'],
  ['any blocked unit stops the run before a change set', 'onboarding/aws/plan.mjs', '  if (units.some((u) => u.findings.some((f) => f.severity === FAIL))) {', '  if (false) {'],
  ['managed registry scanning is refused in Phase 2B', 'onboarding/aws/plan.mjs', "    unit.findings.push(finding(FAIL, 'registry-scanning-unsupported', REGISTRY_SCANNING_UNSUPPORTED));", "    unit.findings.push(finding(WARN, 'registry-scanning-unsupported', REGISTRY_SCANNING_UNSUPPORTED));"],
  ['the generated trust uses StringEquals', 'onboarding/aws/policy/trust.mjs', '          StringEquals: {\n            [AUD_KEY]: STS_AUDIENCE,', '          StringLike: {\n            [AUD_KEY]: STS_AUDIENCE,'],
  ['the generated trust subject is exact (no wildcard)', 'onboarding/aws/policy/trust.mjs', 'const subjects = contexts.map((context) => `repo:${slug}:${context}`);', 'const subjects = contexts.map(() => `repo:${slug}:*`);'],
  ['a replacement is counted as REPLACE', 'onboarding/aws/plan/change-set.mjs', "        if (rc.Replacement === 'True') {\n          return { ...base, action: 'REPLACE' };", "        if (rc.Replacement === 'True') {\n          return { ...base, action: 'UPDATE' };"],
  ['a conditional replacement is counted as REPLACE', 'onboarding/aws/plan/change-set.mjs', "          return { ...base, action: 'REPLACE', conditional: true };", "          return { ...base, action: 'UPDATE', conditional: true };"],
  ['replacements count as destructive', 'onboarding/aws/plan/change-set.mjs', 'destructive: counts.DELETE + counts.REPLACE', 'destructive: counts.DELETE'],
  ['a Dynamic / Import / unknown action fails closed', 'onboarding/aws/plan/change-set.mjs', "        throw new ChangeSetError('unexpected-action',", "        return { ...base, action: 'UPDATE' }; throw new ChangeSetError('unexpected-action',"],
  ['only the documented no-change reason is no-changes', 'onboarding/aws/plan/change-set.mjs', '      if (isNoChangeReason(described.StatusReason)) {', '      if (true) {'],
  ['a described change set importing existing resources is refused', 'onboarding/aws/plan/change-set.mjs', "  if (described.ImportExistingResources === true) problems.push('ImportExistingResources');\n", ''],
  ['the plan id binds the base stack revision', 'onboarding/aws/plan/record.mjs', "    baseStack: baseStack.state === 'absent' ? { state: 'absent' } : { state: 'present', stackId: baseStack.stackId, stackStatus: baseStack.stackStatus, lastUpdatedTime: baseStack.lastUpdatedTime ?? null },", '    baseStack: { state: baseStack.state },'],
  ['the plan id binds the template hash', 'onboarding/aws/plan/record.mjs', '    templateSha256,\n    parametersSha256,\n    tagsSha256,\n', '    parametersSha256,\n    tagsSha256,\n'],
  ['an existing plan is never overwritten', 'onboarding/aws/plan/record.mjs', "  throw new PlanRecordError('plan-exists', `${relative} already exists: a plan is never overwritten (this exact plan was already recorded, possibly incompletely)`);", '  return target;'],
  ['plan.json is written last', 'onboarding/aws/plan/record.mjs', "export const PLAN_FILES = Object.freeze(['template.json', 'parameters.json', 'change-set.json', 'policies.json', 'plan.json']);", "export const PLAN_FILES = Object.freeze(['plan.json', 'template.json', 'parameters.json', 'change-set.json', 'policies.json']);"],
  ['a partial plan directory is never applicable', 'onboarding/aws/plan/record.mjs', '    if (content === null) {', '    if (false) {'],
  ['a no-change plan is never applicable', 'onboarding/aws/plan/record.mjs', "  if (plan.outcome !== 'changes') {", '  if (false) {'],
  ['persisted plan data is secret-checked before any write', 'onboarding/aws/plan/record.mjs', '  assertPersistable(files, env);\n  const relative = planDirOf(planId);', '  const relative = planDirOf(planId);'],
  ['the registry scanning proposal keeps current rules', 'onboarding/aws/discover/ecr.mjs', '  const rules = scanning.rules.map((rule) => ({ frequency: rule.frequency, filters: rule.filters.map((f) => ({ filter: f.filter, type: f.type })) }));', '  const rules = [];'],
  ['an unmanaged policy on an owned managed role blocks, never warns', 'onboarding/aws/plan.mjs', "          FAIL,\n          'unmanaged-policy',", "          WARN,\n          'unmanaged-policy',"],
  ['a managed policy attached directly to an owned role is unmanaged', 'onboarding/aws/plan.mjs', '    const unmanaged = policies.policies.filter((p) => p !== ours);', "    const unmanaged = policies.policies.filter((p) => p !== ours && p.kind === 'inline');"],
  ['an extra inline policy on an owned role is unmanaged', 'onboarding/aws/plan.mjs', '    const unmanaged = policies.policies.filter((p) => p !== ours);', "    const unmanaged = policies.policies.filter((p) => p !== ours && p.kind === 'attached');"],
  ["only the stack's own inline policy name is managed", 'onboarding/aws/plan.mjs', "    const ours = policies.policies.find((p) => p.kind === 'inline' && p.name === `inline:${policyName}`);", "    const ours = policies.policies.find((p) => p.kind === 'inline');"],
  ['an unreadable policy list on an owned role blocks', 'onboarding/aws/plan.mjs', "        finding(FAIL, 'policies-unverified',", "        finding(NOT_VERIFIED, 'policies-unverified',"],
  ['the fake planning harness enforces the planning allowlist itself', 'test/support/aws-plan-fake.mjs', 'export const planFake = (world) => fakeAws(world, { allowlist: assertPlanning });', 'export const planFake = (world) => fakeAws(world, { allowlist: () => {} });'],
  // Phase 2C: aws apply (execute exactly one reviewed change set).
  ['apply revalidates --account against the plan and config', 'onboarding/aws/apply/plan-check.mjs', '  if (account !== plan.account || account !== d.aws.accountId) {', '  if (false) {'],
  ['apply revalidates the live caller account', 'onboarding/aws/apply.mjs', '  const identity = [accountCheck(caller, account), principalCheck(caller)]', '  const identity = [principalCheck(caller)]'],
  ['apply revalidates --region against the plan and config', 'onboarding/aws/apply/plan-check.mjs', '  if (region !== plan.region || region !== d.aws.region) {', '  if (false) {'],
  ['apply enforces the framework binding', 'onboarding/aws/apply/plan-check.mjs', '  for (const problem of frameworkProblems(framework, config)) {', '  for (const problem of []) {'],
  ['apply refuses a configuration changed since the plan', 'onboarding/aws/apply/plan-check.mjs', '  if (plan.createdFromConfigDigest !== configDigestOf(config)) {', '  if (false) {'],
  ['apply recomputes every plan file hash', 'onboarding/aws/plan/record.mjs', '    if (sha256(content) !== plan.files?.[name]) {', '    if (false) {'],
  ['apply verifies the tags the plan id binds', 'onboarding/aws/plan/record.mjs', '  if (!Array.isArray(plan.tags) || sha256(canonicalJson(plan.tags)) !== plan.planIdInput.tagsSha256) {', '  if (false) {'],
  ['plan.json copies must equal what the plan id binds', 'onboarding/aws/apply/plan-check.mjs', '    if (!same(plan[key], input[key])) {', '    if (false) {'],
  ['the recorded destructive count is re-derived from change-set.json', 'onboarding/aws/apply/plan-check.mjs', '    if (!same(plan.changes, classified) || !same(plan.counts, counts) || plan.destructive !== destructive) {', '    if (false) {'],
  ['apply re-describes the change set and compares it', 'onboarding/aws/apply.mjs', "  if (!step(report, 'change-set', 'Change set unchanged', compareChangeSet(record.changeSet, live))) {", '  if (false) {'],
  ['any difference in the live change set refuses', 'onboarding/aws/apply/live.mjs', '  if (differ.length > 0) {', '  if (false) {'],
  ['apply never uses another (newer) change set', 'onboarding/aws/apply/live.mjs', '  if (live?.ChangeSetId !== recorded.ChangeSetId) {', '  if (false) {'],
  ['apply executes only the recorded change-set ARN', 'onboarding/aws/aws-cli.mjs', "'execute-change-set', '--stack-name', stackName, '--change-set-name', changeSetArn];", "'execute-change-set', '--stack-name', stackName, '--change-set-name', changeSetArn.replace(/[0-9a-f]{64}/, 'b'.repeat(64))];"],
  ['an unavailable change set is never executed', 'onboarding/aws/apply/live.mjs', "  if (live.Status !== 'CREATE_COMPLETE' || live.ExecutionStatus !== 'AVAILABLE') {", '  if (false) {'],
  ["the change set's template must be template.json", 'onboarding/aws/apply/live.mjs', '  if (!body || typeof body !== \'object\' || canonicalJson(body) !== templateText) {', '  if (!body) {'],
  ["the template is read from the change set, not the deployed stack", 'onboarding/aws/apply.mjs', "'get-template', '--stack-name', record.binding.stackName, '--change-set-name', record.binding.changeSetArn, '--template-stage', 'Original']", "'get-template', '--stack-name', record.binding.stackName, '--template-stage', 'Original']"],
  ['apply checks the stack before executing', 'onboarding/aws/apply.mjs', "  return step(report, 'stack', title, checkStack({ record, stack, slug }));", '  return true;'],
  ['a stale UPDATE base revision refuses', 'onboarding/aws/apply/live.mjs', '    if (st.status !== base.stackStatus || st.lastUpdatedTime !== (base.lastUpdatedTime ?? null)) {', '    if (false) {'],
  ['another stack at the name (placeholder id) refuses', 'onboarding/aws/apply/live.mjs', '  if (st.stackId !== binding.stackId) {', '  if (false) {'],
  ['a CREATE placeholder must still be REVIEW_IN_PROGRESS', 'onboarding/aws/apply/live.mjs', "    if (st.status !== 'REVIEW_IN_PROGRESS') {", '    if (false) {'],
  ['an UPDATE stack that lost its SSD ownership tags refuses', 'onboarding/aws/apply/live.mjs', '  if (tags.length > 0) {', '  if (false) {'],
  // CREATE placeholders are untagged until execute (observed live, Phase 3C):
  // ownership is the reviewed change set's tags plus the placeholder's identity.
  ['an untagged CREATE placeholder is accepted (the live AWS shape)', 'onboarding/aws/apply/live.mjs', '    if (st.tags.length > 0) {', '    if (true) {'],
  ['a CREATE change set must carry the SSD ownership tags', 'onboarding/aws/apply/live.mjs', '    if (changeSetTags.length > 0) {', '    if (false) {'],
  ['a tagged CREATE placeholder must carry only the SSD tags', 'onboarding/aws/apply/live.mjs', '      if (placeholderTags.length > 0) {', '      if (false) {'],
  ["an existing placeholder's revision is protected", 'onboarding/aws/apply/live.mjs', "    if (base.state === 'present' && st.lastUpdatedTime !== (base.lastUpdatedTime ?? null)) {", '    if (false) {'],
  ['the live stack name must be the recorded one', 'onboarding/aws/apply/live.mjs', '  if (st.name !== binding.stackName) {', '  if (false) {'],
  ['destructive changes cannot be ignored', 'onboarding/aws/apply/plan-check.mjs', '  if (destructive === 0 && (allowDestructive === null || allowDestructive === 0)) {', '  if (true) {'],
  ['a wrong --allow-destructive count refuses', 'onboarding/aws/apply/plan-check.mjs', '  if (allowDestructive !== destructive) {', '  if (false) {'],
  ['the typed account and region must match exactly', 'onboarding/aws/apply.mjs', 'typed?.account === account && typed?.region === region ? [] :', 'true ? [] :'],
  ['--yes never stands in for --account / --region', 'onboarding/aws/cli.mjs', '  if (planId === undefined || options.account === undefined || options.region === undefined) {', '  if (planId === undefined) {'],
  ['the live checks are repeated immediately before execution', 'onboarding/aws/apply.mjs', '  if (!(await verifyLive(report, aws, { record, account, allowDestructive, slug }))) {', '  if (false) {'],
  ['apply-started.json is written before execution', 'onboarding/aws/apply.mjs', "  report.record.started = await writeApplyRecord(root, planId, 'apply-started.json', canonicalJson(started), env);\n", ''],
  ['an applied plan is never applied again', 'onboarding/aws/apply.mjs', "applied.length === 0 ? [] :", "true ? [] :"],
  ['the apply wrapper executes at most once', 'onboarding/aws/aws-cli.mjs', '      if (executed) {', '      if (false) {'],
  ['the apply wrapper refuses arbitrary operations', 'onboarding/aws/aws-cli.mjs', '  return wrapper((argv) => assertAllowed(argv, table, APPLY_WORDS), options, (aws, run) => {', '  return wrapper(() => {}, options, (aws, run) => {'],
  ['a rollback or other *_COMPLETE is never success', 'onboarding/aws/apply/live.mjs', '  if (status === SUCCESS[operation]) {', "  if (status === SUCCESS[operation] || status.endsWith('_COMPLETE')) {"],
  ['an UPDATE that has not started is not success', 'onboarding/aws/apply/live.mjs', "  if (operation === 'UPDATE' && status === base.stackStatus && live.lastUpdatedTime === (base.lastUpdatedTime ?? null)) {", '  if (false) {'],
  ['a different stack id while waiting is failure', 'onboarding/aws/apply/live.mjs', '  if (live.stackId !== binding.stackId) {', '  if (false) {'],
  ['an apply record is never overwritten', 'onboarding/aws/plan/record.mjs', "    await write(root, relative, text, { flag: 'wx', createParents: false });", "    await write(root, relative, text, { flag: 'w', createParents: false });"],
  ['apply records are secret-checked', 'onboarding/aws/plan/record.mjs', '  assertPersistable({ [name]: text }, env);\n', ''],
  ['AWS text in apply output is redacted with the run environment', 'onboarding/aws/apply.mjs', "statusReason: typeof s.StackStatusReason === 'string' ? redact(s.StackStatusReason, env) : null,", "statusReason: typeof s.StackStatusReason === 'string' ? s.StackStatusReason : null,"],
  ['the fake apply harness enforces the apply allowlist itself', 'test/support/aws-apply-fake.mjs', '  const fake = fakeAws(world, { allowlist: assertApply(binding) });', '  const fake = fakeAws(world, { allowlist: () => {} });'],
  // Phase 2D: aws verify (read-only, effective-permission verification).
  ['verify: the account comparison cannot be skipped', 'onboarding/aws/verify.mjs', '  const identity = [identityCheck(accountCheck(caller, account)), identityCheck(principalCheck(caller)), regionC];', '  const identity = [identityCheck(principalCheck(caller)), regionC];'],
  ['verify: the root caller is never accepted', 'onboarding/aws/verify.mjs', '  const identity = [identityCheck(accountCheck(caller, account)), identityCheck(principalCheck(caller)), regionC];', '  const identity = [identityCheck(accountCheck(caller, account)), regionC];'],
  ['verify: an identity failure stops the run before discovery', 'onboarding/aws/verify.mjs', '  if (identity.some((c) => c.status === FAIL)) {', '  if (false) {'],
  ['verify: a region mismatch contacts no AWS', 'onboarding/aws/verify.mjs', '  if (regionC.status === FAIL) {', '  if (false) {'],
  ['verify: only the read-only wrapper is used', 'onboarding/aws/verify.mjs', "import { readOnlyAws } from './aws-cli.mjs';", "import { planningAws as readOnlyAws } from './aws-cli.mjs';"],
  ['the read-only allowlist is never widened with a mutating verb', 'onboarding/aws/aws-cli.mjs', "    'describe-instance-information': { '--filters': true }\n  },", "    'describe-instance-information': { '--filters': true },\n    'send-command': { '--instance-ids': true }\n  },"],
  ['ownership ignores no stack tag', 'onboarding/aws/discover/stacks.mjs', '  reasons.push(...stackTagProblems(st.tags, { scope, slug, environment }));\n', ''],
  ['verify: a managed resource must hold its own logical id', 'onboarding/aws/verify.mjs', '  if (evaluation.stack?.logicalId === expected) {', '  if (true) {'],
  ['a StringLike wildcard subject is never evaluated as an exact value', 'onboarding/aws/policy/trust.mjs', "      if (entry.operator === 'StringLike' && hasWildcard(value)) {", '      if (false) {'],
  ['verify: a forbidden action that simulates ALLOWED fails', 'onboarding/aws/verify.mjs', "    if (r.decision === 'allowed') {\n      findings.push({ severity: p.severity, kind: 'forbidden-access-allowed'", "    if (false) {\n      findings.push({ severity: p.severity, kind: 'forbidden-access-allowed'"],
  ['verify: negative probes are simulated', 'onboarding/aws/verify.mjs', '      simulation = await simulateProbes(aws, arn, [...probes.required, ...probes.denied]);', '      simulation = await simulateProbes(aws, arn, [...probes.required]);'],
  ['verify: ALLOW is not read as DENY', 'onboarding/aws/verify.mjs', "    if (r.decision === 'allowed') {\n      continue;", "    if (r.decision !== 'allowed') {\n      continue;"],
  ['verify: a denial that depends on missing context is not proof', 'onboarding/aws/verify.mjs', "    } else if (r.decision === 'implicitDeny' && r.missingContext.length > 0) {", '    } else if (false) {'],
  ['verify: a refusal that depends on missing context is not a proven FAIL', 'onboarding/aws/verify.mjs', '    const uncertain = r.missingContext.length > 0 || p.possible;', '    const uncertain = p.possible;'],
  ['verify: the policy-text breadth backstop is kept', 'onboarding/aws/verify.mjs', '  if (analysis) {\n    const breadth', '  if (false) {\n    const breadth'],
  ['verify: separation of duties is checked', 'onboarding/aws/verify.mjs', '    separationCheck({ config, roles, target: t }),\n', ''],
  ['verify: two roles with one RoleId are one identity', 'onboarding/aws/verify.mjs', '    } else if (p.roleId === q.roleId) {', '    } else if (false) {'],
  ['verify: a managed repository must be IMMUTABLE', 'onboarding/aws/verify.mjs', "  if (mode !== 'managed') {\n    return adopt(base, { why });", "  if (true) {\n    return adopt(base, { why });"],
  ['verify: the repository is the one in this account and region', 'onboarding/aws/verify.mjs', '  if (result.value.arn !== expectedArn) {', '  if (false) {'],
  ['verify: the scanning configuration is this registry\'s', 'onboarding/aws/verify.mjs', '  } else if (result.value.registryId !== account) {', '  } else if (false) {'],
  ['a MANUAL rule is not automatic scanning coverage', 'onboarding/aws/discover/ecr.mjs', "  const automatic = best && best.frequency !== 'MANUAL';", '  const automatic = best;'],
  ['a wildcard filter matches the whole repository name', 'onboarding/aws/discover/ecr.mjs', '  return new RegExp(`^${body}$`).test(repository);', '  return new RegExp(`^${body}`).test(repository);'],
  ['verify: Inspector enabled is not Inspector coverage', 'onboarding/aws/verify.mjs', '  if (records.length === 0) {', '  if (false) {'],
  ['verify: instance pull access is simulated', 'onboarding/aws/verify.mjs', '  const findings = [...required.findings, ...denied.findings];', '  const findings = [...denied.findings];'],
  ['verify: an unavailable simulation is never PASS', 'onboarding/aws/verify.mjs', "    return { ...c, status: NOT_VERIFIED, findings: [{ severity: NOT_VERIFIED, kind: simulation.error.kind,", "    return { ...c, status: PASS, findings: [{ severity: PASS, kind: simulation.error.kind,"],
  ['verify: an unrecognised simulation decision is malformed', 'onboarding/aws/discover/iam-role.mjs', '      if (!SIMULATION_DECISIONS.includes(r.EvalDecision)) {', '      if (false) {'],
  ['verify: a truncated simulation is malformed', 'onboarding/aws/discover/iam-role.mjs', '    if (got.value.IsTruncated === true) {', '    if (false) {'],
  ['verify: every probe is answered exactly once', 'onboarding/aws/discover/iam-role.mjs', '      if (answers.length !== 1) {', '      if (answers.length === 0) {'],
  ['verify: a required NOT VERIFIED fails the command', 'onboarding/aws/verify.mjs', "  if (checks.some((c) => c.status === NOT_VERIFIED && c.required)) {\n    return 'NOT_VERIFIED';", "  if (false) {\n    return 'NOT_VERIFIED';"],
  ['verify: the fixture simulator is independent of the code', 'test/support/aws-verify-fake.mjs', "          EvalDecision: allowed.has(key) ? 'allowed' : 'implicitDeny',", "          EvalDecision: 'allowed',"],
  // Phase 2E: github plan / apply (onboarding/github)
  ['github: security-gate is matched exactly', 'onboarding/github/protection.mjs', 'return Boolean(entry) && entry.context === REQUIRED_CHECK && Number.isInteger(appId)', 'return Boolean(entry) && Number.isInteger(appId)'],
  ['github: a prefixed status name never matches', 'onboarding/github/protection.mjs', 'return Boolean(entry) && entry.context === REQUIRED_CHECK && Number.isInteger(appId)', 'return Boolean(entry) && entry.context.startsWith(REQUIRED_CHECK) && Number.isInteger(appId)'],
  ['github: a suffixed / embedded status name never matches', 'onboarding/github/protection.mjs', 'return Boolean(entry) && entry.context === REQUIRED_CHECK && Number.isInteger(appId)', 'return Boolean(entry) && entry.context.includes(REQUIRED_CHECK) && Number.isInteger(appId)'],
  ['github: status names are case- and space-sensitive', 'onboarding/github/protection.mjs', 'return Boolean(entry) && entry.context === REQUIRED_CHECK && Number.isInteger(appId)', "return Boolean(entry) && entry.context.toLowerCase().replace(/\\s+/g, '-') === REQUIRED_CHECK && Number.isInteger(appId)"],
  ['github: an unpinned security-gate never satisfies the check', 'onboarding/github/protection.mjs', '&& Number.isInteger(appId) && entry.integration_id === appId;', '&& Number.isInteger(appId) && (entry.integration_id === appId || entry.integration_id == null);'],
  ['github: the GitHub Actions identity is proven, not assumed', 'onboarding/github/discover.mjs', '  if (v.id !== GITHUB_ACTIONS_APP.id || v.slug !== GITHUB_ACTIONS_APP.slug || owner !== GITHUB_ACTIONS_APP.owner) {', '  if (false) {'],
  ['github: GitHub resolving another repository blocks', 'onboarding/github/identity.mjs', '  if (!sameSlug(r.fullName, slug)) {', '  if (false) {'],
  ['github: a local origin naming another repository blocks', 'onboarding/github/identity.mjs', '  if (git.slug && !sameSlug(git.slug, slug)) {', '  if (false) {'],
  ['github: apply never mutates an unresolved identity', 'onboarding/github/identity.mjs', "        mode === 'apply' ? BLOCK : WARN,", '        WARN,'],
  ['github: GitHub reporting another default branch blocks', 'onboarding/github/identity.mjs', '  if (r.defaultBranch !== defaultBranch) {', '  if (false) {'],
  ['github: apply refuses a plan for another default branch', 'onboarding/github/apply.mjs', '  if (input.repository.defaultBranch !== config.repository.defaultBranch) {', '  if (false) {'],
  ['github: apply refuses a plan made against another configuration', 'onboarding/github/apply.mjs', '  if (input.configDigest !== configDigestOf(config)) {', '  if (false) {'],
  ['github: apply only changes the repository the operator named', 'onboarding/github/apply.mjs', '  if (!sameSlug(slug, config.repository.slug)) {', '  if (false) {'],
  ['github: apply requires the live plan to equal the recorded one', 'onboarding/github/apply.mjs', '    if (!derived.planIdInput || planIdOf(derived.planIdInput) !== planId) {', '    if (!derived.planIdInput) {'],
  ['github: apply re-checks immediately before the mutation', 'onboarding/github/apply.mjs', "    derived = await recheck('immediately before the change');", '    derived = await Promise.resolve(derived);'],
  ['github: a plan is applied at most once', 'onboarding/github/apply.mjs', '  if (applied.length > 0) {', '  if (false) {'],
  ['github: the secret value never travels on argv', 'onboarding/github/gh-cli.mjs', '      return run(secretArgv(slug, name), { stdin: value, allowEmpty: true, secrets: [value] });', "      return run([...secretArgv(slug, name), '--body', value.toString('utf8')], { stdin: null, allowEmpty: true, secrets: [value] });"],
  ['github: the secret value never reaches the report or logs', 'onboarding/github/apply.mjs', '        report.execution = { accepted: true, response: null, message: null };', "        report.execution = { accepted: true, response: null, message: value.toString('utf8') };"],
  ['github: supplied secrets are redacted from error text', 'onboarding/github/gh-cli.mjs', '    if (value.length >= 4) {', '    if (false) {'],
  ['github: the secret buffer is zeroed after use', 'onboarding/github/apply.mjs', "    value?.fill(0);\n", "\n"],
  ['github: hidden input never echoes', 'onboarding/github/secret-input.mjs', '        buffer[length] = byte;', '        buffer[length] = byte; output.write(String.fromCharCode(byte));'],
  ['github: records refuse the exact secret being applied', 'onboarding/github/record.mjs', "    if (Buffer.isBuffer(secret) && secret.length > 0 && Buffer.from(text, 'utf8').includes(secret)) {", '    if (false) {'],
  ['github: an omitted bypass list is unknown, never empty (discovery)', 'onboarding/github/discover.mjs', "  if (Array.isArray(v.bypass_actors)) {\n    detail.bypass_actors =", "  detail.bypass_actors = [];\n  if (Array.isArray(v.bypass_actors)) {\n    detail.bypass_actors ="],
  ['github: unknown bypass is NOT VERIFIED, never missing or satisfied', 'onboarding/github/protection.mjs', "      untrusted.some((s) => s.bypass.state === 'unknown')", '      false'],
  ['github: a bypass actor makes a ruleset untrusted', 'onboarding/github/protection.mjs', '  if (detail.bypass_actors.length > 0) {', '  if (false) {'],
  ['github: classic protection without enforce_admins is an admin bypass', 'onboarding/github/protection.mjs', '  if (p.enforce_admins?.enabled !== true) {', '  if (false) {'],
  ['github: code-owner review is required remotely (evaluation)', 'onboarding/github/protection.mjs', "    'code-owner-review': p?.require_code_owner_review === true,", "    'code-owner-review': true,"],
  ['github: the SSD ruleset requires code-owner review', 'onboarding/github/protection.mjs', "  require_code_owner_review: true,\n", "  require_code_owner_review: false,\n"],
  ['github: a drifted SSD-named ruleset is a conflict, never adopted or replaced', 'onboarding/github/protection.mjs', '      if (drift.length > 0) {', '      if (false) {'],
  ['github: rulesets are only ever created, never replaced', 'onboarding/github/gh-cli.mjs', "export const rulesetArgv = (slug) => ['api', '--method', 'POST',", "export const rulesetArgv = (slug) => ['api', '--method', 'PUT',"],
  ['github: the read allowlist refuses arbitrary endpoints', 'onboarding/github/gh-cli.mjs', '    if (!sameArgv(argv, readArgv(endpoint)) || !patterns.some((p) => p.test(endpoint))) {', '    if (!sameArgv(argv, readArgv(endpoint))) {'],
  ['github: reads go through named endpoints only', 'onboarding/github/gh-cli.mjs', '      if (!Object.hasOwn(endpoints, name)) {', '      if (false) {'],
  ['github: the child pins github.com', 'onboarding/github/gh-cli.mjs', "  return { ...out, GH_HOST, GH_PAGER: 'cat',", "  return { ...out, GH_PAGER: 'cat',"],
  ['github: a timeout fails closed', 'onboarding/github/gh-cli.mjs', '  if (timedOut) {', '  if (false) {'],
  ['github: a non-document response fails closed', 'onboarding/github/gh-cli.mjs', "      if (parsed === null || typeof parsed !== 'object') {", '      if (false) {'],
  ["github: CODEOWNERS follows GitHub's lookup order", 'onboarding/github/gh-cli.mjs', "export const CODEOWNERS_PATHS = Object.freeze(['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']);", "export const CODEOWNERS_PATHS = Object.freeze(['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS']);"],
  ['github: a missing CODEOWNERS is never complete', 'onboarding/github/codeowners.mjs', "    out.state = 'incomplete';\n    out.reasons.push(`no CODEOWNERS file", "    out.state = 'complete';\n    out.reasons.push(`no CODEOWNERS file"],
  ['github: GitHub-reported CODEOWNERS errors are not ignored', 'onboarding/github/codeowners.mjs', '  } else if (remote.errors.list.length > 0) {', '  } else if (false) {'],
  ['github: a 5xx after the request leaves the outcome unknown', 'onboarding/github/apply.mjs', 'error.status >= 400 && error.status < 500)', 'error.status >= 400 && error.status < 600)'],
  ['github: the fake GitHub checks argv independently', 'test/support/github-fake.mjs', '      if (!checks.some((check) => { try { check(argv); return true; } catch { return false; } })) {', '      if (false) {'],
  // --- Phase 3C: shared break-glass stacks ---------------------------------------------
  ['TTL is declared on the request table', 'onboarding/aws/templates/shared-break-glass.mjs', '    TimeToLiveSpecification: { AttributeName: TTL_ATTRIBUTE, Enabled: true },\n', ''],
  ['TTL is enabled, not merely named', 'onboarding/aws/templates/shared-break-glass.mjs', '    TimeToLiveSpecification: { AttributeName: TTL_ATTRIBUTE, Enabled: true },', '    TimeToLiveSpecification: { AttributeName: TTL_ATTRIBUTE, Enabled: false },'],
  ['the TTL attribute is exactly ttl', 'onboarding/aws/break-glass/names.mjs', "export const TTL_ATTRIBUTE = 'ttl';", "export const TTL_ATTRIBUTE = 'expiresAt';"],
  ['the table grant is never broadened to *', 'onboarding/aws/policy/break-glass.mjs', '      Action: [...TABLE_ACTIONS[role]],\n      Resource: a.table', "      Action: [...TABLE_ACTIONS[role]],\n      Resource: '*'"],
  ['the CI execution role holds dynamodb:PutItem (replay record)', 'onboarding/aws/policy/break-glass.mjs', "  ci: ['dynamodb:DeleteItem', 'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],", "  ci: ['dynamodb:DeleteItem', 'dynamodb:GetItem', 'dynamodb:UpdateItem'],"],
  ['production and synthetic tables differ', 'onboarding/aws/break-glass/names.mjs', '    table: `${base}-requests`,', "    table: 'ssd-break-glass-requests',"],
  ['production and synthetic secrets differ', 'onboarding/aws/break-glass/names.mjs', "[k, `ssd/break-glass/${environment}/${SECRET_SLUGS[k]}`]", "[k, `ssd/break-glass/${SECRET_SLUGS[k]}`]"],
  ['production and synthetic execution roles differ', 'onboarding/aws/break-glass/names.mjs', '    roles: Object.freeze({ ci: `${base}-ci-execution`, interactions: `${base}-interactions-execution` }),', "    roles: Object.freeze({ ci: 'ssd-break-glass-ci-execution', interactions: 'ssd-break-glass-interactions-execution' }),"],
  ['a break-glass stack carries its own environment tag', 'onboarding/aws/templates/common.mjs', '    { Key: SSD_TAGS.environment, Value: expectedEnvironment({ scope, environment }) },\n', ''],
  ['a break-glass stack is never tagged production by default', 'onboarding/aws/templates/common.mjs', "  if (scope !== 'break-glass') {\n    return DELIVERY_ENVIRONMENT;", "  if (scope !== 'break-glass' || environment === 'synthetic') {\n    return DELIVERY_ENVIRONMENT;"],
  ['a production role never reaches synthetic state', 'onboarding/aws/policy/break-glass.mjs', '      Action: [...TABLE_ACTIONS[role]],\n      Resource: a.table', '      Action: [...TABLE_ACTIONS[role]],\n      Resource: [a.table, breakGlassArns(otherEnvironment(environment), target).table]'],
  ['the cross-environment table probe exists', 'onboarding/aws/policy/break-glass.mjs', '    ...[...TABLE_ACTIONS.ci, ...NEVER_TABLE].map((action) => probe(action, o.table,', '    ...[].map((action) => probe(action, o.table,'],
  ['the interaction function never puts', 'onboarding/aws/policy/break-glass.mjs', "  interactions: ['dynamodb:GetItem', 'dynamodb:UpdateItem']", "  interactions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem']"],
  ['the CI role reads only the bot token', 'onboarding/aws/policy/break-glass.mjs', "const SECRETS = Object.freeze({ ci: ['slackBotToken'],", "const SECRETS = Object.freeze({ ci: ['slackBotToken', 'slackSigningSecret'],"],
  ['an undocumented resource wildcard is a finding', 'onboarding/aws/policy/break-glass.mjs', '        if (/[*?]/.test(resource) && !allowed.has(resource)) {', '        if (false) {'],
  ['execution-role trust is Lambda only', 'onboarding/aws/policy/break-glass.mjs', '      problems.push(`statement ${s.sid} is not "Allow lambda.amazonaws.com sts:AssumeRole"', '      void (`statement ${s.sid} is not "Allow lambda.amazonaws.com sts:AssumeRole"'],
  ['secrets are created without a value', 'onboarding/aws/templates/shared-break-glass.mjs', '      Name: n.secrets[key],\n', "      Name: n.secrets[key],\n      SecretString: 'placeholder',\n"],
  ['the template refuses shared identifiers', 'onboarding/aws/templates/shared-break-glass.mjs', '  assertSeparated(target, { production:', '  void (target, { production:'],
  ['the operator config refuses one Slack channel for both environments', 'onboarding/aws/break-glass/operator-config.mjs', '      assertSeparated({ account: aws.accountId, region: aws.region }, { production: p, synthetic: s });', '      void p, s;'],
  ['the operator config refuses credential values', 'onboarding/aws/break-glass/operator-config.mjs', '  if (hits.length > 0) {\n    throw new OperatorConfigError(', '  if (false) {\n    throw new OperatorConfigError('],
  ['the operator config refuses unknown keys', 'onboarding/aws/break-glass/operator-config.mjs', '    if (!allowed.includes(key)) {', '    if (false) {'],
  ['the CI broker has no Function URL or permission in the template', 'onboarding/aws/templates/shared-break-glass.mjs', "  resources[L.url] = retained('AWS::Lambda::Url', { TargetFunctionArn: arnOf(L.interactionsFunction), AuthType: 'NONE' });", "  resources[L.url] = retained('AWS::Lambda::Url', { TargetFunctionArn: arnOf(L.ciFunction), AuthType: 'NONE' });"],
  ['the public InvokeFunction is via the Function URL only', 'onboarding/aws/templates/shared-break-glass.mjs', '    InvokedViaFunctionUrl: true\n', ''],
  ['async follow-ups are never retried', 'onboarding/aws/templates/shared-break-glass.mjs', '    MaximumRetryAttempts: 0,', '    MaximumRetryAttempts: 2,'],
  ['the code is pinned to an object version', 'onboarding/aws/templates/shared-break-glass.mjs', ', S3ObjectVersion: env.artifact.versionId }', ' }'],
  ['break-glass planning changes only break-glass stacks', 'onboarding/aws/aws-cli.mjs', "      '--stack-name': matches(BREAK_GLASS_STACK_NAMES),\n", "      '--stack-name': true,\n"],
  ['break-glass planning never sends an IMPORT change set', 'onboarding/aws/aws-cli.mjs', "      '--change-set-name': matches(CHANGE_SET_NAME),\n      '--change-set-type': matches(/^(?:CREATE|UPDATE)$/),\n      '--template-body': templateBody,\n      '--tags': ssdTags,\n      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n    },\n    'describe-change-set': { '--stack-name': matches(BREAK_GLASS_STACK_NAMES)", "      '--change-set-name': matches(CHANGE_SET_NAME),\n      '--change-set-type': matches(/^(?:CREATE|UPDATE|IMPORT)$/),\n      '--template-body': templateBody,\n      '--tags': ssdTags,\n      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n    },\n    'describe-change-set': { '--stack-name': matches(BREAK_GLASS_STACK_NAMES)"],
  ['break-glass planning never sends --import-existing-resources', 'onboarding/aws/aws-cli.mjs', "      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n    },\n    'describe-change-set': { '--stack-name': matches(BREAK_GLASS_STACK_NAMES)", "      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/),\n      '--import-existing-resources': false\n    },\n    'describe-change-set': { '--stack-name': matches(BREAK_GLASS_STACK_NAMES)"],
  ['break-glass reads never include a secret value', 'onboarding/aws/aws-cli.mjs', "    'describe-secret': { '--secret-id': is(BREAK_GLASS_SECRET_ID) }", "    'describe-secret': { '--secret-id': is(BREAK_GLASS_SECRET_ID) },\n    'get-secret-value': { '--secret-id': true }"],
  ['break-glass secret reads are confined by name', 'onboarding/aws/aws-cli.mjs', "    'describe-secret': { '--secret-id': is(BREAK_GLASS_SECRET_ID) }", "    'describe-secret': { '--secret-id': true }"],
  ['doctor keeps no break-glass read', 'onboarding/aws/aws-cli.mjs', 'export const BREAK_GLASS_READ_OPERATIONS = union(READ_ONLY_OPERATIONS, BREAK_GLASS_READS);', 'export const BREAK_GLASS_READ_OPERATIONS = union(READ_ONLY_OPERATIONS, BREAK_GLASS_READS);\nObject.assign(READ_ONLY_OPERATIONS.cloudformation, BREAK_GLASS_READS.cloudformation);'],
  ['a break-glass resource owned by another stack blocks the plan', 'onboarding/aws/break-glass/plan.mjs', "      mode: 'managed',\n      discovered,", "      mode: 'existing',\n      discovered,"],
  ['an unversioned artifact bucket blocks', 'onboarding/aws/break-glass/artifact.mjs', "    if (versioning.value.status !== 'Enabled') {", '    if (false) {'],
  ['a public artifact bucket blocks', 'onboarding/aws/break-glass/artifact.mjs', '    if (off.length > 0) {', '    if (false) {'],
  ['an S3 digest mismatch blocks', 'onboarding/aws/break-glass/artifact.mjs', '    } else if (checksum !== expected) {', '    } else if (false) {'],
  ['a break-glass plan is applied only against its operator config', 'onboarding/aws/apply/plan-check.mjs', "  if (plan.createdFromConfigDigest !== operatorDigestOf(operator)) {", '  if (false) {'],
  ['a break-glass plan never applies with .ssd/onboarding.yml', 'onboarding/aws/apply/plan-check.mjs', "  if (plan.scope === 'break-glass' || operator) {", '  if (operator) {'],
  ['apply checks the break-glass stack name', 'onboarding/aws/apply/plan-check.mjs', '  if (!environment || plan.stackName !== BREAK_GLASS_STACKS[environment]) {', '  if (false) {'],
  ['verify: TTL disabled fails', 'onboarding/aws/break-glass/verify.mjs', "    findings.push(fail('ttl-disabled', `TTL is ${status}`));", '    void status;'],
  ['verify: TTL on another attribute fails', 'onboarding/aws/break-glass/verify.mjs', '    if (attribute !== TTL_ATTRIBUTE) findings.push(', '    if (false) findings.push('],
  ['verify: the CI broker has no Function URL', 'onboarding/aws/break-glass/verify.mjs', "  if (url.state === 'present') findings.push(fail('ci-url',", "  if (false) findings.push(fail('ci-url',"],
  ['verify: the CI broker has no resource policy', 'onboarding/aws/break-glass/verify.mjs', "  if (policy.state === 'present') findings.push(fail('ci-resource-policy',", "  if (false) findings.push(fail('ci-resource-policy',"],
  ['verify: a public InvokeFunction must be via the URL', 'onboarding/aws/break-glass/verify.mjs', "conditionValue(s, 'Bool', 'lambda:InvokedViaFunctionUrl') === 'true'", 'true'],
  ['verify: CodeSha256 must be the configured artifact', 'onboarding/aws/break-glass/verify.mjs', 'fn.value.codeSha256 === expected ? []', 'true ? []'],
  ['verify: a function references only its own environment', 'onboarding/aws/break-glass/verify.mjs', "        findings.push(fail('cross-environment-reference',", "        void (fail('cross-environment-reference',"],
  ['verify: a function runs as its own role', 'onboarding/aws/break-glass/verify.mjs', "  if (f.role !== a.roles[role]) findings.push(", '  if (false) findings.push('],
  ['verify: a function environment holds no extra variable', 'onboarding/aws/break-glass/verify.mjs', '    const keys = [...new Set([...Object.keys(want), ...Object.keys(f.variables)])].sort();', '    const keys = Object.keys(want).sort();'],
  ['verify: the stack holds no unexpected resource', 'onboarding/aws/break-glass/verify.mjs', "      findings.push(fail('unexpected-resource',", "      void (fail('unexpected-resource',"],
  ['verify: a secret of the other environment fails', 'onboarding/aws/break-glass/verify.mjs', "    if (tag !== environment) findings.push(", '    if (false) findings.push('],
  ['verify: an attached managed policy fails', 'onboarding/aws/break-glass/verify.mjs', "      if (!(p.kind === 'inline' && p.name === `inline:${n.rolePolicies[role]}`)) findings.push(", '      if (false) findings.push('],
  ['verify: async retries must be 0', 'onboarding/aws/break-glass/verify.mjs', "  if (config.value.maximumRetryAttempts !== 0) findings.push(", '  if (false) findings.push('],
  ['verify: no concurrency cap is WARN, not PASS', 'onboarding/aws/break-glass/verify.mjs', "  return done(c, reserved === null ? [warn('no-concurrency-cap',", "  return done(c, false ? [warn('no-concurrency-cap',"],
  ['Lambda CodeSha256 is base64, not hex', 'onboarding/aws/break-glass/names.mjs', "  return Buffer.from(hex, 'hex').toString('base64');", '  return hex;'],
  ['a missing S3 SHA-256 blocks the plan', 'onboarding/aws/break-glass/artifact.mjs', "      findings.push(f(FAIL, 'artifact-checksum-absent',", "      findings.push(f('NOT VERIFIED', 'artifact-checksum-absent',"],
  ['a composite S3 SHA-256 blocks the plan', 'onboarding/aws/break-glass/artifact.mjs', "      findings.push(f(FAIL, 'artifact-checksum-not-full-object',", "      findings.push(f('NOT VERIFIED', 'artifact-checksum-not-full-object',"],
  ['only a FULL_OBJECT S3 SHA-256 is trusted', 'onboarding/aws/break-glass/artifact.mjs', "head.value.checksumType !== 'FULL_OBJECT' || checksum.includes('-')", "head.value.checksumType === 'COMPOSITE'"],
  ['the public interaction function is provisioned with reserved concurrency', 'onboarding/aws/templates/shared-break-glass.mjs', '  }, { ReservedConcurrentExecutions: INTERACTIONS_RESERVED_CONCURRENCY });', '  });'],
  ['the reservation is the reviewed number', 'onboarding/aws/break-glass/names.mjs', 'export const INTERACTIONS_RESERVED_CONCURRENCY = 5;', 'export const INTERACTIONS_RESERVED_CONCURRENCY = 1000;'],
  ['verify: a missing interaction reservation FAILS, never WARNs', 'onboarding/aws/break-glass/verify.mjs', "    return done(c, [fail('no-concurrency-cap', 'the public interaction", "    return done(c, [warn('no-concurrency-cap', 'the public interaction"],
  ['verify: the interaction reservation must equal the contract', 'onboarding/aws/break-glass/verify.mjs', 'reserved === INTERACTIONS_RESERVED_CONCURRENCY ? []', 'true ? []'],
  ['verify: the interaction concurrency check is required', 'onboarding/aws/break-glass/verify.mjs', "  const required = role === 'interactions';", '  const required = false;'],
  ['plan: a reservation that does not fit the account blocks', 'onboarding/aws/break-glass/plan.mjs', '  if (left < MIN_UNRESERVED_CONCURRENCY) {', '  if (false) {'],
  ['plan: Lambda keeps 100 unreserved', 'onboarding/aws/break-glass/names.mjs', 'export const MIN_UNRESERVED_CONCURRENCY = 100;', 'export const MIN_UNRESERVED_CONCURRENCY = 0;']
];

// Temp-workspace lifecycle
// ------------------------
// Every directory this script creates is owned by the scope that created it and
// is removed by that scope's `finally`, on every exit path. Nothing here globs,
// sweeps a temp parent, or deletes a path it did not itself create: only exact
// paths returned by mkdtempSync are removed. `tmpdir()` is read on each call, so
// TMPDIR keeps working:
//
//   TMPDIR="$HOME/.cache/ssd-verify-tmp" node tools/mutation-check-onboarding.mjs
export const TEMP_PREFIX = 'ssd-mutant-';

// A half-built copy is still a leak: if cpSync fails after mkdtempSync has
// created the root, this removes the root before rethrowing, so no caller has to
// clean up a directory it never received.
export function copyRepo(source = ROOT, parent = tmpdir()) {
  const dir = mkdtempSync(join(parent, TEMP_PREFIX));
  try {
    cpSync(source, dir, {
      recursive: true,
      filter: (src) => !/[\\/](\.git|node_modules|reports)([\\/]|$)/.test(src.slice(source.length))
    });
    return dir;
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

// How a killed mutation is REPORTED — never how it is judged. A non-zero child
// status is the kill; this only turns the child's output into a human-readable
// count. `node --test` prints `# fail N` under the TAP reporter and `ℹ fail N`
// under the spec reporter, and which one a runtime picks is not this script's
// business, so both are read (from stdout AND stderr) and anything unparseable
// falls back to the exit status rather than inventing a number — or printing
// `undefined`, as it did on GitHub's runner.
export function killSummary(result) {
  const output = `${result?.stdout ?? ''}\n${result?.stderr ?? ''}`;
  const failed = /# fail (\d+)/.exec(output)?.[1] ?? /^[^\S\n]*(?:ℹ[^\S\n]*)?fail (\d+)[^\S\n]*$/m.exec(output)?.[1];
  if (failed !== undefined) {
    return `${failed} test(s) failed`;
  }
  return `test suite exited ${result?.status ?? result?.signal ?? 'non-zero'}`;
}

// Returns an exit code rather than calling process.exit, so that every failure
// path — a failing pristine suite included — unwinds through the `finally` that
// owns the pristine copy. A process.exit here would skip it, which is exactly
// how an aborted run used to leave a full repository copy behind.
export function runMutationCheck({
  source = ROOT,
  tests = TESTS,
  mutations = MUTATIONS,
  parent = tmpdir(),
  log = console.log,
  logError = console.error
} = {}) {
  const pristine = copyRepo(source, parent);
  try {
    const baseline = spawnSync(process.execPath, ['--test', ...tests], { cwd: pristine, encoding: 'utf8' });
    if (baseline.status !== 0) {
      logError('The unmutated suite fails; fix it before checking mutations.\n' + (baseline.stdout ?? '').slice(-2000));
      return 1;
    }

    let survivors = 0;
    for (const [invariant, file, search, replace] of mutations) {
      const dir = copyRepo(source, parent);
      try {
        const path = join(dir, file);
        const sourceText = readFileSync(path, 'utf8');
        const count = sourceText.split(search).length - 1;
        if (count !== 1) {
          log(`STALE   ${invariant}: the mutation target occurs ${count} time(s) in ${file}; update this script`);
          survivors += 1;
          continue;
        }
        writeFileSync(path, sourceText.replace(search, replace));
        const result = spawnSync(process.execPath, ['--test', ...tests], { cwd: dir, encoding: 'utf8' });
        if (result.status === 0) {
          log(`SURVIVED ${invariant} (${file})`);
          survivors += 1;
        } else {
          log(`killed   ${invariant} — ${killSummary(result)}`);
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    log(`\n${mutations.length - survivors}/${mutations.length} mutations killed.`);
    return survivors === 0 ? 0 : 1;
  } finally {
    rmSync(pristine, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMutationCheck();
}
