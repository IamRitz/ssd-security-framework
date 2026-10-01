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
  'test/aws-plan.test.js'
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
  ['a stack for another consumer is never managed', 'onboarding/aws/discover/stacks.mjs', "  if (scope === 'repo' && consumer !== canonical) {", '  if (false) {'],
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
  ['ownership requires ssd:environment=production', 'onboarding/aws/discover/stacks.mjs', '  if (environment !== DELIVERY_ENVIRONMENT) {', '  if (false) {'],
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
  ['the planner never sends an IMPORT change set', 'onboarding/aws/aws-cli.mjs', "matches(/^(?:CREATE|UPDATE)$/)", "matches(/^(?:CREATE|UPDATE|IMPORT)$/)"],
  ['the planner never sends --import-existing-resources', 'onboarding/aws/aws-cli.mjs', "      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)\n", "      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/),\n      '--import-existing-resources': false\n"],
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
  ["only the stack's own inline policy name is managed", 'onboarding/aws/plan.mjs', "    const ours = policies.policies.find((p) => p.kind === 'inline' && p.name === `inline:${ROLE_POLICY_NAMES[key]}`);", "    const ours = policies.policies.find((p) => p.kind === 'inline');"],
  ['an unreadable policy list on an owned role blocks', 'onboarding/aws/plan.mjs', "        finding(FAIL, 'policies-unverified',", "        finding(NOT_VERIFIED, 'policies-unverified',"],
  ['the fake planning harness enforces the planning allowlist itself', 'test/support/aws-plan-fake.mjs', 'export const planFake = (world) => fakeAws(world, { allowlist: assertPlanning });', 'export const planFake = (world) => fakeAws(world, { allowlist: () => {} });'],
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
