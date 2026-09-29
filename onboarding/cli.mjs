#!/usr/bin/env node
// ssd-onboard — configuration-driven consumer onboarding (Phase 1).
//
// TRUST BOUNDARY: this program edits files in the consumer repository only. It
// makes no AWS calls and no GitHub mutations. The only external programs it runs
// are `git` (read-only) and, for `baseline prepare --run`, `gh api` (GET) and
// `gh run download` — enforced by the allowlist in ghReadOnly().
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';

import { analyze, hasDrift, isBlocking, validationFails } from './lib/analyze.mjs';
import {
  CANDIDATE_FILE,
  NEXT_STEP,
  dispatchInstructions,
  installBaseline,
  loadCandidateForAcceptance,
  prepareCandidate,
  promotionBlockers,
  rolloutState,
  summarizeFindings
} from './lib/baseline.mjs';
import { CONFIG_PATH, isContainerProfile, isEcrProfile, loadConfig, serializeConfig, validateConfig } from './lib/config.mjs';
import { contractProblems } from './lib/contract.mjs';
import { applyWrites, planWrites, removeFile } from './lib/files.mjs';
import { diagnose, doctorErrorReport, doctorExitCode, renderDoctor } from './lib/doctor.mjs';
import { detectFramework } from './lib/framework.mjs';
import { assertSafeRepoPath, safeWriteFile } from './lib/safe-path.mjs';
import { buildConfig, interview } from './lib/init.mjs';
import { semgrepScope } from './lib/coverage.mjs';
import { consumerGitState, inspectRepository } from './lib/inspect.mjs';
import { terminalPrompter } from './lib/prompt.mjs';
import { renderAll } from './lib/render.mjs';
import { renderReport, reportJson } from './lib/report.mjs';
import { parseYaml } from './lib/yaml.mjs';

const run = promisify(execFile);

export class UsageError extends Error {}

const USAGE = `ssd-onboard — configuration-driven onboarding for ssd-security-framework consumers

Usage: node <framework>/onboarding/cli.mjs <command> [options]

Repository commands (edit files in the consumer repository only; no AWS, no GitHub writes):
  onboard [--non-interactive --from <file>] [--adopt <path>]... [--force <path>]...
                          RECOMMENDED FIRST STEP: init + render + validate + doctor in one
                          guided run. Creates the initial log-only state; it never accepts a
                          baseline, enables enforcement, or changes GitHub settings
  init [--non-interactive --from <file>] [--overwrite]
                          derive facts, ask the owner's decisions, write ${CONFIG_PATH}
  inspect [--json]        report what the scanners would and would not cover
  validate [--json]       check config + repository + generated files (CI-friendly)
  doctor [--json]         READ-ONLY operational readiness: lifecycle, drift, governance gaps;
                          exit 1 on any FAIL (WARN / NOT VERIFIED do not fail)
  render [--dry-run] [--adopt <path>]... [--force <path>]... [--prune]
                          regenerate workflows and scanner configs from the config
  render --check          fail if any generated file differs from a fresh render
  update                  alias of render
  baseline status         show the rollout / baseline state
  baseline prepare [--run <run-id>] [--replace-candidate]
                          explain the bootstrap dispatch, or fetch and verify its candidate
  baseline accept [--yes --expect-findings <n>]
                          accept the reviewed candidate as the baseline (explicit)
  promote --enforce [--yes]
                          move log-only -> enforce (requires an accepted baseline)

Cloud commands (Phase 2/3 — designed, not implemented):
  aws doctor|plan|apply|verify

Common options:
  --repo <dir>            consumer repository root (default: current directory)
  -h, --help
`;

// --- external programs -------------------------------------------------------------

// `gh`, restricted to the read-only operations Phase 1 needs.
export function ghReadOnly(execImpl = (args) => run('gh', args, { maxBuffer: 64 * 1024 * 1024 }).then((r) => r.stdout)) {
  return async (args) => {
    const [command, subcommand] = args;
    const isGetApi =
      command === 'api' &&
      !args.some((arg) => /^(-X|--method|-f|-F|--field|--raw-field|--input)(=|$)/.test(arg));
    const isDownload = command === 'run' && subcommand === 'download';
    if (!isGetApi && !isDownload) {
      throw new Error(`refusing to run 'gh ${args.slice(0, 2).join(' ')}': ssd-onboard Phase 1 makes no GitHub mutations`);
    }
    return execImpl(args);
  };
}

// --- shared loading -------------------------------------------------------------------

// The framework revision this CLI belongs to. Tests inject one through io.
async function frameworkFor(io) {
  return io.framework !== undefined ? io.framework : detectFramework();
}

async function loadAnalysis(root, io, { adopt = [], force = [] } = {}) {
  const { config, errors, warnings } = await loadConfig(join(root, CONFIG_PATH));
  const facts = await inspectRepository(root);
  const framework = await frameworkFor(io);
  const result = await analyze({ root, config, configErrors: errors, configWarnings: warnings, facts, adopt, force, framework });
  return { config, facts, framework, result };
}

async function writeConfig(root, config) {
  // Confined to the consumer repository; .ssd/ is created by safeWriteFile.
  await safeWriteFile(root, CONFIG_PATH, serializeConfig(config));
}

async function readPartial(path) {
  const text = await readFile(path, 'utf8');
  return path.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
}

// --- commands -----------------------------------------------------------------------------

// The owner's answers: a partial config from --from, or the interview.
// `init` and `onboard` both take them from here, and both merge them through
// buildConfig — there is one partial-config path.
async function obtainPartial(options, facts, io, prompter, commandName) {
  if (options['non-interactive']) {
    if (!options.from) {
      throw new UsageError('--non-interactive requires --from <partial-config.yml|.json>');
    }
    return readPartial(resolve(options.from));
  }
  return interview(prompter, facts, { cliRef: (await frameworkFor(io))?.sha ?? null, commandName });
}

// partial + facts -> the config and the analysis of writing it. Nothing is
// written. `decisions` / `errors` non-empty means there is no config to analyze.
async function planInit(root, partial, facts, io, { adopt = [], force = [] } = {}) {
  const { config: candidate, decisions } = await buildConfig(partial, facts);
  if (decisions.length > 0) {
    return { decisions, errors: [], config: null, result: null };
  }
  const { config, errors, warnings } = validateConfig(candidate);
  if (errors.length > 0) {
    return { decisions, errors, config: null, result: null };
  }
  const result = await analyze({ root, config, configWarnings: warnings, facts, adopt, force, framework: await frameworkFor(io) });
  return { decisions, errors, config, result };
}

// Prints why planInit produced no config. True when it did not.
function refusedPlan(plan, io) {
  if (plan.decisions.length > 0) {
    io.err(`These decisions belong to the repository owner and were not made:\n${plan.decisions.map((d) => `  - ${d}`).join('\n')}`);
    return true;
  }
  if (plan.errors.length > 0) {
    io.err(`Refusing to write ${CONFIG_PATH}:\n${plan.errors.map((e) => `  - ${e.path}: ${e.message}`).join('\n')}`);
    return true;
  }
  return false;
}

async function configExists(root) {
  try {
    await readFile(join(root, CONFIG_PATH));
    return true;
  } catch {
    return false;
  }
}

async function cmdInit(root, options, io) {
  if ((await configExists(root)) && !options.overwrite) {
    throw new UsageError(`${CONFIG_PATH} already exists. Edit it and run \`ssd-onboard render\`, or pass --overwrite to start over.`);
  }
  const facts = await inspectRepository(root);
  let partial;
  if (options['non-interactive']) {
    partial = await obtainPartial(options, facts, io, null, 'init');
  } else {
    const prompter = io.prompter ?? terminalPrompter();
    try {
      partial = await obtainPartial(options, facts, io, prompter, 'init');
    } finally {
      prompter.close();
    }
  }
  const plan = await planInit(root, partial, facts, io);
  if (refusedPlan(plan, io)) {
    return 1;
  }
  const { config, result } = plan;
  io.out(renderReport(result, { title: 'Effective configuration (not yet written)' }));
  if (!options['non-interactive']) {
    const prompter = io.prompter ?? terminalPrompter();
    try {
      const write = await prompter.confirm({ id: 'writeConfig', question: `Write ${CONFIG_PATH}?`, default: true });
      if (!write) {
        io.err('Nothing written.');
        return 1;
      }
    } finally {
      prompter.close();
    }
  }
  await writeConfig(root, config);
  io.out(`Wrote ${CONFIG_PATH}.`);
  io.out(
    isBlocking(result)
      ? 'Generation is BLOCKED until the errors above are resolved (edit the config, then `ssd-onboard validate`).'
      : 'Next: `ssd-onboard render`, review the diff, and open a pull request.'
  );
  return 0;
}

// `onboard`: the first-time path — init, render, validate and doctor composed in
// process from the same functions those commands use. It adds no rule of its
// own except being STRICTER about when it writes: nothing is written unless the
// complete result (config plus every generated file) would validate, and the
// operator has seen it and said yes. It never accepts a baseline, promotes to
// enforce, adopts or forces a path the operator did not name, or contacts
// GitHub or AWS.
const ALREADY_ONBOARDED = `This repository already has ${CONFIG_PATH}. Nothing was written.

Use:
  ssd-onboard validate    check the config, the repository and the generated files
  ssd-onboard doctor      read-only readiness report
  ssd-onboard render      regenerate the generated files from the config (alias: update)

Use the low-level \`ssd-onboard init --overwrite\` only for a deliberate reinitialization.`;

const PLAN_LABEL = { create: 'CREATE', update: 'UPDATE', unchanged: 'unchanged', forced: 'OVERWRITE', adopted: 'ADOPT', conflict: 'CONFLICT' };

function securityModel(config) {
  const cloud = isEcrProfile(config.profile)
    ? `identifiers recorded for ${config.delivery.aws.accountId}/${config.delivery.aws.region}; NOT contacted or verified; no delivery workflow until promote --enforce`
    : 'not used';
  return [
    'Security model:',
    '  source scanning:   enabled, through the OIDC-free _source-scan.yml (no cloud identity, declared secrets only)',
    `  image scanning:    ${isContainerProfile(config.profile) ? `enabled (${config.container.dockerfile}, built without credentials)` : 'none (source-only)'}`,
    `  Semgrep baseline:  ${config.semgrep.baseline.state}`,
    `  gate mode:         ${config.rollout.gateMode}`,
    `  break-glass:       ${config.breakGlass.mode}`,
    `  AWS/OIDC:          ${cloud}`
  ].join('\n');
}

async function cmdOnboard(root, options, io) {
  const interactive = !options['non-interactive'];
  if (interactive && options.from) {
    throw new UsageError('--from is only read with --non-interactive');
  }
  if (!interactive && !options.from) {
    throw new UsageError('--non-interactive requires --from <partial-config.yml|.json>');
  }
  if (options.overwrite) {
    throw new UsageError('onboard never reinitializes; use `ssd-onboard init --overwrite` deliberately');
  }
  if (await configExists(root)) {
    io.err(ALREADY_ONBOARDED);
    return 1;
  }
  // Only the paths the operator named; never widened, never retried with more.
  const explicit = { adopt: options.adopt ?? [], force: options.force ?? [] };

  io.out('SSD Onboard — creates the initial, log-only integration state for review.\nIt does not accept a baseline, enable enforcement, or configure GitHub; nothing is committed.\n');
  const facts = await inspectRepository(root);
  const prompter = interactive ? io.prompter ?? terminalPrompter() : null;
  let plan;
  try {
    const partial = await obtainPartial(options, facts, io, prompter, 'onboard');
    plan = await planInit(root, partial, facts, io, explicit);
    if (refusedPlan(plan, io)) {
      io.err('Nothing written.');
      return 1;
    }
    const planned = plan.result;
    io.out(renderReport(planned, { title: 'Onboarding plan (nothing written yet)' }));
    if (isBlocking(planned)) {
      io.err('Nothing written: onboarding writes only a state that validates. Resolve the errors above and run `ssd-onboard onboard` again.');
      if (planned.plan.some((entry) => entry.action === 'conflict')) {
        io.err('A CONFLICT is an existing file ssd-onboard will not overwrite on its own. Review it, then re-run with --adopt <path> (human-owned file) or --force <path> (hand-edited generated file) for exactly that path, or move it aside.');
      }
      return 1;
    }
    io.out(securityModel(plan.config));
    io.out(['', 'Planned files:', `  ${'CREATE'.padEnd(9)} ${CONFIG_PATH}`, ...planned.plan.map((entry) => `  ${PLAN_LABEL[entry.action].padEnd(9)} ${entry.path}`)].join('\n'));
    for (const entry of planned.plan.filter((e) => !['create', 'unchanged'].includes(e.action))) {
      io.out(`\n${PLAN_LABEL[entry.action]} ${entry.path}\n${entry.diff}`);
    }
    const consumer = await consumerGitState(root);
    if (facts.git.isGit && !consumer.clean) {
      io.err('Note: the working tree already has uncommitted changes; review `git status` so they are not mixed into the onboarding pull request.');
    }
    if (interactive) {
      const write = await prompter.confirm({ id: 'writeOnboarding', question: 'Write these onboarding files?', default: false });
      if (!write) {
        io.err('Nothing written.');
        return 1;
      }
    }
  } finally {
    prompter?.close();
  }

  // Every path is proven confined BEFORE the first write, so a symbolic link or
  // escaping path refuses the whole onboarding instead of half of it.
  const { config, result } = plan;
  for (const path of [CONFIG_PATH, ...result.plan.map((entry) => entry.path)]) {
    await assertSafeRepoPath(root, path);
  }
  const written = [];
  try {
    try {
      await safeWriteFile(root, CONFIG_PATH, serializeConfig(config), { flag: 'wx' });
    } catch (error) {
      error.failedPath = CONFIG_PATH;
      error.written = [];
      throw error;
    }
    written.push(CONFIG_PATH);
    written.push(...(await applyWrites(root, result.plan)));
  } catch (error) {
    written.push(...(error.written ?? []));
    io.err(`ssd-onboard: writing ${error.failedPath ?? '(unknown path)'} failed: ${error.message}`);
    io.err(
      written.length === 0
        ? 'Onboarding did NOT complete. No file was written.'
        : `Onboarding did NOT complete. Written (nothing was rolled back):\n${written.map((p) => `  ${p}`).join('\n')}\n` +
            `Once the cause is fixed, \`ssd-onboard render\` completes the generated files from ${CONFIG_PATH}; then run \`ssd-onboard validate\`.`
    );
    return 1;
  }

  // What was written is re-read from disk and judged exactly as `validate`
  // judges it — never the pre-write analysis.
  const fresh = await loadAnalysis(root, io);
  const listWritten = `Written (nothing was committed):\n${written.map((p) => `  ${p}`).join('\n')}`;
  if (validationFails(fresh.result)) {
    io.out(renderReport(fresh.result, { title: 'ssd-onboard validate' }));
    io.err(`Onboarding did NOT complete: the written state does not validate.\n${listWritten}\nResolve the errors above, then \`ssd-onboard render\` and \`ssd-onboard validate\`.`);
    return 1;
  }
  const report = diagnose({ result: fresh.result, facts: fresh.facts });
  io.out(`\nReadiness:\n${renderDoctor(report)}`);
  if (doctorExitCode(report) !== 0) {
    io.err(`Onboarding did NOT complete: doctor reports a FAIL.\n${listWritten}`);
    return 1;
  }
  const rollout = fresh.result.rollout.name;
  const lines = [
    'Onboarding generated successfully.',
    'Local validation passed (validate and render --check).',
    listWritten,
    '',
    `Rollout state: ${rollout}`,
    rollout === 'enforcing'
      ? 'Items marked NOT VERIFIED above must still be verified before this repository is relied on.'
      : 'This repository is NOT production-ready yet: WARN and NOT VERIFIED items above are expected at this stage.',
    '',
    'Next:',
    '  1. Review the changes:  git status && git diff',
    '  2. Commit the onboarding files and open a pull request.'
  ];
  if (rollout === 'onboarding') {
    lines.push('  3. After that pull request is merged, run the baseline bootstrap:', '', ...dispatchInstructions(fresh.config).map((line) => (line ? `     ${line}` : '')));
    lines.push('', '     Do not copy a candidate baseline into place by hand.');
  } else {
    lines.push(`  3. After it is merged: ${NEXT_STEP[rollout]}`);
  }
  io.out(`\n${lines.join('\n')}`);
  return 0;
}

async function cmdInspect(root, options, io) {
  let hasConfig = true;
  try {
    await readFile(join(root, CONFIG_PATH));
  } catch {
    hasConfig = false;
  }
  if (hasConfig) {
    const { result } = await loadAnalysis(root, io);
    io.out(options.json ? `${JSON.stringify(reportJson(result), null, 2)}\n` : renderReport(result, { title: 'ssd-onboard inspect' }));
    return 0;
  }
  const facts = await inspectRepository(root);
  const summary = {
    repository: facts.git,
    files: facts.files.length,
    fileSource: facts.fileSource,
    languages: facts.rulesetSuggestion.languages,
    suggestedRulesets: facts.rulesetSuggestion.rulesets,
    suggestedSemgrepExclusions: facts.ignoreSuggestions,
    semgrepScopeToday: semgrepScope(facts.files, { roots: ['.'], ignorePatterns: facts.semgrepignore === null ? null : facts.semgrepignore.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')) }),
    semgrepScopeProposed: semgrepScope(facts.files, { roots: ['.'], ignorePatterns: [] }),
    semgrepignore: facts.semgrepignore === null ? 'absent (Semgrep would apply its built-in ignore list, skipping tests/)' : 'present',
    dockerfiles: facts.dockerfiles,
    manifests: facts.manifests,
    workflows: facts.workflows.map((w) => ({ path: w.path, generatedBySsdOnboard: w.marker.marked, intact: w.marker.intact ?? null })),
    codeowners: facts.codeowners
  };
  if (options.json) {
    io.out(`${JSON.stringify(summary, null, 2)}\n`);
    return 0;
  }
  const lines = ['ssd-onboard inspect (no config yet)', '==================================='];
  lines.push(`Repository:   ${facts.git.slug ?? '(no GitHub origin)'}   default branch: ${facts.git.defaultBranch ?? '(unknown)'}`);
  lines.push(`Files:        ${facts.files.length} (${facts.fileSource})`);
  lines.push(`Languages:    ${facts.rulesetSuggestion.languages.map((l) => `${l.pack} (${l.count})`).join(', ') || 'none detected'}`);
  lines.push(`Semgrep:      suggested rulesets ${facts.rulesetSuggestion.rulesets.join(' ')}; .semgrepignore ${summary.semgrepignore}`);
  // The effective SAST scope today, and what `init` would propose by default.
  const today = semgrepScope(facts.files, {
    roots: ['.'],
    ignorePatterns: facts.semgrepignore === null ? null : facts.semgrepignore.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
  });
  const proposed = semgrepScope(facts.files, { roots: ['.'], ignorePatterns: [] });
  const describe = (scope) =>
    `${scope.inScope} source file(s) scanned, ${scope.ignoredTotal} ignored${scope.ignored.length ? ` (${scope.ignored.map((i) => `${i.pattern}: ${i.count}`).join(', ')})` : ''}`;
  lines.push(`SAST scope today (roots .):    ${describe(today)}${today.implicit ? " — Semgrep's BUILT-IN ignore list" : ''}`);
  lines.push(`SAST scope proposed by init:   ${describe(proposed)} — explicit .semgrepignore, no exclusions`);
  lines.push(`Suggested SAST exclusions (NOT applied without confirmation): ${facts.ignoreSuggestions.map((s) => `${s.pattern} (${s.count})`).join(', ') || 'none'}`);
  lines.push(`Dockerfiles:  ${facts.dockerfiles.join(', ') || 'none'}`);
  lines.push('Dependency manifests:');
  facts.manifests.forEach((m) => lines.push(`  ${m.path.padEnd(40)} ${m.coverage.padEnd(20)} ${m.why.join('; ')}`));
  if (facts.manifests.length === 0) {
    lines.push('  none');
  }
  lines.push('Workflows:');
  facts.workflows.forEach((w) => lines.push(`  ${w.path}${w.marker.marked ? ` (generated by ssd-onboard${w.marker.intact ? '' : ', HAND-EDITED'})` : ''}`));
  lines.push(`CODEOWNERS:   ${facts.codeowners ?? 'none'}`);
  lines.push('', 'Next: `ssd-onboard init`.');
  io.out(`${lines.join('\n')}\n`);
  return 0;
}

async function cmdValidate(root, options, io) {
  const { result } = await loadAnalysis(root, io);
  const drift = result.config ? hasDrift(result) : false;
  if (options.json) {
    io.out(`${JSON.stringify({ ...reportJson(result), drift }, null, 2)}\n`);
  } else {
    io.out(renderReport(result, { title: 'ssd-onboard validate' }));
    if (drift) {
      io.out('Generated files are NOT up to date with the config (see "Files that will change"). Run `ssd-onboard render`.');
    }
  }
  return validationFails(result) ? 1 : 0;
}

// Read-only: the same analysis `validate` decides from, projected into
// readiness checks (lib/doctor.mjs). Writes nothing, contacts nothing.
async function cmdDoctor(root, options, io) {
  let analysis;
  try {
    analysis = await loadAnalysis(root, io);
  } catch (error) {
    if (!options.json) {
      throw error; // the shared `ssd-onboard: <message>` path, exit 1
    }
    io.out(`${JSON.stringify(doctorErrorReport(error), null, 2)}\n`);
    return 1;
  }
  const { facts, result } = analysis;
  const report = diagnose({ result, facts });
  io.out(options.json ? `${JSON.stringify(report, null, 2)}\n` : renderDoctor(report));
  return doctorExitCode(report);
}

async function cmdRender(root, options, io) {
  const adopt = options.adopt ?? [];
  const force = options.force ?? [];
  const { result } = await loadAnalysis(root, io, { adopt, force });
  if (isBlocking(result)) {
    io.out(renderReport(result, { title: options.check ? 'ssd-onboard render --check' : 'ssd-onboard render' }));
    io.err('Nothing written: generation is blocked.');
    return 1;
  }
  const changed = result.plan.filter((entry) => entry.action !== 'unchanged');
  if (options.check) {
    if (!hasDrift(result)) {
      io.out(`Generated files are up to date (${result.plan.length} file(s)).`);
      return 0;
    }
    io.out('Generated files have DRIFTED from .ssd/onboarding.yml:');
    changed.forEach((entry) => io.out(`  ${entry.action.padEnd(9)} ${entry.path}\n${entry.diff}`));
    result.stale.forEach((stale) => io.out(`  stale     ${stale.path}`));
    return 1;
  }
  for (const entry of changed) {
    io.out(`${entry.action.toUpperCase()} ${entry.path}\n${entry.diff}`);
  }
  if (options['dry-run']) {
    io.out(`Dry run: ${changed.length} file(s) would change. Nothing written.`);
    return 0;
  }
  const written = await applyWrites(root, result.plan);
  const pruned = [];
  for (const stale of result.stale) {
    if (!options.prune) {
      continue;
    }
    if (!stale.intact && !force.includes(stale.path)) {
      io.err(`not pruning ${stale.path}: it was edited by hand (pass --force ${stale.path} to remove it anyway)`);
      continue;
    }
    await removeFile(root, stale.path);
    pruned.push(stale.path);
  }
  io.out(`Wrote ${written.length} file(s)${pruned.length ? `, removed ${pruned.length} stale file(s)` : ''}. Nothing was committed.`);
  if (result.stale.length > pruned.length) {
    io.out('Stale generated files remain; pass --prune to remove them.');
  }
  return 0;
}

async function cmdBaseline(root, sub, options, io) {
  const { config, errors } = await loadConfig(join(root, CONFIG_PATH));
  if (!config || errors.length > 0) {
    io.err(`${CONFIG_PATH} is invalid; run \`ssd-onboard validate\`.`);
    return 1;
  }
  if (sub === 'status') {
    const state = await rolloutState(root, config);
    io.out(`Rollout state: ${state.name}`);
    io.out(`  gate mode:  ${config.rollout.gateMode}`);
    io.out(`  baseline:   ${state.baseline.path} (${config.semgrep.baseline.state}; ${state.baseline.exists ? `${state.baseline.findings} finding(s) on disk` : 'absent'})`);
    io.out(`  candidate:  ${state.candidate.exists ? `${CANDIDATE_FILE} (${state.candidate.findings} finding(s), NOT accepted)` : 'none'}`);
    state.problems.forEach((p) => io.out(`  ✗ ${p}`));
    io.out(`Next: ${NEXT_STEP[state.name]}`);
    return state.name === 'inconsistent' ? 1 : 0;
  }
  if (sub === 'prepare') {
    if (!options.run) {
      const state = await rolloutState(root, config);
      if (state.name !== 'onboarding' && state.name !== 'candidate-downloaded') {
        io.err(`baseline prepare is for first onboarding; the rollout state is '${state.name}'.`);
        return 1;
      }
      io.out(dispatchInstructions(config).join('\n'));
      return 0;
    }
    const tmp = await mkdtemp(join(tmpdir(), 'ssd-candidate-'));
    try {
      const { candidate, provenance } = await prepareCandidate({
        root,
        config,
        runId: options.run,
        gh: io.gh ?? ghReadOnly(),
        tmpDir: tmp,
        replace: Boolean(options['replace-candidate'])
      });
      io.out(`Installed a CANDIDATE baseline from run ${provenance.scan.runId} (${provenance.scan.event} on ${provenance.scan.ref} at ${provenance.scan.commit}).`);
      io.out(`  provenance ${provenance.digest}`);
      io.out(`  ${CANDIDATE_FILE}: ${candidate.findings.length} finding(s); rulesets ${candidate.rulesets.join(' ')}`);
      summarizeFindings(candidate).forEach(([rule, count]) => io.out(`    ${String(count).padStart(4)}  ${rule}`));
      io.out('It is NOT accepted. Review every finding, then run `ssd-onboard baseline accept`.');
      return 0;
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }
  if (sub === 'accept') {
    // Machine checks first: the repository must be valid and bound to the
    // framework, and the candidate bound to exactly this checkout. Only then is
    // a human asked to confirm.
    const { result } = await loadAnalysis(root, io);
    if (isBlocking(result)) {
      io.out(renderReport(result, { title: 'ssd-onboard baseline accept' }));
      io.err('Not accepted: the repository has blocking problems.');
      return 1;
    }
    const consumer = await consumerGitState(root);
    const { candidate, text, provenance } = await loadCandidateForAcceptance({ root, config, consumer });
    const count = candidate.findings.length;
    io.out(
      `Candidate from run ${provenance.scan.runId} (${provenance.scan.event} on ${provenance.scan.ref} at ${provenance.scan.commit}),\n` +
        `framework ${provenance.framework.ref}, ${provenance.semgrep.version ?? 'semgrep'} ${provenance.semgrep.image ?? ''}\n` +
        `provenance ${provenance.digest} — bound to this checkout.`
    );
    io.out(`Accepting it makes these ${count} Semgrep finding(s) PERMANENTLY non-blocking:`);
    summarizeFindings(candidate).forEach(([rule, n]) => io.out(`  ${String(n).padStart(4)}  ${rule}`));
    candidate.findings.forEach((f) => io.out(`        ${f.path}  ${f.checkId}  ${f.fingerprint.slice(0, 12)}`));
    if (options.yes) {
      if (options['expect-findings'] === undefined || Number(options['expect-findings']) !== count) {
        io.err(`--yes requires --expect-findings ${count} (the exact number being accepted).`);
        return 1;
      }
    } else {
      const prompter = io.prompter ?? terminalPrompter();
      try {
        const typed = await prompter.ask({ id: 'confirmFindings', question: `Type ${count} to accept these ${count} finding(s), anything else to abort` });
        if (typed !== String(count)) {
          io.err('Not accepted. Nothing written.');
          return 1;
        }
      } finally {
        prompter.close();
      }
    }
    const facts = await inspectRepository(root);
    // Plan the re-render BEFORE touching disk, so a conflict aborts the whole
    // acceptance rather than leaving a baseline with stale workflows.
    const next = { ...config, semgrep: { ...config.semgrep, baseline: { ...config.semgrep.baseline, state: 'accepted' } } };
    const plan = await planWrites(root, renderAll(next));
    if (plan.some((entry) => entry.action === 'conflict')) {
      io.err('Refusing: a generated file is in conflict; run `ssd-onboard render` to see why. The baseline was not written.');
      return 1;
    }
    const accepted = await installBaseline({ root, config, text, semgrepignoreText: facts.semgrepignore });
    await writeConfig(root, accepted);
    await applyWrites(root, plan);
    io.out(`Accepted: ${config.semgrep.baseline.path} (${count} finding(s)); semgrep.baseline.state: accepted.`);
    plan.filter((e) => e.action !== 'unchanged').forEach((e) => io.out(`${e.action.toUpperCase()} ${e.path}\n${e.diff}`));
    io.out('The bootstrap dispatch input was removed from the security workflow. Nothing was committed.');
    return 0;
  }
  throw new UsageError(`unknown baseline command '${sub ?? ''}' (status | prepare | accept)`);
}

async function cmdPromote(root, options, io) {
  if (!options.enforce) {
    throw new UsageError('promote requires --enforce (the only promotion there is)');
  }
  const { config, framework, result } = await loadAnalysis(root, io);
  if (!config) {
    io.out(renderReport(result));
    return 1;
  }
  const blockers = await promotionBlockers({ root, config });
  if (isBlocking(result)) {
    blockers.push(...result.errors.map((e) => `[${e.area}] ${e.message}`));
  }
  if (blockers.length > 0) {
    io.err(`Refusing to promote to enforce:\n${blockers.map((b) => `  - ${b}`).join('\n')}`);
    return 1;
  }
  const next = { ...config, rollout: { ...config.rollout, gateMode: 'enforce' } };
  const check = validateConfig(next);
  if (check.errors.length > 0) {
    io.err(`Refusing: ${check.errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`);
    return 1;
  }
  // The enforcing render adds files (the ECR delivery workflow): check them
  // against the pinned framework contracts too, before anything is written.
  const rendered = renderAll(check.config);
  const contract = await contractProblems(rendered, check.config, framework.readWorkflow);
  if (contract.problems.length > 0 || contract.unverified.length > 0) {
    io.err(`Refusing: the enforcing workflows do not match the framework contracts:\n${[...contract.problems, ...contract.unverified].map((p) => `  - ${p}`).join('\n')}`);
    return 1;
  }
  const plan = await planWrites(root, rendered);
  if (plan.some((entry) => entry.action === 'conflict')) {
    io.err('Refusing: a generated file is in conflict; run `ssd-onboard render` to see why.');
    return 1;
  }
  io.out('Promoting log-only -> enforce. A BLOCK will now fail the required security-gate check.');
  plan.filter((e) => e.action !== 'unchanged').forEach((e) => io.out(`${e.action.toUpperCase()} ${e.path}\n${e.diff}`));
  if (!options.yes) {
    const prompter = io.prompter ?? terminalPrompter();
    try {
      if (!(await prompter.confirm({ id: 'confirmPromote', question: 'Write these changes?', default: false }))) {
        io.err('Not promoted. Nothing written.');
        return 1;
      }
    } finally {
      prompter.close();
    }
  }
  await writeConfig(root, check.config);
  await applyWrites(root, plan);
  io.out('rollout.gateMode: enforce. Review the diff, open a pull request, and require `security-gate` in branch protection. Nothing was committed.');
  return 0;
}

// --- dispatch ---------------------------------------------------------------------------------

const OPTIONS = {
  repo: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
  json: { type: 'boolean' },
  check: { type: 'boolean' },
  'dry-run': { type: 'boolean' },
  adopt: { type: 'string', multiple: true },
  force: { type: 'string', multiple: true },
  prune: { type: 'boolean' },
  overwrite: { type: 'boolean' },
  'non-interactive': { type: 'boolean' },
  from: { type: 'string' },
  run: { type: 'string' },
  'replace-candidate': { type: 'boolean' },
  yes: { type: 'boolean' },
  'expect-findings': { type: 'string' },
  enforce: { type: 'boolean' }
};

export async function main(argv, io = {}) {
  const out = io.out ?? ((text) => process.stdout.write(text.endsWith('\n') ? text : `${text}\n`));
  const err = io.err ?? ((text) => process.stderr.write(text.endsWith('\n') ? text : `${text}\n`));
  const context = { ...io, out, err };
  try {
    const [command, ...args] = argv;
    const { values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true });
    if (!command || values.help || command === 'help') {
      out(USAGE);
      return command ? 0 : 2;
    }
    const root = resolve(values.repo ?? process.cwd());
    switch (command) {
      case 'onboard':
        return await cmdOnboard(root, values, context);
      case 'init':
        return await cmdInit(root, values, context);
      case 'inspect':
        return await cmdInspect(root, values, context);
      case 'validate':
        return await cmdValidate(root, values, context);
      case 'doctor':
        return await cmdDoctor(root, values, context);
      case 'render':
      case 'update':
        return await cmdRender(root, values, context);
      case 'baseline':
        return await cmdBaseline(root, positionals[0], values, context);
      case 'promote':
        return await cmdPromote(root, values, context);
      case 'aws':
      case 'github':
        err(
          `'ssd-onboard ${command}' is Phase ${command === 'aws' ? '2/3' : '2'} and is not implemented in this version.\n` +
            'Its reviewed design is in docs/onboarding-architecture.md (Parts D and E). Nothing was contacted.'
        );
        return 2;
      default:
        throw new UsageError(`unknown command '${command}'`);
    }
  } catch (error) {
    if (error instanceof UsageError || error.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION' || error.code === 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE') {
      err(`${error.message}\n\n${USAGE}`);
      return 2;
    }
    err(`ssd-onboard: ${error.message}`);
    return 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  process.exitCode = await main(process.argv.slice(2));
}
