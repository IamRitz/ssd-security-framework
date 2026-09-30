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
import { diagnose, doctorBlocks, doctorErrorReport, doctorExitCode } from './lib/doctor.mjs';
import { detectFramework } from './lib/framework.mjs';
import { assertSafeRepoPath, safeWriteFile } from './lib/safe-path.mjs';
import { buildConfig, interview } from './lib/init.mjs';
import { semgrepScope } from './lib/coverage.mjs';
import { consumerGitState, inspectRepository } from './lib/inspect.mjs';
import { PLAIN, blank, command, diff, dim, fileRow, format, group, heading, outputStyle, row, rows, section, status, text } from './lib/output.mjs';
import { terminalPrompter } from './lib/prompt.mjs';
import { renderAll } from './lib/render.mjs';
import { manifestRows, reportBlocks, reportJson } from './lib/report.mjs';
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

// --- human output helpers ----------------------------------------------------------

// A refusal: one FAIL row and the reasons beneath it.
const refusal = (title, items = []) => [rows([status('FAIL', title)]), items.length > 0 && group(text(items.map((item) => `- ${item}`)))];

// Instruction lines (baseline.mjs): lines indented by two spaces are commands.
const instructions = (lines) => lines.map((line) => (line.startsWith('  ') ? command(line.trim()) : text(line)));

// The baseline lifecycle, in order (baseline.mjs rolloutState).
const LIFECYCLE = ['onboarding', 'candidate-downloaded', 'baseline-accepted', 'enforcing'];

// Findings per rule, most first (baseline.mjs summarizeFindings).
const findingCounts = (candidate) => rows(summarizeFindings(candidate).map(([rule, n]) => row(String(n).padStart(4), rule)));

// Prints why planInit produced no config. True when it did not.
function refusedPlan(plan, io) {
  if (plan.decisions.length > 0) {
    io.printErr(refusal('These decisions belong to the repository owner and were not made:', plan.decisions));
    return true;
  }
  if (plan.errors.length > 0) {
    io.printErr(refusal(`Refusing to write ${CONFIG_PATH}:`, plan.errors.map((e) => `${e.path}: ${e.message}`)));
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
  io.print(reportBlocks(result, { title: 'SSD Init', notes: ['Effective configuration (not yet written)'] }));
  if (!options['non-interactive']) {
    const prompter = io.prompter ?? terminalPrompter();
    try {
      const write = await prompter.confirm({ id: 'writeConfig', question: `Write ${CONFIG_PATH}?`, default: true });
      if (!write) {
        io.printErr(refusal('Nothing written.'));
        return 1;
      }
    } finally {
      prompter.close();
    }
  }
  await writeConfig(root, config);
  io.print(
    section('Written', rows([fileRow('create', CONFIG_PATH)])),
    section(
      'Next',
      isBlocking(result)
        ? rows([status('FAIL', 'Generation is BLOCKED until the errors above are resolved (edit the config, then `ssd-onboard validate`).')])
        : text('`ssd-onboard render`, review the diff, and open a pull request.')
    )
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

function securityModel(config) {
  const cloud = isEcrProfile(config.profile)
    ? `identifiers recorded for ${config.delivery.aws.accountId}/${config.delivery.aws.region}; NOT contacted or verified; no delivery workflow until promote --enforce`
    : 'not used';
  return section(
    'Security model',
    rows([
      row('Source scanning', 'enabled, through the OIDC-free _source-scan.yml (no cloud identity, declared secrets only)'),
      row('Image scanning', isContainerProfile(config.profile) ? `enabled (${config.container.dockerfile}, built without credentials)` : 'none (source-only)'),
      row('Semgrep baseline', config.semgrep.baseline.state),
      row('Gate mode', config.rollout.gateMode),
      row('Break-glass', config.breakGlass.mode),
      row('AWS/OIDC', cloud)
    ])
  );
}

// The diff of every planned write that changes an existing file.
const changeDiffs = (plan) => {
  const changes = plan.filter((entry) => !['create', 'unchanged'].includes(entry.action));
  return changes.length === 0 ? [] : [section('Changes to existing files', changes.flatMap((entry) => [rows([fileRow(entry.action, entry.path)]), diff(entry.diff)]))];
};

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

  io.print(
    heading(
      'SSD Onboard',
      'Creates the initial, log-only integration state for review.',
      'It does not accept a baseline, enable enforcement, or configure GitHub; nothing is committed.'
    )
  );
  const facts = await inspectRepository(root);
  const prompter = interactive ? io.prompter ?? terminalPrompter() : null;
  let plan;
  try {
    const partial = await obtainPartial(options, facts, io, prompter, 'onboard');
    plan = await planInit(root, partial, facts, io, explicit);
    if (refusedPlan(plan, io)) {
      io.printErr(refusal('Nothing written.'));
      return 1;
    }
    const planned = plan.result;
    const blocking = isBlocking(planned);
    io.print(
      reportBlocks(planned, {
        title: 'Onboarding plan',
        notes: ['Nothing is written yet.'],
        files: [{ action: 'create', path: CONFIG_PATH }],
        extra: blocking ? [] : [securityModel(plan.config)]
      }),
      blocking ? [] : changeDiffs(planned.plan)
    );
    if (blocking) {
      io.printErr(
        refusal('Nothing written: onboarding writes only a state that validates.', [
          'Resolve the blocking issues above and run `ssd-onboard onboard` again.',
          ...(planned.plan.some((entry) => entry.action === 'conflict')
            ? [
                'A CONFLICT is an existing file ssd-onboard will not overwrite on its own. Review it, then re-run with --adopt <path> (human-owned file) or --force <path> (hand-edited generated file) for exactly that path, or move it aside.'
              ]
            : [])
        ])
      );
      return 1;
    }
    const consumer = await consumerGitState(root);
    if (facts.git.isGit && !consumer.clean) {
      io.printErr(rows([status('WARN', 'Note: the working tree already has uncommitted changes; review `git status` so they are not mixed into the onboarding pull request.')]));
    }
    if (interactive) {
      const write = await prompter.confirm({ id: 'writeOnboarding', question: 'Write these onboarding files?', default: false });
      if (!write) {
        io.printErr(refusal('Nothing written.'));
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
    io.printErr(
      written.length === 0
        ? refusal('Onboarding did NOT complete. No file was written.')
        : [
            refusal('Onboarding did NOT complete. Written (nothing was rolled back):', written),
            text(`Once the cause is fixed, \`ssd-onboard render\` completes the generated files from ${CONFIG_PATH}; then run \`ssd-onboard validate\`.`)
          ]
    );
    return 1;
  }

  // What was written is re-read from disk and judged exactly as `validate`
  // judges it — never the pre-write analysis.
  const fresh = await loadAnalysis(root, io);
  const actionOf = new Map([[CONFIG_PATH, 'create'], ...result.plan.map((entry) => [entry.path, entry.action])]);
  const writtenRows = rows(written.map((path) => fileRow(actionOf.get(path) ?? 'update', path)));
  if (validationFails(fresh.result)) {
    io.print(reportBlocks(fresh.result, { title: 'SSD Validate', drift: hasDrift(fresh.result) }));
    io.printErr(
      refusal('Onboarding did NOT complete: the written state does not validate.'),
      section('Written (nothing was committed)', writtenRows),
      text('Resolve the errors above, then `ssd-onboard render` and `ssd-onboard validate`.')
    );
    return 1;
  }
  const report = diagnose({ result: fresh.result, facts: fresh.facts });
  io.print(blank(), doctorBlocks(report, { title: 'Readiness' }));
  if (doctorExitCode(report) !== 0) {
    io.printErr(refusal('Onboarding did NOT complete: doctor reports a FAIL.'), section('Written (nothing was committed)', writtenRows));
    return 1;
  }
  const rollout = fresh.result.rollout.name;
  const next = [text('1. Review the changes:'), group(command('git status && git diff')), text('2. Commit the onboarding files and open a pull request.')];
  if (rollout === 'onboarding') {
    next.push(
      text('3. After that pull request is merged, run the baseline bootstrap:'),
      group(instructions(dispatchInstructions(fresh.config)), blank(), text('Do not copy a candidate baseline into place by hand.'))
    );
  } else {
    next.push(text(`3. After it is merged: ${NEXT_STEP[rollout]}`));
  }
  io.print(
    section('Result', rows([status('PASS', 'Onboarding generated successfully.'), status('PASS', 'Local validation passed (validate and render --check).')])),
    section('Written (nothing was committed)', writtenRows),
    section(
      'Rollout',
      rows([row('State', rollout, { strong: true })]),
      rows([
        status(
          'WARN',
          rollout === 'enforcing'
            ? 'Items marked NOT VERIFIED above must still be verified before this repository is relied on.'
            : 'This repository is NOT production-ready yet: WARN and NOT VERIFIED items above are expected at this stage.'
        )
      ])
    ),
    section('Next', next)
  );
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
    if (options.json) {
      io.json(reportJson(result));
    } else {
      io.print(reportBlocks(result, { title: 'SSD Inspect' }));
    }
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
    io.json(summary);
    return 0;
  }
  // The effective SAST scope today, and what `init` would propose by default.
  const today = summary.semgrepScopeToday;
  const proposed = summary.semgrepScopeProposed;
  const describe = (scope) =>
    `${scope.inScope} source file(s) scanned · ${scope.ignoredTotal} ignored${scope.ignored.length ? ` (${scope.ignored.map((i) => `${i.pattern}: ${i.count}`).join(', ')})` : ''}`;
  const languages = facts.rulesetSuggestion.languages;
  io.print(
    heading('SSD Inspect', 'No configuration yet: what the scanners would and would not cover.'),
    section(
      'Repository',
      rows([
        row('Name', facts.git.slug ?? '(no GitHub origin)', { strong: true }),
        row('Default branch', facts.git.defaultBranch ?? '(unknown)'),
        row('Files', `${facts.files.length} (${facts.fileSource})`)
      ])
    ),
    section('Languages', languages.length ? rows(languages.map((l) => row(l.pack, `${l.count} file(s)`))) : dim('none detected')),
    section(
      'SAST',
      rows([
        row('Suggested rulesets', facts.rulesetSuggestion.rulesets.join(' ')),
        row('.semgrepignore', summary.semgrepignore),
        row('Scope today', `${describe(today)} (roots .)`, { details: today.implicit ? "Semgrep's BUILT-IN ignore list" : [] }),
        row('Scope with init', describe(proposed), { details: 'explicit .semgrepignore, no exclusions' }),
        row('Suggested exclusions', facts.ignoreSuggestions.map((i) => `${i.pattern} (${i.count})`).join(', ') || 'none', {
          details: 'NOT applied without confirmation'
        })
      ])
    ),
    section('Containers', rows([row('Dockerfiles', facts.dockerfiles.join(', ') || 'none')])),
    section('Dependencies', facts.manifests.length ? manifestRows(facts.manifests) : dim('none')),
    section(
      'Workflows',
      facts.workflows.length
        ? rows(facts.workflows.map((w) => row(w.path, w.marker.marked ? `generated by ssd-onboard${w.marker.intact ? '' : ', HAND-EDITED'}` : '')))
        : dim('none')
    ),
    section('Governance', rows([status(facts.codeowners ? 'PASS' : 'WARN', 'CODEOWNERS', facts.codeowners ?? 'none')])),
    section('Next', text('`ssd-onboard init`.'))
  );
  return 0;
}

async function cmdValidate(root, options, io) {
  const { result } = await loadAnalysis(root, io);
  const drift = result.config ? hasDrift(result) : false;
  if (options.json) {
    io.json({ ...reportJson(result), drift });
  } else {
    io.print(reportBlocks(result, { title: 'SSD Validate', drift }));
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
    io.json(doctorErrorReport(error));
    return 1;
  }
  const { facts, result } = analysis;
  const report = diagnose({ result, facts });
  if (options.json) {
    io.json(report);
  } else {
    io.print(doctorBlocks(report));
  }
  return doctorExitCode(report);
}

// Planned changes with their diffs, for render / accept / promote.
const changeBlocks = (entries, title = 'Files') =>
  entries.length === 0 ? [] : [section(title, rows(entries.map((entry) => fileRow(entry.action, entry.path)))), section('Diffs', entries.flatMap((entry) => [rows([fileRow(entry.action, entry.path)]), diff(entry.diff)]))];

async function cmdRender(root, options, io) {
  const adopt = options.adopt ?? [];
  const force = options.force ?? [];
  const title = options.check ? 'SSD Render --check' : 'SSD Render';
  const { result } = await loadAnalysis(root, io, { adopt, force });
  if (isBlocking(result)) {
    io.print(reportBlocks(result, { title }));
    io.printErr(refusal('Nothing written: generation is blocked.'));
    return 1;
  }
  const changed = result.plan.filter((entry) => entry.action !== 'unchanged');
  if (options.check) {
    if (!hasDrift(result)) {
      io.print(heading(title), section('Result', rows([status('PASS', `Generated files are up to date (${result.plan.length} file(s)).`)], { words: true })));
      return 0;
    }
    io.print(
      heading(title),
      section(
        'Files',
        rows([
          ...changed.map((entry) => fileRow(entry.action, entry.path)),
          ...result.stale.map((stale) => fileRow('stale', stale.path, '', { details: 'generated, no longer produced; --prune removes it' }))
        ])
      ),
      changed.length ? section('Diffs', changed.flatMap((entry) => [rows([fileRow(entry.action, entry.path)]), diff(entry.diff)])) : [],
      section('Result', rows([status('FAIL', `Generated files have DRIFTED from ${CONFIG_PATH}.`)], { words: true }), text('Run `ssd-onboard render`.'))
    );
    return 1;
  }
  io.print(heading(title), changeBlocks(changed));
  if (options['dry-run']) {
    io.print(section('Result', text(`Dry run: ${changed.length} file(s) would change. Nothing written.`)));
    return 0;
  }
  const written = await applyWrites(root, result.plan);
  const pruned = [];
  for (const stale of result.stale) {
    if (!options.prune) {
      continue;
    }
    if (!stale.intact && !force.includes(stale.path)) {
      io.printErr(rows([status('WARN', `not pruning ${stale.path}: it was edited by hand (pass --force ${stale.path} to remove it anyway)`)]));
      continue;
    }
    await removeFile(root, stale.path);
    pruned.push(stale.path);
  }
  io.print(
    section(
      'Result',
      text(`Wrote ${written.length} file(s)${pruned.length ? `, removed ${pruned.length} stale file(s)` : ''}. Nothing was committed.`),
      result.stale.length > pruned.length ? rows([status('WARN', 'Stale generated files remain; pass --prune to remove them.')]) : []
    )
  );
  return 0;
}

async function cmdBaseline(root, sub, options, io) {
  const { config, errors } = await loadConfig(join(root, CONFIG_PATH));
  if (!config || errors.length > 0) {
    io.printErr(refusal(`${CONFIG_PATH} is invalid; run \`ssd-onboard validate\`.`));
    return 1;
  }
  if (sub === 'status') {
    const state = await rolloutState(root, config);
    io.print(
      heading('SSD Baseline'),
      section(
        'Rollout',
        rows([
          row('State', state.name, { strong: true }),
          row('Lifecycle', LIFECYCLE.map((name) => (name === state.name ? `[${name}]` : name)).join(' → ')),
          row('Gate mode', config.rollout.gateMode),
          row(
            'Baseline',
            `${state.baseline.path} (${config.semgrep.baseline.state}; ${state.baseline.exists ? `${state.baseline.findings} finding(s) on disk` : 'absent'})`
          ),
          row('Candidate', state.candidate.exists ? `${CANDIDATE_FILE} (${state.candidate.findings} finding(s), NOT accepted)` : 'none')
        ])
      ),
      state.problems.length ? section('Problems', rows(state.problems.map((p) => status('FAIL', p)))) : [],
      section('Next', text(NEXT_STEP[state.name]))
    );
    return state.name === 'inconsistent' ? 1 : 0;
  }
  if (sub === 'prepare') {
    if (!options.run) {
      const state = await rolloutState(root, config);
      if (state.name !== 'onboarding' && state.name !== 'candidate-downloaded') {
        io.printErr(refusal(`baseline prepare is for first onboarding; the rollout state is '${state.name}'.`));
        return 1;
      }
      io.print(heading('SSD Baseline prepare'), section('Bootstrap dispatch', instructions(dispatchInstructions(config))));
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
      io.print(
        heading('SSD Baseline prepare'),
        section(
          'Candidate baseline',
          rows([
            status('WARN', 'Installed a CANDIDATE baseline', 'NOT accepted'),
            row('Run', `${provenance.scan.runId} (${provenance.scan.event} on ${provenance.scan.ref} at ${provenance.scan.commit})`),
            row('Provenance', provenance.digest),
            row('File', CANDIDATE_FILE),
            row('Findings', `${candidate.findings.length} finding(s)`),
            row('Rulesets', candidate.rulesets.join(' '))
          ])
        ),
        section('Findings by rule', findingCounts(candidate)),
        section('Next', text('It is NOT accepted. Review every finding, then run `ssd-onboard baseline accept`.'))
      );
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
      io.print(reportBlocks(result, { title: 'SSD Baseline accept' }));
      io.printErr(refusal('Not accepted: the repository has blocking problems.'));
      return 1;
    }
    const consumer = await consumerGitState(root);
    const { candidate, text: candidateText, provenance } = await loadCandidateForAcceptance({ root, config, consumer });
    const count = candidate.findings.length;
    io.print(
      heading('SSD Baseline accept'),
      section(
        'Candidate',
        rows([
          row('Run', `${provenance.scan.runId} (${provenance.scan.event} on ${provenance.scan.ref} at ${provenance.scan.commit})`),
          row('Framework', provenance.framework.ref),
          row('Semgrep', `${provenance.semgrep.version ?? 'semgrep'} ${provenance.semgrep.image ?? ''}`.trim()),
          row('Provenance', `${provenance.digest} — bound to this checkout.`)
        ])
      ),
      section(
        `Findings (${count})`,
        rows([status('WARN', `Accepting it makes these ${count} Semgrep finding(s) PERMANENTLY non-blocking:`)]),
        findingCounts(candidate),
        rows(candidate.findings.map((f) => row(f.path, `${f.checkId}  ${f.fingerprint.slice(0, 12)}`)))
      )
    );
    if (options.yes) {
      if (options['expect-findings'] === undefined || Number(options['expect-findings']) !== count) {
        io.printErr(refusal(`--yes requires --expect-findings ${count} (the exact number being accepted).`));
        return 1;
      }
    } else {
      const prompter = io.prompter ?? terminalPrompter();
      try {
        const typed = await prompter.ask({ id: 'confirmFindings', question: `Type ${count} to accept these ${count} finding(s), anything else to abort` });
        if (typed !== String(count)) {
          io.printErr(refusal('Not accepted. Nothing written.'));
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
      io.printErr(refusal('Refusing: a generated file is in conflict; run `ssd-onboard render` to see why. The baseline was not written.'));
      return 1;
    }
    const accepted = await installBaseline({ root, config, text: candidateText, semgrepignoreText: facts.semgrepignore });
    await writeConfig(root, accepted);
    await applyWrites(root, plan);
    const after = await rolloutState(root, accepted);
    io.print(
      section(
        'Accepted',
        rows([
          status('PASS', `Accepted: ${config.semgrep.baseline.path} (${count} finding(s)); semgrep.baseline.state: accepted.`),
          row('Rollout state', after.name, { strong: true })
        ])
      ),
      changeBlocks(plan.filter((e) => e.action !== 'unchanged')),
      section('Next', text('The bootstrap dispatch input was removed from the security workflow. Nothing was committed.'), text(NEXT_STEP[after.name]))
    );
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
    io.print(reportBlocks(result, { title: 'SSD Promote' }));
    return 1;
  }
  const blockers = await promotionBlockers({ root, config });
  if (isBlocking(result)) {
    blockers.push(...result.errors.map((e) => `[${e.area}] ${e.message}`));
  }
  if (blockers.length > 0) {
    io.printErr(refusal('Refusing to promote to enforce:', blockers));
    return 1;
  }
  const next = { ...config, rollout: { ...config.rollout, gateMode: 'enforce' } };
  const check = validateConfig(next);
  if (check.errors.length > 0) {
    io.printErr(refusal(`Refusing: ${check.errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`));
    return 1;
  }
  // The enforcing render adds files (the ECR delivery workflow): check them
  // against the pinned framework contracts too, before anything is written.
  const rendered = renderAll(check.config);
  const contract = await contractProblems(rendered, check.config, framework.readWorkflow);
  if (contract.problems.length > 0 || contract.unverified.length > 0) {
    io.printErr(refusal('Refusing: the enforcing workflows do not match the framework contracts:', [...contract.problems, ...contract.unverified]));
    return 1;
  }
  const plan = await planWrites(root, rendered);
  if (plan.some((entry) => entry.action === 'conflict')) {
    io.printErr(refusal('Refusing: a generated file is in conflict; run `ssd-onboard render` to see why.'));
    return 1;
  }
  io.print(
    heading('SSD Promote'),
    section('Gate mode', rows([row('Change', `${config.rollout.gateMode} → enforce`, { strong: true })]), text('A BLOCK will now fail the required security-gate check.')),
    changeBlocks(plan.filter((e) => e.action !== 'unchanged'))
  );
  if (!options.yes) {
    const prompter = io.prompter ?? terminalPrompter();
    try {
      if (!(await prompter.confirm({ id: 'confirmPromote', question: 'Write these changes?', default: false }))) {
        io.printErr(refusal('Not promoted. Nothing written.'));
        return 1;
      }
    } finally {
      prompter.close();
    }
  }
  await writeConfig(root, check.config);
  await applyWrites(root, plan);
  io.print(
    section(
      'Result',
      rows([status('PASS', 'rollout.gateMode: enforce.')]),
      text('Review the diff, open a pull request, and require `security-gate` in branch protection. Nothing was committed.')
    )
  );
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

// Output channels. Human text goes through output.mjs, which sanitizes it and
// adds color only for an interactive terminal; `json` writes the machine
// document byte for byte. An injected writer (tests) is never a terminal:
// plain text unless the caller passes io.color.
function channels(io) {
  const writer = (stream) => (chunk) => stream.write(chunk.endsWith('\n') ? chunk : `${chunk}\n`);
  const rawOut = io.out ?? writer(process.stdout);
  const rawErr = io.err ?? writer(process.stderr);
  const styleOf = (injected, stream) => (injected ? { ...PLAIN, color: io.color === true } : outputStyle(stream));
  const outStyle = styleOf(io.out !== undefined, process.stdout);
  const errStyle = styleOf(io.err !== undefined, process.stderr);
  const line = (message) => text(String(message).replace(/\n$/, ''));
  return {
    print: (...blocks) => rawOut(format(blocks, outStyle)),
    printErr: (...blocks) => rawErr(format(blocks, errStyle)),
    out: (message) => rawOut(format(line(message), outStyle)),
    err: (message) => rawErr(format(line(message), errStyle)),
    json: (value) => rawOut(`${JSON.stringify(value, null, 2)}\n`)
  };
}

export async function main(argv, io = {}) {
  const context = { ...io, ...channels(io) };
  const { out, err } = context;
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
