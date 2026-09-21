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

import { analyze, hasDrift, isBlocking } from './lib/analyze.mjs';
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
import { CONFIG_PATH, loadConfig, serializeConfig, validateConfig } from './lib/config.mjs';
import { contractProblems } from './lib/contract.mjs';
import { applyWrites, planWrites, removeFile } from './lib/files.mjs';
import { detectFramework } from './lib/framework.mjs';
import { safeWriteFile } from './lib/safe-path.mjs';
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
  init [--non-interactive --from <file>] [--overwrite]
                          derive facts, ask the owner's decisions, write ${CONFIG_PATH}
  inspect [--json]        report what the scanners would and would not cover
  validate [--json]       check config + repository + generated files (CI-friendly)
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

async function cmdInit(root, options, io) {
  const configPath = join(root, CONFIG_PATH);
  let existing = false;
  try {
    await readFile(configPath);
    existing = true;
  } catch {
    // absent: expected
  }
  if (existing && !options.overwrite) {
    throw new UsageError(`${CONFIG_PATH} already exists. Edit it and run \`ssd-onboard render\`, or pass --overwrite to start over.`);
  }
  const facts = await inspectRepository(root);
  let partial;
  if (options['non-interactive']) {
    if (!options.from) {
      throw new UsageError('--non-interactive requires --from <partial-config.yml|.json>');
    }
    partial = await readPartial(resolve(options.from));
  } else {
    const prompter = io.prompter ?? terminalPrompter();
    try {
      partial = await interview(prompter, facts, { cliRef: (await frameworkFor(io))?.sha ?? null });
    } finally {
      prompter.close();
    }
  }
  const { config: candidate, decisions } = await buildConfig(partial, facts);
  if (decisions.length > 0) {
    io.err(`These decisions belong to the repository owner and were not made:\n${decisions.map((d) => `  - ${d}`).join('\n')}`);
    return 1;
  }
  const { config, errors, warnings } = validateConfig(candidate);
  if (errors.length > 0) {
    io.err(`Refusing to write ${CONFIG_PATH}:\n${errors.map((e) => `  - ${e.path}: ${e.message}`).join('\n')}`);
    return 1;
  }
  const result = await analyze({ root, config, configWarnings: warnings, facts, framework: await frameworkFor(io) });
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
  return isBlocking(result) || drift ? 1 : 0;
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
      case 'init':
        return await cmdInit(root, values, context);
      case 'inspect':
        return await cmdInspect(root, values, context);
      case 'validate':
        return await cmdValidate(root, values, context);
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
