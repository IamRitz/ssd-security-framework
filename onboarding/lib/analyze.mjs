// Analysis: config + repository facts -> everything `inspect`, `validate` and
// `render` need to decide. READ-ONLY: no AWS, no GitHub, no writes.
import { posix } from 'node:path';

import { rolloutState, scopeDigestFor } from './baseline.mjs';
import { isContainerProfile } from './config.mjs';
import { contractProblems } from './contract.mjs';
import { frameworkProblems } from './framework.mjs';
import {
  COVERAGE_CLASSES,
  analyzeGitleaksToml,
  analyzeTrufflehogExcludes,
  dependencyFindings,
  semgrepScope
} from './coverage.mjs';
import { planWrites, readMarker } from './files.mjs';
import { renderAll } from './render.mjs';

// Paths whose change can narrow or disable a security control without touching
// a workflow. CODEOWNERS should cover every one of them.
export function securityOwnedPaths(config) {
  const paths = ['.ssd/', '.github/workflows/', config.semgrep.baseline.path, '.semgrepignore'];
  if (config.gitleaks.mode !== 'default') {
    paths.push(config.gitleaks.path);
  }
  if (config.trufflehog.excludePathsFile) {
    paths.push(config.trufflehog.excludePathsFile);
  }
  return paths;
}

function codeownersCovers(text, path) {
  const rules = text
    .split('\n')
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter(Boolean)
    .map((line) => line.split(/\s+/))
    .filter((parts) => parts.length >= 2)
    .map(([pattern]) => pattern);
  const target = `/${path}`;
  return rules.some((pattern) => {
    if (pattern === '*' || pattern === '/*' || pattern === '**') {
      return true;
    }
    const anchored = pattern.startsWith('/') ? pattern : `/${pattern}`;
    if (anchored.endsWith('/')) {
      return target.startsWith(anchored) || `${target}/`.startsWith(anchored);
    }
    return target === anchored || target.startsWith(`${anchored}/`);
  });
}

// framework: the revision this CLI belongs to (framework.mjs detectFramework),
// or null. Generation is blocked unless it is bound to config.framework.ref.
export async function analyze({ root, config, configErrors = [], configWarnings = [], facts, adopt = [], force = [], framework = null }) {
  const errors = configErrors.map((e) => ({ area: 'config', message: `${e.path}: ${e.message}` }));
  const warnings = configWarnings.map((w) => ({ area: 'config', message: `${w.path}: ${w.message}` }));
  const result = { config, errors, warnings, coverage: {}, rollout: null, plan: [], stale: [] };
  if (!config || configErrors.some((e) => ['profile', 'semgrep.rulesets', 'framework.ref'].includes(e.path))) {
    return result;
  }
  const files = facts.files;
  const fileSet = new Set(files);
  const dirSet = new Set(files.flatMap((file) => file.split('/').slice(0, -1).map((_, i, parts) => parts.slice(0, i + 1).join('/'))));

  // --- repository identity -------------------------------------------------------
  // Identity is FAIL-CLOSED against the repository's own git facts, because the
  // configured values decide what the generated workflows gate: `render` filters
  // `pull_request` on repository.defaultBranch and conditions delivery on it, so
  // a config naming `develop` in a repository whose default branch is `main`
  // generates a gate that never runs on the branch that ships. A mismatch is an
  // error, not a warning a `render` can be run straight past.
  //
  // Only a KNOWN fact blocks: when origin or origin/HEAD is absent, git says
  // nothing about identity and no identity is invented here — the config stands
  // on its own (config.mjs still validates the values themselves).
  if (facts.git.slug && config.repository.slug && facts.git.slug.toLowerCase() !== config.repository.slug.toLowerCase()) {
    errors.push({
      area: 'repository',
      message: `repository.slug is ${config.repository.slug} but origin points at ${facts.git.slug}; the generated workflows would be built for another repository`
    });
  }
  if (facts.git.defaultBranch && config.repository.defaultBranch && facts.git.defaultBranch !== config.repository.defaultBranch) {
    errors.push({
      area: 'repository',
      message: `repository.defaultBranch is ${config.repository.defaultBranch} but origin/HEAD is ${facts.git.defaultBranch}; pull requests into the real default branch would not be scanned`
    });
  }
  // The templates are this CLI's commit; the output calls framework.ref. They
  // must be the same immutable commit (framework.mjs).
  const bindingProblems = frameworkProblems(framework, config);
  bindingProblems.forEach((message) => errors.push({ area: 'framework', message }));

  // --- Semgrep -------------------------------------------------------------------------
  for (const root of config.semgrep.roots) {
    if (root !== '.' && !fileSet.has(root) && !dirSet.has(root)) {
      errors.push({ area: 'semgrep', message: `semgrep.roots entry '${root}' does not exist in the repository; Semgrep would fail or scan nothing` });
    }
  }
  for (const ruleset of config.semgrep.rulesets) {
    if (/\.ya?ml$/.test(ruleset) && !ruleset.startsWith('p/') && !ruleset.startsWith('r/') && !fileSet.has(ruleset)) {
      errors.push({ area: 'semgrep', message: `local Semgrep rule file '${ruleset}' does not exist` });
    }
  }
  let ignorePatterns;
  if (config.semgrep.ignore.managed) {
    ignorePatterns = config.semgrep.ignore.patterns;
  } else if (facts.semgrepignore === null) {
    ignorePatterns = null;
    errors.push({
      area: 'semgrep',
      message:
        "semgrep.ignore.managed is false and there is no .semgrepignore, so Semgrep would apply its built-in ignore list and silently skip tests/, test/, build/, vendor/ and node_modules/. Let ssd-onboard manage the file (managed: true) or commit an explicit one"
    });
  } else {
    ignorePatterns = facts.semgrepignore.split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
    if (readMarker(facts.semgrepignore).marked) {
      warnings.push({ area: 'semgrep', message: '.semgrepignore carries the ssd-onboard marker but semgrep.ignore.managed is false; it will no longer be regenerated' });
    }
  }
  const scope = semgrepScope(files, { roots: config.semgrep.roots, ignorePatterns });
  result.coverage.semgrep = { roots: config.semgrep.roots, rulesets: config.semgrep.rulesets, ignorePatterns, ...scope };
  if (scope.inScope === 0) {
    errors.push({ area: 'semgrep', message: 'the effective Semgrep scope contains no source files; SAST would report a clean scan of nothing' });
  }
  if (!config.semgrep.roots.includes('.')) {
    warnings.push({
      area: 'semgrep',
      message: `SAST is NARROWED to ${config.semgrep.roots.join(', ')}. ${scope.outsideRoots} source-like file(s) are OUTSIDE SAST coverage${scope.outsideTopLevel.length ? ` (${scope.outsideTopLevel.slice(0, 8).join(', ')}${scope.outsideTopLevel.length > 8 ? ', …' : ''})` : ''}`
    });
  }
  const suggestedPacks = facts.rulesetSuggestion.languages.map((entry) => entry.pack);
  const missingPacks = suggestedPacks.filter((pack) => !config.semgrep.rulesets.includes(pack));
  if (missingPacks.length > 0) {
    warnings.push({ area: 'semgrep', message: `the repository contains code for ${missingPacks.join(', ')} but semgrep.rulesets does not include those packs` });
  }

  // --- Gitleaks ------------------------------------------------------------------------
  const gitleaks = { mode: config.gitleaks.mode, path: config.gitleaks.path ?? null, defaultRules: 'preserved' };
  if (config.gitleaks.mode === 'default') {
    if (fileSet.has('.gitleaks.toml')) {
      warnings.push({ area: 'gitleaks', message: ".gitleaks.toml exists but gitleaks.mode is 'default', so it is NOT used (gitleaks_config: '')" });
    }
  } else if (config.gitleaks.mode === 'existing') {
    const text = await facts.readText(config.gitleaks.path);
    if (text === null) {
      errors.push({ area: 'gitleaks', message: `gitleaks.path ${config.gitleaks.path} does not exist` });
    } else {
      const analysis = analyzeGitleaksToml(text);
      gitleaks.analysis = analysis;
      if (!analysis.extendsDefault) {
        gitleaks.defaultRules = 'REPLACED';
      }
      for (const problem of analysis.problems) {
        errors.push({ area: 'gitleaks', message: `${config.gitleaks.path} ${problem}` });
      }
      for (const warning of analysis.warnings) {
        warnings.push({ area: 'gitleaks', message: `${config.gitleaks.path} ${warning}` });
      }
    }
  }
  result.coverage.gitleaks = gitleaks;

  // --- TruffleHog ------------------------------------------------------------------------
  const trufflehog = { excludePathsFile: config.trufflehog.excludePathsFile, entries: [] };
  if (config.trufflehog.excludePathsFile) {
    const text = await facts.readText(config.trufflehog.excludePathsFile);
    if (text === null) {
      errors.push({ area: 'trufflehog', message: `trufflehog.excludePathsFile ${config.trufflehog.excludePathsFile} does not exist` });
    } else {
      const analysis = analyzeTrufflehogExcludes(text, files);
      trufflehog.entries = analysis.entries;
      analysis.problems.forEach((message) => errors.push({ area: 'trufflehog', message: `${config.trufflehog.excludePathsFile} ${message}` }));
      analysis.warnings.forEach((message) => warnings.push({ area: 'trufflehog', message: `${config.trufflehog.excludePathsFile} ${message}` }));
    }
  } else if (fileSet.has('.trufflehog-exclude-paths.txt')) {
    warnings.push({ area: 'trufflehog', message: ".trufflehog-exclude-paths.txt exists but trufflehog.excludePathsFile is empty, so it is NOT used (trufflehog_exclude_paths: '')" });
  }
  result.coverage.trufflehog = trufflehog;

  // --- dependencies ------------------------------------------------------------------------
  const deps = dependencyFindings(facts.manifests);
  result.coverage.dependencies = { manifests: facts.manifests, ...deps };
  for (const manifest of deps.blocking) {
    errors.push({
      area: 'dependencies',
      message:
        `${manifest.path}: ${COVERAGE_CLASSES[manifest.coverage]} (${manifest.why.join('; ')}). ` +
        'This layout is UNSUPPORTED by the current framework, and generation is blocked rather than claiming coverage that does not exist. ' +
        (manifest.coverage === 'osv-only'
          ? 'Supporting it needs the dependency_roots framework change (docs/onboarding-architecture.md C.3).'
          : 'Commit a lockfile the framework scans (see docs/onboarding-cli.md § Dependency layouts).') +
        ' There is deliberately no local override in this version.'
    });
  }
  deps.warnings.forEach((message) => warnings.push({ area: 'dependencies', message }));
  if (facts.vendoredNodeModules.length > 0) {
    warnings.push({ area: 'dependencies', message: `${facts.vendoredNodeModules.length} package(s) are committed under node_modules/; they are not classified as this repository's manifests` });
  }

  // --- container -----------------------------------------------------------------------------
  if (isContainerProfile(config.profile) && config.container) {
    const { dockerfile, context } = config.container;
    result.coverage.container = { ...config.container };
    if (!fileSet.has(dockerfile)) {
      errors.push({ area: 'container', message: `container.dockerfile ${dockerfile} does not exist` });
    } else {
      const text = (await facts.readText(dockerfile)) ?? '';
      const secretArgs = [...text.matchAll(/^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)/gim)]
        .map((m) => m[1])
        .filter((name) => /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|AUTH)/i.test(name));
      if (secretArgs.length > 0) {
        warnings.push({
          area: 'container',
          message: `${dockerfile} declares ARG ${secretArgs.join(', ')}. The generated build passes NO build arguments; a secret must never be a build argument (it is recorded in image history). Use a BuildKit secret mount in your own pipeline instead`
        });
      }
    }
    if (context !== '.' && !dirSet.has(context)) {
      errors.push({ area: 'container', message: `container.context ${context} does not exist` });
    }
  } else if (facts.dockerfiles.length > 0) {
    warnings.push({
      area: 'container',
      message: `found ${facts.dockerfiles.join(', ')} but the profile is source-only, so no image is scanned. If this repository ships that image, use a container profile`
    });
  }

  // --- rollout / baseline ---------------------------------------------------------------------
  const rollout = await rolloutState(root, config);
  result.rollout = rollout;
  rollout.problems.forEach((message) => errors.push({ area: 'baseline', message }));
  rollout.warnings.forEach((message) => warnings.push({ area: 'baseline', message }));
  if (config.semgrep.baseline.state === 'accepted' && !config.semgrep.baseline.acceptedScope) {
    warnings.push({
      area: 'baseline',
      message:
        'the baseline was adopted, not accepted through ssd-onboard, so the Semgrep scope it was generated under is unknown. If that scope was narrower (for example src/ only, or without an explicit .semgrepignore), newly scanned code carries findings the baseline never reviewed and full scans will BLOCK on them'
    });
  }
  if (config.semgrep.baseline.state === 'accepted' && config.semgrep.baseline.acceptedScope) {
    const current = scopeDigestFor(config, facts.semgrepignore);
    if (current !== config.semgrep.baseline.acceptedScope) {
      warnings.push({
        area: 'baseline',
        message:
          'the Semgrep scope (rulesets, roots or ignore patterns) changed since the baseline was accepted. Findings in newly scanned code were never reviewed into the baseline and will BLOCK full scans; a baseline is only rebuilt by deleting it in a reviewed pull request'
      });
    }
  }

  // --- CODEOWNERS ---------------------------------------------------------------------------------
  if (!facts.codeowners) {
    warnings.push({
      area: 'codeowners',
      message: `no CODEOWNERS file. Without it, one line in an app-team PR can switch the gate to log-only or narrow a scan unreviewed. Cover: ${securityOwnedPaths(config).join(' ')}`
    });
  } else {
    const uncovered = securityOwnedPaths(config).filter((path) => !codeownersCovers(facts.codeownersText ?? '', path));
    if (uncovered.length > 0) {
      warnings.push({ area: 'codeowners', message: `${facts.codeowners} does not cover: ${uncovered.join(' ')}` });
    }
  }

  // --- the files `render` would write -----------------------------------------------------------
  const rendered = renderAll(config);
  // Checked only once bound: the contracts are then read from the immutable
  // git object at framework.ref, never from a working tree or a moving ref.
  if (bindingProblems.length === 0) {
    const contract = await contractProblems(rendered, config, framework.readWorkflow);
    contract.problems.forEach((message) => errors.push({ area: 'framework', message }));
    for (const file of contract.unverified) {
      errors.push({ area: 'framework', message: `${file} could not be read at ${config.framework.ref}; the generated call cannot be verified` });
    }
    for (const note of contract.staticGrants) {
      warnings.push({ area: 'permissions', message: note });
    }
  }
  result.plan = await planWrites(root, rendered, { adopt, force });
  const renderedPaths = new Set(rendered.map((file) => file.path));
  const candidates = [...facts.workflows.map((w) => w.path), '.semgrepignore', ...(fileSet.has('.gitleaks.toml') ? ['.gitleaks.toml'] : [])];
  for (const path of new Set(candidates)) {
    if (renderedPaths.has(path) || !fileSet.has(path)) {
      continue;
    }
    const text = await facts.readText(path);
    const marker = readMarker(text ?? '');
    if (marker.marked) {
      result.stale.push({ path, intact: marker.intact });
    }
  }
  for (const entry of result.plan) {
    if (entry.action === 'conflict') {
      errors.push({ area: 'files', message: `${entry.path}: ${entry.reason}` });
    }
  }
  for (const stale of result.stale) {
    warnings.push({
      area: 'files',
      message: `${stale.path} was generated by ssd-onboard but the current config no longer produces it${posix.basename(stale.path).endsWith('.yml') ? ' (for a delivery workflow: delivery is generated only while enforcing)' : ''}; remove it with \`ssd-onboard render --prune\``
    });
  }
  return result;
}

export const isBlocking = (result) => result.errors.length > 0;
export const hasDrift = (result) => result.plan.some((entry) => entry.action !== 'unchanged') || result.stale.length > 0;
