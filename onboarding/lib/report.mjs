// The onboarding report: a concise, human-readable answer to "what will this
// repository's security pipeline actually cover, and what will change?"
import { NEXT_STEP } from './baseline.mjs';
import { COVERAGE_CLASSES } from './coverage.mjs';
import { isEcrProfile } from './config.mjs';

const ACTION_LABEL = {
  create: 'create   ',
  update: 'update   ',
  unchanged: 'unchanged',
  forced: 'OVERWRITE',
  adopted: 'ADOPT    ',
  conflict: 'CONFLICT '
};

function wrap(prefix, text) {
  return text
    .split('\n')
    .map((line, index) => (index === 0 ? `${prefix}${line}` : `${' '.repeat(prefix.length)}${line}`))
    .join('\n');
}

export function renderReport(result, { title = 'ssd-onboard report', showDiffs = false } = {}) {
  const { config } = result;
  const out = [title, '='.repeat(title.length)];
  if (!config) {
    out.push('', 'The configuration could not be read:');
    result.errors.forEach((e) => out.push(wrap('  ✗ ', e.message)));
    return `${out.join('\n')}\n`;
  }
  const rollout = result.rollout;
  out.push(
    `Repository:     ${config.repository.slug ?? '(unknown)'} (default branch ${config.repository.defaultBranch ?? '?'})`,
    `Profile:        ${config.profile ?? '(unset)'}`,
    `Framework ref:  ${config.framework.repository}@${config.framework.ref ?? '(unset)'}`,
    `Gate mode:      ${config.rollout.gateMode}${rollout ? `   (rollout state: ${rollout.name})` : ''}`
  );
  if (rollout) {
    out.push(`Next step:      ${NEXT_STEP[rollout.name]}`);
  }

  const c = result.coverage;
  if (c.semgrep) {
    out.push('', 'Coverage:');
    const s = c.semgrep;
    out.push(`  Semgrep rulesets:  ${s.rulesets.join(', ')}`);
    out.push(`  Semgrep roots:     ${s.roots.join(', ')}${s.roots.includes('.') ? ' (whole repository)' : ' (NARROWED)'}`);
    if (s.ignorePatterns === null) {
      out.push("  Semgrep ignored:   Semgrep's BUILT-IN list (no .semgrepignore): tests/, test/, build/, vendor/, node_modules/, …");
    } else if (s.ignorePatterns.length === 0) {
      out.push('  Semgrep ignored:   nothing (explicit, empty .semgrepignore)');
    } else {
      out.push(`  Semgrep ignored:   ${s.ignored.map((i) => `${i.pattern} (${i.count} file${i.count === 1 ? '' : 's'})`).join(', ') || s.ignorePatterns.join(', ')}`);
    }
    out.push(`  Semgrep scope:     ${s.inScope} source file(s) scanned, ${s.ignoredTotal} ignored, ${s.outsideRoots} outside the roots`);
  }
  if (c.gitleaks) {
    const g = c.gitleaks;
    const label =
      g.mode === 'default'
        ? "default ruleset (no config file; gitleaks_config: '')"
        : g.mode === 'managed'
          ? `${g.path} (generated; [extend] useDefault = true — default rules preserved)`
          : `${g.path} (repository-owned; default rules ${g.defaultRules})`;
    out.push(`  Gitleaks:          ${label}`);
  }
  if (c.trufflehog) {
    out.push(
      `  TruffleHog:        ${c.trufflehog.excludePathsFile ? `excludes paths from ${c.trufflehog.excludePathsFile} (${c.trufflehog.entries.map((e) => `${e.pattern} → ${e.matched}`).join(', ') || 'no valid entries'})` : "no path exclusions (trufflehog_exclude_paths: '')"}`
    );
  }
  if (c.dependencies) {
    const d = c.dependencies;
    out.push(`  Dependency manifests (${d.manifests.length}):`);
    if (d.manifests.length === 0) {
      out.push('    none found — OSV-Scanner still runs and reports an empty result');
    }
    for (const m of d.manifests) {
      out.push(`    ${m.path.padEnd(40)} ${m.coverage.padEnd(20)} ${m.why.length ? m.why.join('; ') : COVERAGE_CLASSES[m.coverage]}`);
    }
    out.push(`  Not fully covered: ${d.blocking.length === 0 ? 'none' : d.blocking.map((m) => `${m.path} (${m.coverage}, UNSUPPORTED — blocks generation)`).join(', ')}`);
  }
  if (c.container) {
    out.push(`  Container build:   context ${c.container.context}, Dockerfile ${c.container.dockerfile}, image ${c.container.imageName} (no credentials, no build args)`);
  }

  out.push('', 'Cloud:');
  if (isEcrProfile(config.profile) && config.delivery) {
    const d = config.delivery;
    out.push(
      `  Account/region:    ${d.aws.accountId} / ${d.aws.region}`,
      `  ECR repository:    ${d.ecr.repository} (${d.ecr.ownership})`,
      `  OIDC provider:     ${d.oidcProvider}`,
      `  Push+scan role:    ${d.roles.pushScanRoleArn ?? '(missing)'} (${d.roles.pushScanOwnership})`,
      `  Deploy role:       ${d.roles.deployRoleArn ?? '(missing)'} (${d.roles.deployOwnership})`,
      `  SSM target:        ${d.ssm.instanceId} → container ${d.ssm.containerName}, host port ${d.ssm.appPort}${d.environment ? `, environment ${d.environment}` : ''}`,
      `  Delivery workflow: ${config.rollout.gateMode === 'enforce' ? config.workflows.delivery : `not generated until promote --enforce (a log-only delivery would deploy unenforced images)`}`
    );
  } else {
    out.push('  Delivery:          none managed by the framework for this profile');
  }
  out.push(
    '  Break-glass:       disabled (not supported by Phase 1 generation)',
    `  Slack:             ${config.notifications.slack.enabled ? `secret ${config.notifications.slack.githubSecretName} (value not stored here)` : 'disabled'}`,
    '  (AWS resources are not contacted by this command. `ssd-onboard aws doctor` is Phase 2.)'
  );

  if (result.plan.length > 0 || result.stale.length > 0) {
    out.push('', 'Files that will change:');
    for (const entry of result.plan) {
      out.push(`  ${ACTION_LABEL[entry.action]} ${entry.path}`);
    }
    for (const stale of result.stale) {
      out.push(`  STALE     ${stale.path} (generated, no longer produced; --prune removes it)`);
    }
    if (showDiffs) {
      for (const entry of result.plan.filter((e) => e.action !== 'unchanged')) {
        out.push('', entry.diff.trimEnd());
      }
    }
  }

  if (result.warnings.length > 0) {
    out.push('', `Warnings (${result.warnings.length}):`);
    result.warnings.forEach((w) => out.push(wrap('  ! ', `[${w.area}] ${w.message}`)));
  }
  if (result.errors.length > 0) {
    out.push('', `Errors — generation is blocked (${result.errors.length}):`);
    result.errors.forEach((e) => out.push(wrap('  ✗ ', `[${e.area}] ${e.message}`)));
  } else {
    out.push('', 'No blocking problems.');
  }
  return `${out.join('\n')}\n`;
}

export function reportJson(result) {
  return {
    config: result.config,
    rollout: result.rollout,
    coverage: result.coverage,
    files: result.plan.map(({ path, action, reason }) => ({ path, action, reason })),
    stale: result.stale,
    warnings: result.warnings,
    errors: result.errors
  };
}
