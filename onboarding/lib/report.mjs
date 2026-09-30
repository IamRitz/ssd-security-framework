// The onboarding report: a concise, human-readable answer to "what will this
// repository's security pipeline actually cover, and what will change?"
//
// reportBlocks() builds it from the analysis as output.mjs blocks; it decides
// nothing — every status shown is read off the analysis (errors, warnings,
// coverage classes) that `validate` and `render` already act on.
import { NEXT_STEP } from './baseline.mjs';
import { BLOCKING_CLASSES, COVERAGE_CLASSES } from './coverage.mjs';
import { isEcrProfile } from './config.mjs';
import { dim, fileRow, heading, result as resultLine, row, rows, section, status } from './output.mjs';

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// Worst status among the analysis entries of `areas`.
function areaStatus(result, ...areas) {
  if (result.errors.some((e) => areas.includes(e.area))) {
    return 'FAIL';
  }
  return result.warnings.some((w) => areas.includes(w.area)) ? 'WARN' : 'PASS';
}

export function manifestStatus(manifest) {
  if (BLOCKING_CLASSES.has(manifest.coverage)) {
    return 'FAIL';
  }
  return manifest.coverage === 'osv-unverified' ? 'WARN' : 'PASS';
}

// One row per dependency manifest: path and coverage class; the reason is secondary.
export function manifestRows(manifests) {
  return rows(
    manifests.map((m) =>
      status(manifestStatus(m), m.path, BLOCKING_CLASSES.has(m.coverage) ? `${m.coverage} · UNSUPPORTED — blocks generation` : m.coverage, {
        details: m.why.length ? m.why.join('; ') : COVERAGE_CLASSES[m.coverage]
      })
    )
  );
}

// Analysis entries grouped by area, first appearance first: one status row per
// area, its messages beneath (bulleted when there are several).
export function problemRows(entries, word) {
  const areas = new Map();
  for (const entry of entries) {
    areas.set(entry.area, [...(areas.get(entry.area) ?? []), entry.message]);
  }
  return rows(
    [...areas].map(([area, messages]) =>
      status(word, area, messages.length === 1 ? messages[0] : messages.map((m) => `- ${m}`).join('\n'), { stacked: true })
    )
  );
}

function coverageSection(result) {
  const c = result.coverage;
  const items = [];
  if (c.semgrep) {
    const s = c.semgrep;
    let ignored;
    if (s.ignorePatterns === null) {
      ignored = "Semgrep's BUILT-IN list (no .semgrepignore): tests/, test/, build/, vendor/, node_modules/, …";
    } else if (s.ignorePatterns.length === 0) {
      ignored = 'nothing (explicit, empty .semgrepignore)';
    } else {
      ignored = s.ignored.map((i) => `${i.pattern} (${plural(i.count, 'file')})`).join(', ') || s.ignorePatterns.join(', ');
    }
    items.push(
      status(areaStatus(result, 'semgrep'), 'Semgrep', `${s.inScope} source file(s) scanned · ${s.ignoredTotal} ignored · ${s.outsideRoots} outside the roots`, {
        details: [
          `rulesets: ${s.rulesets.join(', ')}`,
          `roots:    ${s.roots.join(', ')}${s.roots.includes('.') ? ' (whole repository)' : ' (NARROWED)'}`,
          `ignored:  ${ignored}`
        ]
      })
    );
  }
  if (c.gitleaks) {
    const g = c.gitleaks;
    const label =
      g.mode === 'default'
        ? "default ruleset (no config file; gitleaks_config: '')"
        : g.mode === 'managed'
          ? `${g.path} (generated; [extend] useDefault = true — default rules preserved)`
          : `${g.path} (repository-owned; default rules ${g.defaultRules})`;
    items.push(status(areaStatus(result, 'gitleaks'), 'Gitleaks', label));
  }
  if (c.trufflehog) {
    const t = c.trufflehog;
    items.push(
      status(
        areaStatus(result, 'trufflehog'),
        'TruffleHog',
        t.excludePathsFile
          ? `excludes paths from ${t.excludePathsFile} (${t.entries.map((e) => `${e.pattern} → ${e.matched}`).join(', ') || 'no valid entries'})`
          : "no path exclusions (trufflehog_exclude_paths: '')"
      )
    );
  }
  if (c.dependencies) {
    const d = c.dependencies;
    items.push(
      status(
        d.blocking.length > 0 ? 'FAIL' : areaStatus(result, 'dependencies'),
        'Dependencies',
        `${plural(d.manifests.length, 'manifest')} · ${d.blocking.length === 0 ? 'all fully covered' : `${d.blocking.length} not fully covered`}`
      )
    );
  }
  if (c.container) {
    items.push(
      status(areaStatus(result, 'container'), 'Container build', `context ${c.container.context}, Dockerfile ${c.container.dockerfile}, image ${c.container.imageName} (no credentials, no build args)`)
    );
  }
  const out = [section('Coverage', rows(items))];
  if (c.dependencies) {
    const d = c.dependencies;
    out.push(
      section(
        `Dependency manifests (${d.manifests.length})`,
        d.manifests.length === 0 ? dim('none found — OSV-Scanner still runs and reports an empty result') : manifestRows(d.manifests),
        rows([
          row('Not fully covered', d.blocking.length === 0 ? 'none' : d.blocking.map((m) => `${m.path} (${m.coverage}, UNSUPPORTED — blocks generation)`).join('\n'))
        ])
      )
    );
  }
  return out;
}

function cloudSection(config) {
  const items = [];
  if (isEcrProfile(config.profile) && config.delivery) {
    const d = config.delivery;
    items.push(
      row('Account/region', `${d.aws.accountId} / ${d.aws.region}`),
      row('ECR repository', `${d.ecr.repository} (${d.ecr.ownership})`),
      row('OIDC provider', d.oidcProvider),
      row('Push+scan role', `${d.roles.pushScanRoleArn ?? '(missing)'} (${d.roles.pushScanOwnership})`),
      row('Deploy role', `${d.roles.deployRoleArn ?? '(missing)'} (${d.roles.deployOwnership})`),
      row('SSM target', `${d.ssm.instanceId} → container ${d.ssm.containerName}, host port ${d.ssm.appPort}${d.environment ? `, environment ${d.environment}` : ''}`),
      row(
        'Delivery workflow',
        config.rollout.gateMode === 'enforce' ? config.workflows.delivery : 'not generated until promote --enforce (a log-only delivery would deploy unenforced images)'
      )
    );
  } else {
    items.push(row('Delivery', 'none managed by the framework for this profile'));
  }
  items.push(
    row('Break-glass', 'disabled (not supported by Phase 1 generation)'),
    row('Slack', config.notifications.slack.enabled ? `secret ${config.notifications.slack.githubSecretName} (value not stored here)` : 'disabled')
  );
  return section('Cloud', rows(items), dim('AWS resources are not contacted by this command. `ssd-onboard aws doctor` is Phase 2.'));
}

// The overall result of a report: BLOCKED on any error (or, for validate, on
// drift), READY WITH WARNINGS on any warning, READY otherwise.
export function reportOutcome(result, { drift = false } = {}) {
  if (result.errors.length > 0) {
    return { outcome: 'BLOCKED', detail: `${plural(result.errors.length, 'blocking issue')} — generation is blocked` };
  }
  if (drift) {
    return { outcome: 'BLOCKED', detail: 'generated files are NOT up to date with the config — run `ssd-onboard render`' };
  }
  if (result.warnings.length > 0) {
    return { outcome: 'READY WITH WARNINGS', detail: `${plural(result.warnings.length, 'warning')}, no blocking problems` };
  }
  return { outcome: 'READY', detail: 'no blocking problems' };
}

// options:
//   title, notes   the heading
//   files          extra plan entries listed first (onboard: the config itself)
//   extra          blocks shown before the file list (onboard: the security model)
//   drift          validate: out-of-date generated files fail the result
export function reportBlocks(result, { title = 'SSD Report', notes = [], files = [], extra = [], drift = false } = {}) {
  const { config } = result;
  const out = [heading(title, ...notes)];
  if (!config) {
    out.push(section('Configuration', dim('The configuration could not be read.'), problemRows(result.errors, 'FAIL')));
    out.push(section('Result', resultLine('BLOCKED', `${plural(result.errors.length, 'blocking issue')}`)));
    return out;
  }
  const rollout = result.rollout;
  out.push(
    section(
      'Repository',
      rows([
        row('Name', config.repository.slug ?? '(unknown)', { strong: true }),
        row('Default branch', config.repository.defaultBranch ?? '?'),
        row('Profile', config.profile ?? '(unset)'),
        row('Framework', `${config.framework.repository}@${config.framework.ref ?? '(unset)'}`)
      ])
    ),
    ...coverageSection(result),
    section(
      'Rollout',
      rows([
        status(config.rollout.gateMode === 'enforce' ? 'PASS' : 'WARN', 'Gate mode', config.rollout.gateMode),
        rollout && row('Rollout state', rollout.name, { strong: true }),
        rollout && row('Next step', NEXT_STEP[rollout.name])
      ])
    ),
    cloudSection(config),
    ...extra
  );

  const plan = [...files, ...result.plan];
  if (plan.length > 0 || result.stale.length > 0) {
    out.push(
      section(
        'Files',
        rows([
          ...plan.map((entry) => fileRow(entry.action, entry.path)),
          ...result.stale.map((stale) => fileRow('stale', stale.path, '', { details: 'generated, no longer produced; --prune removes it' }))
        ])
      )
    );
  }
  if (result.warnings.length > 0) {
    out.push(section(`Warnings (${result.warnings.length})`, problemRows(result.warnings, 'WARN')));
  }
  if (result.errors.length > 0) {
    out.push(section(`Blocking issues (${result.errors.length})`, problemRows(result.errors, 'FAIL')));
  }
  const { outcome, detail } = reportOutcome(result, { drift });
  out.push(section('Result', resultLine(outcome, detail)));
  return out;
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
