// `ssd-onboard doctor`: is this consumer repository OPERATIONALLY ready to use
// the framework safely?
//
// A CONSUMER of existing truth, never a second validator. Every check is a
// projection of one `analyze()` result (the same one `validate` and
// `render --check` decide from) plus the repository facts it was computed
// over. Nothing here parses the config, checks a pin, classifies a manifest,
// interprets the baseline lifecycle or renders a workflow.
//
//   - every analyze ERROR is attributed to exactly one check, and a check that
//     holds an error is FAIL — an unknown area lands in a catch-all FAIL, so an
//     error can never be dropped;
//   - every analyze WARNING lifts its check to at least WARN;
//   - doctor adds no FAIL of its own: a FAIL exists only where analyze has an
//     error or the generated files have drifted (validate's exit-1 conditions).
//     WARN and NOT VERIFIED may say more than validate does (rollout stage,
//     unestablished identity, governance that cannot be proven locally).
//
// READ-ONLY by construction: this module imports no write-side helper and no
// filesystem or process API (a test asserts both). It never contacts AWS or
// GitHub; what only GitHub or AWS could prove is NOT VERIFIED, never guessed.
import { hasDrift, securityOwnedPaths } from './analyze.mjs';
import { NEXT_STEP } from './baseline.mjs';
import { isContainerProfile, isEcrProfile } from './config.mjs';
import { COVERAGE_CLASSES } from './coverage.mjs';
import { bootstrapAvailable } from './render.mjs';
import { parseYaml } from './yaml.mjs';

export const PASS = 'PASS';
export const WARN = 'WARN';
export const FAIL = 'FAIL';
export const NOT_VERIFIED = 'NOT VERIFIED';

// Severity for "lift to at least": evidence can only raise a status.
const RANK = { [PASS]: 0, [NOT_VERIFIED]: 1, [WARN]: 2, [FAIL]: 3 };
const atLeast = (status, floor) => (RANK[status] >= RANK[floor] ? status : floor);

// analyze areas -> the check that owns them. `framework` and `config` are split
// further below; anything absent here goes to the catch-all.
const AREA_CHECK = {
  repository: 'identity',
  semgrep: 'semgrep',
  gitleaks: 'secret-scanning',
  trufflehog: 'secret-scanning',
  dependencies: 'dependencies',
  container: 'container',
  baseline: 'baseline',
  codeowners: 'codeowners',
  files: 'generated-files'
};

const SOURCE_JOB = 'source-security';
const SOURCE_WORKFLOW = '_source-scan.yml';

function check(id, title, fields) {
  return { id, title, status: PASS, observed: [], expected: [], why: '', remediation: [], evidence: [], ...fields };
}

// --- attribution ------------------------------------------------------------------

// The check id an analyze entry belongs to. `framework` errors are told apart
// by the structured record analyze keeps of them (result.framework), never by
// re-running the binding or contract check.
export function routeEntry(entry, result) {
  if (entry.area === 'config') {
    return /^rollout\.gateMode:/.test(entry.message) ? 'gate-mode' : 'configuration';
  }
  if (entry.area === 'framework') {
    const fw = result.framework;
    if (fw?.binding.includes(entry.message)) {
      return 'framework-pin';
    }
    if (fw?.contract?.problems.includes(entry.message)) {
      return isSourceJobProblem(entry.message, result) ? 'source-boundary' : 'workflow-contract';
    }
    if (fw?.contract?.unverified.includes(entry.message)) {
      return 'workflow-contract';
    }
    return 'other';
  }
  if (entry.area === 'permissions') {
    // contract.mjs static-grant notes name "<workflow path> job <job id>".
    return workflowEntries(result).some((e) => entry.message.includes(`${e.path} job ${SOURCE_JOB} `)) ? 'source-boundary' : 'workflow-contract';
  }
  return AREA_CHECK[entry.area] ?? 'other';
}

// contract.mjs prefixes every problem with "<workflow path> job <job id>".
function isSourceJobProblem(message, result) {
  return workflowEntries(result).some((entry) => message.startsWith(`${entry.path} job ${SOURCE_JOB} `));
}

function workflowEntries(result) {
  return result.plan.filter((entry) => entry.kind === 'workflow');
}

// --- explanation only -----------------------------------------------------------------

// What a workflow's source-security job actually does, read from text that an
// existing result already holds (the render the contract checked, or the
// committed bytes a drift names). EXPLANATION ONLY: it never decides a status
// by itself — the contract and drift results do. Returns human-readable notes.
export function describeSourceBoundary(text) {
  let doc;
  try {
    doc = parseYaml(text);
  } catch {
    return ['the workflow could not be parsed, so its source-security job cannot be described'];
  }
  const job = doc?.jobs?.[SOURCE_JOB];
  if (!job || typeof job !== 'object') {
    return [`there is no ${SOURCE_JOB} job: no source security runs from this workflow`];
  }
  const notes = [];
  const target = typeof job.uses === 'string' ? job.uses.split('@')[0].split('/').pop() : null;
  if (target !== SOURCE_WORKFLOW) {
    notes.push(`${SOURCE_JOB} calls ${target ?? '(nothing)'}, not the OIDC-free ${SOURCE_WORKFLOW}`);
  }
  const permissions = job.permissions ?? doc.permissions;
  if (permissions === 'write-all' || (permissions && typeof permissions === 'object' && permissions['id-token'] === 'write')) {
    notes.push(`${SOURCE_JOB} is granted id-token: write, so the scanners could request a GitHub OIDC token`);
  }
  if (job.secrets === 'inherit') {
    notes.push(`${SOURCE_JOB} passes \`secrets: inherit\`, handing EVERY repository secret to the scanner workflow (the contract check reports this as undeclared secrets '0', '1', …)`);
  }
  return notes;
}

// --- checks -------------------------------------------------------------------------

function configurationCheck(config) {
  return check('configuration', 'Configuration', {
    observed: config ? [`.ssd/onboarding.yml: schema ${config.schemaVersion}, profile ${config.profile}`] : ['.ssd/onboarding.yml could not be read as a configuration'],
    expected: ['a configuration that validates against the closed schema'],
    why: 'every generated workflow is rendered from this file; a readiness check of anything else is meaningless while it is invalid.',
    remediation: ['Fix each error listed, then run `ssd-onboard validate`.']
  });
}

function identityCheck(config, facts) {
  const git = facts.git;
  const c = check('identity', 'Repository identity', {
    observed: [
      `configured: ${config.repository.slug} (default branch ${config.repository.defaultBranch})`,
      `git: ${git.isGit ? `origin ${git.slug ?? '(not a GitHub remote, or none)'}, origin/HEAD ${git.defaultBranch ?? '(unknown)'}` : 'not a git repository'}`
    ],
    expected: [`origin is github.com/${config.repository.slug} and origin/HEAD is ${config.repository.defaultBranch}`],
    why: 'the generated workflows gate pull requests into repository.defaultBranch of repository.slug; the wrong identity gates a branch or repository that does not ship.'
  });
  const unknown = [];
  if (!git.isGit) {
    unknown.push('this directory is not a git repository');
  } else {
    if (!git.slug) {
      unknown.push('origin is absent or is not a GitHub remote');
    }
    if (!git.defaultBranch) {
      unknown.push('origin/HEAD is not set, so the real default branch is unknown');
    }
  }
  if (unknown.length > 0) {
    // Identity is never invented (analyze only blocks on a KNOWN mismatch), and
    // doctor does not add a fail-closed rule analyze does not have.
    c.status = WARN;
    c.observed.push(`identity not established: ${unknown.join('; ')}`);
    c.remediation = git.isGit
      ? ['Point origin at the GitHub repository and run `git remote set-head origin --auto`, then re-run doctor.']
      : ['Run doctor in a clone of the GitHub repository.'];
  }
  c.remediation.push('If the configured values are wrong, correct repository.slug / repository.defaultBranch, then `ssd-onboard render`.');
  return c;
}

function frameworkPinCheck(config, result) {
  const bound = result.framework && result.framework.binding.length === 0;
  return check('framework-pin', 'Framework pin', {
    observed: [
      `framework.repository ${config.framework.repository}`,
      `framework.ref ${config.framework.ref}`,
      bound ? 'ssd-onboard runs from a clean checkout of that repository at exactly that commit' : 'ssd-onboard is NOT bound to framework.ref (see below)'
    ],
    expected: ['framework.ref is a full 40-character commit SHA, and ssd-onboard runs from a clean checkout of framework.repository at that SHA'],
    why: 'the templates are this CLI\'s commit while the generated workflows call framework.ref; if they differ, the output assumes one revision\'s contracts while running another\'s.',
    remediation: [`Run ssd-onboard from a clean checkout of ${config.framework.repository} at ${config.framework.ref} (git checkout --detach ${config.framework.ref}), or change framework.ref deliberately and re-render.`]
  });
}

function workflowContractCheck(config, result) {
  const contract = result.framework?.contract ?? null;
  const c = check('workflow-contract', 'Workflow contract', {
    observed: contract ? [`generated reusable-workflow calls were checked against ${config.framework.repository}@${config.framework.ref}`] : [],
    expected: ['every generated call pins framework.ref, passes only declared inputs/secrets, and grants exactly the permissions the pinned callee requires'],
    why: 'a call that disagrees with the pinned reusable workflow fails to start, runs one version against another, or over-grants permissions.',
    remediation: ['Re-render from a CLI bound to framework.ref (`ssd-onboard render`); if the problem persists, the framework revision and generator disagree — report it.']
  });
  if (!contract) {
    c.status = NOT_VERIFIED;
    c.observed.push('not checked: the generator is not bound to framework.ref (see Framework pin)');
  }
  return c;
}

function generatedFilesCheck(result) {
  const changed = result.plan.filter((entry) => entry.action !== 'unchanged');
  const c = check('generated-files', 'Generated workflow', {
    observed: [],
    expected: ['every generated file is byte-identical to a fresh render of .ssd/onboarding.yml, and no stale generated file remains'],
    why: 'what runs in CI is the committed file; if it differs from the render, the reviewed configuration is not what gates pull requests.',
    remediation: ['Run `ssd-onboard render`, review the diff, and commit the generated files.']
  });
  // hasDrift is exactly `render --check`'s failure condition.
  if (hasDrift(result)) {
    c.status = FAIL;
    changed.forEach((entry) => c.observed.push(`${entry.action === 'create' ? 'missing' : entry.action}: ${entry.path}${entry.reason ? ` — ${entry.reason}` : ''}`));
    result.stale.forEach((stale) => c.observed.push(`stale: ${stale.path} (generated, no longer produced)`));
    if (changed.some((entry) => entry.action === 'conflict')) {
      c.remediation.push('A CONFLICT is a hand-edited or human-owned file: move the change into .ssd/onboarding.yml, or pass --force/--adopt <path> after reviewing the diff.');
    }
    if (result.stale.length > 0) {
      c.remediation.push('Remove stale generated files with `ssd-onboard render --prune`.');
    }
  } else {
    c.observed.push(`${result.plan.length} generated file(s) match a fresh render: ${result.plan.map((entry) => entry.path).join(', ')}`);
  }
  return c;
}

function baselineCheck(config, result) {
  const rollout = result.rollout;
  const b = rollout.baseline;
  const c = check('baseline', 'Semgrep baseline', {
    observed: [
      `semgrep.baseline.state: ${config.semgrep.baseline.state}; rollout state: ${rollout.name}`,
      `${b.path}: ${b.exists ? `present${b.findings === null ? '' : ` (${b.findings} finding(s))`}` : 'absent'}`,
      `candidate: ${rollout.candidate.exists ? `present (${rollout.candidate.findings ?? '?'} finding(s), NOT accepted)` : 'none'}`
    ],
    expected: ['an accepted, readable baseline at semgrep.baseline.path (state: accepted)'],
    why: 'the gate evaluates Semgrep findings against the declared lifecycle: `absent` means an empty accepted set; `accepted` fails closed on every run without a valid file.',
    remediation: [`Next: ${NEXT_STEP[rollout.name]}`]
  });
  if (rollout.name === 'inconsistent') {
    c.status = FAIL;
  } else if (rollout.name === 'onboarding' || rollout.name === 'candidate-downloaded') {
    // A VALID lifecycle state, not a corrupt one: the gate is trusted and
    // treats every Semgrep finding as new. Only production readiness is missing.
    c.status = WARN;
    c.observed.push('valid onboarding lifecycle state: no baseline has been accepted yet, so every existing Semgrep finding is NEW');
  }
  return c;
}

function gateModeCheck(config) {
  const enforce = config.rollout.gateMode === 'enforce';
  return check('gate-mode', 'Gate mode', {
    status: enforce ? PASS : WARN,
    observed: [`rollout.gateMode: ${config.rollout.gateMode}`],
    expected: ['enforce (for production readiness)'],
    why: enforce
      ? 'a trusted BLOCK verdict fails the stable security-gate check.'
      : 'log-only is a legitimate rollout state, but trusted BLOCK verdicts are reported and NOT enforced by the stable security-gate check.',
    remediation: enforce ? [] : ['After observing the repository in log-only with an accepted baseline, run `ssd-onboard promote --enforce`.']
  });
}

function bootstrapCheck(config, result) {
  const available = bootstrapAvailable(config);
  const entry = result.plan.find((e) => e.path === config.workflows.security);
  const c = check('bootstrap', 'Bootstrap wiring', {
    expected: [
      available
        ? `${config.workflows.security} offers the one-time bootstrap_baseline input on workflow_dispatch only (state absent, log-only)`
        : `${config.workflows.security} has NO bootstrap input (state ${config.semgrep.baseline.state}, ${config.rollout.gateMode})`
    ],
    why: 'a candidate baseline may come only from a deliberately dispatched full scan while no baseline is accepted; pull_request and push runs never produce one.',
    remediation: ['Run `ssd-onboard render`, review the diff, and commit the generated files.']
  });
  if (entry?.action === 'unchanged') {
    c.observed.push(available ? 'bootstrap_baseline dispatch input present, as rendered for this lifecycle state' : 'no bootstrap input, as rendered for this lifecycle state');
  } else {
    c.status = NOT_VERIFIED;
    c.observed.push(`${config.workflows.security} is not the verified render (see Generated workflow), so its bootstrap wiring cannot be confirmed`);
  }
  return c;
}

function sourceBoundaryCheck(config, result) {
  const workflows = workflowEntries(result);
  const contract = result.framework?.contract ?? null;
  const c = check('source-boundary', 'Source workflow OIDC boundary', {
    expected: [
      `every ${SOURCE_JOB} job calls ${config.framework.repository}/.github/workflows/${SOURCE_WORKFLOW}@${config.framework.ref}`,
      'with no id-token: write and no `secrets: inherit` (only declared secrets)'
    ],
    why: `${SOURCE_WORKFLOW} is the OIDC-free source workflow: the scanners run third-party code over the pull request, so they must hold no cloud identity and no repository secrets.`,
    remediation: ['Do not hand-edit generated workflows: run `ssd-onboard render`, review the diff, and commit it.']
  });
  const notes = [];
  if (!contract) {
    c.status = NOT_VERIFIED;
    c.observed.push('the generated calls were not checked against the pinned framework (see Framework pin)');
  } else {
    // What the contract checked is the render; explain it when it failed.
    for (const entry of workflows) {
      if (contract.problems.some((message) => message.startsWith(`${entry.path} job ${SOURCE_JOB} `))) {
        notes.push(...describeSourceBoundary(entry.content).map((note) => `rendered ${entry.path}: ${note}`));
      }
    }
  }
  const outOfSync = workflows.filter((entry) => entry.action !== 'unchanged');
  for (const entry of outOfSync) {
    // What RUNS is the committed file; describe it when it is not the render.
    const committed = entry.current === null ? [] : describeSourceBoundary(entry.current);
    notes.push(...committed.map((note) => `committed ${entry.path}: ${note}`));
  }
  if (outOfSync.length > 0) {
    // The drift itself is the FAIL (Generated workflow). A described violation
    // makes this check FAIL too — it explains that same drift, it is not a new
    // rule; without one the boundary is simply unproven.
    c.status = atLeast(c.status, notes.some((n) => n.startsWith('committed ')) ? FAIL : NOT_VERIFIED);
    c.observed.push(`not the verified render: ${outOfSync.map((e) => e.path).join(', ')} (see Generated workflow)`);
  } else if (contract) {
    c.observed.push(`${workflows.map((e) => e.path).join(', ')}: ${SOURCE_JOB} matches the pinned ${SOURCE_WORKFLOW} contract (exact permissions, declared secrets only)`);
  }
  c.observed.push(...notes);
  return c;
}

function semgrepCheck(config, facts, result) {
  const s = result.coverage.semgrep;
  const ignore = config.semgrep.ignore.managed
    ? `.semgrepignore managed by ssd-onboard (${config.semgrep.ignore.patterns.length} pattern(s))`
    : facts.semgrepignore === null
      ? ".semgrepignore ABSENT: Semgrep would apply its built-in list (skips tests/, build/, vendor/, …)"
      : '.semgrepignore repository-owned';
  return check('semgrep', 'Semgrep configuration', {
    observed: [
      `rulesets: ${config.semgrep.rulesets.join(', ')}`,
      `roots: ${config.semgrep.roots.join(', ')}${config.semgrep.roots.includes('.') ? ' (whole repository)' : ' (NARROWED)'}`,
      ignore,
      ...(s ? [`scope: ${s.inScope} source file(s) scanned, ${s.ignoredTotal} ignored, ${s.outsideRoots} outside the roots`] : [])
    ],
    expected: ['rulesets for every language present, the whole repository in scope, and an explicit .semgrepignore'],
    why: 'code outside the effective Semgrep scope gets no SAST at all, while the scan still reports clean.',
    remediation: ['Adjust semgrep.* in .ssd/onboarding.yml as the items below say, then `ssd-onboard render`.']
  });
}

function secretScanningCheck(config) {
  return check('secret-scanning', 'Secret scanning configuration', {
    observed: [
      `Gitleaks: ${config.gitleaks.mode}${config.gitleaks.mode === 'default' ? ' (built-in ruleset, no config file)' : ` (${config.gitleaks.path})`}`,
      `TruffleHog exclusions: ${config.trufflehog.excludePathsFile || 'none'}`
    ],
    expected: ["Gitleaks' default rules preserved, and no exclusion broad enough to hide secrets"],
    why: 'a Gitleaks config that replaces the default rules, or a broad exclusion, silently stops secret detection.',
    remediation: ['Adjust gitleaks.* / trufflehog.* or the referenced files as the items below say, then `ssd-onboard render`.']
  });
}

function dependenciesCheck(result) {
  const d = result.coverage.dependencies;
  return check('dependencies', 'Dependency coverage', {
    observed: d.manifests.length === 0
      ? ['no dependency manifests found (OSV-Scanner still runs and reports an empty result)']
      : d.manifests.map((m) => `${m.path}: ${m.coverage} — ${m.why.length ? m.why.join('; ') : COVERAGE_CLASSES[m.coverage]}`),
    expected: ['every manifest read by a dependency scanner the framework runs (osv-only and uncovered layouts are unsupported)'],
    why: 'an unscanned manifest ships vulnerable dependencies while the dependency gate reports clean.',
    remediation: ['Commit a lockfile the framework scans (docs/onboarding-cli.md § Dependency layouts). There is deliberately no local override.']
  });
}

function containerCheck(config, facts) {
  if (!isContainerProfile(config.profile)) {
    return check('container', 'Container profile fit', {
      observed: [facts.dockerfiles.length ? `Dockerfiles present: ${facts.dockerfiles.join(', ')}` : 'no Dockerfile; image, registry and deploy controls are N/A for source-only'],
      expected: ['source-only is used only when the repository ships no container image'],
      why: 'a source-only profile scans no image: a container this repository ships would reach production unscanned.',
      remediation: ['If this repository ships that image, switch to a container profile and re-run `ssd-onboard init --overwrite` or edit the config.']
    });
  }
  const k = config.container;
  return check('container', 'Container build', {
    observed: [`Dockerfile ${k.dockerfile}, context ${k.context}, image ${k.imageName}`],
    expected: ['the configured Dockerfile and context exist; no secret-shaped build arguments'],
    why: 'the image gate scans exactly the image built from these inputs.',
    remediation: ['Correct container.* in .ssd/onboarding.yml, then `ssd-onboard render`.']
  });
}

function codeownersCheck(config, facts) {
  return check('codeowners', 'CODEOWNERS coverage', {
    status: NOT_VERIFIED,
    observed: [
      facts.codeowners ? `${facts.codeowners} present` : 'no CODEOWNERS file',
      'local heuristic coverage is not proof: the matcher is a conservative subset of CODEOWNERS syntax, and whether GitHub accepts the owners or REQUIRES code-owner review cannot be seen locally'
    ],
    expected: securityOwnedPaths(config),
    why: 'without a designated security/platform reviewer, an application PR could change gate mode, baseline, scan scope or workflow wiring unreviewed.',
    remediation: [
      'Add CODEOWNERS entries (with owners) for every path listed under Expected.',
      'Require code-owner review for the default branch in a GitHub ruleset or branch protection.'
    ]
  });
}

// A settings link only when origin is POSITIVELY github.com and names the
// configured repository (whose slug the schema restricts to safe characters).
// Any other host — GitHub Enterprise included — gets host-neutral guidance.
export function githubSettingsUrl(config, facts, path) {
  const git = facts.git;
  if (git.host !== 'github.com' || !git.slug || git.slug.toLowerCase() !== config.repository.slug.toLowerCase()) {
    return null;
  }
  return `https://github.com/${config.repository.slug}/settings/${path}`;
}

function governanceCheck(config, facts) {
  const url = githubSettingsUrl(config, facts, 'rules');
  return check('github-governance', 'GitHub merge governance', {
    status: NOT_VERIFIED,
    observed: ['not checked: doctor makes no GitHub API calls; a job named security-gate in a workflow proves nothing about merge rules'],
    expected: [
      `the default branch ${config.repository.defaultBranch} requires the stable \`security-gate\` status check`,
      'code-owner review is required for the SSD control paths'
    ],
    why: 'framework enforcement makes the Actions check fail; only a repository ruleset or branch protection makes that failure authoritative for merge.',
    remediation: [
      'In the repository settings, open Rules → Rulesets.',
      `Protect the default branch ${config.repository.defaultBranch} and require the stable \`security-gate\` check.${url ? ` (${url})` : ''}`,
      'Then re-run with a future remote-aware doctor.'
    ]
  });
}

function awsCheck(config) {
  const d = config.delivery;
  return check('aws-delivery', 'AWS delivery prerequisites', {
    status: NOT_VERIFIED,
    observed: ['not checked: doctor makes no AWS calls (`ssd-onboard aws doctor` is Phase 2 and not implemented)'],
    expected: [
      `GitHub OIDC provider in account ${d.aws.accountId} (${d.oidcProvider})`,
      `ECR repository ${d.ecr.repository} in ${d.aws.region}`,
      `push+scan role ${d.roles.pushScanRoleArn}`,
      `deploy role ${d.roles.deployRoleArn}`,
      `SSM-managed instance ${d.ssm.instanceId}`
    ],
    why: 'the delivery workflow assumes these exist and trust only this repository; a missing or over-trusting role breaks delivery or its isolation.',
    remediation: ['Verify each resource and its trust policy in the AWS account (docs/aws-setup.md).']
  });
}

function slackCheck(config, facts) {
  const url = githubSettingsUrl(config, facts, 'secrets/actions');
  return check('slack-secret', 'Slack notification secret', {
    status: NOT_VERIFIED,
    observed: ['not checked: GitHub secrets cannot be read locally'],
    expected: [`a GitHub Actions secret named ${config.notifications.slack.githubSecretName}`],
    why: 'without it, gate notifications are silently not delivered.',
    remediation: [`In the repository settings, open Secrets and variables → Actions and create it.${url ? ` (${url})` : ''}`]
  });
}

function otherCheck() {
  return check('other', 'Other validation problems', {
    observed: [],
    expected: ['no unattributed validation problem'],
    why: 'validate reported these; doctor has no dedicated check for them, so they are listed rather than dropped.',
    remediation: ['Run `ssd-onboard validate` and resolve each item.']
  });
}

// --- assembly ---------------------------------------------------------------------------

// result: analyze(); facts: inspectRepository() it was computed over.
export function diagnose({ result, facts }) {
  const config = result.config;
  const configErrors = result.errors.filter((e) => e.area === 'config');
  let checks;
  if (!config || configErrors.length > 0 || !result.rollout) {
    // analyze stops early (or runs over null fields) on an invalid config: no
    // other check can be trusted, so none is reported as passing.
    checks = [configurationCheck(config), otherCheck()];
    attribute(checks, result, (entry) => (entry.area === 'config' ? 'configuration' : 'other'));
    checks[0].status = FAIL;
    checks[1].observed.push('other checks were not evaluated: the configuration must be valid first');
    checks[1].status = atLeast(checks[1].status, NOT_VERIFIED);
    return finish(checks, config);
  }
  checks = [
    configurationCheck(config),
    identityCheck(config, facts),
    frameworkPinCheck(config, result),
    workflowContractCheck(config, result),
    generatedFilesCheck(result),
    baselineCheck(config, result),
    gateModeCheck(config),
    bootstrapCheck(config, result),
    sourceBoundaryCheck(config, result),
    semgrepCheck(config, facts, result),
    secretScanningCheck(config),
    dependenciesCheck(result),
    containerCheck(config, facts),
    codeownersCheck(config, facts),
    governanceCheck(config, facts),
    ...(isEcrProfile(config.profile) && config.delivery ? [awsCheck(config)] : []),
    ...(config.notifications.slack.enabled ? [slackCheck(config, facts)] : []),
    otherCheck()
  ];
  attribute(checks, result, (entry) => routeEntry(entry, result));
  return finish(checks, config);
}

// Every analyze entry lands in exactly one check; an error makes it FAIL, a
// warning at least WARN. Unknown areas route to the catch-all (routeEntry); a
// route naming no present check is a doctor bug and fails loudly rather than
// dropping the entry.
function attribute(checks, result, route) {
  const byId = new Map(checks.map((c) => [c.id, c]));
  const place = (entry, severity) => {
    const target = byId.get(route(entry));
    if (!target) {
      throw new Error(`doctor: no check for [${entry.area}] ${entry.message}`);
    }
    target.evidence.push({ severity, area: entry.area, message: entry.message });
    target.status = atLeast(target.status, severity === 'error' ? FAIL : WARN);
  };
  result.errors.forEach((entry) => place(entry, 'error'));
  result.warnings.forEach((entry) => place(entry, 'warning'));
}

function finish(checks, config) {
  // The catch-all is shown only when it holds something.
  const shown = checks.filter((c) => c.id !== 'other' || c.evidence.length > 0 || c.observed.length > 0);
  const counts = { [PASS]: 0, [WARN]: 0, [FAIL]: 0, [NOT_VERIFIED]: 0 };
  shown.forEach((c) => (counts[c.status] += 1));
  const outcome = counts[FAIL] > 0 ? 'NOT READY' : counts[WARN] > 0 ? 'READY WITH WARNINGS' : 'READY (LOCAL CHECKS)';
  return {
    schemaVersion: 1,
    command: 'doctor',
    repository: config?.repository?.slug ?? null,
    profile: config?.profile ?? null,
    outcome,
    counts,
    checks: shown
  };
}

export const doctorExitCode = (report) => (report.counts[FAIL] > 0 ? 1 : 0);

// `doctor --json` when no diagnosis can be built (the config is missing or
// unreadable, or analysis threw): still one JSON document, exit 1 as for every
// other command. Usage errors are rejected by the shared argument parser
// before any command runs, so they stay plain text with exit 2.
export function doctorErrorReport(error) {
  const kind =
    error?.cause?.code === 'ENOENT' ? 'config-missing' : error?.name === 'YamlSubsetError' ? 'config-malformed' : 'runtime';
  return { schemaVersion: 1, command: 'doctor', outcome: 'ERROR', error: { kind, message: error?.message ?? String(error) } };
}

// --- output ---------------------------------------------------------------------------

const WIDTH = 14;

export function renderDoctor(report) {
  const out = [`SSD Doctor — ${report.profile ?? '(no valid profile)'}${report.repository ? `  (${report.repository})` : ''}`, ''];
  for (const c of report.checks) {
    out.push(`${c.status.padEnd(WIDTH)}${c.title}`);
  }
  for (const c of report.checks.filter((x) => x.status !== PASS)) {
    out.push('', `${c.status}  ${c.title}`);
    out.push(...section('What', [...c.observed, ...c.evidence.map((e) => `${e.severity === 'error' ? '✗' : '!'} [${e.area}] ${e.message}`)]));
    out.push(`Why: ${c.why}`);
    out.push(...section('Expected', c.expected));
    out.push(...section('How', c.remediation));
  }
  const nv = report.counts[NOT_VERIFIED];
  out.push(
    '',
    `Result: ${report.outcome} (${report.counts[FAIL]} FAIL, ${report.counts[WARN]} WARN, ${nv} NOT VERIFIED, ${report.counts[PASS]} PASS)`
  );
  if (nv > 0) {
    out.push('NOT VERIFIED items cannot be proven from this checkout; verify them where stated before relying on them.');
  }
  return `${out.join('\n')}\n`;
}

function section(label, items) {
  if (items.length === 0) {
    return [];
  }
  if (items.length === 1) {
    return [`${label}: ${items[0]}`];
  }
  return [`${label}:`, ...items.map((item) => `  ${item}`)];
}
