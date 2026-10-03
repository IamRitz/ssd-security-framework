// `ssd-onboard github plan --scope secrets|protection`: inspect the configured
// repository READ-ONLY and record what `github apply` would change.
//
// It changes nothing on GitHub: every call goes through readGh(), whose
// allowlist is GET-only over endpoints built for repository.slug and
// repository.defaultBranch. Its one write is .ssd/github-plans/<plan-id>/plan.json.
// It never reads a secret value (GitHub cannot return one).
//
// One plan holds one privilege class: `secrets` (an Actions secret; needs
// secret write) or `protection` (a repository ruleset; needs admin). Order:
//   1. the CLI is bound to framework.ref (the same rule as render / aws plan);
//   2. secrets with Slack disabled: nothing to plan, GitHub is not contacted;
//   3. the authenticated user, then the repository: identity (identity.mjs);
//   4. scope discovery and evaluation;
//   5. operations -> planIdInput -> plan.json.
// derivePlan() is shared with `github apply`, which re-derives the plan from
// live state and refuses unless it is IDENTICAL to the recorded one.
import { analyzeCodeowners } from './codeowners.mjs';
import { discoverActionsApp, discoverBranchRules, discoverClassic, discoverCodeowners, discoverRepository, discoverRulesetDetail, discoverRulesetList, discoverSecret, discoverUser } from './discover.mjs';
import { readGh } from './gh-cli.mjs';
import { blocks, identityFindings } from './identity.mjs';
import { SSD_RULESET_NAME, desiredRuleset, evaluateProtection } from './protection.mjs';
import { PLAN_SCHEMA_VERSION, canonicalJson, configDigestOf, planIdOf, sha256, writePlan } from './record.mjs';
import { frameworkProblems } from '../lib/framework.mjs';

export const SCHEMA_VERSION = 1;
export const SCOPES = Object.freeze(['secrets', 'protection']);
// PLANNED / COMPLIANT / NO_CHANGES / NOTHING_TO_PLAN succeed; INCOMPLETE,
// NOT_VERIFIED, BLOCKED and ERROR exit 1 — uncertainty is never success.
export const OUTCOMES = Object.freeze({ PLANNED: 0, COMPLIANT: 0, NO_CHANGES: 0, NOTHING_TO_PLAN: 0, INCOMPLETE: 1, NOT_VERIFIED: 1, BLOCKED: 1, ERROR: 1 });
export const exitCodeOf = (report) => OUTCOMES[report.outcome] ?? 1;

const finding = (severity, kind, message) => ({ severity, kind, message });

// --- secrets ----------------------------------------------------------------------

async function deriveSecrets(ctx) {
  const { config, gh } = ctx;
  const name = config.notifications.slack.githubSecretName;
  const secret = await discoverSecret(gh, name);
  const section = { enabled: true, name, state: secret.state, metadata: secret.metadata ?? null, reason: secret.reason ?? null };
  if (secret.state === 'unverified') {
    ctx.findings.push(finding('NOT VERIFIED', 'secret-unverified', `whether Actions secret ${name} exists could not be read (${secret.reason}); repository secrets need collaborator write/admin or the fine-grained Secrets permission`));
    return { section, operations: [], observed: null, notVerified: true };
  }
  // GitHub returns names and timestamps only: a present secret's VALUE is
  // unknowable, so the plan proposes setting it (create) or rotating it.
  const operations = [{ type: 'actions-secret-set', name, action: secret.state === 'absent' ? 'create' : 'rotate' }];
  const observed = { secret: { name, state: secret.state, createdAt: secret.metadata?.createdAt ?? null, updatedAt: secret.metadata?.updatedAt ?? null } };
  return { section, operations, observed, notVerified: false };
}

// --- protection -------------------------------------------------------------------

async function deriveProtection(ctx) {
  const { config, facts, gh, repository } = ctx;
  const branch = config.repository.defaultBranch;
  const actionsApp = await discoverActionsApp(gh);
  const branchRules = await discoverBranchRules(gh);
  const rulesetList = await discoverRulesetList(gh);
  // Details for every ruleset that applies to the branch, and for any carrying
  // the SSD name (its exact shape decides between reuse and conflict).
  const ids = new Set();
  if (branchRules.state === 'present') branchRules.value.forEach((r) => ids.add(r.ruleset_id));
  if (rulesetList.state === 'present') rulesetList.value.filter((r) => r.name === SSD_RULESET_NAME).forEach((r) => ids.add(r.id));
  const rulesetDetails = new Map();
  for (const id of [...ids].sort((a, b) => a - b)) {
    rulesetDetails.set(id, await discoverRulesetDetail(gh, id));
  }
  const classic = await discoverClassic(gh);
  const discovered = { actionsApp, branchRules, rulesetList, rulesetDetails, classic };
  const evaluation = evaluateProtection({ branch, discovered });
  const remote = await discoverCodeowners(gh, { canRead: repository.value.permissions.pull });
  const codeowners = analyzeCodeowners({ config, facts, remote });

  evaluation.unverified.forEach((m) => ctx.findings.push(finding('NOT VERIFIED', 'protection-unverified', m)));
  evaluation.conflicts.forEach((c) => ctx.findings.push(finding('BLOCK', c.kind, c.message)));
  codeowners.warnings.forEach((m) => ctx.findings.push(finding('WARN', 'codeowners-local', m)));

  const operations = [];
  let notVerified = false;
  if (evaluation.groupsMissing.length > 0 && evaluation.conflicts.length === 0) {
    // Creating a ruleset safely needs: what applies today (so nothing is
    // duplicated), every ruleset name (so nothing is clobbered), the GitHub
    // Actions identity (to pin the check) and repository admin.
    const missing = [];
    if (branchRules.state !== 'present') missing.push('the rules applying to the branch are unreadable');
    if (rulesetList.state !== 'present') missing.push(`the repository's rulesets are unreadable (${rulesetList.reason})`);
    if (evaluation.appId === null) missing.push('the GitHub Actions app identity is unproven');
    if (!repository.value.permissions.admin) missing.push('this token is not a repository admin (rulesets need administration permission)');
    if (missing.length > 0) {
      notVerified = true;
      ctx.findings.push(finding('NOT VERIFIED', 'cannot-plan-ruleset', `a ruleset is needed (${evaluation.groupsMissing.join(', ')}) but cannot be planned safely: ${missing.join('; ')}`));
    } else {
      const body = desiredRuleset({ branch, groups: evaluation.groupsMissing, appId: evaluation.appId });
      operations.push({ type: 'ruleset-create', name: SSD_RULESET_NAME, groups: evaluation.groupsMissing, body, bodySha256: sha256(canonicalJson(body)) });
    }
  }
  const status = evaluation.governance === 'satisfied' && codeowners.state === 'complete' ? 'COMPLIANT' : evaluation.governance === 'unverified' || (evaluation.governance === 'satisfied' && codeowners.state === 'unverified') ? 'NOT VERIFIED' : 'INCOMPLETE';
  const observed = {
    actionsApp: actionsApp.state === 'verified' ? { id: actionsApp.id } : { unverified: actionsApp.reason },
    branchRules: branchRules.state === 'present' ? branchRules.value.map((r) => ({ type: r.type, ruleset_id: r.ruleset_id, ruleset_source_type: r.ruleset_source_type, ruleset_source: r.ruleset_source, parameters: r.parameters ?? {} })) : { unverified: branchRules.reason },
    rulesets: rulesetList.state === 'present' ? rulesetList.value : { unverified: rulesetList.reason },
    rulesetDetails: Object.fromEntries([...rulesetDetails.entries()].map(([id, d]) => [String(id), d])),
    classic
  };
  return { section: { status, evaluation, codeowners }, operations, observed, notVerified };
}

// --- shared derivation ------------------------------------------------------------

// -> { findings, user, repository, secrets?, protection?, operations, observed,
//      planIdInput | null, notVerified, blocked }
export async function derivePlan({ config, facts, scope, gh, mode = 'plan' }) {
  const ctx = { config, facts, gh, findings: [] };
  const user = await discoverUser(gh); // a 401 ends the run here (ERROR)
  const repository = await discoverRepository(gh);
  ctx.repository = repository;
  ctx.findings.push(...identityFindings({ config, facts, repository, mode }));
  const base = { user: user.state === 'present' ? user.login : null, repository: repository.state === 'present' ? repository.value : null };
  if (blocks(ctx.findings)) {
    return { ...base, findings: ctx.findings, operations: [], observed: null, planIdInput: null, notVerified: false, blocked: true };
  }
  const derived = scope === 'secrets' ? await deriveSecrets(ctx) : await deriveProtection(ctx);
  const blocked = blocks(ctx.findings);
  const planIdInput =
    derived.operations.length > 0 && !blocked
      ? {
          kind: 'ssd-github-plan',
          schemaVersion: PLAN_SCHEMA_VERSION,
          scope,
          repository: { slug: config.repository.slug, id: repository.value.id, defaultBranch: config.repository.defaultBranch },
          configDigest: configDigestOf(config),
          framework: { repository: config.framework.repository, ref: config.framework.ref },
          operations: derived.operations,
          observedSha256: sha256(canonicalJson(derived.observed))
        }
      : null;
  return {
    ...base,
    findings: ctx.findings,
    [scope]: derived.section,
    operations: blocked ? [] : derived.operations,
    observed: derived.observed,
    planIdInput,
    notVerified: derived.notVerified,
    blocked
  };
}

function outcomeOf(scope, derived) {
  if (derived.blocked) return 'BLOCKED';
  if (derived.planIdInput) return 'PLANNED';
  if (derived.notVerified) return 'NOT_VERIFIED';
  if (scope === 'protection') {
    const status = derived.protection.status;
    return status === 'COMPLIANT' ? 'COMPLIANT' : status === 'NOT VERIFIED' ? 'NOT_VERIFIED' : 'INCOMPLETE';
  }
  return 'NO_CHANGES';
}

// --- the command ------------------------------------------------------------------

export async function githubPlan({ config, facts, scope, framework, root, exec, env = process.env, now }) {
  const report = {
    schemaVersion: SCHEMA_VERSION,
    command: 'github plan',
    scope,
    outcome: null,
    repository: { slug: config.repository.slug, defaultBranch: config.repository.defaultBranch, origin: facts?.git?.slug ?? null, github: null },
    user: null,
    findings: [],
    operations: [],
    plan: null
  };
  const binding = frameworkProblems(framework, config);
  if (binding.length > 0) {
    report.findings = binding.map((m) => finding('BLOCK', 'framework-binding', m));
    report.outcome = 'BLOCKED';
    return report;
  }
  if (scope === 'secrets' && !config.notifications.slack.enabled) {
    report.secrets = { enabled: false, name: config.notifications.slack.githubSecretName, state: 'not-needed', metadata: null, reason: null };
    report.findings.push(finding('PASS', 'slack-disabled', 'notifications.slack.enabled is false: no GitHub secret is needed, and GitHub was not contacted'));
    report.outcome = 'NOTHING_TO_PLAN';
    return report;
  }
  const gh = readGh({ slug: config.repository.slug, branch: config.repository.defaultBranch, exec, env, now });
  const derived = await derivePlan({ config, facts, scope, gh, mode: 'plan' });
  report.user = derived.user;
  report.repository.github = derived.repository;
  report.findings = derived.findings;
  report.operations = derived.operations;
  if (derived[scope]) report[scope] = derived[scope];
  report.outcome = outcomeOf(scope, derived);
  if (derived.planIdInput) {
    const planId = planIdOf(derived.planIdInput);
    const doc = { schemaVersion: PLAN_SCHEMA_VERSION, planId, planIdInput: derived.planIdInput, observed: derived.observed };
    const written = await writePlan(root, planId, canonicalJson(doc), { env });
    report.plan = { id: planId, ...written };
  }
  return report;
}
