// `ssd-onboard github apply --plan-id <id> --slug <owner/repo>`: execute EXACTLY
// one reviewed plan from .ssd/github-plans/<id>/, once.
//
// It never recomputes a different plan and runs that: it re-derives the plan
// from live GitHub state (plan.mjs derivePlan, the same code `github plan`
// ran) and refuses unless the result has the SAME plan id — the same
// repository id and default branch, configuration digest, framework ref,
// operations and observed state. Order:
//   1. --slug equals repository.slug (stated by the operator, before GitHub);
//   2. plan.json is intact (id = hash of its bound input) and not applied;
//   3. the plan's repository, default branch, configuration digest and
//      framework ref equal the current ones; the CLI is bound to framework.ref;
//   4. live re-derivation (identity included: origin must be known) == plan;
//   5. typed confirmation of the slug, or --yes;
//   6. secrets only: the value is read (hidden TTY / stdin), AFTER confirmation;
//   7. live re-derivation AGAIN, immediately before the mutation;
//   8. apply-started.json (exclusive), the ONE mutation, apply.json.
// The single mutation is built by gh-cli.mjs for this plan only:
//   secrets     `gh secret set <NAME> --repo github.com/<o>/<r> --app actions`,
//               value on stdin;
//   protection  `gh api --method POST repos/<o>/<r>/rulesets --input -`, the
//               plan's exact ruleset document on stdin.
import { discoverSecret } from './discover.mjs';
import { GhCliError, readGh, rulesetCreator, secretSetter, redact } from './gh-cli.mjs';
import { derivePlan } from './plan.mjs';
import { SSD_RULESET_NAME } from './protection.mjs';
import { applyRecordsOf, canonicalJson, configDigestOf, planIdOf, readPlan, writeApplyRecord } from './record.mjs';
import { SecretInputError } from './secret-input.mjs';
import { frameworkProblems } from '../lib/framework.mjs';

export const SCHEMA_VERSION = 1;
export const OUTCOMES = Object.freeze({ APPLIED: 0, REFUSED: 1, ERROR: 1, APPLY_FAILED: 1 });
export const exitCodeOf = (report) => OUTCOMES[report.outcome] ?? 1;

export class ApplyError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'ApplyError';
    this.kind = kind;
  }
}

const finding = (severity, kind, message) => ({ severity, kind, message });
const sameSlug = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

// Which bound parts differ between the recorded and the live plan input.
function differences(recorded, live) {
  if (!live) {
    return ['the live state no longer calls for any change (or cannot be planned)'];
  }
  const parts = [];
  for (const key of ['scope', 'repository', 'configDigest', 'framework', 'operations', 'observedSha256']) {
    if (canonicalJson(recorded[key] ?? null) !== canonicalJson(live[key] ?? null)) {
      parts.push(
        {
          scope: 'scope',
          repository: 'the repository id or default branch',
          configDigest: 'the configuration',
          framework: 'the framework ref',
          operations: 'the operations',
          observedSha256: 'the observed GitHub state (rulesets, protection, secret metadata)'
        }[key]
      );
    }
  }
  return parts.length > 0 ? parts : ['the plan input'];
}

export async function githubApply({ config, facts, planId, slug, yes = false, confirm = null, readSecret = null, framework, root, exec, env = process.env, now = Date.now, onPreflight = () => {} }) {
  const report = {
    schemaVersion: SCHEMA_VERSION,
    command: 'github apply',
    planId,
    scope: null,
    outcome: null,
    repository: { slug: config.repository.slug, defaultBranch: config.repository.defaultBranch },
    user: null,
    findings: [],
    operation: null,
    execution: null,
    verification: null
  };
  const refuse = (kind, message, extra = []) => {
    report.findings.push(...extra, finding('FAIL', kind, message));
    report.outcome = 'REFUSED';
    return report;
  };

  // 1. The operator's stated target.
  if (!sameSlug(slug, config.repository.slug)) {
    return refuse('slug-mismatch', `--slug ${slug} is not repository.slug ${config.repository.slug}; apply only ever changes the configured repository`);
  }
  // 2. The record.
  const { applicable, reason, plan } = await readPlan(root, planId);
  if (!applicable) {
    return refuse('plan-not-applicable', `plan ${planId} cannot be applied: ${reason}`);
  }
  const input = plan.planIdInput;
  report.scope = input.scope;
  report.operation = input.operations[0];
  if (input.operations.length !== 1 || !['secrets', 'protection'].includes(input.scope)) {
    return refuse('plan-inconsistent', 'a plan holds exactly one operation of a known scope');
  }
  const op = input.operations[0];
  if ((input.scope === 'secrets' && op.type !== 'actions-secret-set') || (input.scope === 'protection' && (op.type !== 'ruleset-create' || op.name !== SSD_RULESET_NAME))) {
    return refuse('plan-inconsistent', `operation ${op.type} does not belong to a ${input.scope} plan`);
  }
  const applied = await applyRecordsOf(root, planId);
  if (applied.length > 0) {
    return refuse('already-applied', `plan ${planId} was already applied or attempted (${applied.join(', ')}); a plan is applied at most once — re-plan`);
  }
  // 3. Intent: the plan was made for exactly this configuration.
  if (!sameSlug(input.repository.slug, config.repository.slug)) {
    return refuse('repository-mismatch', `the plan is for ${input.repository.slug}, but repository.slug is ${config.repository.slug}`);
  }
  if (input.repository.defaultBranch !== config.repository.defaultBranch) {
    return refuse('default-branch-changed', `the plan is for default branch ${input.repository.defaultBranch}, but repository.defaultBranch is ${config.repository.defaultBranch}`);
  }
  if (input.configDigest !== configDigestOf(config)) {
    return refuse('config-changed', `.ssd/onboarding.yml changed since the plan was made; a plan reviewed against another configuration is stale — re-plan`);
  }
  const binding = frameworkProblems(framework, config);
  if (binding.length > 0 || input.framework?.ref !== config.framework.ref) {
    return refuse('framework-binding', binding[0] ?? `the plan was made with framework.ref ${input.framework?.ref}, not ${config.framework.ref}`);
  }
  if (input.scope === 'secrets' && (!config.notifications.slack.enabled || op.name !== config.notifications.slack.githubSecretName)) {
    return refuse('config-changed', 'the plan sets a secret the configuration no longer asks for');
  }

  // 4. Live re-derivation.
  const gh = readGh({ slug: config.repository.slug, branch: config.repository.defaultBranch, exec, env, now });
  const recheck = async (when) => {
    const derived = await derivePlan({ config, facts, scope: input.scope, gh, mode: 'apply' });
    report.user = derived.user;
    if (derived.blocked) {
      refuse('identity', `${when}: the repository identity or its rulesets block this apply`, derived.findings.filter((f) => f.severity === 'BLOCK'));
      return null;
    }
    if (!derived.planIdInput || planIdOf(derived.planIdInput) !== planId) {
      refuse('state-changed', `${when}: GitHub no longer matches the reviewed plan (${differences(input, derived.planIdInput).join('; ')}); nothing was changed — re-plan`, derived.findings.filter((f) => f.severity !== 'PASS'));
      return null;
    }
    return derived;
  };
  let derived = await recheck('before confirmation');
  if (!derived) {
    return report;
  }
  report.findings.push(...derived.findings);
  onPreflight(report);

  // 5. Confirmation.
  if (!yes) {
    if (!confirm) {
      return refuse('confirmation-required', 'apply needs typed confirmation on a terminal, or --yes (with --slug)');
    }
    const typed = await confirm({ slug: config.repository.slug, planId, scope: input.scope });
    if (typed !== config.repository.slug) {
      return refuse('not-confirmed', 'the typed repository did not match; nothing was changed');
    }
  }

  // 6. The secret value, only now.
  let value = null;
  if (input.scope === 'secrets') {
    if (!readSecret) {
      return refuse('secret-input', 'no secret input is available');
    }
    try {
      value = await readSecret();
    } catch (error) {
      if (error instanceof SecretInputError) {
        return refuse('secret-input', error.message);
      }
      throw error;
    }
  }
  try {
    // 7. Time of use.
    derived = await recheck('immediately before the change');
    if (!derived) {
      return report;
    }
    // 8. The one mutation.
    const started = { schemaVersion: SCHEMA_VERSION, planId, scope: input.scope, operation: op, user: derived.user, startedAt: new Date(now()).toISOString() };
    await writeApplyRecord(root, planId, 'apply-started.json', canonicalJson(started), { env, secrets: value ? [value] : [] });
    report.execution = { accepted: false, response: null, message: null };
    try {
      if (input.scope === 'secrets') {
        await secretSetter({ slug: config.repository.slug, name: op.name, exec, env, now }).set(value);
        report.execution = { accepted: true, response: null, message: null };
      } else {
        const created = await rulesetCreator({ slug: config.repository.slug, body: JSON.stringify(op.body), exec, env, now }).create();
        const ok = created && typeof created === 'object' && Number.isSafeInteger(created.id) && created.name === SSD_RULESET_NAME;
        report.execution = { accepted: true, response: ok ? { id: created.id, name: created.name } : null, message: ok ? null : 'GitHub accepted the request but returned an unexpected document' };
      }
    } catch (error) {
      if (!(error instanceof GhCliError)) {
        throw error;
      }
      // A 4xx answer, or a refusal before anything was sent, proves the change
      // did not happen. A 5xx, a timeout or an unreadable answer leaves the
      // outcome UNKNOWN, and says so.
      const known = ['refused', 'command-unavailable', 'authentication'].includes(error.kind) || (Number.isInteger(error.status) && error.status >= 400 && error.status < 500);
      report.execution = { accepted: false, response: null, message: redact(error.message, { env, secrets: value ? [value] : [] }), kind: error.kind, outcomeKnown: known };
      report.findings.push(
        finding('FAIL', 'apply-failed', known ? `GitHub refused the change: ${report.execution.message}` : `the change's outcome is UNKNOWN (${error.kind}: ${report.execution.message}); check the repository settings before re-planning`)
      );
      report.outcome = 'APPLY_FAILED';
    }
  } finally {
    value?.fill(0);
    value = null;
  }

  // 9. Observe the result (read-only), then record it.
  if (report.outcome !== 'APPLY_FAILED') {
    report.outcome = 'APPLIED';
    try {
      if (input.scope === 'secrets') {
        const after = await discoverSecret(gh, op.name);
        const before = derived.observed.secret;
        const changed = after.state === 'present' && (before.state === 'absent' || after.metadata.updatedAt !== before.updatedAt);
        report.verification = { state: changed ? 'observed' : 'not-observed', detail: changed ? `secret ${op.name} is present (updated ${after.metadata.updatedAt ?? 'at an unreported time'}); its value is not readable` : `secret ${op.name}: the update could not be observed (${after.state})` };
      } else {
        const after = await derivePlan({ config, facts, scope: 'protection', gh, mode: 'apply' });
        const governance = after.protection?.evaluation.governance ?? 'unverified';
        report.verification = { state: governance === 'satisfied' ? 'observed' : 'not-observed', detail: governance === 'satisfied' ? 'merge-governance requirements are now satisfied by a trusted ruleset' : `the requirements are not yet observed as satisfied (${governance})`, protection: after.protection?.status ?? null };
      }
    } catch (error) {
      report.verification = { state: 'not-observed', detail: `the result could not be re-read: ${redact(error.message, { env })}` };
    }
    if (report.verification.state !== 'observed') {
      report.findings.push(finding('WARN', 'not-observed', report.verification.detail));
    }
  }
  const record = { schemaVersion: SCHEMA_VERSION, planId, scope: input.scope, outcome: report.outcome, operation: op, user: report.user, execution: report.execution, verification: report.verification, finishedAt: new Date(now()).toISOString() };
  try {
    await writeApplyRecord(root, planId, 'apply.json', canonicalJson(record), { env });
  } catch (error) {
    report.findings.push(finding('WARN', 'record-failed', `apply.json could not be written: ${redact(error.message, { env })}`));
  }
  return report;
}
