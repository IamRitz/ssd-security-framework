// Merge-governance evaluation for `github plan --scope protection`: PURE.
//
// Inputs are discovery results (discover.mjs) that have already been
// schema-checked; nothing here talks to GitHub. The question it answers:
//
//   default branch
//     -> pull request required, with code-owner review, >= 1 approval,
//        stale approvals dismissed on push, and the last push approved
//     -> the stable required check `security-gate`, from GitHub Actions
//     -> no standing bypass
//
// TRUST RULES (each is mutation-tested):
//   - a requirement is satisfied only by a TRUSTED source: an ACTIVE ruleset
//     that GitHub reports as applying to the branch (rules/branches) and whose
//     bypass list is PROVEN empty, or classic protection that is readable,
//     enforces admins and has no bypass allowances;
//   - a bypass list GitHub did not return is UNKNOWN, never empty: the source
//     contributes nothing, and the requirement is NOT VERIFIED;
//   - the status check matches only when context === 'security-gate' EXACTLY
//     and its integration is the GitHub Actions app id GitHub itself reported
//     (GET /apps/github-actions) — never by prefix, case or similarity, and
//     never unpinned (any app, or any commit status, could satisfy that);
//   - the change proposed is ADDITIVE ONLY: one new ruleset holding just the
//     missing rule groups. GitHub aggregates every applicable ruleset and
//     applies the most restrictive version of each rule, so adding one never
//     weakens or overwrites another. Existing rulesets and classic protection
//     are never edited; a ruleset that already carries the SSD name but is not
//     exactly an SSD ruleset is a CONFLICT that refuses the plan.

export const REQUIRED_CHECK = 'security-gate';

// GitHub Actions' GitHub App. 15368 was confirmed on 2026-10-03 from the live
// read-only API: GET /apps/github-actions -> { id: 15368, slug:
// "github-actions", owner: "github" }, and a check run created by Actions on
// this framework's own pull request carried app.id 15368. The plan re-reads
// /apps/github-actions on every run and requires this exact identity; if
// GitHub ever answers differently the requirement is NOT VERIFIED (and a test
// pins the mapping).
export const GITHUB_ACTIONS_APP = Object.freeze({ id: 15368, slug: 'github-actions', owner: 'github' });

export const SSD_RULESET_NAME = 'ssd-merge-governance';

// The pull-request rule the SSD ruleset carries. required_review_thread_resolution
// is a REQUIRED field of GitHub's pull_request rule; false adds no governance.
export const PULL_REQUEST_PARAMETERS = Object.freeze({
  dismiss_stale_reviews_on_push: true,
  require_code_owner_review: true,
  require_last_push_approval: true,
  required_approving_review_count: 1,
  required_review_thread_resolution: false
});

// The requirements, each judged on its own: rules from several sources
// aggregate, so two rulesets can satisfy them together.
export const REQUIREMENTS = Object.freeze([
  { id: 'status-check', group: 'required_status_checks', label: `required status check \`${REQUIRED_CHECK}\` from GitHub Actions` },
  { id: 'code-owner-review', group: 'pull_request', label: 'code-owner review required' },
  { id: 'approvals', group: 'pull_request', label: 'at least one approving review' },
  { id: 'dismiss-stale', group: 'pull_request', label: 'stale approvals dismissed on push' },
  { id: 'last-push-approval', group: 'pull_request', label: 'the most recent push approved by someone else' }
]);

// --- exact matching ---------------------------------------------------------------

// A ruleset required_status_checks entry: { context, integration_id? }.
export function isPinnedSecurityGate(entry, appId) {
  return Boolean(entry) && entry.context === REQUIRED_CHECK && Number.isInteger(appId) && entry.integration_id === appId;
}

// What one pull_request parameter object satisfies.
function pullRequestSatisfies(p) {
  return {
    'code-owner-review': p?.require_code_owner_review === true,
    approvals: Number.isInteger(p?.required_approving_review_count) && p.required_approving_review_count >= 1,
    'dismiss-stale': p?.dismiss_stale_reviews_on_push === true,
    'last-push-approval': p?.require_last_push_approval === true
  };
}

// --- sources ----------------------------------------------------------------------

const describeActor = (a) => {
  const mode = a.bypass_mode ? ` (${a.bypass_mode})` : '';
  switch (a.actor_type) {
    case 'OrganizationAdmin':
      return `organization admins${mode}`;
    case 'RepositoryRole':
      return `repository role ${a.actor_id === 5 ? 'admin' : a.actor_id === 4 ? 'write' : a.actor_id === 2 ? 'maintain' : a.actor_id === 1 ? 'read' : a.actor_id === 3 ? 'triage' : `#${a.actor_id}`}${mode}`;
    case 'Team':
      return `team #${a.actor_id}${mode}`;
    case 'Integration':
      return `GitHub App (integration) #${a.actor_id}${mode}`;
    case 'DeployKey':
      return `deploy keys${mode}`;
    case 'EnterpriseOwner':
      return `enterprise owners${mode}`;
    default:
      return `${a.actor_type ?? 'unknown actor type'} #${a.actor_id ?? '?'}${mode}`;
  }
};

// One applicable ruleset -> a source. `applied` are its rules/branches entries.
function rulesetSource(id, applied, detail) {
  const first = applied[0];
  const source = {
    kind: 'ruleset',
    id,
    name: detail?.name ?? null,
    sourceType: first.ruleset_source_type,
    sourceName: first.ruleset_source,
    enforcement: detail?.enforcement ?? null,
    bypass: { state: 'unknown', actors: [] },
    trusted: false,
    reasons: [],
    satisfies: {},
    checks: []
  };
  for (const rule of applied) {
    if (rule.type === 'pull_request') {
      for (const [req, ok] of Object.entries(pullRequestSatisfies(rule.parameters))) {
        source.satisfies[req] ||= ok;
      }
    }
    if (rule.type === 'required_status_checks') {
      for (const entry of rule.parameters?.required_status_checks ?? []) {
        source.checks.push({ context: entry.context, integrationId: entry.integration_id ?? null });
      }
    }
  }
  if (!detail) {
    source.reasons.push('its details (enforcement, bypass list) could not be read with this token');
    return source;
  }
  if (detail.enforcement !== 'active') {
    source.reasons.push(`enforcement is ${detail.enforcement}, not active`);
    return source;
  }
  if (!Array.isArray(detail.bypass_actors)) {
    source.reasons.push('GitHub did not return its bypass list to this token: bypass cannot be ruled out');
    return source;
  }
  if (detail.bypass_actors.length > 0) {
    source.bypass = { state: 'present', actors: detail.bypass_actors.map(describeActor) };
    source.reasons.push(`bypass allowed for: ${source.bypass.actors.join(', ')}`);
    return source;
  }
  if (detail.current_user_can_bypass !== undefined && detail.current_user_can_bypass !== 'never') {
    source.reasons.push(`the bypass list is empty but GitHub reports current_user_can_bypass: ${detail.current_user_can_bypass}`);
    return source;
  }
  source.bypass = { state: 'none', actors: [] };
  source.trusted = true;
  return source;
}

// Classic branch protection -> a source, or null when the branch has none.
function classicSource(classic) {
  if (classic.state === 'absent') {
    return null;
  }
  const source = { kind: 'classic', id: null, name: 'classic branch protection', bypass: { state: 'unknown', actors: [] }, trusted: false, reasons: [], satisfies: {}, checks: [] };
  if (classic.state !== 'present') {
    source.reasons.push('the branch is protected, but its protection settings need repository admin to read');
    return source;
  }
  const p = classic.value;
  const reviews = p.required_pull_request_reviews ?? null;
  if (reviews) {
    Object.assign(
      source.satisfies,
      pullRequestSatisfies({
        require_code_owner_review: reviews.require_code_owner_reviews,
        required_approving_review_count: reviews.required_approving_review_count,
        dismiss_stale_reviews_on_push: reviews.dismiss_stale_reviews,
        require_last_push_approval: reviews.require_last_push_approval
      })
    );
  }
  for (const check of p.required_status_checks?.checks ?? []) {
    source.checks.push({ context: check.context, integrationId: check.app_id ?? null });
  }
  for (const context of p.required_status_checks?.contexts ?? []) {
    if (!source.checks.some((c) => c.context === context)) {
      source.checks.push({ context, integrationId: null });
    }
  }
  const actors = [];
  if (p.enforce_admins?.enabled !== true) {
    actors.push('repository admins (enforce_admins is off)');
  }
  const allowances = reviews?.bypass_pull_request_allowances ?? {};
  for (const [kind, list] of Object.entries(allowances)) {
    if (Array.isArray(list) && list.length > 0) {
      actors.push(`${list.length} ${kind} with pull-request bypass allowances`);
    }
  }
  if (actors.length > 0) {
    source.bypass = { state: 'present', actors };
    source.reasons.push(`bypass allowed for: ${actors.join(', ')}`);
    return source;
  }
  source.bypass = { state: 'none', actors: [] };
  source.trusted = true;
  return source;
}

// --- the SSD ruleset --------------------------------------------------------------

// The ruleset `github apply` creates: exactly the missing rule groups.
export function desiredRuleset({ branch, groups, appId }) {
  const rules = [];
  if (groups.includes('pull_request')) {
    rules.push({ type: 'pull_request', parameters: { ...PULL_REQUEST_PARAMETERS } });
  }
  if (groups.includes('required_status_checks')) {
    rules.push({
      type: 'required_status_checks',
      parameters: { required_status_checks: [{ context: REQUIRED_CHECK, integration_id: appId }], strict_required_status_checks_policy: false }
    });
  }
  return {
    name: SSD_RULESET_NAME,
    target: 'branch',
    enforcement: 'active',
    bypass_actors: [],
    conditions: { ref_name: { include: [`refs/heads/${branch}`], exclude: [] } },
    rules
  };
}

// Is an existing ruleset carrying the SSD name EXACTLY an SSD ruleset for this
// branch? -> list of differences (empty = well-formed). Parameters GitHub may
// add with neutral defaults (e.g. allowed_merge_methods) are not compared;
// every field the SSD ruleset sets is.
export function ssdRulesetDrift(detail, { branch, appId }) {
  const drift = [];
  if (detail.target !== 'branch') drift.push(`target is ${detail.target}`);
  if (detail.enforcement !== 'active') drift.push(`enforcement is ${detail.enforcement}`);
  if (!Array.isArray(detail.bypass_actors)) drift.push('its bypass list is not visible');
  else if (detail.bypass_actors.length > 0) drift.push(`it has ${detail.bypass_actors.length} bypass actor(s)`);
  const include = detail.conditions?.ref_name?.include;
  const exclude = detail.conditions?.ref_name?.exclude;
  if (!Array.isArray(include) || include.length !== 1 || include[0] !== `refs/heads/${branch}` || !Array.isArray(exclude) || exclude.length !== 0) {
    drift.push(`its branch condition is not exactly refs/heads/${branch}`);
  }
  if (detail.conditions && Object.keys(detail.conditions).some((k) => k !== 'ref_name')) {
    drift.push('it has conditions other than ref_name');
  }
  const rules = Array.isArray(detail.rules) ? detail.rules : [];
  const types = rules.map((r) => r.type);
  if (rules.length === 0) drift.push('it has no rules');
  if (new Set(types).size !== types.length) drift.push('it repeats a rule type');
  for (const rule of rules) {
    if (rule.type === 'pull_request') {
      for (const [key, value] of Object.entries(PULL_REQUEST_PARAMETERS)) {
        if (rule.parameters?.[key] !== value) drift.push(`pull_request.${key} is ${JSON.stringify(rule.parameters?.[key])}, not ${JSON.stringify(value)}`);
      }
    } else if (rule.type === 'required_status_checks') {
      const checks = rule.parameters?.required_status_checks;
      if (!Array.isArray(checks) || checks.length !== 1 || !isPinnedSecurityGate(checks[0], appId)) drift.push(`required_status_checks is not exactly [${REQUIRED_CHECK} from integration ${appId}]`);
      if (rule.parameters?.strict_required_status_checks_policy !== false) drift.push('strict_required_status_checks_policy is not false');
    } else {
      drift.push(`it has a ${rule.type} rule, which an SSD ruleset never holds`);
    }
  }
  return drift;
}

// --- evaluation -------------------------------------------------------------------

// discovered = {
//   actionsApp: { state: 'verified', id } | { state: 'unverified', reason },
//   branchRules: { state: 'present', value: [...] } | { state: 'unverified', reason },
//   rulesetList: { state: 'present', value: [...] } | { state: 'unverified', reason },
//   rulesetDetails: Map<id, detail | null>,
//   classic: { state: 'absent' | 'present' | 'unverified', value?, reason? },
//   permissions: repository.permissions
// }
// -> { requirements, sources, conflicts, groupsMissing, governance, unverified }
export function evaluateProtection({ branch, discovered }) {
  const { actionsApp, branchRules, rulesetList, rulesetDetails, classic } = discovered;
  const appId = actionsApp.state === 'verified' ? actionsApp.id : null;
  const unverified = [];
  const conflicts = [];
  const sources = [];

  if (actionsApp.state !== 'verified') {
    unverified.push(`the GitHub Actions app identity could not be proven (${actionsApp.reason}): a pinned \`${REQUIRED_CHECK}\` cannot be recognised or planned`);
  }
  if (branchRules.state === 'present') {
    const byId = new Map();
    for (const rule of branchRules.value) {
      byId.set(rule.ruleset_id, [...(byId.get(rule.ruleset_id) ?? []), rule]);
    }
    for (const [id, applied] of [...byId.entries()].sort((a, b) => a[0] - b[0])) {
      sources.push(rulesetSource(id, applied, rulesetDetails.get(id) ?? null));
    }
  } else {
    unverified.push(`the rules that apply to ${branch} could not be read (${branchRules.reason})`);
  }
  const classicSrc = classicSource(classic);
  if (classicSrc) {
    sources.push(classicSrc);
  }

  // Each requirement: satisfied by a trusted source, or not.
  const requirements = REQUIREMENTS.map((req) => {
    const provides = (s) => (req.id === 'status-check' ? s.checks.some((c) => isPinnedSecurityGate({ context: c.context, integration_id: c.integrationId }, appId)) : s.satisfies[req.id] === true);
    const trusted = sources.filter((s) => s.trusted && provides(s));
    const untrusted = sources.filter((s) => !s.trusted && provides(s));
    const notes = [];
    if (req.id === 'status-check') {
      for (const s of sources) {
        for (const c of s.checks) {
          if (c.context === REQUIRED_CHECK && (appId === null || c.integrationId !== appId)) {
            notes.push(`${sourceLabel(s)} requires \`${REQUIRED_CHECK}\` ${c.integrationId === null ? 'from ANY source (not pinned to GitHub Actions): an app or commit status could satisfy it' : `from integration ${c.integrationId}, not GitHub Actions`}`);
          } else if (/^gate-mode\b/i.test(c.context)) {
            notes.push(`${sourceLabel(s)} requires \`${c.context}\`: the gate-mode check is informational and changes name with the mode; it is never the required gate`);
          } else if (c.context !== REQUIRED_CHECK && c.context.toLowerCase().replace(/[\s_]+/g, '-').includes(REQUIRED_CHECK)) {
            notes.push(`${sourceLabel(s)} requires \`${c.context}\`, which is NOT \`${REQUIRED_CHECK}\` (names are compared exactly)`);
          }
        }
      }
    }
    let state;
    if (trusted.length > 0) {
      state = 'satisfied';
    } else if (
      branchRules.state !== 'present' ||
      (req.id === 'status-check' && appId === null) ||
      // classic protection we cannot read may be what satisfies it
      classic.state === 'unverified' ||
      untrusted.some((s) => s.bypass.state === 'unknown')
    ) {
      state = 'unverified';
    } else {
      state = 'missing';
    }
    return { ...req, state, by: trusted.map(sourceLabel), untrusted: untrusted.map((s) => `${sourceLabel(s)} (${s.reasons.join('; ')})`), notes };
  });

  // An existing ruleset with the SSD name.
  let ssdExisting = null;
  if (rulesetList.state === 'present') {
    const named = rulesetList.value.filter((r) => r.name === SSD_RULESET_NAME && r.source_type === 'Repository');
    for (const summary of named) {
      const detail = rulesetDetails.get(summary.id) ?? null;
      if (!detail) {
        conflicts.push({ kind: 'ssd-ruleset-unreadable', message: `a ruleset named ${SSD_RULESET_NAME} (#${summary.id}) exists but could not be read; remove or inspect it by hand, then re-plan` });
        continue;
      }
      const drift = ssdRulesetDrift(detail, { branch, appId });
      if (drift.length > 0) {
        conflicts.push({ kind: 'ssd-ruleset-drifted', message: `ruleset ${SSD_RULESET_NAME} (#${summary.id}) is not exactly an SSD ruleset for ${branch}: ${drift.join('; ')}. ssd-onboard never edits a ruleset: fix or delete it by hand, then re-plan` });
        continue;
      }
      ssdExisting = { id: summary.id, groups: detail.rules.map((r) => r.type) };
    }
  }

  const groupsMissing = [...new Set(requirements.filter((r) => r.state !== 'satisfied').map((r) => r.group))].sort();
  if (ssdExisting && groupsMissing.length > 0) {
    conflicts.push({
      kind: 'ssd-ruleset-incomplete',
      message: `ruleset ${SSD_RULESET_NAME} (#${ssdExisting.id}) already exists but the branch still lacks: ${groupsMissing.join(', ')}. Adding rules to it would be an edit, which v1 never makes: delete it by hand, then re-plan`
    });
  }
  const governance = requirements.every((r) => r.state === 'satisfied') ? 'satisfied' : requirements.some((r) => r.state === 'unverified') ? 'unverified' : 'missing';
  return { appId, requirements, sources: sources.map(publicSource), conflicts, groupsMissing, governance, unverified };
}

const sourceLabel = (s) => (s.kind === 'classic' ? 'classic branch protection' : `ruleset ${s.name ?? `#${s.id}`}${s.sourceType === 'Organization' ? ` (organization ${s.sourceName})` : ''}`);
const publicSource = (s) => ({ kind: s.kind, id: s.id, label: sourceLabel(s), enforcement: s.enforcement ?? null, bypass: s.bypass, trusted: s.trusted, reasons: s.reasons });
