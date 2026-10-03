// Merge-governance evaluation (onboarding/github/protection.mjs) and the
// CODEOWNERS analysis (codeowners.mjs): pure functions over discovery results
// shaped like the recorded fixtures (test/fixtures/github).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { analyzeCodeowners } from '../onboarding/github/codeowners.mjs';
import { GITHUB_ACTIONS_APP, PULL_REQUEST_PARAMETERS, REQUIRED_CHECK, SSD_RULESET_NAME, desiredRuleset, evaluateProtection, isPinnedSecurityGate, ssdRulesetDrift } from '../onboarding/github/protection.mjs';
import { config } from './support/onboarding-fixtures.mjs';
import { COMPLETE_CODEOWNERS, contentsDoc, facts, fixture, rulesetDetail } from './support/github-fake.mjs';

const BRANCH = 'main';
const APP = { state: 'verified', id: 15368 };

// Rules GitHub reports for the branch, from ruleset details.
const rulesFrom = (...details) =>
  details.flatMap((d) => d.rules.map((r) => ({ type: r.type, ruleset_source_type: d.source_type ?? 'Repository', ruleset_source: d.source ?? 'acme/app', ruleset_id: d.id, parameters: r.parameters ?? {} })));

function evaluate({ details = [], hidden = [], actionsApp = APP, classic = { state: 'absent' }, branchRules, rulesetList } = {}) {
  const rulesetDetails = new Map(details.map((d) => [d.id, hidden.includes(d.id) ? (({ bypass_actors, current_user_can_bypass, ...rest }) => rest)(d) : d]));
  return evaluateProtection({
    branch: BRANCH,
    discovered: {
      actionsApp,
      branchRules: branchRules ?? { state: 'present', value: rulesFrom(...details) },
      rulesetList: rulesetList ?? { state: 'present', value: details.map((d) => ({ id: d.id, name: d.name, source_type: d.source_type ?? 'Repository', enforcement: d.enforcement })) },
      rulesetDetails,
      classic
    }
  });
}
const state = (e, id) => e.requirements.find((r) => r.id === id).state;
const withChecks = (checks) => rulesetDetail({ rules: [{ type: 'required_status_checks', parameters: { required_status_checks: checks, strict_required_status_checks_policy: false } }, rulesetDetail().rules[0]] });

describe('github protection: the GitHub Actions identity', () => {
  it('pins app id 15368 / github-actions / github, as observed live', () => {
    assert.deepEqual({ ...GITHUB_ACTIONS_APP }, { id: 15368, slug: 'github-actions', owner: 'github' });
    const live = fixture('live-actions-app.json');
    assert.deepEqual([live.id, live.slug, live.owner.login], [GITHUB_ACTIONS_APP.id, GITHUB_ACTIONS_APP.slug, GITHUB_ACTIONS_APP.owner]);
    assert.equal(fixture('live-check-run-app.json').app.id, GITHUB_ACTIONS_APP.id, 'an Actions check run carries that app id');
  });

  it('an unproven Actions identity leaves the check requirement NOT VERIFIED, never satisfied', () => {
    const e = evaluate({ details: [rulesetDetail()], actionsApp: { state: 'unverified', reason: 'HTTP 403' } });
    assert.equal(state(e, 'status-check'), 'unverified');
    assert.notEqual(e.governance, 'satisfied');
  });
});

describe('github protection: exact `security-gate` matching', () => {
  it('a compliant ruleset (documented shape) satisfies every requirement', () => {
    const e = evaluate({ details: [rulesetDetail()] });
    assert.equal(e.governance, 'satisfied');
    assert.deepEqual(e.groupsMissing, []);
    assert.ok(e.requirements.every((r) => r.state === 'satisfied'));
  });

  it('only the exact context pinned to GitHub Actions matches', () => {
    assert.equal(isPinnedSecurityGate({ context: 'security-gate', integration_id: 15368 }, 15368), true);
    for (const entry of [
      { context: 'security-gate' },
      { context: 'security-gate', integration_id: 1 },
      { context: 'security-gate-pr', integration_id: 15368 },
      { context: 'Security Gate', integration_id: 15368 },
      { context: 'security_gate', integration_id: 15368 },
      { context: 'gate-mode: enforce', integration_id: 15368 },
      { context: 'gate-mode: LOG-ONLY (gate NOT enforcing)', integration_id: 15368 },
      { context: ' security-gate', integration_id: 15368 },
      { context: 'security-gate ', integration_id: 15368 },
      { context: 'pr/security-gate', integration_id: 15368 },
      { context: 'SECURITY-GATE', integration_id: 15368 }
    ]) {
      assert.equal(isPinnedSecurityGate(entry, 15368), false, JSON.stringify(entry));
    }
  });

  for (const [what, checks] of [
    ['security-gate-pr', [{ context: 'security-gate-pr', integration_id: 15368 }]],
    ['Security Gate', [{ context: 'Security Gate', integration_id: 15368 }]],
    ['gate-mode: …', [{ context: 'gate-mode: enforce', integration_id: 15368 }]],
    ['an unpinned security-gate', [{ context: 'security-gate' }]],
    ['security-gate from another app', [{ context: 'security-gate', integration_id: 999 }]]
  ]) {
    it(`a ruleset requiring only ${what} does NOT satisfy the check`, () => {
      const e = evaluate({ details: [withChecks(checks)] });
      assert.equal(state(e, 'status-check'), 'missing');
      assert.deepEqual(e.groupsMissing, ['required_status_checks']);
      assert.ok(e.requirements.find((r) => r.id === 'status-check').notes.length > 0, 'the near miss is explained');
    });
  }
});

describe('github protection: pull-request requirements', () => {
  for (const [key, id, value] of [
    ['require_code_owner_review', 'code-owner-review', false],
    ['required_approving_review_count', 'approvals', 0],
    ['dismiss_stale_reviews_on_push', 'dismiss-stale', false],
    ['require_last_push_approval', 'last-push-approval', false]
  ]) {
    it(`${key}: ${JSON.stringify(value)} leaves ${id} missing`, () => {
      const d = rulesetDetail();
      d.rules = d.rules.map((r) => (r.type === 'pull_request' ? { ...r, parameters: { ...r.parameters, [key]: value } } : r));
      const e = evaluate({ details: [d] });
      assert.equal(state(e, id), 'missing');
      assert.deepEqual(e.groupsMissing, ['pull_request']);
    });
  }

  it('required PR review and code-owner review are recognised', () => {
    const e = evaluate({ details: [rulesetDetail()] });
    assert.equal(state(e, 'code-owner-review'), 'satisfied');
    assert.equal(state(e, 'approvals'), 'satisfied');
  });

  it('requirements aggregate across trusted rulesets (most restrictive wins)', () => {
    const pr = rulesetDetail({ id: 1, name: 'reviews', rules: [rulesetDetail().rules[0]] });
    const checks = rulesetDetail({ id: 2, name: 'checks', rules: [rulesetDetail().rules[1]] });
    assert.equal(evaluate({ details: [pr, checks] }).governance, 'satisfied');
  });
});

describe('github protection: bypass', () => {
  for (const [what, actors] of [
    ['repository admins', [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }]],
    ['organization admins', [{ actor_id: 1, actor_type: 'OrganizationAdmin', bypass_mode: 'always' }]],
    ['a team', [{ actor_id: 77, actor_type: 'Team', bypass_mode: 'pull_request' }]],
    ['an app', [{ actor_id: 12345, actor_type: 'Integration', bypass_mode: 'always' }]],
    ['deploy keys', [{ actor_id: null, actor_type: 'DeployKey', bypass_mode: 'always' }]]
  ]) {
    it(`a bypass actor (${what}) makes the ruleset count for nothing: not compliant`, () => {
      const e = evaluate({ details: [rulesetDetail({ bypass_actors: actors, current_user_can_bypass: 'always' })] });
      assert.equal(e.governance, 'missing');
      assert.equal(e.sources[0].bypass.state, 'present');
      assert.equal(e.sources[0].trusted, false);
      assert.deepEqual(e.groupsMissing, ['pull_request', 'required_status_checks']);
    });
  }

  it('a bypass list GitHub did not return is UNKNOWN: NOT VERIFIED, never compliant', () => {
    const e = evaluate({ details: [rulesetDetail()], hidden: [42] });
    assert.equal(e.sources[0].bypass.state, 'unknown');
    assert.equal(e.governance, 'unverified');
    assert.ok(e.requirements.every((r) => r.state === 'unverified'));
  });

  it('an unreadable ruleset detail is UNKNOWN too', () => {
    const d = rulesetDetail();
    const e = evaluateProtection({
      branch: BRANCH,
      discovered: { actionsApp: APP, branchRules: { state: 'present', value: rulesFrom(d) }, rulesetList: { state: 'present', value: [] }, rulesetDetails: new Map([[42, null]]), classic: { state: 'absent' } }
    });
    assert.equal(e.governance, 'unverified');
  });

  it('an empty bypass list with current_user_can_bypass other than never is not trusted', () => {
    const e = evaluate({ details: [rulesetDetail({ current_user_can_bypass: 'pull_requests_only' })] });
    assert.notEqual(e.governance, 'satisfied');
  });

  it('a non-active ruleset is not trusted', () => {
    const d = rulesetDetail({ enforcement: 'evaluate' });
    const e = evaluate({ details: [d] });
    assert.notEqual(e.governance, 'satisfied');
  });

  it('unreadable rules for the branch: everything NOT VERIFIED', () => {
    const e = evaluate({ branchRules: { state: 'unverified', reason: 'HTTP 403' } });
    assert.equal(e.governance, 'unverified');
  });
});

describe('github protection: classic branch protection', () => {
  const classic = (edit = (p) => p) => ({ state: 'present', value: edit(structuredClone(normalizeClassic(fixture('doc-protection.json')))) });

  it('readable, admins enforced, no allowances: counts (documented shape)', () => {
    assert.equal(evaluate({ classic: classic() }).governance, 'satisfied');
  });

  it('enforce_admins off is an admin bypass: not compliant', () => {
    const e = evaluate({ classic: classic((p) => ({ ...p, enforce_admins: { enabled: false } })) });
    assert.equal(e.governance, 'missing');
    assert.match(e.sources[0].reasons.join(), /admins/);
  });

  it('pull-request bypass allowances: not compliant', () => {
    const e = evaluate({ classic: classic((p) => ({ ...p, required_pull_request_reviews: { ...p.required_pull_request_reviews, bypass_pull_request_allowances: { users: ['alice'], teams: [], apps: [] } } })) });
    assert.equal(e.governance, 'missing');
  });

  it('an unpinned classic context does not satisfy the check', () => {
    const e = evaluate({ classic: classic((p) => ({ ...p, required_status_checks: { checks: [{ context: 'security-gate', app_id: null }], contexts: ['security-gate'] } })) });
    assert.equal(state(e, 'status-check'), 'missing');
  });

  it('protected but unreadable (no admin): NOT VERIFIED', () => {
    const e = evaluate({ classic: { state: 'unverified', reason: 'HTTP 404' } });
    assert.equal(e.governance, 'unverified');
  });
});

describe('github protection: the additive SSD ruleset', () => {
  it('holds only the missing groups, no bypass, exactly the default branch', () => {
    const body = desiredRuleset({ branch: BRANCH, groups: ['required_status_checks'], appId: 15368 });
    assert.equal(body.name, SSD_RULESET_NAME);
    assert.deepEqual(body.bypass_actors, []);
    assert.deepEqual(body.conditions, { ref_name: { include: ['refs/heads/main'], exclude: [] } });
    assert.deepEqual(body.rules, [{ type: 'required_status_checks', parameters: { required_status_checks: [{ context: REQUIRED_CHECK, integration_id: 15368 }], strict_required_status_checks_policy: false } }]);
    const full = desiredRuleset({ branch: BRANCH, groups: ['pull_request', 'required_status_checks'], appId: 15368 });
    assert.deepEqual(full.rules[0].parameters, { ...PULL_REQUEST_PARAMETERS });
    assert.deepEqual({ ...PULL_REQUEST_PARAMETERS }, { dismiss_stale_reviews_on_push: true, require_code_owner_review: true, require_last_push_approval: true, required_approving_review_count: 1, required_review_thread_resolution: false });
  });

  it('an existing compliant ruleset: nothing missing, so no duplicate is planned', () => {
    assert.deepEqual(evaluate({ details: [rulesetDetail()] }).groupsMissing, []);
  });

  it('a partly compatible ruleset: only the missing group is proposed; the other ruleset is untouched', () => {
    const e = evaluate({ details: [withChecks([{ context: 'security-gate' }])] });
    assert.deepEqual(e.groupsMissing, ['required_status_checks']);
    assert.deepEqual(e.conflicts, []);
  });

  it('a well-formed existing SSD ruleset is reused, never duplicated', () => {
    const ssd = { id: 7, source_type: 'Repository', ...desiredRuleset({ branch: BRANCH, groups: ['pull_request', 'required_status_checks'], appId: 15368 }) };
    const e = evaluate({ details: [ssd] });
    assert.equal(e.governance, 'satisfied');
    assert.deepEqual(e.conflicts, []);
    assert.deepEqual(ssdRulesetDrift(ssd, { branch: BRANCH, appId: 15368 }), []);
  });

  for (const [what, edit] of [
    ['a bypass actor', (d) => ({ ...d, bypass_actors: [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }] })],
    ['another branch', (d) => ({ ...d, conditions: { ref_name: { include: ['refs/heads/release'], exclude: [] } } })],
    ['a changed check', (d) => ({ ...d, rules: d.rules.map((r) => (r.type === 'required_status_checks' ? { ...r, parameters: { ...r.parameters, required_status_checks: [{ context: 'security-gate' }] } } : r)) })],
    ['a weakened review rule', (d) => ({ ...d, rules: d.rules.map((r) => (r.type === 'pull_request' ? { ...r, parameters: { ...r.parameters, require_last_push_approval: false } } : r)) })],
    ['an extra rule type', (d) => ({ ...d, rules: [...d.rules, { type: 'deletion', parameters: {} }] })],
    ['evaluate mode', (d) => ({ ...d, enforcement: 'evaluate' })]
  ]) {
    it(`an SSD-named ruleset with ${what} is a CONFLICT (no blind overwrite)`, () => {
      const ssd = edit({ id: 7, source_type: 'Repository', ...desiredRuleset({ branch: BRANCH, groups: ['pull_request', 'required_status_checks'], appId: 15368 }) });
      const e = evaluate({ details: [ssd] });
      assert.ok(e.conflicts.some((c) => c.kind === 'ssd-ruleset-drifted'), JSON.stringify(e.conflicts));
    });
  }

  it('an SSD ruleset holding only some groups while others are missing: conflict, never an edit', () => {
    const ssd = { id: 7, source_type: 'Repository', ...desiredRuleset({ branch: BRANCH, groups: ['pull_request'], appId: 15368 }) };
    const e = evaluate({ details: [ssd] });
    assert.ok(e.conflicts.some((c) => c.kind === 'ssd-ruleset-incomplete'));
  });

  it('an unrelated ruleset never becomes a conflict and is never proposed for change', () => {
    const unrelated = rulesetDetail({ id: 9, name: 'tags', rules: [{ type: 'deletion', parameters: {} }] });
    const e = evaluate({ details: [unrelated] });
    assert.deepEqual(e.conflicts, []);
    assert.deepEqual(e.groupsMissing, ['pull_request', 'required_status_checks']);
  });
});

describe('github protection: CODEOWNERS (remote fact vs local heuristic)', () => {
  const cfg = config('source-only');
  const remote = (text, extra = {}) => ({ state: 'present', file: { path: '.github/CODEOWNERS', size: Buffer.byteLength(text), sha: contentsDoc(text).sha, text, tooLarge: false, ...extra }, errors: { state: 'present', list: [] } });

  it('absent on GitHub: incomplete, owners never invented', () => {
    const r = analyzeCodeowners({ config: cfg, facts: facts(), remote: { state: 'absent' } });
    assert.equal(r.state, 'incomplete');
    assert.match(r.reasons[0], /never invents owners/);
    assert.match(r.warnings[0], /exists locally but not on main/);
  });

  it('present, no GitHub errors, heuristically complete: complete (and labelled heuristic)', () => {
    const r = analyzeCodeowners({ config: cfg, facts: facts(), remote: remote(COMPLETE_CODEOWNERS) });
    assert.equal(r.state, 'complete');
    assert.match(r.reasons[0], /heuristic/);
  });

  it('GitHub parse errors (unknown owners) make it incomplete even when the heuristic is complete', () => {
    const errors = fixture('doc-codeowners-errors.json').errors.map((e) => ({ line: e.line, kind: e.kind, message: e.message, path: e.path }));
    const r = analyzeCodeowners({ config: cfg, facts: facts(), remote: { ...remote(COMPLETE_CODEOWNERS), errors: { state: 'present', list: errors } } });
    assert.equal(r.state, 'incomplete');
  });

  it('coverage is judged on GITHUB\'S copy: a complete local file does not hide an incomplete remote one', () => {
    const r = analyzeCodeowners({ config: cfg, facts: facts(), remote: remote('/.ssd/ @acme/security\n') });
    assert.equal(r.state, 'incomplete');
    assert.ok(r.uncovered.includes('.github/workflows/'));
    assert.match(r.warnings.join(), /differs from GitHub's copy/);
  });

  it('unreadable errors or content: NOT VERIFIED', () => {
    assert.equal(analyzeCodeowners({ config: cfg, facts: facts(), remote: { ...remote(COMPLETE_CODEOWNERS), errors: { state: 'unverified', reason: 'x' } } }).state, 'unverified');
    assert.equal(analyzeCodeowners({ config: cfg, facts: facts(), remote: remote(COMPLETE_CODEOWNERS, { text: null }) }).state, 'unverified');
    assert.equal(analyzeCodeowners({ config: cfg, facts: facts(), remote: { state: 'unverified', reason: 'x' } }).state, 'unverified');
  });

  it('over GitHub\'s 3 MB limit: incomplete', () => {
    assert.equal(analyzeCodeowners({ config: cfg, facts: facts(), remote: remote(COMPLETE_CODEOWNERS, { tooLarge: true, size: 4e6 }) }).state, 'incomplete');
  });
});

// discoverClassic()'s normalized shape from the documented protection document.
function normalizeClassic(p) {
  return {
    enforce_admins: { enabled: p.enforce_admins.enabled },
    required_pull_request_reviews: {
      require_code_owner_reviews: p.required_pull_request_reviews.require_code_owner_reviews,
      required_approving_review_count: p.required_pull_request_reviews.required_approving_review_count,
      dismiss_stale_reviews: p.required_pull_request_reviews.dismiss_stale_reviews,
      require_last_push_approval: p.required_pull_request_reviews.require_last_push_approval,
      bypass_pull_request_allowances: { users: [], teams: [], apps: [] }
    },
    required_status_checks: { checks: p.required_status_checks.checks, contexts: p.required_status_checks.contexts }
  };
}
