// Read-only GitHub discovery for `github plan` / `github apply` re-checks.
//
// Every response is UNTRUSTED input. Each reader checks the shape it relies on
// and throws GitHubDataError (-> outcome ERROR, fail closed) when a field it
// decides from is missing or of the wrong type. GitHub's answers are mapped
// conservatively:
//   - 401, timeout, deadline, malformed output: thrown (the run ends; ERROR);
//   - 403 / 404 on something that needs more privilege: { state: 'unverified' }
//     with the reason, never "absent" — GitHub answers 404 for "no access" too;
//   - "absent" only where the absence is proven: an empty list from an
//     endpoint that answered, or a 404 on a read the token was already shown
//     to be allowed (contents of a repository it can read).
import { createHash } from 'node:crypto';

import { FATAL_KINDS, CODEOWNERS_PATHS, GhCliError, MAX_PAGES } from './gh-cli.mjs';
import { GITHUB_ACTIONS_APP } from './protection.mjs';

export class GitHubDataError extends Error {
  constructor(endpoint, message) {
    super(`unexpected GitHub response for ${endpoint}: ${message}`);
    this.name = 'GitHubDataError';
    this.kind = 'malformed-response';
  }
}

// GitHub caps CODEOWNERS: a larger file is not loaded at all.
export const CODEOWNERS_MAX_BYTES = 3 * 1024 * 1024;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isInt = (v) => Number.isSafeInteger(v);
const isBool = (v) => typeof v === 'boolean';
const optional = (v, test) => v === undefined || v === null || test(v);

function expect(endpoint, condition, message) {
  if (!condition) {
    throw new GitHubDataError(endpoint, message);
  }
}

// A non-fatal GitHub refusal -> unverified; anything else propagates.
async function attempt(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (error) {
    if (error instanceof GhCliError && !FATAL_KINDS.has(error.kind)) {
      return { ok: false, error, reason: `${error.status ? `HTTP ${error.status}: ` : ''}${error.message}` };
    }
    throw error;
  }
}

// Pages of a list endpoint. `items(body)` extracts the array of one page.
async function paged(gh, name, items) {
  const all = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const body = await gh.get(name, page);
    const list = items(body);
    all.push(...list);
    if (list.length < 100) {
      return { complete: true, value: all };
    }
  }
  return { complete: false, value: all };
}

// --- identity -----------------------------------------------------------------------

export async function discoverUser(gh) {
  const r = await attempt(() => gh.get('user'));
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  expect('user', isObj(r.value) && isStr(r.value.login), 'no login');
  return { state: 'present', login: r.value.login };
}

export async function discoverRepository(gh) {
  const r = await attempt(() => gh.get('repository'));
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  const v = r.value;
  const where = 'repos/<owner>/<repo>';
  expect(where, isObj(v), 'not an object');
  expect(where, isStr(v.full_name) && isInt(v.id) && v.id > 0, 'no full_name / id');
  expect(where, isStr(v.default_branch) && v.default_branch !== '', 'no default_branch');
  expect(where, isBool(v.archived), 'no archived flag');
  expect(where, optional(v.permissions, isObj), 'permissions is not an object');
  const p = v.permissions ?? {};
  for (const key of ['admin', 'maintain', 'push', 'pull']) {
    expect(where, optional(p[key], isBool), `permissions.${key} is not a boolean`);
  }
  return {
    state: 'present',
    value: {
      fullName: v.full_name,
      id: v.id,
      defaultBranch: v.default_branch,
      archived: v.archived,
      visibility: isStr(v.visibility) ? v.visibility : null,
      // Unknown permissions are false: privilege is never assumed.
      permissions: { admin: p.admin === true, maintain: p.maintain === true, push: p.push === true, pull: p.pull === true }
    }
  };
}

// The GitHub Actions app, as GitHub reports it. Only the exact expected
// identity is "verified".
export async function discoverActionsApp(gh) {
  const r = await attempt(() => gh.get('actionsApp'));
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  const v = r.value;
  expect('apps/github-actions', isObj(v) && isInt(v.id) && isStr(v.slug), 'no id / slug');
  const owner = isObj(v.owner) ? v.owner.login : null;
  if (v.id !== GITHUB_ACTIONS_APP.id || v.slug !== GITHUB_ACTIONS_APP.slug || owner !== GITHUB_ACTIONS_APP.owner) {
    return { state: 'unverified', reason: `GitHub reports the github-actions app as id ${v.id}, slug ${v.slug}, owner ${owner}; expected ${GITHUB_ACTIONS_APP.id}/${GITHUB_ACTIONS_APP.slug}/${GITHUB_ACTIONS_APP.owner}` };
  }
  return { state: 'verified', id: v.id };
}

// --- secrets ------------------------------------------------------------------------

// Metadata of one Actions secret. GitHub never returns a secret's value; the
// value is UNKNOWABLE here, so "present" says nothing about it.
export async function discoverSecret(gh, name) {
  const where = 'repos/<owner>/<repo>/actions/secrets';
  const r = await attempt(() =>
    paged(gh, 'secrets', (body) => {
      expect(where, isObj(body) && isInt(body.total_count) && Array.isArray(body.secrets), 'no total_count / secrets');
      for (const s of body.secrets) {
        expect(where, isObj(s) && isStr(s.name) && optional(s.created_at, isStr) && optional(s.updated_at, isStr), 'a secret entry without a name');
      }
      return body.secrets;
    })
  );
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  const found = r.value.value.find((s) => s.name === name);
  if (found) {
    return { state: 'present', metadata: { name: found.name, createdAt: found.created_at ?? null, updatedAt: found.updated_at ?? null } };
  }
  if (!r.value.complete) {
    return { state: 'unverified', reason: `the repository has more than ${MAX_PAGES * 100} secrets; the list was not read completely` };
  }
  return { state: 'absent', metadata: null };
}

// --- protection ---------------------------------------------------------------------

function checkRule(where, rule) {
  expect(where, isObj(rule) && isStr(rule.type), 'a rule without a type');
  expect(where, optional(rule.parameters, isObj), `${rule.type}: parameters is not an object`);
  if (rule.type === 'required_status_checks') {
    const list = rule.parameters?.required_status_checks;
    expect(where, Array.isArray(list), 'required_status_checks without its list');
    for (const c of list) {
      expect(where, isObj(c) && isStr(c.context) && optional(c.integration_id, isInt), 'a required status check without a string context');
    }
  }
  if (rule.type === 'pull_request') {
    const p = rule.parameters ?? {};
    expect(where, optional(p.required_approving_review_count, isInt), 'pull_request.required_approving_review_count is not an integer');
    for (const key of ['require_code_owner_review', 'dismiss_stale_reviews_on_push', 'require_last_push_approval']) {
      expect(where, optional(p[key], isBool), `pull_request.${key} is not a boolean`);
    }
  }
}

// The ACTIVE rules GitHub applies to the branch, from every ruleset (repository
// and organization). GitHub resolves conditions and enforcement here, so
// ssd-onboard never re-implements ref_name matching.
export async function discoverBranchRules(gh) {
  const where = 'repos/<owner>/<repo>/rules/branches/<branch>';
  const r = await attempt(() =>
    paged(gh, 'branchRules', (body) => {
      expect(where, Array.isArray(body), 'not a list');
      for (const rule of body) {
        checkRule(where, rule);
        expect(where, isInt(rule.ruleset_id) && isStr(rule.ruleset_source_type) && isStr(rule.ruleset_source), 'a rule without its ruleset id / source');
      }
      return body;
    })
  );
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  if (!r.value.complete) {
    return { state: 'unverified', reason: 'more rules apply to the branch than ssd-onboard reads' };
  }
  return { state: 'present', value: r.value.value };
}

export async function discoverRulesetList(gh) {
  const where = 'repos/<owner>/<repo>/rulesets';
  const r = await attempt(() =>
    paged(gh, 'rulesets', (body) => {
      expect(where, Array.isArray(body), 'not a list');
      for (const s of body) {
        expect(where, isObj(s) && isInt(s.id) && isStr(s.name) && isStr(s.source_type) && isStr(s.enforcement), 'a ruleset without id / name / source_type / enforcement');
      }
      return body;
    })
  );
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  if (!r.value.complete) {
    return { state: 'unverified', reason: 'the repository has more rulesets than ssd-onboard reads' };
  }
  return { state: 'present', value: r.value.value.map((s) => ({ id: s.id, name: s.name, source_type: s.source_type, source: isStr(s.source) ? s.source : null, enforcement: s.enforcement, target: s.target ?? null, updated_at: s.updated_at ?? null })) };
}

// One ruleset's detail, or null when this token may not read it. bypass_actors
// is kept ABSENT when GitHub omits it (the caller cannot see it), never
// defaulted to [].
export async function discoverRulesetDetail(gh, id) {
  const where = `repos/<owner>/<repo>/rulesets/${id}`;
  const r = await attempt(() => gh.get('ruleset', id));
  if (!r.ok) {
    return null;
  }
  const v = r.value;
  expect(where, isObj(v) && v.id === id && isStr(v.name) && isStr(v.enforcement), 'no matching id / name / enforcement');
  expect(where, Array.isArray(v.rules), 'no rules list');
  v.rules.forEach((rule) => checkRule(where, rule));
  expect(where, optional(v.conditions, isObj), 'conditions is not an object');
  if (v.bypass_actors !== undefined && v.bypass_actors !== null) {
    expect(where, Array.isArray(v.bypass_actors), 'bypass_actors is not a list');
    for (const a of v.bypass_actors) {
      expect(where, isObj(a) && isStr(a.actor_type) && optional(a.actor_id, isInt) && optional(a.bypass_mode, isStr), 'a bypass actor without actor_type');
    }
  }
  expect(where, optional(v.current_user_can_bypass, isStr), 'current_user_can_bypass is not a string');
  const detail = {
    id: v.id,
    name: v.name,
    target: v.target ?? null,
    enforcement: v.enforcement,
    source_type: v.source_type ?? null,
    conditions: v.conditions ?? null,
    rules: v.rules.map((rule) => ({ type: rule.type, parameters: rule.parameters ?? {} })),
    updated_at: v.updated_at ?? null
  };
  if (Array.isArray(v.bypass_actors)) {
    detail.bypass_actors = v.bypass_actors.map((a) => ({ actor_type: a.actor_type, actor_id: a.actor_id ?? null, bypass_mode: a.bypass_mode ?? null }));
  }
  if (isStr(v.current_user_can_bypass)) {
    detail.current_user_can_bypass = v.current_user_can_bypass;
  }
  return detail;
}

// Classic branch protection. `branches/<b>` is readable with read access and
// says whether the branch is protected at all; the full settings need admin.
export async function discoverClassic(gh) {
  const branch = await attempt(() => gh.get('branch'));
  if (!branch.ok) {
    return { state: 'unverified', reason: branch.reason };
  }
  expect('repos/<owner>/<repo>/branches/<branch>', isObj(branch.value) && isBool(branch.value.protected), 'no protected flag');
  if (branch.value.protected === false) {
    return { state: 'absent' };
  }
  const r = await attempt(() => gh.get('protection'));
  if (!r.ok) {
    return { state: 'unverified', reason: r.reason };
  }
  const v = r.value;
  const where = 'repos/<owner>/<repo>/branches/<branch>/protection';
  expect(where, isObj(v), 'not an object');
  expect(where, optional(v.enforce_admins, (e) => isObj(e) && isBool(e.enabled)), 'enforce_admins without enabled');
  const reviews = v.required_pull_request_reviews;
  expect(where, optional(reviews, isObj), 'required_pull_request_reviews is not an object');
  if (reviews) {
    expect(where, optional(reviews.required_approving_review_count, isInt), 'required_approving_review_count is not an integer');
    for (const key of ['require_code_owner_reviews', 'dismiss_stale_reviews', 'require_last_push_approval']) {
      expect(where, optional(reviews[key], isBool), `${key} is not a boolean`);
    }
    expect(where, optional(reviews.bypass_pull_request_allowances, isObj), 'bypass_pull_request_allowances is not an object');
  }
  const checks = v.required_status_checks;
  expect(where, optional(checks, isObj), 'required_status_checks is not an object');
  if (checks) {
    expect(where, optional(checks.checks, (l) => Array.isArray(l) && l.every((c) => isObj(c) && isStr(c.context) && optional(c.app_id, isInt))), 'a check without a string context');
    expect(where, optional(checks.contexts, (l) => Array.isArray(l) && l.every(isStr)), 'contexts is not a list of strings');
  }
  const allowances = reviews?.bypass_pull_request_allowances ?? {};
  return {
    state: 'present',
    value: {
      enforce_admins: v.enforce_admins ? { enabled: v.enforce_admins.enabled } : null,
      required_pull_request_reviews: reviews
        ? {
            require_code_owner_reviews: reviews.require_code_owner_reviews ?? false,
            required_approving_review_count: reviews.required_approving_review_count ?? 0,
            dismiss_stale_reviews: reviews.dismiss_stale_reviews ?? false,
            require_last_push_approval: reviews.require_last_push_approval ?? false,
            bypass_pull_request_allowances: Object.fromEntries(['users', 'teams', 'apps'].map((k) => [k, Array.isArray(allowances[k]) ? allowances[k].map((a) => (isObj(a) ? a.login ?? a.slug ?? a.id ?? '?' : '?')) : []]))
          }
        : null,
      required_status_checks: checks ? { checks: (checks.checks ?? []).map((c) => ({ context: c.context, app_id: c.app_id ?? null })), contexts: checks.contexts ?? [] } : null
    }
  };
}

// --- CODEOWNERS ---------------------------------------------------------------------

// The CODEOWNERS file GitHub uses for the default branch: the first of
// .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS that exists THERE (GitHub's
// documented lookup order), and GitHub's own parse errors for it.
// `canRead`: the token was shown to read the repository, so a 404 on contents
// proves absence.
export async function discoverCodeowners(gh, { canRead }) {
  let file = null;
  for (const path of CODEOWNERS_PATHS) {
    const r = await attempt(() => gh.get('contents', path));
    if (!r.ok) {
      if (r.error.kind === 'not-found' && canRead) {
        continue;
      }
      return { state: 'unverified', reason: `${path}: ${r.reason}` };
    }
    const v = r.value;
    const where = `repos/<owner>/<repo>/contents/${path}`;
    expect(where, isObj(v) && isStr(v.type), 'not a contents object');
    if (v.type !== 'file') {
      // GitHub does not document how it treats a directory or link here.
      return { state: 'unverified', reason: `${path} on the default branch is a ${v.type}, not a regular file` };
    }
    expect(where, isInt(v.size) && v.size >= 0 && isStr(v.sha), 'no size / sha');
    let text = null;
    if (v.encoding === 'base64' && isStr(v.content) && v.content !== '') {
      const bytes = Buffer.from(v.content.replace(/\s+/g, ''), 'base64');
      expect(where, bytes.length === v.size, 'content does not match its size (truncated?)');
      text = bytes.toString('utf8');
    }
    file = { path, size: v.size, sha: v.sha, text, tooLarge: v.size > CODEOWNERS_MAX_BYTES };
    break;
  }
  if (!file) {
    return { state: 'absent' };
  }
  const errors = await attempt(() => gh.get('codeownersErrors'));
  if (!errors.ok) {
    return { state: 'present', file, errors: { state: 'unverified', reason: errors.reason } };
  }
  const where = 'repos/<owner>/<repo>/codeowners/errors';
  expect(where, isObj(errors.value) && Array.isArray(errors.value.errors), 'no errors list');
  const list = errors.value.errors.map((e) => {
    expect(where, isObj(e), 'an error entry is not an object');
    return { line: isInt(e.line) ? e.line : null, kind: isStr(e.kind) ? e.kind : 'unknown', message: isStr(e.message) ? e.message : '', path: isStr(e.path) ? e.path : file.path };
  });
  return { state: 'present', file, errors: { state: 'present', list } };
}

// A git blob id, to compare the local CODEOWNERS with the one GitHub uses.
export function gitBlobSha(text) {
  const bytes = Buffer.from(text, 'utf8');
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}
